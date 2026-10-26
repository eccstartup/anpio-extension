// ANP wallet background service worker — owns the key vault + signing.
//
// v4: a wallet is ONE independent mnemonic encrypted under the single global
// wallet password. An account holds many wallets (each its own handle + many
// derived keys/DIDs). The private keys never leave this worker. A site asks for
// a signature; we stage it as a pending request and only sign once the user
// approves it in the popup.
import { base64 } from '@scure/base'
import {
  deriveEd25519PrivateKey,
  deriveKeyPrivateKey,
  buildAwikiIdentity,
  buildHandleAggregateDoc,
  signAnpLoginRequest,
  signChallenge,
  isValidMnemonic,
  type DidWbaIdentity,
} from './lib/anp'
import {
  AWIKI_DID_DOMAIN,
  AWIKI_ANP_ENDPOINT,
  AWIKI_SERVICE_DID,
  getChallenge,
  registerIdentity,
} from './lib/awiki'
import {
  PAGE_MESSAGE,
  type BgRequest,
  type BgResponse,
  type SignReq,
  type SignResult,
  type SignResultMessage,
  type PendingRequest,
  type StoredAccount,
  type Wallet,
  type StoredKey,
  type ActiveKeyRef,
} from './protocol'

// ---------------------------------------------------------------------------
// In-memory session state (lost when the SW is killed). One global password
// decrypts every wallet, but we only hold the mnemonic of wallets we've touched.
// ---------------------------------------------------------------------------
interface Unlocked {
  password: string
  /** walletId -> decrypted mnemonic. Lazy; unlocked wallets only. */
  mnemonics: Map<string, string>
  priv: Uint8Array
  identity: DidWbaIdentity | null
  activeRef: ActiveKeyRef | null
}

let unlocked: Unlocked | null = null

// Build an awiki identity bound to the configured self-hosted server (DID
// domain + ANPMessageService). The signed proof is the registration credential.
const AWIKI_MESSAGE_SERVICE = { serviceEndpoint: AWIKI_ANP_ENDPOINT, serviceDid: AWIKI_SERVICE_DID }
function buildIdentity(handle: string, priv: Uint8Array): DidWbaIdentity {
  return buildAwikiIdentity(handle, priv, AWIKI_DID_DOMAIN, AWIKI_MESSAGE_SERVICE)
}

interface Pending {
  id: string
  req: SignReq
  tabId: number
  pageOrigin: string
}

// Map keeps insertion order; newest last.
const pending = new Map<string, Pending>()

// ---------------------------------------------------------------------------
// WebCrypto AES-GCM + PBKDF2
// ---------------------------------------------------------------------------
const enc = new TextEncoder()
const dec = new TextDecoder()

// WebCrypto wants BufferSource backed by a concrete ArrayBuffer; typed arrays
// from @scure/base are generic `Uint8Array<ArrayBufferLike>`. Cast is safe.
const buf = (u: Uint8Array): BufferSource => u as unknown as BufferSource

async function pbkdf2Key(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey('raw', buf(enc.encode(password)), 'PBKDF2', false, ['deriveKey'])
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: buf(salt), iterations: 150_000, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

/** Encrypt a mnemonic under a password → one wallet's ciphertext blob. */
async function encryptMnemonic(mnemonic: string, password: string) {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const key = await pbkdf2Key(password, salt)
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: buf(iv) }, key, buf(enc.encode(mnemonic)))
  return { salt: base64.encode(salt), iv: base64.encode(iv), ciphertext: base64.encode(new Uint8Array(ct)) }
}

async function decryptMnemonic(encBlob: { salt: string; iv: string; ciphertext: string }, password: string): Promise<string | null> {
  try {
    const key = await pbkdf2Key(password, base64.decode(encBlob.salt))
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: buf(base64.decode(encBlob.iv)) },
      key,
      buf(base64.decode(encBlob.ciphertext)),
    )
    return dec.decode(pt)
  } catch {
    return null
  }
}

// ---------------------------------------------------------------------------
// Storage + migration
// ---------------------------------------------------------------------------
const ACCOUNT_KEY = 'anp_account'

// v2 shape (single handle/did/key) — kept only for migration.
interface LegacyV2 {
  version: number
  handle?: string
  salt: string
  iv: string
  ciphertext: string
  did?: string
  keyid?: string
  publicKeyMultibase: string
  didDocument?: Record<string, unknown>
  registered?: boolean
  accessToken?: string
}

// v3 shape (one mnemonic, many identity groupings) — kept only for migration.
interface LegacyV3 {
  version: number
  salt: string
  iv: string
  ciphertext: string
  identities: { id: string; label: string; activeKeyIndex: number; keys: StoredKey[] }[]
  nextKeyIndex: number
  activeIdentityId: string
}

async function loadAccount(): Promise<StoredAccount | null> {
  const record = await chrome.storage.local.get(ACCOUNT_KEY)
  const account = record[ACCOUNT_KEY] as StoredAccount | LegacyV2 | LegacyV3 | undefined
  if (!account) return null
  let next: StoredAccount
  if ((account as StoredAccount).version === 4) next = account as StoredAccount
  else if ((account as LegacyV3).version === 3) next = migrateV3ToV4(account as LegacyV3)
  else next = migrateV3ToV4(migrateV2(account as LegacyV2))
  normalizePrimaryKeyIndex(next)
  await saveAccount(next)
  return next
}

/** Fill a missing primaryKeyIndex (older v4 accounts) — default to the active key. */
function normalizePrimaryKeyIndex(account: StoredAccount) {
  for (const w of account.wallets) {
    if (typeof w.primaryKeyIndex !== 'number' || !Number.isInteger(w.primaryKeyIndex)) {
      w.primaryKeyIndex = w.keys.length ? Math.min(w.activeKeyIndex ?? 0, w.keys.length - 1) : 0
    }
  }
}

async function saveAccount(account: StoredAccount) {
  await chrome.storage.local.set({ [ACCOUNT_KEY]: account })
}

/** v2 → v3 shape (one mnemonic, single identity grouping). Pure. */
function migrateV2(v2: LegacyV2): LegacyV3 {
  const id = crypto.randomUUID()
  const label = (v2.handle ?? '').split('.')[0] || 'identity-0'
  const key: StoredKey = {
    index: 0,
    handle: v2.handle ?? '',
    did: v2.did ?? '',
    keyid: v2.keyid ?? '',
    publicKeyMultibase: v2.publicKeyMultibase,
    didDocument: v2.didDocument ?? {},
    registered: v2.registered,
    accessToken: v2.accessToken,
  }
  return {
    version: 3,
    salt: v2.salt,
    iv: v2.iv,
    ciphertext: v2.ciphertext,
    identities: [{ id, label, activeKeyIndex: 0, keys: [key] }],
    nextKeyIndex: 1,
    activeIdentityId: id,
  }
}

/**
 * v3 → v4: collapse the (single-mnemonic) groupings into ONE wallet. Keys keep
 * their derivation order (identity array order, then key array order). The v3
 * active key's COLLAPSED array position becomes the wallet's activeKeyIndex —
 * using its derivation `index` would be wrong if a previous identity held keys.
 */
function migrateV3ToV4(v3: LegacyV3): StoredAccount {
  const walletId = crypto.randomUUID()
  const keys: StoredKey[] = v3.identities.flatMap((id) => id.keys)

  const activeIdentity = v3.identities.find((i) => i.id === v3.activeIdentityId) ?? v3.identities[0] ?? null
  let activeKeyIndex = 0
  let handle = ''
  let label = '钱包 1'
  if (activeIdentity) {
    label = activeIdentity.label || '钱包 1'
    const kIdx = Math.min(activeIdentity.activeKeyIndex, Math.max(0, activeIdentity.keys.length - 1))
    const activeKey = activeIdentity.keys[kIdx]
    if (activeKey) activeKeyIndex = Math.max(0, keys.indexOf(activeKey))
    handle = activeKey?.handle ?? ''
  }

  const wallet: Wallet = {
    id: walletId,
    label,
    handle,
    salt: v3.salt,
    iv: v3.iv,
    ciphertext: v3.ciphertext, // mnemonic unchanged — still under the global password
    nextKeyIndex: v3.nextKeyIndex,
    activeKeyIndex,
    primaryKeyIndex: keys.length ? activeKeyIndex : 0,
    keys,
  }
  return { version: 4, wallets: [wallet], activeWalletId: walletId }
}

// ---------------------------------------------------------------------------
// Active-wallet/key resolution + minting helpers
// ---------------------------------------------------------------------------
function walletOf(account: StoredAccount, walletId: string | null): Wallet | null {
  if (!walletId) return account.wallets[0] ?? null
  return account.wallets.find((w) => w.id === walletId) ?? null
}

function activeKeyOf(account: StoredAccount): { wallet: Wallet; key: StoredKey; keyIndex: number } | null {
  const wallet = walletOf(account, account.activeWalletId)
  if (!wallet) return null
  const keyIndex = wallet.keys.length ? Math.min(wallet.activeKeyIndex, wallet.keys.length - 1) : 0
  const key = wallet.keys[keyIndex]
  if (!key) return null
  return { wallet, key, keyIndex }
}

function activeRefOf(account: StoredAccount): ActiveKeyRef | null {
  const active = activeKeyOf(account)
  if (!active) return null
  return { walletId: active.wallet.id, keyIndex: active.keyIndex }
}

/** Mint a key (its own DID) at `index` from the wallet mnemonic, bound to `handle`. */
function mintStoredKey(mnemonic: string, index: number, handle: string): StoredKey {
  const identity = buildIdentity(handle, deriveKeyPrivateKey(mnemonic, index))
  return {
    index,
    handle,
    did: identity.did,
    keyid: identity.keyid,
    publicKeyMultibase: identity.publicKeyMultibase,
    didDocument: identity.didDocument,
  }
}

/**
 * The ONE place that re-derives the in-memory active key. Using the wrong
 * wallet's mnemonic yields a valid Ed25519 key that binds to the wrong DID, so
 * every active-key mutation routes through here. `walletId`'s mnemonic must
 * already be in `unlocked.mnemonics`.
 * Returns an error string, or null on success.
 */
function activateKey(account: StoredAccount, walletId: string, keyIndex: number): string | null {
  if (!unlocked) return 'Wallet locked'
  const wallet = walletOf(account, walletId)
  if (!wallet) return 'Wallet not found'
  const mnemonic = unlocked.mnemonics.get(walletId)
  if (!mnemonic) return '钱包无法解密，请重新解锁'
  const idx = Math.min(keyIndex, Math.max(0, wallet.keys.length - 1))
  const key = wallet.keys[idx]
  if (!key) {
    // Wallet with no keys yet — hold the master key so sign() errors cleanly.
    unlocked.priv = deriveEd25519PrivateKey(mnemonic)
    unlocked.identity = null
    unlocked.activeRef = { walletId, keyIndex: 0 }
    return null
  }
  unlocked.priv = deriveKeyPrivateKey(mnemonic, key.index)
  unlocked.identity = {
    did: key.did,
    keyid: key.keyid,
    didDocument: key.didDocument,
    publicKeyMultibase: key.publicKeyMultibase,
  }
  unlocked.activeRef = { walletId, keyIndex: idx }
  return null
}

/** Ensure a target wallet's mnemonic is decrypted into the session. */
async function ensureWalletMnemonic(account: StoredAccount, walletId: string): Promise<string | null> {
  if (!unlocked) return null
  const cached = unlocked.mnemonics.get(walletId)
  if (cached) return cached
  const wallet = walletOf(account, walletId)
  if (!wallet) return null
  const mnemonic = await decryptMnemonic(
    { salt: wallet.salt, iv: wallet.iv, ciphertext: wallet.ciphertext },
    unlocked.password,
  )
  if (!mnemonic) return null
  unlocked.mnemonics.set(walletId, mnemonic)
  return mnemonic
}

/**
 * Derive the identity + private key for an arbitrary (walletId, keyIndex),
 * using the key's own E1 DID + stored didDocument and the *target* wallet's
 * mnemonic. Used by `register` (submitting key) and `approve` when the user
 * picks a specific key from the sign-approval chooser — so approval no longer
 * depends on the active key. Returns null if the wallet can't be decrypted.
 */
async function identityFor(
  account: StoredAccount,
  walletId: string,
  keyIndex: number,
): Promise<{ identity: DidWbaIdentity; priv: Uint8Array } | null> {
  const wallet = walletOf(account, walletId)
  if (!wallet) return null
  const key = wallet.keys[keyIndex]
  if (!key || !key.did || !key.didDocument) return null
  const mnemonic = await ensureWalletMnemonic(account, walletId)
  if (!mnemonic) return null
  const priv = deriveKeyPrivateKey(mnemonic, key.index)
  const identity: DidWbaIdentity = {
    did: key.did,
    keyid: key.keyid,
    didDocument: key.didDocument,
    publicKeyMultibase: key.publicKeyMultibase,
  }
  return { identity, priv }
}

/**
 * Submit the wallet's aggregate ad.json to the server, signed by its PRIMARY key.
 * Does not persist — the caller marks keys registered and saves on success.
 */
async function submitAggregateRegister(
  account: StoredAccount,
  wallet: Wallet,
  local: string,
  primaryPriv: Uint8Array,
): Promise<{
  ok: boolean
  message?: string
  dids?: string[]
  did?: string
  fullHandle?: string
  ad?: Record<string, unknown>
  accessToken?: string
  userId?: string
}> {
  const primary = wallet.keys[wallet.primaryKeyIndex]
  if (!primary) return { ok: false, message: '主密钥不存在' }
  const fullHandle = `${local}.${AWIKI_DID_DOMAIN}`
  const aggregate = buildHandleAggregateDoc(fullHandle, wallet.keys, primary.did, primaryPriv, {
    didDomain: AWIKI_DID_DOMAIN,
    messageService: AWIKI_MESSAGE_SERVICE,
  }) as Record<string, unknown>
  const chal = await getChallenge()
  const challengeSig = signChallenge(primaryPriv, chal.challenge)
  const result = (await registerIdentity(aggregate, fullHandle, chal.challenge, challengeSig, primary.did)) as {
    did?: string
    dids?: string[]
    access_token?: string
    token?: string
    user_id?: string
    message?: string
  }
  if (result.did && (result.access_token || result.token)) {
    return {
      ok: true,
      did: primary.did,
      dids: result.dids,
      fullHandle,
      ad: aggregate,
      accessToken: result.access_token ?? result.token,
      userId: result.user_id,
    }
  }
  return { ok: false, message: result.message ?? 'Registration failed' }
}

// ---------------------------------------------------------------------------
// Pending request helpers
// ---------------------------------------------------------------------------
function refreshBadge() {
  const count = pending.size
  void chrome.action.setBadgeText({ text: count > 0 ? String(count) : '' })
  void chrome.action.setBadgeBackgroundColor({ color: '#2C7A7B' })
}

function buildPendingState(p: Pending, did: string | null): PendingRequest {
  let bodyPreview = p.req.body
  if (bodyPreview.length > 300) bodyPreview = bodyPreview.slice(0, 300) + '…'
  return {
    id: p.id,
    url: p.req.url,
    method: (p.req.method ?? 'POST').toUpperCase(),
    nonce: p.req.nonce,
    bodyPreview,
    did: did ?? '',
    pageOrigin: p.pageOrigin,
  }
}

// Surf the approval UI to the user the moment a site asks for a signature.
// `chrome.action.openPopup()` needs a user gesture, so fall back to a dedicated
// window; if both fail the toolbar badge still shows the pending count.
async function openPopup() {
  try {
    await chrome.action.openPopup()
  } catch {
    try {
      await chrome.windows.create({ url: chrome.runtime.getURL('popup.html'), type: 'popup', width: 440, height: 640 })
    } catch {
      /* ignore */
    }
  }
}

// ---------------------------------------------------------------------------
// Message handling
// ---------------------------------------------------------------------------
chrome.runtime.onMessage.addListener((msg: BgRequest, sender, sendResponse) => {
  void handle(msg, sender).then(sendResponse).catch((e) => {
    sendResponse({ status: 'error', error: e instanceof Error ? e.message : String(e) } as BgResponse)
  })
  return true // keep the channel open for the async response
})

async function handle(msg: BgRequest, sender: chrome.runtime.MessageSender): Promise<BgResponse> {
  switch (msg.type) {
    case 'anp-wallet/sign': {
      const { id, req } = msg.payload
      const account = await loadAccount()
      if (!account) {
        void openPopup()
        return { status: 'no-account', error: 'No ANP account. Open the wallet to create one.' }
      }

      const tabId = sender.tab?.id
      if (tabId == null) return { status: 'error', error: 'No tab context' }

      // Stage even while locked: the popup opens, the user unlocks, then approves.
      pending.set(id, {
        id,
        req,
        tabId,
        pageOrigin: (sender.origin ?? '') || (sender.url ? new URL(sender.url).origin : ''),
      })
      refreshBadge()
      void openPopup()
      return { status: 'pending', id }
    }

    case 'anp-wallet/get-identity': {
      const account = await loadAccount()
      if (!account) return { status: 'no-account', error: 'No account' }
      const active = activeKeyOf(account)
      if (!active || !active.key.did || !active.key.keyid || !active.key.didDocument) {
        return { status: 'no-key', error: '尚未注册 DID' }
      }
      return {
        did: active.key.did,
        keyid: active.key.keyid,
        publicKeyMultibase: active.key.publicKeyMultibase,
        didDocument: active.key.didDocument,
      }
    }

    case 'anp-wallet/get-state': {
      const account = await loadAccount()
      return {
        status: 'ok',
        unlocked: Boolean(unlocked),
        account,
        activeRef: unlocked?.activeRef ?? (account ? activeRefOf(account) : null),
        pending: [...pending.values()].map((p) => buildPendingState(p, unlocked?.identity?.did ?? null)),
      }
    }

    case 'anp-wallet/unlock': {
      const account = await loadAccount()
      if (!account) return { status: 'error', error: 'No account' }
      const activeWallet = walletOf(account, account.activeWalletId)
      if (!activeWallet) return { status: 'error', error: 'No wallet' }
      const mnemonic = await decryptMnemonic(
        { salt: activeWallet.salt, iv: activeWallet.iv, ciphertext: activeWallet.ciphertext },
        msg.password,
      )
      if (!mnemonic) return { status: 'error', error: 'Wrong password' }
      unlocked = {
        password: msg.password,
        mnemonics: new Map([[activeWallet.id, mnemonic]]),
        priv: new Uint8Array(),
        identity: null,
        activeRef: { walletId: activeWallet.id, keyIndex: activeWallet.activeKeyIndex },
      }
      const err = activateKey(account, activeWallet.id, activeWallet.activeKeyIndex)
      if (err) return { status: 'error', error: err }
      return { status: 'ok' }
    }

    case 'anp-wallet/lock':
      unlocked = null
      return { status: 'ok' }

    case 'anp-wallet/create-account': {
      const { mnemonic, password, handle, label } = msg
      if (!isValidMnemonic(mnemonic)) return { status: 'error', error: 'Invalid mnemonic' }
      if ((password ?? '').length < 8) return { status: 'error', error: 'Password must be at least 8 characters' }

      const { salt, iv, ciphertext } = await encryptMnemonic(mnemonic, password)
      const id = crypto.randomUUID()
      const wlabel = (label ?? handle ?? '').split('.')[0] || '钱包 1'
      const wallet: Wallet = { id, label: wlabel, handle: handle ?? '', salt, iv, ciphertext, nextKeyIndex: 0, activeKeyIndex: 0, primaryKeyIndex: 0, keys: [] }
      // Every wallet owns its own key0 (its own DID), even before a handle is set.
      const local0 = (handle ?? '').trim().toLowerCase().split('.')[0] || id.slice(0, 8)
      const key = mintStoredKey(mnemonic, 0, `${local0}.${AWIKI_DID_DOMAIN}`)
      wallet.keys.push(key)
      wallet.nextKeyIndex = 1
      const active = { key, keyIndex: 0 }
      const account: StoredAccount = { version: 4, wallets: [wallet], activeWalletId: id }
      await saveAccount(account)
      unlocked = {
        password,
        mnemonics: new Map([[id, mnemonic]]),
        priv: new Uint8Array(),
        identity: null,
        activeRef: { walletId: id, keyIndex: 0 },
      }
      const err = activateKey(account, id, wallet.activeKeyIndex)
      if (err) return { status: 'error', error: err }
      return { status: 'ok', did: active.key.did, keyid: active.key.keyid, didDocument: active.key.didDocument, publicKeyMultibase: active.key.publicKeyMultibase }
    }

    case 'anp-wallet/add-wallet': {
      if (!unlocked) return { status: 'locked', error: '钱包已锁定，请先解锁再操作' }
      if (!isValidMnemonic(msg.mnemonic)) return { status: 'error', error: 'Invalid mnemonic' }
      const account = await loadAccount()
      if (!account) return { status: 'error', error: 'No account' }
      const { salt, iv, ciphertext } = await encryptMnemonic(msg.mnemonic, unlocked.password)
      const id = crypto.randomUUID()
      const label = (msg.label ?? msg.handle ?? '').split('.')[0] || `钱包 ${account.wallets.length + 1}`
      const wallet: Wallet = { id, label, handle: msg.handle ?? '', salt, iv, ciphertext, nextKeyIndex: 0, activeKeyIndex: 0, primaryKeyIndex: 0, keys: [] }
      const local0 = (msg.handle ?? '').trim().toLowerCase().split('.')[0] || id.slice(0, 8)
      wallet.keys.push(mintStoredKey(msg.mnemonic, 0, `${local0}.${AWIKI_DID_DOMAIN}`))
      wallet.nextKeyIndex = 1
      account.wallets.push(wallet)
      account.activeWalletId = id
      await saveAccount(account)
      unlocked.mnemonics.set(id, msg.mnemonic)
      const err = activateKey(account, id, wallet.activeKeyIndex)
      if (err) return { status: 'error', error: err }
      return { status: 'ok', walletId: id, keyIndex: wallet.activeKeyIndex }
    }

    case 'anp-wallet/delete-wallet': {
      if (!unlocked) return { status: 'locked', error: '钱包已锁定，请先解锁再操作' }
      const account = await loadAccount()
      if (!account) return { status: 'error', error: 'No account' }
      const idx = account.wallets.findIndex((w) => w.id === msg.walletId)
      if (idx < 0) return { status: 'error', error: 'Wallet not found' }
      account.wallets.splice(idx, 1)
      unlocked.mnemonics.delete(msg.walletId)
      if (account.wallets.length === 0) {
        account.activeWalletId = null
        await saveAccount(account)
        unlocked.identity = null
        unlocked.activeRef = null
        unlocked.priv = new Uint8Array()
        return { status: 'ok' }
      }
      if (account.activeWalletId === msg.walletId) account.activeWalletId = account.wallets[0].id
      await saveAccount(account)
      const activeId = account.activeWalletId ?? account.wallets[0].id
      const fallback = walletOf(account, activeId)
      const err = activateKey(account, activeId, fallback?.activeKeyIndex ?? 0)
      if (err) return { status: 'error', error: err }
      return { status: 'ok' }
    }

    case 'anp-wallet/rename-wallet': {
      if (!unlocked) return { status: 'locked', error: '钱包已锁定，请先解锁再操作' }
      const account = await loadAccount()
      if (!account) return { status: 'error', error: 'No account' }
      const wallet = walletOf(account, msg.walletId)
      if (!wallet) return { status: 'error', error: 'Wallet not found' }
      const label = (msg.label ?? '').trim()
      if (!label) return { status: 'error', error: '名称不能为空' }
      wallet.label = label
      await saveAccount(account)
      return { status: 'ok' }
    }

    case 'anp-wallet/select-wallet': {
      if (!unlocked) return { status: 'locked', error: '钱包已锁定，请先解锁再操作' }
      const account = await loadAccount()
      if (!account) return { status: 'error', error: 'No account' }
      const wallet = walletOf(account, msg.walletId)
      if (!wallet) return { status: 'error', error: 'Wallet not found' }
      account.activeWalletId = wallet.id
      await saveAccount(account)
      const m = await ensureWalletMnemonic(account, wallet.id)
      if (!m) return { status: 'error', error: '钱包无法解密，请重新解锁' }
      const err = activateKey(account, wallet.id, wallet.activeKeyIndex)
      if (err) return { status: 'error', error: err }
      return { status: 'ok' }
    }

    case 'anp-wallet/list-wallets': {
      const account = await loadAccount()
      if (!account) return { status: 'no-account', error: 'No account' }
      return {
        status: 'ok',
        wallets: account.wallets.map((w) => ({
          id: w.id,
          label: w.label,
          handle: w.handle,
          activeKeyIndex: w.activeKeyIndex,
          keyCount: w.keys.length,
          registeredCount: w.keys.filter((k) => k.registered).length,
        })),
        activeRef: activeRefOf(account),
      }
    }

    case 'anp-wallet/add-key': {
      if (!unlocked) return { status: 'locked', error: '钱包已锁定，请先解锁再操作' }
      const account = await loadAccount()
      if (!account) return { status: 'error', error: 'No account' }
      const wallet = walletOf(account, msg.walletId)
      if (!wallet) return { status: 'error', error: 'Wallet not found' }
      const mnemonic = await ensureWalletMnemonic(account, wallet.id)
      if (!mnemonic) return { status: 'error', error: '钱包无法解密，请重新解锁' }
      const index = wallet.nextKeyIndex
      wallet.nextKeyIndex += 1
      const local = wallet.handle.split('.')[0] || wallet.id.slice(0, 8)
      wallet.keys.push(mintStoredKey(mnemonic, index, `${local.toLowerCase()}.${AWIKI_DID_DOMAIN}`))
      // The handle's aggregate ad.json no longer matches the keys → needs re-register.
      if (wallet.registered) {
        wallet.registered = false
        wallet.handleDocuments = undefined
      }
      await saveAccount(account)
      return { status: 'ok', walletId: wallet.id, keyIndex: wallet.keys.length - 1 }
    }

    case 'anp-wallet/delete-key': {
      if (!unlocked) return { status: 'locked', error: '钱包已锁定，请先解锁再操作' }
      const account = await loadAccount()
      if (!account) return { status: 'error', error: 'No account' }
      const wallet = walletOf(account, msg.walletId)
      if (!wallet) return { status: 'error', error: 'Wallet not found' }
      if (wallet.keys.length <= 1) return { status: 'error', error: '每个钱包至少保留一把密钥' }
      if (msg.keyIndex === wallet.primaryKeyIndex) return { status: 'error', error: '主密钥不能删除' }
      wallet.keys.splice(msg.keyIndex, 1)
      // If the deleted key sat before the active/primary one, both references shift left.
      if (msg.keyIndex < wallet.activeKeyIndex) wallet.activeKeyIndex -= 1
      if (wallet.activeKeyIndex >= wallet.keys.length) wallet.activeKeyIndex = Math.max(0, wallet.keys.length - 1)
      if (msg.keyIndex < wallet.primaryKeyIndex) wallet.primaryKeyIndex -= 1
      if (wallet.primaryKeyIndex >= wallet.keys.length) wallet.primaryKeyIndex = Math.max(0, wallet.keys.length - 1)
      // The handle's aggregate ad.json no longer matches the keys → needs re-register.
      if (wallet.registered) {
        wallet.registered = false
        wallet.handleDocuments = undefined
      }
      await saveAccount(account)
      if (unlocked.activeRef?.walletId === wallet.id) {
        const err = activateKey(account, wallet.id, wallet.activeKeyIndex)
        if (err) return { status: 'error', error: err }
      }
      return { status: 'ok' }
    }

    case 'anp-wallet/select-active': {
      if (!unlocked) return { status: 'locked', error: '钱包已锁定，请先解锁再操作' }
      const account = await loadAccount()
      if (!account) return { status: 'error', error: 'No account' }
      const wallet = walletOf(account, msg.walletId)
      if (!wallet) return { status: 'error', error: 'Wallet not found' }
      if (!wallet.keys[msg.keyIndex]) return { status: 'error', error: 'Key not found' }
      account.activeWalletId = wallet.id
      wallet.activeKeyIndex = msg.keyIndex
      await saveAccount(account)
      const m = await ensureWalletMnemonic(account, wallet.id)
      if (!m) return { status: 'error', error: '钱包无法解密，请重新解锁' }
      const err = activateKey(account, wallet.id, msg.keyIndex)
      if (err) return { status: 'error', error: err }
      return { status: 'ok' }
    }

    // ---- awiki-open-server registration (aggregate ad.json + one-time challenge) ----
    case 'anp-wallet/register': {
      const account = await loadAccount()
      if (!account) return { status: 'error', error: 'No account' }
      if (!unlocked) return { status: 'locked', error: '钱包已锁定，请先解锁再注册' }
      const wallet = walletOf(account, msg.walletId)
      if (!wallet) return { status: 'error', error: 'Wallet not found' }
      const local = msg.handle.trim().toLowerCase().split('.')[0]
      if (!local) return { status: 'error', error: 'Handle required' }
      const primary = wallet.keys[wallet.primaryKeyIndex]
      if (!primary) return { status: 'error', error: '主密钥不存在' }
      const mnemonic = await ensureWalletMnemonic(account, wallet.id)
      if (!mnemonic) return { status: 'error', error: '钱包无法解密，请重新解锁' }
      try {
        const priv = deriveKeyPrivateKey(mnemonic, primary.index)
        // One handle → ONE aggregate ad.json spanning every key, SUBMITTED BY THE PRIMARY.
        const r = await submitAggregateRegister(account, wallet, local, priv)
        if (!r.ok) return { status: 'error', error: r.message ?? 'Registration failed' }
        for (const k of wallet.keys) {
          k.handle = r.fullHandle!
          k.registered = true
        }
        wallet.handle = r.fullHandle!
        wallet.registered = true
        wallet.handleDocuments = r.ad
        account.activeWalletId = wallet.id
        wallet.activeKeyIndex = wallet.primaryKeyIndex
        await saveAccount(account)
        const err = activateKey(account, wallet.id, wallet.primaryKeyIndex)
        if (err) return { status: 'error', error: err }
        return {
          status: 'ok',
          did: primary.did,
          dids: r.dids,
          accessToken: r.accessToken ?? undefined,
          userId: r.userId,
        }
      } catch (e) {
        return { status: 'error', error: e instanceof Error ? e.message : String(e) }
      }
    }

    case 'anp-wallet/set-primary': {
      if (!unlocked) return { status: 'locked', error: '钱包已锁定，请先解锁再操作' }
      const account = await loadAccount()
      if (!account) return { status: 'error', error: 'No account' }
      const wallet = walletOf(account, msg.walletId)
      if (!wallet) return { status: 'error', error: 'Wallet not found' }
      const key = wallet.keys[msg.keyIndex]
      if (!key) return { status: 'error', error: 'Key not found' }
      const oldPri = wallet.primaryKeyIndex
      if (oldPri === msg.keyIndex) return { status: 'ok', primaryKeyIndex: msg.keyIndex }
      wallet.primaryKeyIndex = msg.keyIndex
      if (wallet.registered) {
        // Changing the primary re-binds ownership on the server: submit the
        // aggregate again signed by the NEW primary. Roll back on failure.
        const local = wallet.handle.split('.')[0]
        if (!local) return { status: 'error', error: 'Handle required' }
        const mnemonic = await ensureWalletMnemonic(account, wallet.id)
        if (!mnemonic) return { status: 'error', error: '钱包无法解密，请重新解锁' }
        try {
          const priv = deriveKeyPrivateKey(mnemonic, key.index)
          const r = await submitAggregateRegister(account, wallet, local, priv)
          if (!r.ok) {
            wallet.primaryKeyIndex = oldPri
            return { status: 'error', error: r.message ?? 'Re-registration failed' }
          }
          wallet.handleDocuments = r.ad
          for (const k of wallet.keys) k.registered = true
        } catch (e) {
          wallet.primaryKeyIndex = oldPri
          return { status: 'error', error: e instanceof Error ? e.message : String(e) }
        }
      }
      await saveAccount(account)
      return { status: 'ok', primaryKeyIndex: wallet.primaryKeyIndex }
    }

    case 'anp-wallet/approve':
      return await approve(msg.id, true, msg.sel)

    case 'anp-wallet/reject':
      return await approve(msg.id, false)

    case 'anp-wallet/export-mnemonic': {
      if (!unlocked) return { status: 'error', error: 'Locked' }
      const walletId = unlocked.activeRef?.walletId
      if (!walletId) return { status: 'error', error: 'No active wallet' }
      const mnemonic = unlocked.mnemonics.get(walletId)
      if (!mnemonic) return { status: 'error', error: '钱包无法解密，请重新解锁' }
      return { status: 'ok', mnemonic }
    }

    default:
      return { status: 'error', error: 'Unknown message' }
  }
}

async function approve(id: string, allowed: boolean, sel?: { walletId: string; keyIndex: number }): Promise<BgResponse> {
  const item = pending.get(id)
  if (!item) return { status: 'error', error: 'Unknown request' }
  if (!unlocked) return { status: 'locked', error: 'Wallet locked. Unlock first.' }
  if (!unlocked.identity && !sel) return { status: 'error', error: '尚未注册 DID，请先在钱包里注册' }
  pending.delete(id)
  refreshBadge()

  const deliver = (result: SignResult | null, error?: string, status?: SignResultMessage['status']) => {
    const message: SignResultMessage = {
      wrap: PAGE_MESSAGE,
      id,
      status: status ?? (allowed ? 'ok' : 'rejected'),
      result: result ?? undefined,
      error,
    }
    void chrome.tabs.sendMessage(item.tabId, message).catch(() => {})
  }

  if (!allowed) {
    deliver(null, 'Rejected by user', 'rejected')
    return { status: 'rejected' }
  }

  // The user may pick a specific key from the sign-approval chooser. In that
  // case sign with the chosen key (its own DID), not the active one.
  let identity: DidWbaIdentity | null = unlocked.identity
  let priv = unlocked.priv
  if (sel) {
    const account = await loadAccount()
    if (!account) return { status: 'error', error: 'No account' }
    const found = await identityFor(account, sel.walletId, sel.keyIndex)
    if (!found) return { status: 'error', error: '所选密钥无法使用，请重新解锁' }
    identity = found.identity
    priv = found.priv
  }
  if (!identity) return { status: 'error', error: '尚未注册 DID，请先在钱包里注册' }

  // The site pre-builds the request body with the ACTIVE key's didDocument. If the
  // user self-selected a DIFFERENT key to sign, that body's didDocument won't match
  // the signer's keyid, so the server can't resolve the key. Rebuild the body with
  // the actual signing key's didDocument so body and key always agree.
  let finalBody = item.req.body
  try {
    const parsed = JSON.parse(item.req.body) as { didDocument?: unknown }
    parsed.didDocument = identity.didDocument
    finalBody = JSON.stringify(parsed)
  } catch {
    /* non-JSON body — sign it as-is */
  }

  try {
    const result = signAnpLoginRequest(identity, priv, {
      url: item.req.url,
      method: item.req.method ?? 'POST',
      body: finalBody,
      nonce: item.req.nonce,
      headers: item.req.headers,
    })
    deliver({ ...result, body: finalBody })
    return { status: 'ok', did: result.did, body: finalBody }
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e)
    deliver(null, message, 'error')
    return { status: 'error', error: message }
  }
}

// React to SW startup: clear stale badge (pending channel is gone anyway).
chrome.runtime.onInstalled.addListener(() => {
  refreshBadge()
})
