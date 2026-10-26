// ANP wallet background service worker — owns the identity vault + signing.
//
// v5: a wallet has exactly one secret source — a BIP39 mnemonic or a set of
// imported Ed25519 seeds — encrypted under the single global wallet password.
// This extension manages IDENTITY keys only: no communication/E2EE keys, no
// device manifest, no access_token persistence.
import { base64, base64urlnopad } from '@scure/base'
import {
  deriveEd25519PrivateKey,
  deriveKeyPrivateKey,
  buildAwikiIdentity,
  buildHandleAggregateDoc,
  signAnpLoginRequest,
  signChallenge,
  isValidMnemonic,
  parseEd25519PrivateKey,
  didDomainOf,
  multibaseEd25519,
  type AwikiMessageService,
  type DidWbaIdentity,
} from './lib/anp'
import {
  AWIKI_DID_DOMAIN,
  AWIKI_FALLBACK_SERVICE,
  BUILTIN_AWIKI_SERVER,
  AwikiRequestError,
  discoverServer,
  getChallenge,
  getEmailStatus,
  lookupHandle,
  registerAggregate,
  registerDidDocument,
  sendEmailVerification,
} from './lib/awiki'
import {
  PAGE_MESSAGE,
  type ActiveKeyRef,
  type AutoLockMinutes,
  type BgRequest,
  type BgResponse,
  type PendingRequest,
  type RegisterMode,
  type ServerConfig,
  type ServerRegistry,
  type SignReq,
  type SignResult,
  type SignResultMessage,
  type StoredAccount,
  type StoredKey,
  type Wallet,
  type WalletKind,
  type WalletSettings,
} from './protocol'

// ---------------------------------------------------------------------------
// In-memory session state (lost when the worker dies). One password decrypts
// every wallet; only secrets of wallets touched in this session stay in memory.
// ---------------------------------------------------------------------------
type WalletSecret =
  | { kind: 'mnemonic'; mnemonic: string }
  | { kind: 'imported'; keys: Map<number, Uint8Array> }

interface Unlocked {
  password: string
  secrets: Map<string, WalletSecret>
  priv: Uint8Array
  identity: DidWbaIdentity | null
  activeRef: ActiveKeyRef | null
}

let unlocked: Unlocked | null = null

/** Legacy local open-server, used only by migrated aggregate wallets. */
const LEGACY_AGGREGATE_SERVER: ServerConfig = {
  id: 'legacy-local',
  label: 'localhost（旧聚合）',
  rpcBase: 'http://127.0.0.1:8765',
  didDomain: 'localhost',
  registerMode: 'aggregate',
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

interface EncryptedBlob {
  salt: string
  iv: string
  ciphertext: string
}

async function encryptSecret(plaintext: string, password: string): Promise<EncryptedBlob> {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const key = await pbkdf2Key(password, salt)
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: buf(iv) }, key, buf(enc.encode(plaintext)))
  return { salt: base64.encode(salt), iv: base64.encode(iv), ciphertext: base64.encode(new Uint8Array(ct)) }
}

async function decryptSecret(blob: EncryptedBlob, password: string): Promise<string | null> {
  try {
    const key = await pbkdf2Key(password, base64.decode(blob.salt))
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: buf(base64.decode(blob.iv)) },
      key,
      buf(base64.decode(blob.ciphertext)),
    )
    return dec.decode(pt)
  } catch {
    return null
  }
}

/** Encrypted secret plaintext: mnemonic string, or {v:1,keys:{index:base64url}}. */
function serializeSecret(secret: WalletSecret): string {
  if (secret.kind === 'mnemonic') return secret.mnemonic
  const keys: Record<string, string> = {}
  for (const [index, seed] of [...secret.keys].sort((a, b) => a[0] - b[0])) {
    keys[String(index)] = base64urlnopad.encode(seed)
  }
  return JSON.stringify({ v: 1, keys })
}

function parseWalletSecret(wallet: Wallet, plaintext: string): WalletSecret {
  if (wallet.kind === 'imported') {
    let data: unknown
    try {
      data = JSON.parse(plaintext)
    } catch {
      throw new Error('导入钱包的秘密格式损坏')
    }
    const record = data as { v?: unknown; keys?: unknown }
    if (!record || record.v !== 1 || !record.keys || typeof record.keys !== 'object') {
      throw new Error('导入钱包的秘密格式损坏')
    }
    const keys = new Map<number, Uint8Array>()
    for (const [key, value] of Object.entries(record.keys as Record<string, unknown>)) {
      const index = Number(key)
      if (!Number.isInteger(index) || index < 0 || typeof value !== 'string') {
        throw new Error('导入钱包的秘密格式损坏')
      }
      let seed: Uint8Array
      try {
        seed = base64urlnopad.decode(value)
      } catch {
        throw new Error('导入钱包的私钥编码损坏')
      }
      if (seed.length !== 32) throw new Error('导入钱包的私钥长度必须是 32 字节')
      keys.set(index, seed)
    }
    if (keys.size === 0) throw new Error('导入钱包没有私钥')
    return { kind: 'imported', keys }
  }

  const mnemonic = plaintext.trim()
  if (!isValidMnemonic(mnemonic)) throw new Error('钱包助记词无法解密或已损坏')
  return { kind: 'mnemonic', mnemonic }
}

// ---------------------------------------------------------------------------
// Storage: account + separate server registry
// ---------------------------------------------------------------------------
const ACCOUNT_KEY = 'anp_account'
const SERVERS_KEY = 'anp_servers'
const SETTINGS_KEY = 'anp_settings'

const AUTO_LOCK_CHOICES: readonly AutoLockMinutes[] = [0, 1, 3, 5, 20]
const DEFAULT_AUTO_LOCK: AutoLockMinutes = 5

let cachedSettings: WalletSettings | null = null

function isAutoLockMinutes(value: unknown): value is AutoLockMinutes {
  return typeof value === 'number' && (AUTO_LOCK_CHOICES as readonly number[]).includes(value)
}

async function loadSettings(): Promise<WalletSettings> {
  if (cachedSettings) return cachedSettings
  let minutes: AutoLockMinutes = DEFAULT_AUTO_LOCK
  try {
    const record = await chrome.storage.local.get(SETTINGS_KEY)
    const raw = record[SETTINGS_KEY] as Partial<WalletSettings> | undefined
    if (raw && isAutoLockMinutes(raw.autoLockMinutes)) minutes = raw.autoLockMinutes
  } catch {
    /* fall back to the default */
  }
  cachedSettings = { autoLockMinutes: minutes }
  return cachedSettings
}

async function saveSettings(settings: WalletSettings): Promise<void> {
  cachedSettings = settings
  await chrome.storage.local.set({ [SETTINGS_KEY]: settings })
}

type LegacyKey = StoredKey & { accessToken?: string }

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
  identities: { id: string; label: string; activeKeyIndex: number; keys: LegacyKey[] }[]
  nextKeyIndex: number
  activeIdentityId: string
}

interface V4Wallet {
  id: string
  label: string
  handle: string
  salt: string
  iv: string
  ciphertext: string
  nextKeyIndex: number
  activeKeyIndex: number
  primaryKeyIndex: number
  keys: LegacyKey[]
  registered?: boolean
  handleDocuments?: Record<string, unknown>
}

interface StoredAccountV4 {
  version: 4
  wallets: V4Wallet[]
  activeWalletId: string | null
}

async function loadAccount(): Promise<StoredAccount | null> {
  const record = await chrome.storage.local.get(ACCOUNT_KEY)
  const raw = record[ACCOUNT_KEY] as
    | StoredAccount
    | StoredAccountV4
    | LegacyV3
    | LegacyV2
    | undefined
  if (!raw) return null

  let next: StoredAccount
  if ((raw as StoredAccount).version === 5) next = raw as StoredAccount
  else if ((raw as StoredAccountV4).version === 4) next = migrateV4ToV5(raw as StoredAccountV4)
  else if ((raw as LegacyV3).version === 3) next = migrateV4ToV5(migrateV3ToV4(raw as LegacyV3))
  else next = migrateV4ToV5(migrateV3ToV4(migrateV2(raw as LegacyV2)))

  normalizeAccount(next)
  await saveAccount(next)
  return next
}

async function saveAccount(account: StoredAccount) {
  await chrome.storage.local.set({ [ACCOUNT_KEY]: account })
}

/** v2 → v3 shape (one mnemonic, single identity grouping). Pure. */
function migrateV2(v2: LegacyV2): LegacyV3 {
  const id = crypto.randomUUID()
  const label = (v2.handle ?? '').split('.')[0] || 'identity-0'
  const key: LegacyKey = {
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
 * active key's COLLAPSED array position becomes the wallet's activeKeyIndex.
 */
function migrateV3ToV4(v3: LegacyV3): StoredAccountV4 {
  const walletId = crypto.randomUUID()
  const keys: LegacyKey[] = v3.identities.flatMap((id) => id.keys)

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

  const wallet: V4Wallet = {
    id: walletId,
    label,
    handle,
    salt: v3.salt,
    iv: v3.iv,
    ciphertext: v3.ciphertext,
    nextKeyIndex: v3.nextKeyIndex,
    activeKeyIndex,
    primaryKeyIndex: keys.length ? activeKeyIndex : 0,
    keys,
  }
  return { version: 4, wallets: [wallet], activeWalletId: walletId }
}

/** v4 → v5: add kind/server binding, infer aggregate mode, drop accessToken. */
function migrateV4ToV5(v4: StoredAccountV4): StoredAccount {
  const wallets: Wallet[] = v4.wallets.map((w) => {
    const first = w.keys[0]
    const parsedDomain = first ? didDomainOf(first.did) : null
    const didDomain = parsedDomain || 'localhost'
    const serverId = didDomain === AWIKI_DID_DOMAIN ? BUILTIN_AWIKI_SERVER.id : null
    const isAggregate = Boolean(
      w.registered && w.handleDocuments && (w.handleDocuments as { type?: unknown }).type === 'ANPHandleAggregate',
    )
    const keys: StoredKey[] = w.keys.map((key) => {
      const { accessToken: _drop, ...rest } = key
      return rest
    })
    return {
      kind: 'mnemonic',
      id: w.id,
      label: w.label,
      handle: w.handle,
      salt: w.salt,
      iv: w.iv,
      ciphertext: w.ciphertext,
      nextKeyIndex: w.nextKeyIndex,
      activeKeyIndex: w.activeKeyIndex,
      primaryKeyIndex: w.primaryKeyIndex,
      keys,
      registered: w.registered,
      handleDocuments: w.handleDocuments,
      serverId,
      didDomain,
      registerMode: isAggregate ? 'aggregate' : 'did_document',
    }
  })
  return { version: 5, wallets, activeWalletId: v4.activeWalletId }
}

function clampIndex(value: number, length: number): number {
  if (!Number.isInteger(value) || value < 0) return 0
  return Math.min(value, Math.max(0, length - 1))
}

/** Repair missing/legacy fields so every later path can rely on v5 invariants. */
function normalizeAccount(account: StoredAccount) {
  account.version = 5
  if (!Array.isArray(account.wallets)) account.wallets = []
  for (const w of account.wallets) {
    if (w.kind !== 'imported') w.kind = 'mnemonic'
    if (!Array.isArray(w.keys)) w.keys = []
    const first = w.keys[0]
    const parsedDomain = first ? didDomainOf(first.did) : null
    if (!w.didDomain) w.didDomain = parsedDomain || 'localhost'
    if (w.serverId === undefined) w.serverId = w.didDomain === AWIKI_DID_DOMAIN ? BUILTIN_AWIKI_SERVER.id : null
    if (w.registerMode !== 'aggregate') w.registerMode = 'did_document'
    if (!w.handle) w.handle = ''
    if (!w.label) w.label = '钱包'

    for (const key of w.keys as LegacyKey[]) {
      if ('accessToken' in key) delete key.accessToken
    }

    const maxIndex = w.keys.reduce((max, key) => Math.max(max, Number.isInteger(key.index) ? key.index : -1), -1)
    if (!Number.isInteger(w.nextKeyIndex) || w.nextKeyIndex <= maxIndex) w.nextKeyIndex = maxIndex + 1
    if (w.nextKeyIndex < 1) w.nextKeyIndex = 1

    w.primaryKeyIndex = clampIndex(w.primaryKeyIndex, w.keys.length)
    w.activeKeyIndex = clampIndex(w.activeKeyIndex, w.keys.length)
  }
  if (!account.activeWalletId || !account.wallets.some((w) => w.id === account.activeWalletId)) {
    account.activeWalletId = account.wallets[0]?.id ?? null
  }
}

// ---- server registry -------------------------------------------------------

function freshRegistry(): ServerRegistry {
  return {
    version: 1,
    servers: [{ ...BUILTIN_AWIKI_SERVER }],
    defaultServerId: BUILTIN_AWIKI_SERVER.id,
  }
}

function isServerConfig(value: unknown): value is ServerConfig {
  if (!value || typeof value !== 'object') return false
  const s = value as Record<string, unknown>
  return (
    typeof s.id === 'string' &&
    typeof s.label === 'string' &&
    typeof s.rpcBase === 'string' &&
    typeof s.didDomain === 'string'
  )
}

async function loadServers(): Promise<ServerRegistry> {
  const record = await chrome.storage.local.get(SERVERS_KEY)
  const raw = record[SERVERS_KEY] as Partial<ServerRegistry> | undefined
  let registry: ServerRegistry
  if (raw && raw.version === 1 && Array.isArray(raw.servers)) {
    registry = {
      version: 1,
      servers: raw.servers.filter(isServerConfig),
      defaultServerId: typeof raw.defaultServerId === 'string' ? raw.defaultServerId : BUILTIN_AWIKI_SERVER.id,
    }
  } else {
    registry = freshRegistry()
  }

  if (!registry.servers.some((s) => s.id === BUILTIN_AWIKI_SERVER.id)) {
    registry.servers.unshift({ ...BUILTIN_AWIKI_SERVER })
  }
  if (!registry.servers.some((s) => s.id === registry.defaultServerId)) {
    registry.defaultServerId = BUILTIN_AWIKI_SERVER.id
  }
  await saveServers(registry)
  return registry
}

async function saveServers(registry: ServerRegistry) {
  await chrome.storage.local.set({ [SERVERS_KEY]: registry })
}

function defaultServerOf(registry: ServerRegistry): ServerConfig {
  return registry.servers.find((s) => s.id === registry.defaultServerId) ?? { ...BUILTIN_AWIKI_SERVER }
}

function effectiveMode(wallet: Wallet): RegisterMode {
  return wallet.registerMode === 'aggregate' ? 'aggregate' : 'did_document'
}

function serverForWallet(wallet: Wallet, registry: ServerRegistry): ServerConfig | null {
  if (wallet.serverId) return registry.servers.find((s) => s.id === wallet.serverId) ?? null
  if (effectiveMode(wallet) === 'aggregate') return LEGACY_AGGREGATE_SERVER
  return null
}

/** Service descriptor known before discovery; registration always re-discovers. */
function knownServiceForServer(server: ServerConfig): AwikiMessageService | undefined {
  if (server.didDomain === AWIKI_DID_DOMAIN) return AWIKI_FALLBACK_SERVICE as AwikiMessageService
  if (server.registerMode === 'aggregate') return aggregateServiceFor(server)
  return undefined
}

function aggregateServiceFor(server: ServerConfig): AwikiMessageService {
  if (server.didDomain === AWIKI_DID_DOMAIN) return AWIKI_FALLBACK_SERVICE as AwikiMessageService
  const rpcBase = server.rpcBase.replace(/\/+$/, '')
  return {
    serviceEndpoint: `${rpcBase}/anp-im/rpc`,
    serviceDid: `did:wba:${server.didDomain}`,
  }
}

// ---------------------------------------------------------------------------
// Active-wallet/key resolution + secret access
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

/** The single private-key accessor for both mnemonic and imported wallets. */
function privateKeyFor(wallet: Wallet, key: StoredKey, secret: WalletSecret): Uint8Array {
  if (secret.kind === 'mnemonic') return deriveKeyPrivateKey(secret.mnemonic, key.index)
  const seed = secret.keys.get(key.index)
  if (!seed) throw new Error(`缺少私钥 #${key.index}`)
  return seed
}

/** Mint a key (its own DID) bound to `handle` and the DID domain. */
function mintStoredKey(
  priv: Uint8Array,
  index: number,
  handle: string,
  didDomain: string,
  service?: AwikiMessageService,
): StoredKey {
  const identity = buildAwikiIdentity(handle, priv, didDomain, service)
  return {
    index,
    handle,
    did: identity.did,
    keyid: identity.keyid,
    publicKeyMultibase: identity.publicKeyMultibase,
    didDocument: identity.didDocument,
  }
}

function keyHandleFor(wallet: Wallet): string {
  return (wallet.handle || `${wallet.id.slice(0, 8)}.${wallet.didDomain}`).toLowerCase()
}

/** Ensure a target wallet's secret is decrypted into the session. */
async function ensureWalletSecret(account: StoredAccount, walletId: string): Promise<WalletSecret | null> {
  if (!unlocked) return null
  const cached = unlocked.secrets.get(walletId)
  if (cached) return cached
  const wallet = walletOf(account, walletId)
  if (!wallet) return null
  const plaintext = await decryptSecret(
    { salt: wallet.salt, iv: wallet.iv, ciphertext: wallet.ciphertext },
    unlocked.password,
  )
  if (plaintext == null) return null
  const secret = parseWalletSecret(wallet, plaintext)
  unlocked.secrets.set(walletId, secret)
  return secret
}

async function reencryptWalletSecret(wallet: Wallet, secret: WalletSecret): Promise<void> {
  if (!unlocked) throw new Error('Wallet locked')
  const blob = await encryptSecret(serializeSecret(secret), unlocked.password)
  wallet.salt = blob.salt
  wallet.iv = blob.iv
  wallet.ciphertext = blob.ciphertext
}

/**
 * The ONE place that re-derives the in-memory active key. Using the wrong
 * wallet's secret yields a valid Ed25519 key that binds to the wrong DID, so
 * every active-key mutation routes through here. The secret must already be
 * in `unlocked.secrets`.
 */
function activateKey(account: StoredAccount, walletId: string, keyIndex: number): string | null {
  if (!unlocked) return 'Wallet locked'
  const wallet = walletOf(account, walletId)
  if (!wallet) return 'Wallet not found'
  const secret = unlocked.secrets.get(walletId)
  if (!secret) return '钱包无法解密，请重新解锁'
  const idx = Math.min(keyIndex, Math.max(0, wallet.keys.length - 1))
  const key = wallet.keys[idx]
  if (!key) {
    if (secret.kind === 'mnemonic') {
      unlocked.priv = deriveEd25519PrivateKey(secret.mnemonic)
      unlocked.identity = null
      unlocked.activeRef = { walletId, keyIndex: 0 }
      return null
    }
    return '钱包没有可用密钥'
  }
  let priv: Uint8Array
  try {
    priv = privateKeyFor(wallet, key, secret)
  } catch (e) {
    return e instanceof Error ? e.message : String(e)
  }
  unlocked.priv = priv
  unlocked.identity = {
    did: key.did,
    keyid: key.keyid,
    didDocument: key.didDocument,
    publicKeyMultibase: key.publicKeyMultibase,
  }
  unlocked.activeRef = { walletId, keyIndex: idx }
  return null
}

/**
 * Derive the identity + private key for an arbitrary (walletId, keyIndex),
 * using the key's own E1 DID + stored didDocument. Used by `approve` when the
 * user picks a specific key from the sign-approval chooser.
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
  const secret = await ensureWalletSecret(account, walletId)
  if (!secret) return null
  let priv: Uint8Array
  try {
    priv = privateKeyFor(wallet, key, secret)
  } catch {
    return null
  }
  const identity: DidWbaIdentity = {
    did: key.did,
    keyid: key.keyid,
    didDocument: key.didDocument,
    publicKeyMultibase: key.publicKeyMultibase,
  }
  return { identity, priv }
}

// ---------------------------------------------------------------------------
// Input validation + wallet construction
// ---------------------------------------------------------------------------
function validateLocal(local: string): string | null {
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(local)) {
    return 'Handle 只能包含小写字母、数字和连字符（1–63 字符）'
  }
  return null
}

function parseLocal(handle: string, didDomain: string): { local: string; error?: string } {
  try {
    const local = localPartOf(handle, didDomain)
    const error = validateLocal(local)
    return error ? { local, error } : { local }
  } catch (e) {
    return { local: '', error: e instanceof Error ? e.message : String(e) }
  }
}

function localPartOf(handle: string, didDomain: string): string {
  const trimmed = handle.trim().toLowerCase()
  const suffix = `.${didDomain.toLowerCase()}`
  const local = trimmed.endsWith(suffix) ? trimmed.slice(0, -suffix.length) : trimmed
  if (!local) throw new Error('Handle required')
  return local
}

function normalizeEmail(email: string | undefined): { value: string; error?: string } {
  const value = (email ?? '').trim().toLowerCase()
  if (!value) return { value, error: '请填写邮箱' }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return { value, error: '邮箱格式不正确' }
  return { value }
}

/** Normalize an optional handle hint to a full handle for the given domain. */
function walletHandleFromInput(raw: string | undefined, didDomain: string): { full: string; error?: string } {
  const trimmed = (raw ?? '').trim().toLowerCase()
  if (!trimmed) return { full: '' }
  const suffix = `.${didDomain.toLowerCase()}`
  const local = trimmed.endsWith(suffix) ? trimmed.slice(0, -suffix.length) : trimmed
  const error = validateLocal(local)
  return error ? { full: '', error } : { full: `${local}.${didDomain}` }
}

interface NewWalletSecret {
  kind: WalletKind
  secret: WalletSecret
  plaintext: string
  priv0: Uint8Array
}

function buildNewSecret(msg: { source?: 'mnemonic' | 'imported'; mnemonic?: string; privateKey?: string }): NewWalletSecret {
  if (msg.source === 'imported') {
    if (!msg.privateKey) throw new Error('请提供 Ed25519 私钥')
    const parsed = parseEd25519PrivateKey(msg.privateKey)
    const secret: WalletSecret = { kind: 'imported', keys: new Map([[0, parsed.seed]]) }
    return { kind: 'imported', secret, plaintext: serializeSecret(secret), priv0: parsed.seed }
  }

  const mnemonic = (msg.mnemonic ?? '').trim()
  if (!isValidMnemonic(mnemonic)) throw new Error('Invalid mnemonic')
  const secret: WalletSecret = { kind: 'mnemonic', mnemonic }
  return { kind: 'mnemonic', secret, plaintext: serializeSecret(secret), priv0: deriveKeyPrivateKey(mnemonic, 0) }
}

interface NewWalletResult {
  wallet: Wallet
  secret: WalletSecret
  key: StoredKey
}

async function createWallet(
  id: string,
  label: string,
  handle: string,
  source: NewWalletSecret,
  password: string,
  server: ServerConfig,
): Promise<NewWalletResult> {
  const blob = await encryptSecret(source.plaintext, password)
  const wallet: Wallet = {
    kind: source.kind,
    id,
    label,
    handle,
    salt: blob.salt,
    iv: blob.iv,
    ciphertext: blob.ciphertext,
    nextKeyIndex: 1,
    activeKeyIndex: 0,
    primaryKeyIndex: 0,
    keys: [],
    serverId: server.id,
    didDomain: server.didDomain,
    registerMode: 'did_document',
  }
  const key = mintStoredKey(
    source.priv0,
    0,
    handle || `${id.slice(0, 8)}.${server.didDomain}`,
    server.didDomain,
    knownServiceForServer(server),
  )
  wallet.keys.push(key)
  return { wallet, secret: source.secret, key }
}

// ---------------------------------------------------------------------------
// Registration helpers
// ---------------------------------------------------------------------------
interface DidRegisterResult {
  keys: StoredKey[]
  primary: StoredKey
  primaryPos: number
  fullHandle: string
  did: string
  userId?: string
}

async function submitDidDocumentRegister(
  wallet: Wallet,
  secret: WalletSecret,
  server: ServerConfig,
  local: string,
  email: string,
  inviteCode: string | undefined,
): Promise<DidRegisterResult> {
  if (wallet.registered) throw new Error('该钱包已注册')
  const discovered = await discoverServer(server)
  if (discovered.didDomain !== server.didDomain) {
    throw new Error(`服务器 DID 域为 ${discovered.didDomain}，与配置的 ${server.didDomain} 不一致`)
  }
  if (wallet.didDomain !== discovered.didDomain) {
    throw new Error(`钱包 DID 域为 ${wallet.didDomain}，与服务器 ${discovered.didDomain} 不一致，请先更换服务器`)
  }

  const fullHandle = `${local}.${server.didDomain}`
  const service = discovered.service as AwikiMessageService
  const rebuilt = wallet.keys.map((key) =>
    mintStoredKey(privateKeyFor(wallet, key, secret), key.index, fullHandle, server.didDomain, service),
  )
  const primaryPos = wallet.primaryKeyIndex
  const primary = rebuilt[primaryPos]
  if (!primary) throw new Error('主密钥不存在')

  // awiki.ai double-checks the mailbox before binding; the popup also polls it.
  if (server.didDomain === AWIKI_DID_DOMAIN) {
    const status = await getEmailStatus(server, email, fullHandle)
    if (!status.verified) throw new Error('邮箱尚未验证，请先点击邮件中的激活链接')
  }

  const result = await registerDidDocument(server, local, email, primary.didDocument, inviteCode)
  if (result.state !== 'registered') {
    throw new Error(`注册未完成（state=${String(result.state ?? 'unknown')}）`)
  }
  if (result.did !== primary.did) {
    throw new Error('服务器返回的 DID 与提交的 DID 不一致')
  }
  return {
    keys: rebuilt,
    primary,
    primaryPos,
    fullHandle,
    did: primary.did,
    userId: typeof result.user_id === 'string' ? result.user_id : undefined,
  }
}

interface AggregateRegisterResult {
  ok: boolean
  message?: string
  dids?: string[]
  did?: string
  fullHandle?: string
  ad?: Record<string, unknown>
  userId?: string
}

async function submitAggregateRegister(
  keys: StoredKey[],
  primaryPos: number,
  server: ServerConfig,
  local: string,
  primaryPriv: Uint8Array,
  email: string | undefined,
): Promise<AggregateRegisterResult> {
  const primary = keys[primaryPos]
  if (!primary) return { ok: false, message: '主密钥不存在' }
  const fullHandle = `${local}.${server.didDomain}`
  const aggregate = buildHandleAggregateDoc(fullHandle, keys, primary.did, primaryPriv, {
    didDomain: server.didDomain,
    messageService: aggregateServiceFor(server),
  }) as Record<string, unknown>
  const challenge = await getChallenge(server)
  const challengeSig = signChallenge(primaryPriv, challenge.challenge)
  const result = (await registerAggregate(
    server,
    aggregate,
    fullHandle,
    challenge.challenge,
    challengeSig,
    primary.did,
    email,
  )) as {
    did?: string
    dids?: string[]
    access_token?: string
    token?: string
    user_id?: string
    message?: string
  }

  if (result.did && (result.access_token || result.token)) {
    return { ok: true, did: primary.did, dids: result.dids, fullHandle, ad: aggregate, userId: result.user_id }
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
  return {
    id: p.id,
    url: p.req.url,
    method: (p.req.method ?? 'POST').toUpperCase(),
    nonce: p.req.nonce,
    // The full body: the user must be able to read exactly what they approve.
    body: p.req.body,
    did: did ?? '',
    pageOrigin: p.pageOrigin,
  }
}

// The side panel stays open while the user visits other tabs (e.g. an email
// activation link), so an open UI re-renders in place instead of losing state.
function nudgeUi(): number {
  const ping = Date.now()
  try {
    void chrome.storage.session?.set({ anp_ui_ping: ping })?.catch(() => {})
  } catch {
    /* storage.session unavailable on very old Chrome */
  }
  return ping
}

async function uiAnswered(ping: number): Promise<boolean> {
  try {
    const got = (await chrome.storage.session?.get('anp_ui_ack')) as { anp_ui_ack?: number } | undefined
    return got?.anp_ui_ack === ping
  } catch {
    return false
  }
}

// ---------------------------------------------------------------------------
// Auto-lock. Numeric settings count idle minutes since the last wallet action;
// `0` means lock as soon as the wallet UI (side panel / popup window) closes.
// The unlock state is memory-only, so a recycled service worker locks anyway.
// ---------------------------------------------------------------------------
const UI_PORT = 'anp-wallet-ui'
let autoLockTimer: ReturnType<typeof setTimeout> | null = null
let uiPorts = 0

function clearAutoLock(): void {
  if (autoLockTimer !== null) {
    clearTimeout(autoLockTimer)
    autoLockTimer = null
  }
}

function lockNow(): void {
  if (!unlocked) return
  clearAutoLock()
  unlocked = null
  nudgeUi()
}

async function armAutoLock(): Promise<void> {
  clearAutoLock()
  if (!unlocked) return
  const { autoLockMinutes } = await loadSettings()
  if (autoLockMinutes === 0) return
  const timer = setTimeout(lockNow, autoLockMinutes * 60_000)
  // Node (integration tests) would otherwise stay alive for the timeout.
  ;(timer as unknown as { unref?: () => void }).unref?.()
  autoLockTimer = timer
}

function watchUiPort(port: chrome.runtime.Port): void {
  if (port.name !== UI_PORT) return
  uiPorts += 1
  port.onDisconnect.addListener(() => {
    uiPorts = Math.max(0, uiPorts - 1)
    if (uiPorts > 0) return
    void loadSettings().then((settings) => {
      if (settings.autoLockMinutes === 0) lockNow()
    })
  })
}

// Surf the approval UI the moment a site asks for a signature.
async function openPopup() {
  const ping = nudgeUi()
  // Give an open side panel a moment to render and acknowledge before opening
  // a separate window on top of it.
  await new Promise((resolve) => setTimeout(resolve, 300))
  if (await uiAnswered(ping)) return
  try {
    await chrome.action.openPopup()
    return
  } catch {
    /* no action popup: the extension lives in the side panel */
  }
  try {
    const win = await chrome.windows.getLastFocused()
    if (win.id != null) {
      await chrome.sidePanel.open({ windowId: win.id })
      return
    }
  } catch {
    /* sidePanel.open needs a user gesture; fall through to a window */
  }
  try {
    await chrome.windows.create({ url: chrome.runtime.getURL('popup.html'), type: 'popup', width: 440, height: 640 })
  } catch {
    /* ignore */
  }
}

// Toolbar click opens the wallet in the browser side panel.
chrome.sidePanel?.setPanelBehavior({ openPanelOnActionClick: true })?.catch(() => {})

// ---------------------------------------------------------------------------
// Server validation
// ---------------------------------------------------------------------------
function normalizeRpcBase(raw: string): { value?: string; error?: string } {
  let url: URL
  try {
    url = new URL((raw ?? '').trim())
  } catch {
    return { error: 'RPC 根 URL 不合法' }
  }
  if (url.protocol !== 'https:') return { error: '仅支持 HTTPS 服务器' }
  if (url.username || url.password) return { error: 'URL 不能包含用户名或密码' }
  if (url.search || url.hash) return { error: 'URL 不能包含查询参数或锚点' }
  const path = url.pathname.replace(/\/+$/, '')
  return { value: `${url.origin}${path}` }
}

function normalizeDidDomain(raw: string): { value?: string; error?: string } {
  const value = (raw ?? '').trim().toLowerCase()
  if (!value) return { error: '请填写 DID 域名' }
  if (/[\s/:]/.test(value)) return { error: 'DID 域名不能包含协议、斜杠、冒号或空白' }
  if (!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(value)) return { error: 'DID 域名不合法' }
  return { value }
}

async function hasServerPermission(rpcBase: string): Promise<boolean> {
  if (!chrome.permissions?.contains) return true
  const origin = `${new URL(rpcBase).origin}/*`
  return chrome.permissions.contains({ origins: [origin] })
}

// ---------------------------------------------------------------------------
// Message handling
// ---------------------------------------------------------------------------
chrome.runtime.onMessage.addListener((msg: BgRequest, sender, sendResponse) => {
  // A user-driven wallet action postpones the idle lock. `get-state` runs on
  // every UI render, so it must not count as activity.
  if (sender.tab == null && msg.type !== 'anp-wallet/get-state') void armAutoLock()
  void handle(msg, sender)
    .then(sendResponse)
    .catch((e) => {
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
      const registry = await loadServers()
      const settings = await loadSettings()
      return {
        status: 'ok',
        unlocked: Boolean(unlocked),
        account,
        activeRef: unlocked?.activeRef ?? (account ? activeRefOf(account) : null),
        pending: [...pending.values()].map((p) => buildPendingState(p, unlocked?.identity?.did ?? null)),
        servers: registry.servers,
        defaultServerId: registry.defaultServerId,
        autoLockMinutes: settings.autoLockMinutes,
      }
    }

    case 'anp-wallet/unlock': {
      const account = await loadAccount()
      if (!account) return { status: 'error', error: 'No account' }
      const activeWallet = walletOf(account, account.activeWalletId)
      if (!activeWallet) return { status: 'error', error: 'No wallet' }
      const plaintext = await decryptSecret(
        { salt: activeWallet.salt, iv: activeWallet.iv, ciphertext: activeWallet.ciphertext },
        msg.password,
      )
      if (plaintext == null) return { status: 'error', error: 'Wrong password' }
      let secret: WalletSecret
      try {
        secret = parseWalletSecret(activeWallet, plaintext)
      } catch (e) {
        return { status: 'error', error: e instanceof Error ? e.message : String(e) }
      }
      unlocked = {
        password: msg.password,
        secrets: new Map([[activeWallet.id, secret]]),
        priv: new Uint8Array(),
        identity: null,
        activeRef: { walletId: activeWallet.id, keyIndex: activeWallet.activeKeyIndex },
      }
      const err = activateKey(account, activeWallet.id, activeWallet.activeKeyIndex)
      if (err) return { status: 'error', error: err }
      void armAutoLock()
      return { status: 'ok' }
    }

    case 'anp-wallet/lock':
      lockNow()
      return { status: 'ok' }

    case 'anp-wallet/set-auto-lock': {
      if (!isAutoLockMinutes(msg.minutes)) return { status: 'error', error: '锁定时间不合法' }
      await saveSettings({ autoLockMinutes: msg.minutes })
      if (unlocked) void armAutoLock()
      else clearAutoLock()
      return { status: 'ok', autoLockMinutes: msg.minutes }
    }

    case 'anp-wallet/create-account': {
      const existing = await loadAccount()
      if (existing && existing.wallets.length > 0) {
        return { status: 'error', error: '已有钱包，请使用“添加钱包”' }
      }
      const password = msg.password ?? ''
      if (password.length < 8) return { status: 'error', error: 'Password must be at least 8 characters' }

      let source: NewWalletSecret
      try {
        source = buildNewSecret(msg)
      } catch (e) {
        return { status: 'error', error: e instanceof Error ? e.message : String(e) }
      }

      const registry = await loadServers()
      const server = defaultServerOf(registry)
      const handle = walletHandleFromInput(msg.handle, server.didDomain)
      if (handle.error) return { status: 'error', error: handle.error }

      const id = crypto.randomUUID()
      const label = (msg.label ?? handle.full.split('.')[0] ?? '').trim() || '钱包 1'
      const { wallet, secret, key } = await createWallet(id, label, handle.full, source, password, server)

      const account: StoredAccount = { version: 5, wallets: [wallet], activeWalletId: id }
      await saveAccount(account)
      unlocked = {
        password,
        secrets: new Map([[id, secret]]),
        priv: new Uint8Array(),
        identity: null,
        activeRef: { walletId: id, keyIndex: 0 },
      }
      const err = activateKey(account, id, wallet.activeKeyIndex)
      if (err) return { status: 'error', error: err }
      void armAutoLock()
      return {
        status: 'ok',
        did: key.did,
        keyid: key.keyid,
        didDocument: key.didDocument,
        publicKeyMultibase: key.publicKeyMultibase,
      }
    }

    case 'anp-wallet/add-wallet': {
      if (!unlocked) return { status: 'locked', error: '钱包已锁定，请先解锁再操作' }
      const account = await loadAccount()
      if (!account) return { status: 'error', error: 'No account' }

      let source: NewWalletSecret
      try {
        source = buildNewSecret(msg)
      } catch (e) {
        return { status: 'error', error: e instanceof Error ? e.message : String(e) }
      }

      const registry = await loadServers()
      const server = defaultServerOf(registry)
      const handle = walletHandleFromInput(msg.handle, server.didDomain)
      if (handle.error) return { status: 'error', error: handle.error }

      const id = crypto.randomUUID()
      const label =
        (msg.label ?? handle.full.split('.')[0] ?? '').trim() || `钱包 ${account.wallets.length + 1}`
      const { wallet, secret } = await createWallet(id, label, handle.full, source, unlocked.password, server)
      account.wallets.push(wallet)
      account.activeWalletId = id
      await saveAccount(account)
      unlocked.secrets.set(id, secret)
      const err = activateKey(account, id, wallet.activeKeyIndex)
      if (err) return { status: 'error', error: err }
      void armAutoLock()
      return { status: 'ok', walletId: id, keyIndex: wallet.activeKeyIndex }
    }

    case 'anp-wallet/delete-wallet': {
      if (!unlocked) return { status: 'locked', error: '钱包已锁定，请先解锁再操作' }
      const account = await loadAccount()
      if (!account) return { status: 'error', error: 'No account' }
      const idx = account.wallets.findIndex((w) => w.id === msg.walletId)
      if (idx < 0) return { status: 'error', error: 'Wallet not found' }
      const wasActive = account.activeWalletId === msg.walletId || unlocked.activeRef?.walletId === msg.walletId
      account.wallets.splice(idx, 1)
      unlocked.secrets.delete(msg.walletId)

      if (account.wallets.length === 0) {
        account.activeWalletId = null
        await saveAccount(account)
        lockNow()
        return { status: 'ok' }
      }

      if (wasActive || !account.activeWalletId) account.activeWalletId = account.wallets[0].id
      await saveAccount(account)
      if (wasActive) {
        const nextWallet = walletOf(account, account.activeWalletId)
        if (!nextWallet) return { status: 'error', error: 'Wallet not found' }
        const secret = await ensureWalletSecret(account, nextWallet.id)
        if (!secret) return { status: 'error', error: '钱包无法解密，请重新解锁' }
        const err = activateKey(account, nextWallet.id, nextWallet.activeKeyIndex)
        if (err) return { status: 'error', error: err }
      }
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
      const secret = await ensureWalletSecret(account, wallet.id)
      if (!secret) return { status: 'error', error: '钱包无法解密，请重新解锁' }
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
          kind: w.kind,
          didDomain: w.didDomain,
          serverId: w.serverId,
          registered: Boolean(w.registered),
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
      const secret = await ensureWalletSecret(account, wallet.id)
      if (!secret) return { status: 'error', error: '钱包无法解密，请重新解锁' }

      const index = wallet.nextKeyIndex
      let priv: Uint8Array
      if (wallet.kind === 'mnemonic') {
        if (msg.privateKey) return { status: 'error', error: '助记词钱包只能派生密钥' }
        if (secret.kind !== 'mnemonic') return { status: 'error', error: '钱包秘密类型不一致' }
        priv = deriveKeyPrivateKey(secret.mnemonic, index)
      } else {
        if (!msg.privateKey) return { status: 'error', error: '导入钱包请提供私钥' }
        let parsed: ReturnType<typeof parseEd25519PrivateKey>
        try {
          parsed = parseEd25519PrivateKey(msg.privateKey)
        } catch (e) {
          return { status: 'error', error: e instanceof Error ? e.message : String(e) }
        }
        if (secret.kind !== 'imported') return { status: 'error', error: '钱包秘密类型不一致' }
        const publicKeyMultibase = multibaseEd25519(parsed.publicKey)
        if (wallet.keys.some((k) => k.publicKeyMultibase === publicKeyMultibase)) {
          return { status: 'error', error: '该私钥已在此钱包中' }
        }
        secret.keys.set(index, parsed.seed)
        priv = parsed.seed
        await reencryptWalletSecret(wallet, secret)
      }

      const registry = await loadServers()
      const server = serverForWallet(wallet, registry)
      const service = server ? knownServiceForServer(server) : undefined
      const key = mintStoredKey(priv, index, keyHandleFor(wallet), wallet.didDomain, service)
      wallet.keys.push(key)
      wallet.nextKeyIndex += 1

      // Only the aggregate ad.json enumerates keys; a registered single-DID
      // wallet keeps its bound primary and simply gains an unregistered key.
      if (effectiveMode(wallet) === 'aggregate' && wallet.registered) {
        wallet.registered = false
        wallet.handleDocuments = undefined
        for (const k of wallet.keys) k.registered = false
      }

      await saveAccount(account)
      return {
        status: 'ok',
        walletId: wallet.id,
        keyIndex: wallet.keys.length - 1,
        did: key.did,
        publicKeyMultibase: key.publicKeyMultibase,
      }
    }

    case 'anp-wallet/delete-key': {
      if (!unlocked) return { status: 'locked', error: '钱包已锁定，请先解锁再操作' }
      const account = await loadAccount()
      if (!account) return { status: 'error', error: 'No account' }
      const wallet = walletOf(account, msg.walletId)
      if (!wallet) return { status: 'error', error: 'Wallet not found' }
      if (wallet.keys.length <= 1) return { status: 'error', error: '每个钱包至少保留一把密钥' }
      if (msg.keyIndex === wallet.primaryKeyIndex) return { status: 'error', error: '主密钥不能删除' }
      const target = wallet.keys[msg.keyIndex]
      if (!target) return { status: 'error', error: 'Key not found' }

      const secret = await ensureWalletSecret(account, wallet.id)
      if (!secret) return { status: 'error', error: '钱包无法解密，请重新解锁' }
      if (wallet.kind === 'imported') {
        if (secret.kind !== 'imported') return { status: 'error', error: '钱包秘密类型不一致' }
        secret.keys.delete(target.index)
        await reencryptWalletSecret(wallet, secret)
      }

      wallet.keys.splice(msg.keyIndex, 1)
      // If the deleted key sat before the active/primary one, both references shift left.
      if (msg.keyIndex < wallet.activeKeyIndex) wallet.activeKeyIndex -= 1
      if (wallet.activeKeyIndex >= wallet.keys.length) wallet.activeKeyIndex = Math.max(0, wallet.keys.length - 1)
      if (msg.keyIndex < wallet.primaryKeyIndex) wallet.primaryKeyIndex -= 1
      if (wallet.primaryKeyIndex >= wallet.keys.length) wallet.primaryKeyIndex = Math.max(0, wallet.keys.length - 1)

      if (effectiveMode(wallet) === 'aggregate' && wallet.registered) {
        wallet.registered = false
        wallet.handleDocuments = undefined
        for (const k of wallet.keys) k.registered = false
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
      const secret = await ensureWalletSecret(account, wallet.id)
      if (!secret) return { status: 'error', error: '钱包无法解密，请重新解锁' }
      const err = activateKey(account, wallet.id, msg.keyIndex)
      if (err) return { status: 'error', error: err }
      return { status: 'ok' }
    }

    case 'anp-wallet/register': {
      const account = await loadAccount()
      if (!account) return { status: 'error', error: 'No account' }
      if (!unlocked) return { status: 'locked', error: '钱包已锁定，请先解锁再注册' }
      const wallet = walletOf(account, msg.walletId)
      if (!wallet) return { status: 'error', error: 'Wallet not found' }
      if (wallet.registered) return { status: 'error', error: '该钱包已注册' }

      const registry = await loadServers()
      const server = serverForWallet(wallet, registry)
      if (!server) {
        return {
          status: 'error',
          error:
            '旧 localhost 钱包未绑定服务器，不能注册到 awiki.ai；请先更换服务器或新建钱包',
        }
      }
      const mode = effectiveMode(wallet)
      const parsed = parseLocal(msg.handle, server.didDomain)
      if (parsed.error) return { status: 'error', error: parsed.error }
      const secret = await ensureWalletSecret(account, wallet.id)
      if (!secret) return { status: 'error', error: '钱包无法解密，请重新解锁' }
      const primaryPos = wallet.primaryKeyIndex
      if (!wallet.keys[primaryPos]) return { status: 'error', error: '主密钥不存在' }

      try {
        let primaryPriv: Uint8Array
        try {
          primaryPriv = privateKeyFor(wallet, wallet.keys[primaryPos], secret)
        } catch (e) {
          return { status: 'error', error: e instanceof Error ? e.message : String(e) }
        }

        if (mode === 'aggregate') {
          const fullHandle = `${parsed.local}.${server.didDomain}`
          const service = aggregateServiceFor(server)
          const rebuilt = wallet.keys.map((key) =>
            mintStoredKey(privateKeyFor(wallet, key, secret), key.index, fullHandle, server.didDomain, service),
          )
          const r = await submitAggregateRegister(
            rebuilt,
            primaryPos,
            server,
            parsed.local,
            primaryPriv,
            msg.email,
          )
          if (!r.ok) return { status: 'error', error: r.message ?? 'Registration failed' }

          wallet.keys = rebuilt
          for (const k of wallet.keys) {
            k.handle = r.fullHandle!
            k.registered = true
          }
          wallet.handle = r.fullHandle!
          wallet.registered = true
          wallet.handleDocuments = r.ad
          wallet.didDomain = server.didDomain
          wallet.registerMode = 'aggregate'
          if (r.userId) wallet.userId = r.userId
          account.activeWalletId = wallet.id
          wallet.activeKeyIndex = primaryPos
          await saveAccount(account)
          const err = activateKey(account, wallet.id, primaryPos)
          if (err) return { status: 'error', error: err }
          return { status: 'ok', did: r.did, dids: r.dids, userId: r.userId, mode }
        }

        const email = normalizeEmail(msg.email)
        if (email.error) return { status: 'error', error: email.error }
        const r = await submitDidDocumentRegister(
          wallet,
          secret,
          server,
          parsed.local,
          email.value,
          msg.inviteCode,
        )

        wallet.keys = r.keys
        for (const k of wallet.keys) {
          k.handle = r.fullHandle
          k.registered = false
        }
        wallet.keys[r.primaryPos].registered = true
        wallet.handle = r.fullHandle
        wallet.registered = true
        wallet.handleDocuments = r.primary.didDocument
        if (r.userId) wallet.userId = r.userId
        wallet.serverId = server.id
        wallet.didDomain = server.didDomain
        wallet.registerMode = 'did_document'
        account.activeWalletId = wallet.id
        wallet.activeKeyIndex = r.primaryPos
        await saveAccount(account)
        const err = activateKey(account, wallet.id, r.primaryPos)
        if (err) return { status: 'error', error: err }
        return { status: 'ok', did: r.did, fullHandle: r.fullHandle, mode }
      } catch (e) {
        return { status: 'error', error: e instanceof Error ? e.message : String(e) }
      }
    }

    case 'anp-wallet/verify-existing': {
      const account = await loadAccount()
      if (!account) return { status: 'error', error: 'No account' }
      if (!unlocked) return { status: 'locked', error: '钱包已锁定，请先解锁再验证' }
      const wallet = walletOf(account, msg.walletId)
      if (!wallet) return { status: 'error', error: 'Wallet not found' }
      if (wallet.registered) return { status: 'error', error: '该钱包已注册' }
      if (effectiveMode(wallet) !== 'did_document') {
        return { status: 'error', error: '旧聚合钱包不支持已有身份验证' }
      }

      const registry = await loadServers()
      const server = serverForWallet(wallet, registry)
      if (!server) return { status: 'error', error: '钱包未绑定服务器，请先更换服务器' }
      const parsed = parseLocal(msg.handle, server.didDomain)
      if (parsed.error) return { status: 'error', error: parsed.error }
      const secret = await ensureWalletSecret(account, wallet.id)
      if (!secret) return { status: 'error', error: '钱包无法解密，请重新解锁' }
      const primaryPos = wallet.primaryKeyIndex
      const primaryKey = wallet.keys[primaryPos]
      if (!primaryKey) return { status: 'error', error: '主密钥不存在' }

      try {
        const discovered = await discoverServer(server)
        if (discovered.didDomain !== server.didDomain) {
          return { status: 'error', error: `服务器 DID 域为 ${discovered.didDomain}，与配置不一致` }
        }
        if (wallet.didDomain !== discovered.didDomain) {
          return { status: 'error', error: `钱包 DID 域为 ${wallet.didDomain}，与服务器不一致，请先更换服务器` }
        }
        const fullHandle = `${parsed.local}.${server.didDomain}`
        const service = discovered.service as AwikiMessageService
        const primaryPriv = privateKeyFor(wallet, primaryKey, secret)
        const candidate = mintStoredKey(primaryPriv, primaryKey.index, fullHandle, server.didDomain, service)

        let lookup: { did?: string; status?: string; user_id?: string }
        try {
          lookup = await lookupHandle(server, fullHandle)
        } catch (e) {
          if (e instanceof AwikiRequestError) {
            if (e.httpStatus === 404) {
              return { status: 'error', error: '服务器不支持 handle 查询，请走注册流程' }
            }
            const lower = e.message.toLowerCase()
            if (lower.includes('not_found') || lower.includes('not found') || lower.includes('不存在')) {
              return { status: 'error', error: 'handle 未注册，请走注册流程' }
            }
          }
          return { status: 'error', error: e instanceof Error ? e.message : String(e) }
        }

        const status = typeof lookup.status === 'string' ? lookup.status.toLowerCase() : ''
        if (status && status !== 'active' && status !== 'registered') {
          return { status: 'error', error: `handle 状态为 ${lookup.status}，不能验证` }
        }
        if (lookup.did !== candidate.did) {
          return { status: 'error', error: '该 handle 绑定的 DID 与这把私钥不匹配' }
        }

        const rebuilt = wallet.keys.map((key) =>
          mintStoredKey(privateKeyFor(wallet, key, secret), key.index, fullHandle, server.didDomain, service),
        )
        wallet.keys = rebuilt
        for (const k of wallet.keys) {
          k.handle = fullHandle
          k.registered = false
        }
        wallet.keys[primaryPos].registered = true
        wallet.handle = fullHandle
        wallet.registered = true
        wallet.handleDocuments = candidate.didDocument
        wallet.serverId = server.id
        wallet.didDomain = server.didDomain
        wallet.registerMode = 'did_document'
        if (typeof lookup.user_id === 'string') wallet.userId = lookup.user_id
        account.activeWalletId = wallet.id
        wallet.activeKeyIndex = primaryPos
        await saveAccount(account)
        const err = activateKey(account, wallet.id, primaryPos)
        if (err) return { status: 'error', error: err }
        return { status: 'ok', did: candidate.did, fullHandle }
      } catch (e) {
        return { status: 'error', error: e instanceof Error ? e.message : String(e) }
      }
    }

    case 'anp-wallet/rebind-server': {
      const account = await loadAccount()
      if (!account) return { status: 'error', error: 'No account' }
      if (!unlocked) return { status: 'locked', error: '钱包已锁定，请先解锁再操作' }
      const wallet = walletOf(account, msg.walletId)
      if (!wallet) return { status: 'error', error: 'Wallet not found' }
      if (wallet.registered) return { status: 'error', error: '已注册钱包不能更换服务器' }
      const registry = await loadServers()
      const server = registry.servers.find((s) => s.id === msg.serverId)
      if (!server) return { status: 'error', error: '服务器不存在' }
      if (wallet.serverId === server.id && wallet.didDomain === server.didDomain) {
        return { status: 'ok', walletId: wallet.id }
      }

      const secret = await ensureWalletSecret(account, wallet.id)
      if (!secret) return { status: 'error', error: '钱包无法解密，请重新解锁' }
      try {
        const placeholder = `${wallet.id.slice(0, 8)}.${server.didDomain}`
        const service = knownServiceForServer(server)
        wallet.keys = wallet.keys.map((key) =>
          mintStoredKey(privateKeyFor(wallet, key, secret), key.index, placeholder, server.didDomain, service),
        )
        wallet.serverId = server.id
        wallet.didDomain = server.didDomain
        wallet.handle = ''
        wallet.registered = false
        wallet.handleDocuments = undefined
        wallet.registerMode = 'did_document'
        await saveAccount(account)
        const err = activateKey(account, wallet.id, wallet.activeKeyIndex)
        if (err) return { status: 'error', error: err }
        return { status: 'ok', walletId: wallet.id }
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
      if (effectiveMode(wallet) === 'did_document' && wallet.registered) {
        return { status: 'error', error: '已注册的单 DID 钱包不能更换主密钥' }
      }
      const oldPri = wallet.primaryKeyIndex
      if (oldPri === msg.keyIndex) return { status: 'ok', primaryKeyIndex: msg.keyIndex }
      wallet.primaryKeyIndex = msg.keyIndex

      if (effectiveMode(wallet) === 'aggregate' && wallet.registered) {
        const registry = await loadServers()
        const server = serverForWallet(wallet, registry)
        if (!server) {
          wallet.primaryKeyIndex = oldPri
          return { status: 'error', error: '钱包未绑定服务器' }
        }
        const parsed = parseLocal(wallet.handle, server.didDomain)
        if (parsed.error) {
          wallet.primaryKeyIndex = oldPri
          return { status: 'error', error: parsed.error }
        }
        const secret = await ensureWalletSecret(account, wallet.id)
        if (!secret) {
          wallet.primaryKeyIndex = oldPri
          return { status: 'error', error: '钱包无法解密，请重新解锁' }
        }
        try {
          const priv = privateKeyFor(wallet, key, secret)
          const r = await submitAggregateRegister(
            wallet.keys,
            msg.keyIndex,
            server,
            parsed.local,
            priv,
            undefined,
          )
          if (!r.ok) {
            wallet.primaryKeyIndex = oldPri
            return { status: 'error', error: r.message ?? 'Re-registration failed' }
          }
          wallet.handleDocuments = r.ad
          wallet.handle = r.fullHandle!
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

    case 'anp-wallet/export-secret': {
      if (!unlocked) return { status: 'error', error: 'Locked' }
      const account = await loadAccount()
      if (!account) return { status: 'error', error: 'No account' }
      const walletId = unlocked.activeRef?.walletId ?? account.activeWalletId
      const wallet = walletOf(account, walletId)
      if (!wallet) return { status: 'error', error: 'No active wallet' }
      const secret = await ensureWalletSecret(account, wallet.id)
      if (!secret) return { status: 'error', error: '钱包无法解密，请重新解锁' }
      if (secret.kind === 'mnemonic') {
        return { status: 'ok', kind: 'mnemonic', mnemonic: secret.mnemonic }
      }
      return {
        status: 'ok',
        kind: 'imported',
        keys: [...secret.keys]
          .sort((a, b) => a[0] - b[0])
          .map(([index, seed]) => ({ index, privateKey: base64urlnopad.encode(seed) })),
      }
    }

    case 'anp-wallet/list-servers': {
      const registry = await loadServers()
      return { status: 'ok', ...registry }
    }

    case 'anp-wallet/add-server': {
      const rpc = normalizeRpcBase(msg.rpcBase)
      if (rpc.error || !rpc.value) return { status: 'error', error: rpc.error ?? 'RPC 根 URL 不合法' }
      const domain = normalizeDidDomain(msg.didDomain)
      if (domain.error || !domain.value) return { status: 'error', error: domain.error ?? 'DID 域名不合法' }

      const registry = await loadServers()
      if (registry.servers.some((s) => s.rpcBase === rpc.value)) {
        return { status: 'error', error: '该 RPC 根 URL 已存在' }
      }
      if (!(await hasServerPermission(rpc.value))) {
        return { status: 'error', error: '缺少该服务器的访问权限，请重新添加并授权' }
      }
      let host = rpc.value
      try {
        host = new URL(rpc.value).host
      } catch {
        /* normalized above */
      }
      const server: ServerConfig = {
        id: crypto.randomUUID(),
        label: (msg.label ?? '').trim() || host,
        rpcBase: rpc.value,
        didDomain: domain.value,
        registerMode: 'did_document',
      }
      registry.servers.push(server)
      await saveServers(registry)
      return { status: 'ok', server }
    }

    case 'anp-wallet/remove-server': {
      const registry = await loadServers()
      const server = registry.servers.find((s) => s.id === msg.serverId)
      if (!server) return { status: 'error', error: '服务器不存在' }
      if (server.builtin) return { status: 'error', error: '内置服务器不能删除' }
      registry.servers = registry.servers.filter((s) => s.id !== msg.serverId)
      if (registry.defaultServerId === msg.serverId) registry.defaultServerId = BUILTIN_AWIKI_SERVER.id
      await saveServers(registry)
      return { status: 'ok' }
    }

    case 'anp-wallet/set-default-server': {
      const registry = await loadServers()
      if (!registry.servers.some((s) => s.id === msg.serverId)) {
        return { status: 'error', error: '服务器不存在' }
      }
      registry.defaultServerId = msg.serverId
      await saveServers(registry)
      return { status: 'ok' }
    }

    case 'anp-wallet/test-server': {
      const registry = await loadServers()
      const server = registry.servers.find((s) => s.id === msg.serverId)
      if (!server) return { status: 'error', error: '服务器不存在' }
      try {
        const discovered = await discoverServer(server)
        return { status: 'ok', didDomain: discovered.didDomain, source: discovered.source }
      } catch (e) {
        return { status: 'error', error: e instanceof Error ? e.message : String(e) }
      }
    }

    case 'anp-wallet/email-status': {
      const registry = await loadServers()
      const server = registry.servers.find((s) => s.id === msg.serverId)
      if (!server) return { status: 'error', error: '服务器不存在' }
      const email = normalizeEmail(msg.email)
      if (email.error) return { status: 'error', error: email.error }
      if (!msg.fullHandle.trim()) return { status: 'error', error: '请先填写 Handle' }
      try {
        const status = await getEmailStatus(server, email.value, msg.fullHandle.trim())
        return { status: 'ok', verified: status.verified, verifiedAt: status.verified_at }
      } catch (e) {
        if (e instanceof AwikiRequestError && e.httpStatus === 404) {
          if (server.didDomain === AWIKI_DID_DOMAIN) {
            return { status: 'error', error: e.message }
          }
          return { status: 'unsupported', error: '该服务器未启用邮箱验证' }
        }
        return { status: 'error', error: e instanceof Error ? e.message : String(e) }
      }
    }

    case 'anp-wallet/email-send': {
      const registry = await loadServers()
      const server = registry.servers.find((s) => s.id === msg.serverId)
      if (!server) return { status: 'error', error: '服务器不存在' }
      const email = normalizeEmail(msg.email)
      if (email.error) return { status: 'error', error: email.error }
      if (!msg.fullHandle.trim()) return { status: 'error', error: '请先填写 Handle' }
      try {
        const result = await sendEmailVerification(server, email.value, msg.fullHandle.trim())
        return { status: 'ok', message: result.message }
      } catch (e) {
        if (e instanceof AwikiRequestError && e.httpStatus === 404) {
          if (server.didDomain === AWIKI_DID_DOMAIN) {
            return { status: 'error', error: e.message }
          }
          return { status: 'unsupported', error: '该服务器未启用邮箱验证' }
        }
        return { status: 'error', error: e instanceof Error ? e.message : String(e) }
      }
    }

    default:
      return { status: 'error', error: 'Unknown message' }
  }
}

async function approve(
  id: string,
  allowed: boolean,
  sel?: { walletId: string; keyIndex: number },
): Promise<BgResponse> {
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

  // The site pre-builds the request body with the ACTIVE key's didDocument; if
  // the user self-selected a DIFFERENT key, that document won't match the
  // signer's keyid. Always bind the body to the signing identity. `did` is the
  // field ANP login verifiers check against the keyid's DID; the connector
  // omits it, so supply it from the identity we actually sign with.
  let finalBody = item.req.body
  try {
    const parsed = JSON.parse(item.req.body) as { did?: unknown; didDocument?: unknown }
    parsed.did = identity.did
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

// Follow wallet UI lifetime for the "lock immediately" setting.
chrome.runtime.onConnect?.addListener(watchUiPort)
