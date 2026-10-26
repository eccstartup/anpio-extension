// Integration test: run the BUILT background service worker (dist/background.js)
// inside a VM with a mocked `chrome`, drive the full v4 multi-wallet flow, and
// dump the delivered signature for the official `verify_official.py` cross-check.
// This exercises the same built artifact the browser loads, not just the source.
import { readFileSync, writeFileSync } from 'node:fs'
import vm from 'node:vm'
import { generateMnemonicPhrase } from '../src/lib/anp'

// ---- mock chrome -----------------------------------------------------------
let bgHandler: (msg: unknown, sender: unknown, sendResponse: (r: unknown) => void) => void = () => {}
const store = new Map<string, unknown>()
const tabMessages: { id: string; status: string; result?: Record<string, unknown>; error?: string }[] = []
let openPopupCalls = 0

;(globalThis as unknown as { chrome: unknown }).chrome = {
  runtime: {
    onMessage: { addListener: (h: typeof bgHandler) => (bgHandler = h) },
    onInstalled: { addListener: () => {} },
    sendMessage: (msg: { type?: string }) =>
      new Promise((resolve) => {
        const sender =
          msg?.type === 'anp-wallet/sign'
            ? { tab: { id: 7 }, origin: 'http://localhost:3000', url: 'http://localhost:3000/' }
            : {}
        bgHandler(msg, sender, (resp: unknown) => resolve(structuredClone(resp)))
      }),
  },
  storage: {
    local: {
      get: async (key: string | string[]) => {
        const keys = Array.isArray(key) ? key : [key]
        const out: Record<string, unknown> = {}
        for (const k of keys) if (store.has(k)) out[k] = store.get(k)
        return out
      },
      set: async (obj: Record<string, unknown>) => {
        for (const k of Object.keys(obj)) store.set(k, obj[k])
      },
    },
  },
  action: {
    setBadgeText: async () => {},
    setBadgeBackgroundColor: async () => {},
    openPopup: async () => {
      openPopupCalls++
    },
  },
  windows: { create: async () => ({ id: 99 }) },
  tabs: {
    sendMessage: async (_tabId: number, m: (typeof tabMessages)[number]) => {
      tabMessages.push(m)
      return true
    },
  },
}

// ---- load the built worker --------------------------------------------------
const src = readFileSync(new URL('../dist/background.js', import.meta.url), 'utf8')
vm.runInThisContext(src, { filename: 'background.js' })

const mnemonicA =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
const mnemonicB = generateMnemonicPhrase(256)
const TARGET = 'http://localhost:3000/api/login/anp/verify'
const nonce = 'f'.repeat(32)
const password = 'correct-horse-battery'

type Resp<T = Record<string, unknown>> = T & { status: string; error?: string }
const assert = (cond: unknown, msg: string) => {
  if (!cond) throw new Error('ASSERT FAILED: ' + msg)
}

type State = {
  status: string
  unlocked: boolean
  account: {
    version: number
    wallets: WalletStored[]
    activeWalletId: string | null
  }
  activeRef: { walletId: string; keyIndex: number } | null
  pending: unknown[]
}
type WalletStored = {
  id: string
  label: string
  handle: string
  registered?: boolean
  nextKeyIndex: number
  activeKeyIndex: number
  primaryKeyIndex: number
  keys: { index: number; did: string; keyid: string; publicKeyMultibase: string; handle: string; registered?: boolean }[]
}

async function bg(msg: unknown): Promise<unknown> {
  return chrome.runtime.sendMessage(msg)
}

async function main() {
  // =========================================================================
  // SCENARIO 1 — v3 → v4 migration (kept only to verify the collapse is safe).
  // Seed a v3 account whose identity keys have NON-monotonic index gaps, so a
  // buggy migration that used `key.index` for the active ref would exceed the
  // key count. The correct migration uses the COLLAPSED ARRAY position.
  // =========================================================================
  const seedV3 = {
    version: 3,
    salt: 'c2FsdA',
    iv: 'aXY',
    ciphertext: 'Y2lwaGVydGV4dA',
    identities: [
      {
        id: 'id1',
        label: '身份 1',
        activeKeyIndex: 0,
        keys: [
          { index: 0, handle: 'a.localhost', did: 'did:x:a', keyid: 'k1', publicKeyMultibase: 'z1', didDocument: {}, registered: true },
          { index: 5, handle: '', did: 'did:x:b', keyid: 'k2', publicKeyMultibase: 'z2', didDocument: {}, registered: false },
        ],
      },
      {
        id: 'id2',
        label: '身份 2',
        activeKeyIndex: 1,
        keys: [
          { index: 7, handle: '', did: 'did:x:c', keyid: 'k3', publicKeyMultibase: 'z3', didDocument: {}, registered: false },
          { index: 8, handle: '', did: 'did:x:d', keyid: 'k4', publicKeyMultibase: 'z4', didDocument: {}, registered: false },
        ],
      },
    ],
    nextKeyIndex: 4,
    activeIdentityId: 'id2',
  }
  store.set('anp_account', seedV3)
  const mig = (await bg({ type: 'anp-wallet/get-state' })) as State
  console.log('migration:', 'version=', mig.account.version, 'wallets=', mig.account.wallets.length, 'activeKeyIndex=', mig.account.wallets[0].activeKeyIndex)
  assert(mig.account.version === 4, 'expected v4 after migration')
  assert(mig.account.wallets.length === 1, 'expected 1 wallet after migration')
  const mw = mig.account.wallets[0]
  assert(mw.label === '身份 2', 'migration should carry the active identity label')
  assert(mw.nextKeyIndex === 4, 'migration should carry nextKeyIndex')
  assert(mw.keys.map((k) => k.index).join(',') === '0,5,7,8', 'migration should preserve identity-then-key order')
  // The active key was the 2nd key (array pos 1) in identity id2 → collapse to array pos 3.
  // Using key.index (8) here would be ~2x the key count → proves the dual-index fix.
  assert(mw.activeKeyIndex === 3, 'activeKeyIndex must be the collapsed ARRAY position (3), not key.index (8)')
  assert(mig.activeRef?.keyIndex === 3, 'activeRef must point at array position 3')
  assert(mw.primaryKeyIndex === 3, 'migration should default primaryKeyIndex to the active key')
  store.clear()

  // =========================================================================
  // SCENARIO 2 — create + multi-wallet + key management.
  // =========================================================================
  const created = (await bg({
    type: 'anp-wallet/create-account',
    mnemonic: mnemonicA,
    password,
    handle: 'agent-aaa.awiki.ai',
  })) as Resp<{ did: string; didDocument: Record<string, unknown> }>
  console.log('create-account:', created.status, created.did)
  assert(created.status === 'ok', 'create-account failed')
  assert(Boolean(created.did && created.didDocument), 'create-account should mint a DID when handle given')
  const didA0 = created.did

  const st0 = (await bg({ type: 'anp-wallet/get-state' })) as State
  assert(st0.account.version === 4, 'expected v4')
  assert(st0.account.wallets.length === 1, 'expected 1 wallet after create')
  assert(st0.account.wallets[0].keys.length === 1, 'expected 1 key after create-with-handle')
  assert(st0.account.wallets[0].nextKeyIndex === 1, 'expected nextKeyIndex=1')
  assert(st0.unlocked === true, 'create should auto-unlock')

  // Add a SECOND wallet with a DIFFERENT mnemonic → also auto-unlocks? add-wallet
  // requires an unlocked session, which create established.
  const addB = (await bg({
    type: 'anp-wallet/add-wallet',
    mnemonic: mnemonicB,
    handle: 'agent-bbb',
    label: '工作',
  })) as Resp<{ walletId: string; keyIndex: number }>
  console.log('add-wallet B:', addB.status, addB.walletId)
  assert(addB.status === 'ok', 'add-wallet B failed')
  const walletAId = st0.account.activeWalletId
  const walletBId = addB.walletId
  assert(walletBId !== walletAId, 'second wallet must have its own id')

  const listed = (await bg({ type: 'anp-wallet/list-wallets' })) as Resp<{
    wallets: { id: string; label: string; keyCount: number; registeredCount: number }[]
    activeRef: { walletId: string; keyIndex: number }
  }>
  console.log('list-wallets:', 'count=', listed.wallets.length, 'active=', listed.activeRef.walletId === walletBId ? 'B' : 'A')
  assert(listed.wallets.length === 2, 'expected 2 wallets')
  assert(listed.activeRef.walletId === walletBId, 'adding a wallet should make it active')
  const wA = listed.wallets.find((w) => w.id === walletAId)!
  const wB = listed.wallets.find((w) => w.id === walletBId)!
  assert(wA.label === 'agent-aaa' && wB.label === '工作', 'labels should default to handle local part / carry explicit label')

  // Active is B now → get-identity returns B's DID, distinct from A's.
  const idelB = (await bg({ type: 'anp-wallet/get-identity' })) as { did: string; didDocument: Record<string, unknown> }
  const didB0 = idelB.did
  console.log('get-identity (active=B):', didB0)
  assert(didB0 !== didA0, 'different mnemonics must yield different DIDs')

  // Switch back to A.
  const selA = (await bg({ type: 'anp-wallet/select-wallet', walletId: walletAId })) as Resp
  assert(selA.status === 'ok', 'select-wallet A failed')
  const idelA = (await bg({ type: 'anp-wallet/get-identity' })) as { did: string }
  assert(idelA.did === didA0, 'switch to A should restore A DID')

  // Add a key to A, then select it as active.
  const addKeyA = (await bg({ type: 'anp-wallet/add-key', walletId: walletAId })) as Resp<{ keyIndex: number }>
  console.log('add-key A:', addKeyA.status, 'keyIndex=', addKeyA.keyIndex)
  assert(addKeyA.status === 'ok' && addKeyA.keyIndex === 1, 'second key should sit at array position 1')
  const stA1 = (await bg({ type: 'anp-wallet/get-state' })) as State
  assert(stA1.account.wallets.find((w) => w.id === walletAId)!.nextKeyIndex === 2, 'nextKeyIndex should be 2 after add-key')

  const selActive = (await bg({ type: 'anp-wallet/select-active', walletId: walletAId, keyIndex: 1 })) as Resp
  assert(selActive.status === 'ok', 'select-active to A key1 failed')
  const idelA1 = (await bg({ type: 'anp-wallet/get-identity' })) as { did: string }
  assert(idelA1.did !== didA0, 'selecting key 1 should switch A to a different DID')

  // Delete the active key → activeKeyIndex clamps back to the remaining key.
  const delK = (await bg({ type: 'anp-wallet/delete-key', walletId: walletAId, keyIndex: 1 })) as Resp
  assert(delK.status === 'ok', 'delete-key failed')
  const stA2 = (await bg({ type: 'anp-wallet/get-state' })) as State
  const wApost = stA2.account.wallets.find((w) => w.id === walletAId)!
  assert(wApost.keys.length === 1, 'should have 1 key after delete')
  assert(wApost.activeKeyIndex === 0, 'activeKeyIndex should clamp back to 0')

  // Refuse to delete the last remaining key.
  const delKLast = (await bg({ type: 'anp-wallet/delete-key', walletId: walletAId, keyIndex: 0 })) as Resp
  assert(delKLast.status === 'error', 'should refuse deleting the last key')

  // =========================================================================
  // SCENARIO 3 — switch-then-sign correctness. The delivered signature's DID
  // MUST match the ACTIVE wallet, proving the right wallet mnemonic was used
  // (the "valid Ed25519 but wrong DID" regression we guard against).
  // =========================================================================
  const selB2 = (await bg({ type: 'anp-wallet/select-wallet', walletId: walletBId })) as Resp
  assert(selB2.status === 'ok', 'select-wallet B failed')
  const idelB2 = (await bg({ type: 'anp-wallet/get-identity' })) as { did: string; didDocument: Record<string, unknown> }
  assert(idelB2.did === didB0, 'active=B should give B DID')

  // Lock (fresh SW) → identity still readable → sign stages while locked.
  const locked = (await bg({ type: 'anp-wallet/lock' })) as Resp
  assert(locked.status === 'ok', 'lock failed')
  const identityLocked = (await bg({ type: 'anp-wallet/get-identity' })) as { did: string; didDocument: Record<string, unknown> }
  console.log('get-identity (locked) did:', identityLocked.did)
  assert(identityLocked.did === didB0, 'get-identity should work while locked')

  const body = JSON.stringify({ nonce, didDocument: idelB2.didDocument })
  const sign = (await bg({
    type: 'anp-wallet/sign',
    payload: { id: 'req-1', req: { url: TARGET, method: 'POST', body, nonce } },
  })) as Resp<{ id: string }>
  console.log('sign ack (locked):', sign.status, 'openPopup calls:', openPopupCalls)
  assert(sign.status === 'pending', 'expected pending even while locked')
  assert(openPopupCalls >= 1, 'expected openPopup() to fire')

  const unlocked = (await bg({ type: 'anp-wallet/unlock', password })) as Resp
  assert(unlocked.status === 'ok', 'unlock failed')
  const approved = (await bg({ type: 'anp-wallet/approve', id: 'req-1' })) as Resp
  assert(approved.status === 'ok', 'approve failed')
  const delivered = tabMessages.find((m) => m.id === 'req-1')
  assert(delivered && delivered.result, 'expected a delivered signature')
  const deliveredDid = (delivered!.result as { did: string }).did
  console.log('delivered did:', deliveredDid, '=== B did?', deliveredDid === didB0)
  assert(deliveredDid === didB0, `delivered signature DID ${deliveredDid} must equal active wallet B DID ${didB0}`)
  // Bug #1: the delivered signature carries the exact body it signed, whose inline
  // didDocument matches the signing key (not the page's pre-built body).
  const deliveredBody = (delivered!.result as { body: string }).body
  const parsedBody = JSON.parse(deliveredBody)
  assert(
    JSON.stringify(parsedBody.didDocument) === JSON.stringify((delivered!.result as { didDocument: Record<string, unknown> }).didDocument),
    'delivered body didDocument must match the signing key didDocument',
  )
  writeFileSync(
    '/tmp/anp-ext-signed.json',
    JSON.stringify(
      { request_method: 'POST', request_url: TARGET, didDocument: delivered!.result?.didDocument, headers: (delivered!.result as { headers: Record<string, string> }).headers, body: deliveredBody },
      null,
      2,
    ),
  )

  // =========================================================================
  // SCENARIO 3b — approve with `sel` self-select. Active is B, but the user
  // picks wallet A key 0 from the sign-approval chooser. The delivered signature
  // MUST carry A-key0's DID (didA0), NOT the active wallet's DID (didB0). This
  // proves the self-select path signs with the chosen key, not the active one.
  // =========================================================================
  const bodySel = JSON.stringify({ nonce, didDocument: idelB2.didDocument })
  const signSel = (await bg({
    type: 'anp-wallet/sign',
    payload: { id: 'req-sel', req: { url: TARGET, method: 'POST', body: bodySel, nonce } },
  })) as Resp<{ id: string }>
  assert(signSel.status === 'pending', 'sign (sel) should stage while unlocked')
  const approveSel = (await bg({
    type: 'anp-wallet/approve',
    id: 'req-sel',
    sel: { walletId: walletAId, keyIndex: 0 },
  })) as Resp
  assert(approveSel.status === 'ok', 'approve with sel failed')
  const deliveredSel = tabMessages.find((m) => m.id === 'req-sel')
  assert(deliveredSel && deliveredSel.result, 'expected a delivered signature for sel')
  const deliveredSelDid = (deliveredSel!.result as { did: string }).did
  console.log('delivered sel did:', deliveredSelDid, '=== A key0?', deliveredSelDid === didA0)
  assert(deliveredSelDid === didA0, `self-selected signature DID ${deliveredSelDid} must equal chosen A key0 DID ${didA0}`)
  // Bug #1: self-selecting a NON-active key must re-build the body so its inline
  // didDocument is the chosen key's — the page's original body (B's doc) must NOT
  // survive, otherwise the server can't resolve the keyid against it.
  const selBody = JSON.parse((deliveredSel!.result as { body: string }).body)
  assert(
    JSON.stringify(selBody.didDocument) === JSON.stringify((deliveredSel!.result as { didDocument: Record<string, unknown> }).didDocument),
    'self-selected body didDocument must be the chosen key, not the page body',
  )
  assert(
    (deliveredSel!.result as { didDocument: { id: string } }).didDocument.id === didA0,
    'self-selected body must carry A key0 didDocument',
  )

  // =========================================================================
  // SCENARIO 4 — register a key on a NON-active wallet. Proves the register
  // handler derives from the target wallet's mnemonic and switches active there.
  // =========================================================================
  const addKeyA2 = (await bg({ type: 'anp-wallet/add-key', walletId: walletAId })) as Resp<{ keyIndex: number }>
  assert(addKeyA2.status === 'ok' && addKeyA2.keyIndex === 1, 'add-key A for register failed')
  const stamp = Date.now().toString(36).slice(-6)
  // Bug #2: register now submits with the wallet's PRIMARY key (no keyIndex param).
  const reg = (await bg({
    type: 'anp-wallet/register',
    walletId: walletAId,
    handle: `bg-${stamp}`,
  })) as Resp<{ did: string; dids: string[] }>
  console.log('register (non-active A):', reg.status, reg.did ?? reg.error ?? '')
  assert(reg.status === 'ok', 'register on non-active wallet failed: ' + (reg.error ?? ''))
  assert(reg.did === didA0, `register must submit with the PRIMARY key (got ${reg.did}, expected ${didA0})`)
  assert(Array.isArray(reg.dids) && reg.dids.length === 2, 'register should return all DIDs under the handle')
  assert(reg.dids.includes(reg.did), 'register dids should include the submitting DID')
  const stReg = (await bg({ type: 'anp-wallet/get-state' })) as State
  assert(stReg.account.activeWalletId === walletAId, 'register should switch active to the registered wallet')
  assert(stReg.activeRef?.keyIndex === 0, 'register should set the PRIMARY key active')
  const wAreg = stReg.account.wallets.find((w) => w.id === walletAId)!
  assert(wAreg.primaryKeyIndex === 0, 'primary should remain key 0')
  // Aggregate model: one handle = ONE ad.json listing every key → all keys become
  // registered, and the wallet flips to handle-level `registered`.
  assert(wAreg.registered === true, 'register should write back wallet-level registered=true')
  assert(wAreg.keys.every((k) => k.registered === true), 'aggregate registration should mark every key registered')
  assert(wAreg.keys.every((k) => k.handle === `bg-${stamp}.localhost`), 'aggregate registration should write back handle to every key')
  const idelReg = (await bg({ type: 'anp-wallet/get-identity' })) as { did: string }
  assert(idelReg.did === reg.did, 'get-identity should return the newly registered DID')

  // =========================================================================
  // SCENARIO 4b — set-primary on a registered wallet re-binds ownership on the
  // server (member takeover) and lets the OLD primary be deleted afterward.
  // =========================================================================
  const setPri = (await bg({ type: 'anp-wallet/set-primary', walletId: walletAId, keyIndex: 1 })) as Resp
  console.log('set-primary A:', setPri.status, setPri.error ?? '')
  assert(setPri.status === 'ok', 'set-primary failed: ' + (setPri.error ?? ''))
  const stPri = (await bg({ type: 'anp-wallet/get-state' })) as State
  const wApri = stPri.account.wallets.find((w) => w.id === walletAId)!
  assert(wApri.primaryKeyIndex === 1, 'set-primary should move primary to key1')
  assert(wApri.registered === true, 'set-primary on a registered wallet should keep it registered')

  // Deleting the CURRENT primary (key1, while 2 keys still exist) is blocked.
  const delCurPri = (await bg({ type: 'anp-wallet/delete-key', walletId: walletAId, keyIndex: 1 })) as Resp
  assert(delCurPri.status === 'error' && delCurPri.error === '主密钥不能删除', 'current primary must not be deletable')

  // Deleting the OLD primary (key0, array pos 0) is now allowed.
  const delOldPri = (await bg({ type: 'anp-wallet/delete-key', walletId: walletAId, keyIndex: 0 })) as Resp
  assert(delOldPri.status === 'ok', 'deleting the old primary after a change should succeed')
  const stDelPri = (await bg({ type: 'anp-wallet/get-state' })) as State
  const wAdel = stDelPri.account.wallets.find((w) => w.id === walletAId)!
  assert(wAdel.keys.length === 1, 'should have 1 key after deleting the old primary')
  // key1 shifts to array pos 0; primary preindexes down to 0.
  assert(wAdel.primaryKeyIndex === 0, 'primary should reindex after a key before it is deleted')

  // =========================================================================
  // SCENARIO 5 — delete-wallet + rename + handle-less wallet + active fallback.
  // =========================================================================
  // Delete the NOT-active wallet → ok, active stays A.
  const delWb = (await bg({ type: 'anp-wallet/delete-wallet', walletId: walletBId })) as Resp
  assert(delWb.status === 'ok', 'delete-wallet B failed')
  const stDel = (await bg({ type: 'anp-wallet/get-state' })) as State
  assert(stDel.account.wallets.length === 1, 'should have 1 wallet after deleting B')
  assert(stDel.account.activeWalletId === walletAId, 'active should stay A after deleting non-active B')

  // Wallet labels are editable (Bug: 「钱包 1」was not renamable).
  const rename = (await bg({ type: 'anp-wallet/rename-wallet', walletId: walletAId, label: '主工作钱包' })) as Resp
  assert(rename.status === 'ok', 'rename-wallet failed')
  const stRen = (await bg({ type: 'anp-wallet/get-state' })) as State
  assert(stRen.account.wallets.find((w) => w.id === walletAId)?.label === '主工作钱包', 'wallet label should update after rename')

  // A wallet added WITHOUT a handle still owns its key0 (Bug: 「钱包 1」had no key0).
  const addNoHandle = (await bg({ type: 'anp-wallet/add-wallet', mnemonic: generateMnemonicPhrase(256) })) as Resp<{ walletId: string; keyIndex: number }>
  assert(addNoHandle.status === 'ok', 'add-wallet (no handle) failed')
  const stNH = (await bg({ type: 'anp-wallet/get-state' })) as State
  const nhWallet = stNH.account.wallets.find((w) => w.id === addNoHandle.walletId)!
  assert(nhWallet.keys.length === 1, 'a handle-less wallet must still have its key0')
  assert(addNoHandle.keyIndex === 0, 'handle-less wallet active key index should be 0')

  // Delete the ACTIVE (handle-less) wallet → falls back to remaining wallet[0] (A).
  const delActive = (await bg({ type: 'anp-wallet/delete-wallet', walletId: addNoHandle.walletId })) as Resp
  console.log('delete active wallet:', delActive.status, 'fallback active=', (stNH.activeRef?.walletId ?? '') || '(recompute)')
  assert(delActive.status === 'ok', 'delete-wallet active (no-handle) failed')
  const stFall = (await bg({ type: 'anp-wallet/get-state' })) as State
  assert(stFall.account.wallets.length === 1, 'should have 1 wallet after deleting active no-handle wallet')
  if (stFall.activeRef) assert(stFall.activeRef.walletId === walletAId, 'active should fall back to A')

  // =========================================================================
  // Optional: real-server login through the built background.
  // =========================================================================
  const BASE = process.env.AGWORLD_URL ?? 'http://localhost:3000'
  try {
    const { nonce: serverNonce } = await fetch(`${BASE}/api/login/anp/nonce`).then((r) => r.json())
    const realBody = JSON.stringify({ nonce: serverNonce, didDocument: idelB2.didDocument })
    const ack = (await bg({ type: 'anp-wallet/sign', payload: { id: 'req-2', req: { url: `${BASE}/api/login/anp/verify`, method: 'POST', body: realBody, nonce: serverNonce } } })) as Resp
    assert(ack.status === 'pending', 'sign staged for server login')
    await bg({ type: 'anp-wallet/approve', id: 'req-2' })
    const delivered2 = tabMessages.find((m) => m.id === 'req-2')!
    const headers = (delivered2.result as { headers: Record<string, string> }).headers
    const res = await fetch(`${BASE}/api/login/anp/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...headers },
      body: (delivered2.result as { body: string }).body,
    })
    const data = (await res.json().catch(() => ({}))) as { token?: string }
    console.log('server login (via built bg):', res.status, 'token present:', Boolean(data.token))
  } catch (e) {
    console.log('server e2e skipped/failed:', (e as Error).message)
  }

  // =========================================================================
  // SCENARIO 6 — the LAST wallet is deletable (Bug: everything must be deletable).
  // =========================================================================
  const delLast = (await bg({ type: 'anp-wallet/delete-wallet', walletId: walletAId })) as Resp
  assert(delLast.status === 'ok', 'deleting the last wallet should succeed')
  const stZero = (await bg({ type: 'anp-wallet/get-state' })) as State
  assert(stZero.account !== null && stZero.account.wallets.length === 0, 'should have 0 wallets after deleting the last one')
  assert(stZero.account.activeWalletId === null, 'activeWalletId should be null with 0 wallets')

  console.log('RESULT: PASS ✅ (v4 multi-wallet: migration + wallet/key mgmt + primary-key model + register-by-primary + set-primary re-register + delete-primary-block + wallet-owned login body + editable labels + handle-less key0 + deletable last wallet)')
}

main().catch((e) => {
  console.error('ERROR', e)
  process.exit(1)
})
