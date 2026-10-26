// Integration test: run the BUILT background service worker (dist/background.js)
// inside a VM with a mocked `chrome` + `fetch`, then drive the full v5 flow:
// migration, server registry, mnemonic/imported wallets, email + did_document
// registration, verify-existing, server rebind, legacy aggregate, and signing.
// This exercises the same built artifact the browser loads, not just the source.
import { readFileSync } from 'node:fs'
import vm from 'node:vm'
import { ed25519 } from '@noble/curves/ed25519'
import { sha256 } from '@noble/hashes/sha256'
import { utf8ToBytes } from '@noble/hashes/utils'
import { base58, base64, base64urlnopad } from '@scure/base'
import {
  buildAwikiIdentity,
  generateMnemonicPhrase,
  jcsCanonicalize,
  multibaseEd25519,
  parseEd25519PrivateKey,
  publicKeyFromPrivateKey,
} from '../src/lib/anp'
import { AWIKI_CLIENT_VERSION } from '../src/lib/awiki'

// ---- mock chrome -----------------------------------------------------------
let bgHandler: (msg: unknown, sender: unknown, sendResponse: (r: unknown) => void) => void = () => {}
const store = new Map<string, unknown>()
const sessionStore = new Map<string, unknown>()
// Simulates an open side panel that re-renders and acknowledges background pings.
let uiAcksPings = false
const tabMessages: { id: string; status: string; result?: Record<string, unknown>; error?: string }[] = []
let openPopupCalls = 0
let tabUpdated: (tabId: number, change: { status?: string }) => void = () => {}
let tabRemoved: (tabId: number) => void = () => {}
const deliveries: {tabId: number; options: {documentId: string; frameId: number}}[] = []

;(globalThis as unknown as { chrome: unknown }).chrome = {
  runtime: {
    id: 'audit-test-extension',
    getURL: (path: string) => `chrome-extension://audit-test-extension/${path}`,
    onMessage: { addListener: (h: typeof bgHandler) => (bgHandler = h) },
    onInstalled: { addListener: () => {} },
    sendMessage: (msg: { type?: string }) =>
      new Promise((resolve) => {
        const sender =
          msg?.type === 'anp-wallet/sign'
            ? { tab: { id: 7 }, documentId: 'page-document-7', frameId: 0, origin: 'http://localhost:3000', url: 'http://localhost:3000/' }
            : { id: 'audit-test-extension', url: 'chrome-extension://audit-test-extension/popup.html' }
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
    session: {
      get: async (key: string) => (sessionStore.has(key) ? { [key]: sessionStore.get(key) } : {}),
      set: async (obj: Record<string, unknown>) => {
        for (const k of Object.keys(obj)) sessionStore.set(k, obj[k])
        // An open side panel re-renders on the ping and writes the ack value.
        if (uiAcksPings && typeof obj.anp_ui_ping === 'number') {
          sessionStore.set('anp_ui_ack', obj.anp_ui_ping)
        }
      },
    },
  },
  permissions: {
    contains: async () => true,
    request: async () => true,
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
    onUpdated: { addListener: (fn: typeof tabUpdated) => { tabUpdated = fn } },
    onRemoved: { addListener: (fn: typeof tabRemoved) => { tabRemoved = fn } },
    sendMessage: async (tabId: number, m: (typeof tabMessages)[number], options: {documentId: string; frameId: number}) => {
      deliveries.push({tabId, options})
      tabMessages.push(m)
      return true
    },
  },
}

// ---- mock fetch / registration servers -------------------------------------
type Call = {
  url: string
  host: string
  path: string
  method: string
  headers: Record<string, string>
  body: any
}

const calls: Call[] = []
const didRegisters: Call[] = []
const aggregateRegisters: Call[] = []
const emailSends: Call[] = []
const lookups: Call[] = []

const MOCK_SERVICE: Record<string, unknown> = {
  id: 'did:wba:awiki.ai#anp-message',
  type: 'ANPMessageService',
  serviceEndpoint: 'https://awiki.ai/anp-im/rpc',
  serviceDid: 'did:wba:awiki.ai',
  profiles: ['anp.core.binding.v1', 'awiki.test.marker'],
  authSchemes: ['bearer', 'didwba'],
  securityProfiles: ['transport-protected'],
  mockUnknownField: { keep: 'verbatim' },
}

function serviceFor(didDomain: string): Record<string, unknown> {
  return {
    id: `did:wba:${didDomain}#anp-message`,
    type: 'ANPMessageService',
    serviceEndpoint: `https://${didDomain}/anp-im/rpc`,
    serviceDid: `did:wba:${didDomain}`,
    profiles: ['anp.core.binding.v1', `marker.${didDomain}`],
    authSchemes: ['bearer', 'didwba'],
    securityProfiles: ['transport-protected'],
    mockUnknownField: { domain: didDomain },
  }
}

const DISCOVERY: Record<string, { didDomain: string; service: Record<string, unknown> }> = {
  'awiki.ai': { didDomain: 'awiki.ai', service: MOCK_SERVICE },
  'reg.example.test': { didDomain: 'reg.example.test', service: serviceFor('reg.example.test') },
  'wrong.example.test': { didDomain: 'wrong.example.test', service: serviceFor('wrong.example.test') },
  'mismatch.example.test': { didDomain: 'other.test', service: serviceFor('other.test') },
}

const emailVerified = new Set<string>()
let lookupMode: 'match' | 'mismatch' | 'missing' | 'unsupported' = 'match'
let lookupDid = ''

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

function parseBody(init?: RequestInit): any {
  const raw = typeof init?.body === 'string' ? init.body : ''
  if (!raw) return undefined
  try {
    return JSON.parse(raw)
  } catch {
    return raw
  }
}

function headersOf(init?: RequestInit): Record<string, string> {
  const out: Record<string, string> = {}
  new Headers(init?.headers).forEach((value, key) => {
    out[key.toLowerCase()] = value
  })
  return out
}

function requestUrl(input: RequestInfo | URL): string {
  if (typeof input === 'string') return input
  if (input instanceof URL) return input.href
  return input.url
}

globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
  const raw = requestUrl(input)
  const url = new URL(raw)
  const host = url.hostname
  const call: Call = {
    url: raw,
    host,
    path: url.pathname,
    method: (init?.method ?? 'GET').toUpperCase(),
    headers: headersOf(init),
    body: parseBody(init),
  }
  calls.push(call)

  if (call.path === '/.well-known/did.json') {
    const found = DISCOVERY[host]
    if (!found) return new Response('not found', { status: 404, headers: { 'content-type': 'text/plain' } })
    return json({ id: `did:wba:${found.didDomain}`, service: [found.service] })
  }

  if (call.path === '/user-service/v1/auth/email-status') {
    if (host !== 'awiki.ai') {
      return new Response('not found', { status: 404, headers: { 'content-type': 'text/plain' } })
    }
    const email = (url.searchParams.get('email') ?? '').toLowerCase()
    const handle = url.searchParams.get('handle') ?? ''
    const verified = emailVerified.has(`${email}|${handle}`)
    return json(verified ? { verified: true, verified_at: '2026-10-26T00:00:00Z' } : { verified: false })
  }

  if (call.path === '/user-service/v1/auth/email-send') {
    if (host !== 'awiki.ai') {
      return new Response('not found', { status: 404, headers: { 'content-type': 'text/plain' } })
    }
    emailSends.push(call)
    return json({ message: 'verification email sent' })
  }

  if (call.path === '/user-service/v1/did-auth/rpc') {
    const rpc = call.body ?? {}
    if (rpc.method === 'challenge') {
      return json({
        jsonrpc: '2.0',
        id: rpc.id,
        result: {
          challenge: 'c'.repeat(32),
          created_at: '2026-10-26T00:00:00Z',
          expires_at: '2026-10-26T00:05:00Z',
          expires_in: 300,
        },
      })
    }
    if (rpc.method === 'register') {
      const params = rpc.params ?? {}
      if (params.did_document) {
        const doc = params.did_document as Record<string, unknown>
        if (!doc.deviceManifest) {
          // awiki release 0714: no manifest, no registration (error seen live).
          return json({
            jsonrpc: '2.0',
            id: rpc.id,
            error: {
              code: -32004,
              message: 'awiki register: Release 0714 registration requires a one-device Manifest.',
            },
          })
        }
        assertDeviceManifest(doc)
        assertDocumentProof(doc)
        didRegisters.push(call)
        return json({
          jsonrpc: '2.0',
          id: rpc.id,
          result: {
            state: 'registered',
            did: params.did_document.id,
            user_id: 'user-1',
            access_token: 'secret-token',
            handle: params.handle,
            domain: host,
            full_handle: `${params.handle}.${host}`,
            binding_generation: 1,
          },
        })
      }
      aggregateRegisters.push(call)
      return json({
        jsonrpc: '2.0',
        id: rpc.id,
        result: {
          did: params.submitting_did,
          dids: params.ad?.dids,
          access_token: 'legacy-token',
          user_id: 'legacy-user',
        },
      })
    }
    return json({ jsonrpc: '2.0', id: rpc.id, error: { code: -32601, message: 'method_not_found' } })
  }

  if (call.path === '/user-service/v1/handle/rpc') {
    lookups.push(call)
    if (lookupMode === 'unsupported') {
      return new Response('not found', { status: 404, headers: { 'content-type': 'text/plain' } })
    }
    const rpc = call.body ?? {}
    if (lookupMode === 'missing') {
      return json({ jsonrpc: '2.0', id: rpc.id, error: { code: -32001, message: 'not_found' } })
    }
    const did =
      lookupMode === 'match' ? lookupDid : 'did:wba:awiki.ai:user:someone-else:e1_not-the-key'
    return json({
      jsonrpc: '2.0',
      id: rpc.id,
      result: {
        did,
        user_id: 'user-existing',
        handle: rpc.params?.handle,
        full_handle: rpc.params?.handle,
        status: 'active',
      },
    })
  }

  return json({ error: 'not found' }, 404)
}) as typeof fetch

// ---- load the built worker --------------------------------------------------
const src = readFileSync(new URL('../dist/background.js', import.meta.url), 'utf8')
vm.runInThisContext(src, { filename: 'background.js' })

// ---- test helpers -----------------------------------------------------------
const password = 'correct-horse-battery'
const mnemonicA =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
const TARGET = 'http://localhost:3000/api/login/anp/verify'
const nonce = 'f'.repeat(32)
const stamp = Date.now().toString(36).slice(-6)

type Resp<T = Record<string, unknown>> = T & { status: string; error?: string }
interface KeyLike {
  index: number
  handle: string
  did: string
  keyid: string
  publicKeyMultibase: string
  didDocument: Record<string, unknown>
  registered?: boolean
  accessToken?: string
}
interface WalletLike {
  kind: string
  id: string
  label: string
  handle: string
  salt: string
  iv: string
  ciphertext: string
  nextKeyIndex: number
  activeKeyIndex: number
  primaryKeyIndex: number
  keys: KeyLike[]
  registered?: boolean
  userId?: string
  handleDocuments?: Record<string, unknown>
  serverId: string | null
  didDomain: string
  registerMode?: string
}
interface AccountLike {
  version: number
  wallets: WalletLike[]
  activeWalletId: string | null
}
interface ServerLike {
  id: string
  label: string
  rpcBase: string
  didDomain: string
  builtin?: boolean
  registerMode?: string
}
interface StateLike {
  status: string
  unlocked: boolean
  account: AccountLike | null
  activeRef: { walletId: string; keyIndex: number } | null
  pending: unknown[]
  servers: ServerLike[]
  defaultServerId: string
  autoLockMinutes: number
}

const assert = (cond: unknown, msg: string) => {
  if (!cond) throw new Error('ASSERT FAILED: ' + msg)
}
const eq = <T>(actual: T, expected: T, msg: string) => {
  if (actual !== expected) {
    throw new Error(`ASSERT FAILED: ${msg}: got ${JSON.stringify(actual)}, expected ${JSON.stringify(expected)}`)
  }
}
const eqJson = (actual: unknown, expected: unknown, msg: string) => {
  eq(JSON.stringify(actual), JSON.stringify(expected), msg)
}
const must = <T>(value: T | null | undefined, msg: string): T => {
  assert(value != null, msg)
  return value as T
}
const assertThrows = (fn: () => unknown, substr: string, msg: string) => {
  try {
    fn()
  } catch (e) {
    const text = e instanceof Error ? e.message : String(e)
    assert(text.includes(substr), `${msg}: unexpected error "${text}" (wanted "${substr}")`)
    return
  }
  throw new Error('ASSERT FAILED: ' + msg + ' (no error thrown)')
}

async function waitFor(cond: () => boolean, msg: string, timeoutMs = 3000): Promise<void> {
  const until = Date.now() + timeoutMs
  while (Date.now() < until) {
    if (cond()) return
    await new Promise((resolve) => setTimeout(resolve, 25))
  }
  throw new Error('ASSERT FAILED: ' + msg)
}

/**
 * Every stored DID document must be a valid one-device manifest document with
 * a proof over the whole document, and must contain only public key material.
 */
function assertStoredDocumentsSafe(account: AccountLike): number {
  let checked = 0
  for (const wallet of account.wallets) {
    const doc = wallet.handleDocuments
    if (!doc || !doc.deviceManifest) continue
    checked++
    assertDeviceManifest(doc)
    assertDocumentProof(doc)
    const docText = JSON.stringify(doc)
    assert(!docText.includes('privateKey'), 'stored DID document has no private key field')
    assert(!/\{"kty":"[^"]*","crv":[^}]*"d":/.test(docText), 'stored DID document has no JWK private scalar')
  }
  return checked
}

function decodeMultibase(value: unknown, msg: string): Uint8Array {
  const text = String(value)
  assert(text.startsWith('z'), `${msg}: publicKeyMultibase must be base58btc`)
  return base58.decode(text.slice(1))
}

/**
 * Mirror the awiki/ANP one-device manifest contract locally. Production
 * (release 0714) rejects registration documents without exactly one device, so
 * the mock register route enforces the same shape instead of accepting any doc.
 */
function assertDeviceManifest(doc: Record<string, unknown>): void {
  const manifest = must(
    doc.deviceManifest as { type?: unknown; devices?: Record<string, unknown>[] } | undefined,
    'DID document declares a deviceManifest',
  )
  eq(manifest.type, 'ANPDeviceManifest', 'device manifest type')
  eq(manifest.devices?.length, 1, 'manifest declares exactly one device')
  const device = must(manifest.devices?.[0], 'manifest device entry')
  eqJson(
    Object.keys(device).sort(),
    ['device_id', 'e2ee_key_id', 'profiles', 'signing_key_id'],
    'device entry has only the closed ANP fields',
  )
  assert(typeof device.device_id === 'string' && device.device_id.length > 0, 'device_id non-empty')
  const profiles = device.profiles as string[]
  assert(Array.isArray(profiles) && profiles.length > 0, 'device profiles non-empty')
  eqJson(
    profiles,
    [
      'anp.core.binding.v1',
      'anp.identity.discovery.v1',
      'anp.direct.base.v1',
      'anp.direct.e2ee.v2',
      'anp.group.base.v2',
      'anp.group.e2ee.v2',
    ],
    'device declares the canonical vNext WBA profile bundle',
  )

  const did = String(doc.id)
  const rootId = `${did}#key-1`
  assert(device.signing_key_id !== rootId, 'device signing key is not the root key')
  assert(device.e2ee_key_id !== rootId, 'device e2ee key is not the root key')
  assert(device.signing_key_id !== device.e2ee_key_id, 'device signing and e2ee keys differ')

  const methods = doc.verificationMethod as Record<string, unknown>[]
  eq(methods.length, 3, 'document has root, device signing and device e2ee methods')
  const byId = new Map(methods.map((m) => [String(m.id), m]))
  const root = must(byId.get(rootId), 'root verification method')
  const signing = must(byId.get(String(device.signing_key_id)), 'device signing method')
  const e2ee = must(byId.get(String(device.e2ee_key_id)), 'device e2ee method')
  for (const method of [root, signing, e2ee]) eq(method.controller, did, 'method controller is the DID')
  assert(!('publicKeyJwk' in root), 'root key has no JWK private material')

  const rootKey = decodeMultibase(root.publicKeyMultibase, 'root')
  const signingKey = decodeMultibase(signing.publicKeyMultibase, 'device signing')
  const e2eeKey = decodeMultibase(e2ee.publicKeyMultibase, 'device e2ee')
  eq(rootKey.length, 34, 'root multikey length')
  eq(signingKey.length, 34, 'device signing multikey length')
  eq(e2eeKey.length, 34, 'device e2ee multikey length')
  eq(rootKey[0], 0xed, 'root is Ed25519')
  eq(rootKey[1], 0x01, 'root multicodec')
  eq(signingKey[0], 0xed, 'device signing is Ed25519')
  eq(signingKey[1], 0x01, 'device signing multicodec')
  eq(e2eeKey[0], 0xec, 'device e2ee is X25519')
  eq(e2eeKey[1], 0x01, 'device e2ee multicodec')
  const materials = [rootKey, signingKey, e2eeKey].map((b) => seedHex(b.slice(2)))
  eq(new Set(materials).size, 3, 'root/device signing/e2ee public material are distinct')

  eqJson(doc.authentication, [rootId, device.signing_key_id], 'authentication binds root + device signing')
  eqJson(doc.assertionMethod, [rootId, device.signing_key_id], 'assertionMethod binds root + device signing')
  eqJson(doc.keyAgreement, [device.e2ee_key_id], 'keyAgreement references only the device e2ee key')
}

/** Verify the eddsa-jcs-2022 proof over the final document (including manifest). */
function assertDocumentProof(doc: Record<string, unknown>): void {
  const proof = must(doc.proof as Record<string, unknown> | undefined, 'document proof')
  const proofValue = String(proof.proofValue)
  assert(proofValue.startsWith('z'), 'proofValue is base58btc multibase')
  const vmId = String(proof.verificationMethod)
  const vm = must(
    (doc.verificationMethod as Record<string, unknown>[]).find((m) => m.id === vmId),
    'proof verification method resolves',
  )
  const publicKey = decodeMultibase(vm.publicKeyMultibase, 'proof key')
  eq(publicKey[0], 0xed, 'proof key is Ed25519')

  const { proofValue: _proofValue, ...proofFields } = proof
  const unsigned: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(doc)) if (key !== 'proof') unsigned[key] = value
  // ANP's eddsa-jcs-2022 verifier folds @context into the proof configuration
  // for multibase proofValue; reproduce that when checking the signature.
  const options: Record<string, unknown> = { ...proofFields }
  if (unsigned['@context'] !== undefined) options['@context'] = unsigned['@context']
  const input = new Uint8Array(64)
  input.set(sha256(utf8ToBytes(jcsCanonicalize(options))), 0)
  input.set(sha256(utf8ToBytes(jcsCanonicalize(unsigned))), 32)
  const signature = base58.decode(proofValue.slice(1))
  assert(ed25519.verify(signature, input, publicKey.slice(2)), 'document proof verifies over the manifest')
}

async function bg<T = any>(msg: Record<string, unknown>): Promise<T> {
  return (await chrome.runtime.sendMessage(msg)) as T
}

function stateAccount(state: StateLike): AccountLike {
  return must(state.account, 'expected an account')
}
function walletFrom(state: StateLike, id: string): WalletLike {
  return must(stateAccount(state).wallets.find((w) => w.id === id), `wallet ${id} missing`)
}
function rawAccount(): AccountLike {
  return must(store.get('anp_account') as AccountLike | undefined, 'raw account missing')
}
function rawJson(): string {
  return JSON.stringify(store.get('anp_account'))
}
function testSeed(n: number): Uint8Array {
  return Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + n * 13 + 1) & 0xff)
}
function seedHex(seed: Uint8Array): string {
  return Array.from(seed, (b) => b.toString(16).padStart(2, '0')).join('')
}
function seedKey(seed: Uint8Array): string {
  return Array.from(seed).join(',')
}
function concatSeedPub(seed: Uint8Array): Uint8Array {
  const pub = publicKeyFromPrivateKey(seed)
  const out = new Uint8Array(64)
  out.set(seed, 0)
  out.set(pub, 32)
  return out
}
function hasNoSecret(json: string, seed: Uint8Array, label: string): void {
  assert(!json.includes(seedHex(seed)), `${label}: account must not contain hex seed`)
  assert(!json.includes(base64.encode(seed)), `${label}: account must not contain base64 seed`)
  assert(!json.includes(base64urlnopad.encode(seed)), `${label}: account must not contain base64url seed`)
  assert(!json.includes('z' + base58.encode(seed)), `${label}: account must not contain base58 seed`)
}
function serviceIn(doc: Record<string, unknown>): Record<string, unknown> {
  const services = Array.isArray(doc.service) ? (doc.service as Record<string, unknown>[]) : []
  eq(services.filter((s) => s.type === 'ANPMessageService').length, 1, 'exactly one ANPMessageService')
  return services.find((s) => s.type === 'ANPMessageService') as Record<string, unknown>
}
function expectedService(mock: Record<string, unknown>, did: string): Record<string, unknown> {
  return { ...mock, id: `${did}#message`, type: 'ANPMessageService' }
}
function assertVersionHeader(call: Call, label: string): void {
  eq(call.headers['x-awiki-client-version'], AWIKI_CLIENT_VERSION, `${label}: client version header`)
}

async function main() {
  // =========================================================================
  // 0. Packaging: the UI ships as the side panel, not a transient popup.
  // =========================================================================
  const builtManifest = JSON.parse(
    readFileSync(new URL('../dist/manifest.json', import.meta.url), 'utf8'),
  ) as {
    side_panel?: { default_path?: string }
    action?: { default_popup?: string }
    permissions?: string[]
  }
  eq(builtManifest.side_panel?.default_path, 'popup.html', 'built manifest declares the side panel UI')
  assert(!builtManifest.action?.default_popup, 'action click opens the side panel, not a popup')
  assert((builtManifest.permissions ?? []).includes('sidePanel'), 'sidePanel permission declared')

  // =========================================================================
  // 1. v4 → v5 migration: server binding, kind, aggregate inference, token drop.
  // =========================================================================
  const v4 = {
    version: 4,
    activeWalletId: 'w-awiki',
    wallets: [
      {
        id: 'w-awiki',
        label: 'awiki',
        handle: 'alice.awiki.ai',
        salt: 'c2FsdA',
        iv: 'aXY',
        ciphertext: 'Y2lwaGVydGV4dA',
        nextKeyIndex: 1,
        activeKeyIndex: 0,
        primaryKeyIndex: 0,
        registered: true,
        handleDocuments: { type: 'ANPDIDDocument', id: 'did:wba:awiki.ai:user:alice:e1_a' },
        keys: [
          {
            index: 0,
            handle: 'alice.awiki.ai',
            did: 'did:wba:awiki.ai:user:alice:e1_a',
            keyid: 'did:wba:awiki.ai:user:alice:e1_a#key-1',
            publicKeyMultibase: 'zA',
            didDocument: {},
            registered: true,
            accessToken: 'stale-token',
          },
        ],
      },
      {
        id: 'w-local',
        label: 'local',
        handle: '',
        salt: 'c2FsdA',
        iv: 'aXY',
        ciphertext: 'Y2lwaGVydGV4dA',
        nextKeyIndex: 1,
        activeKeyIndex: 0,
        primaryKeyIndex: 0,
        keys: [
          {
            index: 0,
            handle: 'local.localhost',
            did: 'did:wba:localhost:user:local:e1_b',
            keyid: 'did:wba:localhost:user:local:e1_b#key-1',
            publicKeyMultibase: 'zB',
            didDocument: {},
          },
        ],
      },
      {
        id: 'w-agg',
        label: 'aggregate',
        handle: 'agg.localhost',
        salt: 'c2FsdA',
        iv: 'aXY',
        ciphertext: 'Y2lwaGVydGV4dA',
        nextKeyIndex: 1,
        activeKeyIndex: 0,
        primaryKeyIndex: 0,
        registered: true,
        handleDocuments: { type: 'ANPHandleAggregate', dids: ['did:wba:localhost:user:agg:e1_c'] },
        keys: [
          {
            index: 0,
            handle: 'agg.localhost',
            did: 'did:wba:localhost:user:agg:e1_c',
            keyid: 'did:wba:localhost:user:agg:e1_c#key-1',
            publicKeyMultibase: 'zC',
            didDocument: {},
            registered: true,
          },
        ],
      },
    ],
  }
  store.set('anp_account', v4)
  const mig = await bg<StateLike>({ type: 'anp-wallet/get-state' })
  eq(stateAccount(mig).version, 5, 'migration must produce version 5')
  const mAwiki = walletFrom(mig, 'w-awiki')
  const mLocal = walletFrom(mig, 'w-local')
  const mAgg = walletFrom(mig, 'w-agg')
  eq(mAwiki.kind, 'mnemonic', 'migrated wallet kind')
  eq(mAwiki.didDomain, 'awiki.ai', 'awiki wallet DID domain')
  eq(mAwiki.serverId, 'awiki.ai', 'awiki wallet binds builtin server')
  eq(mAwiki.registerMode, 'did_document', 'awiki wallet register mode')
  eq(mLocal.didDomain, 'localhost', 'localhost wallet DID domain')
  eq(mLocal.serverId, null, 'localhost wallet has no server')
  eq(mAgg.registerMode, 'aggregate', 'legacy aggregate inferred from handleDocuments')
  eq(mAgg.serverId, null, 'aggregate wallet uses internal legacy server')
  assert(!('accessToken' in mAwiki.keys[0]), 'migration must strip key accessToken')
  assert(!rawJson().includes('accessToken'), 'stored account must not contain accessToken')
  console.log('migration v4→v5: ok')
  store.clear()

  // =========================================================================
  // 2. Server registry CRUD.
  // =========================================================================
  let st = await bg<StateLike>({ type: 'anp-wallet/get-state' })
  eq(st.servers.length, 1, 'registry starts with only builtin awiki')
  eq(st.defaultServerId, 'awiki.ai', 'default server starts awiki.ai')
  assert(st.servers[0].builtin === true, 'builtin flag')

  const badScheme = await bg<Resp>({ type: 'anp-wallet/add-server', rpcBase: 'http://reg.example.test', didDomain: 'reg.example.test' })
  eq(badScheme.status, 'error', 'http server rejected')
  assert(must(badScheme.error, 'error text').includes('HTTPS'), 'http rejection mentions HTTPS')

  const add1 = await bg<Resp<{ server: ServerLike }>>({
    type: 'anp-wallet/add-server',
    rpcBase: 'https://reg.example.test/',
    didDomain: 'reg.example.test',
    label: 'Reg',
  })
  eq(add1.status, 'ok', 'add custom HTTPS server')
  const custom1 = must(add1.server, 'added server')
  eq(custom1.rpcBase, 'https://reg.example.test', 'rpcBase normalized without trailing slash')
  eq(custom1.didDomain, 'reg.example.test', 'custom DID domain')

  const dup = await bg<Resp>({
    type: 'anp-wallet/add-server',
    rpcBase: 'https://reg.example.test',
    didDomain: 'reg.example.test',
  })
  eq(dup.status, 'error', 'duplicate rpcBase rejected')

  const tested = await bg<Resp<{ didDomain: string; source: string }>>({
    type: 'anp-wallet/test-server',
    serverId: custom1.id,
  })
  eq(tested.status, 'ok', 'test-server discovery')
  eq(tested.didDomain, 'reg.example.test', 'discovered custom domain')
  eq(tested.source, 'well-known', 'discovery source')

  const addWrong = await bg<Resp<{ server: ServerLike }>>({
    type: 'anp-wallet/add-server',
    rpcBase: 'https://wrong.example.test',
    didDomain: 'wrong.example.test',
  })
  const wrongServer = must(addWrong.server, 'wrong server')
  const addMismatch = await bg<Resp<{ server: ServerLike }>>({
    type: 'anp-wallet/add-server',
    rpcBase: 'https://mismatch.example.test',
    didDomain: 'mismatch.example.test',
  })
  const mismatchServer = must(addMismatch.server, 'mismatch server')
  const wrongTest = await bg<Resp>({ type: 'anp-wallet/test-server', serverId: mismatchServer.id })
  eq(wrongTest.status, 'error', 'discovered domain mismatch rejected')
  assert(must(wrongTest.error, 'mismatch error').includes('不一致'), 'mismatch error explains domain')

  const setCustom = await bg<Resp>({ type: 'anp-wallet/set-default-server', serverId: custom1.id })
  eq(setCustom.status, 'ok', 'set custom default')
  const delBuiltin = await bg<Resp>({ type: 'anp-wallet/remove-server', serverId: 'awiki.ai' })
  eq(delBuiltin.status, 'error', 'builtin server cannot be deleted')
  const delDefaultCustom = await bg<Resp>({ type: 'anp-wallet/remove-server', serverId: custom1.id })
  eq(delDefaultCustom.status, 'ok', 'custom default server removable')
  st = await bg<StateLike>({ type: 'anp-wallet/get-state' })
  eq(st.defaultServerId, 'awiki.ai', 'deleting default custom falls back to awiki')

  const add2 = await bg<Resp<{ server: ServerLike }>>({
    type: 'anp-wallet/add-server',
    rpcBase: 'https://reg.example.test',
    didDomain: 'reg.example.test',
    label: 'Reg',
  })
  const custom2 = must(add2.server, 're-added custom server')
  const customServerId = custom2.id
  await bg({ type: 'anp-wallet/remove-server', serverId: wrongServer.id })
  await bg({ type: 'anp-wallet/remove-server', serverId: mismatchServer.id })
  st = await bg<StateLike>({ type: 'anp-wallet/get-state' })
  eq(st.servers.length, 2, 'registry keeps builtin + custom')
  eq(st.defaultServerId, 'awiki.ai', 'default back to awiki')
  console.log('server registry: ok')

  // =========================================================================
  // 3. Mnemonic wallet creation, derivation, export.
  // =========================================================================
  const created = await bg<Resp<{ did: string }>>({
    type: 'anp-wallet/create-account',
    source: 'mnemonic',
    mnemonic: mnemonicA,
    password,
  })
  eq(created.status, 'ok', 'create mnemonic account')
  st = await bg<StateLike>({ type: 'anp-wallet/get-state' })
  const walletAId = must(stateAccount(st).activeWalletId, 'active wallet after create')
  let walletA = walletFrom(st, walletAId)
  eq(walletA.kind, 'mnemonic', 'wallet A kind')
  eq(walletA.didDomain, 'awiki.ai', 'wallet A domain')
  eq(walletA.serverId, 'awiki.ai', 'wallet A server')
  eq(walletA.keys.length, 1, 'wallet A has key 0')
  eq(walletA.nextKeyIndex, 1, 'wallet A nextKeyIndex')
  assert(walletA.keys[0].did.includes(walletAId.slice(0, 8)), 'placeholder handle uses wallet id prefix')
  assert(!rawJson().includes(mnemonicA), 'stored account must not contain plaintext mnemonic')

  const addKeyA1 = await bg<Resp<{ keyIndex: number }>>({ type: 'anp-wallet/add-key', walletId: walletAId })
  eq(addKeyA1.status, 'ok', 'add second key to mnemonic wallet')
  eq(addKeyA1.keyIndex, 1, 'second key array position')

  const exportA = await bg<Resp<{ kind: string; mnemonic: string }>>({ type: 'anp-wallet/export-secret' })
  eq(exportA.status, 'ok', 'export mnemonic wallet')
  eq(exportA.kind, 'mnemonic', 'export kind mnemonic')
  eq(exportA.mnemonic, mnemonicA, 'export returns the mnemonic')
  console.log('mnemonic wallet: ok')

  // =========================================================================
  // 4. Ed25519 import parser across encodings.
  // =========================================================================
  const seedB = testSeed(2)
  eq(seedKey(parseEd25519PrivateKey(seedHex(seedB)).seed), seedKey(seedB), 'hex seed')
  eq(seedKey(parseEd25519PrivateKey('0x' + seedHex(seedB)).seed), seedKey(seedB), '0x hex seed')
  eq(seedKey(parseEd25519PrivateKey(base64.encode(seedB)).seed), seedKey(seedB), 'base64 seed')
  eq(seedKey(parseEd25519PrivateKey(base64urlnopad.encode(seedB)).seed), seedKey(seedB), 'base64url seed')
  eq(seedKey(parseEd25519PrivateKey('z' + base58.encode(seedB)).seed), seedKey(seedB), 'base58 seed')
  const jwkB = JSON.stringify({
    kty: 'OKP',
    crv: 'Ed25519',
    d: base64urlnopad.encode(seedB),
    x: base64urlnopad.encode(publicKeyFromPrivateKey(seedB)),
  })
  eq(seedKey(parseEd25519PrivateKey(jwkB).seed), seedKey(seedB), 'JWK seed')
  const seedPubB = concatSeedPub(seedB)
  eq(seedKey(parseEd25519PrivateKey(seedHex(seedPubB)).seed), seedKey(seedB), '64-byte seed||pub')
  eq(seedKey(parseEd25519PrivateKey(base64.encode(seedPubB)).seed), seedKey(seedB), '64-byte base64')
  assertThrows(() => parseEd25519PrivateKey(base64urlnopad.encode(new Uint8Array(31))), '无法识别私钥格式', '31-byte key rejected')
  assertThrows(
    () => parseEd25519PrivateKey(JSON.stringify({ kty: 'OKP', crv: 'X25519', d: base64urlnopad.encode(seedB) })),
    'Ed25519',
    'non-Ed25519 JWK rejected',
  )
  const mismatched = seedPubB.slice()
  mismatched[63] ^= 0xff
  assertThrows(() => parseEd25519PrivateKey(seedHex(mismatched)), '不一致', 'mismatched 64-byte key rejected')
  console.log('import parser: ok')

  // =========================================================================
  // 5. Imported wallet: create, secrets at rest, key add/delete, export.
  // =========================================================================
  const addB = await bg<Resp<{ walletId: string; keyIndex: number }>>({
    type: 'anp-wallet/add-wallet',
    source: 'imported',
    privateKey: '0x' + seedHex(seedB),
    label: 'Imported',
  })
  eq(addB.status, 'ok', 'create imported wallet')
  const walletBId = addB.walletId
  const pubB = publicKeyFromPrivateKey(seedB)
  st = await bg<StateLike>({ type: 'anp-wallet/get-state' })
  let walletB = walletFrom(st, walletBId)
  eq(walletB.kind, 'imported', 'wallet B kind')
  eq(walletB.keys.length, 1, 'wallet B key count')
  eq(walletB.keys[0].publicKeyMultibase, multibaseEd25519(pubB), 'wallet B derived public key')
  hasNoSecret(rawJson(), seedB, 'wallet B create')

  const exportB = await bg<Resp<{ kind: string; keys: { index: number; privateKey: string }[] }>>({
    type: 'anp-wallet/export-secret',
  })
  eq(exportB.status, 'ok', 'export imported wallet')
  eq(exportB.kind, 'imported', 'export kind imported')
  eq(exportB.keys.length, 1, 'exported key count')
  eq(exportB.keys[0].index, 0, 'exported key index')
  eq(exportB.keys[0].privateKey, base64urlnopad.encode(seedB), 'exported seed')

  const seedC = testSeed(3)
  const addKeyB1 = await bg<Resp<{ keyIndex: number }>>({
    type: 'anp-wallet/add-key',
    walletId: walletBId,
    privateKey: seedHex(seedC),
  })
  eq(addKeyB1.status, 'ok', 'add imported key')
  eq(addKeyB1.keyIndex, 1, 'imported key array position')
  st = await bg<StateLike>({ type: 'anp-wallet/get-state' })
  walletB = walletFrom(st, walletBId)
  eq(walletB.keys.length, 2, 'wallet B now has two keys')
  eq(walletB.nextKeyIndex, 2, 'wallet B nextKeyIndex after import')
  hasNoSecret(rawJson(), seedC, 'wallet B add-key')

  const dupKey = await bg<Resp>({ type: 'anp-wallet/add-key', walletId: walletBId, privateKey: seedHex(seedC) })
  eq(dupKey.status, 'error', 'duplicate imported key rejected')
  assert(must(dupKey.error, 'dup error').includes('已在此钱包'), 'duplicate message')

  const cipherBefore = walletB.ciphertext
  const delKeyB = await bg<Resp>({ type: 'anp-wallet/delete-key', walletId: walletBId, keyIndex: 1 })
  eq(delKeyB.status, 'ok', 'delete imported key')
  st = await bg<StateLike>({ type: 'anp-wallet/get-state' })
  walletB = walletFrom(st, walletBId)
  eq(walletB.keys.length, 1, 'one key after delete')
  assert(walletB.ciphertext !== cipherBefore, 'delete re-encrypts the imported secret blob')
  hasNoSecret(rawJson(), seedB, 'wallet B after delete')
  assert(!rawJson().includes(base64urlnopad.encode(seedC)), 'deleted imported seed removed from blob')

  const mnemonicKey = await bg<Resp>({ type: 'anp-wallet/add-key', walletId: walletAId, privateKey: seedHex(seedB) })
  eq(mnemonicKey.status, 'error', 'mnemonic wallet rejects imported key')
  assert(must(mnemonicKey.error, 'mnemonic key error').includes('助记词钱包'), 'mnemonic key error message')

  await bg({ type: 'anp-wallet/lock' })
  const exportLocked = await bg<Resp>({ type: 'anp-wallet/export-secret' })
  eq(exportLocked.status, 'error', 'export while locked fails')
  eq(exportLocked.error, 'Locked', 'locked export error')
  const unlockB = await bg<Resp>({ type: 'anp-wallet/unlock', password })
  eq(unlockB.status, 'ok', 'unlock imported wallet')
  console.log('imported wallet: ok')

  // =========================================================================
  // 6. verify-existing: match, DID mismatch, missing, unsupported.
  // =========================================================================
  const didRegistersBeforeVerify = didRegisters.length
  const emailSendsBeforeVerify = emailSends.length
  const localMatch = `ve-${stamp}`
  const fullMatch = `${localMatch}.awiki.ai`
  const candidateB = buildAwikiIdentity(fullMatch, seedB, 'awiki.ai')
  lookupMode = 'match'
  lookupDid = candidateB.did
  const verifiedB = await bg<Resp<{ did: string; fullHandle: string }>>({
    type: 'anp-wallet/verify-existing',
    walletId: walletBId,
    handle: localMatch,
  })
  eq(verifiedB.status, 'ok', 'verify-existing success')
  eq(verifiedB.did, candidateB.did, 'verified DID matches the imported key')
  eq(verifiedB.fullHandle, fullMatch, 'verified full handle')
  st = await bg<StateLike>({ type: 'anp-wallet/get-state' })
  walletB = walletFrom(st, walletBId)
  eq(walletB.registered, true, 'wallet marked registered after verify')
  eq(walletB.userId, 'user-existing', 'verify-existing persists the server account id')
  eq(walletB.handle, fullMatch, 'wallet handle after verify')
  eq(walletB.keys[0].registered, true, 'primary key registered')
  eq(walletB.keys[0].did, candidateB.did, 'DID re-minted with the handle')
  eq(walletB.activeKeyIndex, 0, 'verified wallet activates its primary')
  eq(didRegisters.length, didRegistersBeforeVerify, 'verify-existing must not call register')
  eq(emailSends.length, emailSendsBeforeVerify, 'verify-existing must not send email')
  const verifiedBDid = verifiedB.did

  async function addImported(seed: Uint8Array, label: string): Promise<string> {
    const added = await bg<Resp<{ walletId: string }>>({
      type: 'anp-wallet/add-wallet',
      source: 'imported',
      privateKey: seedHex(seed),
      label,
    })
    eq(added.status, 'ok', `add imported wallet ${label}`)
    return added.walletId
  }

  const mismatchWallet = await addImported(testSeed(4), 'Mismatch')
  lookupMode = 'mismatch'
  const verifyMismatch = await bg<Resp>({
    type: 'anp-wallet/verify-existing',
    walletId: mismatchWallet,
    handle: `mm-${stamp}`,
  })
  eq(verifyMismatch.status, 'error', 'verify-existing rejects mismatched DID')
  assert(must(verifyMismatch.error, 'mismatch verify error').includes('不匹配'), 'mismatch verify message')

  const missingWallet = await addImported(testSeed(5), 'Missing')
  lookupMode = 'missing'
  const verifyMissing = await bg<Resp>({
    type: 'anp-wallet/verify-existing',
    walletId: missingWallet,
    handle: `nf-${stamp}`,
  })
  eq(verifyMissing.status, 'error', 'verify-existing handles missing handle')
  assert(must(verifyMissing.error, 'missing verify error').includes('未注册'), 'missing verify message')

  const unsupportedWallet = await addImported(testSeed(6), 'Unsupported')
  lookupMode = 'unsupported'
  const verifyUnsupported = await bg<Resp>({
    type: 'anp-wallet/verify-existing',
    walletId: unsupportedWallet,
    handle: `us-${stamp}`,
  })
  eq(verifyUnsupported.status, 'error', 'verify-existing handles unsupported lookup')
  assert(
    must(verifyUnsupported.error, 'unsupported verify error').includes('不支持 handle 查询'),
    'unsupported verify message',
  )
  eq(didRegisters.length, didRegistersBeforeVerify, 'failed verifications never register')
  eq(emailSends.length, emailSendsBeforeVerify, 'failed verifications never email')

  const seedH = testSeed(7)
  const walletHId = await addImported(seedH, 'Rebind')
  console.log('verify-existing: ok')

  // =========================================================================
  // 7. Email verification + did_document registration (awiki).
  // =========================================================================
  const handleA = `mn-${stamp}`
  const fullHandleA = `${handleA}.awiki.ai`
  const emailA = 'Tester@Example.COM'
  const emailKey = `tester@example.com|${fullHandleA}`
  emailVerified.delete(emailKey)

  const statusBefore = await bg<Resp<{ verified: boolean }>>({
    type: 'anp-wallet/email-status',
    serverId: 'awiki.ai',
    email: emailA,
    fullHandle: fullHandleA,
  })
  eq(statusBefore.status, 'ok', 'email-status before verification')
  eq(statusBefore.verified, false, 'email starts unverified')
  assertVersionHeader(calls[calls.length - 1], 'email-status')

  const send = await bg<Resp<{ message: string }>>({
    type: 'anp-wallet/email-send',
    serverId: 'awiki.ai',
    email: emailA,
    fullHandle: fullHandleA,
  })
  eq(send.status, 'ok', 'email-send')
  eq(emailSends.length, 1, 'email-send recorded')
  eq(emailSends[0].body.email, 'tester@example.com', 'email normalized before send')
  eq(emailSends[0].body.handle, fullHandleA, 'email send uses full handle')
  assertVersionHeader(emailSends[0], 'email-send')

  emailVerified.add(emailKey)
  const statusAfter = await bg<Resp<{ verified: boolean }>>({
    type: 'anp-wallet/email-status',
    serverId: 'awiki.ai',
    email: emailA,
    fullHandle: fullHandleA,
  })
  eq(statusAfter.status, 'ok', 'email-status after verification')
  eq(statusAfter.verified, true, 'email verified after activation')

  const regA = await bg<Resp<{ did: string; fullHandle: string; mode: string }>>({
    type: 'anp-wallet/register',
    walletId: walletAId,
    handle: handleA,
    email: emailA,
  })
  eq(regA.status, 'ok', 'register mnemonic wallet on awiki')
  eq(regA.mode, 'did_document', 'register mode did_document')
  eq(regA.fullHandle, fullHandleA, 'registered full handle')
  eq(didRegisters.length, 1, 'one did_document registration captured')
  const regCall = didRegisters[0]
  assertVersionHeader(regCall, 'register')
  eq(regCall.host, 'awiki.ai', 'register sent to awiki')
  assert(!!regCall.body.params.did_document, 'register params include did_document')
  eq(regCall.body.params.email, 'tester@example.com', 'register email normalized')
  eq(regCall.body.params.handle, handleA, 'register handle is local part')
  assert(!('ad' in regCall.body.params), 'did_document register has no aggregate ad')
  assert(!('challenge' in regCall.body.params), 'did_document register has no challenge')
  eq(regCall.body.params.did_document.id, regA.did, 'submitted document DID matches response')

  st = await bg<StateLike>({ type: 'anp-wallet/get-state' })
  walletA = walletFrom(st, walletAId)
  eq(walletA.registered, true, 'wallet A registered')
  eq(walletA.keys.length, 2, 'wallet A keeps its two keys')
  eq(walletA.keys.filter((k) => k.registered).length, 1, 'only the primary key registered')
  eq(walletA.keys[walletA.primaryKeyIndex].registered, true, 'primary key registered')
  eq(walletA.keys.filter((k) => !k.registered).length, 1, 'second key unregistered')
  eq(walletA.handle, fullHandleA, 'wallet handle written back')
  eq(walletA.userId, 'user-1', 'register persists the server account id')
  eq(walletA.activeKeyIndex, walletA.primaryKeyIndex, 'active key is primary after register')
  eq(walletA.didDomain, 'awiki.ai', 'registered wallet domain')
  const didLocal = regA.did.split(':')[4]
  eq(didLocal, handleA, 'DID local-part equals the handle')

  const docA = must(walletA.handleDocuments, 'wallet A stored DID document')
  eq(docA.id, regA.did, 'stored document id')
  assertDeviceManifest(docA)
  assertDocumentProof(docA)
  eqJson(serviceIn(docA), expectedService(MOCK_SERVICE, regA.did), 'submitted service is verbatim')
  const proofA = docA.proof as Record<string, unknown>
  eq(proofA.type, 'DataIntegrityProof', 'proof type')
  eq(proofA.cryptosuite, 'eddsa-jcs-2022', 'proof cryptosuite')
  eq(proofA.domain, 'awiki.ai', 'proof domain')
  eq(proofA.verificationMethod, `${regA.did}#key-1`, 'proof signed by the root key')
  assert(String(proofA.proofValue).startsWith('z'), 'proofValue is base58 multibase')
  const rootVm = (docA.verificationMethod as Record<string, unknown>[])[0]
  eq(rootVm.publicKeyMultibase, walletA.keys[walletA.primaryKeyIndex].publicKeyMultibase, 'root key is the identity key')
  assert(!('privateKeyMultibase' in rootVm) && !('publicKeyJwk' in rootVm), 'no private/JWK material in the document')
  assert(assertStoredDocumentsSafe(rawAccount()) >= 1, 'the registered DID document is manifest-valid and public-only')

  // Production rejects manifest-less docs with -32004; tampering with the
  // manifest must also break the proof over the whole document.
  const strippedDoc = structuredClone(docA)
  delete strippedDoc.deviceManifest
  assertThrows(
    () => assertDeviceManifest(strippedDoc),
    'deviceManifest',
    'manifest-less document rejected locally with the production rule',
  )
  const tamperedDoc = structuredClone(docA)
  ;(tamperedDoc.deviceManifest as Record<string, unknown>).devices = []
  assertThrows(
    () => assertDocumentProof(tamperedDoc),
    'document proof verifies',
    'tampering with the manifest invalidates the proof',
  )

  const jsonAfterReg = rawJson()
  assert(!jsonAfterReg.includes('tester@example.com'), 'account must not persist the email')
  assert(!jsonAfterReg.includes('secret-token'), 'account must not persist access_token')
  assert(!jsonAfterReg.includes('accessToken'), 'account must not have accessToken field')
  console.log('did_document register + email: ok')

  // =========================================================================
  // 8. Post-registration key rules + signing (mnemonic + imported self-select).
  // =========================================================================
  const addKeyA2 = await bg<Resp<{ keyIndex: number }>>({ type: 'anp-wallet/add-key', walletId: walletAId })
  eq(addKeyA2.status, 'ok', 'add key after did_document registration')
  st = await bg<StateLike>({ type: 'anp-wallet/get-state' })
  walletA = walletFrom(st, walletAId)
  eq(walletA.keys.length, 3, 'wallet A now has three keys')
  eq(walletA.registered, true, 'wallet stays registered after add-key')
  eq(walletA.keys.filter((k) => k.registered).length, 1, 'new key stays unregistered')

  const setPrimaryRegistered = await bg<Resp>({
    type: 'anp-wallet/set-primary',
    walletId: walletAId,
    keyIndex: 2,
  })
  eq(setPrimaryRegistered.status, 'error', 'registered did_document wallet rejects set-primary')
  assert(
    must(setPrimaryRegistered.error, 'set-primary error').includes('不能更换主密钥'),
    'set-primary rejection message',
  )

  await bg({ type: 'anp-wallet/lock' })
  const identityLocked = await bg<{ did: string; didDocument: Record<string, unknown> }>({
    type: 'anp-wallet/get-identity',
  })
  eq(identityLocked.did, regA.did, 'get-identity works while locked')

  const padding = 'x'.repeat(400)
  const body = JSON.stringify({ nonce, didDocument: {}, padding })
  const signAck = await bg<Resp<{ id: string }>>({
    type: 'anp-wallet/sign',
    payload: { id: 'req-1', req: { url: TARGET, method: 'POST', body, nonce } },
  })
  eq(signAck.status, 'pending', 'sign stages while locked')
  st = await bg<StateLike>({ type: 'anp-wallet/get-state' })
  const staged = must(st.pending[0], 'staged pending request') as {
    id: string
    url: string
    method: string
    nonce: string
    body: string
  }
  eq(staged.url, TARGET, 'approval UI gets the full target URL')
  eq(staged.nonce, nonce, 'approval UI gets the nonce')
  eq(staged.body, body, 'approval UI gets the full untruncated body')
  await waitFor(() => openPopupCalls > 0, 'sign opens the approval UI when nothing is open')

  const unlockA = await bg<Resp>({ type: 'anp-wallet/unlock', password })
  eq(unlockA.status, 'ok', 'unlock mnemonic wallet')
  const approveA = await bg<Resp<{ did: string; body: string }>>({ type: 'anp-wallet/approve', id: signAck.id })
  eq(approveA.status, 'ok', 'approve mnemonic signature')
  const deliveredA = must(tabMessages.find((m) => m.id === 'req-1'), 'delivered mnemonic signature')
  eq((deliveredA.result as { did: string }).did, regA.did, 'mnemonic signature uses registered DID')
  const bodyA = JSON.parse((deliveredA.result as { body: string }).body)
  eq(bodyA.didDocument.id, regA.did, 'delivered body carries the signing DID document')
  // The inline document is the registered one, with its standard (folded) proof —
  // the wallet does not fork the cryptosuite to suit a relying party.
  assertDocumentProof(bodyA.didDocument)
  eq(bodyA.nonce, nonce, 'delivered body keeps the site nonce')
  eq(bodyA.padding, padding, 'delivered body keeps the rest of the signed content')

  // An open side panel acknowledges the ping, so no extra window is opened.
  const popupCallsBefore = openPopupCalls
  uiAcksPings = true
  const signPanel = await bg<Resp<{ id: string }>>({
    type: 'anp-wallet/sign',
    payload: { id: 'req-panel', req: { url: TARGET, method: 'POST', body, nonce } },
  })
  eq(signPanel.status, 'pending', 'sign stages with the side panel open')
  await new Promise((resolve) => setTimeout(resolve, 500))
  eq(openPopupCalls, popupCallsBefore, 'open side panel suppresses the separate approval window')
  await bg({ type: 'anp-wallet/reject', id: signPanel.id })
  uiAcksPings = false

  // A request without a site body is signed as empty bytes, not filled in by
  // the wallet with fields the site never asked for.
  const emptyAck = await bg<Resp<{ id: string }>>({
    type: 'anp-wallet/sign',
    payload: { id: 'req-empty', req: { url: TARGET, method: 'POST', body: '', nonce } },
  })
  const approveEmpty = await bg<Resp<{ body: string }>>({ type: 'anp-wallet/approve', id: emptyAck.id })
  eq(approveEmpty.status, 'ok', 'approve a signature without a site body')
  const deliveredEmpty = must(
    tabMessages.find((m) => m.id === 'req-empty'),
    'delivered empty-body signature',
  )
  eq((deliveredEmpty.result as { body: string }).body, '', 'empty site body is signed as-is')

  // ANP-03 needs a server-issued nonce: without one the wallet refuses to sign
  // rather than making one up.
  const signNoNonce = await bg<Resp<{ id: string }>>({
    type: 'anp-wallet/sign',
    payload: { id: 'req-no-nonce', req: { url: TARGET, method: 'POST', body, nonce: '' } },
  })
  eq(signNoNonce.status, 'error', 'sign without a nonce is refused')
  st = await bg<StateLike>({ type: 'anp-wallet/get-state' })
  assert(
    !st.pending.some((p) => (p as { id: string }).id === 'req-no-nonce'),
    'no pending request is staged without a nonce',
  )
  assert(
    !tabMessages.some((m) => m.id === 'req-no-nonce'),
    'nothing is delivered for a nonce-less request',
  )

  const signSel = await bg<Resp<{ id: string }>>({
    type: 'anp-wallet/sign',
    payload: { id: 'req-sel', req: { url: TARGET, method: 'POST', body, nonce } },
  })
  eq(signSel.status, 'pending', 'sign stages for self-select')
  const approveSel = await bg<Resp>({
    type: 'anp-wallet/approve',
    id: signSel.id,
    sel: { walletId: walletBId, keyIndex: 0 },
  })
  eq(approveSel.status, 'ok', 'approve imported key self-select')
  const deliveredSel = must(tabMessages.find((m) => m.id === 'req-sel'), 'delivered self-selected signature')
  eq((deliveredSel.result as { did: string }).did, verifiedBDid, 'self-selected signature uses imported key DID')
  assert(
    (deliveredSel.result as { didDocument: { id: string } }).didDocument.id === verifiedBDid,
    'self-selected body is re-written for the imported key',
  )
  const selBody = JSON.parse((deliveredSel.result as { body: string }).body)
  eq(selBody.didDocument.id, verifiedBDid, 'self-selected body document matches the imported DID')
  assertDocumentProof(selBody.didDocument)
  console.log('signing (mnemonic + imported): ok')

  // =========================================================================
  // 9. Custom server: rebind, unsupported email, did_document registration.
  // =========================================================================
  const setCustomDefault = await bg<Resp>({ type: 'anp-wallet/set-default-server', serverId: customServerId })
  eq(setCustomDefault.status, 'ok', 'custom server becomes default')

  st = await bg<StateLike>({ type: 'anp-wallet/get-state' })
  const hBefore = walletFrom(st, walletHId)
  const hPubBefore = hBefore.keys[0].publicKeyMultibase
  const hDidBefore = hBefore.keys[0].did
  const rebindH = await bg<Resp>({ type: 'anp-wallet/rebind-server', walletId: walletHId, serverId: customServerId })
  eq(rebindH.status, 'ok', 'rebind unregistered wallet to custom server')
  st = await bg<StateLike>({ type: 'anp-wallet/get-state' })
  const hAfter = walletFrom(st, walletHId)
  eq(hAfter.serverId, customServerId, 'rebound wallet server')
  eq(hAfter.didDomain, 'reg.example.test', 'rebound wallet DID domain')
  eq(hAfter.keys[0].publicKeyMultibase, hPubBefore, 'rebind keeps the public key')
  assert(hAfter.keys[0].did !== hDidBefore, 'rebind changes the DID')
  eq(hAfter.handle, '', 'rebind clears the handle')
  eq(hAfter.registered, false, 'rebound wallet is unregistered')

  const rebindRegistered = await bg<Resp>({
    type: 'anp-wallet/rebind-server',
    walletId: walletAId,
    serverId: customServerId,
  })
  eq(rebindRegistered.status, 'error', 'registered wallet cannot rebind')
  assert(must(rebindRegistered.error, 'rebind error').includes('已注册'), 'rebind rejection message')

  const handleH = `cu-${stamp}`
  const fullHandleH = `${handleH}.reg.example.test`
  const emailCustom = await bg<Resp>({
    type: 'anp-wallet/email-status',
    serverId: customServerId,
    email: 'tester@example.com',
    fullHandle: fullHandleH,
  })
  eq(emailCustom.status, 'unsupported', 'custom server without email verification reports unsupported')

  const regH = await bg<Resp<{ did: string; fullHandle: string; mode: string }>>({
    type: 'anp-wallet/register',
    walletId: walletHId,
    handle: handleH,
    email: 'tester@example.com',
  })
  eq(regH.status, 'ok', 'register on custom server')
  eq(regH.mode, 'did_document', 'custom registration still uses did_document')
  eq(regH.fullHandle, fullHandleH, 'custom full handle')
  eq(didRegisters.length, 2, 'custom registration captured')
  const regHCall = didRegisters[1]
  assertVersionHeader(regHCall, 'custom register')
  eq(regHCall.host, 'reg.example.test', 'custom register host')
  eq(regHCall.body.params.handle, handleH, 'custom register local handle')
  assert(!!regHCall.body.params.did_document, 'custom register sends did_document')
  st = await bg<StateLike>({ type: 'anp-wallet/get-state' })
  const hReg = walletFrom(st, walletHId)
  eq(hReg.registered, true, 'custom wallet registered')
  eq(hReg.didDomain, 'reg.example.test', 'custom wallet domain preserved')
  eq(hReg.keys[0].did.split(':')[2], 'reg.example.test', 'custom DID domain')
  eqJson(
    serviceIn(must(hReg.handleDocuments, 'custom DID document')),
    expectedService(serviceFor('reg.example.test'), regH.did),
    'custom service descriptor is verbatim',
  )
  assert(assertStoredDocumentsSafe(rawAccount()) >= 2, 'registered DID documents are manifest-valid and public-only')
  console.log('custom server rebind + register: ok')

  // =========================================================================
  // 10. DID-domain mismatch guards.
  // =========================================================================
  const addWrong2 = await bg<Resp<{ server: ServerLike }>>({
    type: 'anp-wallet/add-server',
    rpcBase: 'https://wrong.example.test',
    didDomain: 'wrong.example.test',
  })
  const wrong2 = must(addWrong2.server, 'wrong server 2')
  await bg({ type: 'anp-wallet/set-default-server', serverId: wrong2.id })
  const walletWrongId = await addImported(testSeed(8), 'WrongDomain')
  const rawW = rawAccount()
  const walletWrong = must(rawW.wallets.find((w) => w.id === walletWrongId), 'wrong wallet in storage')
  walletWrong.didDomain = 'awiki.ai'
  store.set('anp_account', rawW)
  const regWrong = await bg<Resp>({
    type: 'anp-wallet/register',
    walletId: walletWrongId,
    handle: `wr-${stamp}`,
    email: 'tester@example.com',
  })
  eq(regWrong.status, 'error', 'wallet/server domain mismatch rejected')
  assert(must(regWrong.error, 'wallet mismatch error').includes('不一致'), 'wallet mismatch message')
  eq(didRegisters.length, 2, 'mismatched wallet never reaches register')
  await bg({ type: 'anp-wallet/delete-wallet', walletId: walletWrongId })

  const addMismatch2 = await bg<Resp<{ server: ServerLike }>>({
    type: 'anp-wallet/add-server',
    rpcBase: 'https://mismatch.example.test',
    didDomain: 'mismatch.example.test',
  })
  const mismatch2 = must(addMismatch2.server, 'mismatch server 2')
  await bg({ type: 'anp-wallet/set-default-server', serverId: mismatch2.id })
  const walletMismatchId = await addImported(testSeed(9), 'DiscoveryMismatch')
  const regMismatch = await bg<Resp>({
    type: 'anp-wallet/register',
    walletId: walletMismatchId,
    handle: `dm-${stamp}`,
    email: 'tester@example.com',
  })
  eq(regMismatch.status, 'error', 'discovered domain mismatch rejected')
  assert(must(regMismatch.error, 'mismatch error').includes('不一致'), 'discovery mismatch message')
  eq(didRegisters.length, 2, 'domain mismatch never reaches register')
  await bg({ type: 'anp-wallet/delete-wallet', walletId: walletMismatchId })
  await bg({ type: 'anp-wallet/set-default-server', serverId: 'awiki.ai' })
  await bg({ type: 'anp-wallet/remove-server', serverId: wrong2.id })
  await bg({ type: 'anp-wallet/remove-server', serverId: mismatch2.id })
  console.log('domain mismatch guards: ok')

  // =========================================================================
  // 11. Legacy aggregate compatibility: ad + challenge, re-submit on set-primary.
  // =========================================================================
  st = await bg<StateLike>({ type: 'anp-wallet/get-state' })
  const walletABeforeAggregate = walletFrom(st, walletAId)
  eq(walletABeforeAggregate.keys.length, 3, 'aggregate clone source has three keys')
  await bg({ type: 'anp-wallet/lock' })

  const aggregateWallet = structuredClone(walletABeforeAggregate)
  aggregateWallet.id = `agg-${stamp}`
  aggregateWallet.label = 'Aggregate'
  aggregateWallet.handle = ''
  aggregateWallet.registered = false
  delete aggregateWallet.handleDocuments
  aggregateWallet.serverId = null
  aggregateWallet.didDomain = 'localhost'
  aggregateWallet.registerMode = 'aggregate'
  aggregateWallet.activeKeyIndex = 0
  aggregateWallet.primaryKeyIndex = 0
  aggregateWallet.nextKeyIndex = 3
  store.set('anp_account', {
    version: 5,
    wallets: [aggregateWallet],
    activeWalletId: aggregateWallet.id,
  } satisfies AccountLike)

  st = await bg<StateLike>({ type: 'anp-wallet/get-state' })
  const aggLoaded = walletFrom(st, aggregateWallet.id)
  eq(aggLoaded.registerMode, 'aggregate', 'v5 aggregate mode survives normalization')
  const unlockAgg = await bg<Resp>({ type: 'anp-wallet/unlock', password })
  eq(unlockAgg.status, 'ok', 'unlock aggregate wallet from cloned mnemonic blob')

  const handleAgg = `ag-${stamp}`
  const fullHandleAgg = `${handleAgg}.localhost`
  const regAgg = await bg<Resp<{ did: string; dids: string[]; mode: string }>>({
    type: 'anp-wallet/register',
    walletId: aggregateWallet.id,
    handle: handleAgg,
  })
  eq(regAgg.status, 'ok', 'register legacy aggregate wallet')
  eq(regAgg.mode, 'aggregate', 'aggregate mode response')
  eq(regAgg.dids.length, 3, 'aggregate response lists all DIDs')
  eq(aggregateRegisters.length, 1, 'one aggregate registration captured')
  const aggCall = aggregateRegisters[0]
  assertVersionHeader(aggCall, 'aggregate register')
  eq(aggCall.host, '127.0.0.1', 'aggregate register uses legacy localhost server')
  assert(!!aggCall.body.params.ad, 'aggregate params include ad')
  assert(!!aggCall.body.params.challenge, 'aggregate params include challenge')
  assert(!!aggCall.body.params.challenge_signature, 'aggregate params include challenge_signature')
  eq(aggCall.body.params.submitting_did, regAgg.did, 'aggregate submitting DID is the primary')
  assert(!('did_document' in aggCall.body.params), 'aggregate does not send did_document')
  assert(!('email' in aggCall.body.params), 'aggregate register omits empty email')
  const challengeCalls = calls.filter((c) => c.host === '127.0.0.1' && c.body?.method === 'challenge')
  eq(challengeCalls.length, 1, 'aggregate fetches a challenge')
  assertVersionHeader(challengeCalls[0], 'aggregate challenge')
  const ad = aggCall.body.params.ad as Record<string, unknown>
  eq(ad.type, 'ANPHandleAggregate', 'aggregate document type')
  eq(ad.handle, fullHandleAgg, 'aggregate handle')
  eq((ad.dids as string[]).length, 3, 'aggregate document lists every key DID')
  eq((ad.verificationMethod as unknown[]).length, 3, 'aggregate document lists every key')
  assert(!('keyAgreement' in ad), 'aggregate document has no keyAgreement')
  assert(String((ad.proof as Record<string, unknown>).proofValue).startsWith('z'), 'aggregate proof is base58')

  st = await bg<StateLike>({ type: 'anp-wallet/get-state' })
  let agg = walletFrom(st, aggregateWallet.id)
  eq(agg.registered, true, 'aggregate wallet registered')
  eq(agg.keys.every((k) => k.registered === true), true, 'aggregate marks every key registered')
  eq(agg.handle, fullHandleAgg, 'aggregate wallet handle')
  eq(agg.activeKeyIndex, 0, 'aggregate primary active')

  const aggKey1Did = agg.keys[1].did
  const setPrimaryAgg = await bg<Resp>({ type: 'anp-wallet/set-primary', walletId: agg.id, keyIndex: 1 })
  eq(setPrimaryAgg.status, 'ok', 'aggregate set-primary re-registers')
  eq(aggregateRegisters.length, 2, 'set-primary submits the aggregate again')
  eq(
    aggregateRegisters[1].body.params.submitting_did,
    aggKey1Did,
    're-submitted aggregate uses the new primary as submitting DID',
  )
  st = await bg<StateLike>({ type: 'anp-wallet/get-state' })
  agg = walletFrom(st, aggregateWallet.id)
  eq(agg.primaryKeyIndex, 1, 'aggregate primary moved')
  eq(agg.keys.every((k) => k.registered === true), true, 're-registration keeps every key registered')

  const aggAddKey = await bg<Resp<{ keyIndex: number }>>({ type: 'anp-wallet/add-key', walletId: agg.id })
  eq(aggAddKey.status, 'ok', 'aggregate add-key')
  st = await bg<StateLike>({ type: 'anp-wallet/get-state' })
  agg = walletFrom(st, aggregateWallet.id)
  eq(agg.keys.length, 4, 'aggregate gained a key')
  eq(agg.registered, false, 'aggregate registration invalidated by add-key')
  eq(agg.keys.every((k) => !k.registered), true, 'all aggregate keys unregistered after invalidation')
  console.log('legacy aggregate: ok')

  // =========================================================================
  // 12. Auto-lock setting: persisted, validated, surfaced in state.
  // =========================================================================
  st = await bg<StateLike>({ type: 'anp-wallet/get-state' })
  eq(st.autoLockMinutes, 5, 'default auto-lock is five minutes')

  const badLock = await bg<Resp>({ type: 'anp-wallet/set-auto-lock', minutes: 2 })
  eq(badLock.status, 'error', 'unsupported auto-lock interval rejected')

  for (const minutes of [1, 3, 20, 0]) {
    const setLock = await bg<Resp>({ type: 'anp-wallet/set-auto-lock', minutes })
    eq(setLock.status, 'ok', `set auto-lock to ${minutes}`)
    st = await bg<StateLike>({ type: 'anp-wallet/get-state' })
    eq(st.autoLockMinutes, minutes, `auto-lock ${minutes} surfaced in state`)
    eq((store.get('anp_settings') as { autoLockMinutes: number }).autoLockMinutes, minutes, `auto-lock ${minutes} persisted`)
  }
  console.log('auto-lock setting: ok')

  // =========================================================================
  // Security regressions: approval binds an immutable wallet-generated record.
  const pageSender = {tab: {id: 71}, documentId: 'document-a', frameId: 0,
    origin: 'https://page.example', url: 'https://page.example/'}
  const fromPage = (msg: unknown, sender = pageSender): Promise<any> =>
    new Promise((resolve) => bgHandler(msg, sender, (resp) => resolve(structuredClone(resp))))
  const safeBody = JSON.stringify({nonce, action: 'safe-login'})
  const first = await fromPage({type: 'anp-wallet/sign', payload: {id: 'same-page-id', req: {url: TARGET, body: safeBody, nonce}}})
  eq(first.status, 'pending', 'stage immutable request')
  assert(first.id !== 'same-page-id', 'approval ID is generated by wallet')
  const snapshot = await bg<StateLike>({type: 'anp-wallet/get-state'})
  const shown = snapshot.pending.find((p: any) => p.id === first.id) as any
  eq(shown.body, safeBody, 'UI sees original body')
  const duplicate = await fromPage({type: 'anp-wallet/sign', payload: {id: 'same-page-id', req: {url: TARGET, body: 'replacement-not-shown', nonce}}})
  eq(duplicate.status, 'error', 'same-document duplicate cannot replace snapshot')
  const second = await fromPage({type: 'anp-wallet/sign', payload: {id: 'same-page-id', req: {url: TARGET, body: 'other-tab', nonce}}},
    {...pageSender, tab: {id: 72}, documentId: 'document-b'})
  eq(second.status, 'pending', 'another tab has a separate request namespace')
  assert(second.id !== first.id, 'cross-tab IDs do not collide')
  eq((await fromPage({type: 'anp-wallet/approve', id: first.id})).status, 'error', 'content script cannot approve')
  const approved = await bg<Resp>({type: 'anp-wallet/approve', id: shown.id})
  eq(approved.status, 'ok', 'old snapshot still approves original immutable record')
  const signed = tabMessages.filter((m) => m.id === 'same-page-id').slice(-1)[0]!
  assert(String(signed.result?.body).includes('safe-login'), 'only the displayed request was signed')
  assert(!String(signed.result?.body).includes('replacement-not-shown'), 'replacement was not signed')
  eq(deliveries[deliveries.length - 1]?.options.documentId, 'document-a', 'result targets original document')
  eq(deliveries[deliveries.length - 1]?.tabId, 71, 'result targets original tab')
  eq((await bg<Resp>({type: 'anp-wallet/approve', id: first.id})).status, 'error', 'approval cannot replay')
  tabUpdated(72, {status: 'loading'})
  eq((await bg<Resp>({type: 'anp-wallet/approve', id: second.id})).status, 'error', 'navigation invalidates approval')
  const pendingMessage = (id: string, body = '') => ({type: 'anp-wallet/sign', payload: {id, req: {url: TARGET, body, nonce}}})
  eq((await fromPage(pendingMessage('oversize', 'x'.repeat(1024 * 1024)))).status, 'error', 'oversize requests refused')
  const expiring = await fromPage(pendingMessage('expires'))
  const savedNow = Date.now
  try {
    Date.now = () => savedNow() + 5 * 60 * 1000 + 1
    eq((await bg<Resp>({type: 'anp-wallet/approve', id: expiring.id})).status, 'error', 'expired request cannot be approved')
  } finally { Date.now = savedNow }
  const concurrent = await Promise.all(Array.from({length: 40}, (_, i) => fromPage(pendingMessage(`queue-${i}`))))
  eq(concurrent.filter((r) => r.status === 'pending').length, 32, 'concurrent requests respect queue cap')
  tabRemoved(71)
  const afterClose = await bg<StateLike>({type: 'anp-wallet/get-state'})
  assert(!afterClose.pending.some((p: any) => concurrent.some((r) => r.id === p.id)), 'closing tab clears its requests')
  console.log('immutable approval, sender isolation, document binding, expiry and queue limits: ok')

  // 13. Global invariants: headers, identity-only, deletable last wallet.
  // =========================================================================
  const discoveryCalls = calls.filter((c) => c.path === '/.well-known/did.json')
  assert(discoveryCalls.length >= 4, 'discovery was exercised')
  for (const call of discoveryCalls) {
    assert(!('x-awiki-client-version' in call.headers), 'discovery carries no client version header')
  }
  const userCalls = calls.filter((c) => c.path.startsWith('/user-service/v1/'))
  assert(userCalls.length >= 8, 'user-service calls were exercised')
  for (const call of userCalls) assertVersionHeader(call, `user-service ${call.path}`)

  const finalJson = rawJson()
  assert(!finalJson.includes('accessToken'), 'final account has no accessToken')
  assert(!finalJson.includes('legacy-token'), 'final account has no aggregate access token')
  eq(finalJson.includes('secret-token'), false, 'access token never persisted')

  const delLast = await bg<Resp>({ type: 'anp-wallet/delete-wallet', walletId: agg.id })
  eq(delLast.status, 'ok', 'delete the last wallet')
  st = await bg<StateLike>({ type: 'anp-wallet/get-state' })
  eq(stateAccount(st).wallets.length, 0, 'zero wallets remain')
  eq(stateAccount(st).activeWalletId, null, 'active wallet cleared')
  eq(st.unlocked, false, 'vault locks when the last wallet is deleted')

  console.log(
    'RESULT: PASS ✅ (v4→v5 migration, server registry, mnemonic+imported wallets, import parsing, verify-existing, email+did_document register, custom server rebind, domain guards, aggregate compat, auto-lock setting, signing, identity-only)',
  )
}

main().catch((e) => {
  console.error('ERROR', e)
  process.exit(1)
})
