// ANP-03 ANP Agent Network Protocol + RFC 9421 HTTP Message Signatures.
//
// This is the *pure* signing core for the ANP wallet web extension. It is
// dependency-light (only @scure/* + @noble/*) so it runs identically in the
// extension service worker and under Node (the verification harness).
//
// Goal: byte-for-byte interop with the official `pip install anp` client
// (anp.authentication.did_wba, e1 profile) so the same headers authenticate
// to a server that accepts the official client.

import { entropyToMnemonic, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english'
import { ed25519 } from '@noble/curves/ed25519'
import { sha256 } from '@noble/hashes/sha256'
import { sha512 } from '@noble/hashes/sha512'
import { hmac } from '@noble/hashes/hmac'
import { utf8ToBytes } from '@noble/hashes/utils'
import { base58, base64, base64urlnopad } from '@scure/base'

// ---------------------------------------------------------------------------
// HD derivation (BIP39 -> SLIP-0010 Ed25519)
//
// Same mnemonic always derives the same key/DID, so every user who imports the
// same phrase gets the exact same identity — the point of mnemonic keygen.
//
// SLIP-0010 Ed25519 hardened derivation. Path segments MUST be hardened
// (append a `'`), which is all we use here. ANP has no assigned coin type, so
// we fix a documented default path; determinism/recoverability is the contract.
// ---------------------------------------------------------------------------

export type DerivationPath = string

/** Default derivation path for an ANP wallet key (documented, deterministic). */
export const DEFAULT_DERIVATION_PATH: DerivationPath = "m/44'/0'/0'"

const HARDENED_OFFSET = 0x80000000

function hmacSha512(key: Uint8Array, msg: Uint8Array): Uint8Array {
  return hmac(sha512, key, msg)
}

function masterKeyFromSeed(seed: Uint8Array): { key: Uint8Array; chainCode: Uint8Array } {
  const I = hmacSha512(utf8ToBytes('ed25519 seed'), seed)
  return { key: I.subarray(0, 32), chainCode: I.subarray(32, 64) }
}

function deriveChild(
  parentKey: Uint8Array,
  chainCode: Uint8Array,
  index: number,
): { key: Uint8Array; chainCode: Uint8Array } {
  // SLIP-0010: data = 0x00 || ser256(parentKey) || ser32(index) (big-endian).
  const data = new Uint8Array(37)
  data[0] = 0x00
  data.set(parentKey, 1)
  new DataView(data.buffer).setUint32(33, index, false)
  const I = hmacSha512(chainCode, data)
  return { key: I.subarray(0, 32), chainCode: I.subarray(32, 64) }
}

function derivePrivateKeyFromSeed(seed: Uint8Array, path: DerivationPath): Uint8Array {
  let { key, chainCode } = masterKeyFromSeed(seed)
  const segments = path.replace(/^m\//, '').split('/').filter(Boolean)
  for (const seg of segments) {
    const hardened = /[hH']$/.test(seg)
    const index = parseInt(seg.replace(/[hH']$/, ''), 10) + (hardened ? HARDENED_OFFSET : 0)
    ;({ key, chainCode } = deriveChild(key, chainCode, index))
  }
  return key
}

/**
 * Derive the Ed25519 private key (32 bytes) for a BIP39 mnemonic.
 * `passphrase` is the optional BIP39 passphrase (empty string by default).
 */
export function deriveEd25519PrivateKey(
  mnemonic: string,
  opts: { passphrase?: string; path?: DerivationPath } = {},
): Uint8Array {
  const { passphrase = '', path = DEFAULT_DERIVATION_PATH } = opts
  if (!validateMnemonic(mnemonic, wordlist)) {
    throw new Error('Invalid BIP39 mnemonic')
  }
  const seed = mnemonicToSeedSync(mnemonic, passphrase)
  return derivePrivateKeyFromSeed(seed, path)
}

/**
 * Generate a BIP39 mnemonic from OS-level cryptographic randomness.
 *
 * Entropy comes from `crypto.getRandomValues` — the platform CSPRNG (Web Crypto
 * in the browser, node:crypto in Node) — never `Math.random()`. The default is
 * 256 bits (24 words), the maximum BIP39 entropy and matching the 256-bit
 * Ed25519 key space. `entropyBits` must be a multiple of 32 in [128, 256].
 */
export function generateMnemonicPhrase(entropyBits: number = 256): string {
  if (!Number.isInteger(entropyBits) || entropyBits < 128 || entropyBits > 256 || entropyBits % 32 !== 0) {
    throw new Error(`entropyBits must be a multiple of 32 in [128, 256], got ${entropyBits}`)
  }
  const entropy = new Uint8Array(entropyBits / 8)
  globalThis.crypto.getRandomValues(entropy)
  return entropyToMnemonic(entropy, wordlist)
}

export function isValidMnemonic(mnemonic: string): boolean {
  return validateMnemonic(mnemonic.trim(), wordlist)
}

/** Public key (32 bytes) from a 32-byte Ed25519 private key. */
export function publicKeyFromPrivateKey(priv: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(priv)
}

// ---------------------------------------------------------------------------
// Multibase + multikey fingerprint (match official e1 encoding)
// ---------------------------------------------------------------------------

/** `z` + base58btc(`0xed 0x01` + 32 raw public-key bytes). */
export function multibaseEd25519(pub: Uint8Array): string {
  const prefixed = new Uint8Array(34)
  prefixed[0] = 0xed
  prefixed[1] = 0x01
  prefixed.set(pub, 2)
  return 'z' + base58.encode(prefixed)
}

/**
 * RFC 7638 JWK thumbprint for the Ed25519 key, matched to the official
 * `compute_multikey_fingerprint`: canonical JSON `{"crv":"Ed25519","kty":"OKP","x":"..."}`
 * (keys sorted alphabetically), SHA-256, base64url WITHOUT padding.
 */
export function computeMultikeyFingerprint(pub: Uint8Array): string {
  const x = base64urlnopad.encode(pub)
  const canonical = `{"crv":"Ed25519","kty":"OKP","x":"${x}"}`
  const digest = sha256(utf8ToBytes(canonical))
  return base64urlnopad.encode(digest)
}

// ---------------------------------------------------------------------------
// did:wba identity (e1 profile)
// ---------------------------------------------------------------------------

export interface DidWbaIdentity {
  did: string
  keyid: string
  didDocument: Record<string, unknown>
  publicKeyMultibase: string
}

export interface DidWbaInput {
  /** Bare host (no scheme/port), e.g. `alice.example.com`. */
  hostname: string
  /** Optional port (encoded `%3A<port>`), e.g. 3000. */
  port?: number | null
  /** Optional path segments (first becomes directory for the DID). */
  pathSegments?: string[]
}

/** `did:wba:<hostname>` + optional `%3A<port>`. */
export function buildDidBase(input: DidWbaInput): string {
  let base = `did:wba:${input.hostname}`
  if (input.port != null) {
    base += encodeURIComponent(`:${input.port}`)
  }
  return base
}

/**
 * Build the e1 DID document, matching the official SDK byte-for-byte for the
 * parts the ANP-03 HTTP-signature auth path needs:
 *   - verificationMethod `#key-1` with type `Multikey` + `publicKeyMultibase`
 *   - authentication + assertionMethod referencing `#key-1`
 * (The official SDK's W3C Data Integrity `proof` field is intentionally omitted:
 *  the ANP-03 login endpoint resolves the inline document for the verification
 *  key only and does not require doc-integrity proof. See README.)
 */
export function buildDidWbaIdentity(input: DidWbaInput, priv: Uint8Array): DidWbaIdentity {
  const pub = publicKeyFromPrivateKey(priv)
  const didBase = buildDidBase(input)
  const segments = [...(input.pathSegments ?? [])]

  // e1 profile binds the key into the DID only when path segments are present.
  if (segments.length > 0) {
    segments.push(`e1_${computeMultikeyFingerprint(pub)}`)
  }
  const did = segments.length > 0 ? `${didBase}:${segments.join(':')}` : didBase
  const keyid = `${did}#key-1`
  const publicKeyMultibase = multibaseEd25519(pub)

  const didDocument = {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/data-integrity/v2',
      'https://w3id.org/security/multikey/v1',
    ],
    id: did,
    verificationMethod: [
      { id: keyid, type: 'Multikey', controller: did, publicKeyMultibase },
    ],
    authentication: [keyid],
    assertionMethod: [keyid],
  }

  return { did, keyid, didDocument, publicKeyMultibase }
}

// ---------------------------------------------------------------------------
// awiki.ai handle identity (did:wba:awiki.ai:user:<local>:e1_<fp>)
//
// A registered ANP identity binds a WNS handle (`alice.awiki.ai`) into the DID
// path (`user:alice`) and self-signs with an eddsa-jcs-2022 DataIntegrityProof.
// This is the exact shape `awiki-cli-rs2` / the official `anp` SDK submit to
// the awiki.ai `register` RPC.
// ---------------------------------------------------------------------------

/** ISO-8601 UTC timestamp without milliseconds (matches the SDK proof `created`). */
export function isoUtcNow(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z')
}

/** Random lowercase hex string (`numBytes` bytes → 2·numBytes chars), matching `random_hex`. */
export function randomHex(numBytes: number): string {
  const bytes = new Uint8Array(numBytes)
  globalThis.crypto.getRandomValues(bytes)
  let out = ''
  for (const b of bytes) out += b.toString(16).padStart(2, '0')
  return out
}

/**
 * RFC 8785 JSON Canonicalization Scheme. Object keys are sorted by UTF-16 code
 * unit; strings/numbers reuse `JSON.stringify` (which already emits the exact
 * RFC 8785 escaping). The DID document + proof options contain no non-finite
 * numbers, so number edge cases are out of scope here.
 */
export function jcsCanonicalize(value: unknown): string {
  if (value === null) return 'null'
  if (value === true) return 'true'
  if (value === false) return 'false'
  if (typeof value === 'string') return JSON.stringify(value)
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('JCS: non-finite number')
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) return '[' + value.map(jcsCanonicalize).join(',') + ']'
  if (typeof value === 'object') {
    const keys = Object.keys(value as Record<string, unknown>).sort()
    return (
      '{' +
      keys
        .map((k) => JSON.stringify(k) + ':' + jcsCanonicalize((value as Record<string, unknown>)[k]))
        .join(',') +
      '}'
    )
  }
  throw new Error('JCS: unsupported type')
}

/**
 * eddsa-jcs-2022 DataIntegrityProof (W3C), byte-for-byte with the official
 * `anp.proof.generate_w3c_proof`:
 *   toBeSigned = sha256(jcs(proofOptions)) || sha256(jcs(document))
 *   proofValue = base64url(Ed25519(toBeSigned))
 *
 * `domain` (the DID authority, e.g. `awiki.ai`) and `challenge` (a nonce) are
 * part of the signed proof options — awiki.ai's `register` RPC rejects proofs
 * without a whitelisted `domain`.
 */
export function signDidDocumentProof(
  doc: Record<string, unknown>,
  priv: Uint8Array,
  keyid: string,
  opts: { domain?: string; challenge?: string } = {},
): Record<string, unknown> {
  const proofOptions: Record<string, unknown> = {
    type: 'DataIntegrityProof',
    created: isoUtcNow(),
    verificationMethod: keyid,
    proofPurpose: 'assertionMethod',
    cryptosuite: 'eddsa-jcs-2022',
  }
  if (opts.domain) proofOptions.domain = opts.domain
  if (opts.challenge) proofOptions.challenge = opts.challenge

  const withoutProof: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(doc)) if (k !== 'proof') withoutProof[k] = v

  const optionsHash = sha256(utf8ToBytes(jcsCanonicalize(proofOptions)))
  const docHash = sha256(utf8ToBytes(jcsCanonicalize(withoutProof)))
  const toBeSigned = new Uint8Array(64)
  toBeSigned.set(optionsHash, 0)
  toBeSigned.set(docHash, 32)
  const signature = ed25519.sign(toBeSigned, priv)
  return { ...proofOptions, proofValue: base64urlnopad.encode(signature) }
}

/**
 * SLIP-0010 derivation path for a key at `index`. Index 0 is the wallet's
 * original path (`m/44'/0'/0'`), so existing identities stay recoverable from
 * the same mnemonic. Higher indexes derive additional independent keys.
 */
export function keyPathFor(index: number): DerivationPath {
  if (!Number.isInteger(index) || index < 0) throw new Error(`invalid key index: ${index}`)
  return `m/44'/0'/${index}'`
}

/** Derive the Ed25519 private key for the given key index (see keyPathFor). */
export function deriveKeyPrivateKey(mnemonic: string, index: number): Uint8Array {
  return deriveEd25519PrivateKey(mnemonic, { path: keyPathFor(index) })
}

/**
 * Ed25519-sign a server-issued challenge with the wallet key, returning the
 * base64url signature. The open server's `register` verifies this against the
 * Multikey embedded in the submitted DID document — that's what binds the
 * person submitting now to the key's owner (a self-signed document alone is
 * replayable). Plain Ed25519 over the challenge's UTF-8 bytes.
 */
export function signChallenge(priv: Uint8Array, challenge: string): string {
  return base64urlnopad.encode(ed25519.sign(utf8ToBytes(challenge), priv))
}

/** Extract the WNS local-part from a full handle (`alice.awiki.ai` → `alice`). */
export function localPartFromHandle(handle: string, didDomain = 'awiki.ai'): string {
  const trimmed = handle.trim().toLowerCase()
  const suffix = `.${didDomain}`
  const localPart = trimmed.endsWith(suffix) ? trimmed.slice(0, -suffix.length) : trimmed
  if (!localPart) throw new Error('Invalid handle: empty local-part')
  return localPart
}

/**
 * Build the awiki.ai handle identity. `handle` is the full WNS handle
 * (`alice.awiki.ai`); the DID becomes `did:wba:awiki.ai:user:alice:e1_<fp>`
 * with an ANPHandleService entry and a self-signed eddsa-jcs-2022 proof.
 */
/** Optional ANPMessageService to embed in the signed DID document. */
export interface AwikiMessageService {
  serviceEndpoint: string
  serviceDid: string
}

export function buildAwikiIdentity(
  handle: string,
  priv: Uint8Array,
  didDomain = 'awiki.ai',
  messageService?: AwikiMessageService,
): DidWbaIdentity {
  const localPart = localPartFromHandle(handle, didDomain)
  const pub = publicKeyFromPrivateKey(priv)
  const segments = ['user', localPart, `e1_${computeMultikeyFingerprint(pub)}`]
  const did = `did:wba:${didDomain}:${segments.join(':')}`
  const keyid = `${did}#key-1`
  const publicKeyMultibase = multibaseEd25519(pub)

  const services: Record<string, unknown>[] = [
    {
      id: `${did}#handle`,
      type: 'ANPHandleService',
      serviceEndpoint: `https://${didDomain}/.well-known/handle/${localPart}`,
    },
  ]
  // The open server requires a signed document to declare exactly one
  // ANPMessageService pointing back at itself (awiki.ai ignored it). Append it
  // only when the caller supplies the target server's endpoint + service DID.
  if (messageService) {
    services.push({
      id: `${did}#anp-message`,
      type: 'ANPMessageService',
      serviceEndpoint: messageService.serviceEndpoint,
      serviceDid: messageService.serviceDid,
      profiles: [],
      securityProfiles: ['transport-protected'],
      authSchemes: ['bearer', 'didwba'],
    })
  }

  const doc: Record<string, unknown> = {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/data-integrity/v2',
      'https://w3id.org/security/multikey/v1',
    ],
    id: did,
    verificationMethod: [{ id: keyid, type: 'Multikey', controller: did, publicKeyMultibase }],
    authentication: [keyid],
    assertionMethod: [keyid],
    service: services,
  }
  doc.proof = signDidDocumentProof(doc, priv, keyid, { domain: didDomain, challenge: randomHex(16) })

  return { did, keyid, didDocument: doc, publicKeyMultibase }
}

/** One key's contribution to a handle's aggregate `ad.json`. */
export interface HandleAggregateKey {
  did: string
  publicKeyMultibase: string
}

/**
 * Build the handle-level aggregate `ad.json`. One handle owns exactly ONE of
 * these, listing every key/DID derived under it (each key keeps its own distinct
 * `e1_<fp>` DID). The primary/owner DID is `submittingDid`; the document is
 * self-signed by that key (proof.verificationMethod = `<submittingDid>#key-1`).
 * The aggregate is a *handle* doc, NOT a single DID doc, so its keys may have
 * different controllers — the server verifies it with `verify_handle_ad_proof`,
 * not the single-controller `verify_did_document_data_integrity_proof`.
 */
export function buildHandleAggregateDoc(
  handle: string,
  keys: HandleAggregateKey[],
  submittingDid: string,
  priv: Uint8Array,
  opts: { didDomain?: string; messageService?: AwikiMessageService } = {},
): Record<string, unknown> {
  const didDomain = opts.didDomain ?? 'awiki.ai'
  const primaryDid = submittingDid
  const keyids = keys.map((k) => `${k.did}#key-1`)
  const verificationMethod = keys.map((k) => ({
    id: `${k.did}#key-1`,
    type: 'Multikey',
    controller: k.did,
    publicKeyMultibase: k.publicKeyMultibase,
  }))
  const services: Record<string, unknown>[] = [
    {
      id: `${primaryDid}#handle`,
      type: 'ANPHandleService',
      serviceEndpoint: `https://${didDomain}/.well-known/handle/${localPartFromHandle(handle, didDomain)}`,
    },
  ]
  if (opts.messageService) {
    services.push({
      id: `${primaryDid}#anp-message`,
      type: 'ANPMessageService',
      serviceEndpoint: opts.messageService.serviceEndpoint,
      serviceDid: opts.messageService.serviceDid,
      profiles: [],
      securityProfiles: ['transport-protected'],
      authSchemes: ['bearer', 'didwba'],
    })
  }
  const created = isoUtcNow()
  const doc: Record<string, unknown> = {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/data-integrity/v2',
      'https://w3id.org/security/multikey/v1',
    ],
    id: primaryDid,
    handle,
    type: 'ANPHandleAggregate',
    protocolType: 'ANP-03',
    version: 1,
    did: primaryDid,
    dids: keys.map((k) => k.did),
    verificationMethod,
    authentication: keyids,
    assertionMethod: keyids,
    owner: primaryDid,
    created,
    updated: created,
    service: services,
  }
  doc.proof = signDidDocumentProof(doc, priv, `${primaryDid}#key-1`, { domain: didDomain, challenge: randomHex(16) })
  return doc
}

export interface SignatureParams {
  created: number
  expires: number
  nonce: string
  keyid: string
}

export const COVERED_COMPONENTS = ['@method', '@target-uri', '@authority', 'content-digest'] as const

export function serializeSignatureParams(
  components: readonly string[],
  params: SignatureParams,
): string {
  const list = components.map((c) => `"${c}"`).join(' ')
  return `(${list});created=${params.created};expires=${params.expires};nonce="${params.nonce}";keyid="${params.keyid}"`
}

export function buildSignatureInputHeader(components: readonly string[], params: SignatureParams): string {
  return `sig1=${serializeSignatureParams(components, params)}`
}

export function contentDigest(body: Uint8Array | string): string {
  const bytes = typeof body === 'string' ? utf8ToBytes(body) : body
  const digest = sha256(bytes)
  return `sha-256=:${base64.encode(digest)}:`
}

function headerValue(
  component: string,
  opts: { method: string; url: string; headers: Record<string, string> },
): string {
  switch (component) {
    case '@method':
      return opts.method.toUpperCase()
    case '@target-uri':
      return opts.url
    case '@authority': {
      const u = new URL(opts.url)
      return u.host // netloc: host + (authoritative) port
    }
    default: {
      const v = opts.headers[component]
      if (v === undefined) throw new Error(`Covered header "${component}" missing`)
      return v
    }
  }
}

/**
 * Build the ASCII signature base (the exact string that is signed), matching
 * how the verifier reconstructs it — each covered component on its own line,
 * then a final `"@signature-params"` line.
 */
export function buildSignatureBase(
  components: readonly string[],
  opts: { method: string; url: string; headers: Record<string, string> },
  params: SignatureParams,
): string {
  const lines = components.map((c) => `"${c}": ${headerValue(c, opts)}`)
  lines.push(`"@signature-params": ${serializeSignatureParams(components, params)}`)
  return lines.join('\n')
}

export interface SignRequest {
  /** Full target URL (must be the URL the request is actually sent to). */
  url: string
  method?: string
  /** Raw body that will be sent (string). The content-digest binds to this. */
  body: string
  /** Server-issued one-time nonce (from the ANP-03 challenge / /nonce endpoint). */
  nonce: string
  /** Optional extra headers that ARE covered by the signature. */
  headers?: Record<string, string>
  /** Lifetime in seconds. Defaults to 300 (server uses a 300s freshness skew). */
  ttl?: number
}

export interface SignedRequest {
  did: string
  keyid: string
  didDocument: Record<string, unknown>
  /** The exact body bytes the signature covers. The caller must POST this. */
  body: string
  /** Headers to merge into the outgoing request (lowercase keys). */
  headers: {
    'content-digest': string
    'signature-input': string
    signature: string
  }
}

/**
 * Sign an ANP-03 request with the wallet key. Produces RFC 9421 headers in the
 * official labeled binary format: `Signature: sig1=:<base64>:` so a server that
 * accepts the official `pip install anp` client accepts ours too.
 *
 * The caller merges the returned `headers` (plus `content-type: application/json`)
 * into its POST. The returned `didDocument` should be inlined into the body so a
 * server without a reachable `.well-known` host can resolve the key.
 */
export function signAnpLoginRequest(
  identity: DidWbaIdentity,
  priv: Uint8Array,
  req: SignRequest,
): SignedRequest {
  const components = [...COVERED_COMPONENTS]
  const method = req.method ?? 'POST'
  const now = Math.floor(Date.now() / 1000)
  const ttl = req.ttl ?? 300

  const contentDigestValue = contentDigest(req.body)

  // The digest is a covered header; merge it before/while evaluating headers.
  const coveredHeaders = { ...(req.headers ?? {}), 'content-digest': contentDigestValue }

  const params: SignatureParams = {
    created: now,
    expires: now + ttl,
    nonce: req.nonce,
    keyid: identity.keyid,
  }

  const base = buildSignatureBase(
    components,
    { method, url: req.url, headers: coveredHeaders },
    params,
  )

  const signature = ed25519.sign(utf8ToBytes(base), priv)
  const signatureHeader = `sig1=:${base64.encode(signature)}:`

  return {
    did: identity.did,
    keyid: identity.keyid,
    didDocument: identity.didDocument,
    body: req.body,
    headers: {
      'content-digest': contentDigestValue,
      'signature-input': buildSignatureInputHeader(components, params),
      signature: signatureHeader,
    },
  }
}
