// Shared message shapes for the ANP wallet extension. This module is pure
// (no imports) so it can be inlined into every bundle — background, content,
// injected, and popup — without side effects.

// A signing request from a website. The wallet produces RFC 9421 headers for
// the given target URL / body / nonce. The caller performs the actual HTTP POST.
export interface SignReq {
  /** Full target URL (must equal the URL the request is actually sent to). */
  url: string
  method?: string
  /** Raw request body (JSON string). The content-digest binds to these bytes. */
  body: string
  /** Server-issued one-time nonce (from the ANP-03 /nonce endpoint or challenge). */
  nonce: string
  /** Optional extra headers that ARE covered by the signature. */
  headers?: Record<string, string>
}

export interface SignResult {
  did: string
  keyid: string
  didDocument: Record<string, unknown>
  /** The exact body bytes the signature covers. The caller must POST this. */
  body: string
  /** Merge these (plus `content-type: application/json`) into the outgoing POST. */
  headers: Record<string, string>
}

export interface IdentityInfo {
  did: string
  keyid: string
  publicKeyMultibase: string
  /** Inline DID document — a site embeds this in the request body so a server
   *  without a reachable .well-known host can resolve the key. */
  didDocument: Record<string, unknown>
}

export interface PendingRequest {
  id: string
  url: string
  method: string
  nonce: string
  bodyPreview: string
  did: string
  pageOrigin: string
}

/**
 * A single key = a single independent DID. Slip-0010-derived from the *wallet's*
 * own mnemonic at `m/44'/0'/<index>'`, so each key within a wallet is a distinct
 * DID (signing keypair). `index` is the derivation path index — NOT an array
 * position. `activeKeyIndex` / handler `keyIndex` args are array positions.
 */
export interface StoredKey {
  /** SLIP-0010 path index, monotonic and never reused after a delete. */
  index: number
  /** Full handle name claimed on the server during registration. */
  handle: string
  did: string
  keyid: string
  publicKeyMultibase: string
  didDocument: Record<string, unknown>
  /** Set once the server confirms the handle→DID binding. */
  registered?: boolean
  accessToken?: string
}

/**
 * A wallet = one independent mnemonic in its own encrypted blob (under the one
 * global wallet password). It owns one handle and derives many keys (DIDs).
 */
export interface Wallet {
  id: string
  /** Display label, e.g. `钱包 1` / `工作`. */
  label: string
  /** The single handle this wallet corresponds to. */
  handle: string
  // This wallet's mnemonic, encrypted under the ONE global password:
  salt: string
  iv: string
  ciphertext: string
  /** Monotonic per-wallet derivation-index source; never decremented on delete. */
  nextKeyIndex: number
  /** Array position of the default signing key within `keys`. */
  activeKeyIndex: number
  /** Array position of the PRIMARY (owner/master) key within `keys`. The primary
   *  registers the handle against the server and cannot be deleted. */
  primaryKeyIndex: number
  keys: StoredKey[]
  /** Set once the handle's aggregate ad.json has been submitted to the server. */
  registered?: boolean
  /** The last aggregate `ad.json` submitted for this handle (display/provenance). */
  handleDocuments?: Record<string, unknown>
}

export interface StoredAccount {
  version: 4
  wallets: Wallet[]
  /** The wallet the user is currently on. Null when the account has no wallets. */
  activeWalletId: string | null
}

/** Reference to the currently selected signing key (wallet + key position). */
export interface ActiveKeyRef {
  walletId: string
  keyIndex: number
}

/** Lightweight view of a wallet for the switcher / list (no secrets). */
export interface WalletSummary {
  id: string
  label: string
  handle: string
  activeKeyIndex: number
  keyCount: number
  registeredCount: number
}

export type AccountState = StoredAccount | null

// ---- window.postMessage protocol (h o s t page <-> injected <-> content) ----
export const PAGE_MESSAGE = 'anp-wallet'
export type PageMethod = 'sign-anp-login' | 'get-identity' | 'ping'

export interface PageMessage {
  wrap: typeof PAGE_MESSAGE
  id: string
  method: PageMethod
  req?: SignReq
  status?: 'ok' | 'error' | 'rejected' | 'locked'
  result?: SignResult | IdentityInfo
  error?: string
}

// ---- chrome.runtime messaging (content/popup -> background) ----
export type BgRequest =
  | { type: 'anp-wallet/sign'; payload: { id: string; req: SignReq } }
  | { type: 'anp-wallet/get-identity' }
  | { type: 'anp-wallet/get-state' }
  | { type: 'anp-wallet/unlock'; password: string }
  | { type: 'anp-wallet/lock' }
  | { type: 'anp-wallet/create-account'; mnemonic: string; password: string; handle?: string; label?: string }
  | { type: 'anp-wallet/add-wallet'; mnemonic: string; handle?: string; label?: string }
  | { type: 'anp-wallet/delete-wallet'; walletId: string }
  | { type: 'anp-wallet/rename-wallet'; walletId: string; label: string }
  | { type: 'anp-wallet/select-wallet'; walletId: string }
  | { type: 'anp-wallet/list-wallets' }
  | { type: 'anp-wallet/register'; walletId: string; handle: string }
  | { type: 'anp-wallet/add-key'; walletId: string }
  | { type: 'anp-wallet/delete-key'; walletId: string; keyIndex: number }
  | { type: 'anp-wallet/select-active'; walletId: string; keyIndex: number }
  | { type: 'anp-wallet/set-primary'; walletId: string; keyIndex: number }
  | { type: 'anp-wallet/approve'; id: string; sel?: { walletId: string; keyIndex: number } }
  | { type: 'anp-wallet/reject'; id: string }
  | { type: 'anp-wallet/export-mnemonic' }

export type BgResponse =
  | SignResult
  | IdentityInfo
  | { status: 'ok' | 'pending' | 'locked' | 'no-account' | 'no-key'; [k: string]: unknown }
  | { did?: string; [k: string]: unknown }

// background -> content (after approval), routed via tabs.sendMessage
export interface SignResultMessage {
  wrap: typeof PAGE_MESSAGE
  id: string
  status: 'ok' | 'error' | 'rejected' | 'locked'
  result?: SignResult
  error?: string
}
