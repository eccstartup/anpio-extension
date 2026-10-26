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

// ---------------------------------------------------------------------------
// Registration servers
// ---------------------------------------------------------------------------

/**
 * `did_document` is the awiki.ai production contract: one DID document bound to
 * one handle. `aggregate` is the older local open-server flow kept only for
 * wallets migrated from v4.
 */
export type RegisterMode = 'did_document' | 'aggregate'

export interface ServerConfig {
  id: string
  label: string
  /** RPC root URL without a trailing slash, e.g. https://awiki.ai. */
  rpcBase: string
  /** DID authority, e.g. awiki.ai. Must match the discovered document's id. */
  didDomain: string
  /** Internal/migration hint; new servers are always did_document. */
  registerMode?: RegisterMode
  builtin?: boolean
}

export interface ServerRegistry {
  version: 1
  servers: ServerConfig[]
  defaultServerId: string
}

export interface DiscoveredServer {
  didDomain: string
  /** The ANPMessageService descriptor copied verbatim from .well-known/did.json. */
  service: Record<string, unknown>
  source: 'well-known' | 'fallback'
}

// ---------------------------------------------------------------------------
// Wallet storage (v5)
// ---------------------------------------------------------------------------

/**
 * A single key = a single independent DID. For mnemonic wallets it is derived
 * from the wallet's mnemonic at `m/44'/0'/<index>'`; for imported wallets it was
 * supplied directly. `index` is monotonic and never reused after a delete.
 */
export interface StoredKey {
  /** Mnemonic wallets: derivation path index. Imported wallets: import order. */
  index: number
  /** Full handle claimed on the server during registration. */
  handle: string
  did: string
  keyid: string
  publicKeyMultibase: string
  didDocument: Record<string, unknown>
  /** Set once the server confirms this key's DID/handle binding. */
  registered?: boolean
}

export type WalletKind = 'mnemonic' | 'imported'

/**
 * A wallet owns exactly one secret source: a BIP39 mnemonic or an imported set
 * of Ed25519 seeds. Both are encrypted in one blob under the global password.
 */
export interface Wallet {
  kind: WalletKind
  id: string
  /** Display label, e.g. `钱包 1` / `工作`. */
  label: string
  /** Full handle this wallet claims, or empty until registration. */
  handle: string
  // Encrypted secret (mnemonic string or imported-key JSON):
  salt: string
  iv: string
  ciphertext: string
  /** Monotonic per-wallet index source; never decremented on delete. */
  nextKeyIndex: number
  /** Array position of the default signing key within `keys`. */
  activeKeyIndex: number
  /** Array position of the PRIMARY (owner/master) key within `keys`. The primary
   *  registers the handle and cannot be deleted. */
  primaryKeyIndex: number
  keys: StoredKey[]
  /** Set once the handle has been registered on the bound server. */
  registered?: boolean
  /** Server-issued account id returned by register/lookup (not a credential). */
  userId?: string
  /** The last submitted DID document (did_document) or aggregate ad.json. */
  handleDocuments?: Record<string, unknown>
  /** Bound registration server; null for legacy localhost wallets. */
  serverId: string | null
  /** DID authority used to build this wallet's DIDs. */
  didDomain: string
  /** Defaults to did_document; aggregate only for migrated v4 wallets. */
  registerMode?: RegisterMode
}

export interface StoredAccount {
  version: 5
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
  kind: WalletKind
  didDomain: string
  serverId: string | null
  registered: boolean
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
  | {
      type: 'anp-wallet/create-account'
      source?: 'mnemonic'
      mnemonic: string
      password: string
      handle?: string
      label?: string
    }
  | {
      type: 'anp-wallet/create-account'
      source: 'imported'
      privateKey: string
      password: string
      handle?: string
      label?: string
    }
  | { type: 'anp-wallet/add-wallet'; source?: 'mnemonic'; mnemonic: string; handle?: string; label?: string }
  | { type: 'anp-wallet/add-wallet'; source: 'imported'; privateKey: string; handle?: string; label?: string }
  | { type: 'anp-wallet/delete-wallet'; walletId: string }
  | { type: 'anp-wallet/rename-wallet'; walletId: string; label: string }
  | { type: 'anp-wallet/select-wallet'; walletId: string }
  | { type: 'anp-wallet/list-wallets' }
  | { type: 'anp-wallet/register'; walletId: string; handle: string; email?: string; inviteCode?: string }
  | { type: 'anp-wallet/verify-existing'; walletId: string; handle: string }
  | { type: 'anp-wallet/add-key'; walletId: string; privateKey?: string }
  | { type: 'anp-wallet/delete-key'; walletId: string; keyIndex: number }
  | { type: 'anp-wallet/select-active'; walletId: string; keyIndex: number }
  | { type: 'anp-wallet/set-primary'; walletId: string; keyIndex: number }
  | { type: 'anp-wallet/rebind-server'; walletId: string; serverId: string }
  | { type: 'anp-wallet/approve'; id: string; sel?: { walletId: string; keyIndex: number } }
  | { type: 'anp-wallet/reject'; id: string }
  | { type: 'anp-wallet/export-secret' }
  | { type: 'anp-wallet/list-servers' }
  | { type: 'anp-wallet/add-server'; rpcBase: string; didDomain: string; label?: string }
  | { type: 'anp-wallet/remove-server'; serverId: string }
  | { type: 'anp-wallet/set-default-server'; serverId: string }
  | { type: 'anp-wallet/test-server'; serverId: string }
  | { type: 'anp-wallet/email-status'; serverId: string; email: string; fullHandle: string }
  | { type: 'anp-wallet/email-send'; serverId: string; email: string; fullHandle: string }

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
