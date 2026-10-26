// awiki-open-server client — plain JSON-RPC 2.0 over HTTP.
//
// Registration is DID-proof + one-time challenge. The wallet prepends the
// self-signed eddsa-jcs-2022 proof on the DID document, but the server also
// demands the submitting client prove possession of the key *right now* by
// signing a server-issued challenge. getChallenge() fetches that nonce; the
// caller signs it with signChallenge() and passes it to registerIdentity().
// No SMS/email OTP.
import { localPartFromHandle } from './anp'

// Point the wallet at a self-hosted AWiki community server. Default is a local
// awiki-open-server on 127.0.0.1:8765 with DID domain `localhost`. Change these
// to point at another domain (e.g. `https://community.example.com`).
export const AWIKI_BASE = 'http://127.0.0.1:8765'
export const AWIKI_DID_DOMAIN = 'localhost'
export const AWIKI_ANP_ENDPOINT = `${AWIKI_BASE}/anp-im/rpc`
export const AWIKI_SERVICE_DID = `did:wba:${AWIKI_DID_DOMAIN}`

interface JsonRpcEnvelope {
  jsonrpc: string
  id: string
  result?: unknown
  error?: { code: number; message: string; data?: unknown } | null
}

async function rpc(endpoint: string, method: string, params: Record<string, unknown>): Promise<unknown> {
  const res = await fetch(`${AWIKI_BASE}${endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 'req-1', method, params }),
  })
  const body = (await res.json().catch(() => ({}))) as JsonRpcEnvelope
  if (body.error) {
    throw new Error(`awiki ${method}: ${body.error.message} (code ${body.error.code})`)
  }
  return body.result
}

export interface AwikiChallenge {
  challenge: string
  created_at: string
  expires_at: string
  expires_in: number
}

/** Ask the server for a fresh one-time challenge to sign during registration. */
export function getChallenge(): Promise<AwikiChallenge> {
  return rpc('/user-service/v1/did-auth/rpc', 'challenge', {}) as Promise<AwikiChallenge>
}

/**
 * Claim a handle by registering its aggregate `ad.json` (one per handle, listing
 * every key/DID under it) plus a freshly signed challenge. No OTP. `handle` is
 * the full WNS handle (`alice.localhost`); `ad` is the aggregate doc built by
 * `buildHandleAggregateDoc`; the submitting key is `submittingDid` (its DID must
 * appear in `ad.dids`). The server verifies the aggregate self-sign and the
 * challenge signature against the submitting key, then binds the handle to ALL
 * DIDs in `ad.dids`.
 */
export function registerIdentity(
  ad: Record<string, unknown>,
  handle: string,
  challenge: string,
  challengeSignature: string,
  submittingDid: string,
): Promise<unknown> {
  const localPart = localPartFromHandle(handle, AWIKI_DID_DOMAIN)
  return rpc('/user-service/v1/did-auth/rpc', 'register', {
    ad,
    handle: localPart,
    challenge,
    challenge_signature: challengeSignature,
    submitting_did: submittingDid,
  })
}
