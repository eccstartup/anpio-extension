// ANP wallet injected API — runs in the MAIN world (page context).
//
// Exposes a `window.anp` object analogous to EIP-1193. A website can:
//   await window.anp.signAnpLogin({ url, body, nonce })  => SignedRequest
//   await window.anp.getIdentity()                        => IdentityInfo
//
// It cannot use chrome.* APIs and holds no keys — everything is relayed to the
// content script (ISOLATED world) via window.postMessage, which forwards to the
// background service worker. The wallet never exposes the private key to the
// page; the page only ever receives signed headers.
import { PAGE_MESSAGE, type PageMessage, type SignReq, type SignResult, type IdentityInfo } from './protocol'

const pending = new Map<string, { resolve: (v: unknown) => void; reject: (e: Error) => void }>()

let seq = 0

function post(msg: PageMessage) {
  window.postMessage({ ...msg, wrap: PAGE_MESSAGE }, '*')
}

function request(method: 'sign-anp-login' | 'get-identity', req?: SignReq): Promise<SignResult | IdentityInfo> {
  const id = `anp-${Date.now().toString(36)}-${seq++}`
  return new Promise<SignResult | IdentityInfo>((resolve, reject) => {
    pending.set(id, { resolve: resolve as (v: unknown) => void, reject })
    post({ wrap: PAGE_MESSAGE, id, method, req })
  })
}

window.addEventListener('message', (event) => {
  if (event.source !== window) return
  const data = event.data as PageMessage
  if (!data || data.wrap !== PAGE_MESSAGE || typeof data.id !== 'string') return
  // The outgoing request we just posted echoes back onto this same window; it
  // carries no `status`, so ignore it and only respond to actual results.
  if (data.status == null) return
  const p = pending.get(data.id)
  if (!p) return
  pending.delete(data.id)
  if (data.status === 'ok' && data.result) {
    p.resolve(data.result)
  } else {
    const detail = data.error ?? (data.status === 'rejected' ? 'Rejected by user' : data.status ?? 'unknown error')
    p.reject(new Error(detail))
  }
})

const anp = {
  isAnpWallet: true,
  names: ['anp'],
  version: '0.1.0',

  /** Sign an ANP-03 login request; returns the RFC 9421 headers to attach. */
  signAnpLogin(req: SignReq): Promise<SignResult> {
    return request('sign-anp-login', req) as Promise<SignResult>
  },

  /** Read-only identity info (no signing, no unlock required). */
  getIdentity(): Promise<IdentityInfo> {
    return request('get-identity') as Promise<IdentityInfo>
  },
}

let installed = false
if (!installed) {
  // Keep a reference so a page can feature-detect without a prior promise.
  ;(window as unknown as { anp: typeof anp }).anp = anp
  installed = true
}

export {}
