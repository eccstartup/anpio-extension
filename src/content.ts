// ANP wallet content script — runs in the ISOLATED world.
//
// Bridges the host page (MAIN world, talks via window.postMessage) and the
// background service worker (chrome.runtime). Relay only — no keys here.
import { PAGE_MESSAGE, type PageMessage, type SignResultMessage, type SignReq, type SignResult, type IdentityInfo } from './protocol'

// Page (injected) -> content -> background
window.addEventListener('message', (event) => {
  if (event.source !== window) return
  const data = event.data as PageMessage
  if (!data || data.wrap !== PAGE_MESSAGE || typeof data.id !== 'string') return
  if (data.method !== 'sign-anp-login' && data.method !== 'get-identity') return
  void relay(data)
})

async function relay(data: PageMessage) {
  if (data.method === 'get-identity') {
    const resp = (await chrome.runtime.sendMessage({ type: 'anp-wallet/get-identity' })) as
      | IdentityInfo
      | { status?: string; error?: string }
    const identity = resp as IdentityInfo
    if (identity && identity.did && identity.keyid) {
      deliver(data.id, { wrap: PAGE_MESSAGE, id: data.id, method: 'get-identity', status: 'ok', result: identity })
    } else {
      deliver(data.id, {
        wrap: PAGE_MESSAGE,
        id: data.id,
        method: 'get-identity',
        status: 'error',
        error: (resp as { error?: string }).error ?? 'no account',
      })
    }
    return
  }

  // sign-anp-login: background acks pending/locked synchronously, but the real
  // result arrives later (after the user approves in the popup) via the
  // runtime.onMessage handler below. So do not resolve the page promise here.
  let status = 'pending'
  let error: string | undefined
  try {
    const resp = (await chrome.runtime.sendMessage({
      type: 'anp-wallet/sign',
      payload: { id: data.id, req: data.req as SignReq },
    })) as { status?: string; error?: string }
    status = resp?.status ?? 'pending'
    error = resp?.error
  } catch (e) {
    status = 'error'
    error = e instanceof Error ? e.message : 'background unreachable'
  }

  // Locked / immediate errors are delivered now; 'pending' waits for approval.
  if (status !== 'pending') {
    deliver(data.id, { wrap: PAGE_MESSAGE, id: data.id, method: 'sign-anp-login', status: status === 'locked' ? 'locked' : 'error', error })
  }
}

// Delayed result arrives after popup approval; route it to the page that asked.
chrome.runtime.onMessage.addListener((msg: SignResultMessage) => {
  if (!msg || msg.wrap !== PAGE_MESSAGE || typeof msg.id !== 'string') return
  deliver(msg.id, msg as unknown as PageMessage)
})

function deliver(id: string, msg: PageMessage) {
  window.postMessage({ ...msg, wrap: PAGE_MESSAGE, id }, '*')
}

export type { SignResult }
