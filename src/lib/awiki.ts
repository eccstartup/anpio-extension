// Registration-server client (awiki.ai or a self-hosted compatible server).
//
// Discovery is `GET <rpcBase>/.well-known/did.json`; user-service calls are
// JSON-RPC 2.0 (or the two email endpoints) and MUST carry the client version
// header, otherwise awiki.ai answers `-32004 client.upgrade_required`.
import { didDomainOf, localPartFromHandle } from './anp'
import type { DiscoveredServer, ServerConfig } from '../protocol'

/** awiki.ai's current minimum client version. Centralised on purpose. */
export const AWIKI_CLIENT_VERSION = 'awiki-cli/0815/1.0.58'

export const AWIKI_RPC_BASE = 'https://awiki.ai'
export const AWIKI_DID_DOMAIN = 'awiki.ai'

export const BUILTIN_AWIKI_SERVER: ServerConfig = {
  id: 'awiki.ai',
  label: 'awiki.ai',
  rpcBase: AWIKI_RPC_BASE,
  didDomain: AWIKI_DID_DOMAIN,
  registerMode: 'did_document',
  builtin: true,
}

/**
 * Known-good ANPMessageService snapshot, used only when awiki.ai's discovery
 * endpoint cannot be reached. A successful discovery always wins.
 */
export const AWIKI_FALLBACK_SERVICE: Record<string, unknown> = {
  id: 'did:wba:awiki.ai#anp-message',
  type: 'ANPMessageService',
  serviceEndpoint: 'https://awiki.ai/anp-im/rpc',
  serviceDid: 'did:wba:awiki.ai',
  profiles: [
    'anp.core.binding.v1',
    'anp.identity.discovery.v1',
    'anp.direct.base.v1',
    'anp.group.base.v2',
    'anp.attachment.v1',
    'anp.federation.relay.v1',
    'awiki.direct.conversation-ref.v1',
    'awiki.final-acceptance.v1',
    'awiki.group.durable-fanout.v1',
  ],
  authSchemes: ['bearer', 'didwba'],
  securityProfiles: ['transport-protected'],
}

export class AwikiRequestError extends Error {
  constructor(
    message: string,
    readonly httpStatus: number | null = null,
    readonly code?: number,
  ) {
    super(message)
    this.name = 'AwikiRequestError'
  }
}

interface JsonRpcEnvelope {
  jsonrpc?: string
  id?: string
  result?: unknown
  error?: { code?: number; message?: string; data?: unknown } | null
}

function baseOf(server: ServerConfig): string {
  return server.rpcBase.replace(/\/+$/, '')
}

function jsonHeaders(): Record<string, string> {
  return {
    'Content-Type': 'application/json',
    'x-awiki-client-version': AWIKI_CLIENT_VERSION,
  }
}

async function readJson(res: Response): Promise<unknown> {
  const text = await res.text()
  if (!text) return {}
  try {
    return JSON.parse(text)
  } catch {
    throw new AwikiRequestError('服务器返回了非 JSON 响应', res.status)
  }
}

async function rpc(
  server: ServerConfig,
  path: string,
  method: string,
  params: Record<string, unknown>,
): Promise<unknown> {
  const res = await fetch(`${baseOf(server)}${path}`, {
    method: 'POST',
    headers: jsonHeaders(),
    body: JSON.stringify({ jsonrpc: '2.0', id: `req-${Date.now()}`, method, params }),
  })
  const body = (await readJson(res)) as JsonRpcEnvelope
  if (!res.ok && !body?.error) {
    throw new AwikiRequestError(`服务器请求失败：HTTP ${res.status}`, res.status)
  }
  if (body?.error) {
    const message = body.error.message || '未知错误'
    throw new AwikiRequestError(
      `awiki ${method}: ${message}${body.error.code != null ? ` (code ${body.error.code})` : ''}`,
      res.status,
      body.error.code,
    )
  }
  return body?.result
}

function isAnpMessageService(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && (value as Record<string, unknown>).type === 'ANPMessageService'
}

/**
 * Fetch and validate the server's service descriptor. For the built-in awiki.ai
 * server only, a network/HTTP/parse failure falls back to the known snapshot;
 * a reachable but malformed document (or a DID-domain mismatch) is always an error.
 */
export async function discoverServer(server: ServerConfig): Promise<DiscoveredServer> {
  let res: Response
  try {
    res = await fetch(`${baseOf(server)}/.well-known/did.json`, {
      method: 'GET',
      headers: { accept: 'application/json' },
    })
  } catch (err) {
    if (server.builtin) {
      return { didDomain: AWIKI_DID_DOMAIN, service: { ...AWIKI_FALLBACK_SERVICE }, source: 'fallback' }
    }
    throw new AwikiRequestError(`无法连接服务器：${err instanceof Error ? err.message : String(err)}`)
  }
  if (!res.ok) {
    if (server.builtin) {
      return { didDomain: AWIKI_DID_DOMAIN, service: { ...AWIKI_FALLBACK_SERVICE }, source: 'fallback' }
    }
    throw new AwikiRequestError(`服务器未发布可用的 .well-known/did.json（HTTP ${res.status}）`, res.status)
  }

  let doc: Record<string, unknown>
  try {
    doc = (await readJson(res)) as Record<string, unknown>
  } catch (err) {
    if (server.builtin) {
      return { didDomain: AWIKI_DID_DOMAIN, service: { ...AWIKI_FALLBACK_SERVICE }, source: 'fallback' }
    }
    throw err
  }

  const id = typeof doc?.id === 'string' ? doc.id : ''
  const didDomain = didDomainOf(id)
  if (!didDomain) throw new AwikiRequestError('服务器的 DID 文档缺少合法 id')
  if (didDomain !== server.didDomain) {
    throw new AwikiRequestError(`服务器 DID 域为 ${didDomain}，与配置的 ${server.didDomain} 不一致`)
  }
  const services = Array.isArray(doc.service) ? doc.service.filter(isAnpMessageService) : []
  if (services.length !== 1) {
    throw new AwikiRequestError(
      `服务器的 DID 文档必须包含恰好一条 ANPMessageService，实际 ${services.length} 条`,
    )
  }
  return { didDomain, service: services[0], source: 'well-known' }
}

export interface AwikiChallenge {
  challenge: string
  created_at: string
  expires_at: string
  expires_in: number
}

/** Ask the legacy aggregate flow for a fresh one-time challenge. */
export function getChallenge(server: ServerConfig): Promise<AwikiChallenge> {
  return rpc(server, '/user-service/v1/did-auth/rpc', 'challenge', {}) as Promise<AwikiChallenge>
}

/**
 * Legacy aggregate registration (local open-server only). Kept for wallets
 * migrated from v4; new wallets use registerDidDocument().
 */
export function registerAggregate(
  server: ServerConfig,
  ad: Record<string, unknown>,
  fullHandle: string,
  challenge: string,
  challengeSignature: string,
  submittingDid: string,
  email?: string,
): Promise<unknown> {
  const localPart = localPartFromHandle(fullHandle, server.didDomain)
  const params: Record<string, unknown> = {
    ad,
    handle: localPart,
    challenge,
    challenge_signature: challengeSignature,
    submitting_did: submittingDid,
  }
  if (email?.trim()) params.email = email.trim()
  return rpc(server, '/user-service/v1/did-auth/rpc', 'register', params)
}

export interface RegisterDidDocumentResult extends Record<string, unknown> {
  state?: string
  did?: string
  user_id?: string
  access_token?: string
  handle?: string
  domain?: string
  full_handle?: string
  binding_generation?: number
}

/**
 * awiki.ai production registration: one self-signed DID document + email.
 * `localPart` is the handle's local part; the caller validates it first.
 */
export async function registerDidDocument(
  server: ServerConfig,
  localPart: string,
  email: string,
  didDocument: Record<string, unknown>,
  inviteCode?: string,
): Promise<RegisterDidDocumentResult> {
  const params: Record<string, unknown> = {
    handle: localPart,
    email,
    did_document: didDocument,
  }
  if (inviteCode?.trim()) params.invite_code = inviteCode.trim()
  const result = await rpc(server, '/user-service/v1/did-auth/rpc', 'register', params)
  return (result ?? {}) as RegisterDidDocumentResult
}

export interface EmailStatus {
  verified: boolean
  verified_at?: string
  email?: string
}

export async function getEmailStatus(
  server: ServerConfig,
  email: string,
  fullHandle: string,
): Promise<EmailStatus> {
  const query = `email=${encodeURIComponent(email)}&handle=${encodeURIComponent(fullHandle)}`
  const res = await fetch(`${baseOf(server)}/user-service/v1/auth/email-status?${query}`, {
    method: 'GET',
    headers: jsonHeaders(),
  })
  const body = (await readJson(res)) as Record<string, unknown>
  if (!res.ok) {
    const detail = typeof body?.message === 'string' ? ` - ${body.message}` : ''
    throw new AwikiRequestError(`邮箱状态查询失败：HTTP ${res.status}${detail}`, res.status)
  }
  return {
    verified: body?.verified === true,
    verified_at: typeof body?.verified_at === 'string' ? body.verified_at : undefined,
    email: typeof body?.email === 'string' ? body.email : undefined,
  }
}

export async function sendEmailVerification(
  server: ServerConfig,
  email: string,
  fullHandle: string,
): Promise<{ message?: string }> {
  const res = await fetch(`${baseOf(server)}/user-service/v1/auth/email-send`, {
    method: 'POST',
    headers: jsonHeaders(),
    body: JSON.stringify({ email, handle: fullHandle }),
  })
  const body = (await readJson(res)) as Record<string, unknown>
  if (!res.ok) {
    const detail = typeof body?.message === 'string' ? ` - ${body.message}` : ''
    throw new AwikiRequestError(`发送验证邮件失败：HTTP ${res.status}${detail}`, res.status)
  }
  return { message: typeof body?.message === 'string' ? body.message : undefined }
}

export interface HandleLookupResult extends Record<string, unknown> {
  did?: string
  user_id?: string
  handle?: string
  domain?: string
  full_handle?: string
  status?: string
}

/** Unauthenticated handle lookup, used to verify an already-registered identity. */
export async function lookupHandle(server: ServerConfig, handle: string): Promise<HandleLookupResult> {
  const result = await rpc(server, '/user-service/v1/handle/rpc', 'lookup', { handle })
  if (!result || typeof result !== 'object') {
    throw new AwikiRequestError('handle 查询返回了空结果')
  }
  return result as HandleLookupResult
}
