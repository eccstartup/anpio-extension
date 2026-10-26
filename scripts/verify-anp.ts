// Verification harness for the ANP wallet signing core.
//
// Two independent checks:
//   (A) Protocol correctness: feed our produced Signature-Input / Signature /
//       Content-Digest + inline DID document to the OFFICIAL `pip install anp`
//       `verify_http_message_signature`. If it returns True, our wire format is
//       byte-for-byte compatible with the official client.
//   (B) Real login: complete the ANP-03 handshake against the local Agent World
//       server and use the returned Bearer token on /api/me.
//
// Deterministic mnemonic so output is reproducible across runs.
import {
  deriveEd25519PrivateKey,
  buildDidWbaIdentity,
  signAnpLoginRequest,
  computeMultikeyFingerprint,
  publicKeyFromPrivateKey,
} from '../src/lib/anp'
import { writeFileSync } from 'node:fs'

const BASE = process.env.AGWORLD_URL ?? 'http://localhost:3000'
const TARGET = `${BASE}/api/login/anp/verify`
const DID_HOST = process.env.AGWORLD_DID_HOST ?? 'agent-123.example.com'

// Standard BIP39 zero-entropy test vector (always valid).
const TEST_MNEMONIC =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

async function main() {
  const priv = deriveEd25519PrivateKey(TEST_MNEMONIC)
  // Host-only e1 identity, exactly like the official agent example.
  const identity = buildDidWbaIdentity({ hostname: DID_HOST }, priv)
  const pub = publicKeyFromPrivateKey(priv)

  console.log('=== identity ===')
  console.log('mnemonic  :', TEST_MNEMONIC)
  console.log('multibase :', identity.publicKeyMultibase)
  console.log('fingerprint:', computeMultikeyFingerprint(pub))
  console.log('did       :', identity.did)
  console.log('keyid     :', identity.keyid)
  console.log('didDocument:', JSON.stringify(identity.didDocument))

  // (A) fetch a real server nonce and sign the login POST.
  const { nonce } = await fetch(`${BASE}/api/login/anp/nonce`).then((r) => r.json())
  const body = JSON.stringify({ nonce, didDocument: identity.didDocument })
  const signed = signAnpLoginRequest(identity, priv, {
    url: TARGET,
    method: 'POST',
    body,
    nonce,
  })

  console.log('\n=== signature ===')
  console.log('signature-input:', signed.headers['signature-input'])
  console.log('content-digest :', signed.headers['content-digest'])
  console.log('signature      :', signed.headers.signature)

  // Hand the exact wire artifacts to the official verifier for check (A).
  writeFileSync(
    '/tmp/anp-signed.json',
    JSON.stringify(
      {
        request_method: 'POST',
        request_url: TARGET,
        didDocument: identity.didDocument,
        headers: { ...signed.headers },
        body,
      },
      null,
      2,
    ),
  )
  console.log('\nwrote /tmp/anp-signed.json for official cross-check')

  // (B) Real handshake against the server.
  console.log('\n=== server e2e ===')
  let res = await fetch(TARGET, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...signed.headers },
    body,
  })
  let data = await res.json().catch(() => ({}))
  console.log('try#1 POST ->', res.status)

  if (res.status === 401) {
    const www = res.headers.get('www-authenticate') ?? ''
    console.log('challenge:', www)
    const challengeNonce = /nonce="([^"]+)"/.exec(www)?.[1]
    if (!challengeNonce) throw new Error('401 without challenge nonce')
    const body2 = JSON.stringify({ nonce: challengeNonce, didDocument: identity.didDocument })
    const signed2 = signAnpLoginRequest(identity, priv, {
      url: TARGET,
      method: 'POST',
      body: body2,
      nonce: challengeNonce,
    })
    res = await fetch(TARGET, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...signed2.headers },
      body: body2,
    })
    data = await res.json().catch(() => ({}))
    console.log('try#2 challenge-resign ->', res.status)
  }

  const token = data.token ?? ''
  console.log('login token present:', Boolean(token))
  if (!res.ok) {
    console.log('login failed body:', JSON.stringify(data))
    process.exit(1)
  }

  const me = await fetch(`${BASE}/api/me`, {
    headers: { authorization: `Bearer ${token}` },
  })
  const meJson = await me.json().catch(() => ({}))
  console.log('/api/me with Bearer ->', me.status, 'identity.did =', meJson.identity?.did)
  const didOk = meJson.identity?.did === identity.did

  console.log(
    '\nRESULT:',
    res.ok && didOk ? 'PASS ✅ (server login + Bearer /api/me)' : 'FAIL ❌',
  )
  if (!(res.ok && didOk)) process.exit(1)
}

main().catch((e) => {
  console.error('ERROR', e)
  process.exit(1)
})
