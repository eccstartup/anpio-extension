// End-to-end check: register a handle on a local awiki-open-server using the
// DID document's self-signed proof PLUS a fresh one-time challenge signature
// (no OTP), via the wallet's real modules (src/lib/anp.ts + src/lib/awiki.ts).
// Also proves the challenge is single-use: replaying the same challenge for a
// second handle fails. Mirrors background.ts `buildIdentity`.
import {
  buildAwikiIdentity,
  buildHandleAggregateDoc,
  deriveEd25519PrivateKey,
  generateMnemonicPhrase,
  signChallenge,
} from '../src/lib/anp'
import {
  AWIKI_BASE,
  AWIKI_DID_DOMAIN,
  AWIKI_ANP_ENDPOINT,
  AWIKI_SERVICE_DID,
  getChallenge,
  registerIdentity,
} from '../src/lib/awiki'

const MESSAGE_SERVICE = { serviceEndpoint: AWIKI_ANP_ENDPOINT, serviceDid: AWIKI_SERVICE_DID }

async function registerOne(
  local: string,
  priv: Uint8Array,
  challenge: string,
  challengeSig: string,
): Promise<{ did: string; handle: string }> {
  const fullHandle = `${local}.${AWIKI_DID_DOMAIN}`
  const identity = buildAwikiIdentity(fullHandle, priv, AWIKI_DID_DOMAIN, MESSAGE_SERVICE)
  const ad = buildHandleAggregateDoc(
    fullHandle,
    [{ did: identity.did, publicKeyMultibase: identity.publicKeyMultibase }],
    identity.did,
    priv,
    { didDomain: AWIKI_DID_DOMAIN, messageService: MESSAGE_SERVICE },
  )
  const result = (await registerIdentity(
    ad,
    fullHandle,
    challenge,
    challengeSig,
    identity.did,
  )) as Record<string, unknown>
  if (!result?.did || !(result.access_token || result.token)) {
    throw new Error(`register returned ${JSON.stringify(result)}`)
  }
  return { did: String(result.did), handle: fullHandle }
}

async function main() {
  const mnemonic = generateMnemonicPhrase()
  const priv = deriveEd25519PrivateKey(mnemonic)
  const stamp = Date.now().toString(36)

  // 1. Fetch a fresh one-time challenge and sign it.
  const chal = await getChallenge()
  if (!chal?.challenge) throw new Error('no challenge from server')
  const challengeSig = signChallenge(priv, chal.challenge)

  // 2. Register using the signed challenge.
  const ok = await registerOne(`alice-${stamp}`, priv, chal.challenge, challengeSig)
  console.log('OK registered (DID proof + one-time challenge, no OTP)')
  console.log('  handle :', ok.handle)
  console.log('  did    :', ok.did)

  // 3. The same challenge is single-use: replaying it for another handle fails.
  let replayRejected = false
  try {
    await registerOne(`mallory-${stamp}`, priv, chal.challenge, challengeSig)
  } catch (e) {
    replayRejected = true
    console.log('  replay :', (e as Error).message)
  }
  if (!replayRejected) {
    console.error('FAIL: replaying the same challenge was NOT rejected')
    process.exit(1)
  }

  // 4. A fresh challenge for the second handle works.
  const chal2 = await getChallenge()
  const sig2 = signChallenge(priv, chal2.challenge)
  const ok2 = await registerOne(`mallory-${stamp}`, priv, chal2.challenge, sig2)
  console.log('  fresh  :', ok2.did, '->', ok2.handle, 'registered')

  // 5. Confirm handle -> DID resolution round-trips.
  const lookup = await fetch(`${AWIKI_BASE}/user-service/v1/handle/rpc`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 'req-2', method: 'lookup', params: { handle: ok.handle } }),
  }).then((r) => r.json())
  const lr = (lookup as { result?: Record<string, unknown>; error?: unknown }).result
  if (!lr?.did || lr.did !== ok.did) {
    console.error('FAIL: lookup mismatch', JSON.stringify(lookup, null, 2))
    process.exit(1)
  }
  console.log('  lookup :', lr.did, '->', lr.full_handle, '(status', lr.status + ')')
}

main().catch((e) => {
  console.error('FAIL:', e)
  process.exit(1)
})
