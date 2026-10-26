// Manual/live registration check against a real server, driven entirely by env
// vars. It uses the wallet's real modules (src/lib/anp.ts + src/lib/awiki.ts),
// not background.ts, so it verifies the wire contract itself.
//
// Defaults to the local legacy open-server:
//   npm run verify:did
// awiki.ai production (requires a real mailbox unless the handle is pre-verified):
//   AWIKI_LIVE=1 AWIKI_EMAIL=you@example.com npx tsx scripts/verify-did-register.ts
// Other server:
//   AWIKI_RPC_BASE=https://reg.example.com AWIKI_DID_DOMAIN=reg.example.com \
//   AWIKI_EMAIL=you@example.com npx tsx scripts/verify-did-register.ts
//
// Modes:
//   AWIKI_MODE=did_document (default) | aggregate (legacy local open-server)
//   AWIKI_HANDLE=alice          local part; defaults to a timestamped test handle
//   AWIKI_MNEMONIC="..."        reuse a key; otherwise one is generated
//   AWIKI_PRIVATE_KEY=0x...     Ed25519 identity key (hex/base64/base58/JWK)
//   AWIKI_INVITE_CODE=...       forwarded only when non-empty
//   AWIKI_REPLAY=1              legacy aggregate: also prove challenge single-use
//
// The mnemonic/private key is never printed. Registration mints a fresh DID, so
// re-running with the same key is fine but creates a new handle each time.
import {
  buildAwikiIdentity,
  buildHandleAggregateDoc,
  deriveEd25519PrivateKey,
  generateMnemonicPhrase,
  parseEd25519PrivateKey,
  signChallenge,
} from '../src/lib/anp'
import type { AwikiMessageService } from '../src/lib/anp'
import {
  AWIKI_DID_DOMAIN,
  AWIKI_RPC_BASE,
  discoverServer,
  getChallenge,
  lookupHandle,
  registerAggregate,
  registerDidDocument,
} from '../src/lib/awiki'
import type { ServerConfig } from '../src/protocol'

type Mode = 'did_document' | 'aggregate'

function env(name: string): string {
  return (process.env[name] ?? '').trim()
}

function fail(message: string): never {
  console.error('FAIL:', message)
  process.exit(1)
}

function loadPrivateKey(): Uint8Array {
  const rawKey = env('AWIKI_PRIVATE_KEY')
  if (rawKey) return parseEd25519PrivateKey(rawKey).seed
  const mnemonic = env('AWIKI_MNEMONIC')
  if (mnemonic) return deriveEd25519PrivateKey(mnemonic)
  return deriveEd25519PrivateKey(generateMnemonicPhrase())
}

async function checkLookup(server: ServerConfig, fullHandle: string, did: string): Promise<void> {
  const result = await lookupHandle(server, fullHandle)
  if (result.did !== did) {
    fail(`lookup returned ${JSON.stringify(result.did)}, expected ${did}`)
  }
  if (result.status && result.status !== 'active' && result.status !== 'registered') {
    fail(`lookup status is ${JSON.stringify(result.status)}`)
  }
  console.log(
    '  lookup :',
    result.did,
    '->',
    result.full_handle ?? fullHandle,
    `(status ${result.status ?? 'n/a'})`,
  )
}

async function main() {
  const live = env('AWIKI_LIVE') === '1'
  const rpcBase = env('AWIKI_RPC_BASE') || (live ? AWIKI_RPC_BASE : 'http://127.0.0.1:8765')
  const didDomain = env('AWIKI_DID_DOMAIN') || (live ? AWIKI_DID_DOMAIN : 'localhost')
  const mode = (env('AWIKI_MODE') || 'did_document') as Mode
  if (mode !== 'did_document' && mode !== 'aggregate') {
    fail(`AWIKI_MODE must be did_document or aggregate, got ${mode}`)
  }

  const server: ServerConfig = {
    id: 'verify',
    label: 'verify',
    rpcBase,
    didDomain,
    registerMode: mode,
    ...(live && didDomain === AWIKI_DID_DOMAIN ? { builtin: true } : {}),
  }
  const email = env('AWIKI_EMAIL')
  if (mode === 'did_document' && !email) {
    fail('AWIKI_EMAIL is required for did_document registration (email is only sent, never stored)')
  }

  const stamp = Date.now().toString(36)
  const local = env('AWIKI_HANDLE') || `tester-${stamp}`
  const fullHandle = `${local}.${didDomain}`
  const priv = loadPrivateKey()
  const invite = env('AWIKI_INVITE_CODE')

  console.log(`server : ${rpcBase} (DID domain ${didDomain})`)
  console.log(`mode   : ${mode}`)
  console.log(`handle : ${fullHandle}`)

  const discovered = await discoverServer(server)
  const messageService = discovered.service as AwikiMessageService
  console.log(`discover: ${discovered.source}, ${messageService.serviceEndpoint}`)

  const identity = buildAwikiIdentity(fullHandle, priv, didDomain, messageService)
  console.log('  did    :', identity.did)

  if (mode === 'did_document') {
    const result = await registerDidDocument(server, local, email, identity.didDocument, invite)
    if (result.state !== 'registered') {
      fail(`register returned state=${JSON.stringify(result.state)}: ${JSON.stringify(result)}`)
    }
    if (result.did && result.did !== identity.did) {
      fail(`register returned DID ${result.did}, expected ${identity.did}`)
    }
    console.log('OK registered did_document (self-signed proof + email)')
    console.log('  full   :', result.full_handle ?? fullHandle)
    console.log('  user   :', result.user_id ?? 'n/a')
    await checkLookup(server, fullHandle, identity.did)
    return
  }

  // ---- legacy aggregate -----------------------------------------------------
  async function aggregateOnce(handleLocal: string, challenge: string, signature: string): Promise<string> {
    const full = `${handleLocal}.${didDomain}`
    const one = buildAwikiIdentity(full, priv, didDomain, messageService)
    const ad = buildHandleAggregateDoc(
      full,
      [{ did: one.did, publicKeyMultibase: one.publicKeyMultibase }],
      one.did,
      priv,
      { didDomain, messageService },
    )
    const result = (await registerAggregate(
      server,
      ad,
      full,
      challenge,
      signature,
      one.did,
      email || undefined,
    )) as Record<string, unknown>
    if (!result?.did || !(result.access_token || result.token)) {
      fail(`aggregate register returned ${JSON.stringify(result)}`)
    }
    if (result.did !== one.did) fail(`aggregate returned DID ${result.did}, expected ${one.did}`)
    return one.did
  }

  const chal = await getChallenge(server)
  if (!chal?.challenge) fail('no challenge from server')
  const signature = signChallenge(priv, chal.challenge)
  const did = await aggregateOnce(local, chal.challenge, signature)
  console.log('OK registered aggregate (DID proof + one-time challenge)')
  console.log('  did    :', did)
  await checkLookup(server, fullHandle, did)

  if (env('AWIKI_REPLAY') === '1') {
    let rejected = false
    try {
      await aggregateOnce(`replay-${stamp}`, chal.challenge, signature)
    } catch (e) {
      rejected = true
      console.log('  replay :', e instanceof Error ? e.message : String(e))
    }
    if (!rejected) fail('replaying the same challenge was NOT rejected')

    const chal2 = await getChallenge(server)
    if (!chal2?.challenge) fail('no second challenge from server')
    const second = await aggregateOnce(`replay-${stamp}`, chal2.challenge, signChallenge(priv, chal2.challenge))
    console.log('  fresh  :', second, 'registered with a fresh challenge')
  }
}

main().catch((e) => {
  console.error('FAIL:', e instanceof Error ? e.message : e)
  process.exit(1)
})
