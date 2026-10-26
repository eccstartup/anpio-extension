// Verify the e1 path-binding case: did:wba with port + path segments appends
// `e1_<multikey fingerprint>` and the official verifier accepts a signature
// keyed by that DID.
import { deriveEd25519PrivateKey, buildDidWbaIdentity, signAnpLoginRequest } from '../src/lib/anp'
import { writeFileSync } from 'node:fs'

const mnemonic =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
const priv = deriveEd25519PrivateKey(mnemonic)
const id = buildDidWbaIdentity(
  { hostname: 'localhost', port: 3000, pathSegments: ['user', 'alice'] },
  priv,
)
console.log('did      :', id.did)
console.log('keyid    :', id.keyid)

const url = 'http://localhost:3000/api/login/anp/verify'
const nonce = 'a'.repeat(32)
const body = JSON.stringify({ nonce, didDocument: id.didDocument })
const signed = signAnpLoginRequest(id, priv, { url, method: 'POST', body, nonce })
writeFileSync(
  '/tmp/anp-path-signed.json',
  JSON.stringify(
    { request_method: 'POST', request_url: url, didDocument: id.didDocument, headers: { ...signed.headers }, body },
    null,
    2,
  ),
)
console.log('signature-input:', signed.headers['signature-input'])
