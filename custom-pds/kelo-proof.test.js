'use strict'

const assert = require('node:assert/strict')
const crypto = require('node:crypto')
const fs = require('node:fs/promises')
const os = require('node:os')
const path = require('node:path')
const { issueKeloProof, verifyKeloProof, TTL_SECONDS, DERIVATION_CONTEXT } = require('./kelo-proof')

function legacySigningKey(secret) {
  return crypto.createHmac('sha256', secret)
    .update('kelo-id-login-proof-v1', 'utf8')
    .digest()
}

async function run() {
  const previousDirectory = process.env.PDS_DATA_DIRECTORY
  const previousJwtSecret = process.env.PDS_JWT_SECRET
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'kelo-proof-'))

  try {
    process.env.PDS_DATA_DIRECTORY = directory
    process.env.PDS_JWT_SECRET = 'test-pds-jwt-secret-for-kelo-proof-compatibility'
    const did = 'did:plc:abcdefghijklmnopqrstuvwx'
    const issued = issueKeloProof(did)

    assert.equal(TTL_SECONDS, 60)
    assert.equal(DERIVATION_CONTEXT, 'kelo-id-login-proof-v1')
    assert.match(issued.proof, /^kelo-proof:v1:\d{10}:([0-9a-f]{32}):([0-9a-f]{64})$/)

    const [, expString, nonce, signature] = issued.proof.match(/^kelo-proof:v1:(\d{1,12}):([0-9a-f]{32}):([0-9a-f]{64})$/)
    const expectedSignature = crypto.createHmac('sha256', legacySigningKey(process.env.PDS_JWT_SECRET))
      .update('v1|' + did + '|' + expString + '|' + nonce, 'utf8')
      .digest('hex')
    assert.equal(signature, expectedSignature, 'signature must use the established PDS_JWT_SECRET-derived key')

    assert.equal(await verifyKeloProof(did, issued.proof), true)
    assert.equal(await verifyKeloProof(did, issued.proof), false, 'proof must be single-use')

    const concurrent = issueKeloProof(did)
    const concurrentResults = await Promise.all([
      verifyKeloProof(did, concurrent.proof),
      verifyKeloProof(did, concurrent.proof),
    ])
    assert.deepEqual(concurrentResults.sort(), [false, true], 'only one concurrent request may consume a proof')

    const expiredNonce = crypto.randomBytes(16).toString('hex')
    const expiredAt = Math.floor(Date.now() / 1000) - 1
    const expiredMac = crypto.createHmac('sha256', legacySigningKey(process.env.PDS_JWT_SECRET))
      .update('v1|' + did + '|' + expiredAt + '|' + expiredNonce, 'utf8')
      .digest('hex')
    const expiredProof = 'kelo-proof:v1:' + expiredAt + ':' + expiredNonce + ':' + expiredMac
    assert.equal(await verifyKeloProof(did, expiredProof), false, 'expired proof must be rejected')

    const futureNonce = crypto.randomBytes(16).toString('hex')
    const futureAt = Math.floor(Date.now() / 1000) + TTL_SECONDS + 30
    const futureMac = crypto.createHmac('sha256', legacySigningKey(process.env.PDS_JWT_SECRET))
      .update('v1|' + did + '|' + futureAt + '|' + futureNonce, 'utf8')
      .digest('hex')
    const futureProof = 'kelo-proof:v1:' + futureAt + ':' + futureNonce + ':' + futureMac
    assert.equal(await verifyKeloProof(did, futureProof), false, 'proof lifetime cannot exceed 60 seconds')

    assert.equal(await verifyKeloProof('did:plc:anotherdidabcdefghijkl', issued.proof), false, 'proof must be DID-bound')
    const tampered = issued.proof.replace(/.$/, issued.proof.endsWith('0') ? '1' : '0')
    assert.equal(await verifyKeloProof(did, tampered), false, 'tampered MAC must be rejected')

    delete process.env.PDS_JWT_SECRET
    assert.equal(await verifyKeloProof(did, issued.proof), false, 'verification must fail closed without PDS_JWT_SECRET')
  } finally {
    await fs.rm(directory, { recursive: true, force: true })
    if (previousDirectory === undefined) delete process.env.PDS_DATA_DIRECTORY
    else process.env.PDS_DATA_DIRECTORY = previousDirectory
    if (previousJwtSecret === undefined) delete process.env.PDS_JWT_SECRET
    else process.env.PDS_JWT_SECRET = previousJwtSecret
  }
}

run().then(() => console.log('Kelo proof tests passed')).catch((error) => {
  console.error(error)
  process.exitCode = 1
})
