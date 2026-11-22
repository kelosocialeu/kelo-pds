'use strict'

const assert = require('node:assert/strict')
const crypto = require('node:crypto')
const fs = require('node:fs/promises')
const os = require('node:os')
const path = require('node:path')
const { issueKeloProof, verifyKeloProof } = require('./kelo-proof')

async function run() {
  const previousDirectory = process.env.PDS_DATA_DIRECTORY
  const previousSecret = process.env.PDS_KELO_ID_PROOF_SECRET
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'kelo-proof-'))

  try {
    process.env.PDS_DATA_DIRECTORY = directory
    process.env.PDS_KELO_ID_PROOF_SECRET = 'test-secret-that-is-long-enough-for-hmac'
    const did = 'did:plc:abcdefghijklmnopqrstuvwx'
    const issued = issueKeloProof(did)

    assert.match(issued.proof, /^kelo-proof:v1:\d{10}:([0-9a-f]{32}):([0-9a-f]{64})$/)
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
    const expiredMac = crypto.createHmac('sha256', process.env.PDS_KELO_ID_PROOF_SECRET)
      .update('v1|' + did + '|' + expiredAt + '|' + expiredNonce, 'utf8')
      .digest('hex')
    const expiredProof = 'kelo-proof:v1:' + expiredAt + ':' + expiredNonce + ':' + expiredMac
    assert.equal(await verifyKeloProof(did, expiredProof), false, 'expired proof must be rejected')
    assert.equal(await verifyKeloProof('did:plc:anotherdidabcdefghijkl', issued.proof), false, 'proof must be DID-bound')

    const tampered = issued.proof.replace(/.$/, issued.proof.endsWith('0') ? '1' : '0')
    assert.equal(await verifyKeloProof(did, tampered), false, 'tampered MAC must be rejected')
  } finally {
    await fs.rm(directory, { recursive: true, force: true })
    if (previousDirectory === undefined) delete process.env.PDS_DATA_DIRECTORY
    else process.env.PDS_DATA_DIRECTORY = previousDirectory
    if (previousSecret === undefined) delete process.env.PDS_KELO_ID_PROOF_SECRET
    else process.env.PDS_KELO_ID_PROOF_SECRET = previousSecret
  }
}

run().then(() => console.log('Kelo proof tests passed')).catch((error) => {
  console.error(error)
  process.exitCode = 1
})
