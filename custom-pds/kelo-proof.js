'use strict'

const crypto = require('node:crypto')
const fs = require('node:fs/promises')
const path = require('node:path')

const PREFIX = 'kelo-proof:v1:'
const TTL_SECONDS = 60
const NONCE_PATTERN = /^[0-9a-f]{32}$/
const DID_PATTERN = /^did:(plc|web):[A-Za-z0-9._:%-]+$/

function getSigningKey() {
  const secret = process.env.PDS_KELO_ID_PROOF_SECRET
  if (typeof secret !== 'string' || secret.length < 32) {
    throw new Error('PDS_KELO_ID_PROOF_SECRET must contain at least 32 characters')
  }
  return Buffer.from(secret, 'utf8')
}

function sign(did, exp, nonce) {
  return crypto.createHmac('sha256', getSigningKey())
    .update('v1|' + did + '|' + exp + '|' + nonce, 'utf8')
    .digest('hex')
}

function issueKeloProof(did) {
  if (typeof did !== 'string' || !DID_PATTERN.test(did)) throw new Error('Invalid DID')
  const expiresAt = Math.floor(Date.now() / 1000) + TTL_SECONDS
  const nonce = crypto.randomBytes(16).toString('hex')
  return { proof: PREFIX + expiresAt + ':' + nonce + ':' + sign(did, expiresAt, nonce), expiresAt }
}

async function pruneUsedNonces(directory, now) {
  let names
  try {
    names = await fs.readdir(directory)
  } catch (error) {
    if (error && error.code === 'ENOENT') return
    throw error
  }
  await Promise.all(names.map(async (name) => {
    if (!NONCE_PATTERN.test(name)) return
    const file = path.join(directory, name)
    try {
      // Keep every newly-created marker for longer than the proof lifetime.
      // Checking mtime (rather than reading a possibly half-written file)
      // avoids a race with another login consuming the same nonce.
      const stat = await fs.stat(file)
      if (stat.mtimeMs < (now - 10 * 60) * 1000) await fs.unlink(file)
    } catch (error) {
      if (error && error.code !== 'ENOENT') throw error
    }
  }))
}

async function verifyKeloProof(did, password) {
  try {
    if (typeof password !== 'string' || !password.startsWith(PREFIX)) return false
    if (typeof did !== 'string' || !DID_PATTERN.test(did)) return false
    const parts = password.slice(PREFIX.length).split(':')
    if (parts.length !== 3) return false
    const [expString, nonce, mac] = parts
    if (!/^\d{1,12}$/.test(expString) || !NONCE_PATTERN.test(nonce) || !/^[0-9a-f]{64}$/.test(mac)) return false
    const expiresAt = Number(expString)
    const now = Math.floor(Date.now() / 1000)
    if (!Number.isSafeInteger(expiresAt) || expiresAt <= now || expiresAt > now + TTL_SECONDS + 5) return false
    const expected = Buffer.from(sign(did, expString, nonce), 'hex')
    const supplied = Buffer.from(mac, 'hex')
    if (expected.length !== supplied.length || !crypto.timingSafeEqual(expected, supplied)) return false

    const usedDirectory = path.join(process.env.PDS_DATA_DIRECTORY || '/pds', 'kelo-id-proof-used')
    await fs.mkdir(usedDirectory, { recursive: true, mode: 0o700 })
    await pruneUsedNonces(usedDirectory, now)
    let handle
    try {
      handle = await fs.open(path.join(usedDirectory, nonce), 'wx', 0o600)
      await handle.writeFile(String(expiresAt) + '\n', 'utf8')
      await handle.sync()
      return true
    } catch (error) {
      if (error && error.code === 'EEXIST') return false
      return false
    } finally {
      if (handle) await handle.close().catch(() => {})
    }
  } catch {
    return false
  }
}

module.exports = { issueKeloProof, verifyKeloProof, PREFIX, TTL_SECONDS }
