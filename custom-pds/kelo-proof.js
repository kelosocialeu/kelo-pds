'use strict'
// Preuve de connexion Kelo ID : signée par le gatekeeper, valable 60 s, à usage unique.
const crypto = require('crypto')
const PREFIX = 'kelo-proof:v1:'
const used = new Map()

function signingKey() {
  const s = process.env.PDS_JWT_SECRET
  if (!s) return null
  return crypto.createHmac('sha256', s).update('kelo-id-login-proof-v1').digest()
}

function verifyKeloProof(did, password) {
  try {
    if (typeof password !== 'string' || !password.startsWith(PREFIX)) return false
    const key = signingKey()
    if (!key) return false
    const parts = password.slice(PREFIX.length).split(':')
    if (parts.length !== 3) return false
    const [expStr, nonce, mac] = parts
    if (!/^\d{1,12}$/.test(expStr)) return false
    if (!/^[0-9a-f]{32}$/.test(nonce)) return false
    if (!/^[0-9a-f]{64}$/.test(mac)) return false
    const exp = parseInt(expStr, 10)
    const now = Math.floor(Date.now() / 1000)
    if (exp < now || exp > now + 120) return false
    const expected = crypto.createHmac('sha256', key).update('v1|' + did + '|' + expStr + '|' + nonce).digest()
    const given = Buffer.from(mac, 'hex')
    if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return false
    for (const [n, e] of used) if (e < now) used.delete(n)
    if (used.has(nonce)) return false
    used.set(nonce, exp)
    return true
  } catch (e) {
    return false
  }
}
module.exports = { verifyKeloProof, PREFIX }
