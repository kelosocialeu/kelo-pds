'use strict'

const fs = require('node:fs')
const file = process.argv[2]
if (!file) throw new Error('Usage: node patch-api.js <index.js>')

const source = fs.readFileSync(file, 'utf8')
if (source.includes('Kelo ID proof issuer. This route is server-to-server only.')) {
  console.log('Kelo ID proof issuer patch already present')
  process.exit(0)
}

const anchor = /const app = (?:\(0,\s*express_1\.default\)|express_1\.default|express)\(\);/g
const matches = [...source.matchAll(anchor)]
if (matches.length !== 1) {
  throw new Error('Expected exactly one PDS Express app initializer; found ' + matches.length + '. Refusing to patch unknown PDS build.')
}

const route = '\n' + "    // Kelo ID proof issuer. This route is server-to-server only.\n    const keloExpress = require('express')\n    const keloCrypto = require('node:crypto')\n    const keloProof = require('./account-manager/kelo-proof')\n    const keloProofRate = new Map()\n    app.use('/kelo-id', keloExpress.json({ limit: '2kb' }))\n    app.use(require('./kelo-oauth-qr')(ctx))\n    app.post('/kelo-id/login-proof', async (req, res) => {\n      res.setHeader('Cache-Control', 'no-store, private')\n      res.setHeader('Pragma', 'no-cache')\n      const configuredApiKey = process.env.PDS_KELO_ID_API_KEY\n      if (!configuredApiKey || configuredApiKey.length < 32 || !process.env.PDS_JWT_SECRET) {\n        return res.status(503).json({ error: 'Kelo ID proof service is not configured' })\n      }\n      const expected = Buffer.from('Bearer ' + configuredApiKey, 'utf8')\n      const supplied = Buffer.from(String(req.headers.authorization || ''), 'utf8')\n      if (expected.length !== supplied.length || !keloCrypto.timingSafeEqual(expected, supplied)) {\n        return res.status(401).json({ error: 'Unauthorized' })\n      }\n      const did = typeof req.body?.did === 'string' ? req.body.did.trim() : ''\n      if (!/^did:(plc|web):[A-Za-z0-9._:%-]+$/.test(did)) {\n        return res.status(400).json({ error: 'Invalid DID' })\n      }\n      const now = Date.now()\n      const previous = keloProofRate.get(did)\n      if (previous && now - previous.startedAt < 60000 && previous.count >= 5) {\n        return res.status(429).json({ error: 'Too many proof requests' })\n      }\n      if (!previous || now - previous.startedAt >= 60000) keloProofRate.set(did, { startedAt: now, count: 1 })\n      else previous.count += 1\n      try {\n        const account = await ctx.accountManager.getAccount(did)\n        if (!account) return res.status(404).json({ error: 'Account not found on this PDS' })\n        return res.status(200).json(keloProof.issueKeloProof(did))\n      } catch {\n        return res.status(503).json({ error: 'Unable to issue Kelo ID proof' })\n      }\n    })\n" + '\n'

const offset = matches[0].index + matches[0][0].length
fs.writeFileSync(file, source.slice(0, offset) + route + source.slice(offset))
console.log('Kelo ID proof issuer route installed')
