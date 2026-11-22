'use strict'

const fs = require('node:fs')

const file = process.argv[2]
if (!file) throw new Error('Usage: node patch-api.js <index.js>')

const source = fs.readFileSync(file, 'utf8')
const anchor = /const app = (?:\\(0,\\s*express_1\\.default\\)|express_1\\.default|express)\\(\\);/g
const matches = [...source.matchAll(anchor)]

if (matches.length !== 1) {
  throw new Error(`Expected exactly one PDS Express app initializer; found ${matches.length}. Refusing to patch unknown PDS build.`)
}

const route = `
    // Kelo ID proof issuer. This route is server-to-server only.
    const keloExpress = require('express')
    const keloCrypto = require('node:crypto')
    const keloProof = require('./account-manager/kelo-proof')
    const keloProofRate = new Map()
    app.use('/kelo-id', keloExpress.json({ limit: '2kb' }))
    app.post('/kelo-id/login-proof', async (req, res) => {
      res.setHeader('Cache-Control', 'no-store, private')
      res.setHeader('Pragma', 'no-cache')

      const configuredApiKey = process.env.PDS_KELO_ID_API_KEY
      if (!configuredApiKey || !process.env.PDS_KELO_ID_PROOF_SECRET || process.env.PDS_KELO_ID_PROOF_SECRET.length < 32) {
        return res.status(503).json({ error: 'Kelo ID proof service is not configured' })
      }

      const expected = Buffer.from('Bearer ' + configuredApiKey, 'utf8')
      const supplied = Buffer.from(String(req.headers.authorization || ''), 'utf8')
      if (expected.length !== supplied.length || !keloCrypto.timingSafeEqual(expected, supplied)) {
        return res.status(401).json({ error: 'Unauthorized' })
      }

      const did = typeof req.body?.did === 'string' ? req.body.did.trim() : ''
      if (!/^did:(plc|web):[A-Za-z0-9._:%-]+$/.test(did)) {
        return res.status(400).json({ error: 'Invalid DID' })
      }

      const now = Date.now()
      const previous = keloProofRate.get(did)
      if (previous && now - previous.startedAt < 60000 && previous.count >= 5) {
        return res.status(429).json({ error: 'Too many proof requests' })
      }
      if (!previous || now - previous.startedAt >= 60000) {
        keloProofRate.set(did, { startedAt: now, count: 1 })
      } else {
        previous.count += 1
      }

      try {
        const account = await ctx.accountManager.getAccount(did)
        if (!account) return res.status(404).json({ error: 'Account not found on this PDS' })

        const issued = keloProof.issueKeloProof(did)
        return res.status(200).json(issued)
      } catch {
        return res.status(503).json({ error: 'Unable to issue Kelo ID proof' })
      }
    })
`

const offset = matches[0].index + matches[0][0].length
const patched = source.slice(0, offset) + route + source.slice(offset)
fs.writeFileSync(file, patched)
console.log('Kelo ID proof issuer route installed')
