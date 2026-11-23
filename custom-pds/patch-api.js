'use strict'

const fs = require('node:fs')
const file = process.argv[2]
if (!file) throw new Error('Usage: node patch-api.js <index.js>')

let source = fs.readFileSync(file, 'utf8')
const marker = 'Kelo ID proof issuer. This route is server-to-server only.'
const existingAt = source.indexOf(marker)

// Older Kelo builds inserted this block immediately after app creation,
// before compression(). Remove that exact block so it can be reinstalled
// at the correct point in the upstream middleware stack.
if (existingAt !== -1) {
  const lineStart = source.lastIndexOf('\n', existingAt) + 1
  const handlerStart = source.indexOf("app.post('/kelo-id/login-proof'", existingAt)
  const blockEnd = handlerStart === -1 ? -1 : source.indexOf('    })', handlerStart)
  if (blockEnd === -1) {
    throw new Error('Found an existing Kelo proof route but could not safely locate its end. Refusing to modify the PDS.')
  }
  let afterBlock = blockEnd + '    })'.length
  if (source[afterBlock] === '\r') afterBlock++
  if (source[afterBlock] === '\n') afterBlock++
  source = source.slice(0, lineStart) + source.slice(afterBlock)
}

const appAnchor = /const app = (?:\(0,\s*express_1\.default\)|express_1\.default|express)\(\);/g
const appMatches = [...source.matchAll(appAnchor)]
if (appMatches.length !== 1) {
  throw new Error('Expected exactly one PDS Express app initializer; found ' + appMatches.length + '. Refusing to patch unknown PDS build.')
}

// In PDS 0.4.219, compression() wraps res.write/res.end. The Kelo HTML
// transformer MUST be registered after compression() so it sees plain HTML,
// and before authRoutes so it can intercept the native OAuth page.
const compressionAnchor = /app\.use\(\s*(?:\(0,\s*)?[\w$]*compression[\w$]*\.default\)?\(\)\s*\);/g
const compressionMatches = [...source.matchAll(compressionAnchor)]
if (compressionMatches.length !== 1) {
  throw new Error('Expected exactly one compiled PDS compression middleware mount; found ' + compressionMatches.length + '. Refusing to guess middleware order.')
}

const authAnchor = /app\.use\(\s*(?:\(0,\s*)?[\w$]*auth[\w$]*\.createRouter\)?\s*\(ctx\)\s*\)\s*;/g
const authMatches = [...source.matchAll(authAnchor)]
if (authMatches.length !== 1) {
  throw new Error('Expected exactly one PDS OAuth/auth router mount; found ' + authMatches.length + '. Refusing to guess middleware order.')
}

const compressionEnd = compressionMatches[0].index + compressionMatches[0][0].length
if (compressionEnd >= authMatches[0].index) {
  throw new Error('Unexpected PDS middleware order: compression() must precede authRoutes.')
}

const route = '\n' + "    // Kelo ID proof issuer. This route is server-to-server only.\n" +
"    const keloExpress = require('express')\n" +
"    const keloCrypto = require('node:crypto')\n" +
"    const keloProof = require('./account-manager/kelo-proof')\n" +
"    const keloProofRate = new Map()\n" +
"    app.use('/kelo-id', keloExpress.json({ limit: '2kb' }))\n" +
"    app.use(require('./kelo-oauth-qr')(ctx))\n" +
"    app.post('/kelo-id/login-proof', async (req, res) => {\n" +
"      res.setHeader('Cache-Control', 'no-store, private')\n" +
"      res.setHeader('Pragma', 'no-cache')\n" +
"      const configuredApiKey = process.env.PDS_KELO_ID_API_KEY\n" +
"      if (!configuredApiKey || configuredApiKey.length < 32 || !process.env.PDS_JWT_SECRET) {\n" +
"        return res.status(503).json({ error: 'Kelo ID proof service is not configured' })\n" +
"      }\n" +
"      const expected = Buffer.from('Bearer ' + configuredApiKey, 'utf8')\n" +
"      const supplied = Buffer.from(String(req.headers.authorization || ''), 'utf8')\n" +
"      if (expected.length !== supplied.length || !keloCrypto.timingSafeEqual(expected, supplied)) {\n" +
"        return res.status(401).json({ error: 'Unauthorized' })\n" +
"      }\n" +
"      const did = typeof req.body?.did === 'string' ? req.body.did.trim() : ''\n" +
"      if (!/^did:(plc|web):[A-Za-z0-9._:%-]+$/.test(did)) {\n" +
"        return res.status(400).json({ error: 'Invalid DID' })\n" +
"      }\n" +
"      const now = Date.now()\n" +
"      const previous = keloProofRate.get(did)\n" +
"      if (previous && now - previous.startedAt < 60000 && previous.count >= 5) {\n" +
"        return res.status(429).json({ error: 'Too many proof requests' })\n" +
"      }\n" +
"      if (!previous || now - previous.startedAt >= 60000) keloProofRate.set(did, { startedAt: now, count: 1 })\n" +
"      else previous.count += 1\n" +
"      try {\n" +
"        const account = await ctx.accountManager.getAccount(did)\n" +
"        if (!account) return res.status(404).json({ error: 'Account not found on this PDS' })\n" +
"        return res.status(200).json(keloProof.issueKeloProof(did))\n" +
"      } catch {\n" +
"        return res.status(503).json({ error: 'Unable to issue Kelo ID proof' })\n" +
"      }\n" +
"    })\n"

source = source.slice(0, compressionEnd) + route + source.slice(compressionEnd)

const installedAt = source.indexOf(marker)
const installedEnd = source.indexOf("app.post('/kelo-id/login-proof'", installedAt)
if (installedAt === -1 || installedEnd === -1 ||
    installedAt <= source.indexOf(compressionMatches[0][0]) ||
    installedAt >= source.indexOf(authMatches[0][0])) {
  throw new Error('Post-patch verification failed: Kelo middleware is not between compression and auth routes.')
}

fs.writeFileSync(file, source)
console.log('Kelo middleware installed after compression() and before native OAuth/auth routes')
