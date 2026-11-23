'use strict'

const crypto = require('node:crypto')
const fs = require('node:fs/promises')
const path = require('node:path')
const express = require('express')
const QRCode = require('/opt/kelo-pds-qrcode/node_modules/qrcode')
const oauthProviderEntry = require.resolve('@atproto/oauth-provider', { paths: [__dirname] })
const oauthTypesPath = require.resolve('@atproto/oauth-types', { paths: [path.dirname(oauthProviderEntry)] })
const { oauthAuthorizationRequestQuerySchema } = require(oauthTypesPath)

const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/\nconst MANUAL_CODE_PATTERN = /^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{12}$/\nconst CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'\nconst TOKEN_TTL_MS = 5 * 60 * 1000
const COOKIE_NAME = 'kelo-oauth-bypass'
let lastPruneAt = 0

function sha256(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex')
}
function dataDirectory() {
  return path.join(process.env.PDS_DATA_DIRECTORY || '/pds', 'kelo-id-oauth-challenges')
}
function requestFile(directory, requestKey) {
  return path.join(directory, 'request-' + requestKey + '.json')
}
function tokenFile(directory, tokenHash) {\n  return path.join(directory, 'token-' + tokenHash + '.json')\n}\nfunction codeFile(directory, codeHash) { return path.join(directory, 'code-' + codeHash + '.json') }\nfunction createManualCode() { let value = ''; for (let index = 0; index < 12; index += 1) value += CODE_ALPHABET[crypto.randomInt(CODE_ALPHABET.length)]; return value.slice(0, 4) + '-' + value.slice(4, 8) + '-' + value.slice(8) }
function safeEqual(left, right) {
  const a = Buffer.from(String(left || ''), 'utf8')
  const b = Buffer.from(String(right || ''), 'utf8')
  return a.length === b.length && a.length > 0 && crypto.timingSafeEqual(a, b)
}
function getApiKey(req, res) {
  const configured = process.env.PDS_KELO_ID_API_KEY
  if (!configured || configured.length < 32) {
    res.status(503).json({ error: 'Kelo ID API is not configured' })
    return false
  }
  if (!safeEqual(req.headers.authorization, 'Bearer ' + configured)) {
    res.status(401).json({ error: 'Unauthorized' })
    return false
  }
  return true
}
function readCookie(req, name) {
  const parts = String(req.headers.cookie || '').split(';')
  const prefix = name + '='
  const part = parts.map((value) => value.trim()).find((value) => value.startsWith(prefix))
  return part ? decodeURIComponent(part.slice(prefix.length)) : ''
}
function appendCookie(res, value) {
  const existing = res.getHeader('Set-Cookie')
  const values = Array.isArray(existing) ? existing : existing ? [String(existing)] : []
  values.push(value)
  res.setHeader('Set-Cookie', values)
}
function setBypassCookie(res, token) {
  appendCookie(res, COOKIE_NAME + '=' + encodeURIComponent(token) + '; Path=/; Max-Age=90; HttpOnly; Secure; SameSite=Lax')
}
function clearBypassCookie(res) {
  appendCookie(res, COOKIE_NAME + '=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax')
}
function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[character])
}
async function ensureDirectory() {
  const directory = dataDirectory()
  await fs.mkdir(directory, { recursive: true, mode: 0o700 })
  if (Date.now() - lastPruneAt > 10 * 60 * 1000) {
    lastPruneAt = Date.now()
    try {
      const entries = await fs.readdir(directory)
      for (const name of entries) {
        if (!name.endsWith('.json') && !name.endsWith('.lock')) continue
        const file = path.join(directory, name)
        const stat = await fs.stat(file).catch(() => null)
        const maxAge = name.endsWith('.lock') ? 15 * 60 * 1000 : 24 * 60 * 60 * 1000
        if (stat && Date.now() - stat.mtimeMs > maxAge) await fs.unlink(file).catch(() => {})
      }
    } catch {
      // A cleanup failure must not interrupt a valid OAuth authorization.
    }
  }
  return directory
}
async function atomicWrite(file, value) {
  const temporary = file + '.' + crypto.randomBytes(8).toString('hex') + '.tmp'
  await fs.writeFile(temporary, JSON.stringify(value), { flag: 'wx', mode: 0o600 })
  await fs.rename(temporary, file)
}
async function readJson(file) {
  try {
    return JSON.parse(await fs.readFile(file, 'utf8'))
  } catch (error) {
    if (error && error.code === 'ENOENT') return null
    throw error
  }
}
async function withRequestLock(directory, requestKey, callback) {
  const lockPath = path.join(directory, 'request-' + requestKey + '.lock')
  let lock
  try {
    lock = await fs.open(lockPath, 'wx', 0o600)
  } catch (error) {
    if (error && error.code === 'EEXIST') {
      throw Object.assign(new Error('OAuth QR request is busy; retry shortly'), { status: 409 })
    }
    throw error
  }
  try {
    return await callback()
  } finally {
    await lock.close().catch(() => {})
    await fs.unlink(lockPath).catch(() => {})
  }
}
async function createOrReuseChallenge(directory, data) {
  const requestKey = sha256(data.requestUri + '|' + data.clientId + '|' + data.deviceId)
  return withRequestLock(directory, requestKey, async () => {
    const file = requestFile(directory, requestKey)
    const current = await readJson(file)
    if (current && current.status === 'pending' && current.expiresAt > Date.now() &&
        current.requestUri === data.requestUri && current.clientId === data.clientId &&
        current.deviceId === data.deviceId) return { ...current, token: current.challengeToken, code: current.manualCode }

    if (current?.challengeHash) await fs.unlink(tokenFile(directory, current.challengeHash)).catch(() => {})\n    if (current?.codeHash) await fs.unlink(codeFile(directory, current.codeHash)).catch(() => {})\n    const token = crypto.randomBytes(32).toString('base64url')\n    const tokenHash = sha256(token)\n    const manualCode = createManualCode()\n    const codeHash = sha256(manualCode.replace(/-/g, ''))
    const record = {
      version: 1, requestKey, challengeHash: tokenHash, challengeToken: token,\n      codeHash, manualCode,
      requestUri: data.requestUri, clientId: data.clientId, deviceId: data.deviceId,
      clientName: data.clientName, scope: data.scope || 'atproto',
      loginHint: data.loginHint || null, createdAt: Date.now(),
      expiresAt: Date.now() + TOKEN_TTL_MS, status: 'pending',
      approvedDid: null, approvedAt: null, deniedDid: null, deniedAt: null, classic: false,
    }
    await atomicWrite(file, record)
    await atomicWrite(tokenFile(directory, tokenHash), { requestKey })\n    await atomicWrite(codeFile(directory, codeHash), { requestKey })\n    return { ...record, token, code: manualCode }
  })
}
async function readChallenge(directory, token) {
  if (typeof token !== 'string' || !TOKEN_PATTERN.test(token)) return null
  const tokenHash = sha256(token)
  const pointer = await readJson(tokenFile(directory, tokenHash))
  if (!pointer || typeof pointer.requestKey !== 'string' || !/^[0-9a-f]{64}$/.test(pointer.requestKey)) return null
  const record = await readJson(requestFile(directory, pointer.requestKey))
  if (!record || record.challengeHash !== tokenHash || record.challengeToken !== token || record.requestKey !== pointer.requestKey) return null
  return record
}
async function readManualCode(directory, input) {\n  const normalized = String(input || '').toUpperCase().replace(/[\\s-]/g, '')\n  if (!MANUAL_CODE_PATTERN.test(normalized)) return null\n  const codeHash = sha256(normalized)\n  const pointer = await readJson(codeFile(directory, codeHash))\n  if (!pointer || typeof pointer.requestKey !== 'string' || !/^[0-9a-f]{64}$/.test(pointer.requestKey)) return null\n  const record = await readJson(requestFile(directory, pointer.requestKey))\n  if (!record || record.codeHash !== codeHash || record.requestKey !== pointer.requestKey || String(record.manualCode || '').replace(/-/g, '') !== normalized) return null\n  return record\n}\nasync function saveChallenge(directory, record) { await atomicWrite(requestFile(directory, record.requestKey), record) }
function validateBrowserNavigation(req, issuer) {
  const mode = req.headers['sec-fetch-mode']
  const destination = req.headers['sec-fetch-dest']
  const site = req.headers['sec-fetch-site']
  if (mode && mode !== 'navigate') return false
  if (destination && destination !== 'document') return false
  if (site && !['same-origin', 'same-site', 'cross-site', 'none'].includes(site)) return false
  const origin = req.headers.origin
  if (origin && origin !== new URL(issuer).origin) return false
  return true
}
function sendIosCookieTest(req, res, issuer) {
  const target = new URL(req.originalUrl, issuer)
  target.searchParams.set('redirect-test', '1')
  const action = escapeHtml(target.pathname + target.search)
  res.setHeader('Cache-Control', 'no-store')
  res.setHeader('Content-Type', 'text/html; charset=utf-8')
  res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
  res.setHeader('Set-Cookie', 'cookie-test=testing; Path=/; HttpOnly; Secure; SameSite=Lax')
  res.end('<!doctype html><html lang="fr"><meta charset="utf-8"><title>Vérification du navigateur</title><body><form id="kelo-cookie-test" method="get" action="' + action + '"></form><script>document.getElementById("kelo-cookie-test").submit()</script></body></html>')
}
function renderQrAuthorizationPage(res, token, record, qrDataUrl) {
  const classicUrl = '/kelo-id/oauth/continue?mode=classic&challenge=' + encodeURIComponent(token)
  const statusUrl = '/kelo-id/oauth/qr/status?challenge=' + encodeURIComponent(token)
  const resumeUrl = '/kelo-id/oauth/continue?mode=resume&challenge=' + encodeURIComponent(token)
  const clientName = escapeHtml(record.clientName || record.clientId)
  const clientId = escapeHtml(record.clientId)
  const scope = escapeHtml(record.scope)
  const image = escapeHtml(qrDataUrl)\n  const manualCode = escapeHtml(record.manualCode || '')\n  const script = [
    'const statusUrl=' + JSON.stringify(statusUrl) + ';',
    'const resumeUrl=' + JSON.stringify(resumeUrl) + ';',
    'const statusNode=document.getElementById("kelo-status");',
    'let stopped=false;',
    'async function poll(){if(stopped)return;try{const response=await fetch(statusUrl,{cache:"no-store",credentials:"same-origin"});const data=await response.json().catch(()=>({}));',
    'if(data.status==="approved"){stopped=true;statusNode.textContent="Connexion autorisée. Finalisation…";window.location.replace(resumeUrl);return;}',
    'if(data.status==="denied"||data.status==="cancelled"){stopped=true;statusNode.textContent="Demande refusée ou annulée. Vous pouvez utiliser la connexion classique.";return;}',
    'if(data.status==="expired"||response.status===410){stopped=true;statusNode.textContent="Ce QR a expiré. Actualisez la page pour en générer un nouveau.";return;}',
    'if(!response.ok){stopped=true;statusNode.textContent=data.error||"Impossible de vérifier la demande.";return;}}catch(e){statusNode.textContent="Connexion en attente…";}setTimeout(poll,1800);}poll();',
  ].join('')
  const html = '<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connexion Kelo PDS</title><style>' +
    '*{box-sizing:border-box}body{margin:0;min-height:100vh;background:#f4f6fb;color:#172033;font:16px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;display:grid;place-items:center;padding:24px}.card{width:min(100%,520px);background:#fff;border:1px solid #e5e9f2;border-radius:24px;padding:32px;box-shadow:0 18px 55px #17203312;text-align:center}.brand{font-weight:750;letter-spacing:.02em;color:#315df5}.eyebrow{font-size:12px;text-transform:uppercase;letter-spacing:.12em;color:#667085;font-weight:700;margin-top:20px}h1{font-size:28px;line-height:1.2;margin:8px 0 12px}.muted{color:#667085}.client{background:#f7f8fc;border-radius:14px;padding:12px;margin:18px 0;text-align:left;overflow-wrap:anywhere}.client strong{display:block}.qr{width:260px;height:260px;max-width:100%;object-fit:contain;margin:12px auto}.manual{background:#f1f5ff;border:1px solid #dce5ff;border-radius:14px;padding:14px;margin:12px auto;max-width:320px}.manual span,.manual small{display:block;color:#667085;font-size:13px}.manual strong{display:block;font:750 24px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.08em;color:#315df5}.hint{font-size:14px;color:#667085}.status{min-height:26px;margin:12px 0;color:#315df5;font-weight:650}.button{display:block;text-decoration:none;border-radius:12px;padding:13px 18px;font-weight:700;margin-top:16px}.primary{background:#315df5;color:white}.secondary{border:1px solid #d9deea;color:#344054}.small{font-size:12px;color:#98a2b3;margin-top:18px}' +
    '</style></head><body><main class="card"><div class="brand">KELO SOCIAL · PDS</div><div class="eyebrow">Authentification sécurisée</div><h1>Se connecter avec Kelo ID</h1><p class="muted">Ouvrez Kelo ID, connectez-vous si nécessaire, puis scannez ce QR code. Vérifiez le compte et l’application avant d’appuyer sur « Autoriser ».</p><div class="client"><strong>' + clientName + '</strong><span>' + clientId + '</span><p>Autorisations demandées : ' + scope + '</p></div><img class="qr" src="' + image + '" alt="QR code de connexion Kelo ID"><p class="hint">Ce QR code expire dans cinq minutes et ne peut être utilisé qu’une seule fois.</p><div class="manual"><span>Ou saisissez ce code dans Kelo ID</span><strong>' + manualCode + '</strong><small>Code à usage unique · valable cinq minutes</small></div><div id="kelo-status" class="status" role="status" aria-live="polite">En attente de votre confirmation dans Kelo ID…</div><a class="button secondary" href="' + classicUrl + '">Utiliser mon identifiant et mon mot de passe</a><p class="small">Ne scannez ce code que si vous avez lancé vous-même cette connexion.</p></main><script>' + script + '</script></body></html>'
  res.setHeader('Cache-Control', 'no-store, private')
  res.setHeader('Pragma', 'no-cache')
  res.setHeader('Referrer-Policy', 'no-referrer')
  res.setHeader('X-Content-Type-Options', 'nosniff')
  res.setHeader('Content-Security-Policy', "default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
  res.status(200).type('html').send(html)
}

function renderLoginChoicePage(res, token, record) {\n  const keloUrl = '/kelo-id/oauth/qr/page?challenge=' + encodeURIComponent(token)\n  const classicUrl = '/kelo-id/oauth/continue?mode=classic&challenge=' + encodeURIComponent(token)\n  const clientName = escapeHtml(record.clientName || record.clientId), clientId = escapeHtml(record.clientId), scope = escapeHtml(record.scope)\n  const html = '<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connexion · Kelo PDS</title><style>*{box-sizing:border-box}body{margin:0;min-height:100vh;background:#f4f6fb;color:#172033;font:16px/1.5 system-ui;display:grid;place-items:center;padding:24px}.card{width:min(100%,500px);background:#fff;border:1px solid #e5e9f2;border-radius:24px;padding:32px;box-shadow:0 18px 55px #17203312;text-align:center}.brand{font-weight:750;color:#315df5}h1{font-size:28px}.muted{color:#667085}.client{background:#f7f8fc;border-radius:14px;padding:12px;margin:18px 0;text-align:left;overflow-wrap:anywhere}.client strong{display:block}.button{display:block;text-decoration:none;border-radius:12px;padding:14px 18px;font-weight:700;margin-top:14px}.primary{background:#315df5;color:white}.secondary{border:1px solid #d9deea;color:#344054}</style></head><body><main class="card"><div class="brand">KELO SOCIAL · PDS</div><h1>Connexion à Kelo PDS</h1><p class="muted">Choisissez votre méthode de connexion. Vous pouvez utiliser Kelo ID ou vos identifiants habituels.</p><div class="client"><strong>' + clientName + '</strong><span>' + clientId + '</span><p>Autorisations demandées : ' + scope + '</p></div><a class="button primary" href="' + keloUrl + '">Se connecter avec Kelo ID</a><a class="button secondary" href="' + classicUrl + '">Se connecter avec identifiant et mot de passe</a></main></body></html>'\n  res.setHeader('Cache-Control', 'no-store, private'); res.setHeader('Pragma', 'no-cache'); res.setHeader('Referrer-Policy', 'no-referrer'); res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"); res.status(200).type('html').send(html)\n}\n\nfunction createKeloOAuthQrRouter(ctx) {
  const router = express.Router()
  const provider = ctx.oauthProvider
  router.use('/kelo-id', express.json({ limit: '4kb' }))

  router.get('/oauth/authorize', async (req, res, next) => {
    try {
      if (!provider || !validateBrowserNavigation(req, provider.issuer)) return next()
      const query = new URL(req.originalUrl, provider.issuer).searchParams
      if (query.getAll('client_id').length !== 1 || query.getAll('request_uri').length !== 1) return next()
      const parsedQuery = oauthAuthorizationRequestQuerySchema.safeParse(Object.fromEntries(query.entries()))
      if (!parsedQuery.success) return next()
      const clientId = parsedQuery.data.client_id
      const requestUri = parsedQuery.data.request_uri

      if (String(req.headers['user-agent'] || '').includes('iPhone OS') &&
          readCookie(req, 'cookie-test') !== 'succeeded' &&
          !(await provider.deviceManager.hasSession(req))) {
        if (!query.has('redirect-test')) return sendIosCookieTest(req, res, provider.issuer)
        if (readCookie(req, 'cookie-test')) {
          res.append('Set-Cookie', 'cookie-test=succeeded; Path=/; Max-Age=2678400; HttpOnly; Secure; SameSite=Lax')
        } else {
          return next()
        }
      }

      const device = await provider.deviceManager.load(req, res)
      const bypassToken = readCookie(req, COOKIE_NAME)
      if (bypassToken) {
        const bypassRecord = await readChallenge(await ensureDirectory(), bypassToken)
        clearBypassCookie(res)
        if (bypassRecord && bypassRecord.deviceId === device.deviceId &&
            bypassRecord.clientId === clientId && bypassRecord.requestUri === requestUri &&
            (bypassRecord.status === 'approved' || (bypassRecord.status === 'cancelled' && bypassRecord.classic))) {
          return next()
        }
      }

      const requestData = await provider.requestManager.get(requestUri, device.deviceId, clientId)
      const promptModes = String(requestData.parameters.prompt || '').split(' ')
      if (promptModes.some((mode) => ['none', 'create', 'select_account'].includes(mode))) return next()
      const client = await provider.clientManager.getClient(clientId)
      const directory = await ensureDirectory()
      const record = await createOrReuseChallenge(directory, {
        requestUri, clientId, deviceId: device.deviceId,
        clientName: client.metadata?.client_name || clientId,
        scope: requestData.parameters.scope || 'atproto',
        loginHint: requestData.parameters.login_hint || null,
      })
      const token = record.token
      if (!token) throw new Error('Unable to restore the pending OAuth QR token')
      return renderLoginChoicePage(res, token, record)
    } catch (error) {
      return next(error)
    }
  })

  router.get('/kelo-id/oauth/qr/page', async (req, res) => {\n    try {\n      const token = String(req.query.challenge || ''), directory = await ensureDirectory(), record = await readChallenge(directory, token)\n      if (!record || record.expiresAt <= Date.now() || record.status !== 'pending') return res.status(410).send('Cette demande de connexion a expiré. Relancez la connexion depuis votre application.')\n      const device = await provider.deviceManager.load(req, res)\n      if (device.deviceId !== record.deviceId) return res.status(403).send('Cette demande appartient à un autre navigateur.')\n      const qrDataUrl = await QRCode.toDataURL(token, { errorCorrectionLevel: 'M', margin: 2, width: 260 })\n      return renderQrAuthorizationPage(res, token, record, qrDataUrl)\n    } catch (error) { return res.status(400).send(escapeHtml(error instanceof Error ? error.message : 'Impossible de créer le QR code.')) }\n  })\n\n  router.get('/kelo-id/oauth/qr', async (req, res) => {
    res.setHeader('Cache-Control', 'no-store, private')
    if (!getApiKey(req, res)) return
    try {
      const token = String(req.query.challenge || ''), code = String(req.query.code || ''), did = String(req.query.did || '')\n      const directory = await ensureDirectory()\n      const record = token ? await readChallenge(directory, token) : await readManualCode(directory, code)
      if (!record) return res.status(404).json({ error: 'QR de connexion introuvable.' })
      if (record.expiresAt <= Date.now()) return res.status(410).json({ error: 'Ce QR a expiré.' })
      if (record.status === 'approved') {
        if (record.approvedDid !== did) return res.status(409).json({ error: 'Ce QR a déjà été utilisé par un autre compte.' })
      } else if (record.status !== 'pending') {
        return res.status(409).json({ error: 'Cette demande de connexion n’est plus active.' })
      }
      const requestData = await provider.requestManager.get(record.requestUri, record.deviceId, record.clientId)
      const localAccount = await ctx.accountManager.getAccount(did)
      if (!localAccount || localAccount.did !== did) {
        return res.status(403).json({ error: 'Ce compte Kelo ID n’est pas hébergé sur Kelo PDS.' })
      }
      if (requestData.parameters.login_hint &&
          requestData.parameters.login_hint.toLowerCase() !== did.toLowerCase() &&
          requestData.parameters.login_hint.toLowerCase() !== String(localAccount.handle || '').toLowerCase()) {
        return res.status(403).json({ error: 'Cette application demande un compte différent de celui connecté à Kelo ID.' })
      }
      const client = await provider.clientManager.getClient(record.clientId)
      return res.json({
        success: true, purpose: 'kelo_pds_oauth', status: record.status,
        alreadyApproved: record.status === 'approved',
        clientName: client.metadata?.client_name || record.clientName || record.clientId,
        clientId: record.clientId, scope: record.scope, loginHint: record.loginHint,
        accountDid: did, accountHandle: localAccount.handle,
        expiresAt: record.expiresAt,
      })
    } catch (error) {
      return res.status(400).json({ error: error instanceof Error ? error.message : 'Demande OAuth invalide.' })
    }
  })

  router.post('/kelo-id/oauth/qr/approve', async (req, res) => {
    res.setHeader('Cache-Control', 'no-store, private')
    if (!getApiKey(req, res)) return
    try {
      const token = String(req.body?.challenge || ''), code = String(req.body?.code || '')\n      const did = String(req.body?.did || ''), action = String(req.body?.action || 'approve')
      if (!/^did:(plc|web):[A-Za-z0-9._:%-]+$/.test(did)) return res.status(400).json({ error: 'DID invalide.' })
      if (!['approve', 'deny'].includes(action)) return res.status(400).json({ error: 'Action invalide.' })
      const directory = await ensureDirectory()\n      const initial = token ? await readChallenge(directory, token) : await readManualCode(directory, code)\n      if (!initial) return res.status(404).json({ error: 'QR ou code de connexion introuvable.' })\n\n      const result = await withRequestLock(directory, initial.requestKey, async () => {\n        const record = token ? await readChallenge(directory, token) : await readManualCode(directory, code)
        if (!record) return { status: 404, error: 'QR de connexion introuvable.' }
        if (record.expiresAt <= Date.now()) return { status: 410, error: 'Ce QR a expiré.' }
        if (record.status === 'approved') {
          if (record.approvedDid === did && action === 'approve') return { success: true, alreadyApproved: true }
          return { status: 409, error: 'Cette demande a déjà été traitée.' }
        }
        if (record.status !== 'pending') return { status: 409, error: 'Cette demande de connexion n’est plus active.' }

        const request = await provider.requestManager.get(record.requestUri, record.deviceId, record.clientId)
        const account = await ctx.accountManager.getAccount(did)
        if (!account || account.did !== did) return { status: 403, error: 'Ce compte Kelo ID n’est pas hébergé sur Kelo PDS.' }
        if (request.parameters.login_hint &&
            request.parameters.login_hint.toLowerCase() !== did.toLowerCase() &&
            request.parameters.login_hint.toLowerCase() !== String(account.handle || '').toLowerCase()) {
          return { status: 403, error: 'Cette application demande un compte différent de celui connecté à Kelo ID.' }
        }

        if (action === 'deny') {
          record.status = 'denied'
          record.deniedDid = did
          record.deniedAt = Date.now()
          await saveChallenge(directory, record)
          return { success: true, denied: true }
        }

        await provider.accountManager.upsertDeviceAccount(record.deviceId, did)
        record.status = 'approved'
        record.approvedDid = did
        record.approvedAt = Date.now()
        await saveChallenge(directory, record)
        return { success: true, approved: true }
      })

      if (!result.success) return res.status(result.status || 409).json({ error: result.error || 'Autorisation impossible.' })
      return res.json(result)
    } catch (error) {
      return res.status(400).json({ error: error instanceof Error ? error.message : 'Autorisation impossible.' })
    }
  })

  router.get('/kelo-id/oauth/qr/status', async (req, res) => {
    res.setHeader('Cache-Control', 'no-store, private')
    try {
      const token = String(req.query.challenge || '')
      const directory = await ensureDirectory()
      const record = await readChallenge(directory, token)
      if (!record) return res.status(404).json({ error: 'QR introuvable.' })
      const device = await provider.deviceManager.load(req, res)
      if (device.deviceId !== record.deviceId) return res.status(403).json({ error: 'Cette demande appartient à un autre appareil.' })
      if (record.expiresAt <= Date.now() && record.status === 'pending') {
        record.status = 'expired'
        await saveChallenge(directory, record)
      }
      return res.json({ status: record.status, expiresAt: record.expiresAt })
    } catch (error) {
      return res.status(400).json({ error: error instanceof Error ? error.message : 'État du QR indisponible.' })
    }
  })

  router.get('/kelo-id/oauth/continue', async (req, res) => {
    try {
      const token = String(req.query.challenge || '')
      const mode = String(req.query.mode || '')
      const directory = await ensureDirectory()
      const initial = await readChallenge(directory, token)
      if (!initial) return res.status(404).send('QR introuvable ou expiré.')
      const device = await provider.deviceManager.load(req, res)
      if (device.deviceId !== initial.deviceId) return res.status(403).send('Cette demande appartient à un autre appareil.')

      const result = await withRequestLock(directory, initial.requestKey, async () => {
        const record = await readChallenge(directory, token)
        if (!record || record.expiresAt <= Date.now()) return { error: 'QR introuvable ou expiré.' }
        if (mode === 'classic') {
          if (record.status !== 'pending' && record.status !== 'denied') return { error: 'Cette demande n’est plus disponible.' }
          record.status = 'cancelled'
          record.classic = true
          await saveChallenge(directory, record)
          return { record }
        }
        if (mode === 'resume') {
          if (record.status !== 'approved' || !record.approvedDid) return { error: 'La connexion n’a pas été autorisée.' }
          const linked = await provider.accountManager.getDeviceAccount(record.deviceId, record.approvedDid).catch(() => null)
          if (!linked) return { error: 'La session Kelo PDS n’a pas pu être créée.' }
          return { record }
        }
        return { error: 'Mode de connexion invalide.' }
      })

      if (!result.record) return res.status(409).send(escapeHtml(result.error || 'Impossible de poursuivre.'))
      setBypassCookie(res, token)
      const target = new URL('/oauth/authorize', provider.issuer)
      target.searchParams.set('client_id', result.record.clientId)
      target.searchParams.set('request_uri', result.record.requestUri)
      return res.redirect(303, target.toString())
    } catch (error) {
      return res.status(400).send(escapeHtml(error instanceof Error ? error.message : 'Impossible de poursuivre.'))
    }
  })

  return router
}

module.exports = createKeloOAuthQrRouter
