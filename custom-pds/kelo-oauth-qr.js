'use strict'

const crypto = require('node:crypto')
const fs = require('node:fs/promises')
const path = require('node:path')
const express = require('express')
const QRCode = require('/opt/kelo-pds-qrcode/node_modules/qrcode')

const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/
const TOKEN_TTL_MS = 5 * 60 * 1000
const COOKIE_NAME = 'kelo-oauth-bypass'

function sha256(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex')
}
function dataDirectory() {
  return path.join(process.env.PDS_DATA_DIRECTORY || '/pds', 'kelo-id-oauth-challenges')
}
function requestFile(directory, requestKey) {
  return path.join(directory, 'request-' + requestKey + '.json')
}
function tokenFile(directory, tokenHash) {
  return path.join(directory, 'token-' + tokenHash + '.json')
}
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
      const current = await readJson(requestFile(directory, requestKey))
      if (current && current.status === 'pending' && current.expiresAt > Date.now()) return current
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
        current.deviceId === data.deviceId) return { ...current, token: data.token || null }

    if (current?.challengeHash) await fs.unlink(tokenFile(directory, current.challengeHash)).catch(() => {})
    const token = crypto.randomBytes(32).toString('base64url')
    const tokenHash = sha256(token)
    const record = {
      version: 1, requestKey, challengeHash: tokenHash,
      requestUri: data.requestUri, clientId: data.clientId, deviceId: data.deviceId,
      clientName: data.clientName, scope: data.scope || 'atproto',
      loginHint: data.loginHint || null, createdAt: Date.now(),
      expiresAt: Date.now() + TOKEN_TTL_MS, status: 'pending',
      approvedDid: null, approvedAt: null, deniedDid: null, deniedAt: null, classic: false,
    }
    await atomicWrite(file, record)
    await atomicWrite(tokenFile(directory, tokenHash), { requestKey })
    return { ...record, token }
  })
}
async function readChallenge(directory, token) {
  if (typeof token !== 'string' || !TOKEN_PATTERN.test(token)) return null
  const tokenHash = sha256(token)
  const pointer = await readJson(tokenFile(directory, tokenHash))
  if (!pointer || typeof pointer.requestKey !== 'string' || !/^[0-9a-f]{64}$/.test(pointer.requestKey)) return null
  const record = await readJson(requestFile(directory, pointer.requestKey))
  if (!record || record.challengeHash !== tokenHash || record.requestKey !== pointer.requestKey) return null
  return record
}
async function saveChallenge(directory, record) {
  await atomicWrite(requestFile(directory, record.requestKey), record)
}
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
function sendIosCookieTest(req, res) {
  const target = new URL(req.originalUrl, req.protocol + '://' + req.get('host'))
  target.searchParams.set('redirect-test', '1')
  const action = escapeHtml(target.pathname + target.search)
  res.setHeader('Cache-Control', 'no-store')
  res.setHeader('Content-Type', 'text/html; charset=utf-8')
  res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
  res.setHeader('Set-Cookie', 'cookie-test=testing; Path=/; HttpOnly; Secure; SameSite=Lax')
  res.end('<!doctype html><html lang="fr"><meta charset="utf-8"><title>Vérification du navigateur</title><body><form id="kelo-cookie-test" method="get" action="' + action + '"></form><script>document.getElementById("kelo-cookie-test").submit()</script></body></html>')
}
function renderAuthorizationPage(res, token, record, qrDataUrl) {
  const classicUrl = '/kelo-id/oauth/continue?mode=classic&challenge=' + encodeURIComponent(token)
  const statusUrl = '/kelo-id/oauth/qr/status?challenge=' + encodeURIComponent(token)
  const resumeUrl = '/kelo-id/oauth/continue?mode=resume&challenge=' + encodeURIComponent(token)
  const clientName = escapeHtml(record.clientName || record.clientId)
  const clientId = escapeHtml(record.clientId)
  const scope = escapeHtml(record.scope)
  const image = escapeHtml(qrDataUrl)
  const script = [
    'const statusUrl=' + JSON.stringify(statusUrl) + ';',
    'const resumeUrl=' + JSON.stringify(resumeUrl) + ';',
    'const statusNode=document.getElementById("kelo-status");',
    'let stopped=false;',
    'async function poll(){if(stopped)return;try{const response=await fetch(statusUrl,{cache:"no-store",credentials:"same-origin"});const data=await response.json();',
    'if(data.status==="approved"){stopped=true;statusNode.textContent="Connexion autorisée. Finalisation…";window.location.replace(resumeUrl);return;}',
    'if(data.status==="denied"||data.status==="cancelled"){stopped=true;statusNode.textContent="Demande refusée ou annulée. Vous pouvez utiliser la connexion classique.";return;}',
    'if(data.status==="expired"||response.status===410){stopped=true;statusNode.textContent="Ce QR a expiré. Actualisez la page pour en générer un nouveau.";return;}',
    'if(!response.ok){stopped=true;statusNode.textContent=data.error||"Impossible de vérifier la demande.";return;}}catch(e){statusNode.textContent="Connexion en attente…";}setTimeout(poll,1800);}poll();',
  ].join('')
  const html = '<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connexion Kelo PDS</title><style>' +
    '*{box-sizing:border-box}body{margin:0;min-height:100vh;background:#f4f6fb;color:#172033;font:16px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;display:grid;place-items:center;padding:24px}.card{width:min(100%,520px);background:#fff;border:1px solid #e5e9f2;border-radius:24px;padding:32px;box-shadow:0 18px 55px #17203312;text-align:center}.brand{font-weight:750;letter-spacing:.02em;color:#315df5}.eyebrow{font-size:12px;text-transform:uppercase;letter-spacing:.12em;color:#667085;font-weight:700;margin-top:20px}h1{font-size:28px;line-height:1.2;margin:8px 0 12px}.muted{color:#667085}.client{background:#f7f8fc;border-radius:14px;padding:12px;margin:18px 0;text-align:left;overflow-wrap:anywhere}.client strong{display:block}.qr{width:260px;height:260px;max-width:100%;object-fit:contain;margin:12px auto}.hint{font-size:14px;color:#667085}.status{min-height:26px;margin:12px 0;color:#315df5;font-weight:650}.button{display:block;text-decoration:none;border-radius:12px;padding:13px 18px;font-weight:700;margin-top:16px}.primary{background:#315df5;color:white}.secondary{border:1px solid #d9deea;color:#344054}.small{font-size:12px;color:#98a2b3;margin-top:18px}' +
    '</style></head><body><main class="card"><div class="brand">KELO SOCIAL · PDS</div><div class="eyebrow">Authentification sécurisée</div><h1>Se connecter avec Kelo ID</h1><p class="muted">Scannez ce QR code avec l’application Kelo ID, puis vérifiez les informations et appuyez sur « Autoriser ».</p><div class="client"><strong>' + clientName + '</strong><span>' + clientId + '</span><p>Autorisations demandées : ' + scope + '</p></div><img class="qr" src="' + image + '" alt="QR code de connexion Kelo ID"><p class="hint">Ce QR code expire dans cinq minutes et ne peut être utilisé qu’une seule fois.</p><div id="kelo-status" class="status" role="status" aria-live="polite">En attente de votre confirmation dans Kelo ID…</div><a class="button secondary" href="' + classicUrl + '">Utiliser mon identifiant et mon mot de passe</a><p class="small">Ne scannez ce code que si vous avez lancé vous-même cette connexion.</p></main><script>' + script + '</script></body></html>'
  res.setHeader('Cache-Control', 'no-store, private')
  res.setHeader('Pragma', 'no-cache')
  res.setHeader('Referrer-Policy', 'no-referrer')
  res.setHeader('X-Content-Type-Options', 'nosniff')
  res.setHeader('Content-Security-Policy', "default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
  res.status(200).type('html').send(html)
}

function createKeloOAuthQrRouter(ctx) {
  const router = express.Router()
  const provider = ctx.oauthProvider
  router.use('/kelo-id', express.json({ limit: '4kb' }))

  router.get('/oauth/authorize', async (req, res, next) => {
    try {
      if (!provider || !validateBrowserNavigation(req, provider.issuer)) return next()
      const query = new URL(req.originalUrl, provider.issuer).searchParams
      const clientId = query.get('client_id')
      const requestUri = query.get('request_uri')
      if (!clientId || !requestUri) return next()

      if (String(req.headers['user-agent'] || '').includes('iPhone OS') &&
          readCookie(req, 'cookie-test') !== 'succeeded' &&
          !(await provider.deviceManager.hasSession(req))) {
        if (!query.has('redirect-test')) return sendIosCookieTest(req, res)
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

      await provider.requestManager.get(requestUri, device.deviceId, clientId)
      const sessions = await provider.accountManager.listDeviceAccounts(device.deviceId)
      if (sessions.length > 0) return next()

      const client = await provider.clientManager.getClient(clientId)
      const directory = await ensureDirectory()
      const record = await createOrReuseChallenge(directory, {
        requestUri, clientId, deviceId: device.deviceId,
        clientName: client.metadata?.client_name || clientId,
        scope: query.get('scope') || 'atproto',
        loginHint: query.get('login_hint') || null,
      })
      const token = record.token
      if (!token) throw new Error('Unable to restore the pending OAuth QR token')
      const qrDataUrl = await QRCode.toDataURL(token, {
        errorCorrectionLevel: 'M', margin: 2, width: 260,
      })
      return renderAuthorizationPage(res, token, record, qrDataUrl)
    } catch (error) {
      return next(error)
    }
  })

  router.get('/kelo-id/oauth/qr', async (req, res) => {
    res.setHeader('Cache-Control', 'no-store, private')
    if (!getApiKey(req, res)) return
    try {
      const token = String(req.query.challenge || '')
      const did = String(req.query.did || '')
      const directory = await ensureDirectory()
      const record = await readChallenge(directory, token)
      if (!record) return res.status(404).json({ error: 'QR de connexion introuvable.' })
      if (record.expiresAt <= Date.now()) return res.status(410).json({ error: 'Ce QR a expiré.' })
      if (record.status === 'approved') {
        if (record.approvedDid !== did) return res.status(409).json({ error: 'Ce QR a déjà été utilisé par un autre compte.' })
      } else if (record.status !== 'pending') {
        return res.status(409).json({ error: 'Cette demande de connexion n’est plus active.' })
      }
      await provider.requestManager.get(record.requestUri, record.deviceId, record.clientId)
      const client = await provider.clientManager.getClient(record.clientId)
      return res.json({
        success: true, purpose: 'kelo_pds_oauth', status: record.status,
        alreadyApproved: record.status === 'approved',
        clientName: client.metadata?.client_name || record.clientName || record.clientId,
        clientId: record.clientId, scope: record.scope, loginHint: record.loginHint,
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
      const token = String(req.body?.challenge || '')
      const did = String(req.body?.did || '')
      const action = String(req.body?.action || 'approve')
      if (!/^did:(plc|web):[A-Za-z0-9._:%-]+$/.test(did)) return res.status(400).json({ error: 'DID invalide.' })
      if (!['approve', 'deny'].includes(action)) return res.status(400).json({ error: 'Action invalide.' })
      const directory = await ensureDirectory()
      const initial = await readChallenge(directory, token)
      if (!initial) return res.status(404).json({ error: 'QR de connexion introuvable.' })

      const result = await withRequestLock(directory, initial.requestKey, async () => {
        const record = await readChallenge(directory, token)
        if (!record) return { status: 404, error: 'QR de connexion introuvable.' }
        if (record.expiresAt <= Date.now()) return { status: 410, error: 'Ce QR a expiré.' }
        if (record.status === 'approved') {
          if (record.approvedDid === did && action === 'approve') return { success: true, alreadyApproved: true }
          return { status: 409, error: 'Cette demande a déjà été traitée.' }
        }
        if (record.status !== 'pending') return { status: 409, error: 'Cette demande de connexion n’est plus active.' }

        const request = await provider.requestManager.get(record.requestUri, record.deviceId, record.clientId)
        const accountResult = await provider.accountManager.getAccount(did)
        const account = accountResult?.account
        if (!account || account.did !== did) return { status: 404, error: 'Ce compte n’existe pas sur Kelo PDS.' }
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
          if (record.status !== 'pending') return { error: 'Cette demande n’est plus disponible.' }
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
