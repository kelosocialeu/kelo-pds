'use strict'

const crypto = require('node:crypto')
const fs = require('node:fs/promises')
const path = require('node:path')
const express = require('express')
const QRCode = require('/opt/kelo-pds-qrcode/node_modules/qrcode')
const oauthProviderEntry = require.resolve('@atproto/oauth-provider', { paths: [__dirname] })
const oauthTypesPath = require.resolve('@atproto/oauth-types', { paths: [path.dirname(oauthProviderEntry)] })
const { oauthAuthorizationRequestQuerySchema } = require(oauthTypesPath)

const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/
const MANUAL_CODE_PATTERN = /^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{12}$/
const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
const TOKEN_TTL_MS = 5 * 60 * 1000
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
function tokenFile(directory, tokenHash) {
  return path.join(directory, 'token-' + tokenHash + '.json')
}
function codeFile(directory, codeHash) { return path.join(directory, 'code-' + codeHash + '.json') }
function createManualCode() { let value = ''; for (let index = 0; index < 12; index += 1) value += CODE_ALPHABET[crypto.randomInt(CODE_ALPHABET.length)]; return value.slice(0, 4) + '-' + value.slice(4, 8) + '-' + value.slice(8) }
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
        current.deviceId === data.deviceId && current.codeHash && current.manualCode) return { ...current, token: current.challengeToken, code: current.manualCode }

    if (current?.challengeHash) await fs.unlink(tokenFile(directory, current.challengeHash)).catch(() => {})
    if (current?.codeHash) await fs.unlink(codeFile(directory, current.codeHash)).catch(() => {})
    const token = crypto.randomBytes(32).toString('base64url')
    const tokenHash = sha256(token)
    const manualCode = createManualCode()
    const codeHash = sha256(manualCode.replace(/-/g, ''))
    const record = {
      version: 1, requestKey, challengeHash: tokenHash, challengeToken: token,
      codeHash, manualCode,
      requestUri: data.requestUri, clientId: data.clientId, deviceId: data.deviceId,
      clientName: data.clientName, scope: data.scope || 'atproto',
      loginHint: data.loginHint || null, createdAt: Date.now(),
      expiresAt: Date.now() + TOKEN_TTL_MS, status: 'pending',
      approvedDid: null, approvedAt: null, deniedDid: null, deniedAt: null, classic: false,
    }
    await atomicWrite(file, record)
    await atomicWrite(tokenFile(directory, tokenHash), { requestKey })
    await atomicWrite(codeFile(directory, codeHash), { requestKey })
    return { ...record, token, code: manualCode }
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
async function readManualCode(directory, input) {
  const normalized = String(input || '').toUpperCase().replace(/[\s-]/g, '')
  if (!MANUAL_CODE_PATTERN.test(normalized)) return null
  const codeHash = sha256(normalized)
  const pointer = await readJson(codeFile(directory, codeHash))
  if (!pointer || typeof pointer.requestKey !== 'string' || !/^[0-9a-f]{64}$/.test(pointer.requestKey)) return null
  const record = await readJson(requestFile(directory, pointer.requestKey))
  if (!record || record.codeHash !== codeHash || record.requestKey !== pointer.requestKey || String(record.manualCode || '').replace(/-/g, '') !== normalized) return null
  return record
}
async function saveChallenge(directory, record) { await atomicWrite(requestFile(directory, record.requestKey), record) }
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
function renderPageShell(title, content, options = {}) {
  const logo = 'https://kelosocial.sirv.com/logo.png'
  const keloIdLogo = 'https://kelosocial.sirv.com/logoid.png'
  const styles = [
    '*{box-sizing:border-box}',
    ':root{color-scheme:light;--ink:#172033;--muted:#667085;--line:#e6eaf2;--blue:#315df5;--blue2:#7048ef;--surface:#fff;--soft:#f5f7fc}',
    'html{min-height:100%;background:#f4f6fb}',
    'body{margin:0;min-height:100vh;color:var(--ink);font:16px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:radial-gradient(ellipse at 12% 8%,#e7edff 0,transparent 34%),radial-gradient(ellipse at 92% 90%,#eee9ff 0,transparent 32%),#f6f8fc;display:flex;flex-direction:column;padding:clamp(14px,3vw,36px)}',
    '.topbar{width:min(100%,1080px);margin:0 auto 22px;display:flex;align-items:center;justify-content:space-between;gap:16px}',
    '.brand{display:inline-flex;align-items:center;gap:11px;color:var(--ink);font-weight:800;letter-spacing:-.035em;font-size:19px;text-decoration:none}',
    '.brand img{width:42px;height:42px;object-fit:contain;border-radius:13px;filter:drop-shadow(0 5px 12px #315df51c)}',
    '.brand small{display:block;color:var(--muted);font-size:11px;letter-spacing:.12em;text-transform:uppercase;font-weight:700;margin-top:-2px}',
    '.secure{display:inline-flex;align-items:center;gap:7px;color:#53627b;font-size:12px;font-weight:650;background:#ffffffb8;border:1px solid #e8ebf3;border-radius:999px;padding:8px 12px}',
    '.secure:before{content:"";width:7px;height:7px;background:#16a36a;border-radius:50%;box-shadow:0 0 0 3px #16a36a1c}',
    '.layout{width:min(100%,1080px);margin:auto;display:grid;grid-template-columns:minmax(0,1fr) minmax(340px,.88fr);gap:clamp(22px,4vw,52px);align-items:center}',
    '.intro{padding:clamp(8px,2vw,28px) 0}',
    '.eyebrow{display:inline-flex;align-items:center;gap:8px;color:var(--blue);font-size:12px;text-transform:uppercase;letter-spacing:.13em;font-weight:800}',
    '.eyebrow:before{content:"";width:22px;height:2px;background:linear-gradient(90deg,var(--blue),var(--blue2));border-radius:9px}',
    'h1{font-size:clamp(30px,4vw,46px);line-height:1.08;letter-spacing:-.055em;margin:15px 0 14px;font-weight:800}',
    '.lead{font-size:clamp(15px,1.5vw,17px);color:var(--muted);max-width:490px;margin:0}',
    '.panel{background:var(--surface);border:1px solid #e8ebf2;border-radius:26px;padding:clamp(22px,3vw,34px);box-shadow:0 24px 70px #17203312,0 3px 12px #17203308}',
    '.choice-panel{max-width:490px;width:100%;justify-self:end}',
    '.client{background:linear-gradient(135deg,#f7f9ff,#f5f3ff);border:1px solid #e7eafe;border-radius:16px;padding:15px 17px;margin:24px 0 20px;overflow-wrap:anywhere}',
    '.client-label{font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:#77839a;font-weight:800;margin-bottom:5px}',
    '.client strong{display:block;font-size:15px;color:#202b40}',
    '.client-id{display:block;color:#77839a;font-size:12px;margin-top:3px;word-break:break-all}',
    '.client-scope{margin:10px 0 0;color:#59677e;font-size:13px}',
    '.actions{display:grid;gap:12px;margin-top:18px}',
    '.button{width:100%;min-height:54px;display:flex;align-items:center;justify-content:center;gap:12px;padding:13px 18px;border-radius:15px;text-decoration:none;font-weight:750;font-size:15px;transition:transform .16s ease,box-shadow .16s ease,border-color .16s ease}',
    '.button:hover{transform:translateY(-1px)}.button:focus-visible{outline:3px solid #315df566;outline-offset:3px}',
    '.primary{background:linear-gradient(110deg,#2563eb,#6550e9);color:white;box-shadow:0 10px 24px #315df532}',
    '.primary:hover{box-shadow:0 13px 28px #315df545}',
    '.secondary{background:#fff;border:1px solid #dfe4ee;color:#344054}',
    '.secondary:hover{border-color:#b9c6e8;background:#fafbff}',
    '.button-logo{width:27px;height:27px;object-fit:contain;border-radius:8px;background:#fff;padding:2px;flex:0 0 auto}',
    '.button-arrow{margin-left:auto;font-size:19px;opacity:.8}',
    '.fineprint{color:#98a2b3;font-size:12px;text-align:center;margin:18px 0 0}',
    '.qr-panel{width:100%;max-width:520px;justify-self:end;text-align:center}',
    '.qr-heading{font-size:19px;font-weight:800;letter-spacing:-.025em;margin:0 0 5px}',
    '.qr-subtitle{font-size:13px;color:var(--muted);margin:0}',
    '.qr-frame{width:min(100%,290px);aspect-ratio:1;margin:20px auto 15px;padding:12px;border:1px solid #e8ebf2;border-radius:23px;background:#fff;box-shadow:0 10px 28px #1720330d;display:grid;place-items:center}',
    '.qr{width:100%;height:100%;object-fit:contain;image-rendering:pixelated}',
    '.manual{background:linear-gradient(120deg,#f0f5ff,#f5f2ff);border:1px solid #e0e7ff;border-radius:17px;padding:15px 12px;margin:14px auto 0;max-width:360px}',
    '.manual-label{display:block;color:#68758c;font-size:12px;font-weight:650}',
    '.manual strong{display:block;font:800 clamp(21px,4vw,27px)/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.09em;color:#315df5;white-space:nowrap}',
    '.manual small{display:block;color:#8893a7;font-size:11px}',
    '.status{min-height:26px;margin:14px 0 4px;color:#315df5;font-size:13px;font-weight:700}',
    '.steps{display:grid;gap:13px;margin:28px 0 0;padding:0;list-style:none;max-width:440px}',
    '.steps li{display:flex;gap:12px;align-items:flex-start;color:#5f6c82;font-size:14px}',
    '.step-no{display:grid;place-items:center;flex:0 0 26px;height:26px;border-radius:9px;background:#eaf0ff;color:#315df5;font-weight:800;font-size:12px}',
    '.security-note{display:flex;gap:10px;align-items:flex-start;text-align:left;color:#7b879a;font-size:12px;line-height:1.5;margin:18px 0 0;padding-top:16px;border-top:1px solid #edf0f5}',
    '.security-note b{color:#58667d}',
    '.footer{width:min(100%,1080px);margin:24px auto 0;color:#a0a8b7;font-size:11px;text-align:center}',
    '@media(max-width:760px){body{padding:14px;min-height:100svh}.topbar{margin-bottom:16px}.layout{grid-template-columns:1fr;gap:18px;width:min(100%,520px)}.intro{padding:4px 3px 0;text-align:center}.intro .lead{margin-inline:auto}.steps{margin:18px auto 0;text-align:left}.choice-panel,.qr-panel{justify-self:stretch;max-width:none}.panel{border-radius:22px;padding:22px}.brand img{width:38px;height:38px}.secure{font-size:11px;padding:7px 9px}h1{font-size:clamp(28px,8vw,36px);margin:10px 0}.qr-frame{width:min(72vw,270px);margin:15px auto 12px}.footer{margin-top:18px}}',
    '@media(max-width:390px){body{padding:10px}.topbar{gap:8px}.brand{font-size:16px;gap:8px}.brand img{width:34px;height:34px}.secure{font-size:10px}.panel{padding:18px}.button{font-size:14px;min-height:51px}.manual strong{letter-spacing:.055em}}',
    '@media(prefers-reduced-motion:reduce){*,*:before,*:after{scroll-behavior:auto!important;transition:none!important}}'
  ].join('')
  const header = '<header class="topbar"><a class="brand" href="https://kelosocial.eu" aria-label="Kelo Social, accueil"><img src="' + logo + '" alt="Logo Kelo Social"><span>KELO SOCIAL<small>Personal Data Server</small></span></a><span class="secure">Connexion sécurisée</span></header>'
  const html = '<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="theme-color" content="#f4f6fb"><meta name="color-scheme" content="light"><title>' + escapeHtml(title) + '</title><style>' + styles + '</style></head><body>' + header + content + '<footer class="footer">Kelo PDS · Votre identité, vos données, votre choix.</footer></body></html>'
  return html
}

function renderQrAuthorizationPage(res, token, record, qrDataUrl) {
  const classicUrl = '/kelo-id/oauth/continue?mode=classic&challenge=' + encodeURIComponent(token)
  const statusUrl = '/kelo-id/oauth/qr/status?challenge=' + encodeURIComponent(token)
  const resumeUrl = '/kelo-id/oauth/continue?mode=resume&challenge=' + encodeURIComponent(token)
  const clientName = escapeHtml(record.clientName || record.clientId)
  const clientId = escapeHtml(record.clientId)
  const scope = escapeHtml(record.scope)
  const image = escapeHtml(qrDataUrl)
  const manualCode = escapeHtml(record.manualCode || '')
  const script = [
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
  const content = '<main class="layout"><section class="intro"><span class="eyebrow">Kelo ID · Autorisation</span><h1>Scannez pour vous connecter.</h1><p class="lead">Ouvrez l’application Kelo ID sur votre téléphone, puis scannez ce QR code. Vérifiez les informations avant d’autoriser la connexion.</p><ol class="steps"><li><span class="step-no">1</span><span>Ouvrez <b>Kelo ID</b> et accédez au scanner.</span></li><li><span class="step-no">2</span><span>Scannez le QR code ou saisissez le code manuel.</span></li><li><span class="step-no">3</span><span>Vérifiez le compte et l’application, puis confirmez dans Kelo ID.</span></li></ol></section><section class="panel qr-panel"><h2 class="qr-heading">Connexion avec Kelo ID</h2><p class="qr-subtitle">Scannez ce code depuis votre application mobile</p><div class="client"><div class="client-label">Application qui demande l’accès</div><strong>' + clientName + '</strong><span class="client-id">' + clientId + '</span><p class="client-scope">Autorisations demandées : ' + scope + '</p></div><div class="qr-frame"><img class="qr" src="' + image + '" alt="QR code de connexion Kelo ID"></div><p class="qr-subtitle">Ce QR code est personnel, temporaire et à usage unique.</p><div class="manual"><span class="manual-label">Vous ne pouvez pas scanner ? Saisissez ce code dans Kelo ID</span><strong>' + manualCode + '</strong><small>Code valable cinq minutes · à usage unique</small></div><div id="kelo-status" class="status" role="status" aria-live="polite">En attente de votre confirmation dans Kelo ID…</div><a class="button secondary" href="' + classicUrl + '">Utiliser identifiant et mot de passe <span class="button-arrow">→</span></a><div class="security-note"><span aria-hidden="true">ⓘ</span><span><b>Conseil de sécurité</b><br>Ne scannez ce code que si vous avez vous-même lancé cette connexion. Ne partagez jamais votre code.</span></div></section></main>'
  const html = renderPageShell('Connexion avec Kelo ID · Kelo PDS', content)
    .replace('</body>', '<script>' + script + '</script></body>')
  res.setHeader('Cache-Control', 'no-store, private')
  res.setHeader('Pragma', 'no-cache')
  res.setHeader('Referrer-Policy', 'no-referrer')
  res.setHeader('X-Content-Type-Options', 'nosniff')
  res.setHeader('Content-Security-Policy', "default-src 'none'; img-src data: https://kelosocial.sirv.com; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
  res.status(200).type('html').send(html)
}

function renderLoginChoicePage(res, token, record) {
  const keloUrl = '/kelo-id/oauth/qr/page?challenge=' + encodeURIComponent(token)
  const classicUrl = '/kelo-id/oauth/continue?mode=classic&challenge=' + encodeURIComponent(token)
  const clientName = escapeHtml(record.clientName || record.clientId)
  const clientId = escapeHtml(record.clientId)
  const scope = escapeHtml(record.scope)
  const content = '<main class="layout"><section class="intro"><span class="eyebrow">Bienvenue sur Kelo PDS</span><h1>Connectez-vous à votre espace.</h1><p class="lead">Choisissez la méthode qui vous convient. Avec Kelo ID, vous pouvez autoriser la connexion depuis votre téléphone sans saisir votre mot de passe sur cet appareil.</p><ol class="steps"><li><span class="step-no">1</span><span>Choisissez votre méthode de connexion.</span></li><li><span class="step-no">2</span><span>Vérifiez l’application qui demande l’accès.</span></li><li><span class="step-no">3</span><span>Confirmez la connexion en toute sécurité.</span></li></ol></section><section class="panel choice-panel"><span class="eyebrow">Choisir une méthode</span><h1 style="font-size:clamp(25px,3vw,32px);margin-top:12px">Comment souhaitez-vous vous connecter ?</h1><p class="lead" style="font-size:14px">Votre demande de connexion est prête.</p><div class="client"><div class="client-label">Application à connecter</div><strong>' + clientName + '</strong><span class="client-id">' + clientId + '</span><p class="client-scope">Autorisations demandées : ' + scope + '</p></div><div class="actions"><a class="button primary" href="' + keloUrl + '"><img class="button-logo" src="https://kelosocial.sirv.com/logoid.png" alt="Logo Kelo ID">Se connecter avec Kelo ID<span class="button-arrow">→</span></a><a class="button secondary" href="' + classicUrl + '">Se connecter avec identifiant et mot de passe<span class="button-arrow">→</span></a></div><p class="fineprint">La connexion Kelo ID nécessite votre validation explicite depuis l’application.</p></section></main>'
  const html = renderPageShell('Connexion · Kelo PDS', content)
  res.setHeader('Cache-Control', 'no-store, private')
  res.setHeader('Pragma', 'no-cache')
  res.setHeader('Referrer-Policy', 'no-referrer')
  res.setHeader('X-Content-Type-Options', 'nosniff')
  res.setHeader('Content-Security-Policy', "default-src 'none'; img-src https://kelosocial.sirv.com; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
  res.status(200).type('html').send(html)
}

const NATIVE_LOGIN_CSS = [
  '*,*::before,*::after{box-sizing:border-box}',
  'html{min-height:100%;background:#f6f8fc}',
  'body{min-height:100vh;margin:0;padding:clamp(16px,3vw,36px);display:flex;flex-direction:column;color:#172033;font:16px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:radial-gradient(ellipse at 12% 8%,#e7edff 0,transparent 34%),radial-gradient(ellipse at 92% 90%,#eee9ff 0,transparent 32%),#f6f8fc}',
  '.kelo-native-brand{display:flex;align-items:center;gap:12px;width:min(100%,1080px);margin:0 auto 22px;padding:12px 16px;background:#ffffffd9;border:1px solid #e6eaf2;border-radius:18px;box-shadow:0 12px 34px #17203312;color:#172033;font:800 16px/1.2 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;letter-spacing:-.025em;backdrop-filter:blur(12px)}',
  '.kelo-native-brand a{display:flex;align-items:center;flex:0 0 auto}',
  '.kelo-native-brand img{display:block;width:42px;height:42px;object-fit:contain;border-radius:12px}',
  '.kelo-native-brand strong{display:block}',
  '.kelo-native-brand strong span{color:#667085;font-weight:650}',
  'body:has(form)>div:not(.kelo-native-brand){width:min(100%,1080px);flex:1;margin:auto;display:flex;align-items:center;justify-content:center}',
  'body:has(form) h1{color:#26345b;font-size:clamp(30px,4vw,46px);font-weight:800;letter-spacing:-.055em;line-height:1.08}',
  'body:has(form) form{width:min(100%,620px);padding:clamp(22px,3vw,36px);background:#fff;border:1px solid #e7eaf2;border-radius:26px;box-shadow:0 24px 70px #17203312,0 3px 12px #17203308}',
  'body:has(form) label{display:block;margin:0 0 7px;color:#344064;font-size:13px;font-weight:700}',
  'body:has(form) input:not([type=checkbox]):not([type=radio]):not([type=hidden]){width:100%;min-height:50px;padding:12px 15px;border:1px solid #dfe4ee;border-radius:12px;background:#f8f9fd;color:#172033;font-family:inherit;font-size:15px;font-weight:500;line-height:1.4;outline:none;transition:border-color .16s ease,box-shadow .16s ease,background .16s ease}',
  'body:has(form) input:not([type=checkbox]):not([type=radio]):not([type=hidden]):focus{border-color:#7050ef;background:#fff;box-shadow:0 0 0 4px #7050ef20}',
  'body:has(form) input[type=checkbox],body:has(form) input[type=radio]{accent-color:#654fe8}',
  'body:has(form) button[type=submit],body:has(form) input[type=submit]{min-height:50px;padding:12px 24px;border:0;border-radius:12px;background:linear-gradient(110deg,#2563eb,#7048ef);color:#fff;font-family:inherit;font-size:15px;font-weight:750;line-height:1.2;box-shadow:0 10px 24px #315df532;cursor:pointer;transition:transform .16s ease,box-shadow .16s ease}',
  'body:has(form) button[type=submit]:hover,body:has(form) input[type=submit]:hover{transform:translateY(-1px);box-shadow:0 13px 28px #315df545}',
  'body:has(form) button:focus-visible,body:has(form) a:focus-visible{outline:3px solid #7050ef66;outline-offset:3px}',
  'body:has(form) [role=alert],body:has(form) .warning{padding:13px 15px;border:1px solid #f1d8a7;border-radius:12px;background:#fff8e9;color:#76521c;font-size:13px;line-height:1.5}',
  'body:has(form) a{color:#5544d8;font-weight:650;text-underline-offset:3px}',
  'body:has(form) form>div{margin-bottom:16px}',
  '@media(max-width:760px){body{padding:14px;min-height:100svh}.kelo-native-brand{margin:0 auto 18px;padding:11px 13px;border-radius:14px}.kelo-native-brand img{width:38px;height:38px}body:has(form)>div:not(.kelo-native-brand){width:100%;align-items:flex-start;padding-top:clamp(24px,8vh,64px)}body:has(form) form{width:100%;padding:22px;border-radius:22px}body:has(form) h1{font-size:clamp(28px,8vw,36px)}}',
  '@media(max-width:390px){body{padding:10px}.kelo-native-brand{gap:9px;font-size:14px}.kelo-native-brand img{width:34px;height:34px}body:has(form) form{padding:18px}}',
  '@media(prefers-reduced-motion:reduce){*,*::before,*::after{scroll-behavior:auto!important;transition:none!important}}'
].join('\n')

function brandNativeLoginPage(req, res, next) {
  const originalSend = res.send
  res.send = function (body, ...args) {
    let output = body
    const contentType = String(res.getHeader('Content-Type') || '')
    if (req.path === '/oauth/authorize' && typeof body === 'string' &&
        (contentType.includes('text/html') || /<(?:!doctype html|html|body)\b/i.test(body)) && !body.includes('kelo-native-brand')) {
      const header = '<header class="kelo-native-brand" role="banner"><a href="https://kelosocial.eu" aria-label="Kelo Social"><img src="https://kelosocial.sirv.com/logo.png" width="42" height="42" alt="Logo Kelo Social"></a><strong>KELO SOCIAL <span>· PDS</span></strong></header>'
      output = body.replace(/<head([^>]*)>/i, (match) => match + '<link rel="stylesheet" href="/kelo-id/login.css">')
      output = output.replace(/<body([^>]*)>/i, (match) => match + header)
      const policy = String(res.getHeader('Content-Security-Policy') || '')
      if (policy) {
        const directives = policy.split(';').map((part) => part.trim()).filter(Boolean)
        const imageIndex = directives.findIndex((part) => /^img-src\s/i.test(part))
        if (imageIndex >= 0) {
          if (!directives[imageIndex].includes('https://kelosocial.sirv.com')) directives[imageIndex] += ' https://kelosocial.sirv.com'
        } else {
          directives.push("img-src 'self' data: https://kelosocial.sirv.com")
        }
        const styleIndex = directives.findIndex((part) => /^style-src\s/i.test(part))
        if (styleIndex >= 0) {
          if (!directives[styleIndex].includes("'self'")) directives[styleIndex] += " 'self'"
        } else {
          directives.push("style-src 'self'")
        }
        res.setHeader('Content-Security-Policy', directives.join('; '))
      }
    }
    return originalSend.call(this, output, ...args)
  }
  next()
}

function createKeloOAuthQrRouter(ctx) {
  const router = express.Router()
  router.use(brandNativeLoginPage)
  router.get('/kelo-id/login.css', (_req, res) => {
    res.setHeader('Cache-Control', 'public, max-age=3600')
    res.type('text/css').send(NATIVE_LOGIN_CSS)
  })
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

  router.get('/kelo-id/oauth/qr/page', async (req, res) => {
    try {
      const token = String(req.query.challenge || ''), directory = await ensureDirectory(), record = await readChallenge(directory, token)
      if (!record || record.expiresAt <= Date.now() || record.status !== 'pending') return res.status(410).send('Cette demande de connexion a expiré. Relancez la connexion depuis votre application.')
      const device = await provider.deviceManager.load(req, res)
      if (device.deviceId !== record.deviceId) return res.status(403).send('Cette demande appartient à un autre navigateur.')
      const qrDataUrl = await QRCode.toDataURL(token, { errorCorrectionLevel: 'M', margin: 2, width: 260 })
      return renderQrAuthorizationPage(res, token, record, qrDataUrl)
    } catch (error) { return res.status(400).send(escapeHtml(error instanceof Error ? error.message : 'Impossible de créer le QR code.')) }
  })

  router.get('/kelo-id/oauth/qr', async (req, res) => {
    res.setHeader('Cache-Control', 'no-store, private')
    if (!getApiKey(req, res)) return
    try {
      const token = String(req.query.challenge || ''), code = String(req.query.code || ''), did = String(req.query.did || '')
      const directory = await ensureDirectory()
      const record = token ? await readChallenge(directory, token) : await readManualCode(directory, code)
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
      const token = String(req.body?.challenge || ''), code = String(req.body?.code || '')
      const did = String(req.body?.did || ''), action = String(req.body?.action || 'approve')
      if (!/^did:(plc|web):[A-Za-z0-9._:%-]+$/.test(did)) return res.status(400).json({ error: 'DID invalide.' })
      if (!['approve', 'deny'].includes(action)) return res.status(400).json({ error: 'Action invalide.' })
      const directory = await ensureDirectory()
      const initial = token ? await readChallenge(directory, token) : await readManualCode(directory, code)
      if (!initial) return res.status(404).json({ error: 'QR ou code de connexion introuvable.' })

      const result = await withRequestLock(directory, initial.requestKey, async () => {
        const record = token ? await readChallenge(directory, token) : await readManualCode(directory, code)
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
