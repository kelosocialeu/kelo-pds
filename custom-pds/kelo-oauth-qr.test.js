'use strict'

const assert = require('node:assert/strict')
const fs = require('node:fs/promises')
const os = require('node:os')
const path = require('node:path')

async function run() {
  const modulePath = process.argv[2]
  assert.ok(modulePath, 'Pass the built Kelo OAuth QR middleware path')

  const dataDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'kelo-oauth-qr-'))
  process.env.PDS_DATA_DIRECTORY = dataDirectory
  process.env.PDS_KELO_ID_API_KEY = 'kelo-test-api-key-'.padEnd(40, 'x')

  const expressPath = require.resolve('express', { paths: [path.dirname(modulePath)] })
  const express = require(expressPath)
  const createRouter = require(modulePath)
  const linkedAccounts = new Map()
  const requestBindings = new Map()
  const requestParameters = new Map([
    ['urn:ietf:params:oauth:request_uri:first', {
      clientId: 'https://client.example/metadata.json',
      parameters: { scope: 'atproto repo', login_hint: 'alice.kelosocial.eu', prompt: undefined },
    }],
    ['urn:ietf:params:oauth:request_uri:classic', {
      clientId: 'https://client.example/metadata.json',
      parameters: { scope: 'atproto', login_hint: null, prompt: undefined },
    }],
    ['urn:ietf:params:oauth:request_uri:silent', {
      clientId: 'https://client.example/metadata.json',
      parameters: { scope: 'atproto', login_hint: null, prompt: 'none' },
    }],
  ])

  const provider = {
    issuer: 'https://pds.kelosocial.eu',
    deviceManager: {
      async hasSession(req) {
        const cookie = String(req.headers.cookie || '')
        return cookie.includes('dev-id=') && cookie.includes('ses-id=')
      },
      async load(req, res) {
        const cookie = String(req.headers.cookie || '')
        const deviceId = cookie.includes('dev-id=device-2') ? 'device-2' : 'device-1'
        if (!cookie.includes('dev-id=')) {
          res.append('Set-Cookie', 'dev-id=device-1; Path=/; HttpOnly; Secure; SameSite=Lax')
          res.append('Set-Cookie', 'ses-id=session-1; Path=/; HttpOnly; Secure; SameSite=Lax')
        }
        return { deviceId, deviceMetadata: { userAgent: 'test', ipAddress: '127.0.0.1' } }
      },
    },
    requestManager: {
      async get(requestUri, deviceId, clientId) {
        const entry = requestParameters.get(requestUri)
        if (!entry || entry.clientId !== clientId) throw new Error('Invalid OAuth request')
        const bound = requestBindings.get(requestUri)
        if (bound && bound !== deviceId) throw new Error('OAuth request belongs to another device')
        requestBindings.set(requestUri, deviceId)
        return { requestUri, clientId, parameters: entry.parameters }
      },
    },
    accountManager: {
      async listDeviceAccounts(deviceId) {
        const did = linkedAccounts.get(deviceId)
        return did ? [{ account: { sub: did } }] : []
      },
      async upsertDeviceAccount(deviceId, did) {
        linkedAccounts.set(deviceId, did)
      },
      async getDeviceAccount(deviceId, did) {
        return linkedAccounts.get(deviceId) === did ? { deviceId, account: { sub: did } } : null
      },
    },
    clientManager: {
      async getClient(clientId) {
        return { id: clientId, metadata: { client_name: 'Application de test' } }
      },
    },
  }

  const ctx = {
    oauthProvider: provider,
    accountManager: {
      async getAccount(did) {
        return did === 'did:plc:alice' ? { did, handle: 'alice.kelosocial.eu' } : null
      },
    },
  }

  const app = express()
  app.use(createRouter(ctx))
  app.get('/oauth/authorize', (_req, res) => res.status(200).send('UPSTREAM_OAUTH'))
  const server = app.listen(0, '127.0.0.1')
  await new Promise((resolve) => server.once('listening', resolve))
  const address = server.address()
  const base = 'http://127.0.0.1:' + address.port
  const browserCookie = 'dev-id=device-1; ses-id=session-1'
  const secondDeviceCookie = 'dev-id=device-2; ses-id=session-2'
  const apiHeaders = { Authorization: 'Bearer ' + process.env.PDS_KELO_ID_API_KEY }
  const navHeaders = {
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Site': 'cross-site',
  }

  async function get(pathname, options = {}) {
    return fetch(base + pathname, { ...options, redirect: 'manual' })
  }
  function tokenFromHtml(html) {
    const match = html.match(/status\?challenge=([A-Za-z0-9_-]{43})/)
    assert.ok(match, 'OAuth page must contain a one-time QR challenge')
    return match[1]
  }

  try {
    const firstPage = await get(
      '/oauth/authorize?client_id=' + encodeURIComponent('https://client.example/metadata.json') +
      '&request_uri=' + encodeURIComponent('urn:ietf:params:oauth:request_uri:first'),
      { headers: navHeaders },
    )
    assert.equal(firstPage.status, 200)
    const firstHtml = await firstPage.text()
    assert.match(firstHtml, /Application de test/)
    assert.match(firstHtml, /Utiliser mon identifiant et mon mot de passe/)
    const firstToken = tokenFromHtml(firstHtml)

    const details = await get(
      '/kelo-id/oauth/qr?challenge=' + firstToken + '&did=did%3Aplc%3Aalice',
      { headers: apiHeaders },
    )
    assert.equal(details.status, 200)
    const detailsJson = await details.json()
    assert.equal(detailsJson.purpose, 'kelo_pds_oauth')
    assert.equal(detailsJson.clientName, 'Application de test')
    assert.equal(detailsJson.scope, 'atproto repo')

    const approval = await get('/kelo-id/oauth/qr/approve', {
      method: 'POST',
      headers: { ...apiHeaders, 'Content-Type': 'application/json' },
      body: JSON.stringify({ challenge: firstToken, did: 'did:plc:alice', action: 'approve' }),
    })
    assert.equal(approval.status, 200)
    assert.equal((await approval.json()).approved, true)
    assert.equal(linkedAccounts.get('device-1'), 'did:plc:alice')

    const replay = await get('/kelo-id/oauth/qr/approve', {
      method: 'POST',
      headers: { ...apiHeaders, 'Content-Type': 'application/json' },
      body: JSON.stringify({ challenge: firstToken, did: 'did:plc:other', action: 'approve' }),
    })
    assert.equal(replay.status, 409, 'A second DID must not reuse an approved QR')

    const status = await get('/kelo-id/oauth/qr/status?challenge=' + firstToken, {
      headers: { Cookie: browserCookie },
    })
    assert.equal(status.status, 200)
    assert.equal((await status.json()).status, 'approved')

    const wrongDevice = await get('/kelo-id/oauth/qr/status?challenge=' + firstToken, {
      headers: { Cookie: secondDeviceCookie },
    })
    assert.equal(wrongDevice.status, 403, 'The QR status must be bound to its original browser')

    const resume = await get('/kelo-id/oauth/continue?mode=resume&challenge=' + firstToken, {
      headers: { Cookie: browserCookie },
    })
    assert.equal(resume.status, 303)
    assert.match(resume.headers.get('location'), /\/oauth\/authorize\?/)
    const bypassCookie = (resume.headers.get('set-cookie') || '').match(/kelo-oauth-bypass=([^;]+)/)
    assert.ok(bypassCookie, 'OAuth resume must set a short-lived one-time bypass cookie')

    const resumed = await get(
      '/oauth/authorize?client_id=' + encodeURIComponent('https://client.example/metadata.json') +
      '&request_uri=' + encodeURIComponent('urn:ietf:params:oauth:request_uri:first'),
      { headers: { ...navHeaders, Cookie: browserCookie + '; kelo-oauth-bypass=' + bypassCookie[1] } },
    )
    assert.equal(resumed.status, 200)
    assert.equal(await resumed.text(), 'UPSTREAM_OAUTH')

    const classicPage = await get(
      '/oauth/authorize?client_id=' + encodeURIComponent('https://client.example/metadata.json') +
      '&request_uri=' + encodeURIComponent('urn:ietf:params:oauth:request_uri:classic'),
      { headers: { ...navHeaders, Cookie: secondDeviceCookie } },
    )
    assert.equal(classicPage.status, 200)
    const classicToken = tokenFromHtml(await classicPage.text())
    const classicContinue = await get('/kelo-id/oauth/continue?mode=classic&challenge=' + classicToken, {
      headers: { Cookie: secondDeviceCookie },
    })
    assert.equal(classicContinue.status, 303)
    const classicBypass = (classicContinue.headers.get('set-cookie') || '').match(/kelo-oauth-bypass=([^;]+)/)
    assert.ok(classicBypass)
    const classicUpstream = await get(
      '/oauth/authorize?client_id=' + encodeURIComponent('https://client.example/metadata.json') +
      '&request_uri=' + encodeURIComponent('urn:ietf:params:oauth:request_uri:classic'),
      { headers: { ...navHeaders, Cookie: secondDeviceCookie + '; kelo-oauth-bypass=' + classicBypass[1] } },
    )
    assert.equal(await classicUpstream.text(), 'UPSTREAM_OAUTH')

    const silent = await get(
      '/oauth/authorize?client_id=' + encodeURIComponent('https://client.example/metadata.json') +
      '&request_uri=' + encodeURIComponent('urn:ietf:params:oauth:request_uri:silent'),
      { headers: { ...navHeaders, Cookie: secondDeviceCookie } },
    )
    assert.equal(await silent.text(), 'UPSTREAM_OAUTH', 'prompt=none must keep the native OAuth behavior')

    console.log('Kelo PDS OAuth QR integration tests passed')
  } finally {
    await new Promise((resolve) => server.close(resolve))
    await fs.rm(dataDirectory, { recursive: true, force: true })
  }
}

run().catch((error) => {
  console.error(error)
  process.exitCode = 1
})
