'use strict'

const assert = require('node:assert/strict')
const { execFileSync } = require('node:child_process')
const fs = require('node:fs/promises')
const os = require('node:os')
const path = require('node:path')

async function run() {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'kelo-pds-patches-'))
  try {
    const accountManager = path.join(directory, 'account-manager.js')
    await fs.writeFile(accountManager, [
      'async login() {',
      '  const validAccountPass = await this.verifyAccountPassword(',
      '    user.did,',
      '    password,',
      '  );',
      '}',
    ].join('\n'))

    execFileSync(process.execPath, [path.join(__dirname, 'patch-login.js'), accountManager])
    execFileSync(process.execPath, [path.join(__dirname, 'patch-login.js'), accountManager])
    const accountSource = await fs.readFile(accountManager, 'utf8')
    assert.equal((accountSource.match(/verifyKeloProof/g) || []).length, 1)
    assert.match(accountSource, /verifyKeloProof\(user\.did, password\)/, 'the original password must reach the PDS verifier unchanged')

    const indexFile = path.join(directory, 'index.js')
    await fs.writeFile(indexFile, [
      'const express_1 = require("express");',
      'async function create(ctx) {',
      '  const app = (0, express_1.default)();',
      "  app.set('trust proxy', []);",
      '}',
    ].join('\n'))

    execFileSync(process.execPath, [path.join(__dirname, 'patch-api.js'), indexFile])
    execFileSync(process.execPath, [path.join(__dirname, 'patch-api.js'), indexFile])
    const indexSource = await fs.readFile(indexFile, 'utf8')
    assert.equal((indexSource.match(/Kelo ID proof issuer/g) || []).length, 1)
    assert.match(indexSource, /app\.post\('\/kelo-id\/login-proof'/)
    assert.match(indexSource, /PDS_KELO_ID_API_KEY/)
    assert.match(indexSource, /PDS_JWT_SECRET/)
    assert.match(indexSource, /app\.use\(require\('\.\/kelo-oauth-qr'\)\(ctx\)\)/, 'OAuth QR middleware must be mounted')
    assert.equal((indexSource.match(/kelo-oauth-qr/g) || []).length, 1)
    assert.doesNotMatch(indexSource, /PDS_KELO_ID_PROOF_SECRET/)
  } finally {
    await fs.rm(directory, { recursive: true, force: true })
  }
}

run().then(() => console.log('Kelo PDS patch tests passed')).catch((error) => {
  console.error(error)
  process.exitCode = 1
})
