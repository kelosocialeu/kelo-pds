'use strict'

const assert = require('node:assert/strict')
const { spawnSync } = require('node:child_process')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')

const patchScript = path.resolve(process.argv[2] || path.join(__dirname, 'patch-api.js'))
const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'kelo-patch-api-'))

function runFixture(name, compressionCall, authCall = 'authRoutes.createRouter(ctx)') {
  const target = path.join(tempDir, name + '.js')
  const fixture = [
    "'use strict';",
    'const express = require("express");',
    'const compression_1 = require("./compression");',
    'const authRoutes = require("./auth-routes");',
    'const app = express();',
    'app.use(loggerMiddleware);',
    'app.use(' + compressionCall + ');',
    'app.use(' + authCall + ');',
    'app.use(cors());',
    '',
  ].join('\n')
  fs.writeFileSync(target, fixture)

  for (let i = 0; i < 2; i++) {
    const result = spawnSync(process.execPath, [patchScript, target], { encoding: 'utf8' })
    assert.equal(result.status, 0, result.stderr || result.stdout)
  }

  const patched = fs.readFileSync(target, 'utf8')
  const marker = patched.indexOf('Kelo ID proof issuer. This route is server-to-server only.')
  const compression = patched.indexOf('app.use(' + compressionCall + ');')
  const auth = patched.indexOf('app.use(' + authCall + ');')
  assert.ok(marker > compression, name + ': Kelo middleware must be registered after compression')
  assert.ok(marker < auth, name + ': Kelo middleware must be registered before OAuth/auth routes')
  assert.equal(patched.split('Kelo ID proof issuer. This route is server-to-server only.').length - 1, 1)
}

try {
  runFixture('typescript-commonjs', '(0, compression_1.default)()')
  runFixture('typescript-commonjs-direct', 'compression_1.default()')
  runFixture('typescript-namespace-import', '(0, util_compression_1.default)()', '(0, auth_routes_1.createRouter)(ctx)')
  console.log('Kelo patch-api middleware-order tests passed')
} finally {
  fs.rmSync(tempDir, { recursive: true, force: true })
}
