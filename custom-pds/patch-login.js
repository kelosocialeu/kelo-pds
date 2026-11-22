'use strict'

const fs = require('node:fs')
const file = process.argv[2]
if (!file) throw new Error('Usage: node patch-login.js <account-manager.js>')

const source = fs.readFileSync(file, 'utf8')
const target = /const validAccountPass = await this\.verifyAccountPassword\(\s*user\.did,\s*password,?\s*\);/g
const matches = [...source.matchAll(target)]
if (matches.length !== 1) {
  throw new Error('Expected exactly one AccountManager.login password check; found ' + matches.length + '. Refusing to patch unknown PDS build.')
}

const replacement = "const validAccountPass = (await require('./kelo-proof').verifyKeloProof(user.did, password)) || await this.verifyAccountPassword(user.did, password);"
fs.writeFileSync(file, source.replace(target, replacement))
console.log('Kelo ID one-time proof validation installed in AccountManager.login')
