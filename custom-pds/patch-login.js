const fs = require('fs')
const file = process.argv[2]
let src = fs.readFileSync(file, 'utf8')
const target = 'const validAccountPass = await this.verifyAccountPassword(user.did, password);'
const count = src.split(target).length - 1
if (count !== 1) { console.error('Cible introuvable ou multiple :', count); process.exit(1) }
src = src.replace(target, "const validAccountPass = require('./kelo-proof').verifyKeloProof(user.did, password) || await this.verifyAccountPassword(user.did, password);")
fs.writeFileSync(file, src)
console.log('login() patche')
