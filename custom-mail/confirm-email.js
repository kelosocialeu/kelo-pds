// Remplace le template compilé Bluesky : lit le HTML Kelo et insère le code
const fs = require('fs')
const path = require('path')
const html = fs.readFileSync(path.join(__dirname, 'confirm-email.kelo.html'), 'utf8')
function render(data) {
  return html.replace(/\{\{\s*token\s*\}\}/g, () => String((data && data.token) || ''))
}
render.default = render
render.__esModule = true
module.exports = render
