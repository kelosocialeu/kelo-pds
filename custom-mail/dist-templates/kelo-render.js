const fs = require('fs')
const path = require('path')
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))
module.exports = function make(file) {
  const html = fs.readFileSync(path.join(__dirname, file), 'utf8')
  const render = (data) => html.replace(/\{\{\s*(\w+)\s*\}\}/g, (_, k) => esc(data && data[k] != null ? data[k] : ''))
  render.default = render
  render.__esModule = true
  return render
}
