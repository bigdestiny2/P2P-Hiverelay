import test from 'brittle'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'

const catalog = readFileSync('dashboard/catalog.html', 'utf8')

test('catalog literal controls avoid submit-default buttons', (t) => {
  const buttons = catalog.match(/<button\b[^>]*>/g) || []
  const literalControls = buttons.filter(tag => !tag.includes('copy-key-btn'))

  t.ok(literalControls.length >= 8, 'catalog exposes filter and pagination controls')
  t.ok(literalControls.every(tag => /\btype="button"/.test(tag)), 'literal controls are explicit buttons')
  t.absent(literalControls.find(tag => !/\btype="button"/.test(tag)))
})

test('catalog cards render untrusted metadata as DOM text and avoid inline copy handlers', (t) => {
  const created = []
  const item = {
    type: 'app" onclick="alert(1)',
    name: '<img src=x onerror=alert(1)>',
    description: '<svg onload=alert(2)>',
    author: '<script>alert(3)</script>',
    categories: ['</span><img src=x onerror=alert(4)>'],
    appKey: 'abc" onclick="alert(5)"><script>alert(6)</script>'
  }
  const script = [
    extractFunction('normalizeCatalogType'),
    extractFunction('catalogCategories'),
    extractFunction('makeEl'),
    extractFunction('appendEl'),
    extractFunction('renderCard'),
    'var card = renderCard(' + JSON.stringify(item) + ')',
    'JSON.stringify({ html: card.outerHTML, assignments: card.innerHTMLAssignments, children: card.children.length })'
  ].join('\n')
  const rendered = JSON.parse(vm.runInNewContext(script, {
    JSON,
    encodeURIComponent,
    copyToClipboard: () => {},
    document: {
      createElement: (tag) => {
        const el = new FakeElement(tag)
        created.push(el)
        return el
      }
    }
  }))

  const html = rendered.html
  t.ok(html.includes('type-resource'), 'unknown catalog type falls back to a safe class')
  t.ok(html.includes('&lt;img src=x onerror=alert(1)&gt;'))
  t.ok(html.includes('&lt;svg onload=alert(2)&gt;'))
  t.ok(html.includes('&lt;script&gt;alert(3)&lt;/script&gt;'))
  t.ok(html.includes('&lt;/span&gt;&lt;img src=x onerror=alert(4)&gt;'))
  t.ok(html.includes('href="/v1/hyper/abc%22%20onclick%3D%22alert(5)%22%3E%3Cscript%3Ealert(6)%3C%2Fscript%3E/"'))
  t.ok(html.includes('<button'))
  t.ok(html.includes('type="button"'))
  t.ok(html.includes('class="btn btn-secondary copy-key-btn"'))
  t.absent(html.includes('onclick="'))
  t.absent(html.includes('copyToClipboard('))
  t.absent(html.includes('<script>'))
  t.absent(html.includes('<img'))
  t.absent(html.includes('<svg'))
  t.ok(html.includes('target="_blank"'))
  t.ok(html.includes('rel="noopener noreferrer"'))
  t.alike(rendered.assignments, [])
  t.ok(rendered.children > 0)
  t.ok(created.every(el => el.innerHTMLAssignments.length === 0))
})

test('catalog grid uses DOM rendering and tolerates malformed category metadata', (t) => {
  const applyFilter = extractFunction('applyFilter')
  const renderGrid = extractFunction('renderGrid')
  const renderCard = extractFunction('renderCard')

  t.absent(renderGrid.includes('grid.innerHTML'))
  t.ok(renderGrid.includes('grid.appendChild(renderCard(item))'))
  t.ok(renderGrid.includes('renderEmptyState(grid'))
  t.ok(renderCard.includes("browse.rel = 'noopener noreferrer'"))
  t.ok(applyFilter.includes('...catalogCategories(item.categories)'))

  const script = [
    extractFunction('catalogCategories'),
    'JSON.stringify({ string: catalogCategories("not-array"), mixed: catalogCategories(["ok", 7, null, undefined, "<x>"]) })'
  ].join('\n')
  const out = JSON.parse(vm.runInNewContext(script, { JSON }))
  t.alike(out.string, [])
  t.alike(out.mixed, ['ok', '7', '<x>'])
})

test('catalog copy controls tolerate missing or rejected clipboard writes', async (t) => {
  const source = [
    extractFunction('showCopyToast'),
    extractFunction('copyToClipboard'),
    `
    (async function () {
      var toast = {
        textContent: '',
        classList: {
          added: [],
          removed: [],
          add: function (name) { this.added.push(name) },
          remove: function (name) { this.removed.push(name) }
        }
      }
      globalThis.document = {
        getElementById: function () { return toast }
      }
      var timers = []
      globalThis.setTimeout = function (fn) { timers.push(fn); return timers.length }
      var results = {}

      delete globalThis.navigator
      copyToClipboard('catalog-key')
      results.noClipboard = toast.textContent

      var writes = []
      globalThis.navigator = {
        clipboard: {
          writeText: function (text) {
            writes.push(text)
            return Promise.reject(new Error('denied'))
          }
        }
      }
      copyToClipboard('catalog-key')
      await Promise.resolve()
      await Promise.resolve()
      results.rejected = toast.textContent

      globalThis.navigator.clipboard.writeText = function (text) {
        writes.push(text)
        return Promise.resolve()
      }
      copyToClipboard('catalog-key-2')
      await Promise.resolve()
      await Promise.resolve()
      results.success = {
        toast: toast.textContent,
        writes: writes,
        timers: timers.length
      }
      return results
    })()
    `
  ].join('\n')

  const out = await vm.runInNewContext(source, { Promise, Error })

  t.is(out.noClipboard, 'Clipboard unavailable')
  t.is(out.rejected, 'Copy failed')
  t.is(out.success.toast, 'Copied to clipboard!')
  t.is(out.success.writes.join(','), 'catalog-key,catalog-key-2')
  t.is(out.success.timers, 3)
})

function extractFunction (name) {
  const start = catalog.indexOf('function ' + name + ' ')
  if (start === -1) throw new Error('missing function ' + name)
  const firstBrace = catalog.indexOf('{', start)
  let depth = 0
  for (let i = firstBrace; i < catalog.length; i++) {
    const char = catalog[i]
    if (char === '{') depth++
    else if (char === '}') {
      depth--
      if (depth === 0) return catalog.slice(start, i + 1)
    }
  }
  throw new Error('unterminated function ' + name)
}

class FakeElement {
  constructor (tag) {
    this.tag = tag
    this.children = []
    this.dataset = {}
    this.className = ''
    this._text = ''
    this.innerHTMLAssignments = []
    this.listeners = []
  }

  appendChild (child) {
    this.children.push(child)
    return child
  }

  removeChild (child) {
    const idx = this.children.indexOf(child)
    if (idx !== -1) this.children.splice(idx, 1)
    return child
  }

  get firstChild () {
    return this.children[0] || null
  }

  addEventListener (type, fn) {
    this.listeners.push({ type, fn })
  }

  set textContent (value) {
    this.children = []
    this._text = String(value)
  }

  get textContent () {
    return this._text + this.children.map(child => child.textContent).join('')
  }

  set innerHTML (value) {
    this.innerHTMLAssignments.push(String(value))
    this.children = []
    this._text = String(value)
  }

  get innerHTML () {
    return escapeFixtureHtml(this._text) + this.children.map(child => child.outerHTML).join('')
  }

  get outerHTML () {
    const attrs = []
    if (this.className) attrs.push(['class', this.className])
    for (const name of ['href', 'target', 'rel', 'title', 'type']) {
      if (this[name]) attrs.push([name, this[name]])
    }
    for (const [key, value] of Object.entries(this.dataset)) {
      attrs.push(['data-' + key.replace(/[A-Z]/g, c => '-' + c.toLowerCase()), value])
    }
    const attrText = attrs.map(([key, value]) => ' ' + key + '="' + escapeFixtureHtml(value) + '"').join('')
    return '<' + this.tag + attrText + '>' + this.innerHTML + '</' + this.tag + '>'
  }
}

function escapeFixtureHtml (value) {
  return String(value).replace(/[&<>"']/g, ch => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[ch]))
}
