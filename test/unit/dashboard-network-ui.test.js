import test from 'brittle'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'

const network = readFileSync('dashboard/network.html', 'utf8')

test('network relay cards render untrusted relay data as DOM text and avoid inline handlers', (t) => {
  const rendered = renderRelayCard({
    _online: true,
    _name: '<img src=x onerror=alert(1)>',
    _region: '<svg onload=alert(2)>',
    _url: 'https://relay.example:9100/base?token=secret#frag',
    publicKey: 'abc" onclick="alert(3)"><script>alert(4)</script>',
    connections: '<img src=x onerror=alert(5)>',
    seededApps: '<script>alert(6)</script>',
    relay: { totalBytesRelayed: 1024, totalCircuitsServed: '<svg onload=alert(7)>' },
    tor: { running: true, onionAddress: '<script>alert(8)</script>.onion' }
  })
  const html = rendered.html

  t.ok(html.includes('&lt;img src=x onerror=alert(1)&gt;'))
  t.ok(html.includes('&lt;svg onload=alert(2)&gt;'))
  t.ok(html.includes('data-network-action="copy-pubkey"'))
  t.ok(html.includes('data-network-action="connect"'))
  t.ok(html.includes('data-public-key="abc&quot; onclick=&quot;alert(3)&quot;&gt;&lt;script&gt;alert(4)&lt;/script&gt;"'))
  t.ok(html.includes('href="https://relay.example:9100/base/dashboard" target="_blank" rel="noopener noreferrer"'))
  t.ok(html.includes('href="https://relay.example:9100/base/api/overview" target="_blank" rel="noopener noreferrer"'))
  t.ok(html.includes('&lt;script&gt;alert(8)...'))
  t.ok((html.match(/<div class="relay-stat-val">0<\/div>/g) || []).length >= 2, 'malformed counters normalize to zero')
  t.absent(html.includes('onclick="'))
  t.absent(html.includes("onclick='"))
  t.absent(html.includes('<script>'))
  t.absent(html.includes('<img'))
  t.absent(html.includes('<svg'))
  t.alike(rendered.innerHTMLAssignments, [])
})

test('network relay cards disable unsafe relay links', (t) => {
  const rendered = renderRelayCard({
    _online: true,
    _name: 'Bad URL Relay',
    _region: 'unknown',
    _url: 'javascript:alert(1)',
    publicKey: 'abc'
  })
  const html = rendered.html

  t.absent(html.includes('href="javascript:'))
  t.ok(html.includes('<button class="btn" type="button" disabled>Dashboard</button>'))
  t.ok(html.includes('<button class="btn" type="button" disabled>API</button>'))
  t.ok(html.includes('data-relay-url=""'))
  t.alike(rendered.innerHTMLAssignments, [])
})

test('network grid uses DOM rendering for relay cards and empty state', (t) => {
  const renderNetworkBody = extractFunction('renderNetwork')

  t.absent(renderNetworkBody.includes('grid.innerHTML'))
  t.ok(renderNetworkBody.includes('clearNode(grid)'))
  t.ok(renderNetworkBody.includes('grid.appendChild(renderRelayCard(result))'))
  t.ok(renderNetworkBody.includes('document.createTextNode'))
})

test('network dashboard requests detailed state with token and falls back to public state', (t) => {
  const refreshBody = extractFunction('refresh')
  const renderNetworkBody = extractFunction('renderNetwork')

  t.ok(refreshBody.includes("fetchWithTimeout('/api/network?detailed=1'"), 'tries detailed network state first')
  t.ok(refreshBody.includes("detailedHeaders.Authorization = 'Bearer ' + token"), 'attaches dashboard token when present')
  t.ok(refreshBody.includes("fetchWithTimeout('/api/network'"), 'falls back to public network state')
  t.absent(refreshBody.includes('AbortSignal.timeout'), 'does not require AbortSignal.timeout support')
  t.ok(renderNetworkBody.includes('r.apiPort != null || r.apiReachable === true'), 'filter tolerates redacted public API availability')
})

test('network copy controls tolerate missing or rejected clipboard writes', async (t) => {
  const source = [
    extractFunction('showToast'),
    extractFunction('writeClipboard'),
    extractFunction('copyText'),
    extractFunction('copyPubkey'),
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
      var copyEl = {
        textContent: 'fallback copy text click to copy',
        getAttribute: function (name) { return name === 'data-copy' ? 'relay-key' : '' }
      }
      var timers = []
      globalThis.setTimeout = function (fn) { timers.push(fn); return timers.length }
      var results = {}

      delete globalThis.navigator
      copyText(copyEl)
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
      copyText(copyEl)
      await Promise.resolve()
      await Promise.resolve()
      results.rejected = toast.textContent

      var hint = { textContent: 'click to copy' }
      var classList = {
        added: [],
        removed: [],
        add: function (name) { this.added.push(name) },
        remove: function (name) { this.removed.push(name) }
      }
      globalThis.navigator.clipboard.writeText = function (text) {
        writes.push(text)
        return Promise.resolve()
      }
      copyPubkey({
        classList: classList,
        querySelector: function (selector) { return selector === '.copy-hint' ? hint : null }
      }, 'pubkey-123')
      await Promise.resolve()
      await Promise.resolve()
      results.success = {
        toast: toast.textContent,
        writes: writes,
        hint: hint.textContent,
        added: classList.added,
        removed: classList.removed,
        timers: timers.length
      }
      return results
    })()
    `
  ].join('\n')

  const out = await vm.runInNewContext(source, { Promise, Error })

  t.is(out.noClipboard, 'Clipboard unavailable')
  t.is(out.rejected, 'Copy failed')
  t.is(out.success.writes.join(','), 'relay-key,pubkey-123')
  t.is(out.success.added.join(','), 'copied')
  t.is(out.success.removed.length, 0)
  t.is(out.success.hint, 'copied!')
  t.is(out.success.toast, 'Public key copied!')
  t.is(out.success.timers, 4)
})

function renderRelayCard (data) {
  const created = []
  const source = [
    extractFunction('formatBytes'),
    extractFunction('formatUptime'),
    extractFunction('metricCount'),
    extractFunction('truncKey'),
    extractFunction('escapeHtml'),
    extractFunction('makeEl'),
    extractFunction('appendEl'),
    extractFunction('safeHttpUrl'),
    extractFunction('renderRelayCard'),
    'var card = renderRelayCard(' + JSON.stringify(data) + '); JSON.stringify({ html: card.outerHTML, innerHTMLAssignments: created.flatMap(function(el) { return el.innerHTMLAssignments }) })'
  ].join('\n')
  return JSON.parse(vm.runInNewContext(source, {
    created,
    document: {
      createElement (tag) {
        const el = new FakeElement(tag)
        created.push(el)
        return el
      }
    },
    Math,
    Number,
    String,
    URL,
    isNaN
  }))
}

function extractFunction (name) {
  const start = network.indexOf('function ' + name)
  if (start === -1) throw new Error('missing function ' + name)
  const firstBrace = network.indexOf('{', start)
  let depth = 0
  for (let i = firstBrace; i < network.length; i++) {
    const char = network[i]
    if (char === '{') depth++
    else if (char === '}') {
      depth--
      if (depth === 0) return network.slice(start, i + 1)
    }
  }
  throw new Error('unterminated function ' + name)
}

class FakeElement {
  constructor (tag) {
    this.tag = String(tag).toLowerCase()
    this.children = []
    this.dataset = {}
    this.style = {}
    this.innerHTMLAssignments = []
    this._text = ''
    this.className = ''
    this.href = ''
    this.target = ''
    this.rel = ''
    this.type = ''
    this.disabled = false
  }

  appendChild (child) {
    this.children.push(child)
    return child
  }

  set textContent (value) {
    this._text = String(value)
    this.children = []
  }

  get textContent () {
    return this._text
  }

  set innerHTML (value) {
    this.innerHTMLAssignments.push(String(value))
  }

  get innerHTML () {
    return escapeFixtureHtml(this._text) + this.children.map(child => child.outerHTML).join('')
  }

  get outerHTML () {
    const attrs = []
    if (this.className) attrs.push(['class', this.className])
    if (this.href) attrs.push(['href', this.href])
    if (this.target) attrs.push(['target', this.target])
    if (this.rel) attrs.push(['rel', this.rel])
    if (this.type) attrs.push(['type', this.type])
    for (const [key, value] of Object.entries(this.dataset)) {
      attrs.push(['data-' + key.replace(/[A-Z]/g, c => '-' + c.toLowerCase()), value])
    }
    const styleText = Object.entries(this.style)
      .map(([key, value]) => key.replace(/[A-Z]/g, c => '-' + c.toLowerCase()) + ':' + value)
      .join(';')
    if (styleText) attrs.push(['style', styleText])
    const attrText = attrs.map(([key, value]) => ' ' + key + '="' + escapeFixtureHtml(value) + '"').join('') +
      (this.disabled ? ' disabled' : '')
    return '<' + this.tag + attrText + '>' + this.innerHTML + '</' + this.tag + '>'
  }
}

function escapeFixtureHtml (value) {
  return String(value).replace(/[&<>"']/g, (ch) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  }[ch]))
}
