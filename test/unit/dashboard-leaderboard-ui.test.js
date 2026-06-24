import test from 'brittle'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'

const leaderboard = readFileSync('dashboard/leaderboard.html', 'utf8')

test('leaderboard rows escape relay metadata and avoid inline copy handlers', (t) => {
  const out = renderRows([{
    relay: 'abc" onclick="alert(1)"><script>alert(2)</script>',
    score: '<img src=x onerror=alert(3)>',
    reliability: '50%" onmouseover="alert(4)',
    avgLatencyMs: '<svg onload=alert(5)>',
    uptimeHours: '<script>alert(6)</script>',
    bytesServed: '<img src=x onerror=alert(7)>',
    region: '</span><img src=x onerror=alert(8)>',
    totalChallenges: '<svg onload=alert(9)>'
  }])

  t.ok(out.html.includes('data-copy-pubkey="abc&quot; onclick=&quot;alert(1)&quot;&gt;&lt;script&gt;alert(2)&lt;/script&gt;"'))
  t.ok(out.html.includes('<button class="copy-btn" type="button" data-copy-pubkey='))
  t.ok(out.html.includes('abc&quot; onc.../script&gt;'))
  t.ok(out.html.includes('<td class="mono score-low">0.0</td>'))
  t.ok(out.html.includes('width:0%;background:'))
  t.ok(out.html.includes('0.0%</span>'))
  t.ok(out.html.includes('0 ms</td>'))
  t.ok(out.html.includes('<td class="mono">0h</td>'))
  t.ok(out.html.includes('<td class="mono">0 B</td>'))
  t.ok(out.html.includes('&lt;/span&gt;&lt;img src=x onerror=alert(8)&gt;'))
  t.absent(out.html.includes('onclick="'))
  t.absent(out.html.includes("onclick='"))
  t.absent(out.html.includes('<script>'))
  t.absent(out.html.includes('<img'))
  t.absent(out.html.includes('<svg'))
  t.alike(out.innerHTMLAssignments, [])
})

test('leaderboard normalization clamps percentages and preserves safe percent strings', (t) => {
  const relay = normalizeRelay({
    pubkey: 'relay-1',
    score: '88.5',
    reliability: '150%',
    avg_latency: '42',
    uptime_hours: '24',
    bytes_served: '2048',
    region: 'EU',
    challenge_count: '7'
  })

  t.is(relay.score, 88.5)
  t.is(relay.reliability, 100)
  t.is(relay.avgLatency, 42)
  t.is(relay.uptimeHours, 24)
  t.is(relay.bytesServed, 2048)
  t.is(relay.challenges, 7)
})

test('leaderboard copy control tolerates missing or rejected clipboard writes', async (t) => {
  const source = [
    extractFunction('showToast'),
    extractFunction('writeClipboard'),
    extractFunction('copyText'),
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
      copyText('relay-pubkey')
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
      copyText('relay-pubkey')
      await Promise.resolve()
      await Promise.resolve()
      results.rejected = toast.textContent

      globalThis.navigator.clipboard.writeText = function (text) {
        writes.push(text)
        return Promise.resolve()
      }
      copyText('relay-pubkey-2')
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
  t.is(out.success.toast, 'Copied!')
  t.is(out.success.writes.join(','), 'relay-pubkey,relay-pubkey-2')
  t.is(out.success.timers, 3)
})

function renderRows (rows) {
  const elements = {}
  const source = [
    'var relays = ' + JSON.stringify(rows) + '.map(normalizeRelay)',
    'var myPubkey = ""',
    'var sortCol = "rank"',
    'var sortAsc = true',
    'var regionFlags = {}',
    extractFunction('formatBytes'),
    extractFunction('formatUptime'),
    extractFunction('formatRelativeTime'),
    extractFunction('truncatePubkey'),
    extractFunction('metricNumber'),
    extractFunction('clampPercent'),
    extractFunction('regionFlag'),
    extractFunction('scoreClass'),
    extractFunction('latencyClass'),
    extractFunction('reliabilityColor'),
    extractFunction('clearNode'),
    extractFunction('makeEl'),
    extractFunction('appendEl'),
    extractFunction('writeClipboard'),
    extractFunction('copyText'),
    extractFunction('bindLeaderboardActions'),
    extractFunction('normalizeRelay'),
    extractFunction('getValue'),
    extractFunction('sortRelays'),
    extractFunction('renderRelayRow'),
    extractFunction('render'),
    'render()',
    'JSON.stringify({ html: document.getElementById("leaderboardBody").innerHTML, innerHTMLAssignments: document._innerHTMLAssignments() })'
  ].join('\n')
  return JSON.parse(vm.runInNewContext(source, context(elements)))
}

function normalizeRelay (row) {
  const source = [
    extractFunction('metricNumber'),
    extractFunction('clampPercent'),
    extractFunction('normalizeRelay'),
    'normalizeRelay(' + JSON.stringify(row) + ')'
  ].join('\n')
  return vm.runInNewContext(source, context({}))
}

function context (elements) {
  return {
    Math,
    Number,
    String,
    Date,
    isNaN,
    navigator: {},
    document: {
      _innerHTMLAssignments () {
        return Object.values(elements).flatMap(function (el) {
          return el.innerHTMLAssignments()
        })
      },
      createElement (tag) {
        return new FakeElement(tag)
      },
      getElementById (id) {
        if (!elements[id]) {
          elements[id] = new FakeElement(id === 'leaderboardBody' ? 'tbody' : 'div')
        }
        return elements[id]
      },
      querySelector (selector) {
        if (selector === '#tableContainer table') {
          if (!elements.__table) elements.__table = new FakeElement('table')
          return elements.__table
        }
        return null
      },
      querySelectorAll () {
        return []
      }
    }
  }
}

function extractFunction (name) {
  const start = leaderboard.indexOf('function ' + name + '(')
  if (start === -1) throw new Error('missing function ' + name)
  const firstBrace = leaderboard.indexOf('{', start)
  let depth = 0
  for (let i = firstBrace; i < leaderboard.length; i++) {
    const char = leaderboard[i]
    if (char === '{') depth++
    else if (char === '}') {
      depth--
      if (depth === 0) return leaderboard.slice(start, i + 1)
    }
  }
  throw new Error('unterminated function ' + name)
}

class FakeElement {
  constructor (tag) {
    this.tag = String(tag || 'div').toLowerCase()
    this.children = []
    this.parentNode = null
    this.dataset = {}
    this.style = {}
    this._text = ''
    this._className = ''
    this._type = ''
    this._innerHTMLAssignments = []
    this.classList = {
      add: () => {},
      remove: () => {}
    }
  }

  set className (value) {
    this._className = value ? String(value) : ''
  }

  get className () {
    return this._className
  }

  set type (value) {
    this._type = value ? String(value) : ''
  }

  get type () {
    return this._type
  }

  set textContent (value) {
    this.children = []
    this._text = value === null || value === undefined ? '' : String(value)
  }

  get textContent () {
    return this._text + this.children.map(function (child) {
      return child.textContent
    }).join('')
  }

  set innerHTML (value) {
    this._innerHTMLAssignments.push(String(value))
    this.children = []
    this._text = ''
  }

  get innerHTML () {
    return escapeFixtureHtml(this._text) + this.children.map(function (child) {
      return child.outerHTML
    }).join('')
  }

  get outerHTML () {
    const attrs = []
    if (this._className) attrs.push('class="' + escapeFixtureHtml(this._className) + '"')
    if (this._type) attrs.push('type="' + escapeFixtureHtml(this._type) + '"')
    for (const [key, value] of Object.entries(this.dataset)) {
      attrs.push(dataAttrName(key) + '="' + escapeFixtureHtml(value) + '"')
    }
    const style = Object.entries(this.style).filter((entry) => entry[1] !== undefined && entry[1] !== '')
    if (style.length) {
      attrs.push('style="' + style.map(function ([key, value]) {
        return cssName(key) + ':' + escapeFixtureHtml(value)
      }).join(';') + '"')
    }
    return '<' + this.tag + (attrs.length ? ' ' + attrs.join(' ') : '') + '>' + this.innerHTML + '</' + this.tag + '>'
  }

  get firstChild () {
    return this.children[0] || null
  }

  appendChild (child) {
    this.children.push(child)
    child.parentNode = this
    return child
  }

  removeChild (child) {
    const index = this.children.indexOf(child)
    if (index !== -1) this.children.splice(index, 1)
    child.parentNode = null
    return child
  }

  addEventListener () {}

  contains (node) {
    return node === this || this.children.includes(node)
  }

  querySelector () {
    return new FakeElement('span')
  }

  innerHTMLAssignments () {
    return this._innerHTMLAssignments.concat(this.children.flatMap(function (child) {
      return child.innerHTMLAssignments()
    }))
  }
}

function dataAttrName (key) {
  return 'data-' + String(key).replace(/[A-Z]/g, function (ch) {
    return '-' + ch.toLowerCase()
  })
}

function cssName (key) {
  return String(key).replace(/[A-Z]/g, function (ch) {
    return '-' + ch.toLowerCase()
  })
}

function escapeFixtureHtml (value) {
  return String(value).replace(/[&<>"']/g, function (ch) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]
  })
}
