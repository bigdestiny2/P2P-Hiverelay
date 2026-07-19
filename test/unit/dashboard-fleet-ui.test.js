import test from 'brittle'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'

const fleet = readFileSync('dashboard/fleet.html', 'utf8')

test('fleet dashboard: surface, auth, and privacy constraints', (t) => {
  t.ok(fleet.includes('id="fleetGrid"'), 'peer grid')
  t.ok(fleet.includes('id="sumPeers"'), 'summary peers')
  t.ok(fleet.includes('id="sumUp"'), 'summary up')
  t.ok(fleet.includes('id="sumDown"'), 'summary down')
  t.ok(fleet.includes("fetchWithTimeout('/api/fleet'"), 'polls /api/fleet')
  t.ok(fleet.includes('Authorization'), 'sends bearer when UI token present')
  t.ok(fleet.includes('never merges private Tor'), 'copy states no private Tor')
  t.ok(fleet.includes('config.fleet.peers'), 'documents peer config')
  t.ok(fleet.includes('function escapeHtml'), 'escapes untrusted peer labels')
  t.ok(fleet.includes('document.hidden'), 'pauses while tab hidden')
  t.ok(fleet.includes("document.addEventListener('visibilitychange'"), 'resumes on visible')
  t.ok(fleet.includes('AbortController'), 'timeout-bounded fetch')
  t.absent(fleet.includes('/ws?token='), 'no token in WS URL')
  t.absent(fleet.includes('onionAddress'), 'UI does not reference onion fields')
})

test('fleet dashboard: render escapes peer labels and errors', (t) => {
  const start = fleet.indexOf('function render (payload)')
  t.ok(start > 0, 'render function present')
  // Extract render + helpers needed
  function extract (name) {
    const s = fleet.indexOf('function ' + name)
    if (s < 0) throw new Error('missing ' + name)
    const brace = fleet.indexOf('{', s)
    let depth = 0
    for (let i = brace; i < fleet.length; i++) {
      if (fleet[i] === '{') depth++
      else if (fleet[i] === '}') {
        depth--
        if (depth === 0) return fleet.slice(s, i + 1)
      }
    }
    throw new Error('unterminated ' + name)
  }

  const elements = {}
  class FakeEl {
    constructor () {
      this._text = ''
      this.className = ''
      this.innerHTML = ''
    }

    set textContent (v) { this._text = String(v) }
    get textContent () { return this._text }
  }

  const source = [
    extract('escapeHtml'),
    extract('formatBytes'),
    extract('formatUptime'),
    extract('setText'),
    extract('render'),
    `
    render({
      summary: { peerCount: 1, up: 0, down: 1, diskWarn: 0, diskCritical: 0, privacyDegraded: 0, updatedAt: 1000 },
      peers: [{
        id: 'x',
        label: '<img src=x onerror=alert(1)>',
        region: '<svg onload=alert(2)>',
        up: false,
        publicKey: 'abc" onclick="alert(3)',
        errors: [{ endpoint: 'poll', error: '<script>alert(4)</script>' }],
        privacyTransports: [{ health: 'ready' }]
      }]
    });
    JSON.stringify({
      grid: document.getElementById('fleetGrid').innerHTML,
      peers: document.getElementById('sumPeers').textContent
    })
    `
  ].join('\n')

  const out = JSON.parse(vm.runInNewContext(source, {
    String,
    Number,
    Array,
    Math,
    isFinite,
    Date,
    document: {
      getElementById (id) {
        if (!elements[id]) elements[id] = new FakeEl()
        return elements[id]
      }
    }
  }))

  t.is(out.peers, '1')
  t.ok(out.grid.includes('&lt;img src=x onerror=alert(1)&gt;'))
  t.ok(out.grid.includes('&lt;svg onload=alert(2)&gt;'))
  t.ok(out.grid.includes('&lt;script&gt;alert(4)&lt;/script&gt;'))
  t.absent(out.grid.includes('<img'))
  t.absent(out.grid.includes('<script>'))
  t.absent(out.grid.includes('<svg'))
  t.absent(out.grid.includes('onclick="'))
})
