import test from 'brittle'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'

const dashboard = readFileSync('dashboard/index.html', 'utf8')
const networkDashboard = readFileSync('dashboard/network.html', 'utf8')
const paymentsDashboard = readFileSync('dashboard/payments.html', 'utf8')
const leaderboardDashboard = readFileSync('dashboard/leaderboard.html', 'utf8')

class FixedDate extends Date {
  static now () {
    return 100000
  }
}

test('operator WebSocket clients authenticate with an in-band token frame', (t) => {
  for (const [label, html] of [
    ['index', dashboard],
    ['network', networkDashboard],
    ['payments', paymentsDashboard],
    ['leaderboard', leaderboardDashboard]
  ]) {
    t.ok(html.includes("document.querySelector('meta[name=\"hiverelay-ui-token\"]')"), `${label} reads injected UI token meta`)
    t.ok(html.includes("sock.send(JSON.stringify({ type: 'auth', token: t }))"), `${label} sends auth frame`)
    t.ok(html.includes('sendWsAuth(ws);'), `${label} authenticates when the WebSocket opens`)
    t.absent(html.includes('/ws?token='), `${label} does not put tokens in the WebSocket URL`)
  }
})

test('operator registry tables escape untrusted app keys and avoid inline action handlers', (t) => {
  const seeded = JSON.parse(renderRegistryDomWith([
    'renderSeeds([{',
    '  appKey: \'abc" onclick="alert(1)"><script>alert(2)</script>\',',
    '  appId: \'<img src=x onerror=alert(3)>\',',
    '  startedAt: 99000,',
    '  bytesServed: \'<svg onload=alert(4)>\'',
    '}])',
    'JSON.stringify({ html: document.getElementById("seedsBody").innerHTML, assignments: document.getElementById("seedsBody").innerHTMLAssignments })'
  ].join('\n')))

  t.ok(seeded.html.includes('data-registry-action="unseed"'))
  t.ok(seeded.html.includes('data-app-key="abc&quot; onclick=&quot;alert(1)&quot;&gt;&lt;script&gt;alert(2)&lt;/script&gt;"'))
  t.ok(seeded.html.includes('&lt;img src=x onerror=alert(3)&gt;'))
  t.ok(seeded.html.includes('abc&quot; onclick...'))
  t.absent(seeded.html.includes('onclick="'))
  t.absent(seeded.html.includes('<script>'))
  t.absent(seeded.html.includes('<img'))
  t.absent(seeded.html.includes('<svg'))
  t.alike(seeded.assignments, [])

  const pending = JSON.parse(renderRegistryDomWith([
    'renderPendingRequests([{',
    '  appKey: \'xyz" onclick="alert(5)"><script>alert(6)</script>\',',
    '  publisherPubkey: \'<img src=x onerror=alert(7)>\',',
    '  replicationFactor: \'<svg onload=alert(8)>\',',
    '  geoPreference: [\'us-east\', \'<script>alert(9)</script>\']',
    '}])',
    'JSON.stringify({ html: document.getElementById("pendingBody").innerHTML, assignments: document.getElementById("pendingBody").innerHTMLAssignments })'
  ].join('\n')))

  t.ok(pending.html.includes('data-registry-action="approve"'))
  t.ok(pending.html.includes('data-registry-action="reject"'))
  t.ok(pending.html.includes('data-app-key="xyz&quot; onclick=&quot;alert(5)&quot;&gt;&lt;script&gt;alert(6)&lt;/script&gt;"'))
  t.ok(pending.html.includes('<td>3</td>'), 'malformed replication factor falls back to default')
  t.ok(pending.html.includes('us-east, &lt;script&gt;alert(9)&lt;/script&gt;'))
  t.absent(pending.html.includes('onclick="'))
  t.absent(pending.html.includes('<script>'))
  t.absent(pending.html.includes('<img'))
  t.absent(pending.html.includes('<svg'))
  t.alike(pending.assignments, [])
})

test('operator registry and payout writes are timeout bounded and block duplicate submits', (t) => {
  t.ok(dashboard.includes('var destSaveBusy = false;'), 'payout save has a busy guard')
  t.ok(dashboard.includes('if (destSaveBusy) return;'), 'payout save blocks duplicate clicks')
  t.ok(dashboard.includes("destDialog.setAttribute('aria-busy', 'true');"), 'payout dialog exposes busy state')
  t.ok(dashboard.includes("fetchWithTimeout('/api/subsidy/destination'"), 'payout save is timeout-bounded')
  t.ok(dashboard.includes("destDialog.setAttribute('aria-busy', 'false');"), 'payout dialog clears busy state')

  t.ok(dashboard.includes('function postJson(path, body)'), 'operator writes share timeout helper')
  t.ok(dashboard.includes('return fetchWithTimeout(path, {'), 'operator write helper is timeout-bounded')
  t.ok(dashboard.includes("postJson('/registry/auto-accept', { enabled: enabled })"), 'auto-accept toggle uses timeout-bounded write')
  t.ok(dashboard.includes('autoAcceptToggle.disabled = true;'), 'auto-accept toggle blocks duplicate writes')
  t.ok(dashboard.includes('autoAcceptToggle.checked = previous;'), 'auto-accept toggle rolls back failed optimistic state')
  t.ok(dashboard.includes('autoAcceptToggle.disabled = false;'), 'auto-accept toggle re-enables after settlement')

  t.ok(dashboard.includes('function runRegistryAction(btn, path, body, onSuccess, label)'), 'registry actions share guarded write helper')
  t.ok(dashboard.includes('if (btn && btn.disabled) return Promise.resolve();'), 'registry actions ignore duplicate clicks')
  t.ok(dashboard.includes('setRegistryActionBusy(btn, true);'), 'registry action buttons enter busy state')
  t.ok(dashboard.includes("btn.setAttribute('aria-busy', busy ? 'true' : 'false');"), 'registry action buttons expose busy state')
  t.ok(dashboard.includes('return postJson(path, body)'), 'registry actions use timeout-bounded writes')
  t.ok(dashboard.includes("runRegistryAction(btn, '/unseed'"), 'unseed action uses guarded helper')
  t.ok(dashboard.includes("runRegistryAction(btn, '/registry/approve'"), 'approve action uses guarded helper')
  t.ok(dashboard.includes("runRegistryAction(btn, '/registry/reject'"), 'reject action uses guarded helper')
  t.ok(dashboard.includes('if (btn.disabled) return;'), 'delegated registry handler ignores already-busy buttons')
  t.ok(dashboard.includes('unseedApp(appKey, btn);'), 'delegated unseed passes clicked button')
  t.ok(dashboard.includes('approveRequest(appKey, btn);'), 'delegated approve passes clicked button')
  t.ok(dashboard.includes('rejectRequest(appKey, btn);'), 'delegated reject passes clicked button')

  t.absent(dashboard.includes("fetch('/registry/auto-accept'"), 'auto-accept no longer uses raw fetch')
  t.absent(dashboard.includes("fetch('/unseed'"), 'unseed no longer uses raw fetch')
  t.absent(dashboard.includes("fetch('/registry/approve'"), 'approve no longer uses raw fetch')
  t.absent(dashboard.includes("fetch('/registry/reject'"), 'reject no longer uses raw fetch')
})

test('operator apps table and developer metadata render untrusted values as DOM text', (t) => {
  const apps = JSON.parse(renderRegistryDomWith([
    'var appKey = \'abc" onclick="alert(1)"><script>alert(2)</script>\'',
    'catalogDevs[appKey] = {',
    '  displayName: \'<b>Trusted?</b>\',',
    '  pubkey: \'pubkey\',',
    '  avatar: \'javascript:alert(1)\'',
    '}',
    'currentApps = [{',
    '  appKey: appKey,',
    '  appId: \'<img src=x onerror=alert(3)>\',',
    '  started: \'<svg onload=alert(4)>\',',
    '  bytesServed: \'<svg onload=alert(5)>\'',
    '}]',
    'renderAppsTable()',
    'JSON.stringify({ html: document.getElementById("appsBody").innerHTML, assignments: document.getElementById("appsBody").innerHTMLAssignments })'
  ].join('\n')))

  t.ok(apps.html.includes('&lt;img src=x onerror=alert(3)&gt;'))
  t.ok(apps.html.includes('&lt;b&gt;Trusted?&lt;/b&gt;'))
  t.ok(apps.html.includes('abc&quot; onclick...'))
  t.ok(apps.html.includes('<td>--</td>'), 'malformed start time falls back')
  t.absent(apps.html.includes('onclick="'))
  t.absent(apps.html.includes('<script>'))
  t.absent(apps.html.includes('<img'))
  t.absent(apps.html.includes('<svg'))
  t.absent(apps.html.includes('javascript:'))
  t.alike(apps.assignments, [])

  const linkedDev = JSON.parse(renderRegistryDomWith([
    'catalogDevs.safe = {',
    '  displayName: \'Linked Dev\',',
    '  pubkey: \'pubkey\',',
    '  avatar: \'https://example.test/avatar.png\'',
    '}',
    'currentApps = [{ appKey: \'safe\', appId: \'Safe App\', started: \'1970-01-01T00:00:10.000Z\', bytesServed: 2048 }]',
    'renderAppsTable()',
    'JSON.stringify({ html: document.getElementById("appsBody").innerHTML, assignments: document.getElementById("appsBody").innerHTMLAssignments })'
  ].join('\n')))

  t.ok(linkedDev.html.includes('<img src="https://example.test/avatar.png"'))
  t.ok(linkedDev.html.includes('alt=""'))
  t.ok(linkedDev.html.includes('referrerpolicy="no-referrer"'))
  t.ok(linkedDev.html.includes('Linked Dev'))
  t.absent(linkedDev.html.includes('onerror='))
  t.alike(linkedDev.assignments, [])
})

test('operator header and peer list render untrusted overview fields as text', (t) => {
  const rendered = JSON.parse(renderDomWith([
    'var chip = document.getElementById("headerMeta")',
    'renderHeaderMeta(chip, \'<script>alert(1)</script>abcdef\', \'<img src=x onerror=alert(2)>\')',
    'var peers = document.getElementById("peersList")',
    'renderPeersList(peers, [',
    '  { publicKey: \'<img src=x onerror=alert(3)>abcdef\' },',
    '  { key: \'abc" onclick="alert(4)\' }',
    '])',
    'JSON.stringify({',
    '  chipHtml: chip.innerHTML,',
    '  chipText: chip.textContent,',
    '  peersHtml: peers.innerHTML,',
    '  peersText: peers.textContent,',
    '  pk: chip.dataset.pk,',
    '  region: chip.dataset.region',
    '})'
  ].join('\n')))

  t.is(rendered.pk, '<script>alert(1)</script>abcdef')
  t.is(rendered.region, '<img src=x onerror=alert(2)>')
  t.ok(rendered.chipHtml.includes('&lt;script&gt;aler...'))
  t.ok(rendered.chipText.includes('<script>aler...'))
  t.ok(rendered.chipText.includes('<img src=x onerror=alert(2)>'))
  t.absent(rendered.chipHtml.includes('<script>'))
  t.absent(rendered.chipHtml.includes('<img'))
  t.absent(rendered.chipHtml.includes('onclick="'))

  t.ok(rendered.peersHtml.includes('&lt;img src=x onerr...'))
  t.ok(rendered.peersHtml.includes('abc&quot; onclick=&quot;al...'))
  t.ok(rendered.peersText.includes('<img src=x onerr...'))
  t.absent(rendered.peersHtml.includes('<script>'))
  t.absent(rendered.peersHtml.includes('<img'))
  t.absent(rendered.peersHtml.includes('onclick="'))
})

test('operator pulse surface is present for data-layer v0/v1/v2', (t) => {
  t.ok(dashboard.includes('id="operatorPulseRow"'), 'primary pulse row')
  t.ok(dashboard.includes('id="statNodeHealth"'), 'node health chip')
  t.ok(dashboard.includes('id="statDisk"'), 'disk chip')
  t.ok(dashboard.includes('id="statRoles"'), 'roles chip')
  t.ok(dashboard.includes('id="statSuppress"'), 'suppressions chip')
  t.ok(dashboard.includes('id="operatorPulseRow2"'), 'secondary pulse row')
  t.ok(dashboard.includes('id="statOutboxWriters"'), 'outbox writers chip')
  t.ok(dashboard.includes('id="statOutboxBytes"'), 'outbox bytes chip')
  t.ok(dashboard.includes('id="statShardRejected"'), 'shard rejects chip')
  t.ok(dashboard.includes('id="statPrivacy"'), 'privacy lane chip')
  t.ok(dashboard.includes('id="namespacesPanel"'), 'namespaces panel')
  t.ok(dashboard.includes('id="compliancePanel"'), 'compliance panel')
  t.ok(dashboard.includes('id="walPanel"'), 'v2 wal panel')
  t.ok(dashboard.includes('id="gatewayPanel"'), 'v2 gateway panel')
  t.ok(dashboard.includes('id="shardPanel"'), 'v2 shard panel')
  t.ok(dashboard.includes('id="attentionPanel"'), 'attention panel')
  t.ok(dashboard.includes('function updateOperatorPulse(overview)'), 'pulse updater')
  t.ok(dashboard.includes('updateOperatorPulse(overview);'), 'wired from updateDashboard')
})

test('operator pulse renders management overview and escapes namespace names', (t) => {
  const out = JSON.parse(renderOperatorPulseWith([
    'updateOperatorPulse({',
    '  health: { healthy: true },',
    '  disk: { ok: true, usedPct: 22, freeGB: 40, status: "ok" },',
    '  roles: { t1: true, t2: true, gateway: false, outboxlog: true, witness: false },',
    '  compliance: { adminArmed: true, suppressedKeys: 3, takedownCount: 3 },',
    '  namespaces: {',
    '    groups: 1,',
    '    totalBytes: 4096,',
    '    suppressedCount: 3,',
    '    namespaces: [{ name: \'<img src=x onerror=alert(1)>\', blind: true, writers: 2, bytes24h: 100, capBytes24h: 1000 }]',
    '  },',
    '  shardStore: { put: 10, get: 5, rejected: 1, bytes: 4096 },',
    '  wal: { source: "outboxlog-journal", healthy: true, length: 12, pruningSupported: false },',
    '  gatewayDetail: { enabled: true, port: 9200, totalRequests: 7, totalBytesServed: 11, cachedDrives: 2, verifyFails: 0, roleConflict: false },',
    '  privacyTransports: [{ id: "tor-v3-onion-v1", running: true, health: "ready", activeConnections: 2, negativeProbe: true }],',
    '  errors: 0',
    '})',
    'JSON.stringify({',
    '  health: document.getElementById("statNodeHealth").textContent,',
    '  disk: document.getElementById("statDisk").textContent,',
    '  roles: document.getElementById("statRoles").textContent,',
    '  suppress: document.getElementById("statSuppress").textContent,',
    '  writers: document.getElementById("statOutboxWriters").textContent,',
    '  privacy: document.getElementById("statPrivacy").textContent,',
    '  nsHtml: document.getElementById("namespacesBody").innerHTML,',
    '  nsDisplay: document.getElementById("namespacesPanel").style.display,',
    '  compDisplay: document.getElementById("compliancePanel").style.display,',
    '  walDisplay: document.getElementById("walPanel").style.display,',
    '  walSource: document.getElementById("walSource").textContent,',
    '  gwDisplay: document.getElementById("gatewayPanel").style.display,',
    '  gwEnabled: document.getElementById("gwEnabled").textContent,',
    '  shardDisplay: document.getElementById("shardPanel").style.display,',
    '  shardPut: document.getElementById("shardPut").textContent,',
    '  armed: document.getElementById("compAdminArmed").textContent,',
    '  attentionHtml: document.getElementById("attentionList").innerHTML',
    '})'
  ].join('\n')))

  t.is(out.health, 'OK')
  t.is(out.disk, '22%')
  t.is(out.roles, 'T1+T2+OL')
  t.is(out.suppress, '3')
  t.is(out.writers, '2')
  t.is(out.privacy, 'ready')
  t.is(out.nsDisplay, '')
  t.is(out.compDisplay, '')
  t.is(out.walDisplay, '')
  t.is(out.walSource, 'outboxlog-journal')
  t.is(out.gwDisplay, '')
  t.is(out.gwEnabled, 'ON')
  t.is(out.shardDisplay, '')
  t.is(out.shardPut, '10')
  t.is(out.armed, 'ARMED')
  t.ok(out.nsHtml.includes('&lt;img src=x onerror=alert(1)&gt;'))
  t.ok(out.nsHtml.includes('blind'))
  t.absent(out.nsHtml.includes('<img'))
  t.absent(out.attentionHtml.includes('T2 custody with gateway'), 'gateway off → no co-location warning')
})

test('operator pulse public overview hides management panels', (t) => {
  const out = JSON.parse(renderOperatorPulseWith([
    'updateOperatorPulse({',
    '  health: { healthy: true },',
    '  disk: { ok: true, usedPct: 10, freeGB: 90, status: "ok" },',
    '  roles: { t1: true, t2: false, gateway: false, outboxlog: false, witness: false },',
    '  compliance: null,',
    '  namespaces: null,',
    '  shardStore: null,',
    '  privacyTransports: [{ id: "tor-v3-onion-v1", running: true, health: "ready", activeConnections: 0 }],',
    '  errors: 0',
    '})',
    'JSON.stringify({',
    '  suppress: document.getElementById("statSuppress").textContent,',
    '  roles: document.getElementById("statRoles").textContent,',
    '  privacy: document.getElementById("statPrivacy").textContent,',
    '  row2: document.getElementById("operatorPulseRow2").style.display,',
    '  nsDisplay: document.getElementById("namespacesPanel").style.display,',
    '  compDisplay: document.getElementById("compliancePanel").style.display',
    '})'
  ].join('\n')))

  t.is(out.suppress, '—')
  t.is(out.roles, 'T1')
  t.is(out.privacy, 'ready')
  t.is(out.row2, '')
  t.is(out.nsDisplay, 'none')
  t.is(out.compDisplay, 'none')
})

test('operator header public-key copy reports missing or rejected clipboard writes', async (t) => {
  const source = [
    extractFunction('clearNode'),
    extractFunction('appendEl'),
    extractFunction('truncateKey'),
    extractFunction('renderHeaderMeta'),
    extractFunction('renderHeaderCopyMessage'),
    extractFunction('renderHeaderCopied'),
    extractFunction('copyHeaderPubkey'),
    `
    (async function () {
      globalThis.document = {
        createElement: function (tag) { return new FakeElement(tag) }
      }
      var timers = []
      globalThis.setTimeout = function (fn) { timers.push(fn); return timers.length }
      var chip = new FakeElement('button')
      chip.dataset.pk = 'pub-key'
      chip.dataset.region = 'uae'
      var results = {}

      delete globalThis.navigator
      copyHeaderPubkey(chip)
      results.noClipboard = chip.textContent
      timers.shift()()
      results.restored = chip.textContent

      var writes = []
      globalThis.navigator = {
        clipboard: {
          writeText: function (text) {
            writes.push(text)
            return Promise.reject(new Error('denied'))
          }
        }
      }
      copyHeaderPubkey(chip)
      await Promise.resolve()
      await Promise.resolve()
      results.rejected = chip.textContent

      globalThis.navigator.clipboard.writeText = function (text) {
        writes.push(text)
        return Promise.resolve()
      }
      copyHeaderPubkey(chip)
      await Promise.resolve()
      await Promise.resolve()
      results.success = chip.textContent
      results.writes = writes
      results.timers = timers.length
      return results
    })()
    `
  ].join('\n')

  const out = await vm.runInNewContext(source, { Promise, Error, FakeElement })

  t.is(out.noClipboard, 'Clipboard unavailable')
  t.ok(out.restored.includes('pub-key · uae'))
  t.is(out.rejected, 'Copy failed')
  t.is(out.success, 'copied ✓')
  t.is(out.writes.join(','), 'pub-key,pub-key')
  t.is(out.timers, 2)
})

function renderDomWith (body) {
  const elements = {}
  const source = [
    extractFunction('clearNode'),
    extractFunction('appendEl'),
    extractFunction('truncateKey'),
    extractFunction('renderHeaderMeta'),
    extractFunction('renderPeersList'),
    body
  ].join('\n')
  return vm.runInNewContext(source, {
    String,
    JSON,
    document: {
      createElement (tag) {
        return new FakeElement(tag)
      },
      getElementById (id) {
        if (!elements[id]) elements[id] = new FakeElement('div')
        return elements[id]
      }
    }
  })
}

function renderOperatorPulseWith (body) {
  const elements = {}
  const source = [
    extractFunction('clearNode'),
    extractFunction('appendEl'),
    extractFunction('formatBytes'),
    extractFunction('formatCount'),
    extractFunction('setText'),
    extractFunction('renderNamespaceRows'),
    extractFunction('renderAttentionList'),
    extractFunction('updateOperatorPulse'),
    body
  ].join('\n')
  return vm.runInNewContext(source, {
    String,
    Number,
    Array,
    Math,
    isNaN,
    document: {
      createElement (tag) {
        return new FakeElement(tag)
      },
      createTextNode (text) {
        return new FakeText(text)
      },
      getElementById (id) {
        if (!elements[id]) {
          const el = new FakeElement('div')
          // default management panels hidden like the HTML
          if (
            id === 'namespacesPanel' ||
            id === 'compliancePanel' ||
            id === 'operatorPulseRow2' ||
            id === 'walPanel' ||
            id === 'gatewayPanel' ||
            id === 'shardPanel'
          ) {
            el.style.display = 'none'
          }
          elements[id] = el
        }
        return elements[id]
      }
    }
  })
}

function renderRegistryDomWith (body) {
  const elements = {}
  const source = [
    'var catalogNames = {}',
    'var catalogDevs = {}',
    'var currentApps = []',
    extractFunction('clearNode'),
    extractFunction('appendEl'),
    extractFunction('safeHttpUrl'),
    extractFunction('renderDevNode'),
    extractFunction('renderAppNameNode'),
    extractFunction('formatBytes'),
    extractFunction('formatUptime'),
    extractFunction('truncateKey'),
    extractFunction('formatTime'),
    extractFunction('renderAppsTable'),
    extractFunction('bindRegistryActionTable'),
    extractFunction('appendRegistryButton'),
    extractFunction('renderSeeds'),
    extractFunction('renderPendingRequests'),
    body
  ].join('\n')
  return vm.runInNewContext(source, {
    String,
    Number,
    Array,
    Date: FixedDate,
    Math,
    URL,
    isNaN,
    window: {},
    document: {
      createElement (tag) {
        return new FakeElement(tag)
      },
      createTextNode (text) {
        return new FakeText(text)
      },
      getElementById (id) {
        if (!elements[id]) elements[id] = new FakeElement(id === 'pendingBody' || id === 'seedsBody' || id === 'appsBody' ? 'tbody' : 'div')
        return elements[id]
      }
    }
  })
}

function extractFunction (name) {
  const start = dashboard.indexOf('function ' + name)
  if (start === -1) throw new Error('missing function ' + name)
  const firstBrace = dashboard.indexOf('{', start)
  let depth = 0
  for (let i = firstBrace; i < dashboard.length; i++) {
    const char = dashboard[i]
    if (char === '{') depth++
    else if (char === '}') {
      depth--
      if (depth === 0) return dashboard.slice(start, i + 1)
    }
  }
  throw new Error('unterminated function ' + name)
}

class FakeElement {
  constructor (tagName) {
    this.tagName = tagName
    this.children = []
    this.dataset = {}
    this.style = {}
    this.className = ''
    this.type = ''
    this.src = ''
    this.alt = undefined
    this.referrerPolicy = ''
    this.colSpan = 0
    this._text = ''
    this.innerHTMLAssignments = []
  }

  appendChild (child) {
    child.parentNode = this
    this.children.push(child)
    return child
  }

  removeChild (child) {
    const idx = this.children.indexOf(child)
    if (idx !== -1) this.children.splice(idx, 1)
    child.parentNode = null
    return child
  }

  get firstChild () {
    return this.children[0] || null
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
    if (this.children.length === 0) return escapeText(this._text)
    return escapeText(this._text) + this.children.map(serializeElement).join('')
  }

  addEventListener () {}

  contains (node) {
    return node === this || this.children.includes(node)
  }
}

class FakeText {
  constructor (text) {
    this.isTextNode = true
    this._text = text === null || text === undefined ? '' : String(text)
  }

  get textContent () {
    return this._text
  }

  get innerHTML () {
    return escapeText(this._text)
  }
}

function serializeElement (el) {
  if (el.isTextNode) return escapeText(el.textContent)
  const attrs = []
  if (el.className) attrs.push('class="' + escapeText(el.className) + '"')
  if (el.type) attrs.push('type="' + escapeText(el.type) + '"')
  if (el.src) attrs.push('src="' + escapeText(el.src) + '"')
  if (el.alt !== undefined) attrs.push('alt="' + escapeText(el.alt) + '"')
  if (el.referrerPolicy) attrs.push('referrerpolicy="' + escapeText(el.referrerPolicy) + '"')
  if (el.colSpan) attrs.push('colspan="' + escapeText(el.colSpan) + '"')
  for (const [key, value] of Object.entries(el.dataset)) {
    attrs.push(dataAttrName(key) + '="' + escapeText(value) + '"')
  }
  const styleText = Object.entries(el.style).filter((entry) => entry[1] !== undefined && entry[1] !== '').map(function ([key, value]) {
    return cssName(key) + ':' + escapeText(value)
  }).join(';')
  if (styleText) attrs.push('style="' + styleText + '"')
  return '<' + el.tagName + (attrs.length ? ' ' + attrs.join(' ') : '') + '>' + el.innerHTML + '</' + el.tagName + '>'
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

function escapeText (value) {
  return String(value).replace(/[&<>"']/g, function (ch) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]
  })
}
