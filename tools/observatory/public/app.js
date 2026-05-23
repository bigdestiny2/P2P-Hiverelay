/* global EventSource */
// Dashboard client — polls /api/state every 5s, renders relay cards.
// No framework, no build step. ~150 lines, fits in one screen.

const REFRESH_MS = 5_000

// Map of known relay pubkeys → friendly names so the peer list reads as
// "(Utah-US)" instead of "37cf4bfbdf33". Populated from /api/config on boot.
const KNOWN = new Map()

async function bootConfig () {
  try {
    const res = await fetch('/api/config')
    const cfg = await res.json()
    document.getElementById('poll-interval').textContent = (cfg.pollIntervalMs / 1000) + 's'
  } catch (err) {
    /* non-fatal */
  }
}

async function refresh () {
  try {
    const res = await fetch('/api/state')
    const state = await res.json()
    rebuildKnownMap(state)
    render(state)
  } catch (err) {
    document.getElementById('updated').textContent = 'Error: ' + err.message
  }
}

function rebuildKnownMap (state) {
  KNOWN.clear()
  for (const [id, snap] of Object.entries(state.relays || {})) {
    // Three-way preference, in order:
    //   1. declaredPubkey from the RELAYS config — works even if the
    //      remote relay's capability doc is identity-redacted.
    //   2. capability.identity — the natural source when present.
    //   3. catalog.relayKey prefix — last-resort fallback.
    const k = snap.declaredPubkey ||
      snap.capability?.identity ||
      snap.catalog?.relayKey?.slice(0, 12)
    if (k) KNOWN.set(k, id)
  }
}

function render (state) {
  if (!state.updatedAt) {
    document.getElementById('updated').textContent = 'Polling…'
    return
  }
  const age = Math.round((Date.now() - state.updatedAt) / 1000)
  document.getElementById('updated').textContent =
    `Last updated: ${new Date(state.updatedAt).toLocaleTimeString()} (${age}s ago)`

  const grid = document.getElementById('grid')
  grid.innerHTML = ''

  for (const [id, snap] of Object.entries(state.relays || {})) {
    grid.appendChild(renderRelay(id, snap))
  }
}

function renderRelay (id, snap) {
  const div = document.createElement('div')
  div.className = 'relay' + (snap.up ? '' : ' down')

  const version = snap.capability?.version || '?'
  const apps = snap.catalog?.total ?? '?'
  const anchored = snap.catalog?.anchored ?? '?'
  const peers = snap.peerCount ?? 0
  const uptimeMin = snap.uptimeMs ? Math.round(snap.uptimeMs / 60_000) : null
  const uptimeStr = uptimeMin != null ? formatUptime(uptimeMin) : '?'
  const running = snap.running ? 'running' : 'idle'

  const peersHtml = (snap.peers || []).map(p => {
    const name = KNOWN.get(p.pubkey)
    if (name && name === id) {
      // shouldn't happen — relays don't see themselves — but guard anyway
      return `<span class="pubkey self">${p.pubkey} (self)</span>`
    }
    if (name) return `<span class="pubkey">${p.pubkey} <em>${name}</em></span>`
    return `<span class="pubkey unknown">${p.pubkey}</span>`
  }).join('')

  const errsHtml = (snap.errors || []).length
    ? `<div class="errors">errors: ${snap.errors.map(e => `${e.endpoint} (${e.error})`).join(', ')}</div>`
    : ''

  div.innerHTML = `
    <div class="relay-header">
      <span class="relay-name">${escapeHtml(id)}</span>
      <span class="relay-meta">${snap.host} · ${snap.region} · v${escapeHtml(String(version))} · ${snap.capability?.identity || ''}</span>
    </div>
    <div class="stats">
      <div class="stat">
        <div class="stat-label">status</div>
        <div class="stat-value ${snap.up ? 'up' : 'down'}">${snap.up ? running : 'DOWN'}</div>
      </div>
      <div class="stat">
        <div class="stat-label">uptime</div>
        <div class="stat-value">${uptimeStr}</div>
      </div>
      <div class="stat">
        <div class="stat-label">peers</div>
        <div class="stat-value ${peers >= 4 ? 'up' : peers >= 2 ? 'warn' : 'down'}">${peers}</div>
      </div>
      <div class="stat">
        <div class="stat-label">apps</div>
        <div class="stat-value">${apps}</div>
      </div>
      <div class="stat">
        <div class="stat-label">anchored</div>
        <div class="stat-value ${anchored > 0 ? 'up' : 'warn'}">${anchored}</div>
      </div>
      <div class="stat">
        <div class="stat-label">operator</div>
        <div class="stat-value" style="font-size:0.85em">${escapeHtml(snap.operator || '?')}</div>
      </div>
    </div>
    <div class="peers">
      <div class="peers-label">connected peers (${peers})</div>
      ${peersHtml || '<span class="updated">none yet</span>'}
    </div>
    ${errsHtml}
  `
  return div
}

function formatUptime (mins) {
  if (mins < 60) return mins + 'm'
  const h = Math.floor(mins / 60)
  const m = mins % 60
  if (h < 24) return `${h}h ${m}m`
  const d = Math.floor(h / 24)
  return `${d}d ${h % 24}h`
}

function escapeHtml (s) {
  return String(s).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]))
}

bootConfig().then(refresh)
setInterval(refresh, REFRESH_MS)

// ── Log stream (SSE) ────────────────────────────────────────────────────

const LOG_MAX_DISPLAYED = 800 // cap the DOM size so the page stays fast
const logEl = document.getElementById('log-stream')
const logEmptyEl = document.getElementById('log-empty')
const logStatusEl = document.getElementById('log-status')
const autoScrollEl = document.getElementById('log-auto-scroll')
const hideInfoEl = document.getElementById('log-hide-info')
const filterEl = document.getElementById('log-filter')
let logFilter = ''
filterEl.addEventListener('input', () => { logFilter = filterEl.value.toLowerCase(); applyFilter() })
hideInfoEl.addEventListener('change', applyFilter)

function applyFilter () {
  const hideInfo = hideInfoEl.checked
  const f = logFilter
  // Optional "relay:utah" filter
  let relayMatch = null
  let textMatch = f
  const m = f.match(/^relay:(\S+)\s*(.*)/)
  if (m) { relayMatch = m[1]; textMatch = m[2].trim() }
  for (const line of logEl.children) {
    if (line === logEmptyEl) continue
    const relay = line.dataset.relay
    const level = line.dataset.level
    const text = line.dataset.text || ''
    let visible = true
    if (hideInfo && level === 'info') visible = false
    if (visible && relayMatch && relay !== relayMatch) visible = false
    if (visible && textMatch && !text.toLowerCase().includes(textMatch)) visible = false
    line.style.display = visible ? '' : 'none'
  }
}

function appendLogLine (entry) {
  if (logEmptyEl.parentNode) logEmptyEl.remove()
  const line = document.createElement('div')
  line.className = 'log-line'
  const level = String(entry.level || 'info').toLowerCase()
  const time = entry.ts
    ? new Date(entry.ts).toLocaleTimeString('en-GB', { hour12: false }) +
      '.' + String(entry.ts % 1000).padStart(3, '0')
    : ''
  // Build a contextual suffix from JSON fields if present
  const fields = entry.fields || {}
  const extras = []
  if (fields.peer) extras.push(`<em>peer=${escapeHtml(String(fields.peer).slice(0, 12))}</em>`)
  if (fields.appKey) extras.push(`<em>appKey=${escapeHtml(String(fields.appKey).slice(0, 12))}</em>`)
  if (fields.source) extras.push(`<em>src=${escapeHtml(fields.source)}</em>`)
  if (fields.error) extras.push(`<em>err=${escapeHtml(String(fields.error).slice(0, 100))}</em>`)
  if (fields.health) extras.push(`<em>health=${escapeHtml(JSON.stringify(fields.health).slice(0, 80))}</em>`)
  line.innerHTML = `
    <span class="log-time">${time}</span>
    <span class="log-relay">${escapeHtml(entry.relay)}</span>
    <span class="log-level ${level}">${level}</span>
    <span class="log-msg">${escapeHtml(entry.msg || '')} ${extras.join(' ')}</span>
  `
  line.dataset.relay = entry.relay
  line.dataset.level = level
  line.dataset.text = (entry.msg + ' ' + JSON.stringify(fields)).toLowerCase()
  logEl.appendChild(line)
  // Cap DOM
  while (logEl.children.length > LOG_MAX_DISPLAYED + 1) { // +1 for empty placeholder if still there
    if (logEl.firstChild === logEmptyEl) logEl.firstChild.remove()
    else logEl.firstChild.remove()
  }
  if (logFilter || hideInfoEl.checked) {
    applyFilter()
  }
  if (autoScrollEl.checked) {
    logEl.scrollTop = logEl.scrollHeight
  }
}

function connectLogStream () {
  logStatusEl.textContent = 'connecting…'
  const es = new EventSource('/api/logs/stream')
  es.onopen = () => { logStatusEl.textContent = 'streaming' }
  es.onmessage = (ev) => {
    try {
      const entry = JSON.parse(ev.data)
      appendLogLine(entry)
    } catch (err) {
      // ignore malformed payload
    }
  }
  es.onerror = () => {
    logStatusEl.textContent = 'reconnecting…'
    // EventSource auto-reconnects, but if it persistently fails we want
    // to surface that. Browser will retry every few seconds.
  }
}
connectLogStream()
