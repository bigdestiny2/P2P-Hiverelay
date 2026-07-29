/* global EventSource, alert, confirm */
/* HiveRelay · Dashboard Admin Operator — live fleet control plane */

let state = null
let evtSource = null
let expandedNode = null

const REGION_NAMES = { NA: 'North America', EU: 'Europe', APAC: 'Asia-Pacific', ME: 'Middle East' }
const FEATURE_LABELS = {
  coreRelay: 'Core Relay',
  seeding: 'Seeding',
  services: 'Service Layer',
  dhtRelayWs: 'DHT Relay (WS)',
  tor: 'Tor Transport',
  holesail: 'Holesail',
  outboxlog: 'OutboxLog',
  forwardRelay: 'Forward Relay',
  signedDirectory: 'Signed Directory',
  vrf: 'VRF (RFC 9381)',
  poker: 'Poker Substrate',
  zk: 'ZK Proofs',
  arbitration: 'Arbitration',
  payment: 'Payments',
  eviction: 'Auto-Eviction',
  autoHeal: 'Auto-Heal',
  distributedDrive: 'Distributed Drive'
}
const TOGGLEABLE = ['dhtRelayWs', 'outboxlog', 'forwardRelay', 'signedDirectory', 'services', 'eviction']

async function fetchState () {
  try { state = await (await fetch('/api/state')).json(); render() } catch { document.getElementById('app').innerHTML = '<div class="loading">Connection lost...</div>' }
}

function connectSSE () {
  if (evtSource) evtSource.close()
  evtSource = new EventSource('/api/events')
  evtSource.onmessage = (e) => {
    try {
      const msg = JSON.parse(e.data)
      if (msg.type === 'fleet') {
        if (!state) { fetchState(); return }
        state.nodes = msg.data; state.lastProbe = msg.timestamp
        state.summary = computeSummary(msg.data)
        render()
      } else if (msg.type === 'action') {
        if (state) { state.actions = [msg.data, ...(state.actions || [])] }
        showToast(msg.data)
      } else if (msg.type === 'control') {
        if (state) {
          state.control = {
            ...(state.control || {}),
            lastCycle: msg.data,
            autoControl: msg.data.autoControl,
            inRange: msg.data.summary?.inRange,
            critical: msg.data.summary?.critical,
            warnings: msg.data.summary?.warnings
          }
          render()
        }
      }
    } catch {}
  }
  evtSource.onerror = () => { evtSource.close(); setTimeout(() => { connectSSE(); fetchState() }, 5000) }
}

function computeSummary (nodes) {
  const regions = {}
  for (const n of nodes) {
    const r = n.region || 'Unknown'
    if (!regions[r]) regions[r] = { total: 0, healthy: 0, degraded: 0, offline: 0 }
    regions[r].total++
    if (n.status === 'healthy') regions[r].healthy++
    else if (n.status === 'offline') regions[r].offline++
    else regions[r].degraded++
  }
  return {
    total: nodes.length,
    healthy: nodes.filter(n => n.status === 'healthy').length,
    degraded: nodes.filter(n => n.status === 'degraded').length,
    offline: nodes.filter(n => n.status === 'offline').length,
    running: nodes.filter(n => n.running === true).length,
    diskWarnings: nodes.filter(n => n.diskPct && n.diskPct > 75).length,
    totalRamGB: Math.round(nodes.reduce((s, n) => s + (n.ramGB || 0), 0)),
    totalDiskGB: nodes.reduce((s, n) => s + (n.diskGB || 0), 0),
    totalSeeded: nodes.reduce((s, n) => s + (n.seededApps || 0), 0),
    totalConns: nodes.reduce((s, n) => s + (n.connections || 0), 0),
    regions
  }
}

function fmtBytes (b) {
  if (!b || b === 0) return '0 B'
  const u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
  const i = Math.floor(Math.log(b) / Math.log(1024))
  return (b / Math.pow(1024, i)).toFixed(1) + ' ' + u[i]
}

function esc (s) { if (s == null) return ''; const d = document.createElement('div'); d.textContent = String(s); return d.innerHTML }

function render () {
  if (!state || !state.nodes) return
  const s = state.summary
  const probeAgo = state.lastProbe ? Math.round((Date.now() - new Date(state.lastProbe).getTime()) / 1000) : '?'

  document.getElementById('app').innerHTML = `
    <div class="header">
      <div class="header-left">
        <div class="logo-mark">H</div>
        <div><h1>Dashboard Admin Operator</h1>
        <div class="header-meta">Fleet control · ${state.nodes.length} nodes · ${s.totalSeeded} apps seeded · ${s.totalConns} connections · probed ${probeAgo}s ago</div></div>
      </div>
      <div class="header-right">
        <div class="live-indicator"><span class="live-pulse"></span><span>LIVE</span></div>
        <button class="btn" onclick="runControlNow()" title="Evaluate ranges + remediate now">Control cycle</button>
        <button class="btn" onclick="stabilizeAll()" title="Install watchdog + swap on all reachable">Stabilize all</button>
        <button class="btn" onclick="reprobe()">Re-probe</button>
      </div>
    </div>
    <div class="container">
      ${renderKPIs(s)}
      ${renderControlPanel(state.control)}
      ${renderRegions(s.regions)}
      ${renderNodeTable(state.nodes)}
      ${renderActionLog(state.actions)}
    </div>
    <div id="toast-container"></div>
    <div class="footer"><div class="footer-meta">Admin Operator · full fleet control · probe ${state.interval || 60}s · auto-control ${state.control?.autoControl ? 'ON' : 'OFF'} · ${new Date().toISOString()}</div></div>
  `
}

function renderControlPanel (ctrl) {
  if (!ctrl) {
    return '<div class="control-panel"><div class="control-panel-head"><strong>Fleet control</strong><span class="dim">waiting for first probe…</span></div></div>'
  }
  const auto = !!ctrl.autoControl
  const cycle = ctrl.lastCycle
  const sum = cycle?.summary || {}
  const nodes = cycle?.nodes || []
  const violators = nodes.filter(n => (n.violations || []).length > 0)
  const remediations = cycle?.remediations || []
  return `
  <div class="control-panel">
    <div class="control-panel-head">
      <div>
        <strong>Fleet control plane</strong>
        <span class="dim"> · healthy ranges by tier · auto-remediate hangs/OOM/disk</span>
      </div>
      <div class="control-panel-actions">
        <label class="toggle-auto" title="When on, each probe auto-restarts hung nodes and enforces baseline">
          <input type="checkbox" ${auto ? 'checked' : ''} onchange="setAutoControl(this.checked)">
          <span>Auto-control ${auto ? 'ON' : 'OFF'}</span>
        </label>
      </div>
    </div>
    <div class="control-kpis">
      <div class="ckpi ok"><div class="ckpi-v">${sum.inRange ?? '—'}</div><div class="ckpi-l">In range</div></div>
      <div class="ckpi warn"><div class="ckpi-v">${sum.warnings ?? 0}</div><div class="ckpi-l">Warnings</div></div>
      <div class="ckpi crit"><div class="ckpi-v">${sum.critical ?? 0}</div><div class="ckpi-l">Critical</div></div>
      <div class="ckpi"><div class="ckpi-v">${sum.offline ?? 0}</div><div class="ckpi-l">Offline</div></div>
      <div class="ckpi"><div class="ckpi-v">${remediations.length}</div><div class="ckpi-l">Last fixes</div></div>
    </div>
    <div class="control-ranges">
      <span class="range-chip">small ≤1GB: mem≤300MB light plugins</span>
      <span class="range-chip">medium 2–4GB: mem≤1.6GB</span>
      <span class="range-chip">large ≥4GB: mem≤4.8GB</span>
      <span class="range-chip">swap ≥256MB · watchdog required · disk warn 75%</span>
    </div>
    ${violators.length
? `
    <div class="violations">
      <div class="section-title" style="margin:8px 0 6px">Out of range <span class="count">${violators.length}</span></div>
      ${violators.map(v => `
        <div class="violation-row">
          <strong>${esc(v.name)}</strong>
          <span class="badge ${esc(v.tier || '')}">${esc(v.tier || '?')}</span>
          ${(v.violations || []).map(x => `<span class="vchip ${x.severity}">${esc(x.code)}: ${esc(x.msg)}</span>`).join('')}
          ${(v.actions || []).map(a => `<span class="auto-act">→ ${esc(a.type)}</span>`).join('')}
        </div>`).join('')}
    </div>`
: '<div class="in-range-ok">All reachable nodes within healthy ranges (or offline only).</div>'}
    ${remediations.length
? `
    <div class="remed-log">
      ${remediations.map(r => `<div class="remed-item ${r.ok ? 'ok' : 'fail'}">${esc(r.node)} · auto:${esc(r.type)} · ${esc(r.reason)} · ${r.ok ? 'ok' : 'fail'} ${esc(r.detail || '')}</div>`).join('')}
    </div>`
: ''}
  </div>`
}

async function setAutoControl (enabled) {
  try {
    const res = await fetch('/api/control', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ autoControl: enabled }) })
    const data = await res.json()
    if (state) {
      state.control = state.control || {}
      state.control.autoControl = data.autoControl
    }
    showToast({ node: 'fleet', action: 'auto-control', detail: enabled ? 'ENABLED' : 'DISABLED' })
    render()
  } catch (e) { alert(e.message) }
}

async function runControlNow () {
  showToast({ node: 'fleet', action: 'control cycle', detail: 'running…' })
  try {
    const res = await fetch('/api/control/run', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ force: true }) })
    const data = await res.json()
    if (data.error) alert(data.error)
    else showToast({ node: 'fleet', action: 'control cycle', detail: `done · ${data.cycle?.remediations?.length || 0} remediations` })
    await fetchState()
  } catch (e) { alert(e.message) }
}

async function stabilizeAll () {
  if (!confirm('Install health watchdog + ensure swap on all reachable nodes?')) return
  showToast({ node: 'fleet', action: 'stabilize-all', detail: 'running…' })
  try {
    const res = await fetch('/api/control/stabilize-all', { method: 'POST' })
    const data = await res.json()
    if (data.error) alert(data.error)
    else {
      const ok = (data.results || []).filter(r => r.ok).length
      showToast({ node: 'fleet', action: 'stabilize-all', detail: `${ok} nodes ok` })
    }
    await fetchState()
  } catch (e) { alert(e.message) }
}

function renderKPIs (s) {
  return `<div class="kpis">
    <div class="kpi neutral"><div class="kpi-value">${s.total}</div><div class="kpi-label">Nodes</div></div>
    <div class="kpi success"><div class="kpi-value">${s.healthy}</div><div class="kpi-label">Healthy</div></div>
    <div class="kpi warning"><div class="kpi-value">${s.degraded}</div><div class="kpi-label">Degraded</div></div>
    <div class="kpi critical"><div class="kpi-value">${s.offline}</div><div class="kpi-label">Offline</div></div>
    <div class="kpi success"><div class="kpi-value">${s.running}</div><div class="kpi-label">Relay Active</div></div>
    <div class="kpi neutral"><div class="kpi-value">${fmtBytes(s.totalDiskGB * 1e9)}</div><div class="kpi-label">Total Disk</div></div>
    <div class="kpi neutral"><div class="kpi-value">${s.totalRamGB} GB</div><div class="kpi-label">Total RAM</div></div>
  </div>`
}

function renderRegions (regions) {
  if (!regions) return ''
  return `<div class="regions">${Object.entries(regions).map(([code, r]) => `
    <div class="region-card"><div class="region-name">${REGION_NAMES[code] || code}</div>
    <div class="region-stats"><span class="up">${r.healthy} up</span>${r.degraded ? `<span class="deg">${r.degraded} deg</span>` : ''}${r.offline ? `<span class="down">${r.offline} down</span>` : ''}<span class="total">${r.total}</span></div></div>`).join('')}</div>`
}

function renderNodeTable (nodes) {
  const sorted = [...nodes].sort((a, b) => {
    const order = { offline: 3, degraded: 2, healthy: 1 }
    return (order[a.status] || 3) - (order[b.status] || 3) || a.name.localeCompare(b.name)
  })
  return `
      <div class="section">
        <div class="section-title">All Nodes <span class="count">${nodes.length}</span> <button class="btn add-btn" onclick="showAddRelay()">+ Add Relay</button></div>
  <table class="tbl"><thead><tr>
    <th></th><th>Node</th><th>Address</th><th>Version</th><th>Relay</th>
    <th>Disk</th><th>Mem</th><th>RAM%</th><th>Load</th><th>Apps</th><th>Conns</th>
    <th>WD</th><th>Services</th><th>Channel</th><th>Region</th><th>Spec</th>
  </tr></thead><tbody>
  ${sorted.map(n => renderRow(n)).join('')}
  ${expandedNode ? renderDetailRow(sorted.find(n => n.name === expandedNode)) : ''}
  </tbody></table></div>`
}

function renderRow (n) {
  const isExpanded = expandedNode === n.name
  const verOk = n.version && n.version !== 'none' && n.targetVersion && n.version === n.targetVersion
  const svcCount = n.features?.services?.count || n.services?.length || 0
  const wdOk = n.watchdog === 'enabled'
  const mem = n.memCurrentMB
  return `<tr class="${n.status} ${isExpanded ? 'expanded' : ''}" onclick="toggleDetail('${esc(n.name)}')">
    <td><span class="chevron ${isExpanded ? 'open' : ''}">&#9654;</span></td>
    <td><span class="indicator"><span class="dot ${n.status}"></span></span> <strong>${esc(n.name)}</strong></td>
    <td class="mono">${esc(n.publicIp)}</td>
    <td class="${verOk ? 'version-ok' : 'version-bad'} mono-val">${esc(n.version || '—')}</td>
    <td>${n.running && n.healthOk !== false ? '<span class="ok-text">running</span>' : (n.running ? '<span class="err-text">hung?</span>' : '<span class="err-text">stopped</span>')}</td>
    <td>${renderDiskBar(n)}</td>
    <td class="mono-val">${mem != null ? mem + 'M' : '—'}</td>
    <td>${renderRamBar(n)}</td>
    <td class="mono">${n.loadAvg != null ? Number(n.loadAvg).toFixed(2) : '—'}</td>
    <td class="mono-val">${n.seededApps || '—'}</td>
    <td class="mono-val">${n.connections || '—'}</td>
    <td>${wdOk ? '<span class="ok-text">on</span>' : '<span class="err-text">off</span>'}</td>
    <td>${svcCount ? `<span class="svc-count">${svcCount}</span>` : '—'}</td>
    <td><span class="badge ${esc(n.channel || 'stable')}">${esc(n.channel || 'stable')}</span></td>
    <td>${esc(n.region || '—')}</td>
    <td class="mono">${n.vcpu || '?'}c/${n.ramGB || '?'}G/${n.diskGB || '?'}G</td>
  </tr>`
}

function renderDetailRow (n) {
  if (!n) return ''
  const f = n.features || {}
  const offline = n.status === 'offline'

  return `<tr class="detail-row"><td colspan="16"><div class="detail-panel">
    <div class="detail-grid">
      <div class="detail-col">
        <div class="detail-section-title">Features & Services</div>
        <div class="feature-grid">
          ${Object.entries(FEATURE_LABELS).map(([key, label]) => {
            const feat = f[key] || {}
            const isOn = feat.enabled === true
            const canToggle = TOGGLEABLE.includes(key) && !offline
            return `<div class="feature-item ${isOn ? 'on' : 'off'}">
              <span class="feat-status ${isOn ? 'on' : 'off'}">${isOn ? 'ON' : 'OFF'}</span>
              <span class="feat-label">${label}</span>
              ${feat.running != null ? `<span class="feat-extra">${feat.running ? 'running' : 'stopped'}</span>` : ''}
              ${feat.count != null ? `<span class="feat-extra">${feat.count} svc</span>` : ''}
              ${feat.coresSeeded != null ? `<span class="feat-extra">${feat.coresSeeded} cores</span>` : ''}
              ${canToggle ? `<button class="feat-toggle ${isOn ? 'off' : 'on'}" onclick="toggleFeature('${esc(n.name)}','${key}',${!isOn})">${isOn ? 'Disable' : 'Enable'}</button>` : ''}
            </div>`
          }).join('')}
        </div>
      </div>
      <div class="detail-col">
        <div class="detail-section-title">Runtime Stats</div>
        <div class="stats-grid">
          ${renderStat('Version', n.version)}
          ${renderStat('Target', n.targetVersion)}
          ${renderStat('Uptime since', n.uptime)}
          ${renderStat('Restarts', n.restarts)}
          ${renderStat('Memory', n.memCurrentMB != null ? n.memCurrentMB + ' MB' : '—')}
          ${renderStat('Tasks', n.tasks)}
          ${renderStat('Swap', n.swapMB ? n.swapMB + ' MB' : 'none')}
          ${renderStat('Apps seeded', n.seededApps)}
          ${renderStat('Connections', n.connections)}
          ${renderStat('Cores seeded', n.features?.seeding?.coresSeeded)}
          ${renderStat('Bytes served', n.bytesServed ? fmtBytes(n.bytesServed) : '—')}
          ${renderStat('Blocks served', n.blocksServed)}
        </div>

        ${n.services && n.services.length > 0
? `
        <div class="detail-section-title" style="margin-top:16px">Service Layer (${n.services.length})</div>
        <div class="svc-list">
          ${n.services.map(s => `<div class="svc-item"><span class="svc-name">${esc(s.name)}</span><span class="svc-ver">v${esc(s.version)}</span><span class="svc-caps">${(s.capabilities || []).length} caps</span></div>`).join('')}
        </div>`
: ''}

        ${n.transports
? `
        <div class="detail-section-title" style="margin-top:16px">Transports</div>
        <div class="stats-grid">
          ${renderTransport('DHT WS', n.transports.dhtRelayWs)}
          ${renderTransport('Tor', n.transports.tor)}
          ${renderTransport('Holesail', n.transports.holesail)}
        </div>`
: ''}
      </div>
      <div class="detail-col">
        <div class="detail-section-title">Controls</div>
        <div class="control-list">
          <button class="ctrl-btn" onclick="nodeAction('${esc(n.name)}','restart')" ${offline ? 'disabled' : ''}>Restart Relay</button>
          <button class="ctrl-btn" onclick="nodeAction('${esc(n.name)}','update')" ${offline ? 'disabled' : ''}>Update (git pull + restart)</button>
          <button class="ctrl-btn" onclick="nodeAction('${esc(n.name)}','doctor')" ${offline ? 'disabled' : ''}>Doctor (swap + locks + cleanup)</button>
        </div>

        <div class="detail-section-title" style="margin-top:16px">Environment</div>
        <div class="env-list">
          ${Object.entries(n.env || {}).map(([k, v]) => `<div class="env-item"><span class="env-key">${esc(k)}</span><span class="env-val">${esc(k.includes('KEY') ? '[redacted]' : v)}</span></div>`).join('') || '<div class="env-empty">No env vars</div>'}
        </div>
      </div>
    </div>
  </div></td></tr>`
}

function renderStat (label, value) {
  return `<div class="stat-item"><span class="stat-label">${esc(label)}</span><span class="stat-value">${esc(value != null ? value : '—')}</span></div>`
}

function renderTransport (name, t) {
  if (!t) return `<div class="stat-item"><span class="stat-label">${name}</span><span class="stat-value">disabled</span></div>`
  return `<div class="stat-item"><span class="stat-label">${name}</span><span class="stat-value">${t.running ? 'running' : 'stopped'} ${t.activeConnections != null ? `(${t.activeConnections} active)` : ''}</span></div>`
}

function renderActionLog (actions) {
  if (!actions || actions.length === 0) return ''
  return `<div class="section"><div class="section-title">Action Log <span class="count">last ${Math.min(actions.length, 10)}</span></div>
  <div class="action-log">${actions.slice(0, 10).map(a => `<div class="action-item"><span class="action-time">${new Date(a.timestamp).toLocaleTimeString()}</span><span class="action-node">${esc(a.node)}</span><span class="action-type">${esc(a.action)}</span><span class="action-detail">${esc(a.detail || '')}</span></div>`).join('')}</div></div>`
}

function renderDiskBar (n) {
  if (n.diskPct == null) return '—'
  const pct = Math.min(n.diskPct, 100)
  const cls = n.diskPct > 85 ? 'crit' : n.diskPct > 70 ? 'warn' : 'norm'
  const totalGB = n.diskGB || 0
  const usedGB = Math.round(totalGB * n.diskPct / 100)
  const freeGB = totalGB - usedGB
  const title = `${usedGB} GB used / ${freeGB} GB free / ${totalGB} GB total`
  return `<div class="bar-cell" title="${title}"><span class="bar"><span class="fill ${cls}" style="width:${pct}%"></span></span><span class="bar-pct">${n.diskPct}%</span></div>`
}

function renderRamBar (n) {
  if (n.ramUsedPct == null) return '—'
  const pct = Math.min(n.ramUsedPct, 100)
  const cls = n.ramUsedPct > 85 ? 'crit' : n.ramUsedPct > 70 ? 'warn' : 'norm'
  const totalGB = n.ramGB || 0
  const usedGB = (totalGB * n.ramUsedPct / 100).toFixed(1)
  const title = `${usedGB} GB used / ${totalGB} GB total`
  return `<div class="bar-cell" title="${title}"><span class="bar ram"><span class="fill ${cls}" style="width:${pct}%"></span></span><span class="bar-pct">${n.ramUsedPct}%</span></div>`
}

function toggleDetail (name) { expandedNode = expandedNode === name ? null : name; render() }

async function nodeAction (name, action) {
  if (!confirm(`${action} on ${name}?`)) return
  try {
    showToast({ node: name, action, detail: 'executing...' })
    const res = await fetch(`/api/node/${name}/${action}`, { method: 'POST' })
    const data = await res.json()
    if (data.error) alert(data.error)
    else showToast({ node: name, action, detail: 'completed' })
    await fetchState()
  } catch (e) { alert(e.message) }
}

async function toggleFeature (name, feature, enabled) {
  if (!confirm(`${enabled ? 'Enable' : 'Disable'} ${feature} on ${name}?`)) return
  try {
    showToast({ node: name, action: `${enabled ? 'enable' : 'disable'} ${feature}`, detail: 'applying...' })
    const res = await fetch(`/api/node/${name}/toggle`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ feature, enabled }) })
    const data = await res.json()
    if (data.error) alert(data.error)
    await fetchState()
  } catch (e) { alert(e.message) }
}

async function reprobe () { try { await fetch('/api/reprobe', { method: 'POST' }) } catch {} }

// --- Add Relay ---
function showAddRelay () {
  const overlay = document.createElement('div')
  overlay.className = 'modal-overlay active'
  overlay.id = 'modal-add-relay'
  overlay.innerHTML = `
    <div class="modal">
      <h2>Add Relay to Fleet</h2>
      <div class="modal-field"><label>Name</label><input type="text" id="relay-name" placeholder="e.g. tokyo-1"></div>
      <div class="modal-field"><label>IP Address</label><input type="text" id="relay-ip" placeholder="1.2.3.4"></div>
      <div class="modal-field">
        <label>SSH Key</label>
        <select id="relay-key">
          <option value="~/.ssh/cloudzy_hiverelay">cloudzy_hiverelay</option>
          <option value="~/.ssh/id_ed25519">id_ed25519 (utah/dubai)</option>
          <option value="~/.ssh/hiverelay_fleet">hiverelay_fleet</option>
        </select>
      </div>
      <div class="modal-field-row">
        <div class="modal-field"><label>Region</label>
          <select id="relay-region">
            <option value="NA">North America</option>
            <option value="EU">Europe</option>
            <option value="APAC">Asia-Pacific</option>
            <option value="ME">Middle East</option>
          </select>
        </div>
        <div class="modal-field"><label>Channel</label>
          <select id="relay-channel">
            <option value="stable">stable</option>
            <option value="canary">canary</option>
          </select>
        </div>
      </div>
      <div class="modal-field-row">
        <div class="modal-field"><label>vCPU</label><input type="number" id="relay-vcpu" value="1" min="1" max="16"></div>
        <div class="modal-field"><label>RAM (GB)</label><input type="number" id="relay-ram" value="2" step="0.5"></div>
        <div class="modal-field"><label>Disk (GB)</label><input type="number" id="relay-disk" value="60"></div>
      </div>
      <div class="modal-actions">
        <button class="btn ghost" onclick="closeModal()">Cancel</button>
        <button class="btn primary" onclick="submitAddRelay()">Add & Probe</button>
      </div>
    </div>`
  document.body.appendChild(overlay)
}

function closeModal () {
  const m = document.getElementById('modal-add-relay')
  if (m) m.remove()
}

async function submitAddRelay () {
  const relay = {
    name: document.getElementById('relay-name').value.trim(),
    publicIp: document.getElementById('relay-ip').value.trim(),
    sshKey: document.getElementById('relay-key').value,
    region: document.getElementById('relay-region').value,
    channel: document.getElementById('relay-channel').value,
    vcpu: parseInt(document.getElementById('relay-vcpu').value) || 1,
    ramGB: parseFloat(document.getElementById('relay-ram').value) || 2,
    diskGB: parseInt(document.getElementById('relay-disk').value) || 60
  }
  if (!relay.name || !relay.publicIp) { alert('Name and IP required'); return }
  closeModal()
  showToast({ node: relay.name, action: 'add relay', detail: 'adding...' })
  try {
    const res = await fetch('/api/relay', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(relay) })
    const data = await res.json()
    if (data.error) { alert(data.error); return }
    showToast({ node: relay.name, action: 'add relay', detail: 'added' })
    await fetchState()
  } catch (e) { alert(e.message) }
}

function showToast (data) {
  const el = document.createElement('div')
  el.className = 'toast'
  el.innerHTML = `<strong>${esc(data.node)}</strong> · ${esc(data.action)} · ${esc(data.detail || '')}`
  document.getElementById('toast-container')?.appendChild(el)
  setTimeout(() => el.remove(), 5000)
}

Object.assign(globalThis, {
  setAutoControl,
  runControlNow,
  stabilizeAll,
  toggleDetail,
  nodeAction,
  toggleFeature,
  reprobe,
  showAddRelay,
  submitAddRelay
})

fetchState().then(() => connectSSE())
