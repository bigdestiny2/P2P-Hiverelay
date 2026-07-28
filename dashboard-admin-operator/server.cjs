'use strict'

/**
 * HiveRelay · Dashboard Admin Operator
 *
 * Full fleet control plane:
 *   - Live probe (SSH /status + /health)
 *   - Healthy-range policy (memory/disk/swap/watchdog by tier)
 *   - Auto-remediation (force restart, doctor, swap, baseline watchdog)
 *   - Manual actions: restart / update / doctor / feature toggles / inventory
 *
 * Inventory:
 *   HIVERELAY_FLEET_DIR         — fleet dir (default: <repo>/fleet)
 *   HIVERELAY_FLEET_INVENTORY   — explicit relays JSON path
 *   Prefers fleet/relays.local.json when present (correct SSH keys).
 *
 * Run:
 *   npm run dashboard:admin-operator
 *   # → http://localhost:3458
 */

const http = require('http')
const crypto = require('crypto')
const { exec, execFile } = require('child_process')
const fs = require('fs')
const path = require('path')
const { createController } = require('./controller.cjs')

const INTERVAL_S = parseInt(process.env.FLEET_INTERVAL || '60', 10)
const PORT = parseInt(process.env.PORT || '3458', 10)

// This process is a fleet-root control plane: it holds every relay's SSH key and
// its endpoints restart services, run `git pull && npm install`, rewrite
// config.json and edit /etc/fstab. Treat it accordingly.
//
// It previously bound 0.0.0.0 with no authentication, which made it remote root
// on all 13 relays for anyone on the same network. Two independent guards now:
// bind loopback, and require a shared secret on every request.
const HOST = process.env.HIVERELAY_ADMIN_HOST || '127.0.0.1'
const TOKEN = process.env.HIVERELAY_ADMIN_TOKEN || crypto.randomBytes(24).toString('hex')
const TOKEN_WAS_GENERATED = !process.env.HIVERELAY_ADMIN_TOKEN

// Timing-safe compare so the token can't be recovered byte-by-byte.
function tokenOk (presented) {
  if (typeof presented !== 'string' || presented.length !== TOKEN.length) return false
  return crypto.timingSafeEqual(Buffer.from(presented), Buffer.from(TOKEN))
}

function presentedToken (req) {
  const auth = req.headers.authorization || ''
  if (auth.startsWith('Bearer ')) return auth.slice(7)
  if (req.headers['x-admin-token']) return String(req.headers['x-admin-token'])
  try {
    return new URL(req.url, 'http://localhost').searchParams.get('token') || ''
  } catch (_) {
    return ''
  }
}
const POLICY_PATH = process.env.HIVERELAY_CONTROL_POLICY
  || path.join(__dirname, 'control-policy.json')

function expandHome (p) {
  if (!p) return p
  return p.replace(/^~(?=\/|$)/, process.env.HOME || '')
}

function resolveFleetDir () {
  if (process.env.HIVERELAY_FLEET_DIR) {
    return path.resolve(expandHome(process.env.HIVERELAY_FLEET_DIR))
  }
  // <repo>/dashboard-admin-operator → <repo>/fleet
  return path.resolve(__dirname, '../fleet')
}

function resolveRelaysJson (fleetDir) {
  if (process.env.HIVERELAY_FLEET_INVENTORY) {
    return path.resolve(expandHome(process.env.HIVERELAY_FLEET_INVENTORY))
  }
  const local = path.join(fleetDir, 'relays.local.json')
  if (fs.existsSync(local)) return local
  return path.join(fleetDir, 'relays.json')
}

function loadChannels (fleetDir) {
  const p = path.join(fleetDir, 'channels.json')
  if (fs.existsSync(p)) return JSON.parse(fs.readFileSync(p, 'utf8'))
  return { stable: 'v0.24.3', canary: 'v0.25.0-rc.4' }
}

const FLEET_DIR = resolveFleetDir()
const RELAYS_JSON = resolveRelaysJson(FLEET_DIR)
const channels = loadChannels(FLEET_DIR)

let fleetState = []
let lastProbe = null
let probing = false
const sseClients = []
const actionLog = []

// --- Probe logic ----------------------------------------------------------

function loadRelays () {
  return JSON.parse(fs.readFileSync(RELAYS_JSON, 'utf8')).relays
}

// Hostname/IP allowlist, applied before any value from the inventory reaches a
// child process. Deliberately strict: letters, digits, dot, colon (IPv6) and
// hyphen. Rejects everything a shell would treat as syntax, so an inventory
// entry can never become a command even if a future call site drops execFile.
function isSafeHost (host) {
  return typeof host === 'string' && host.length > 0 && host.length <= 255 &&
    /^[A-Za-z0-9.:-]+$/.test(host)
}

function probeNode (relay) {
  return new Promise((resolve) => {
    const ip = relay.publicIp
    const keyArg = relay.sshKey && relay.sshKey !== 'default'
      ? ['-i', relay.sshKey.replace(/^~/, process.env.HOME)]
      : []

    const remote = [
      'V=$(grep -m1 \'"version"\' ~/hiverelay/package.json 2>/dev/null | tr -dc \'0-9.\' || echo \'none\')',
      'D=$(df -h / | awk \'NR==2{print $5}\' | tr -dc \'0-9\')',
      'DG=$(df -h / | awk \'NR==2{print $2}\' | tr -dc \'0-9.\')',
      'SW=$(free -m 2>/dev/null | awk \'/Swap/{print $2}\' | head -1)',
      'RM=$(free -m 2>/dev/null | awk \'/Mem/{printf "%d", $3/$2*100}\')',
      'LA=$(cat /proc/loadavg | awk \'{print $1}\')',
      'UP=$(uptime -s 2>/dev/null || echo \'?\')',
      'RT=$(systemctl show hiverelay -p NRestarts --value 2>/dev/null || echo \'?\')',
      // Prefer process RSS (MB) — MemoryCurrent cgroup often includes cache and looks multi-GB wrongly
      'PID=$(systemctl show hiverelay -p MainPID --value 2>/dev/null)',
      'MC=$(ps -o rss= -p "$PID" 2>/dev/null | awk \'{printf "%d",$1/1024}\')',
      'TS=$(systemctl show hiverelay -p TasksCurrent --value 2>/dev/null || echo \'?\')',
      'ENV=$(systemctl show hiverelay -p Environment --value 2>/dev/null | tr \'\' \';\' | tr \' \' \';\')',
      'CFG=$(cat ~/hiverelay/config.json 2>/dev/null || cat ~/.hiverelay/config.json 2>/dev/null || echo \'{}\')',
      'STATUS=$(curl -fsS --max-time 8 http://127.0.0.1:9100/status 2>/dev/null || echo \'{}\')',
      'HEALTH=$(curl -fsS --max-time 4 http://127.0.0.1:9100/health 2>/dev/null || echo \'\')',
      'WD=$(systemctl is-enabled hiverelay-health-watchdog.timer 2>/dev/null || echo missing)',
      'HO=0; echo "$HEALTH" | grep -q \'"ok"[[:space:]]*:[[:space:]]*true\' && HO=1',
      'printf \'{"version":"%s","diskPct":%s,"diskGB":%s,"swapMB":%s,"ramUsedPct":%s,"loadAvg":%s,"uptime":"%s","restarts":%s,"memCurrentMB":%s,"tasks":%s,"env":"%s","watchdog":"%s","healthOk":%s,"config":%s,"status":%s}\\n\' "$V" "${D:-0}" "${DG:-0}" "${SW:-0}" "${RM:-0}" "${LA:-0}" "$UP" "${RT:-0}" "${MC:-0}" "${TS:-0}" "$ENV" "$WD" "$HO" "$CFG" "$STATUS"'
    ].join('\n')

    // `ip` comes from the inventory, and POST /api/relay appends to that
    // inventory after validating only truthiness — so it is caller-controlled.
    // Interpolating it into a shell string made this a remote command-execution
    // sink, re-triggered every 60s by the probe interval. execFile takes an argv
    // array and spawns no shell, so the value can only ever be an argument.
    if (!isSafeHost(ip)) {
      return resolve({ ...makeOffline(relay), note: 'invalid host in inventory' })
    }

    // timeout is required: macOS nc -w is unreliable and can hang forever on dead hosts
    execFile('nc', ['-z', '-G', '3', '-w', '3', ip, '22'], { timeout: 6000 }, (tcpErr) => {
      if (tcpErr) {
        return resolve(makeOffline(relay))
      }

      const sshArgs = [
        ...keyArg,
        '-o', 'IdentitiesOnly=yes',
        '-o', 'ConnectTimeout=8',
        '-o', 'BatchMode=yes',
        '-o', 'StrictHostKeyChecking=accept-new',
        `root@${ip}`,
        remote
      ]
      execFile('ssh', sshArgs, { timeout: 25000 }, (err, stdout) => {
        if (err || !stdout || !stdout.trim().startsWith('{')) {
          return resolve({ ...makeOffline(relay), reachable: true, status: 'degraded' })
        }

        try {
          const d = JSON.parse(stdout.trim())
          const st = d.status || {}
          const health = st.health || {}
          const healthOk = d.healthOk === 1 || d.healthOk === true || health.healthy === true
          const running = st.running === true || health.healthy === true
          // Prefer health endpoint: LISTEN-but-hung nodes show degraded
          let status = 'degraded'
          if (running && healthOk) status = 'healthy'
          else if (!running && !healthOk) status = 'degraded'

          // Extract features from config + env
          const config = d.config || {}
          const env = {}
          for (const pair of (d.env || '').split(';')) {
            const [k, v] = pair.split('=')
            if (k) env[k.trim()] = (v || '').trim()
          }

          const features = extractFeatures(config, env, st)

          resolve({
            ...relay,
            status,
            reachable: true,
            version: d.version || 'none',
            running,
            healthOk,
            watchdog: d.watchdog || 'missing',
            diskPct: d.diskPct,
            diskGB: parseFloat(d.diskGB) || relay.diskGB,
            swapMB: d.swapMB,
            ramUsedPct: d.ramUsedPct,
            loadAvg: d.loadAvg,
            uptime: d.uptime,
            restarts: d.restarts,
            memCurrentMB: d.memCurrentMB,
            tasks: d.tasks,
            targetVersion: channels[relay.channel] || '?',
            probedAt: new Date().toISOString(),
            // Rich status data
            seededApps: st.seededApps,
            connections: st.connections,
            coresSeeded: st.seeder?.coresSeeded,
            bytesServed: st.served?.totalBytesServed,
            blocksServed: st.served?.totalBlocksServed,
            replication: st.replication,
            transports: st.transports,
            appRegistry: st.appRegistry,
            services: st.services?.services || [],
            payment: st.payment,
            // Config
            config,
            env,
            features
          })
        } catch {
          resolve({ ...makeOffline(relay), reachable: true, status: 'degraded' })
        }
      })
    })
  })
}

function makeOffline (relay) {
  return {
    ...relay,
    status: 'offline',
    reachable: false,
    version: null,
    running: false,
    diskPct: null,
    swapMB: null,
    ramUsedPct: null,
    loadAvg: null,
    restarts: null,
    features: {},
    config: {},
    env: {},
    services: [],
    probedAt: new Date().toISOString()
  }
}

function extractFeatures (config, env, status) {
  return {
    coreRelay: { enabled: true, running: status.running === true },
    seeding: { enabled: true, coresSeeded: status.seeder?.coresSeeded || 0 },
    services: { enabled: config.enableServices === true, count: status.services?.count || 0 },
    dhtRelayWs: { enabled: config.transports?.dhtRelayWs === true || env.HIVERELAY_DHT_RELAY_WS === '1', running: status.transports?.dhtRelayWs?.running },
    tor: { enabled: !!status.transports?.tor, running: !!status.transports?.tor },
    holesail: { enabled: !!status.transports?.holesail, running: !!status.transports?.holesail },
    outboxlog: { enabled: config.plugins?.includes('outboxlog') || env.HIVERELAY_OUTBOXLOG === '1', namespaces: config.outboxlog?.namespaces || {} },
    forwardRelay: { enabled: config.forwardRelay?.enabled === true },
    signedDirectory: { enabled: config.signedDirectory?.enabled === true },
    vrf: { enabled: (status.services?.services || []).some(s => s.name === 'vrf') },
    poker: { enabled: config.plugins?.includes('poker') === true },
    zk: { enabled: (status.services?.services || []).some(s => s.name === 'zk') },
    arbitration: { enabled: (status.services?.services || []).some(s => s.name === 'arbitration') },
    payment: { enabled: status.payment?.enabled === true, experimental: status.payment?.experimental },
    eviction: { enabled: config.eviction?.enabled === true },
    autoHeal: { enabled: true }, // from CLI flag
    distributedDrive: { enabled: status.distributedDrive?.enabled === true, available: status.distributedDrive?.moduleAvailable }
  }
}

async function probeAll () {
  if (probing) return
  probing = true
  const relays = loadRelays()
  const results = await Promise.allSettled(relays.map(r => probeNode(r)))
  fleetState = results.map((r, i) =>
    r.status === 'fulfilled' ? r.value : makeOffline(relays[i])
  )
  lastProbe = new Date().toISOString()
  probing = false
  broadcast({ type: 'fleet', data: fleetState, timestamp: lastProbe })

  // Control plane: evaluate healthy ranges + auto-remediate
  try {
    const cycle = await controller.runControlCycle(fleetState)
    if (cycle) {
      broadcast({ type: 'control', data: cycle })
      if (cycle.remediations && cycle.remediations.length) {
        // Re-broadcast fleet after remediations updated nodes in place
        broadcast({ type: 'fleet', data: fleetState, timestamp: new Date().toISOString() })
      }
    }
  } catch (err) {
    console.error('[admin-operator] control cycle error:', err.message)
  }
}

// --- Control plane --------------------------------------------------------

const controller = createController({
  policyPath: POLICY_PATH,
  sshAction: (relay, command, label) => sshAction(relay, command, label),
  logAction,
  probeNode,
  loadRelays
})

function broadcast (msg) {
  const data = `data: ${JSON.stringify(msg)}\n\n`
  for (const res of sseClients) { try { res.write(data) } catch {} }
}

function logAction (node, action, detail) {
  const entry = { node, action, detail, timestamp: new Date().toISOString() }
  actionLog.unshift(entry)
  if (actionLog.length > 100) actionLog.pop()
  broadcast({ type: 'action', data: entry })
}

// --- SSH action executor --------------------------------------------------

function sshAction (relay, command, label) {
  return new Promise((resolve, reject) => {
    const keyArg = relay.sshKey && relay.sshKey !== 'default'
      ? ['-i', relay.sshKey.replace(/^~/, process.env.HOME)]
      : []
    const fullCmd = `ssh ${keyArg.join(' ')} -o IdentitiesOnly=yes -o ConnectTimeout=12 -o BatchMode=yes -o StrictHostKeyChecking=accept-new root@${relay.publicIp} '${command.replace(/'/g, "'\\''")}' 2>&1`
    logAction(relay.name, label, 'started')
    exec(fullCmd, { timeout: 60000 }, (err, stdout, stderr) => {
      const output = (stdout || '') + (stderr || '')
      if (err) {
        logAction(relay.name, label, `FAILED: ${output.slice(0, 200)}`)
        reject(new Error(output.slice(0, 500)))
      } else {
        logAction(relay.name, label, `done: ${output.slice(0, 100)}`)
        resolve(output.trim())
      }
    })
  })
}

// --- HTTP server ----------------------------------------------------------

const server = http.createServer(async (req, res) => {
  // No wildcard CORS. A browser on any origin could otherwise drive this
  // control plane with the operator's own loopback access.
  if (req.method === 'OPTIONS') {
    res.writeHead(204, { 'access-control-allow-methods': 'GET, POST, OPTIONS', 'access-control-allow-headers': 'content-type, authorization, x-admin-token' })
    return res.end()
  }

  // Auth gate ahead of every route, including the static UI and the SSE stream:
  // the stream leaks the full inventory and action log.
  if (!tokenOk(presentedToken(req))) {
    res.writeHead(401, { 'content-type': 'application/json' })
    return res.end(JSON.stringify({ error: 'unauthorized' }))
  }

  // SSE
  if (req.url === '/api/events') {
    res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', 'connection': 'keep-alive' })
    res.write(`data: ${JSON.stringify({ type: 'fleet', data: fleetState, timestamp: lastProbe })}\n\n`)
    res.write(`data: ${JSON.stringify({ type: 'actions', data: actionLog })}\n\n`)
    sseClients.push(res)
    req.on('close', () => { const i = sseClients.indexOf(res); if (i >= 0) sseClients.splice(i, 1) })
    return
  }

  if (req.url === '/api/state') {
    const cycle = controller.getLastCycle()
    return sendJson(res, 200, {
      nodes: fleetState,
      summary: computeSummary(),
      lastProbe,
      channels,
      interval: INTERVAL_S,
      actions: actionLog.slice(0, 30),
      control: {
        autoControl: controller.getPolicy().autoControl,
        policy: controller.getPolicy(),
        lastCycle: cycle,
        inRange: cycle?.summary?.inRange,
        critical: cycle?.summary?.critical,
        warnings: cycle?.summary?.warnings
      }
    })
  }

  if (req.url === '/api/reprobe' && req.method === 'POST') {
    probeAll()
    return sendJson(res, 200, { ok: true })
  }

  // Control plane API
  if (req.url === '/api/control' && req.method === 'GET') {
    return sendJson(res, 200, {
      autoControl: controller.getPolicy().autoControl,
      policy: controller.getPolicy(),
      lastCycle: controller.getLastCycle()
    })
  }

  if (req.url === '/api/control' && req.method === 'POST') {
    try {
      const body = await readBody(req)
      if (typeof body.autoControl === 'boolean') {
        controller.setAutoControl(body.autoControl)
      }
      if (body.reload) controller.reloadPolicy()
      return sendJson(res, 200, { ok: true, autoControl: controller.getPolicy().autoControl, policy: controller.getPolicy() })
    } catch (err) {
      return sendJson(res, 400, { error: err.message })
    }
  }

  // Force a control/remediation cycle now (respects cooldowns unless forceAll)
  if (req.url === '/api/control/run' && req.method === 'POST') {
    try {
      const body = await readBody(req).catch(() => ({}))
      const cycle = await controller.runControlCycle(fleetState, { force: body.force !== false })
      broadcast({ type: 'control', data: cycle })
      broadcast({ type: 'fleet', data: fleetState, timestamp: new Date().toISOString() })
      return sendJson(res, 200, { ok: true, cycle })
    } catch (err) {
      return sendJson(res, 500, { error: err.message })
    }
  }

  // Stabilize entire fleet: ensure baseline + swap on all reachable nodes
  if (req.url === '/api/control/stabilize-all' && req.method === 'POST') {
    const relays = loadRelays()
    const results = []
    for (const relay of relays) {
      const node = fleetState.find(n => n.name === relay.name)
      if (node && node.status === 'offline' && !node.reachable) {
        results.push({ name: relay.name, skipped: true, reason: 'offline' })
        continue
      }
      try {
        await sshAction(relay, controller.REMOTE.ensureBaseline + '\n' + controller.REMOTE.ensureSwap, 'stabilize-all')
        results.push({ name: relay.name, ok: true })
      } catch (err) {
        results.push({ name: relay.name, ok: false, error: err.message?.slice(0, 200) })
      }
    }
    probeAll()
    return sendJson(res, 200, { ok: true, results })
  }

  // Add a new relay to the fleet
  if (req.url === '/api/relay' && req.method === 'POST') {
    const body = await readBody(req)
    if (!body.name || !body.publicIp) return sendJson(res, 400, { error: 'name and publicIp required' })
    // Validate at the boundary, not only at the call site. This value is
    // persisted to the inventory and then handed to ssh every 60s; a truthiness
    // check is not enough to let it become an argv element.
    if (!isSafeHost(body.publicIp)) {
      return sendJson(res, 400, { error: 'publicIp must be a hostname or IP address' })
    }
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(body.name)) {
      return sendJson(res, 400, { error: 'name must be 1-64 chars of [A-Za-z0-9._-]' })
    }

    const relays = loadRelays()
    if (relays.find(r => r.name === body.name)) {
      return sendJson(res, 409, { error: 'relay name already exists' })
    }
    if (relays.find(r => r.publicIp === body.publicIp)) {
      return sendJson(res, 409, { error: 'IP already in fleet' })
    }

    const newRelay = {
      name: body.name,
      publicIp: body.publicIp,
      tailnet: null,
      sshKey: body.sshKey || 'default',
      channel: body.channel || 'stable',
      region: body.region || 'NA',
      diskGB: body.diskGB || 60,
      ramGB: body.ramGB || 2,
      vcpu: body.vcpu || 1,
      role: body.role || 'seed'
    }
    relays.push(newRelay)
    fs.writeFileSync(RELAYS_JSON, JSON.stringify({ _doc: 'Fleet inventory. Updated via dashboard.', relays }, null, 2))
    logAction(body.name, 'add relay', `added to fleet (${body.region}, ${body.channel})`)

    // Probe the new node immediately
    const probed = await probeNode(newRelay)
    fleetState.push(probed)
    broadcast({ type: 'fleet', data: fleetState, timestamp: new Date().toISOString() })
    return sendJson(res, 200, { ok: true, relay: newRelay, state: probed })
  }

  // Remove a relay from the fleet config
  if (req.url.match(/^\/api\/relay\/[^/]+$/) && req.method === 'DELETE') {
    const nodeName = decodeURIComponent(req.url.split('/').slice(-1)[0])
    const relays = loadRelays()
    const filtered = relays.filter(r => r.name !== nodeName)
    if (filtered.length === relays.length) return sendJson(res, 404, { error: 'not found' })
    fs.writeFileSync(RELAYS_JSON, JSON.stringify({ _doc: 'Fleet inventory. Updated via dashboard.', relays: filtered }, null, 2))
    fleetState = fleetState.filter(n => n.name !== nodeName)
    broadcast({ type: 'fleet', data: fleetState, timestamp: new Date().toISOString() })
    logAction(nodeName, 'remove relay', 'removed from fleet config')
    return sendJson(res, 200, { ok: true })
  }

  // Node detail
  // Node detail (GET only — POST routes to actions below)
  const nodeMatch = req.url.match(/^\/api\/node\/([^/]+)$/)
  if (nodeMatch && req.method === 'GET') {
    const nodeName = decodeURIComponent(nodeMatch[1])
    const relay = loadRelays().find(r => r.name === nodeName)
    const state = fleetState.find(n => n.name === nodeName)
    if (!relay) return sendJson(res, 404, { error: 'node not found' })
    return sendJson(res, 200, { relay, state })
  }

  // Actions: restart, update, doctor, toggle feature
  const actionMatch = req.url.match(/^\/api\/node\/([^/]+)\/(restart|update|doctor|toggle)$/)
  if (actionMatch && req.method === 'POST') {
    const [, nodeName, action] = actionMatch
    const relay = loadRelays().find(r => r.name === nodeName)
    if (!relay) return sendJson(res, 404, { error: 'node not found' })

    try {
      if (action === 'restart') {
        await sshAction(relay, 'systemctl restart hiverelay; sleep 3; systemctl is-active hiverelay', 'restart relay')
        // Re-probe this node
        const updated = await probeNode(relay)
        const idx = fleetState.findIndex(n => n.name === nodeName)
        if (idx >= 0) fleetState[idx] = updated
        broadcast({ type: 'fleet', data: fleetState, timestamp: new Date().toISOString() })
        return sendJson(res, 200, { ok: true, state: updated })

      } else if (action === 'update') {
        const output = await sshAction(relay, 'cd ~/hiverelay && git pull --ff-only 2>&1 && npm install --production 2>&1 | tail -5 && systemctl restart hiverelay && sleep 5 && systemctl is-active hiverelay', 'update relay')
        const updated = await probeNode(relay)
        const idx = fleetState.findIndex(n => n.name === nodeName)
        if (idx >= 0) fleetState[idx] = updated
        broadcast({ type: 'fleet', data: fleetState, timestamp: new Date().toISOString() })
        return sendJson(res, 200, { ok: true, output: output.slice(0, 500), state: updated })

      } else if (action === 'doctor') {
        const cmds = [
          'echo "=== Swap ===" && free -m | grep Swap',
          'SW=$(free -m | awk "/Swap/{print $2}") && if [ "$SW" = "0" ]; then echo "Adding 2G swap..." && fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile && echo "/swapfile none swap sw 0 0" >> /etc/fstab && sysctl vm.swappiness=10; fi',
          'echo "=== Locks ===" && rm -f /root/.hiverelay/storage/*.lock 2>/dev/null && echo "cleared"',
          'echo "=== Journal ===" && journalctl --vacuum-size=50M 2>/dev/null',
          'echo "=== Disk ===" && df -h / | tail -1',
          'echo "=== Relay ===" && systemctl is-active hiverelay && curl -fsS --max-time 5 http://127.0.0.1:9100/health 2>/dev/null | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get(\'running\'))" 2>/dev/null || echo "?"'
        ].join('; ')
        const output = await sshAction(relay, cmds, 'doctor relay')
        return sendJson(res, 200, { ok: true, output })

      } else if (action === 'toggle') {
        const body = await readBody(req)
        const { feature, enabled } = body
        const result = await toggleFeature(relay, feature, enabled)
        return sendJson(res, 200, { ok: true, ...result })
      }
    } catch (err) {
      return sendJson(res, 500, { error: err.message })
    }
  }

  // Static files (Admin Operator UI)
  const publicDir = path.join(__dirname, 'public')
  const urlPath = (req.url || '/').split('?')[0]
  let filePath = path.join(publicDir, urlPath === '/' ? 'index.html' : urlPath)
  // prevent path escape
  if (!filePath.startsWith(publicDir) || !fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    filePath = path.join(publicDir, 'index.html')
  }
  serveStatic(res, filePath)
})

async function toggleFeature (relay, feature, enabled) {
  // Map feature name to config/env changes
  const featureMap = {
    dhtRelayWs: { type: 'env', envVar: 'HIVERELAY_DHT_RELAY_WS', dropin: 'dht-relay-ws' },
    outboxlog: { type: 'env', envVar: 'HIVERELAY_OUTBOXLOG', dropin: 'outboxlog', extraEnv: 'HIVERELAY_OUTBOXLOG_NAMESPACE=peerit' },
    forwardRelay: { type: 'config', path: ['forwardRelay', 'enabled'] },
    signedDirectory: { type: 'config', path: ['signedDirectory', 'enabled'] },
    services: { type: 'config', path: ['enableServices'] },
    eviction: { type: 'config', path: ['eviction', 'enabled'] }
  }

  const fm = featureMap[feature]
  if (!fm) throw new Error(`Unknown feature: ${feature}`)

  if (fm.type === 'env') {
    const dropinPath = `/etc/systemd/system/hiverelay.service.d/${fm.dropin}.conf`
    if (enabled) {
      let envLines = `Environment=${fm.envVar}=1`
      if (fm.extraEnv) envLines += `\nEnvironment=${fm.extraEnv}`
      await sshAction(relay, `mkdir -p /etc/systemd/system/hiverelay.service.d && printf '[Service]\\n${envLines}\\n' > ${dropinPath} && systemctl daemon-reload && systemctl restart hiverelay`, `enable ${feature}`)
    } else {
      await sshAction(relay, `rm -f ${dropinPath} && systemctl daemon-reload && systemctl restart hiverelay`, `disable ${feature}`)
    }
  } else if (fm.type === 'config') {
    // Edit config.json using python — creates the file if it doesn't exist
    const [section, key] = fm.path.length === 2 ? fm.path : [null, fm.path[0]]
    const valStr = enabled ? 'true' : 'false'
    const pyCode = section
      ? `d.setdefault('${section}',{})['${key}']=${valStr}`
      : `d['${key}']=${valStr}`

    await sshAction(relay,
      [
        'CFG_PATH=$( [ -f ~/hiverelay/config.json ] && echo ~/hiverelay/config.json || echo ~/.hiverelay/config.json )',
        'mkdir -p ~/.hiverelay',
        `python3 -c "import json; d=json.load(open('$CFG_PATH')) if __import__('os').path.exists('$CFG_PATH') else {}; ${pyCode}; json.dump(d, open('/tmp/cfg.json','w'), indent=2)"`,
        'cp /tmp/cfg.json "$CFG_PATH"',
        'systemctl restart hiverelay'
      ].join(' && '),
      `${enabled ? 'enable' : 'disable'} ${feature}`)
  }

  // Re-probe
  const updated = await probeNode(relay)
  const idx = fleetState.findIndex(n => n.name === relay.name)
  if (idx >= 0) fleetState[idx] = updated
  broadcast({ type: 'fleet', data: fleetState, timestamp: new Date().toISOString() })
  return { state: updated }
}

function readBody (req) {
  return new Promise((resolve, reject) => {
    let d = ''
    req.on('data', c => { d += c; if (d.length > 1e6) reject(new Error('too large')) })
    req.on('end', () => { try { resolve(JSON.parse(d)) } catch { reject(new Error('bad json')) } })
    req.on('error', reject)
  })
}

function sendJson (res, code, data) {
  const body = JSON.stringify(data)
  res.writeHead(code, { 'content-type': 'application/json', 'access-control-allow-origin': '*' })
  res.end(body)
}

function serveStatic (res, filePath) {
  const types = { '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript', '.svg': 'image/svg+xml' }
  const ct = types[path.extname(filePath)] || 'application/octet-stream'
  try {
    const data = fs.readFileSync(filePath)
    res.writeHead(200, { 'content-type': ct })
    res.end(data)
  } catch { sendJson(res, 404, { error: 'not found' }) }
}

function computeSummary () {
  const nodes = fleetState
  const totalRamGB = nodes.reduce((s, n) => s + (n.ramGB || 0), 0)
  const totalDiskGB = nodes.reduce((s, n) => s + (n.diskGB || 0), 0)
  const totalSeeded = nodes.reduce((s, n) => s + (n.seededApps || 0), 0)
  const totalConns = nodes.reduce((s, n) => s + (n.connections || 0), 0)
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
    total: nodes.length, healthy: nodes.filter(n => n.status === 'healthy').length,
    degraded: nodes.filter(n => n.status === 'degraded').length,
    offline: nodes.filter(n => n.status === 'offline').length,
    running: nodes.filter(n => n.running === true).length,
    diskWarnings: nodes.filter(n => n.diskPct && n.diskPct > 75).length,
    totalRamGB: Math.round(totalRamGB), totalDiskGB, totalSeeded, totalConns, regions
  }
}

// --- Bootstrap ------------------------------------------------------------

async function main () {
  console.log(`[admin-operator] Fleet dir: ${FLEET_DIR}`)
  console.log(`[admin-operator] Inventory: ${RELAYS_JSON}`)
  const relays = loadRelays()
  console.log(`[admin-operator] ${relays.length} nodes configured`)
  // Listen first so UI is available while the (slow) fleet probe runs
  await new Promise((resolve, reject) => {
    server.listen(PORT, HOST, () => {
      console.log(`\n  [admin-operator] Dashboard Admin Operator → http://${HOST}:${PORT}/?token=${TOKEN}\n`)
      if (TOKEN_WAS_GENERATED) {
        console.log('  [admin-operator] Generated a one-off token for this run.')
        console.log('  [admin-operator] Set HIVERELAY_ADMIN_TOKEN to pin it across restarts.\n')
      }
      if (HOST !== '127.0.0.1' && HOST !== 'localhost') {
        console.log(`  [admin-operator] WARNING: bound to ${HOST}, not loopback. This process can`)
        console.log('  [admin-operator] run commands as root on every relay in the inventory.\n')
      }
      resolve()
    })
    server.on('error', reject)
  })
  console.log(`[admin-operator] Running initial probe...`)
  await probeAll()
  const s = computeSummary()
  console.log(`[admin-operator] Done: ${s.healthy} healthy, ${s.degraded} degraded, ${s.offline} offline`)
  setInterval(() => { probeAll().catch(() => {}) }, INTERVAL_S * 1000)
  console.log(`[admin-operator] Polling every ${INTERVAL_S}s`)
}

main().catch(err => { console.error('[admin-operator] Fatal:', err); process.exit(1) })
