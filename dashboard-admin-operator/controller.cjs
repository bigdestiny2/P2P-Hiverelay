'use strict'

/**
 * Fleet control plane — evaluate healthy ranges + auto-remediate.
 * Called after each probe cycle when policy.autoControl is true.
 */

const fs = require('fs')

function defaultPolicy () {
  return {
    autoControl: true,
    cooldownsSec: { forceRestart: 480, doctor: 1800, ensureBaseline: 3600, ensureSwap: 7200 },
    global: {
      requireHealthOk: true,
      requireRunning: true,
      requireWatchdog: true,
      minSwapMB: 256,
      diskPctWarn: 75,
      diskPctCritical: 90,
      forceRestartOnDegraded: true,
      forceRestartOnHung: true,
      maxConcurrentRemediations: 3
    },
    tiers: {
      small: { ramGBMax: 1.1, memMBMax: 300, memMBWarn: 240, diskPctMax: 85 },
      medium: { ramGBMin: 1.1, ramGBMax: 4, memMBMax: 1600, memMBWarn: 1200, diskPctMax: 85 },
      large: { ramGBMin: 4, memMBMax: 4800, memMBWarn: 3500, diskPctMax: 90 }
    }
  }
}

function loadPolicy (policyPath) {
  try {
    if (fs.existsSync(policyPath)) {
      return { ...defaultPolicy(), ...JSON.parse(fs.readFileSync(policyPath, 'utf8')) }
    }
  } catch (e) {
    console.error('[controller] policy load failed:', e.message)
  }
  return defaultPolicy()
}

function savePolicy (policyPath, policy) {
  const out = { ...policy }
  delete out._loadedAt
  fs.writeFileSync(policyPath, JSON.stringify(out, null, 2) + '\n')
}

function tierFor (node, policy) {
  const ram = Number(node.ramGB) || 2
  const tiers = policy.tiers || {}
  if (ram <= (tiers.small?.ramGBMax ?? 1.1)) return { name: 'small', ...tiers.small }
  if (ram < (tiers.large?.ramGBMin ?? 4)) return { name: 'medium', ...tiers.medium }
  return { name: 'large', ...tiers.large }
}

/**
 * @returns {{ violations: object[], actions: object[] }}
 */
function evaluateNode (node, policy) {
  const violations = []
  const tier = tierFor(node, policy)
  const g = policy.global || {}

  if (node.status === 'offline') {
    if (node.reachable) {
      violations.push({ code: 'degraded_ssh_ok', severity: 'critical', msg: 'SSH ok but probe failed', auto: 'forceRestart' })
    } else {
      violations.push({ code: 'offline', severity: 'critical', msg: 'SSH unreachable', auto: null })
    }
    return { violations, tier: tier.name, actions: suggestActions(violations) }
  }

  // healthOk from enhanced probe; fall back to running/status
  const healthOk = node.healthOk === true || (node.running === true && node.status === 'healthy')
  if (g.requireHealthOk && !healthOk) {
    violations.push({ code: 'health_fail', severity: 'critical', msg: ' /health not ok', auto: 'forceRestart' })
  }
  if (g.requireRunning && node.running !== true && healthOk) {
    // still warming or status lag — soft
    if (node.status === 'degraded') {
      violations.push({ code: 'not_running', severity: 'warning', msg: 'process not fully running', auto: 'forceRestart' })
    }
  }
  if (node.status === 'degraded' && g.forceRestartOnDegraded) {
    if (!violations.some(v => v.code === 'health_fail' || v.code === 'not_running')) {
      violations.push({ code: 'degraded', severity: 'critical', msg: 'node marked degraded', auto: 'forceRestart' })
    }
  }

  const mem = Number(node.memCurrentMB) || 0
  if (mem > 0 && tier.memMBMax && mem > tier.memMBMax) {
    violations.push({
      code: 'mem_over_max',
      severity: 'critical',
      msg: `mem ${mem}MB > tier max ${tier.memMBMax}MB (${tier.name})`,
      auto: 'forceRestart'
    })
  } else if (mem > 0 && tier.memMBWarn && mem > tier.memMBWarn) {
    violations.push({
      code: 'mem_warn',
      severity: 'warning',
      msg: `mem ${mem}MB > warn ${tier.memMBWarn}MB (${tier.name})`,
      auto: null
    })
  }

  const disk = Number(node.diskPct) || 0
  if (disk >= (g.diskPctCritical || 90)) {
    violations.push({ code: 'disk_critical', severity: 'critical', msg: `disk ${disk}%`, auto: 'doctor' })
  } else if (disk >= (g.diskPctWarn || 75) || (tier.diskPctMax && disk >= tier.diskPctMax)) {
    violations.push({ code: 'disk_warn', severity: 'warning', msg: `disk ${disk}%`, auto: null })
  }

  const swap = Number(node.swapMB) || 0
  if (g.minSwapMB != null && swap < g.minSwapMB) {
    violations.push({ code: 'no_swap', severity: 'warning', msg: `swap ${swap}MB < ${g.minSwapMB}MB`, auto: 'ensureSwap' })
  }

  if (g.requireWatchdog && node.watchdog !== 'enabled' && node.watchdog !== true) {
    violations.push({ code: 'no_watchdog', severity: 'warning', msg: 'health watchdog timer missing', auto: 'ensureBaseline' })
  }

  return { violations, tier: tier.name, actions: suggestActions(violations) }
}

function suggestActions (violations) {
  const seen = new Set()
  const actions = []
  for (const v of violations) {
    if (v.auto && !seen.has(v.auto)) {
      seen.add(v.auto)
      actions.push({ type: v.auto, reason: v.code, severity: v.severity })
    }
  }
  // prefer forceRestart first
  actions.sort((a, b) => {
    const order = { forceRestart: 0, doctor: 1, ensureSwap: 2, ensureBaseline: 3 }
    return (order[a.type] ?? 9) - (order[b.type] ?? 9)
  })
  return actions
}

function evaluateFleet (nodes, policy) {
  const results = []
  for (const n of nodes) {
    const ev = evaluateNode(n, policy)
    results.push({
      name: n.name,
      status: n.status,
      tier: ev.tier,
      violations: ev.violations,
      actions: ev.actions,
      memCurrentMB: n.memCurrentMB,
      diskPct: n.diskPct,
      swapMB: n.swapMB,
      watchdog: n.watchdog,
      healthOk: n.healthOk,
      running: n.running
    })
  }
  const critical = results.filter(r => r.violations.some(v => v.severity === 'critical')).length
  const warnings = results.filter(r => r.violations.some(v => v.severity === 'warning') && !r.violations.some(v => v.severity === 'critical')).length
  const inRange = results.filter(r => r.violations.length === 0 && r.status === 'healthy').length
  return {
    evaluatedAt: new Date().toISOString(),
    nodes: results,
    summary: {
      total: results.length,
      inRange,
      critical,
      warnings,
      offline: results.filter(r => r.status === 'offline').length
    }
  }
}

/** Remote shell snippets for remediation */
const REMOTE = {
  forceRestart: [
    'set +e',
    'systemctl kill -s SIGKILL hiverelay 2>/dev/null',
    'systemctl stop hiverelay 2>/dev/null',
    'fuser -k -9 9100/tcp 2>/dev/null',
    'sleep 2',
    'systemctl reset-failed hiverelay 2>/dev/null',
    'systemctl start hiverelay',
    'for i in $(seq 1 20); do',
    '  sleep 3',
    '  H=$(curl -sS --max-time 4 http://127.0.0.1:9100/health 2>/dev/null)',
    '  if echo "$H" | grep -q ok; then echo RESTART_OK; exit 0; fi',
    'done',
    'echo RESTART_PENDING',
    'exit 0'
  ].join('\n'),

  doctor: [
    'set +e',
    'echo "=== doctor ==="',
    'SW=$(free -m | awk "/Swap/{print \\$2}")',
    // Shell parameter expansion, not a JavaScript template placeholder.
    // eslint-disable-next-line no-template-curly-in-string
    'if [ "${SW:-0}" = "0" ]; then',
    '  fallocate -l 2G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=2048',
    '  chmod 600 /swapfile; mkswap /swapfile; swapon /swapfile',
    '  grep -q /swapfile /etc/fstab || echo "/swapfile none swap sw 0 0" >> /etc/fstab',
    '  sysctl -w vm.swappiness=10 >/dev/null',
    'fi',
    'rm -f /root/.hiverelay/storage/*.lock 2>/dev/null',
    'journalctl --vacuum-size=80M 2>/dev/null',
    'df -h / | tail -1',
    'echo DOCTOR_OK'
  ].join('\n'),

  ensureSwap: [
    'set +e',
    'if [ "$(swapon --show --noheadings 2>/dev/null | wc -l)" -eq 0 ]; then',
    '  fallocate -l 2G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=2048',
    '  chmod 600 /swapfile; mkswap /swapfile; swapon /swapfile',
    '  grep -q /swapfile /etc/fstab || echo "/swapfile none swap sw 0 0" >> /etc/fstab',
    '  sysctl -w vm.swappiness=10 >/dev/null',
    '  echo SWAP_ADDED',
    'else',
    '  echo SWAP_PRESENT',
    'fi'
  ].join('\n'),

  ensureBaseline: [
    'set +e',
    '# health watchdog install (inline)',
    'if [ ! -f /usr/local/bin/hiverelay-health-watchdog.sh ]; then',
    '  cat > /usr/local/bin/hiverelay-health-watchdog.sh << "WATCH"',
    '#!/usr/bin/env bash',
    'set -uo pipefail',
    // Shell parameter expansions, not JavaScript template placeholders.
    // eslint-disable-next-line no-template-curly-in-string
    'URL="${HIVERELAY_HEALTH_URL:-http://127.0.0.1:9100/health}"',
    // eslint-disable-next-line no-template-curly-in-string
    'TIMEOUT="${HIVERELAY_HEALTH_TIMEOUT:-5}"',
    // eslint-disable-next-line no-template-curly-in-string
    'NEED_FAILS="${HIVERELAY_HEALTH_FAILS:-2}"',
    'STATE_FILE=/run/hiverelay-health-watchdog.failcount',
    'UNIT=hiverelay',
    'active=$(systemctl is-active "$UNIT" 2>/dev/null || echo inactive)',
    '[ "$active" = "active" ] || [ "$active" = "activating" ] || { echo 0 >"$STATE_FILE"; exit 0; }',
    'body=$(curl -fsS --max-time "$TIMEOUT" "$URL" 2>/dev/null || true)',
    'if echo "$body" | grep -q \'"ok"[[:space:]]*:[[:space:]]*true\'; then echo 0 >"$STATE_FILE"; exit 0; fi',
    'fails=0; [ -f "$STATE_FILE" ] && fails=$(cat "$STATE_FILE" 2>/dev/null || echo 0)',
    'fails=$((fails+1)); echo "$fails" >"$STATE_FILE"',
    '[ "$fails" -lt "$NEED_FAILS" ] && exit 0',
    'systemctl kill -s SIGKILL "$UNIT" 2>/dev/null; sleep 1; fuser -k -9 9100/tcp 2>/dev/null; sleep 1',
    'systemctl reset-failed "$UNIT" 2>/dev/null; systemctl start "$UNIT" 2>/dev/null',
    'echo 0 >"$STATE_FILE"',
    'WATCH',
    '  chmod 0755 /usr/local/bin/hiverelay-health-watchdog.sh',
    'fi',
    'cat > /etc/systemd/system/hiverelay-health-watchdog.service << "EOF"',
    '[Unit]',
    'Description=HiveRelay health watchdog',
    '[Service]',
    'Type=oneshot',
    'ExecStart=/usr/local/bin/hiverelay-health-watchdog.sh',
    'TimeoutStartSec=30',
    'EOF',
    'cat > /etc/systemd/system/hiverelay-health-watchdog.timer << "EOF"',
    '[Unit]',
    'Description=HiveRelay health watchdog every 2m',
    '[Timer]',
    'OnBootSec=3min',
    'OnUnitActiveSec=2min',
    'AccuracySec=30s',
    'Persistent=true',
    'Unit=hiverelay-health-watchdog.service',
    '[Install]',
    'WantedBy=timers.target',
    'EOF',
    'mkdir -p /etc/systemd/system/hiverelay.service.d',
    'cat > /etc/systemd/system/hiverelay.service.d/stabilize-restart.conf << "EOF"',
    '[Service]',
    'Restart=always',
    'RestartSec=15',
    'TimeoutStopSec=12',
    'KillMode=mixed',
    'FinalKillSignal=SIGKILL',
    'SendSIGKILL=yes',
    'EOF',
    'systemctl daemon-reload',
    'systemctl enable --now hiverelay-health-watchdog.timer 2>/dev/null',
    'echo BASELINE_OK'
  ].join('\n')
}

function createController ({ policyPath, sshAction, logAction, probeNode, loadRelays }) {
  let policy = loadPolicy(policyPath)
  policy._loadedAt = new Date().toISOString()
  const lastActionAt = new Map() // key: `${node}:${type}` -> epoch ms
  let lastCycle = null
  let controlling = false

  function cooldownOk (node, type) {
    const sec = (policy.cooldownsSec && policy.cooldownsSec[type]) || 600
    const key = `${node}:${type}`
    const prev = lastActionAt.get(key) || 0
    return Date.now() - prev >= sec * 1000
  }

  function markAction (node, type) {
    lastActionAt.set(`${node}:${type}`, Date.now())
  }

  function getPolicy () { return policy }

  function setAutoControl (enabled) {
    policy.autoControl = !!enabled
    try { savePolicy(policyPath, policy) } catch {}
    logAction('fleet', 'auto-control', enabled ? 'ENABLED' : 'DISABLED')
    return policy.autoControl
  }

  function reloadPolicy () {
    policy = loadPolicy(policyPath)
    policy._loadedAt = new Date().toISOString()
    return policy
  }

  /**
   * Run evaluation + optional auto-remediation against current fleetState nodes.
   * @param {object[]} nodes
   */
  async function runControlCycle (nodes, { force = false } = {}) {
    if (controlling) return lastCycle
    controlling = true
    try {
      const evaluation = evaluateFleet(nodes, policy)
      const remediations = []
      const auto = force || policy.autoControl
      const maxN = policy.global?.maxConcurrentRemediations || 3

      if (auto) {
        const plan = []
        for (const r of evaluation.nodes) {
          for (const a of r.actions) {
            if (!cooldownOk(r.name, a.type)) continue
            plan.push({ name: r.name, ...a })
          }
        }
        // one action per node, critical first
        const byNode = new Map()
        for (const p of plan) {
          if (!byNode.has(p.name)) byNode.set(p.name, p)
        }
        const batch = [...byNode.values()].slice(0, maxN)
        const relays = loadRelays()

        await Promise.all(batch.map(async (p) => {
          const relay = relays.find(x => x.name === p.name)
          if (!relay) return
          const cmd = REMOTE[p.type]
          if (!cmd) return
          try {
            logAction(p.name, `auto:${p.type}`, `reason=${p.reason}`)
            markAction(p.name, p.type)
            const out = await sshAction(relay, cmd, `auto:${p.type}`)
            remediations.push({ node: p.name, type: p.type, reason: p.reason, ok: true, detail: String(out).slice(0, 200) })
            // re-probe node after remediation
            try {
              const updated = await probeNode(relay)
              const idx = nodes.findIndex(n => n.name === p.name)
              if (idx >= 0) nodes[idx] = updated
            } catch {}
          } catch (err) {
            remediations.push({ node: p.name, type: p.type, reason: p.reason, ok: false, detail: err.message?.slice(0, 200) })
          }
        }))
      }

      // re-evaluate after remediations
      const after = remediations.length ? evaluateFleet(nodes, policy) : evaluation
      lastCycle = {
        ...after,
        autoControl: !!policy.autoControl,
        remediations,
        forced: !!force
      }
      return lastCycle
    } finally {
      controlling = false
    }
  }

  function getLastCycle () { return lastCycle }

  return {
    getPolicy,
    setAutoControl,
    reloadPolicy,
    runControlCycle,
    getLastCycle,
    evaluateFleet: (nodes) => evaluateFleet(nodes, policy),
    evaluateNode: (node) => evaluateNode(node, policy),
    REMOTE
  }
}

module.exports = {
  loadPolicy,
  savePolicy,
  defaultPolicy,
  tierFor,
  evaluateNode,
  evaluateFleet,
  createController,
  REMOTE
}
