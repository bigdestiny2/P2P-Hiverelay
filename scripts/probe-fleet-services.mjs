#!/usr/bin/env node
/**
 * probe-fleet-services.mjs — what each relay is ACTUALLY running.
 *
 * The fleet's service picture has been assembled from config: from
 * `services.json`, from systemd `Environment=` lines, from what someone
 * remembers enabling. This project already learned once that config is not
 * runtime truth — the "dubai incident", where services were configured and did
 * not load, because `services.json` is the runtime authority and a plugin name
 * that does not match a registered builtin fails silently.
 *
 * So this reads the runtime instead: `GET /api/v1/services` on each relay,
 * which is the registry's own catalogue of what is loaded right now. Where the
 * HTTP API is not reachable from outside, it falls back to running the same
 * request over SSH from the box's own loopback.
 *
 * Read-only. Makes no changes, needs no auth on the read path.
 *
 * Usage:
 *   node scripts/probe-fleet-services.mjs
 *   node scripts/probe-fleet-services.mjs --json > fleet-services.json
 *   node scripts/probe-fleet-services.mjs --relays fleet/relays.local.json
 *   node scripts/probe-fleet-services.mjs --include utah,bern
 *   node scripts/probe-fleet-services.mjs --exclude sydney,dallas
 *   node scripts/probe-fleet-services.mjs --no-ssh      # HTTP only
 */

import { readFileSync, existsSync } from 'node:fs'
import { execFile } from 'node:child_process'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)
const REPO = join(dirname(fileURLToPath(import.meta.url)), '..')

const args = process.argv.slice(2)
const asJson = args.includes('--json')
const allowSsh = !args.includes('--no-ssh')
const relaysArg = args[args.indexOf('--relays') + 1]
const include = parseNameList(optionValue('--include') || process.env.HIVERELAY_FLEET_INCLUDE || '', '--include')
const exclude = parseNameList(optionValue('--exclude') || process.env.HIVERELAY_FLEET_EXCLUDE || '', '--exclude')

function optionValue (name) {
  const at = args.indexOf(name)
  if (at === -1) return ''
  const value = args[at + 1]
  if (!value || value.startsWith('--')) throw new Error(`${name} requires a value`)
  return value
}

function parseNameList (value, label) {
  if (!value) return new Set()
  if (!/^[A-Za-z0-9._-]+(?:,[A-Za-z0-9._-]+)*$/.test(value)) {
    throw new Error(`${label} must be a comma-separated relay-name list`)
  }
  return new Set(value.split(','))
}

function inventoryPath () {
  if (relaysArg && args.includes('--relays')) return relaysArg
  if (process.env.HIVERELAY_FLEET_INVENTORY) return process.env.HIVERELAY_FLEET_INVENTORY
  const local = join(REPO, 'fleet', 'relays.local.json')
  return existsSync(local) ? local : join(REPO, 'fleet', 'relays.json')
}

// Same allowlist discipline as the admin operator: inventory values become argv
// elements, so validate before they reach a child process.
function isSafeHost (host) {
  return typeof host === 'string' && host.length > 0 && host.length <= 255 &&
    /^[A-Za-z0-9.:-]+$/.test(host)
}

function expandHome (p) {
  return typeof p === 'string' ? p.replace(/^~(?=\/|$)/, process.env.HOME || '') : p
}

async function probeHttp (relay) {
  const base = `http://${relay.publicIp}:9100`
  const [services, capability] = await Promise.all([
    fetch(`${base}/api/v1/services`, { signal: AbortSignal.timeout(6000) }),
    fetch(`${base}/.well-known/hiverelay.json`, { signal: AbortSignal.timeout(6000) })
  ])
  return {
    body: await services.json(),
    capability: capability.ok ? await capability.json() : null,
    status: services.status,
    via: 'http'
  }
}

async function probeSsh (relay) {
  if (!isSafeHost(relay.publicIp)) throw new Error('unsafe host in inventory')
  const key = expandHome(relay.sshKey)
  const keyArgs = key && key !== 'default' ? ['-i', key] : []
  const remote = [
    'S=$(curl -fsS --max-time 6 http://127.0.0.1:9100/api/v1/services) || exit $?',
    'C=$(curl -fsS --max-time 6 http://127.0.0.1:9100/.well-known/hiverelay.json 2>/dev/null || printf \'{}\')',
    'printf \'%s\\n__HIVERELAY_CAP__\\n%s\\n\' "$S" "$C"'
  ].join('\n')
  const { stdout } = await execFileAsync('ssh', [
    ...keyArgs,
    '-o', 'BatchMode=yes',
    '-o', 'ConnectTimeout=8',
    '-o', 'StrictHostKeyChecking=accept-new',
    `root@${relay.publicIp}`,
    remote
  ], { timeout: 25000 })
  const parts = stdout.split('\n__HIVERELAY_CAP__\n')
  return {
    body: JSON.parse(parts[0]),
    capability: parts[1] ? JSON.parse(parts[1]) : null,
    status: 200,
    via: 'ssh'
  }
}

async function probe (relay) {
  const base = { name: relay.name, region: relay.region ?? null, ramGB: relay.ramGB ?? null }
  if (!isSafeHost(relay.publicIp)) {
    return { ...base, reachable: false, error: 'unsafe host in inventory', services: [] }
  }
  for (const attempt of allowSsh ? [probeHttp, probeSsh] : [probeHttp]) {
    try {
      const { body, capability, via } = await attempt(relay)
      // 503 {"error":"Services not enabled"} is a real answer, not a failure.
      if (body && body.error) {
        return { ...base, reachable: true, via, servicesEnabled: false, services: [], note: body.error }
      }
      const services = Array.isArray(body?.services)
        ? body.services.map(s => (typeof s === 'string' ? s : s?.name)).filter(Boolean).sort()
        : []
      const serviceProfile = capability?.protocol_profile?.services || {}
      const notifyProfile = serviceProfile.notify || null
      const features = Array.isArray(capability?.features) ? capability.features : []
      const supportedTransports = Array.isArray(capability?.supported_transports) ? capability.supported_transports : []
      const privacyTransports = Array.isArray(capability?.privacyTransports) ? capability.privacyTransports : []
      const torPrivacy = privacyTransports.find(entry => entry?.network === 'tor') || null
      const notifyWatchSources = Array.isArray(notifyProfile?.watch_sources) ? notifyProfile.watch_sources : []
      return {
        ...base,
        reachable: true,
        via,
        servicesEnabled: true,
        services,
        total: body?.total ?? services.length,
        notifyLoaded: services.includes('notify'),
        notifyFeatureAdvertised: features.includes('notify-v1'),
        notifyEgressLive: notifyProfile?.egress?.live === true,
        notifyWatchSources,
        exactLaneWake: notifyWatchSources.includes('notify-outbox-lane'),
        outboxlogLoaded: services.includes('outboxlog'),
        outboxlogAdvertised: !!serviceProfile.outboxlog,
        torRuntime: supportedTransports.includes('tor'),
        torSignedReady: !!torPrivacy,
        torRestricted: torPrivacy?.auth?.mode === 'client-auth-v3',
        torNegativeProbe: torPrivacy?.negativeProbe === true,
        forwardRelayAdvertised: supportedTransports.includes('hiverelay-forward')
      }
    } catch (err) {
      base.error = safeProbeError(err)
    }
  }
  return { ...base, reachable: false, services: [] }
}

function safeProbeError (err) {
  if (err?.name === 'TimeoutError' || err?.code === 'ETIMEDOUT') return 'probe timeout'
  if (err?.code === 'ECONNREFUSED') return 'connection refused'
  if (err?.code === 'EHOSTUNREACH' || err?.code === 'ENETUNREACH') return 'host unreachable'
  if (err?.code === 'ENOENT') return 'probe command unavailable'
  return 'probe failed'
}

const inv = inventoryPath()
const inventoryLabel = inv === join(REPO, 'fleet', 'relays.json') ? 'fleet/relays.json' : 'operator inventory'
const inventoryRelays = JSON.parse(readFileSync(inv, 'utf8')).relays
const knownNames = new Set(inventoryRelays.map(relay => relay.name))
for (const name of include) {
  if (!knownNames.has(name)) throw new Error(`--include names unknown relay ${name}`)
}
const relays = inventoryRelays.filter(relay => {
  if (include.size > 0 && !include.has(relay.name)) return false
  return !exclude.has(relay.name)
})
if (relays.length === 0) throw new Error('relay scope selected no inventory entries')
const results = await Promise.all(relays.map(probe))

if (asJson) {
  console.log(JSON.stringify({
    probedAt: new Date().toISOString(),
    inventory: inventoryLabel,
    source: 'runtime GET /api/v1/services (not config)',
    relays: results
  }, null, 2))
} else {
  console.log(`\nRuntime service catalogue — ${relays.length} relays from ${inventoryLabel}`)
  console.log('Source: GET /api/v1/services (what is LOADED, not what is configured)\n')
  const w = Math.max(...results.map(r => r.name.length), 6)
  for (const r of results) {
    const status = !r.reachable ? 'unreachable' : r.servicesEnabled === false ? 'services off' : `${r.services.length} loaded`
    const wake = !r.notifyLoaded
      ? 'wake=off'
      : r.notifyEgressLive
        ? (r.exactLaneWake ? 'wake=live+exact-lane' : 'wake=live+direct')
        : r.notifyFeatureAdvertised
          ? 'wake=misadvertised-no-egress'
          : 'wake=loaded-not-live'
    const mailbox = r.outboxlogLoaded
      ? (r.outboxlogAdvertised ? 'mailbox=advertised' : 'mailbox=loaded-not-advertised')
      : 'mailbox=off'
    const privacy = privacyLabel(r)
    const detail = !r.reachable ? (r.error || '') : `${wake} ${mailbox} ${privacy}; ${r.services.join(', ') || (r.note || '')}`
    console.log(`  ${r.name.padEnd(w)}  ${String(r.region ?? '-').padEnd(5)} ${status.padEnd(13)} ${detail}`)
  }

  const reachable = results.filter(r => r.reachable)
  const union = [...new Set(reachable.flatMap(r => r.services))].sort()
  console.log(`\n  reachable: ${reachable.length}/${results.length}`)
  console.log(`  distinct services running across the fleet: ${union.length}${union.length ? ' — ' + union.join(', ') : ''}`)

  // The number that actually matters for diversity: a service on one box is a
  // single point of failure regardless of how many relays exist.
  const counts = new Map()
  for (const r of reachable) for (const s of r.services) counts.set(s, (counts.get(s) || 0) + 1)
  const singletons = [...counts].filter(([, n]) => n === 1).map(([s]) => s).sort()
  if (singletons.length) console.log(`  running on exactly ONE relay (SPOF): ${singletons.join(', ')}`)
  console.log(`  signed live wake egress: ${reachable.filter(r => r.notifyEgressLive).length}/${reachable.length}`)
  console.log(`  signed exact-lane wake: ${reachable.filter(r => r.exactLaneWake).length}/${reachable.length}`)
  console.log(`  unsafe legacy wake advertisements: ${reachable.filter(r => r.notifyFeatureAdvertised && !r.notifyEgressLive).length}/${reachable.length}`)
  console.log(`  advertised outbox mailbox: ${reachable.filter(r => r.outboxlogAdvertised).length}/${reachable.length}`)
  console.log(`  signed ready Tor endpoints: ${reachable.filter(r => r.torSignedReady).length}/${reachable.length}`)
  console.log(`  restricted Tor endpoints with negative proof: ${reachable.filter(r => r.torRestricted && r.torNegativeProbe).length}/${reachable.length}`)
  console.log(`  advertised one-hop forward relays: ${reachable.filter(r => r.forwardRelayAdvertised).length}/${reachable.length}`)
  console.log()
}

function privacyLabel (relay) {
  if (!relay.torRuntime) return relay.forwardRelayAdvertised ? 'privacy=forward-only' : 'privacy=clearnet'
  if (!relay.torSignedReady) return 'privacy=tor-loaded-not-ready'
  if (!relay.torRestricted) return 'privacy=tor-public-ready'
  return relay.torNegativeProbe ? 'privacy=tor-restricted-proved' : 'privacy=tor-restricted-unproved'
}
