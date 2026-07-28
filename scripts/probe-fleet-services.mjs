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
  const url = `http://${relay.publicIp}:9100/api/v1/services`
  const res = await fetch(url, { signal: AbortSignal.timeout(6000) })
  return { body: await res.json(), status: res.status, via: 'http' }
}

async function probeSsh (relay) {
  if (!isSafeHost(relay.publicIp)) throw new Error('unsafe host in inventory')
  const key = expandHome(relay.sshKey)
  const keyArgs = key && key !== 'default' ? ['-i', key] : []
  const { stdout } = await execFileAsync('ssh', [
    ...keyArgs,
    '-o', 'BatchMode=yes',
    '-o', 'ConnectTimeout=8',
    '-o', 'StrictHostKeyChecking=accept-new',
    `root@${relay.publicIp}`,
    'curl -fsS --max-time 6 http://127.0.0.1:9100/api/v1/services'
  ], { timeout: 25000 })
  return { body: JSON.parse(stdout), status: 200, via: 'ssh' }
}

async function probe (relay) {
  const base = { name: relay.name, region: relay.region ?? null, ramGB: relay.ramGB ?? null }
  if (!isSafeHost(relay.publicIp)) {
    return { ...base, reachable: false, error: 'unsafe host in inventory', services: [] }
  }
  for (const attempt of allowSsh ? [probeHttp, probeSsh] : [probeHttp]) {
    try {
      const { body, via } = await attempt(relay)
      // 503 {"error":"Services not enabled"} is a real answer, not a failure.
      if (body && body.error) {
        return { ...base, reachable: true, via, servicesEnabled: false, services: [], note: body.error }
      }
      const services = Array.isArray(body?.services)
        ? body.services.map(s => (typeof s === 'string' ? s : s?.name)).filter(Boolean).sort()
        : []
      return { ...base, reachable: true, via, servicesEnabled: true, services, total: body?.total ?? services.length }
    } catch (err) {
      base.error = err?.message?.slice(0, 120) || String(err)
    }
  }
  return { ...base, reachable: false, services: [] }
}

const inv = inventoryPath()
const relays = JSON.parse(readFileSync(inv, 'utf8')).relays
const results = await Promise.all(relays.map(probe))

if (asJson) {
  console.log(JSON.stringify({
    probedAt: new Date().toISOString(),
    inventory: inv,
    source: 'runtime GET /api/v1/services (not config)',
    relays: results
  }, null, 2))
} else {
  console.log(`\nRuntime service catalogue — ${relays.length} relays from ${inv}`)
  console.log('Source: GET /api/v1/services (what is LOADED, not what is configured)\n')
  const w = Math.max(...results.map(r => r.name.length), 6)
  for (const r of results) {
    const status = !r.reachable ? 'unreachable' : r.servicesEnabled === false ? 'services off' : `${r.services.length} loaded`
    const detail = !r.reachable ? (r.error || '') : r.services.join(', ') || (r.note || '')
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
  console.log()
}
