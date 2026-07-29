#!/usr/bin/env node

import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { resolve } from 'node:path'

const ROOT = resolve(import.meta.dirname, '..')
const NAME_RE = /^[A-Za-z0-9._-]{1,64}$/
const HOST_RE = /^(?!-)[A-Za-z0-9._:[\]-]{1,253}$/
const TAG_RE = /^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/
const PROBE_SCRIPT = readFileSync(resolve(import.meta.dirname, 'lib', 'repair-fleet-updater-probe.sh'), 'utf8')
const APPLY_SCRIPT = readFileSync(resolve(import.meta.dirname, 'lib', 'repair-fleet-updater-apply.sh'), 'utf8')

function valueAfter (args, name) {
  const index = args.indexOf(name)
  if (index === -1) return null
  if (index + 1 >= args.length) throw new Error(`${name} requires a value`)
  return args[index + 1]
}

function safeField (value) {
  return String(value ?? '?').replace(/[^\x20-\x7e]/g, '?').replace(/\|/g, '?').slice(0, 100) || '?'
}

function run (command, args, input) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    input,
    env: process.env,
    maxBuffer: 1024 * 1024
  })
  if (result.error || result.status !== 0) {
    throw new Error(`${command} failed with status ${result.status ?? 'unavailable'}`)
  }
  return result.stdout || ''
}

function sshArgs (relay) {
  const args = ['-o', 'StrictHostKeyChecking=accept-new', '-o', 'ConnectTimeout=10', '-o', 'BatchMode=yes']
  if (relay.sshKey && relay.sshKey !== 'default') args.push('-i', relay.sshKey)
  args.push(`root@${relay.tailnet || relay.publicIp}`)
  return args
}

function loadRelay (inventoryPath, relayName) {
  let inventory
  try {
    inventory = JSON.parse(readFileSync(inventoryPath, 'utf8'))
  } catch {
    throw new Error('fleet inventory is unreadable or invalid')
  }
  if (!Array.isArray(inventory.relays)) throw new Error('inventory has no relays array')
  const matches = inventory.relays.filter(relay => relay?.name === relayName)
  if (matches.length !== 1) throw new Error(`inventory must contain exactly one relay named ${relayName}`)
  const relay = matches[0]
  const host = relay.tailnet || relay.publicIp
  if (!HOST_RE.test(host || '')) throw new Error('selected relay has an invalid host')
  if (relay.sshKey && relay.sshKey !== 'default' &&
      (typeof relay.sshKey !== 'string' || relay.sshKey.length > 1024)) {
    throw new Error('selected relay has an invalid SSH key path')
  }
  const unsafeKeyPath = typeof relay.sshKey === 'string' && [...relay.sshKey].some(char => {
    const code = char.charCodeAt(0)
    return code < 32 || code === 127
  })
  if (relay.sshKey !== 'default' && unsafeKeyPath) {
    throw new Error('selected relay has an invalid SSH key path')
  }
  return relay
}

function printProbe (relayName, stdout, hash) {
  const line = stdout.split(/\r?\n/).find(entry => entry.startsWith('HIVERELAY_REPAIR_PROBE|'))
  if (!line) throw new Error('relay probe returned no structured result')
  const [, version, running, enabled, active, channel, pin, tagVerified, headMatches, healthVersion, repoClean, ready] = line.split('|')
  process.stdout.write(`${JSON.stringify({
    mode: 'dry-run',
    relay: relayName,
    updaterSha256: hash,
    current: {
      version: safeField(version),
      running: safeField(running),
      timer: `${safeField(enabled)}/${safeField(active)}`,
      channel: safeField(channel),
      pin: safeField(pin),
      healthVersion: safeField(healthVersion)
    },
    verification: {
      tagVerified: tagVerified === 'true',
      headMatches: headMatches === 'true',
      repoClean: repoClean === 'true',
      readyToApply: ready === 'true'
    },
    mutation: false
  }, null, 2)}\n`)
}

function main () {
  const args = process.argv.slice(2)
  if (args.includes('--help')) {
    process.stdout.write('Usage: node scripts/repair-fleet-updater-pin.mjs --relay <name> --pin <vX.Y.Z> [--channel stable] [--inventory path] [--apply --confirm-relay <name>]\n')
    return
  }

  const relayName = valueAfter(args, '--relay')
  const pin = valueAfter(args, '--pin')
  const channel = valueAfter(args, '--channel') || 'stable'
  const inventoryPath = resolve(valueAfter(args, '--inventory') || process.env.HIVERELAY_FLEET_INVENTORY || resolve(ROOT, 'fleet', 'relays.local.json'))
  const updaterPath = resolve(valueAfter(args, '--updater') || resolve(ROOT, 'fleet', 'updater.sh'))
  const apply = args.includes('--apply')
  const confirmation = valueAfter(args, '--confirm-relay')

  if (!NAME_RE.test(relayName || '')) throw new Error('--relay must be one exact inventory name')
  if (!TAG_RE.test(pin || '')) throw new Error('--pin must be one exact release tag')
  if (!NAME_RE.test(channel)) throw new Error('--channel is invalid')
  if (apply && confirmation !== relayName) throw new Error('--apply requires --confirm-relay to exactly repeat the relay name')

  const relay = loadRelay(inventoryPath, relayName)
  let updater
  try {
    updater = readFileSync(updaterPath)
  } catch {
    throw new Error('updater source is unreadable')
  }
  const hash = createHash('sha256').update(updater).digest('hex')
  const base = sshArgs(relay)

  if (!apply) {
    const stdout = run('ssh', [...base, 'bash', '-s', '--', pin], PROBE_SCRIPT)
    printProbe(relayName, stdout, hash)
    return
  }

  const remotePath = `/tmp/hiverelay-updater.${hash}.repair`
  const scpArgs = base.slice(0, -1)
  run('scp', [...scpArgs, updaterPath, `${base.at(-1)}:${remotePath}`])
  const stdout = run('ssh', [...base, 'bash', '-s', '--', remotePath, hash, channel, pin], APPLY_SCRIPT)
  const line = stdout.split(/\r?\n/).find(entry => entry.startsWith('HIVERELAY_REPAIR_OK|'))
  if (!line) throw new Error('relay repair returned no success proof')
  process.stdout.write(`${JSON.stringify({
    mode: 'apply',
    relay: relayName,
    updaterSha256: hash,
    pin,
    channel,
    result: safeField(line),
    applicationRestarted: false
  }, null, 2)}\n`)
}

try {
  main()
} catch (err) {
  process.stderr.write(`fleet updater pin repair: ${safeField(err?.message)}\n`)
  process.exitCode = 1
}
