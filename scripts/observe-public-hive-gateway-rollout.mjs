#!/usr/bin/env node

import { constants as fsConstants } from 'node:fs'
import { open } from 'node:fs/promises'
import { spawn } from 'node:child_process'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const scriptDir = path.dirname(fileURLToPath(import.meta.url))
const defaultChecker = path.join(scriptDir, 'check-fleet-rollout.mjs')
const MAX_STATE_BYTES = 16 * 1024 * 1024
const usage = `
Usage:
  node scripts/observe-public-hive-gateway-rollout.mjs [observer options] -- <fleet:check-rollout options>

Observer options:
  --sample-interval-ms <ms>  Delay after an observing sample (default: 60000)
  --max-runtime-ms <ms>      Overall observer budget (default: 691200000 / 8 days)
  --checker <absolute-path>  Alternate checker script (fixtures/tests only)
  --help                     Show this help

The forwarded checker options must include the manifest, remote evidence,
window state, output evidence, pinned known_hosts, allowed_signers, target,
and channel=canary. Exit 2 means keep observing; any red/failure stops. Stable
promotion remains a separate explicit command.`

try {
  await main()
} catch (err) {
  console.error(`public gateway observer: ${safeError(err)}`)
  process.exitCode = 1
}

async function main () {
  const { options, forwarded } = parseArgs(process.argv.slice(2))
  if (options.help) {
    console.log(usage.trim())
    return
  }
  assertForwardedGatewayCheck(forwarded)

  const checker = requireAbsolutePath(options.checker || defaultChecker, 'checker')
  const sampleIntervalMs = exactInteger(options.sampleIntervalMs, 60_000, 1_000, 5 * 60_000, 'sample-interval-ms')
  const maxRuntimeMs = exactInteger(options.maxRuntimeMs, 8 * 24 * 60 * 60 * 1000,
    60_000, 8 * 24 * 60 * 60 * 1000, 'max-runtime-ms')
  const statePath = requireAbsolutePath(valueAfter(forwarded, '--gateway-window-state'), 'gateway-window-state')
  const deadline = Date.now() + maxRuntimeMs
  let samples = 0

  console.log(`Public gateway observer started; checker=${checker} interval=${sampleIntervalMs}ms`)
  while (Date.now() < deadline) {
    const code = await runChecker(checker, forwarded)
    samples++
    if (code === 0) {
      console.log(`Public gateway observation complete after ${samples} checker run(s). Stable promotion remains explicit.`)
      return
    }
    if (code !== 2) {
      throw new Error(`rollout checker stopped red with exit ${code}; observation aborted`)
    }

    const state = await readObservationState(statePath)
    const maxProbeGapMs = state.maxProbeGapMs
    if (!Number.isSafeInteger(maxProbeGapMs) || maxProbeGapMs < 60_000 || maxProbeGapMs > 30 * 60_000) {
      throw new Error('observation state contains an invalid signed maxProbeGapMs')
    }
    // Leave at least half the signed gap for checker execution, updater jitter,
    // and scheduling delay. The checker remains authoritative and resets any
    // discontinuous window; this guard avoids knowingly choosing a bad cadence.
    if (sampleIntervalMs * 2 > maxProbeGapMs) {
      throw new Error(`sample interval ${sampleIntervalMs}ms leaves insufficient margin under signed maxProbeGapMs ${maxProbeGapMs}`)
    }
    if (Date.now() + sampleIntervalMs >= deadline) break
    console.log(`Observation incomplete after ${samples} checker run(s); next sample in ${sampleIntervalMs}ms.`)
    await sleep(sampleIntervalMs)
  }
  throw new Error(`observer runtime budget ${maxRuntimeMs}ms expired before the signed window completed`)
}

function parseArgs (argv) {
  const separator = argv.indexOf('--')
  if (separator < 0 && argv.length === 1 && (argv[0] === '--help' || argv[0] === '-h')) {
    return { options: { help: true }, forwarded: [] }
  }
  if (separator < 0) throw new Error('a -- separator before fleet checker options is required')
  const own = argv.slice(0, separator)
  const forwarded = argv.slice(separator + 1)
  const options = {}
  const valueOptions = new Set(['sample-interval-ms', 'max-runtime-ms', 'checker'])
  const seen = new Set()
  for (let i = 0; i < own.length; i++) {
    const raw = own[i]
    if (raw === '--help' || raw === '-h') {
      if (seen.has('help')) throw new Error('duplicate --help')
      seen.add('help')
      options.help = true
      continue
    }
    if (!raw.startsWith('--')) throw new Error(`unexpected observer argument ${JSON.stringify(raw)}`)
    const name = raw.slice(2)
    if (!valueOptions.has(name)) throw new Error(`unknown observer option --${name}`)
    if (seen.has(name)) throw new Error(`duplicate observer option --${name}`)
    seen.add(name)
    const value = own[++i]
    if (!value || value.startsWith('--')) throw new Error(`missing value for --${name}`)
    options[camel(name)] = value
  }
  return { options, forwarded }
}

function assertForwardedGatewayCheck (argv) {
  if (argv.length === 0) throw new Error('fleet checker options are required after --')
  const required = [
    '--target',
    '--gateway-evidence',
    '--gateway-manifest',
    '--gateway-window-state',
    '--evidence',
    '--known-hosts',
    '--allowed-signers',
    '--channel'
  ]
  for (const flag of required) {
    const value = valueAfter(argv, flag)
    if (!value) throw new Error(`${flag} is required in forwarded fleet checker options`)
  }
  if (valueAfter(argv, '--channel') !== 'canary') {
    throw new Error('observer is restricted to the canary gateway cohort')
  }
  if (argv.includes('--dry-run')) throw new Error('observer cannot accumulate a dry-run window')
}

function valueAfter (argv, flag) {
  const indexes = []
  for (let i = 0; i < argv.length; i++) if (argv[i] === flag) indexes.push(i)
  if (indexes.length !== 1) return null
  const value = argv[indexes[0] + 1]
  return value && !value.startsWith('--') ? value : null
}

async function runChecker (checker, forwarded) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [checker, ...forwarded], {
      stdio: 'inherit',
      env: process.env
    })
    let settled = false
    const finish = (fn, value) => {
      if (settled) return
      settled = true
      process.off('SIGINT', onInterrupt)
      process.off('SIGTERM', onTerminate)
      fn(value)
    }
    const onInterrupt = () => {
      child.kill('SIGINT')
      finish(reject, new Error('observer interrupted'))
    }
    const onTerminate = () => {
      child.kill('SIGTERM')
      finish(reject, new Error('observer terminated'))
    }
    process.once('SIGINT', onInterrupt)
    process.once('SIGTERM', onTerminate)
    child.once('error', err => finish(reject, err))
    child.once('exit', (code, signal) => {
      if (signal) finish(reject, new Error(`rollout checker terminated by ${signal}`))
      else finish(resolve, Number.isInteger(code) ? code : 1)
    })
  })
}

async function readObservationState (file) {
  let handle
  try {
    if (typeof fsConstants.O_NOFOLLOW !== 'number') throw new Error('platform lacks O_NOFOLLOW')
    handle = await open(file, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW)
    const before = await handle.stat({ bigint: true })
    if (!before.isFile() || before.nlink !== 1n || before.size < 1n || before.size > BigInt(MAX_STATE_BYTES)) {
      throw new Error('observation state must be a bounded single-link regular file')
    }
    const buffer = Buffer.allocUnsafe(MAX_STATE_BYTES + 1)
    let length = 0
    while (length < buffer.length) {
      const { bytesRead } = await handle.read(buffer, length, buffer.length - length, length)
      if (bytesRead === 0) break
      length += bytesRead
    }
    if (length > MAX_STATE_BYTES) throw new Error('observation state exceeds its read bound')
    const after = await handle.stat({ bigint: true })
    if (!sameSnapshot(before, after) || BigInt(length) !== after.size) {
      throw new Error('observation state changed while being read')
    }
    const value = JSON.parse(buffer.subarray(0, length).toString('utf8'))
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('observation state must contain a JSON object')
    return value
  } catch (err) {
    throw new Error(`cannot safely resume observation state: ${safeError(err)}`)
  } finally {
    await handle?.close().catch(() => {})
  }
}

function sameSnapshot (left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode &&
    left.nlink === right.nlink && left.size === right.size && left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
}

function exactInteger (value, fallback, min, max, label) {
  if (value == null) return fallback
  if (!/^(?:0|[1-9][0-9]*)$/.test(String(value))) throw new Error(`--${label} must be an exact integer`)
  const number = Number(value)
  if (!Number.isSafeInteger(number) || number < min || number > max) {
    throw new Error(`--${label} must be between ${min} and ${max}`)
  }
  return number
}

function requireAbsolutePath (value, label) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || value.length > 4096 || hasControlChars(value)) {
    throw new Error(`${label} must be a bounded absolute path`)
  }
  return value
}

function hasControlChars (value) {
  for (const character of String(value)) {
    const code = character.charCodeAt(0)
    if (code <= 31 || code === 127) return true
  }
  return false
}

function camel (value) {
  return value.replace(/-([a-z])/g, (_, character) => character.toUpperCase())
}

function safeError (err) {
  return String(err?.message || err || 'unknown error').replace(/[\r\n\0]/g, ' ').slice(0, 1000)
}

function sleep (ms) {
  return new Promise(resolve => setTimeout(resolve, ms))
}
