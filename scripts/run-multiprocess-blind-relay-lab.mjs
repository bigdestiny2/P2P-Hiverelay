#!/usr/bin/env node
import { createHash } from 'node:crypto'
import { execFile, spawn } from 'node:child_process'
import fs from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import {
  buildLocalMultiprocessBlindReport,
  verifyLocalMultiprocessBlindReport
} from './verify-multiprocess-blind-relay-report.mjs'

const execFileAsync = promisify(execFile)
const REPOSITORY_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const CHILD_SCRIPT = path.join(REPOSITORY_ROOT, 'scripts', 'run-multiprocess-blind-relay-child.mjs')
const MAX_CHILD_OUTPUT_BYTES = 64 * 1024 * 1024
const DEFAULTS = Object.freeze({
  processCount: 3,
  relaysPerProcess: 2,
  recordsPerRelay: 16,
  concurrencyPerProcess: 8,
  contentBytes: 256,
  childTimeoutMs: 180_000
})

function fail (message) {
  const error = new Error(message)
  error.code = 'BLIND_LOCAL_MULTIPROCESS_LAB_INVALID'
  throw error
}

function boundedInteger (value, fallback, minimum, maximum, field) {
  if (value == null) return fallback
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail(`${field} must be an integer within ${minimum}..${maximum}`)
  }
  return value
}

function digest (bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

async function gitCommit () {
  const result = await execFileAsync('git', ['rev-parse', 'HEAD'], {
    cwd: REPOSITORY_ROOT,
    timeout: 10_000,
    maxBuffer: 1024 * 1024,
    encoding: 'utf8'
  })
  const commit = result.stdout.trim()
  if (!/^[0-9a-f]{40}$/.test(commit)) fail('git HEAD is not a full lowercase commit')
  return commit
}

function collectStream (stream, field, onOverflow) {
  const chunks = []
  let bytes = 0
  stream.on('data', chunk => {
    bytes += chunk.byteLength
    if (bytes > MAX_CHILD_OUTPUT_BYTES) {
      onOverflow(`${field} exceeded ${MAX_CHILD_OUTPUT_BYTES} bytes`)
      return
    }
    chunks.push(Buffer.from(chunk))
  })
  return () => Buffer.concat(chunks, bytes)
}

async function launchChild (input) {
  await fs.mkdir(input.root, { recursive: true, mode: 0o700 })
  await fs.chmod(input.root, 0o700)
  const logicalOperatorScope = `local-operator-scope-${String(input.processIndex).padStart(2, '0')}`
  const identityScope = `local-process-identity-${String(input.processIndex).padStart(2, '0')}`
  const args = [
    CHILD_SCRIPT,
    '--operator-scope', logicalOperatorScope,
    '--identity-scope', identityScope,
    '--root', input.root,
    '--relays', String(input.relaysPerProcess),
    '--records', String(input.recordsPerRelay),
    '--concurrency', String(input.concurrencyPerProcess),
    '--content-bytes', String(input.contentBytes)
  ]
  if (input.keep) args.push('--keep')
  const observedSpawnUnixMillis = Date.now()
  const child = spawn(process.execPath, args, {
    cwd: REPOSITORY_ROOT,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env }
  })
  const observedPid = child.pid
  if (!Number.isSafeInteger(observedPid) || observedPid <= 0) fail('child process did not receive a PID')
  let terminalError = null
  const stopForOverflow = message => {
    if (terminalError) return
    terminalError = new Error(message)
    child.kill('SIGTERM')
  }
  const stdoutBytes = collectStream(child.stdout, 'child stdout', stopForOverflow)
  const stderrBytes = collectStream(child.stderr, 'child stderr', stopForOverflow)
  const timeout = setTimeout(() => {
    if (terminalError) return
    terminalError = new Error(`child ${input.processIndex} exceeded ${input.childTimeoutMs}ms`)
    child.kill('SIGTERM')
  }, input.childTimeoutMs)
  const result = await new Promise((resolve, reject) => {
    child.once('error', reject)
    child.once('close', (exitCode, signal) => resolve({ exitCode, signal }))
  }).finally(() => clearTimeout(timeout))
  const observedExitUnixMillis = Date.now()
  const stdout = stdoutBytes()
  const stderr = stderrBytes()
  if (terminalError) throw terminalError
  if (result.exitCode !== 0 || result.signal !== null) {
    fail(`child ${input.processIndex} failed with exit=${result.exitCode} signal=${result.signal || 'none'}: ${stderr.toString('utf8').trim()}`)
  }
  let envelope
  try {
    envelope = JSON.parse(stdout.toString('utf8'))
  } catch (error) {
    fail(`child ${input.processIndex} emitted invalid JSON: ${error.message}`)
  }
  return Object.freeze({
    processIndex: input.processIndex,
    observedPid,
    observedSpawnUnixMillis,
    observedExitUnixMillis,
    exitCode: result.exitCode,
    signal: result.signal,
    stdoutSha256: digest(stdout),
    stderrSha256: digest(stderr),
    stderrBytes: stderr.byteLength,
    envelope
  })
}

export async function runLocalMultiprocessBlindRelayLab (options = {}) {
  if (typeof process.getuid !== 'function' || typeof process.getgid !== 'function') {
    fail('local multi-process blind lab requires POSIX UID/GID and Unix sockets')
  }
  const processCount = boundedInteger(options.processCount, DEFAULTS.processCount, 3, 8,
    'processCount')
  const relaysPerProcess = boundedInteger(options.relaysPerProcess, DEFAULTS.relaysPerProcess, 2, 8,
    'relaysPerProcess')
  const recordsPerRelay = boundedInteger(options.recordsPerRelay, DEFAULTS.recordsPerRelay, 1, 250000,
    'recordsPerRelay')
  const concurrencyPerProcess = boundedInteger(
    options.concurrencyPerProcess,
    DEFAULTS.concurrencyPerProcess,
    1,
    128,
    'concurrencyPerProcess'
  )
  const contentBytes = boundedInteger(options.contentBytes, DEFAULTS.contentBytes, 32, 4000,
    'contentBytes')
  const childTimeoutMs = boundedInteger(options.childTimeoutMs, DEFAULTS.childTimeoutMs, 45_000, 900_000,
    'childTimeoutMs')
  const keep = options.keep === true
  const root = options.root == null
    ? await fs.mkdtemp(path.join(await fs.realpath('/tmp'), 'brmultiprocess-'))
    : path.resolve(options.root)
  if (options.root != null) await fs.mkdir(root, { recursive: true, mode: 0o700 })
  const sourceCommit = await gitCommit()
  try {
    const outcomes = await Promise.allSettled(Array.from({ length: processCount }, (_, processIndex) =>
      launchChild({
        processIndex,
        root: path.join(root, `process-${String(processIndex).padStart(2, '0')}`),
        relaysPerProcess,
        recordsPerRelay,
        concurrencyPerProcess,
        contentBytes,
        childTimeoutMs,
        keep
      })
    ))
    const failures = outcomes
      .map((outcome, processIndex) => ({ outcome, processIndex }))
      .filter(value => value.outcome.status === 'rejected')
    if (failures.length > 0) {
      fail(failures.map(({ outcome, processIndex }) =>
        `child ${processIndex}: ${outcome.reason?.message || String(outcome.reason)}`
      ).join('; '))
    }
    const children = outcomes.map(outcome => outcome.value)
    children.sort((left, right) => left.processIndex - right.processIndex)
    const report = buildLocalMultiprocessBlindReport({
      generatedAt: new Date().toISOString(),
      sourceCommit,
      supervisorPid: process.pid,
      supervisorUid: process.getuid(),
      supervisorGid: process.getgid(),
      relaysPerProcess,
      recordsPerRelay,
      concurrencyPerProcess,
      contentBytes,
      children
    })
    verifyLocalMultiprocessBlindReport(report)
    return report
  } finally {
    if (!keep) await fs.rm(root, { recursive: true, force: true })
  }
}

function parseCli (argv) {
  const options = {}
  for (let index = 0; index < argv.length; index++) {
    const value = argv[index]
    if (value === '--processes') options.processCount = Number(argv[++index])
    else if (value === '--relays-per-process') options.relaysPerProcess = Number(argv[++index])
    else if (value === '--records') options.recordsPerRelay = Number(argv[++index])
    else if (value === '--concurrency') options.concurrencyPerProcess = Number(argv[++index])
    else if (value === '--content-bytes') options.contentBytes = Number(argv[++index])
    else if (value === '--child-timeout-ms') options.childTimeoutMs = Number(argv[++index])
    else if (value === '--root') options.root = argv[++index]
    else if (value === '--output') options.output = argv[++index]
    else if (value === '--pretty') options.pretty = true
    else if (value === '--assert-correctness') options.assertCorrectness = true
    else if (value === '--assert-local') options.assertLocal = true
    else if (value === '--keep') options.keep = true
    else fail(`unknown argument ${value}`)
  }
  return options
}

async function main () {
  const options = parseCli(process.argv.slice(2))
  const report = await runLocalMultiprocessBlindRelayLab(options)
  const json = JSON.stringify(report, null, options.pretty ? 2 : 0) + '\n'
  if (options.output) {
    const output = path.resolve(options.output)
    await fs.mkdir(path.dirname(output), { recursive: true })
    await fs.writeFile(output, json)
  } else {
    process.stdout.write(json)
  }
  if (options.assertCorrectness && !report.correctnessGateReady) process.exitCode = 1
  if (options.assertLocal && !report.localGateReady) process.exitCode = 1
}

if (fileURLToPath(import.meta.url) === path.resolve(process.argv[1] || '')) {
  main().catch(error => {
    process.stderr.write(`[blind-local-multiprocess-lab] ${error.code || 'ERROR'}: ${error.message}\n`)
    process.exitCode = 1
  })
}
