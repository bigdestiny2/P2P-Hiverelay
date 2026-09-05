#!/usr/bin/env node

import { execFile, spawn } from 'node:child_process'
import { constants } from 'node:fs'
import { link, open, opendir, readFile, rename, unlink } from 'node:fs/promises'
import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto'
import { promisify } from 'node:util'
import { basename, dirname, join, resolve, sep } from 'node:path'
import { pathToFileURL } from 'node:url'

export const WATCHDOG_PATHS = Object.freeze({
  policy: '/etc/hiverelay/watchdog/restart-policy-v1.json',
  signer: '/etc/hiverelay/watchdog/signer-snapshot-v1.json',
  sequence: '/var/lib/hiverelay-watchdog/highest-restart-policy-sequence-v1.json',
  failure: '/run/hiverelay-watchdog/failure-state-v1.json',
  diagnostics: '/var/log/hiverelay-watchdog/diagnostics'
})

export const WATCHDOG_UNIT = 'hiverelay.service'
export const HEALTH_BODY_MAX = 65_536
export const SOURCE_MAX = 24_576
export const BUNDLE_MAX = 524_288
export const CAPTURE_MAX_MS = 10_000
export const MAX_SOURCES = 16
export const MAX_ARTIFACTS = 16
export const MAX_ARTIFACT_AGE_MS = 7 * 24 * 60 * 60 * 1000

const execFileAsync = promisify(execFile)
const LOWER_SHA256 = /^[0-9a-f]{64}$/
const LOWER_SIGNATURE = /^[0-9a-f]{128}$/
const PRINTABLE_PRINCIPAL = /^[\x20-\x7e]{1,128}$/
const ARTIFACT_NAME = /^watchdog-([0-9]{13})-([0-9a-f]{64})\.json$/
const FAILURE_OUTCOMES = new Set([
  'eligible-empty',
  'eligible-timeout',
  'healthy',
  'responsive-not-restartable'
])
const ELIGIBLE_OUTCOMES = new Set(['eligible-empty', 'eligible-timeout'])
const ELIGIBLE_TRANSPORT_EXITS = new Set([7, 18, 28, 52, 55, 56])
const SENSITIVE = /authorization|cookie|token|secret|password|private[-_ ]?key|credential/i
const REQUIRED_POLICY_KEYS = [
  'executableSha256',
  'expiresAt',
  'issuedAt',
  'killAllowed',
  'kind',
  'sequence',
  'signature',
  'signerPrincipal',
  'termGraceMs',
  'unit',
  'version'
]

function fail (code, message = code) {
  const err = new Error(message)
  err.code = code
  throw err
}

function isObject (value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function sortedValue (value) {
  if (Array.isArray(value)) return value.map(sortedValue)
  if (!isObject(value)) return value
  const output = {}
  for (const key of Object.keys(value).sort()) output[key] = sortedValue(value[key])
  return output
}

export function canonicalJson (value) {
  return JSON.stringify(sortedValue(value))
}

function exactKeys (value, expected, label) {
  if (!isObject(value)) fail('WATCHDOG_SCHEMA_INVALID', `${label} must be an object`)
  const actual = Object.keys(value).sort()
  const wanted = [...expected].sort()
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail('WATCHDOG_SCHEMA_INVALID', `${label} keys mismatch`)
  }
}

function safeInteger (value, label, min = 0, max = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    fail('WATCHDOG_SCHEMA_INVALID', `${label} must be a safe integer in [${min},${max}]`)
  }
  return value
}

export function parseCanonicalJson (bytes, maxBytes, label = 'watchdog JSON') {
  if (!Buffer.isBuffer(bytes)) bytes = Buffer.from(bytes)
  if (bytes.byteLength < 2 || bytes.byteLength > maxBytes) {
    fail('WATCHDOG_FILE_SIZE_INVALID', `${label} size is outside its bound`)
  }
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    fail('WATCHDOG_JSON_NONCANONICAL', `${label} has a UTF-8 BOM`)
  }
  let text
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    fail('WATCHDOG_JSON_UTF8_INVALID', `${label} is not canonical UTF-8`)
  }
  let value
  try {
    value = JSON.parse(text)
  } catch {
    fail('WATCHDOG_JSON_INVALID', `${label} is not JSON`)
  }
  if (text !== canonicalJson(value)) {
    fail('WATCHDOG_JSON_NONCANONICAL', `${label} is not strict canonical JSON`)
  }
  return value
}

function modeOf (stat) {
  return stat.mode & 0o7777
}

async function readExactFileHandle (handle, size, maxBytes, label) {
  if (!Number.isSafeInteger(size) || size < 1 || size > maxBytes) {
    fail('WATCHDOG_FILE_SIZE_INVALID', `${label} size is outside its bound`)
  }
  const output = Buffer.alloc(size)
  let offset = 0
  while (offset < size) {
    const { bytesRead } = await handle.read(output, offset, size - offset, offset)
    if (bytesRead === 0) fail('WATCHDOG_FILE_SHORT_READ', `${label} ended before fstat size`)
    offset += bytesRead
  }
  const extra = Buffer.alloc(1)
  const { bytesRead } = await handle.read(extra, 0, 1, size)
  if (bytesRead !== 0) fail('WATCHDOG_FILE_GREW', `${label} changed while being read`)
  return output
}

export async function readAuthorityJson (path, spec, authority = {}) {
  const expectedUid = authority.uid ?? 0
  const expectedGid = authority.gid ?? 0
  const expectedMode = spec.mode
  let handle
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_CLOEXEC)
    const before = await handle.stat()
    if (!before.isFile() || before.nlink !== 1 || before.uid !== expectedUid || before.gid !== expectedGid ||
        modeOf(before) !== expectedMode) {
      fail('WATCHDOG_FILE_AUTHORITY_INVALID', `${spec.label} authority metadata mismatch`)
    }
    const bytes = await readExactFileHandle(handle, before.size, spec.maxBytes, spec.label)
    const after = await handle.stat()
    if (after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size ||
        after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs || after.nlink !== 1 ||
        after.uid !== expectedUid || after.gid !== expectedGid || modeOf(after) !== expectedMode) {
      fail('WATCHDOG_FILE_CHANGED', `${spec.label} changed while being read`)
    }
    return { value: parseCanonicalJson(bytes, spec.maxBytes, spec.label), bytes, stat: before }
  } finally {
    if (handle) await handle.close().catch(() => {})
  }
}

async function openAuthorityDirectory (path, authority = {}) {
  const expectedUid = authority.uid ?? 0
  const expectedGid = authority.gid ?? 0
  const expectedMode = authority.directoryMode ?? 0o700
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_DIRECTORY | constants.O_CLOEXEC)
  const stat = await handle.stat()
  if (!stat.isDirectory() || stat.uid !== expectedUid || stat.gid !== expectedGid || modeOf(stat) !== expectedMode) {
    await handle.close()
    fail('WATCHDOG_DIRECTORY_AUTHORITY_INVALID', 'watchdog directory authority metadata mismatch')
  }
  return handle
}

async function atomicReplaceAuthorityJson (path, value, spec, authority = {}) {
  const parent = dirname(path)
  const parentHandle = await openAuthorityDirectory(parent, authority)
  const uid = authority.uid ?? 0
  const gid = authority.gid ?? 0
  const bytes = Buffer.from(canonicalJson(value))
  if (bytes.byteLength > spec.maxBytes) fail('WATCHDOG_FILE_SIZE_INVALID', `${spec.label} exceeds its byte bound`)
  const temp = join(parent, `.${basename(path)}.${process.pid}.${randomBytes(12).toString('hex')}.tmp`)
  let handle
  let installed = false
  try {
    handle = await open(temp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL |
      constants.O_NOFOLLOW | constants.O_CLOEXEC, spec.mode)
    await handle.chmod(spec.mode)
    if (typeof handle.chown === 'function') await handle.chown(uid, gid)
    const created = await handle.stat()
    if (!created.isFile() || created.nlink !== 1 || created.uid !== uid || created.gid !== gid ||
        modeOf(created) !== spec.mode) {
      fail('WATCHDOG_TEMP_AUTHORITY_INVALID', `${spec.label} temp authority mismatch`)
    }
    await handle.writeFile(bytes)
    await handle.sync()
    await handle.close()
    handle = null
    await rename(temp, path)
    installed = true
    await parentHandle.sync()
    const reread = await readAuthorityJson(path, spec, authority)
    if (!reread.bytes.equals(bytes)) fail('WATCHDOG_INSTALL_VERIFY_FAILED', `${spec.label} installed bytes mismatch`)
    return { bytes, sha256: sha256(bytes) }
  } finally {
    if (handle) await handle.close().catch(() => {})
    if (!installed) await unlink(temp).catch(() => {})
    await parentHandle.close().catch(() => {})
  }
}

async function clearAuthorityFile (path, spec, authority = {}) {
  const expectedUid = authority.uid ?? 0
  const expectedGid = authority.gid ?? 0
  let handle
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_CLOEXEC)
    const stat = await handle.stat()
    if (!stat.isFile() || stat.nlink !== 1 || stat.uid !== expectedUid || stat.gid !== expectedGid ||
        modeOf(stat) !== spec.mode || stat.size > spec.maxBytes) {
      fail('WATCHDOG_FILE_AUTHORITY_INVALID', `${spec.label} authority metadata mismatch`)
    }
  } catch (err) {
    if (err && err.code === 'ENOENT') return false
    throw err
  } finally {
    if (handle) await handle.close().catch(() => {})
  }
  const parentHandle = await openAuthorityDirectory(dirname(path), authority)
  try {
    await unlink(path)
    await parentHandle.sync()
    return true
  } finally {
    await parentHandle.close().catch(() => {})
  }
}

function sha256 (bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

export function classifyHealth ({ body, status, curlExit }) {
  if (!Buffer.isBuffer(body)) body = Buffer.from(body)
  safeInteger(status, 'health status', 0, 999)
  safeInteger(curlExit, 'curl exit', 0, 255)
  if (body.byteLength > HEALTH_BODY_MAX) fail('WATCHDOG_HEALTH_BODY_OVERSIZED')
  if (body.byteLength === 0) {
    if (curlExit === 0) return 'eligible-empty'
    return ELIGIBLE_TRANSPORT_EXITS.has(curlExit) ? 'eligible-timeout' : 'responsive-not-restartable'
  }
  if (curlExit === 0 && status >= 200 && status <= 299) {
    try {
      const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body))
      if (isObject(value) && value.ok === true) return 'healthy'
    } catch {}
  }
  return 'responsive-not-restartable'
}

function validateFailureState (value) {
  exactKeys(value, [
    'consecutiveEligibleFailures',
    'executableSha256',
    'firstFailureAt',
    'kind',
    'lastFailureAt',
    'lastOutcome',
    'mainPid',
    'procStarttime',
    'unit',
    'version'
  ], 'failure state')
  if (value.kind !== 'HiveRelayWatchdogFailureStateV1' || value.version !== 1 ||
      value.unit !== WATCHDOG_UNIT || !LOWER_SHA256.test(value.executableSha256) ||
      !FAILURE_OUTCOMES.has(value.lastOutcome)) fail('WATCHDOG_FAILURE_STATE_INVALID')
  safeInteger(value.mainPid, 'failure state mainPid', 1)
  safeInteger(value.procStarttime, 'failure state procStarttime', 1)
  safeInteger(value.consecutiveEligibleFailures, 'failure count', 0, 2)
  safeInteger(value.firstFailureAt, 'firstFailureAt')
  safeInteger(value.lastFailureAt, 'lastFailureAt')
  if (value.consecutiveEligibleFailures === 0 && value.firstFailureAt !== 0) fail('WATCHDOG_FAILURE_STATE_INVALID')
  if (value.consecutiveEligibleFailures > 0 && (value.firstFailureAt < 1 || value.lastFailureAt < value.firstFailureAt ||
      !ELIGIBLE_OUTCOMES.has(value.lastOutcome))) fail('WATCHDOG_FAILURE_STATE_INVALID')
  if (value.consecutiveEligibleFailures === 1 && value.firstFailureAt !== value.lastFailureAt) {
    fail('WATCHDOG_FAILURE_STATE_INVALID')
  }
  if (value.consecutiveEligibleFailures === 2 &&
      (value.lastFailureAt - value.firstFailureAt < 60_000 || value.lastFailureAt - value.firstFailureAt > 600_000)) {
    fail('WATCHDOG_FAILURE_STATE_INVALID')
  }
  return value
}

function sameFailureTarget (left, target) {
  return left.unit === target.unit && left.executableSha256 === target.executableSha256 &&
    left.mainPid === target.mainPid && left.procStarttime === target.procStarttime
}

const FAILURE_SPEC = Object.freeze({ label: 'failure state', maxBytes: 4096, mode: 0o600 })
const SEQUENCE_SPEC = Object.freeze({ label: 'consumed sequence', maxBytes: 4096, mode: 0o600 })
const POLICY_SPEC = Object.freeze({ label: 'restart policy', maxBytes: 8192, mode: 0o400 })
const SIGNER_SPEC = Object.freeze({ label: 'signer snapshot', maxBytes: 4096, mode: 0o400 })

export async function recordFailureOutcome ({ outcome, target, now = Date.now(), paths = WATCHDOG_PATHS, authority = {} }) {
  if (!FAILURE_OUTCOMES.has(outcome)) fail('WATCHDOG_OUTCOME_INVALID')
  if (!isObject(target) || target.unit !== WATCHDOG_UNIT || !LOWER_SHA256.test(target.executableSha256)) {
    fail('WATCHDOG_TARGET_INVALID')
  }
  safeInteger(target.mainPid, 'target mainPid', 1)
  safeInteger(target.procStarttime, 'target procStarttime', 1)
  safeInteger(now, 'observation time', 1)

  let previous = null
  try {
    previous = validateFailureState((await readAuthorityJson(paths.failure, FAILURE_SPEC, authority)).value)
  } catch (err) {
    const corruptState = new Set([
      'ENOENT',
      'WATCHDOG_FILE_SIZE_INVALID',
      'WATCHDOG_JSON_UTF8_INVALID',
      'WATCHDOG_JSON_INVALID',
      'WATCHDOG_JSON_NONCANONICAL',
      'WATCHDOG_SCHEMA_INVALID',
      'WATCHDOG_FAILURE_STATE_INVALID'
    ])
    if (!err || !corruptState.has(err.code)) throw err
  }

  let consecutiveEligibleFailures = 0
  let firstFailureAt = 0
  if (ELIGIBLE_OUTCOMES.has(outcome)) {
    const elapsed = previous && sameFailureTarget(previous, target) ? now - previous.lastFailureAt : -1
    const continues = previous && previous.consecutiveEligibleFailures === 1 &&
      ELIGIBLE_OUTCOMES.has(previous.lastOutcome) && elapsed >= 60_000 && elapsed <= 600_000
    if (continues) {
      consecutiveEligibleFailures = 2
      firstFailureAt = previous.firstFailureAt
    } else if (previous && sameFailureTarget(previous, target) && previous.consecutiveEligibleFailures === 2 &&
      ELIGIBLE_OUTCOMES.has(previous.lastOutcome) && elapsed >= 60_000 && elapsed <= 600_000) {
      consecutiveEligibleFailures = 2
      firstFailureAt = previous.firstFailureAt
    } else {
      consecutiveEligibleFailures = 1
      firstFailureAt = now
    }
  }

  const state = {
    kind: 'HiveRelayWatchdogFailureStateV1',
    version: 1,
    unit: target.unit,
    executableSha256: target.executableSha256,
    mainPid: target.mainPid,
    procStarttime: target.procStarttime,
    consecutiveEligibleFailures,
    firstFailureAt,
    lastFailureAt: now,
    lastOutcome: outcome
  }
  validateFailureState(state)
  await atomicReplaceAuthorityJson(paths.failure, state, FAILURE_SPEC, authority)
  return { state, restartEligible: consecutiveEligibleFailures === 2 }
}

function validatePolicy (value, now, target) {
  exactKeys(value, REQUIRED_POLICY_KEYS, 'restart policy')
  if (value.kind !== 'HiveRelayWatchdogRestartPolicyV1' || value.version !== 1 ||
      value.unit !== WATCHDOG_UNIT || value.unit !== target.unit ||
      !LOWER_SHA256.test(value.executableSha256) || value.executableSha256 !== target.executableSha256 ||
      typeof value.killAllowed !== 'boolean' || !PRINTABLE_PRINCIPAL.test(value.signerPrincipal) ||
      !LOWER_SIGNATURE.test(value.signature)) fail('WATCHDOG_POLICY_INVALID')
  safeInteger(value.sequence, 'policy sequence', 1)
  safeInteger(value.issuedAt, 'policy issuedAt', 0)
  safeInteger(value.expiresAt, 'policy expiresAt', 0)
  safeInteger(value.termGraceMs, 'policy termGraceMs', 5000, 120_000)
  if (value.issuedAt > now || value.expiresAt < now || value.expiresAt < value.issuedAt ||
      value.expiresAt - value.issuedAt > 86_400_000) fail('WATCHDOG_POLICY_TIME_INVALID')
  return value
}

function validateSigner (value) {
  exactKeys(value, ['kind', 'publicKey', 'signerPrincipal', 'version'], 'signer snapshot')
  if (value.kind !== 'HiveRelayWatchdogSignerSnapshotV1' || value.version !== 1 ||
      !PRINTABLE_PRINCIPAL.test(value.signerPrincipal) || !LOWER_SHA256.test(value.publicKey)) {
    fail('WATCHDOG_SIGNER_INVALID')
  }
  return value
}

function validateConsumedSequence (value) {
  exactKeys(value, ['consumedAt', 'kind', 'policySha256', 'sequence', 'version'], 'consumed sequence')
  if (value.kind !== 'HiveRelayWatchdogConsumedSequenceV1' || value.version !== 1 ||
      !LOWER_SHA256.test(value.policySha256)) fail('WATCHDOG_SEQUENCE_INVALID')
  safeInteger(value.sequence, 'consumed sequence', 0)
  safeInteger(value.consumedAt, 'consumedAt', 0)
  return value
}

export function policySigningBytes (policy) {
  return Buffer.from(JSON.stringify([
    'hiverelay.watchdog.restart-policy.v1',
    policy.kind,
    policy.version,
    policy.sequence,
    policy.issuedAt,
    policy.expiresAt,
    policy.unit,
    policy.executableSha256,
    policy.termGraceMs,
    policy.killAllowed,
    policy.signerPrincipal
  ]))
}

function verifyPolicySignature (policy, signer) {
  if (policy.signerPrincipal !== signer.signerPrincipal) fail('WATCHDOG_SIGNER_PRINCIPAL_MISMATCH')
  const prefix = Buffer.from('302a300506032b6570032100', 'hex')
  const key = createPublicKey({ key: Buffer.concat([prefix, Buffer.from(signer.publicKey, 'hex')]), format: 'der', type: 'spki' })
  if (!verify(null, policySigningBytes(policy), key, Buffer.from(policy.signature, 'hex'))) {
    fail('WATCHDOG_POLICY_SIGNATURE_INVALID')
  }
}

function validateAuthorizationState (state, target, now) {
  validateFailureState(state)
  if (!sameFailureTarget(state, target) || state.consecutiveEligibleFailures !== 2 ||
      !ELIGIBLE_OUTCOMES.has(state.lastOutcome) || now < state.lastFailureAt ||
      now - state.lastFailureAt > 600_000) fail('WATCHDOG_FAILURE_PREDICATE_INVALID')
}

async function readAuthorizationSet ({ paths, authority, now, target }) {
  const [policyRecord, signerRecord, sequenceRecord, failureRecord] = await Promise.all([
    readAuthorityJson(paths.policy, POLICY_SPEC, authority),
    readAuthorityJson(paths.signer, SIGNER_SPEC, authority),
    readAuthorityJson(paths.sequence, SEQUENCE_SPEC, authority),
    readAuthorityJson(paths.failure, FAILURE_SPEC, authority)
  ])
  const policy = validatePolicy(policyRecord.value, now, target)
  const signer = validateSigner(signerRecord.value)
  const sequence = validateConsumedSequence(sequenceRecord.value)
  validateAuthorizationState(failureRecord.value, target, now)
  verifyPolicySignature(policy, signer)
  if (policy.sequence <= sequence.sequence) fail('WATCHDOG_POLICY_REPLAY')
  return { policyRecord, signerRecord, sequenceRecord, failureRecord, policy, signer, sequence }
}

function sameAuthorityRecord (left, right) {
  return left.bytes.equals(right.bytes) &&
    left.stat.dev === right.stat.dev && left.stat.ino === right.stat.ino &&
    left.stat.size === right.stat.size && left.stat.uid === right.stat.uid &&
    left.stat.gid === right.stat.gid && left.stat.nlink === right.stat.nlink &&
    modeOf(left.stat) === modeOf(right.stat)
}

function sameAuthorizationSet (left, right) {
  return sameAuthorityRecord(left.policyRecord, right.policyRecord) &&
    sameAuthorityRecord(left.signerRecord, right.signerRecord) &&
    sameAuthorityRecord(left.sequenceRecord, right.sequenceRecord) &&
    sameAuthorityRecord(left.failureRecord, right.failureRecord)
}

function redactText (text) {
  let redacted = 0
  const lines = text.split('\n').map(line => {
    if (!SENSITIVE.test(line)) return line
    redacted++
    return '[REDACTED]'
  })
  return { text: lines.join('\n'), redacted }
}

function boundedUtf8Text (text, maxBytes) {
  const encoded = Buffer.from(text)
  if (encoded.byteLength <= maxBytes) return { data: text, truncated: false }
  for (let end = maxBytes; end > 0; end--) {
    try {
      return {
        data: new TextDecoder('utf-8', { fatal: true }).decode(encoded.subarray(0, end)),
        truncated: true
      }
    } catch {}
  }
  return { data: '', truncated: true }
}

async function readBounded (path, maxBytes) {
  let handle
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_CLOEXEC)
    const chunks = []
    let total = 0
    while (total <= maxBytes) {
      const chunk = Buffer.alloc(Math.min(4096, maxBytes + 1 - total))
      const { bytesRead } = await handle.read(chunk, 0, chunk.byteLength, null)
      if (bytesRead === 0) break
      chunks.push(chunk.subarray(0, bytesRead))
      total += bytesRead
    }
    return Buffer.concat(chunks)
  } finally {
    if (handle) await handle.close().catch(() => {})
  }
}

async function execBounded (executable, args, maxBytes, timeout) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, {
      env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/sbin:/usr/bin:/sbin:/bin' },
      stdio: ['ignore', 'pipe', 'ignore'],
      windowsHide: true
    })
    const chunks = []
    let total = 0
    let timedOut = false
    let settled = false
    const finish = (err, value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (err) reject(err)
      else resolve(value)
    }
    const timer = setTimeout(() => {
      timedOut = true
      child.kill('SIGKILL')
    }, timeout)
    if (timer.unref) timer.unref()
    child.stdout.on('data', chunk => {
      if (total >= maxBytes + 1) return
      const bounded = Buffer.from(chunk).subarray(0, maxBytes + 1 - total)
      chunks.push(bounded)
      total += bounded.byteLength
    })
    child.once('error', err => finish(err))
    child.once('close', code => {
      if (timedOut) return finish(Object.assign(new Error('capture command timed out'), { code: 'WATCHDOG_CAPTURE_COMMAND_TIMEOUT' }))
      if (code !== 0) return finish(Object.assign(new Error('capture command failed'), { code: 'WATCHDOG_CAPTURE_COMMAND_FAILED' }))
      finish(null, Buffer.concat(chunks))
    })
  })
}

function storedSource (kind, raw, observedAt) {
  const bounded = raw.subarray(0, SOURCE_MAX)
  const decoded = new TextDecoder('utf-8').decode(bounded)
  const redaction = redactText(decoded)
  const storage = boundedUtf8Text(redaction.text, SOURCE_MAX)
  const stored = Buffer.from(storage.data)
  return {
    record: {
      kind,
      observedAt,
      truncated: raw.byteLength > SOURCE_MAX || storage.truncated,
      originalBytes: raw.byteLength,
      storedBytes: stored.byteLength,
      sha256: sha256(stored),
      data: storage.data
    },
    redacted: redaction.redacted
  }
}

function normalizedCgroupPath (raw) {
  const text = raw.toString('utf8')
  for (const line of text.split('\n')) {
    const match = /^0::(\/[A-Za-z0-9_.@:/-]*)$/.exec(line)
    if (!match) continue
    const root = '/sys/fs/cgroup'
    const path = resolve(root, `.${match[1]}`)
    if (path !== root && !path.startsWith(`${root}${sep}`)) fail('WATCHDOG_CGROUP_PATH_INVALID')
    return path
  }
  return null
}

async function defaultCaptureLoaders (target) {
  const proc = `/proc/${target.mainPid}`
  const loaders = [
    ['systemd-show', () => execBounded('/usr/bin/systemctl', [
      'show', WATCHDOG_UNIT,
      '--property=ActiveState,SubState,MainPID,NRestarts,ExecMainStatus,MemoryCurrent,CPUUsageNSec',
      '--no-pager'
    ], SOURCE_MAX, 2000), true],
    ['journal', () => execBounded('/usr/bin/journalctl', [
      '--unit', WATCHDOG_UNIT, '--no-pager', '--output=short-iso', '--lines=200'
    ], SOURCE_MAX, 3000)],
    ['proc-status', () => readBounded(`${proc}/status`, SOURCE_MAX), true],
    ['proc-io', () => readBounded(`${proc}/io`, SOURCE_MAX), true],
    ['proc-limits', () => readBounded(`${proc}/limits`, SOURCE_MAX)],
    ['proc-cgroup', () => readBounded(`${proc}/cgroup`, SOURCE_MAX), true],
    ['pressure-cpu', () => readBounded('/proc/pressure/cpu', SOURCE_MAX)],
    ['pressure-io', () => readBounded('/proc/pressure/io', SOURCE_MAX)],
    ['pressure-memory', () => readBounded('/proc/pressure/memory', SOURCE_MAX)]
  ]
  try {
    const cgroupRaw = await readBounded(`${proc}/cgroup`, SOURCE_MAX)
    const cgroup = normalizedCgroupPath(cgroupRaw)
    if (cgroup) {
      for (const name of ['memory.current', 'memory.max', 'memory.events', 'cpu.pressure', 'io.pressure', 'memory.pressure']) {
        if (loaders.length >= MAX_SOURCES) break
        loaders.push([`cgroup-${name.replace('.', '-')}`, () => readBounded(join(cgroup, name), SOURCE_MAX)])
      }
    }
  } catch {}
  return loaders
}

async function cleanupDiagnostics (directory, now, authority) {
  const dirHandle = await openAuthorityDirectory(directory, authority)
  await dirHandle.close()
  const records = []
  let seen = 0
  const dir = await opendir(directory)
  try {
    for await (const entry of dir) {
      seen++
      if (seen > 512) fail('WATCHDOG_DIAGNOSTIC_DIRECTORY_OVERSIZED')
      const match = ARTIFACT_NAME.exec(entry.name)
      if (!match) continue
      if (records.length >= 256) fail('WATCHDOG_DIAGNOSTIC_ENUMERATION_OVERSIZED')
      records.push({ name: entry.name, timestamp: Number(match[1]) })
    }
  } finally {
    await dir.close().catch(() => {})
  }
  records.sort((a, b) => a.timestamp - b.timestamp || a.name.localeCompare(b.name))
  const expired = records.filter(record => now - record.timestamp > MAX_ARTIFACT_AGE_MS)
  const remaining = records.filter(record => now - record.timestamp <= MAX_ARTIFACT_AGE_MS)
  const excess = remaining.slice(0, Math.max(0, remaining.length - (MAX_ARTIFACTS - 1)))
  for (const record of [...expired, ...excess]) {
    const path = join(directory, record.name)
    let handle
    try {
      handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_CLOEXEC)
      const stat = await handle.stat()
      if (!stat.isFile() || stat.nlink !== 1 || stat.uid !== (authority.uid ?? 0) ||
          stat.gid !== (authority.gid ?? 0) || modeOf(stat) !== 0o600) {
        fail('WATCHDOG_DIAGNOSTIC_AUTHORITY_INVALID')
      }
    } finally {
      if (handle) await handle.close().catch(() => {})
    }
    await unlink(path)
  }
}

async function publishDiagnostic (directory, value, now, authority) {
  const bytes = Buffer.from(canonicalJson(value))
  if (bytes.byteLength > BUNDLE_MAX) fail('WATCHDOG_DIAGNOSTIC_BUNDLE_OVERSIZED')
  await cleanupDiagnostics(directory, now, authority)
  const digest = sha256(bytes)
  const name = `watchdog-${String(now).padStart(13, '0')}-${digest}.json`
  if (!ARTIFACT_NAME.test(name)) fail('WATCHDOG_DIAGNOSTIC_NAME_INVALID')
  const finalPath = join(directory, name)
  const temp = join(directory, `.${name}.${process.pid}.${randomBytes(12).toString('hex')}.tmp`)
  const parentHandle = await openAuthorityDirectory(directory, authority)
  let handle
  let linked = false
  try {
    handle = await open(temp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL |
      constants.O_NOFOLLOW | constants.O_CLOEXEC, 0o600)
    await handle.chmod(0o600)
    if (typeof handle.chown === 'function') await handle.chown(authority.uid ?? 0, authority.gid ?? 0)
    await handle.writeFile(bytes)
    await handle.sync()
    await handle.close()
    handle = null
    await link(temp, finalPath)
    linked = true
    await parentHandle.sync()
    await unlink(temp)
    await parentHandle.sync()
    const installed = await readAuthorityJson(finalPath, {
      label: 'diagnostic bundle',
      maxBytes: BUNDLE_MAX,
      mode: 0o600
    }, authority)
    if (!installed.bytes.equals(bytes)) fail('WATCHDOG_DIAGNOSTIC_INSTALL_VERIFY_FAILED')
    return { path: finalPath, sha256: digest, bytes: bytes.byteLength }
  } finally {
    if (handle) await handle.close().catch(() => {})
    if (!linked) await unlink(temp).catch(() => {})
    await parentHandle.close().catch(() => {})
  }
}

export async function captureDiagnostic ({
  target,
  policySha256,
  healthBody,
  healthStatus,
  now = Date.now(),
  paths = WATCHDOG_PATHS,
  authority = {},
  loaders
}) {
  if (!Buffer.isBuffer(healthBody)) healthBody = Buffer.from(healthBody)
  if (healthBody.byteLength > HEALTH_BODY_MAX) fail('WATCHDOG_HEALTH_BODY_OVERSIZED')
  if (!isObject(target) || target.unit !== WATCHDOG_UNIT || !LOWER_SHA256.test(target.executableSha256) ||
      !LOWER_SHA256.test(target.cgroupSha256)) fail('WATCHDOG_TARGET_INVALID')
  safeInteger(target.mainPid, 'target mainPid', 1)
  safeInteger(target.procStarttime, 'target procStarttime', 1)
  if (!LOWER_SHA256.test(policySha256)) fail('WATCHDOG_POLICY_DIGEST_INVALID')
  safeInteger(healthStatus, 'health status', 0, 999)
  const started = Date.now()
  const sourceLoaders = loaders || await defaultCaptureLoaders(target)
  if (!Array.isArray(sourceLoaders) || sourceLoaders.length > MAX_SOURCES) fail('WATCHDOG_SOURCE_ALLOWLIST_INVALID')
  const sources = []
  const counters = { attempted: 0, captured: 0, failed: 0, truncated: 0, redacted: 0 }
  for (const entry of sourceLoaders) {
    if (!Array.isArray(entry) || (entry.length !== 2 && entry.length !== 3) || typeof entry[0] !== 'string' ||
        !/^[a-z0-9.-]{1,64}$/.test(entry[0]) || typeof entry[1] !== 'function' ||
        (entry.length === 3 && typeof entry[2] !== 'boolean')) {
      fail('WATCHDOG_SOURCE_ALLOWLIST_INVALID')
    }
    if (Date.now() - started >= CAPTURE_MAX_MS) fail('WATCHDOG_CAPTURE_DEADLINE_EXCEEDED')
    counters.attempted++
    try {
      const raw = await entry[1]()
      const stored = storedSource(entry[0], Buffer.from(raw), now)
      sources.push(stored.record)
      counters.captured++
      if (stored.record.truncated) counters.truncated++
      counters.redacted += stored.redacted
    } catch {
      counters.failed++
      if (entry[2] === true) fail('WATCHDOG_REQUIRED_SOURCE_CAPTURE_FAILED')
    }
  }
  if (Date.now() - started > CAPTURE_MAX_MS) fail('WATCHDOG_CAPTURE_DEADLINE_EXCEEDED')
  const healthDigest = sha256(healthBody)
  const healthRedaction = redactText(new TextDecoder('utf-8').decode(healthBody))
  const healthStorage = boundedUtf8Text(healthRedaction.text, HEALTH_BODY_MAX)
  const storedHealth = Buffer.from(healthStorage.data)
  const bundle = {
    kind: 'HiveRelayWatchdogDiagnosticBundleV1',
    version: 1,
    capturedAt: now,
    target: {
      unit: target.unit,
      executableSha256: target.executableSha256,
      mainPid: target.mainPid,
      procStarttime: target.procStarttime,
      cgroupSha256: target.cgroupSha256
    },
    health: {
      status: healthStatus,
      bodySha256: healthDigest,
      originalBytes: healthBody.byteLength,
      storedBytes: storedHealth.byteLength,
      truncated: healthStorage.truncated,
      data: healthStorage.data
    },
    policySha256,
    sources,
    counters: { ...counters, redacted: counters.redacted + healthRedaction.redacted }
  }
  return publishDiagnostic(paths.diagnostics, bundle, now, authority)
}

export async function authorizeRestart ({
  target,
  healthBody,
  healthStatus,
  now = Date.now(),
  paths = WATCHDOG_PATHS,
  authority = {},
  loaders
}) {
  safeInteger(now, 'authorization time', 1)
  if (!isObject(target) || target.unit !== WATCHDOG_UNIT || !LOWER_SHA256.test(target.executableSha256) ||
      !LOWER_SHA256.test(target.cgroupSha256)) fail('WATCHDOG_TARGET_INVALID')
  safeInteger(target.mainPid, 'target mainPid', 1)
  safeInteger(target.procStarttime, 'target procStarttime', 1)
  if (!Buffer.isBuffer(healthBody)) healthBody = Buffer.from(healthBody)
  if (healthBody.byteLength !== 0) fail('WATCHDOG_RESTART_HEALTH_BODY_NONEMPTY')
  const first = await readAuthorizationSet({ paths, authority, now, target })
  const second = await readAuthorizationSet({ paths, authority, now, target })
  if (!sameAuthorizationSet(first, second)) fail('WATCHDOG_AUTHORITY_SUBSTITUTION')
  const policySha256 = sha256(second.policyRecord.bytes)
  const consumed = {
    kind: 'HiveRelayWatchdogConsumedSequenceV1',
    version: 1,
    sequence: second.policy.sequence,
    policySha256,
    consumedAt: now
  }
  validateConsumedSequence(consumed)
  await atomicReplaceAuthorityJson(paths.sequence, consumed, SEQUENCE_SPEC, authority)
  const diagnostic = await captureDiagnostic({
    target,
    policySha256,
    healthBody,
    healthStatus,
    now,
    paths,
    authority,
    loaders
  })
  return {
    policy: second.policy,
    policySha256,
    diagnostic,
    sequenceConsumed: true
  }
}

export function parseProcStarttime (text) {
  const close = text.lastIndexOf(')')
  if (close < 2) fail('WATCHDOG_PROC_STAT_INVALID')
  const fields = text.slice(close + 1).trim().split(/\s+/)
  if (fields.length < 20 || !/^[0-9]+$/.test(fields[19])) fail('WATCHDOG_PROC_STAT_INVALID')
  const value = Number(fields[19])
  return safeInteger(value, 'proc starttime', 1)
}

export function cgroupHasUnit (bytes, unit = WATCHDOG_UNIT) {
  const text = Buffer.from(bytes).toString('utf8')
  return text.split('\n').some(line => {
    const separator = line.indexOf(':/')
    if (separator < 1) return false
    const path = line.slice(separator + 1)
    return path === `/${unit}` || path.endsWith(`/${unit}`)
  })
}

async function hashFile (path) {
  const handle = await open(path, constants.O_RDONLY | constants.O_CLOEXEC)
  const hash = createHash('sha256')
  try {
    const buffer = Buffer.alloc(64 * 1024)
    while (true) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.byteLength, null)
      if (bytesRead === 0) break
      hash.update(buffer.subarray(0, bytesRead))
    }
  } finally {
    await handle.close()
  }
  return hash.digest('hex')
}

export async function snapshotProcess (pid, options = {}) {
  safeInteger(pid, 'pid', 1, 4_194_304)
  const procRoot = options.procRoot || '/proc'
  const proc = join(procRoot, String(pid))
  const [statText, cgroup, uptimeText] = await Promise.all([
    readFile(join(proc, 'stat'), 'utf8'),
    readFile(join(proc, 'cgroup')),
    readFile(join(procRoot, 'uptime'), 'utf8')
  ])
  const procStarttime = parseProcStarttime(statText)
  const executableSha256 = await hashFile(join(proc, 'exe'))
  if (!cgroupHasUnit(cgroup)) fail('WATCHDOG_CGROUP_UNIT_MISMATCH')
  const cgroupSha256 = sha256(cgroup)
  const uptime = Number(uptimeText.trim().split(/\s+/)[0])
  if (!Number.isFinite(uptime) || uptime < 0) fail('WATCHDOG_PROC_UPTIME_INVALID')
  let ticks = options.clkTck
  if (ticks === undefined) {
    const result = await execFileAsync('/usr/bin/getconf', ['CLK_TCK'], {
      encoding: 'utf8',
      env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/sbin:/usr/bin:/sbin:/bin' },
      timeout: 1000,
      maxBuffer: 128
    })
    ticks = Number(result.stdout.trim())
  }
  safeInteger(ticks, 'CLK_TCK', 1, 1_000_000)
  const ageSeconds = Math.floor(uptime - (procStarttime / ticks))
  if (!Number.isSafeInteger(ageSeconds)) fail('WATCHDOG_PROCESS_AGE_INVALID')
  return { procStarttime, executableSha256, cgroupSha256, ageSeconds }
}

function parseDecimal (text, label, min, max = Number.MAX_SAFE_INTEGER) {
  if (!/^(0|[1-9][0-9]*)$/.test(text)) fail('WATCHDOG_ARGUMENT_INVALID', `${label} is invalid`)
  return safeInteger(Number(text), label, min, max)
}

async function main (argv) {
  const command = argv[0]
  if (command === 'snapshot' && argv.length === 2) {
    const value = await snapshotProcess(parseDecimal(argv[1], 'pid', 1, 4_194_304))
    process.stdout.write(`${value.procStarttime}\t${value.executableSha256}\t${value.cgroupSha256}\t${value.ageSeconds}\n`)
    return
  }
  if (command === 'classify' && argv.length === 4) {
    const body = await readFile(argv[1])
    const outcome = classifyHealth({
      body,
      status: parseDecimal(argv[2], 'health status', 0, 999),
      curlExit: parseDecimal(argv[3], 'curl exit', 0, 255)
    })
    process.stdout.write(`${outcome}\n`)
    return
  }
  if (command === 'record' && argv.length === 6) {
    const result = await recordFailureOutcome({
      outcome: argv[1],
      target: {
        unit: argv[2],
        mainPid: parseDecimal(argv[3], 'mainPid', 1, 4_194_304),
        procStarttime: parseDecimal(argv[4], 'procStarttime', 1),
        executableSha256: argv[5]
      }
    })
    process.stdout.write(result.restartEligible ? 'eligible\n' : 'recorded\n')
    return
  }
  if (command === 'clear' && argv.length === 1) {
    await clearAuthorityFile(WATCHDOG_PATHS.failure, FAILURE_SPEC)
    process.stdout.write('cleared\n')
    return
  }
  if (command === 'diagnose' && argv.length === 8) {
    const healthBody = await readFile(argv[7])
    const diagnostic = await captureDiagnostic({
      target: {
        unit: argv[1],
        mainPid: parseDecimal(argv[2], 'mainPid', 1, 4_194_304),
        procStarttime: parseDecimal(argv[3], 'procStarttime', 1),
        executableSha256: argv[4],
        cgroupSha256: argv[5]
      },
      policySha256: '0'.repeat(64),
      healthStatus: parseDecimal(argv[6], 'health status', 0, 999),
      healthBody
    })
    process.stdout.write(['diagnostic', diagnostic.sha256, diagnostic.path].join('\t') + '\n')
    return
  }
  if (command === 'authorize' && argv.length === 8) {
    const healthBody = await readFile(argv[7])
    const result = await authorizeRestart({
      target: {
        unit: argv[1],
        mainPid: parseDecimal(argv[2], 'mainPid', 1, 4_194_304),
        procStarttime: parseDecimal(argv[3], 'procStarttime', 1),
        executableSha256: argv[4],
        cgroupSha256: argv[5]
      },
      healthStatus: parseDecimal(argv[6], 'health status', 0, 999),
      healthBody
    })
    const policy = result.policy
    process.stdout.write([
      'authorized',
      policy.termGraceMs,
      policy.killAllowed ? '1' : '0',
      result.policySha256,
      result.diagnostic.sha256,
      result.diagnostic.path
    ].join('\t') + '\n')
    return
  }
  fail('WATCHDOG_USAGE', 'invalid watchdog policy helper invocation')
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).catch(err => {
    const code = err && typeof err.code === 'string' ? err.code : 'WATCHDOG_POLICY_ERROR'
    process.stderr.write(`${code}\n`)
    process.exitCode = 1
  })
}
