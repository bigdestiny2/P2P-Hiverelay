import { createHash } from 'node:crypto'
import { constants as fsConstants } from 'node:fs'
import { open } from 'node:fs/promises'
import { isIP } from 'node:net'
import path from 'node:path'
import {
  PUBLIC_HIVE_GATEWAY_FINITE_POLICY
} from './public-hive-gateway-policy.mjs'

export const PUBLIC_HIVE_GATEWAY_EVIDENCE_SCHEMA = 'hiverelay-public-gateway-preflight-v2'
export const PUBLIC_HIVE_GATEWAY_PROBE_SCHEMA = 'hiverelay-public-gateway-probe-v1'
export const PUBLIC_HIVE_GATEWAY_PROBE_CHECKS = Object.freeze([
  'metadata',
  'exactBytes',
  'range',
  'head',
  'canonicalIdentity',
  'managementIsolation',
  'forwardedHostIsolation',
  'unavailableAppIsolation',
  'defaultSniRejection',
  'sniHostBinding'
])

const MAX_EVIDENCE_BYTES = 2 * 1024 * 1024
const DEFAULT_MAX_EVIDENCE_AGE_MS = 24 * 60 * 60 * 1000
const MAX_FUTURE_SKEW_MS = 5 * 60 * 1000
const MIN_GATEWAY_CERTIFICATE_REMAINING_MS = 7 * 24 * 60 * 60 * 1000
const RELEASE_TAG_PATTERN = /^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/
const RELEASE_SHA_PATTERN = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/i
const SHA256_PATTERN = /^[a-f0-9]{64}$/i
const FINGERPRINT256_PATTERN = /^(?:[a-f0-9]{2}:){31}[a-f0-9]{2}$/i
const DRIVE_VERSION_PATTERN = /^(?:0|[1-9][0-9]{0,19})$/
const Z32_ALPHABET = 'ybndrfg8ejkmcpqxot1uwisza345h769'
const FORBIDDEN_PUBLIC_VALUE_PATTERNS = [
  [/-----BEGIN [A-Z ]*(?:PRIVATE|SECRET) KEY-----/, 'private key block'],
  [/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b/, 'GitHub token'],
  [/\bgithub_pat_[A-Za-z0-9_]{20,}\b/, 'GitHub token'],
  [/\bAuthorization\s*:\s*/i, 'authorization header'],
  [/\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b/i, 'bearer token'],
  [/\bAPP_SEED=[^\s'"]+/i, 'APP_SEED'],
  [/\bHIVERELAY_API_KEY=[^\s'"]+/i, 'API key'],
  [/\bsk-[A-Za-z0-9_-]{20,}\b/, 'API key']
]

export async function readAndVerifyPublicHiveGatewayEvidence (opts) {
  const file = requireAbsolutePath(opts?.file, 'gateway evidence')
  const expected = normalizeExpectedRelease(opts)
  const buffer = await readBoundedRegularFile(file)
  const evidence = parseJsonObject(buffer)
  const verified = verifyPublicHiveGatewayEvidence(evidence, expected)
  return {
    ...verified,
    evidencePath: file,
    evidenceSha256: createHash('sha256').update(buffer).digest('hex')
  }
}

export function verifyPublicHiveGatewayEvidence (evidence, opts) {
  const expected = normalizeExpectedRelease(opts)
  requireObject(evidence, 'gateway evidence')
  requireOnlyKeys('gateway evidence', evidence, [
    'schema',
    'status',
    'checkedAt',
    'mode',
    'admissionProfile',
    'release',
    'config',
    'static',
    'nginx',
    'probe',
    'probeError'
  ])
  assertPublicSafeValues(evidence)

  requireEqual(evidence.schema, PUBLIC_HIVE_GATEWAY_EVIDENCE_SCHEMA, 'gateway evidence schema')
  requireEqual(evidence.status, 'pass', 'gateway evidence status')
  const checkedAtMs = requireIsoTimestamp(evidence.checkedAt, 'gateway evidence checkedAt')
  requireFreshTimestamp(checkedAtMs, 'gateway evidence checkedAt', expected)
  if (evidence.mode !== 'fleet') {
    throw new Error('gateway evidence must declare the explicit fleet production posture')
  }
  if (expected.requireMode && evidence.mode !== expected.requireMode) {
    throw new Error(`gateway evidence mode must equal ${JSON.stringify(expected.requireMode)}`)
  }
  if (typeof evidence.admissionProfile !== 'string' || evidence.admissionProfile.length < 1 ||
      evidence.admissionProfile.length > 128 || !/^[a-z0-9]+(?:-[a-z0-9]+)+$/.test(evidence.admissionProfile)) {
    throw new Error('gateway evidence admission profile must be an explicit versioned profile')
  }
  if (evidence.admissionProfile.startsWith('transitional-')) {
    throw new Error('gateway evidence must not use transitional public-app admission')
  }
  if (expected.requireAdmissionProfile) {
    requireEqual(evidence.admissionProfile, expected.requireAdmissionProfile, 'gateway evidence admission profile')
  }

  requireObject(evidence.release, 'gateway evidence release')
  requireOnlyKeys('gateway evidence release', evidence.release, ['target', 'sha'])
  requireEqual(evidence.release.target, expected.releaseTarget, 'gateway evidence release target')
  requireEqual(String(evidence.release.sha || '').toLowerCase(), expected.releaseSha, 'gateway evidence release SHA')

  requireObject(evidence.config, 'gateway evidence config')
  requireOnlyKeys('gateway evidence config', evidence.config, [
    'suffix',
    'appKeyCount',
    'apiHost',
    'apiPort',
    'gatewayHost',
    'gatewayPort',
    'connectAddress',
    'publicSuffixReady',
    'custodyEnabled',
    'physicalEnforcementRequired',
    'finiteProductionPolicy'
  ])
  const configuredSuffix = requireCanonicalDnsSuffix(evidence.config.suffix, 'gateway evidence config suffix')
  const configuredConnectAddress = requireIpAddress(evidence.config.connectAddress, 'gateway evidence config connectAddress')
  if (!Number.isSafeInteger(evidence.config.appKeyCount) || evidence.config.appKeyCount < 1) {
    throw new Error('gateway evidence config appKeyCount must be a positive integer')
  }
  if (typeof evidence.config.publicSuffixReady !== 'boolean') {
    throw new Error('gateway evidence config publicSuffixReady must be boolean')
  }
  if (evidence.config.appKeyCount > 1 && evidence.config.publicSuffixReady !== true) {
    throw new Error('multi-app fleet evidence requires Public Suffix isolation')
  }
  requireObject(evidence.config.finiteProductionPolicy, 'gateway evidence finite production policy')
  requireOnlyKeys('gateway evidence finite production policy', evidence.config.finiteProductionPolicy,
    Object.keys(PUBLIC_HIVE_GATEWAY_FINITE_POLICY))
  for (const [field, expectedValue] of Object.entries(PUBLIC_HIVE_GATEWAY_FINITE_POLICY)) {
    requireEqual(evidence.config.finiteProductionPolicy[field], expectedValue, `gateway evidence finite production policy ${field}`)
  }
  requireEqual(evidence.config.custodyEnabled, false, 'gateway evidence custody status')
  requireEqual(evidence.config.physicalEnforcementRequired, true, 'gateway evidence physical enforcement requirement')
  requireObject(evidence.static, 'gateway evidence static result')
  requireOnlyKeys('gateway evidence static result', evidence.static, ['ok', 'errors', 'warnings'])
  requireEqual(evidence.static.ok, true, 'gateway static preflight status')
  requireEmptyArray(evidence.static.errors, 'gateway static preflight errors')
  if (!Array.isArray(evidence.static.warnings)) throw new Error('gateway static preflight warnings must be an array')

  requireObject(evidence.nginx, 'gateway active nginx result')
  requireOnlyKeys('gateway active nginx result', evidence.nginx, ['ok', 'errors', 'source', 'sha256'])
  requireEqual(evidence.nginx.source, 'active', 'gateway nginx evidence source')
  if (!SHA256_PATTERN.test(evidence.nginx.sha256 || '')) throw new Error('gateway active nginx SHA-256 is invalid')
  const nginxSha256 = evidence.nginx.sha256.toLowerCase()
  if (expected.expectedNginxSha256) requireEqual(nginxSha256, expected.expectedNginxSha256, 'gateway active nginx SHA-256')
  requireEqual(evidence.nginx.ok, true, 'gateway nginx preflight status')
  requireEmptyArray(evidence.nginx.errors, 'gateway nginx preflight errors')
  requireEqual(evidence.probeError, null, 'gateway probe error')

  const probe = evidence.probe
  requireObject(probe, 'gateway live probe')
  requireOnlyKeys('gateway live probe', probe, [
    'schema',
    'observedAt',
    'origin',
    'connectAddress',
    'appKey',
    'path',
    'sha256',
    'bytes',
    'driveVersion',
    'tlsProtocol',
    'peerFingerprint256',
    'peerValidTo',
    'metadataSigned',
    'checks'
  ])
  requireEqual(probe.schema, PUBLIC_HIVE_GATEWAY_PROBE_SCHEMA, 'gateway live probe schema')
  const observedAtMs = requireIsoTimestamp(probe.observedAt, 'gateway live probe observedAt')
  requireFreshTimestamp(observedAtMs, 'gateway live probe observedAt', expected)
  if (observedAtMs > checkedAtMs) throw new Error('gateway live probe observedAt must not be after evidence checkedAt')
  const probeOrigin = requireHttpsOrigin(probe.origin)
  const probeConnectAddress = requireIpAddress(probe.connectAddress, 'gateway live probe connectAddress')
  requireEqual(probeConnectAddress, configuredConnectAddress, 'gateway live probe connectAddress binding')
  if (expected.expectedOrigin) requireEqual(probeOrigin.origin, expected.expectedOrigin, 'gateway live probe origin')
  if (expected.expectedConnectAddress) {
    requireEqual(probeConnectAddress, expected.expectedConnectAddress, 'gateway live probe expected connectAddress')
  }
  if (!/^[a-f0-9]{64}$/.test(probe.appKey || '')) throw new Error('gateway live probe appKey must be 64 lowercase hex characters')
  if (expected.expectedAppKey) requireEqual(probe.appKey, expected.expectedAppKey, 'gateway live probe expected appKey')
  const expectedProbeHostname = `${encodeZ32Key(Buffer.from(probe.appKey, 'hex'))}.${configuredSuffix}`
  if (probeOrigin.hostname !== expectedProbeHostname) {
    throw new Error('gateway live probe origin hostname must exactly encode appKey under the configured suffix')
  }
  if (typeof probe.path !== 'string' || !probe.path.startsWith('/') || probe.path.length > 4096 || hasControlChars(probe.path)) {
    throw new Error('gateway live probe path must be a bounded absolute URL path')
  }
  if (expected.expectedPath) requireEqual(probe.path, expected.expectedPath, 'gateway live probe expected path')
  if (!SHA256_PATTERN.test(probe.sha256 || '')) throw new Error('gateway live probe content SHA-256 is invalid')
  const contentSha256 = probe.sha256.toLowerCase()
  if (expected.expectedSha256) requireEqual(contentSha256, expected.expectedSha256, 'gateway live probe expected content SHA-256')
  if (!Number.isSafeInteger(probe.bytes) || probe.bytes < 1) throw new Error('gateway live probe byte count must be a positive integer')
  if (!DRIVE_VERSION_PATTERN.test(probe.driveVersion || '') || !Number.isSafeInteger(Number(probe.driveVersion))) {
    throw new Error('gateway live probe driveVersion must be a non-negative safe integer string')
  }
  if (expected.expectedDriveVersion) {
    requireEqual(probe.driveVersion, expected.expectedDriveVersion, 'gateway live probe expected driveVersion')
  }
  if (probe.tlsProtocol !== 'TLSv1.2' && probe.tlsProtocol !== 'TLSv1.3') {
    throw new Error('gateway live probe must use TLS 1.2 or TLS 1.3')
  }
  if (!FINGERPRINT256_PATTERN.test(probe.peerFingerprint256 || '')) {
    throw new Error('gateway live probe certificate fingerprint is invalid')
  }
  const peerFingerprint256 = probe.peerFingerprint256.toUpperCase()
  if (expected.expectedPeerFingerprint256) {
    requireEqual(peerFingerprint256, expected.expectedPeerFingerprint256, 'gateway live probe expected certificate fingerprint')
  }
  const peerValidTo = Date.parse(probe.peerValidTo)
  if (!Number.isFinite(peerValidTo) || peerValidTo - expected.nowMs < MIN_GATEWAY_CERTIFICATE_REMAINING_MS) {
    throw new Error('gateway live probe certificate must remain valid for at least 7 days')
  }

  requireObject(probe.checks, 'gateway live probe checks')
  requireOnlyKeys('gateway live probe checks', probe.checks, PUBLIC_HIVE_GATEWAY_PROBE_CHECKS)
  for (const check of PUBLIC_HIVE_GATEWAY_PROBE_CHECKS) {
    requireEqual(probe.checks[check], true, `gateway live probe check ${check}`)
  }

  return {
    schema: 'hiverelay-public-gateway-evidence-verification-v2',
    status: 'verified',
    mode: 'fleet',
    admissionProfile: evidence.admissionProfile,
    publicSuffixReady: evidence.config.publicSuffixReady,
    physicalEnforcementRequired: true,
    finiteProductionPolicy: { ...PUBLIC_HIVE_GATEWAY_FINITE_POLICY },
    releaseTarget: expected.releaseTarget,
    releaseSha: expected.releaseSha,
    checkedAt: evidence.checkedAt,
    probeObservedAt: probe.observedAt,
    origin: probeOrigin.origin,
    connectAddress: probeConnectAddress,
    appKey: probe.appKey,
    path: probe.path,
    contentSha256,
    driveVersion: probe.driveVersion,
    tlsProtocol: probe.tlsProtocol,
    peerFingerprint256,
    nginxSha256,
    checks: Object.fromEntries(PUBLIC_HIVE_GATEWAY_PROBE_CHECKS.map(name => [name, true]))
  }
}

function normalizeExpectedRelease (opts) {
  const releaseTarget = String(opts?.releaseTarget || '')
  const releaseSha = String(opts?.releaseSha || '').toLowerCase()
  if (!RELEASE_TAG_PATTERN.test(releaseTarget)) throw new Error('expected release target must be a tag like v1.2.3')
  if (!RELEASE_SHA_PATTERN.test(releaseSha)) throw new Error('expected release SHA must be 40 or 64 hex characters')
  const nowValue = opts?.nowMs ?? opts?.now ?? Date.now()
  const nowMs = nowValue instanceof Date ? nowValue.getTime() : Number(nowValue)
  const maxAgeMs = opts?.maxAgeMs ?? DEFAULT_MAX_EVIDENCE_AGE_MS
  if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw new Error('evidence verifier now must be a valid epoch timestamp')
  if (!Number.isSafeInteger(maxAgeMs) || maxAgeMs < 1) throw new Error('evidence verifier maxAgeMs must be a positive integer')
  const requireMode = opts?.requireMode || null
  if (requireMode && requireMode !== 'fleet') throw new Error('required gateway evidence mode must be fleet')
  const requireAdmissionProfile = opts?.requireAdmissionProfile || null
  if (requireAdmissionProfile && (typeof requireAdmissionProfile !== 'string' || requireAdmissionProfile.length > 128 ||
      !/^[a-z0-9]+(?:-[a-z0-9]+)+$/.test(requireAdmissionProfile) || requireAdmissionProfile.startsWith('transitional-'))) {
    throw new Error('required gateway admission profile must be an explicit non-transitional versioned profile')
  }
  const expectedOrigin = opts?.expectedOrigin ? requireHttpsOrigin(opts.expectedOrigin).origin : null
  const expectedConnectAddress = opts?.expectedConnectAddress
    ? requireIpAddress(opts.expectedConnectAddress, 'expected gateway connectAddress')
    : null
  const expectedAppKey = normalizeExpectedHex(opts?.expectedAppKey, 'expected gateway appKey')
  const expectedPath = opts?.expectedPath || null
  if (expectedPath && (typeof expectedPath !== 'string' || !expectedPath.startsWith('/') ||
      expectedPath.length > 4096 || hasControlChars(expectedPath))) {
    throw new Error('expected gateway path must be a bounded absolute URL path')
  }
  const expectedSha256 = normalizeExpectedHex(opts?.expectedSha256, 'expected gateway content SHA-256')
  const expectedDriveVersion = opts?.expectedDriveVersion || null
  if (expectedDriveVersion && (!DRIVE_VERSION_PATTERN.test(expectedDriveVersion) || !Number.isSafeInteger(Number(expectedDriveVersion)))) {
    throw new Error('expected gateway driveVersion is invalid')
  }
  const expectedPeerFingerprint256 = opts?.expectedPeerFingerprint256
    ? String(opts.expectedPeerFingerprint256).toUpperCase()
    : null
  if (expectedPeerFingerprint256 && !FINGERPRINT256_PATTERN.test(expectedPeerFingerprint256)) {
    throw new Error('expected gateway certificate fingerprint is invalid')
  }
  const expectedNginxSha256 = normalizeExpectedHex(opts?.expectedNginxSha256, 'expected gateway nginx SHA-256')
  return {
    releaseTarget,
    releaseSha,
    nowMs,
    maxAgeMs,
    requireMode,
    requireAdmissionProfile,
    expectedOrigin,
    expectedConnectAddress,
    expectedAppKey,
    expectedPath,
    expectedSha256,
    expectedDriveVersion,
    expectedPeerFingerprint256,
    expectedNginxSha256
  }
}

function normalizeExpectedHex (value, label) {
  if (value == null || value === '') return null
  const normalized = String(value).toLowerCase()
  if (!SHA256_PATTERN.test(normalized)) throw new Error(`${label} is invalid`)
  return normalized
}

async function readBoundedRegularFile (file) {
  let handle
  try {
    if (typeof fsConstants.O_NOFOLLOW !== 'number') {
      throw new Error('gateway evidence cannot be opened safely on this platform')
    }
    handle = await open(file, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW)
    const before = await handle.stat({ bigint: true })
    assertEvidenceFile(before)

    // A fixed-size descriptor read prevents an attacker from growing a file
    // indefinitely after the initial stat and making readFile allocate without
    // a bound. One extra byte is enough to prove the size limit was crossed.
    const buffer = Buffer.allocUnsafe(MAX_EVIDENCE_BYTES + 1)
    let length = 0
    while (length < buffer.byteLength) {
      const { bytesRead } = await handle.read(buffer, length, buffer.byteLength - length, length)
      if (bytesRead === 0) break
      length += bytesRead
    }
    if (length > MAX_EVIDENCE_BYTES) {
      throw new Error(`gateway evidence must be a regular file no larger than ${MAX_EVIDENCE_BYTES} bytes`)
    }

    const after = await handle.stat({ bigint: true })
    if (!sameEvidenceSnapshot(before, after) || BigInt(length) !== after.size) {
      throw new Error('gateway evidence changed while it was being read')
    }
    await assertEvidencePathIdentity(file, after)
    return buffer.subarray(0, length)
  } catch (err) {
    if (err?.message?.startsWith('gateway evidence')) throw err
    throw new Error('gateway evidence must be a readable, non-symlink regular file')
  } finally {
    await handle?.close().catch(() => {})
  }
}

function assertEvidenceFile (info) {
  if (!info.isFile() || info.nlink !== 1n || info.size < 1n || info.size > BigInt(MAX_EVIDENCE_BYTES)) {
    throw new Error(`gateway evidence must be a regular file no larger than ${MAX_EVIDENCE_BYTES} bytes with one link`)
  }
}

function sameEvidenceSnapshot (left, right) {
  return left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
}

async function assertEvidencePathIdentity (file, expected) {
  let current
  try {
    current = await open(file, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW)
    const info = await current.stat({ bigint: true })
    if (!sameEvidenceSnapshot(expected, info)) {
      throw new Error('gateway evidence path changed while it was being inspected')
    }
  } catch (err) {
    if (err?.message?.startsWith('gateway evidence')) throw err
    throw new Error('gateway evidence path changed while it was being inspected')
  } finally {
    await current?.close().catch(() => {})
  }
}

function parseJsonObject (buffer) {
  let value
  try {
    value = JSON.parse(buffer.toString('utf8'))
  } catch {
    throw new Error('gateway evidence must contain valid JSON')
  }
  requireObject(value, 'gateway evidence')
  return value
}

function requireAbsolutePath (value, label) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || value.length > 4096 || hasControlChars(value)) {
    throw new Error(`${label} path must be a bounded absolute path`)
  }
  return value
}

function requireHttpsOrigin (value) {
  let url
  try {
    url = new URL(value)
  } catch {
    throw new Error('gateway live probe origin must be an HTTPS origin')
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw new Error('gateway live probe origin must be a credential-free HTTPS origin')
  }
  return url
}

function requireCanonicalDnsSuffix (value, label) {
  if (typeof value !== 'string' || value.length < 3 || value.length > 200 || value !== value.toLowerCase() ||
      value.startsWith('.') || value.endsWith('.') || value.includes('..')) {
    throw new Error(`${label} must be a canonical lowercase DNS suffix`)
  }
  const labels = value.split('.')
  if (labels.length < 2 || labels.some(part => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(part))) {
    throw new Error(`${label} must be a canonical lowercase DNS suffix`)
  }
  return value
}

function requireIpAddress (value, label) {
  if (typeof value !== 'string' || value.length < 2 || value.length > 64 || value !== value.trim() || isIP(value) === 0) {
    throw new Error(`${label} must be an explicit IP address`)
  }
  return value.toLowerCase()
}

function encodeZ32Key (bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.byteLength !== 32) throw new Error('gateway live probe appKey must encode 32 bytes')
  let output = ''
  let accumulator = 0
  let bits = 0
  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte
    bits += 8
    while (bits >= 5) {
      bits -= 5
      output += Z32_ALPHABET[(accumulator >>> bits) & 31]
      accumulator &= bits === 0 ? 0 : (1 << bits) - 1
    }
  }
  if (bits > 0) output += Z32_ALPHABET[(accumulator << (5 - bits)) & 31]
  return output
}

function requireObject (value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`)
}

function requireOnlyKeys (label, value, allowed) {
  const allowedSet = new Set(allowed)
  const extra = Object.keys(value).filter(key => !allowedSet.has(key))
  if (extra.length > 0) throw new Error(`${label} has unsupported fields: ${extra.join(', ')}`)
}

function requireEqual (actual, expected, label) {
  if (actual !== expected) throw new Error(`${label} must equal ${JSON.stringify(expected)}`)
}

function requireEmptyArray (value, label) {
  if (!Array.isArray(value) || value.length !== 0) throw new Error(`${label} must be an empty array`)
}

function requireIsoTimestamp (value, label) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) || !Number.isFinite(Date.parse(value))) {
    throw new Error(`${label} must be an ISO-8601 timestamp`)
  }
  return Date.parse(value)
}

function requireFreshTimestamp (valueMs, label, expected) {
  if (valueMs < expected.nowMs - expected.maxAgeMs) {
    throw new Error(`${label} is older than the allowed evidence age`)
  }
  if (valueMs > expected.nowMs + MAX_FUTURE_SKEW_MS) {
    throw new Error(`${label} is more than 5 minutes in the future`)
  }
}

function assertPublicSafeValues (value) {
  visit(value, '$')

  function visit (node, at) {
    if (node == null) return
    if (typeof node === 'string') {
      if (hasControlChars(node)) throw new Error(`gateway evidence must not contain control characters at ${at}`)
      for (const [pattern, name] of FORBIDDEN_PUBLIC_VALUE_PATTERNS) {
        if (pattern.test(node)) throw new Error(`gateway evidence must not contain ${name} at ${at}`)
      }
      try {
        const url = new URL(node)
        if (url.username || url.password) throw new Error(`gateway evidence must not expose URL credentials at ${at}`)
      } catch (err) {
        if (err?.message?.startsWith('gateway evidence')) throw err
      }
      return
    }
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i++) visit(node[i], `${at}[${i}]`)
      return
    }
    if (typeof node === 'object') {
      for (const [key, child] of Object.entries(node)) visit(child, `${at}.${key}`)
    }
  }
}

function hasControlChars (value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if (code <= 31 || code === 127) return true
  }
  return false
}
