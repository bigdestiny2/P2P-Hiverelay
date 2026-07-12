import { Buffer } from 'node:buffer'
import { createHash } from 'node:crypto'
import { isIP } from 'node:net'
import {
  PUBLIC_HIVE_GATEWAY_DEPLOYMENT_PROFILE,
  PUBLIC_HIVE_GATEWAY_FINITE_POLICY
} from './public-hive-gateway-policy.mjs'

export const PUBLIC_HIVE_GATEWAY_RELEASE_SCHEMA = 'hiverelay-public-gateway-release-v1'
export const PUBLIC_HIVE_GATEWAY_RELEASE_MANIFEST_PATH = 'fleet/public-hive-gateway-release.json'
export const PUBLIC_HIVE_GATEWAY_OPERATOR_CONTRACT_SCHEMA = 'hiverelay-public-gateway-operator-contract-v1'
export const PUBLIC_HIVE_GATEWAY_OPERATOR_CONTRACT_DIRECTORY = 'fleet/public-hive-gateway-operators'
export const MIN_PUBLIC_HIVE_GATEWAY_OBSERVATION_WINDOW_MS = 24 * 60 * 60 * 1000
export const MAX_PUBLIC_HIVE_GATEWAY_OBSERVATION_WINDOW_MS = 7 * 24 * 60 * 60 * 1000

const HIVE_Z32_ALPHABET = 'ybndrfg8ejkmcpqxot1uwisza345h769'
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/
const ADMISSION_PROFILE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/
const RELEASE_TAG_PATTERN = /^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/
const SHA256_PATTERN = /^[a-f0-9]{64}$/
const FINGERPRINT256_PATTERN = /^(?:[A-F0-9]{2}:){31}[A-F0-9]{2}$/
const RELAY_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/
const DRIVE_VERSION_PATTERN = /^(?:0|[1-9][0-9]{0,19})$/
const OPERATOR_ID_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/

export function normalizePublicHiveGatewayReleaseManifest (manifest, opts = {}) {
  requireObject(manifest, 'public gateway release manifest')
  requireOnlyKeys('public gateway release manifest', manifest, [
    'schema',
    'enabled',
    'releaseTarget',
    'admissionProfile',
    'observationWindowMs',
    'maxProbeGapMs',
    'cohort'
  ])
  requireEqual(manifest.schema, PUBLIC_HIVE_GATEWAY_RELEASE_SCHEMA, 'public gateway release manifest schema')

  if (manifest.enabled !== true) {
    throw new Error('public gateway release manifest must be explicitly enabled')
  }
  if (!RELEASE_TAG_PATTERN.test(manifest.releaseTarget || '')) {
    throw new Error('public gateway release manifest releaseTarget must be a tag like v1.2.3')
  }
  if (opts.releaseTarget && manifest.releaseTarget !== opts.releaseTarget) {
    throw new Error(`public gateway release manifest must target ${opts.releaseTarget}`)
  }
  if (!ADMISSION_PROFILE_PATTERN.test(manifest.admissionProfile || '') ||
      manifest.admissionProfile.startsWith('transitional-')) {
    throw new Error('public gateway release manifest requires a bounded, frozen admissionProfile')
  }
  if (!Number.isSafeInteger(manifest.observationWindowMs) ||
      manifest.observationWindowMs < MIN_PUBLIC_HIVE_GATEWAY_OBSERVATION_WINDOW_MS ||
      manifest.observationWindowMs > MAX_PUBLIC_HIVE_GATEWAY_OBSERVATION_WINDOW_MS) {
    throw new Error('public gateway release observationWindowMs must be between 24 hours and 7 days')
  }
  if (!Number.isSafeInteger(manifest.maxProbeGapMs) || manifest.maxProbeGapMs < 60 * 1000 ||
      manifest.maxProbeGapMs > 30 * 60 * 1000) {
    throw new Error('public gateway release maxProbeGapMs must be between 1 and 30 minutes')
  }
  if (!Array.isArray(manifest.cohort) || manifest.cohort.length < 1 || manifest.cohort.length > 128) {
    throw new Error('public gateway release manifest must name 1 to 128 cohort relays')
  }

  const relayNames = new Set()
  const normalizedCohort = manifest.cohort.map((entry, index) => {
    const label = `public gateway release cohort[${index}]`
    requireObject(entry, label)
    requireOnlyKeys(label, entry, [
      'relay',
      'channel',
      'suffix',
      'origin',
      'connectAddress',
      'appKey',
      'path',
      'contentSha256',
      'driveVersion',
      'peerFingerprint256',
      'nginxConfigSha256',
      'deploymentProfile',
      'operatorContractSha256'
    ])
    if (!RELAY_NAME_PATTERN.test(entry.relay || '')) throw new Error(`${label} relay is invalid`)
    if (relayNames.has(entry.relay)) throw new Error(`public gateway release cohort repeats relay ${entry.relay}`)
    relayNames.add(entry.relay)
    if (entry.channel !== 'canary' && entry.channel !== 'stable') {
      throw new Error(`${label} channel must be canary or stable`)
    }

    const suffix = normalizeManifestHostSuffix(entry.suffix)
    if (!suffix) throw new Error(`${label} suffix is invalid`)
    const appKey = String(entry.appKey || '').toLowerCase()
    if (!SHA256_PATTERN.test(appKey)) throw new Error(`${label} appKey must be 64 lowercase hex characters`)
    const expectedHost = `${encodeManifestAppKey(Buffer.from(appKey, 'hex'))}.${suffix}`
    const origin = normalizeHttpsOrigin(entry.origin, label)
    if (origin.hostname !== expectedHost) {
      throw new Error(`${label} origin must encode its exact appKey and suffix`)
    }
    if (isIP(entry.connectAddress) === 0) throw new Error(`${label} connectAddress must be an exact IP address`)
    const releasePath = requireCanonicalOriginPath(entry.path, `${label} path`)
    const contentSha256 = String(entry.contentSha256 || '').toLowerCase()
    if (!SHA256_PATTERN.test(contentSha256)) throw new Error(`${label} contentSha256 is invalid`)
    if (!DRIVE_VERSION_PATTERN.test(entry.driveVersion || '') || !Number.isSafeInteger(Number(entry.driveVersion))) {
      throw new Error(`${label} driveVersion must be a non-negative safe integer string`)
    }
    const peerFingerprint256 = String(entry.peerFingerprint256 || '').toUpperCase()
    if (!FINGERPRINT256_PATTERN.test(peerFingerprint256)) throw new Error(`${label} peerFingerprint256 is invalid`)
    const nginxConfigSha256 = String(entry.nginxConfigSha256 || '').toLowerCase()
    if (!SHA256_PATTERN.test(nginxConfigSha256)) throw new Error(`${label} nginxConfigSha256 is invalid`)
    let deploymentProfile = null
    let operatorContractSha256 = null
    if (entry.deploymentProfile != null || entry.operatorContractSha256 != null) {
      if (entry.deploymentProfile !== PUBLIC_HIVE_GATEWAY_DEPLOYMENT_PROFILE) {
        throw new Error(`${label} deploymentProfile must be exactly ${PUBLIC_HIVE_GATEWAY_DEPLOYMENT_PROFILE}`)
      }
      operatorContractSha256 = String(entry.operatorContractSha256 || '').toLowerCase()
      if (!SHA256_PATTERN.test(operatorContractSha256)) {
        throw new Error(`${label} operatorContractSha256 is required for ${PUBLIC_HIVE_GATEWAY_DEPLOYMENT_PROFILE}`)
      }
      deploymentProfile = PUBLIC_HIVE_GATEWAY_DEPLOYMENT_PROFILE
    }

    const normalized = {
      relay: entry.relay,
      channel: entry.channel,
      suffix,
      origin: origin.origin,
      connectAddress: entry.connectAddress,
      appKey,
      path: releasePath,
      contentSha256,
      driveVersion: entry.driveVersion,
      peerFingerprint256,
      nginxConfigSha256
    }
    if (deploymentProfile) {
      normalized.deploymentProfile = deploymentProfile
      normalized.operatorContractSha256 = operatorContractSha256
    }
    return Object.freeze(normalized)
  })
  if (!normalizedCohort.some(entry => entry.channel === 'canary')) {
    throw new Error('public gateway release manifest must include at least one canary relay')
  }
  if (opts.requirePublicT1 === true) {
    const legacy = normalizedCohort.find(entry =>
      entry.deploymentProfile !== PUBLIC_HIVE_GATEWAY_DEPLOYMENT_PROFILE ||
      !SHA256_PATTERN.test(entry.operatorContractSha256 || '')
    )
    if (legacy) {
      throw new Error(`public gateway release cohort relay ${legacy.relay} must use ${PUBLIC_HIVE_GATEWAY_DEPLOYMENT_PROFILE} with a canonical operator contract digest`)
    }
  }

  return Object.freeze({
    schema: PUBLIC_HIVE_GATEWAY_RELEASE_SCHEMA,
    enabled: true,
    releaseTarget: manifest.releaseTarget,
    admissionProfile: manifest.admissionProfile,
    observationWindowMs: manifest.observationWindowMs,
    maxProbeGapMs: manifest.maxProbeGapMs,
    cohort: Object.freeze(normalizedCohort)
  })
}

export function cohortEntryForRelay (manifest, relayName) {
  const entries = manifest.cohort.filter(entry => entry.relay === relayName)
  if (entries.length !== 1) throw new Error(`public gateway release manifest does not uniquely approve relay ${relayName}`)
  return entries[0]
}

export function cohortEntriesForChannel (manifest, channel) {
  if (channel !== 'canary' && channel !== 'stable') throw new Error('public gateway cohort channel must be canary or stable')
  return manifest.cohort.filter(entry => entry.channel === channel)
}

export function operatorContractPathForRelay (relayName) {
  if (!RELAY_NAME_PATTERN.test(relayName || '')) throw new Error('operator contract relay name is invalid')
  return `${PUBLIC_HIVE_GATEWAY_OPERATOR_CONTRACT_DIRECTORY}/${relayName}.json`
}

export function normalizePublicHiveGatewayOperatorContract (value, opts = {}) {
  const label = 'public gateway operator contract'
  requireObject(value, label)
  if (Object.hasOwn(value, 'appLabel') || Object.hasOwn(value, 'appHostname') || Object.hasOwn(value, 'origin')) {
    requireOnlyKeys(label, value, [
      'schema', 'deploymentProfile', 'relay', 'channel', 'operatorId',
      'registrableDomain', 'apiHostname', 'suffix', 'appKey', 'appLabel',
      'appHostname', 'origin', 'addressFamilyPolicy', 'expectedAddresses',
      'expectedConnectAddress', 'certificateFingerprint256',
      'certificateSpkiSha256', 'publicSuffixReady', 'finiteProductionPolicy',
      'release'
    ])
    value = {
      schema: value.schema,
      deploymentProfile: value.deploymentProfile,
      relay: value.relay,
      channel: value.channel,
      operatorId: value.operatorId,
      registrableDomain: value.registrableDomain,
      apiHostname: value.apiHostname,
      suffix: value.suffix,
      appKey: value.appKey,
      addressFamilyPolicy: value.addressFamilyPolicy,
      expectedAddresses: value.expectedAddresses,
      expectedConnectAddress: value.expectedConnectAddress,
      certificateFingerprint256: value.certificateFingerprint256,
      certificateSpkiSha256: value.certificateSpkiSha256,
      publicSuffixReady: value.publicSuffixReady,
      finiteProductionPolicy: value.finiteProductionPolicy,
      release: value.release
    }
  }
  requireOnlyKeys(label, value, [
    'schema',
    'deploymentProfile',
    'relay',
    'channel',
    'operatorId',
    'registrableDomain',
    'apiHostname',
    'suffix',
    'appKey',
    'addressFamilyPolicy',
    'expectedAddresses',
    'expectedConnectAddress',
    'certificateFingerprint256',
    'certificateSpkiSha256',
    'publicSuffixReady',
    'finiteProductionPolicy',
    'release'
  ])
  requireEqual(value.schema, PUBLIC_HIVE_GATEWAY_OPERATOR_CONTRACT_SCHEMA, `${label} schema`)
  requireEqual(value.deploymentProfile, PUBLIC_HIVE_GATEWAY_DEPLOYMENT_PROFILE, `${label} deploymentProfile`)
  if (!RELAY_NAME_PATTERN.test(value.relay || '')) throw new Error(`${label} relay is invalid`)
  if (opts.relay && value.relay !== opts.relay) throw new Error(`${label} relay must equal ${opts.relay}`)
  if (value.channel !== 'canary' && value.channel !== 'stable') throw new Error(`${label} channel must be canary or stable`)
  if (!OPERATOR_ID_PATTERN.test(value.operatorId || '')) throw new Error(`${label} operatorId is invalid`)
  const registrableDomain = requireCanonicalDnsName(value.registrableDomain, `${label} registrableDomain`)
  const apiHostname = requireCanonicalDnsName(value.apiHostname, `${label} apiHostname`)
  const suffix = requireCanonicalDnsName(value.suffix, `${label} suffix`)
  if (suffix === registrableDomain || !suffix.endsWith(`.${registrableDomain}`)) {
    throw new Error(`${label} suffix must be a proper child of registrableDomain`)
  }
  if (apiHostname === suffix || apiHostname.endsWith(`.${suffix}`) ||
      apiHostname === registrableDomain || !apiHostname.endsWith(`.${registrableDomain}`)) {
    throw new Error(`${label} apiHostname must be a separate exact child outside the app suffix`)
  }
  const appKey = String(value.appKey || '').toLowerCase()
  if (!SHA256_PATTERN.test(appKey)) throw new Error(`${label} appKey is invalid`)
  const appLabel = encodeManifestAppKey(Buffer.from(appKey, 'hex'))
  const appHostname = `${appLabel}.${suffix}`
  const origin = `https://${appHostname}`

  const addressFamilyPolicy = value.addressFamilyPolicy
  if (!['dual-stack', 'ipv4-only', 'ipv6-only'].includes(addressFamilyPolicy)) {
    throw new Error(`${label} addressFamilyPolicy is invalid`)
  }
  if (!Array.isArray(value.expectedAddresses) || value.expectedAddresses.length < 1 || value.expectedAddresses.length > 2) {
    throw new Error(`${label} expectedAddresses must contain 1 or 2 addresses for the Phase 1 full-probe budget`)
  }
  const expectedAddresses = value.expectedAddresses.map((address, index) =>
    requireCanonicalIp(address, `${label} expectedAddresses[${index}]`))
  if (new Set(expectedAddresses).size !== expectedAddresses.length) throw new Error(`${label} expectedAddresses contains duplicates`)
  expectedAddresses.sort(compareIpAddresses)
  const hasIpv4 = expectedAddresses.some(address => isIP(address) === 4)
  const hasIpv6 = expectedAddresses.some(address => isIP(address) === 6)
  if (addressFamilyPolicy === 'dual-stack' && (!hasIpv4 || !hasIpv6)) throw new Error(`${label} dual-stack policy requires IPv4 and IPv6`)
  if (addressFamilyPolicy === 'ipv4-only' && (!hasIpv4 || hasIpv6)) throw new Error(`${label} ipv4-only policy has invalid addresses`)
  if (addressFamilyPolicy === 'ipv6-only' && (!hasIpv6 || hasIpv4)) throw new Error(`${label} ipv6-only policy has invalid addresses`)
  const expectedConnectAddress = requireCanonicalIp(value.expectedConnectAddress, `${label} expectedConnectAddress`)
  if (!isLoopbackIp(expectedConnectAddress) && !expectedAddresses.includes(expectedConnectAddress)) {
    throw new Error(`${label} expectedConnectAddress must be loopback or a reviewed public address`)
  }
  const certificateFingerprint256 = String(value.certificateFingerprint256 || '').toUpperCase()
  if (!FINGERPRINT256_PATTERN.test(certificateFingerprint256)) throw new Error(`${label} certificateFingerprint256 is invalid`)
  const certificateSpkiSha256 = String(value.certificateSpkiSha256 || '').toLowerCase()
  if (!SHA256_PATTERN.test(certificateSpkiSha256)) throw new Error(`${label} certificateSpkiSha256 is invalid`)
  if (typeof value.publicSuffixReady !== 'boolean') throw new Error(`${label} publicSuffixReady must be boolean`)
  const finiteProductionPolicy = normalizeFiniteProductionPolicy(value.finiteProductionPolicy, label)
  const release = normalizeOperatorRelease(value.release, label, opts)

  return Object.freeze({
    schema: PUBLIC_HIVE_GATEWAY_OPERATOR_CONTRACT_SCHEMA,
    deploymentProfile: PUBLIC_HIVE_GATEWAY_DEPLOYMENT_PROFILE,
    relay: value.relay,
    channel: value.channel,
    operatorId: value.operatorId,
    registrableDomain,
    apiHostname,
    suffix,
    appKey,
    appLabel,
    appHostname,
    origin,
    addressFamilyPolicy,
    expectedAddresses: Object.freeze(expectedAddresses),
    expectedConnectAddress,
    certificateFingerprint256,
    certificateSpkiSha256,
    publicSuffixReady: value.publicSuffixReady,
    finiteProductionPolicy,
    release
  })
}

export function canonicalPublicHiveGatewayOperatorContract (value, opts = {}) {
  return canonicalJson(normalizePublicHiveGatewayOperatorContract(value, opts))
}

export function sha256PublicHiveGatewayOperatorContract (value, opts = {}) {
  return createHash('sha256').update(canonicalPublicHiveGatewayOperatorContract(value, opts)).digest('hex')
}

export function assertOperatorContractMatchesCohort (contractValue, manifest, cohortEntry) {
  const contract = normalizePublicHiveGatewayOperatorContract(contractValue, {
    relay: cohortEntry.relay,
    releaseTarget: manifest.releaseTarget
  })
  if (cohortEntry.deploymentProfile !== PUBLIC_HIVE_GATEWAY_DEPLOYMENT_PROFILE) {
    throw new Error(`public gateway cohort ${cohortEntry.relay} is not operator-contract bound`)
  }
  const comparisons = {
    channel: cohortEntry.channel,
    suffix: cohortEntry.suffix,
    origin: cohortEntry.origin,
    expectedConnectAddress: cohortEntry.connectAddress,
    appKey: cohortEntry.appKey,
    certificateFingerprint256: cohortEntry.peerFingerprint256
  }
  for (const [field, expected] of Object.entries(comparisons)) {
    if (contract[field] !== expected) throw new Error(`operator contract ${field} does not match cohort ${cohortEntry.relay}`)
  }
  const releaseComparisons = {
    target: manifest.releaseTarget,
    expectedPath: cohortEntry.path,
    expectedContentSha256: cohortEntry.contentSha256,
    expectedDriveVersion: cohortEntry.driveVersion,
    expectedNginxSha256: cohortEntry.nginxConfigSha256
  }
  for (const [field, expected] of Object.entries(releaseComparisons)) {
    if (contract.release[field] !== expected) throw new Error(`operator contract release ${field} does not match cohort ${cohortEntry.relay}`)
  }
  const digest = sha256PublicHiveGatewayOperatorContract(contract)
  if (digest !== cohortEntry.operatorContractSha256) {
    throw new Error(`operator contract digest does not match cohort ${cohortEntry.relay}`)
  }
  return { contract, digest }
}

function normalizeFiniteProductionPolicy (value, parentLabel) {
  const label = `${parentLabel} finiteProductionPolicy`
  requireObject(value, label)
  requireOnlyKeys(label, value, Object.keys(PUBLIC_HIVE_GATEWAY_FINITE_POLICY))
  for (const [field, expected] of Object.entries(PUBLIC_HIVE_GATEWAY_FINITE_POLICY)) {
    requireEqual(value[field], expected, `${label} ${field}`)
  }
  return Object.freeze({ ...PUBLIC_HIVE_GATEWAY_FINITE_POLICY })
}

function normalizeOperatorRelease (value, parentLabel, opts) {
  const label = `${parentLabel} release`
  requireObject(value, label)
  requireOnlyKeys(label, value, [
    'target', 'expectedPath', 'expectedContentSha256', 'expectedDriveVersion', 'expectedNginxSha256'
  ])
  if (!RELEASE_TAG_PATTERN.test(value.target || '')) throw new Error(`${label} target is invalid`)
  if (opts.releaseTarget && value.target !== opts.releaseTarget) throw new Error(`${label} target must equal ${opts.releaseTarget}`)
  const expectedPath = requireCanonicalOriginPath(value.expectedPath, `${label} expectedPath`)
  const expectedContentSha256 = String(value.expectedContentSha256 || '').toLowerCase()
  if (!SHA256_PATTERN.test(expectedContentSha256)) throw new Error(`${label} expectedContentSha256 is invalid`)
  const expectedDriveVersion = String(value.expectedDriveVersion || '')
  if (!DRIVE_VERSION_PATTERN.test(expectedDriveVersion) || !Number.isSafeInteger(Number(expectedDriveVersion))) {
    throw new Error(`${label} expectedDriveVersion is invalid`)
  }
  const expectedNginxSha256 = String(value.expectedNginxSha256 || '').toLowerCase()
  if (!SHA256_PATTERN.test(expectedNginxSha256)) throw new Error(`${label} expectedNginxSha256 is invalid`)
  return Object.freeze({
    target: value.target,
    expectedPath,
    expectedContentSha256,
    expectedDriveVersion,
    expectedNginxSha256
  })
}

function normalizeHttpsOrigin (value, label) {
  let url
  try {
    url = new URL(value)
  } catch {
    throw new Error(`${label} origin must be an HTTPS origin`)
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw new Error(`${label} origin must be a credential-free HTTPS origin`)
  }
  return url
}

// Keep the signed-manifest validator dependency-free. Release workflows invoke
// it immediately after checkout, before npm dependencies exist, so importing
// the runtime gateway helper (and its b4a dependency) would weaken the earliest
// fail-closed publication gate.
function encodeManifestAppKey (key) {
  const bytes = Buffer.from(key)
  if (bytes.byteLength !== 32) throw new Error('Hive app key must be 32 bytes')

  let output = ''
  let accumulator = 0
  let bits = 0
  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte
    bits += 8
    while (bits >= 5) {
      bits -= 5
      output += HIVE_Z32_ALPHABET[(accumulator >>> bits) & 31]
      accumulator &= bits === 0 ? 0 : (1 << bits) - 1
    }
  }
  if (bits > 0) output += HIVE_Z32_ALPHABET[(accumulator << (5 - bits)) & 31]
  return output
}

function normalizeManifestHostSuffix (value) {
  if (typeof value !== 'string') return null
  let suffix = value.trim().toLowerCase()
  if (suffix.endsWith('.')) suffix = suffix.slice(0, -1)
  if (!suffix || suffix.length > 200 || suffix.includes('..')) return null
  const labels = suffix.split('.')
  if (labels.length < 2 || labels.some(label => !DNS_LABEL.test(label))) return null
  return suffix
}

function requireCanonicalDnsName (value, label) {
  const normalized = normalizeManifestHostSuffix(value)
  if (!normalized || normalized !== value) throw new Error(`${label} must be a canonical lowercase DNS name`)
  return normalized
}

function requireCanonicalIp (value, label) {
  if (typeof value !== 'string' || value !== value.trim() || isIP(value) === 0) throw new Error(`${label} must be an IP address`)
  let canonical = value.toLowerCase()
  if (isIP(value) === 6) canonical = new URL(`http://[${value}]/`).hostname.slice(1, -1)
  if (canonical !== value) throw new Error(`${label} must use canonical IP spelling`)
  return canonical
}

function compareIpAddresses (left, right) {
  const family = isIP(left) - isIP(right)
  return family || left.localeCompare(right)
}

function isLoopbackIp (value) {
  return value === '::1' || (isIP(value) === 4 && value.startsWith('127.'))
}

function requireCanonicalOriginPath (value, label) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 4096 ||
      !value.startsWith('/') || value.startsWith('//') || value.includes('\\') ||
      value.includes('?') || value.includes('#') || value.includes('%') || hasControlChars(value) ||
      /(?:^|\/)\.{1,2}(?:\/|$)/.test(value)) {
    throw new Error(`${label} must be a canonical origin-relative pathname`)
  }
  const base = 'https://public-hive-path.invalid'
  const parsed = new URL(value, base)
  if (parsed.origin !== base || parsed.pathname !== value || parsed.search || parsed.hash) {
    throw new Error(`${label} must be a canonical origin-relative pathname`)
  }
  return value
}

function canonicalJson (value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value)
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new Error('operator contract contains a non-finite number')
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`
  if (!value || typeof value !== 'object') throw new Error('operator contract contains an unsupported value')
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`
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

function hasControlChars (value) {
  for (const character of String(value)) {
    const code = character.charCodeAt(0)
    if (code <= 31 || code === 127) return true
  }
  return false
}
