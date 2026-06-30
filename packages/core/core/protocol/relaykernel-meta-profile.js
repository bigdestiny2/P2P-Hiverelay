import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  buildRelayKernelSeedLeaseCaps
} from './relaykernel-seed-lease-profile.js'
import {
  roleDomainSignable
} from './role-domain-signature.js'

export const RELAYKERNEL_META_PROFILE_KIND = 'relaykernel-meta-profile'
export const RELAYKERNEL_META_PROFILE_VERSION = 1
export const RELAYKERNEL_META_DIRECTORY_TOPIC = 'rk-directory-v1'
export const RELAYKERNEL_META_DIRECTORY_MIN_INTERVAL_SECONDS = 600

export const RELAYKERNEL_META_PROTOCOL_VERSION = Object.freeze({
  major: 1,
  minor: 0,
  patch: 0
})

export const RELAYKERNEL_META_KERNEL_CHANNELS = Object.freeze([
  'rk-seed',
  'rk-proof',
  'rk-circuit',
  'rk-meta',
  'rk-accounting'
])

export const RELAYKERNEL_META_RESERVED_APP_CAPABILITY_PREFIXES = Object.freeze([
  'rk',
  'rk1',
  'rk2',
  'rk3',
  'rkp',
  'rkv',
  'rkc',
  't1',
  't2',
  't3',
  'hiverelay',
  'relaykernel'
])

export const RELAYKERNEL_META_RESERVED_APP_CAPABILITIES = Object.freeze([
  ...RELAYKERNEL_META_KERNEL_CHANNELS,
  'seed-request-v1',
  'relay-circuit-v1',
  'hiverelay-proof',
  'hiverelay-forward',
  'hiverelay-publish',
  'hiverelay-custody',
  'hiverelay-accounting',
  'circuit-relay',
  'proof-of-retrievability',
  'capability-meta',
  'os-accounting'
])

const HEX_32 = /^[0-9a-f]{64}$/i

export function buildRelayKernelMetaProfile (opts = {}) {
  const capabilityDoc = opts.capabilityDoc || {}
  const relayPubkey = lowerHex(opts.relayPubkey, HEX_32) || lowerHex(capabilityDoc.pubkey, HEX_32)
  const protocolVersion = normalizeProtocolVersion(opts.protocolVersion)
  const kernelChannels = orderedUnique(
    Array.isArray(opts.kernelChannels) ? opts.kernelChannels : RELAYKERNEL_META_KERNEL_CHANNELS
  )
  const appCapabilities = normalizeAppCapabilities(opts.appCapabilities)
  const advertisedCapabilities = orderedUnique([
    ...kernelChannels,
    ...appCapabilities.map(capability => capability.name)
  ])
  const capLimits = buildRelayKernelSeedLeaseCaps(opts.capLimits)
  const directoryOptIn = opts.directoryOptIn === true
  const directoryRecordProvided = !!(opts.directoryRecord && typeof opts.directoryRecord === 'object')

  return {
    kind: RELAYKERNEL_META_PROFILE_KIND,
    version: RELAYKERNEL_META_PROFILE_VERSION,
    protocolVersion,
    relayPubkey,
    source: {
      capabilityDocSigned: !!capabilityDoc.signature,
      capabilitySchemaVersion: Number.isSafeInteger(capabilityDoc.schemaVersion)
        ? capabilityDoc.schemaVersion
        : null
    },
    meta: {
      kernelChannels,
      appCapabilities,
      advertisedCapabilities,
      reservedAppCapabilityPrefixes: [...RELAYKERNEL_META_RESERVED_APP_CAPABILITY_PREFIXES],
      reservedAppCapabilities: [...RELAYKERNEL_META_RESERVED_APP_CAPABILITIES],
      layer2CapabilitiesSeparated: appCapabilities.every(capability => capabilityIsLayer2Separated(capability, kernelChannels)),
      capLimits
    },
    directory: buildDirectoryProfile({
      opts,
      capabilityDoc,
      relayPubkey,
      directoryOptIn,
      directoryRecordProvided,
      advertisedCapabilities,
      capLimits
    })
  }
}

export function validateRelayKernelMetaProfile (profile) {
  const errors = []
  const warnings = []

  if (!profile || typeof profile !== 'object') {
    return { valid: false, errors: ['profile object required'], warnings }
  }
  if (profile.kind !== RELAYKERNEL_META_PROFILE_KIND) errors.push('kind mismatch')
  if (profile.version !== RELAYKERNEL_META_PROFILE_VERSION) errors.push('version mismatch')
  if (!profile.protocolVersion || profile.protocolVersion.major !== RELAYKERNEL_META_PROTOCOL_VERSION.major) {
    errors.push('protocol major mismatch')
  }
  if (!lowerHex(profile.relayPubkey, HEX_32)) errors.push('relayPubkey must be 32 bytes hex')

  const meta = profile.meta || {}
  const kernelChannels = arrayOfStrings(meta.kernelChannels)
  for (const channel of RELAYKERNEL_META_KERNEL_CHANNELS) {
    if (!kernelChannels.includes(channel)) errors.push('missing kernel channel: ' + channel)
  }
  for (const channel of kernelChannels) {
    if (!RELAYKERNEL_META_KERNEL_CHANNELS.includes(channel)) {
      errors.push('non-kernel capability in kernelChannels: ' + channel)
    }
  }

  const advertised = arrayOfStrings(meta.advertisedCapabilities)
  for (const channel of kernelChannels) {
    if (!advertised.includes(channel)) errors.push('kernel channel not advertised: ' + channel)
  }
  const appCapabilities = Array.isArray(meta.appCapabilities) ? meta.appCapabilities : []
  for (const capability of appCapabilities) {
    if (!capability || typeof capability !== 'object') {
      errors.push('app capability object required')
      continue
    }
    if (!validCapabilityName(capability.name)) errors.push('invalid app capability name')
    if (!validCapabilityName(capability.channel)) errors.push('invalid app capability channel')
    if (!Number.isSafeInteger(capability.version) || capability.version < 1) {
      errors.push('invalid app capability version')
    }
    if (RELAYKERNEL_META_KERNEL_CHANNELS.includes(capability.name)) {
      errors.push('app capability shadows kernel channel: ' + capability.name)
    }
    if (kernelChannels.includes(capability.channel)) {
      errors.push('app capability channel collides with kernel channel: ' + capability.channel)
    }
    const reservedName = reservedAppCapabilityReason(capability.name, kernelChannels)
    if (reservedName) {
      errors.push('app capability name uses reserved kernel namespace: ' + capability.name)
    }
    const reservedChannel = reservedAppCapabilityReason(capability.channel, kernelChannels)
    if (reservedChannel) {
      errors.push('app capability channel uses reserved kernel namespace: ' + capability.channel)
    }
    if (!advertised.includes(capability.name)) {
      errors.push('app capability not advertised: ' + capability.name)
    }
  }
  if (meta.layer2CapabilitiesSeparated !== true) {
    errors.push('layer-2 capabilities are not separated from kernel channels')
  }

  const directory = profile.directory || {}
  if (directory.optIn !== true) {
    if (directory.publicEnumerable === true) errors.push('directory is enumerable without opt-in')
    if (directory.topic !== null) errors.push('directory topic must be null unless opt-in is true')
    if (directory.record !== null) errors.push('directory record must be null unless opt-in is true')
    if (directory.providedRecordIgnored === true) errors.push('directory record supplied while opt-in is false')
  } else {
    if (directory.topic !== RELAYKERNEL_META_DIRECTORY_TOPIC) errors.push('directory topic mismatch')
    if (directory.publicEnumerable !== true) errors.push('opt-in directory must be publicEnumerable')
    if (!Number.isSafeInteger(directory.rateLimitSeconds) ||
      directory.rateLimitSeconds < RELAYKERNEL_META_DIRECTORY_MIN_INTERVAL_SECONDS) {
      errors.push('directory rate limit below minimum')
    }
    validateDirectoryRecord(directory.record, advertised, errors)
  }

  if (profile.source && profile.source.capabilityDocSigned !== true) {
    warnings.push('capability document is not signed')
  }

  return { valid: errors.length === 0, errors, warnings }
}

function buildDirectoryProfile ({
  opts,
  capabilityDoc,
  relayPubkey,
  directoryOptIn,
  directoryRecordProvided,
  advertisedCapabilities,
  capLimits
}) {
  const rateLimitSeconds = cappedFloorInteger(
    opts.directoryRateLimitSeconds,
    RELAYKERNEL_META_DIRECTORY_MIN_INTERVAL_SECONDS
  )
  if (!directoryOptIn) {
    return {
      optIn: false,
      topic: null,
      publicEnumerable: false,
      rateLimitSeconds,
      record: null,
      providedRecordIgnored: directoryRecordProvided
    }
  }

  const source = opts.directoryRecord || {}
  const record = {
    relayPubkey,
    endpoint: stringOr(source.endpoint) || stringOr(opts.endpoint) || endpointFromCapabilityDoc(capabilityDoc),
    capabilities: orderedUnique(arrayOfStrings(source.capabilities).length > 0
      ? source.capabilities
      : advertisedCapabilities),
    capLimits,
    feeSchedule: normalizeFeeSchedule(source.feeSchedule || opts.feeSchedule),
    region: stringOr(source.region) || stringOr(opts.region) || stringOr(capabilityDoc.region),
    uptime: safeNonNegativeInteger(source.uptime, opts.uptime, 0)
  }
  const payloadHash = directoryRecordPayloadHash(record)

  return {
    optIn: true,
    topic: RELAYKERNEL_META_DIRECTORY_TOPIC,
    publicEnumerable: true,
    rateLimitSeconds,
    record: {
      ...record,
      payloadHash,
      domain: {
        protocol: 'relaykernel',
        rolePrefix: 'rk1',
        channel: 'rk-meta',
        messageType: 'directory-record',
        messageVersion: 1,
        signableHex: b4a.toString(roleDomainSignable({
          protocol: 'relaykernel',
          rolePrefix: 'rk1',
          channel: 'rk-meta',
          messageType: 'directory-record',
          messageVersion: 1,
          payloadHash
        }), 'hex')
      }
    },
    providedRecordIgnored: false
  }
}

function validateDirectoryRecord (record, advertised, errors) {
  if (!record || typeof record !== 'object') {
    errors.push('directory record required when opt-in is true')
    return
  }
  if (!lowerHex(record.relayPubkey, HEX_32)) errors.push('directory relayPubkey must be 32 bytes hex')
  if (typeof record.endpoint !== 'string' || record.endpoint.length === 0) {
    errors.push('directory endpoint required')
  }
  const capabilities = arrayOfStrings(record.capabilities)
  for (const channel of RELAYKERNEL_META_KERNEL_CHANNELS) {
    if (!capabilities.includes(channel)) errors.push('directory missing kernel capability: ' + channel)
  }
  for (const capability of capabilities) {
    if (!advertised.includes(capability)) errors.push('directory capability not advertised: ' + capability)
  }
  if (!record.domain || record.domain.protocol !== 'relaykernel' ||
    record.domain.rolePrefix !== 'rk1' ||
    record.domain.channel !== 'rk-meta' ||
    record.domain.messageType !== 'directory-record') {
    errors.push('directory record is not role-domain separated')
  }
  if (!lowerHex(record.payloadHash, HEX_32)) errors.push('directory payloadHash must be 32 bytes hex')
}

function normalizeProtocolVersion (value) {
  const version = value && typeof value === 'object' ? value : {}
  return {
    major: safeNonNegativeInteger(version.major, RELAYKERNEL_META_PROTOCOL_VERSION.major),
    minor: safeNonNegativeInteger(version.minor, RELAYKERNEL_META_PROTOCOL_VERSION.minor),
    patch: safeNonNegativeInteger(version.patch, RELAYKERNEL_META_PROTOCOL_VERSION.patch)
  }
}

function normalizeAppCapabilities (capabilities) {
  return (Array.isArray(capabilities) ? capabilities : [])
    .filter(capability => capability && typeof capability === 'object')
    .map(capability => ({
      name: lowerToken(capability.name),
      channel: lowerToken(capability.channel || capability.name),
      version: safeNonNegativeInteger(capability.version, 1),
      owner: stringOr(capability.owner) || null,
      discovery: stringOr(capability.discovery) || 'per-app'
    }))
    .sort((a, b) => a.name.localeCompare(b.name))
}

function capabilityIsLayer2Separated (capability, kernelChannels) {
  return !RELAYKERNEL_META_KERNEL_CHANNELS.includes(capability.name) &&
    !kernelChannels.includes(capability.channel) &&
    !reservedAppCapabilityReason(capability.name, kernelChannels) &&
    !reservedAppCapabilityReason(capability.channel, kernelChannels)
}

function reservedAppCapabilityReason (value, kernelChannels) {
  if (typeof value !== 'string' || value.length === 0) return null
  const token = value.toLowerCase()
  const kernels = Array.isArray(kernelChannels) ? kernelChannels : RELAYKERNEL_META_KERNEL_CHANNELS
  if (kernels.includes(token)) return 'kernel-channel'
  if (RELAYKERNEL_META_RESERVED_APP_CAPABILITIES.includes(token)) return 'kernel-capability'
  for (const prefix of RELAYKERNEL_META_RESERVED_APP_CAPABILITY_PREFIXES) {
    if (token === prefix) return 'reserved-prefix'
    if (token.startsWith(prefix + '-') || token.startsWith(prefix + '.') || token.startsWith(prefix + '_')) {
      return 'reserved-prefix'
    }
  }
  return null
}

function normalizeFeeSchedule (value) {
  const schedule = value && typeof value === 'object' ? value : {}
  return {
    perGiBPerDay: safeNonNegativeInteger(schedule.perGiBPerDay, 0)
  }
}

function endpointFromCapabilityDoc (doc) {
  const url = stringOr(doc.gatewayUrl)
  if (!url) return null
  try {
    const parsed = new URL(url)
    return parsed.host
  } catch (_) {
    return url
  }
}

function directoryRecordPayloadHash (record) {
  const out = b4a.alloc(32)
  sodium.crypto_generichash(out, b4a.from(stableStringify(record)))
  return b4a.toString(out, 'hex')
}

function cappedFloorInteger (value, floor) {
  return Number.isSafeInteger(value) && value > floor ? value : floor
}

function safeNonNegativeInteger (...values) {
  for (const value of values) {
    if (Number.isSafeInteger(value) && value >= 0) return value
  }
  return 0
}

function stringOr (value) {
  return typeof value === 'string' && value.length > 0 ? value : null
}

function lowerToken (value) {
  return typeof value === 'string' && value.length > 0 ? value.toLowerCase() : null
}

function validCapabilityName (value) {
  return typeof value === 'string' && /^[a-z0-9][a-z0-9._-]*$/.test(value)
}

function orderedUnique (values) {
  const out = []
  const seen = new Set()
  for (const value of arrayOfStrings(values)) {
    if (seen.has(value)) continue
    seen.add(value)
    out.push(value)
  }
  return out
}

function arrayOfStrings (value) {
  return Array.isArray(value)
    ? value.filter(v => typeof v === 'string' && v.length > 0).map(v => v.toLowerCase())
    : []
}

function lowerHex (value, pattern) {
  if (typeof value !== 'string' || !pattern.test(value)) return null
  return value.toLowerCase()
}

function stableStringify (value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return '[' + value.map(stableStringify).join(',') + ']'
  const keys = Object.keys(value).sort()
  return '{' + keys.map(key => JSON.stringify(key) + ':' + stableStringify(value[key])).join(',') + '}'
}
