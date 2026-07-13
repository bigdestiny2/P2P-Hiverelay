/**
 * Strict deployment inputs for the public HTTPS Hive gateway.
 *
 * Values selected here are placed on the CLI override object, so the complete
 * precedence remains:
 *
 *   gateway CLI flag > gateway environment variable > config.json > defaults
 *
 * Exact numeric strings are converted to numbers before RelayNode sees them.
 * This is important because the runtime intentionally rejects numeric strings
 * (to avoid Node's listen(path) overload) and parseInt-style partial values.
 */

import { isIP } from 'node:net'
import { normalizeHiveAppHostSuffix } from '../gateway/hive-host.js'
import {
  MAX_HIVE_APP_PUBLIC_KEYS,
  normalizeHiveAppPublicKeys,
  normalizeHiveAppPublicVersions
} from '../gateway/public-app-admission.js'

const MAX_GATEWAY_ALLOWLIST_ENTRIES = 64
const MAX_GATEWAY_IN_FLIGHT = 4096
const MAX_GATEWAY_RESPONSE_BYTES = 1024 * 1024 * 1024
const MAX_GATEWAY_EGRESS_BYTES = 1024 * 1024 * 1024 * 1024
const MAX_GATEWAY_WINDOW_MS = 60 * 60 * 1000
export const PUBLIC_T1_GATEWAY_FINITE_LIMITS = Object.freeze({
  gatewayMaxResponseBytes: 64 * 1024 * 1024,
  gatewayMaxTransformBytes: 4 * 1024 * 1024,
  gatewayEgressBytesPerWindow: 256 * 1024 * 1024,
  gatewayEgressWindowMs: 60 * 1000,
  gatewayMaxResponseLifetimeMs: 15 * 60 * 1000
})
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/
const hasOwn = (object, key) => Object.prototype.hasOwnProperty.call(object, key)

const INPUTS = [
  {
    key: 'gatewayHost',
    flag: 'gateway-host',
    env: 'HIVERELAY_GATEWAY_HOST',
    parse: parseBindHost
  },
  {
    key: 'gatewayPort',
    flag: 'gateway-port',
    env: 'HIVERELAY_GATEWAY_PORT',
    parse: (value, label) => parseExactInteger(value, label, 1, 65535)
  },
  {
    key: 'gatewayTrustProxy',
    flag: 'gateway-trust-proxy',
    env: 'HIVERELAY_GATEWAY_TRUST_PROXY',
    parse: parseBoolean
  },
  {
    key: 'gatewayTrustedProxyAddresses',
    flag: 'gateway-trusted-proxy-address',
    env: 'HIVERELAY_GATEWAY_TRUSTED_PROXY_ADDRESSES',
    parse: parseTrustedProxyAddresses
  },
  {
    key: 'gatewayRequireForwardedSNI',
    flag: 'gateway-require-forwarded-sni',
    env: 'HIVERELAY_GATEWAY_REQUIRE_FORWARDED_SNI',
    parse: parseBoolean
  },
  {
    key: 'gatewayCompatibilityHosts',
    flag: 'gateway-compatibility-host',
    env: 'HIVERELAY_GATEWAY_COMPATIBILITY_HOSTS',
    parse: parseCompatibilityHosts
  },
  {
    key: 'gatewayMaxInFlight',
    flag: 'gateway-max-in-flight',
    env: 'HIVERELAY_GATEWAY_MAX_IN_FLIGHT',
    parse: (value, label) => parseExactInteger(value, label, 1, MAX_GATEWAY_IN_FLIGHT)
  },
  {
    key: 'gatewayMaxInFlightPerApp',
    flag: 'gateway-max-in-flight-per-app',
    env: 'HIVERELAY_GATEWAY_MAX_IN_FLIGHT_PER_APP',
    parse: (value, label) => parseExactInteger(value, label, 1, MAX_GATEWAY_IN_FLIGHT)
  },
  {
    key: 'gatewayMaxResponseBytes',
    flag: 'gateway-max-response-bytes',
    env: 'HIVERELAY_GATEWAY_MAX_RESPONSE_BYTES',
    parse: (value, label) => parseExactInteger(value, label, 1, MAX_GATEWAY_RESPONSE_BYTES)
  },
  {
    key: 'gatewayMaxTransformBytes',
    flag: 'gateway-max-transform-bytes',
    env: 'HIVERELAY_GATEWAY_MAX_TRANSFORM_BYTES',
    parse: (value, label) => parseExactInteger(value, label, 1, MAX_GATEWAY_RESPONSE_BYTES)
  },
  {
    key: 'gatewayEgressBytesPerWindow',
    flag: 'gateway-egress-bytes-per-window',
    env: 'HIVERELAY_GATEWAY_EGRESS_BYTES_PER_WINDOW',
    parse: (value, label) => parseExactInteger(value, label, 1, MAX_GATEWAY_EGRESS_BYTES)
  },
  {
    key: 'gatewayEgressWindowMs',
    flag: 'gateway-egress-window-ms',
    env: 'HIVERELAY_GATEWAY_EGRESS_WINDOW_MS',
    parse: (value, label) => parseExactInteger(value, label, 1000, MAX_GATEWAY_WINDOW_MS)
  },
  {
    key: 'gatewayMaxResponseLifetimeMs',
    flag: 'gateway-max-response-lifetime-ms',
    env: 'HIVERELAY_GATEWAY_MAX_RESPONSE_LIFETIME_MS',
    parse: (value, label) => parseExactInteger(value, label, 1000, MAX_GATEWAY_WINDOW_MS)
  },
  {
    key: 'hiveAppHostSuffix',
    flag: 'hive-app-host-suffix',
    env: 'HIVERELAY_HIVE_APP_HOST_SUFFIX',
    parse: parseHiveAppHostSuffix
  },
  {
    key: 'hiveAppPublicKeys',
    flag: 'hive-app-public-key',
    env: 'HIVERELAY_HIVE_APP_PUBLIC_KEYS',
    parse: parseHiveAppPublicKeys
  },
  {
    key: 'hiveAppPublicVersions',
    flag: 'hive-app-public-version',
    env: 'HIVERELAY_HIVE_APP_PUBLIC_VERSIONS',
    parse: parseHiveAppPublicVersions
  }
]
const PUBLIC_GATEWAY_FLAGS = new Set(INPUTS.map(input => input.flag))

/**
 * Apply strict public-gateway flags and environment variables to the mutable
 * CLI override object. Existing overrides beat environment values; an explicit
 * gateway flag beats both.
 */
export function applyPublicHiveGatewayEnv (cliOverrides = {}, argv = {}, env = {}) {
  if (!cliOverrides || typeof cliOverrides !== 'object' || Array.isArray(cliOverrides)) {
    throw new TypeError('public Hive gateway CLI overrides must be an object')
  }
  if (!argv || typeof argv !== 'object' || Array.isArray(argv)) {
    throw new TypeError('public Hive gateway argv must be an object')
  }
  if (!env || typeof env !== 'object' || Array.isArray(env)) {
    throw new TypeError('public Hive gateway env must be an object')
  }
  for (const key of Object.keys(argv)) {
    if ((key.startsWith('gateway-') || key.startsWith('hive-app-')) && !PUBLIC_GATEWAY_FLAGS.has(key)) {
      throw new Error(`Unknown public Hive gateway option: --${key}`)
    }
  }

  for (const input of INPUTS) {
    if (hasOwn(argv, input.flag)) {
      cliOverrides[input.key] = input.parse(argv[input.flag], `--${input.flag}`)
      continue
    }
    if (!hasOwn(cliOverrides, input.key) && hasOwn(env, input.env)) {
      cliOverrides[input.key] = input.parse(env[input.env], input.env)
    }
  }

  const max = cliOverrides.gatewayMaxInFlight
  const perApp = cliOverrides.gatewayMaxInFlightPerApp
  if (Number.isSafeInteger(max) && Number.isSafeInteger(perApp)) {
    assertPublicHiveGatewayConcurrency(cliOverrides)
  }
  const maxResponseBytes = cliOverrides.gatewayMaxResponseBytes
  const maxTransformBytes = cliOverrides.gatewayMaxTransformBytes
  if (Number.isSafeInteger(maxResponseBytes) && Number.isSafeInteger(maxTransformBytes) && maxTransformBytes > maxResponseBytes) {
    throw new Error('Invalid public Hive gateway finite policy: gatewayMaxTransformBytes must not exceed gatewayMaxResponseBytes')
  }
  if (hasOwn(cliOverrides, 'hiveAppPublicKeys') && hasOwn(cliOverrides, 'hiveAppPublicVersions')) {
    assertPublicHiveGatewayVersionPins(cliOverrides)
  }

  return cliOverrides
}

/**
 * Validate the merged concurrency values after config.json and defaults have
 * been applied. Checking only the raw deployment inputs would miss a single
 * env override that conflicts with the persisted/default value on the other
 * side of the relation.
 */
export function assertPublicHiveGatewayConcurrency (config = {}) {
  const max = config.gatewayMaxInFlight
  const perApp = config.gatewayMaxInFlightPerApp
  if (!Number.isSafeInteger(max) || max < 1 || max > MAX_GATEWAY_IN_FLIGHT) {
    throw new Error(`Invalid gatewayMaxInFlight: expected an integer from 1 to ${MAX_GATEWAY_IN_FLIGHT}`)
  }
  if (!Number.isSafeInteger(perApp) || perApp < 1 || perApp > MAX_GATEWAY_IN_FLIGHT) {
    throw new Error(`Invalid gatewayMaxInFlightPerApp: expected an integer from 1 to ${MAX_GATEWAY_IN_FLIGHT}`)
  }
  if (perApp > max) {
    throw new Error('Invalid public Hive gateway concurrency: gatewayMaxInFlightPerApp must not exceed gatewayMaxInFlight')
  }
  return config
}

export function assertPublicHiveGatewayVersionPins (config = {}) {
  const keys = normalizeHiveAppPublicKeys(config.hiveAppPublicKeys ?? [])
  const versions = normalizeHiveAppPublicVersions(config.hiveAppPublicVersions ?? {})
  if (!keys) throw new Error('Invalid hiveAppPublicKeys: expected 64-character hexadecimal app keys')
  if (!versions) throw new Error('Invalid hiveAppPublicVersions: expected an object mapping app keys to non-negative safe integer versions')
  for (const key of versions.keys()) {
    if (!keys.has(key)) throw new Error('Invalid hiveAppPublicVersions: version pins must not name keys outside hiveAppPublicKeys')
  }
  return config
}

export function assertPublicHiveGatewayFiniteLimits (config = {}) {
  const fields = [
    ['gatewayMaxResponseBytes', 1, MAX_GATEWAY_RESPONSE_BYTES],
    ['gatewayMaxTransformBytes', 1, MAX_GATEWAY_RESPONSE_BYTES],
    ['gatewayEgressBytesPerWindow', 1, MAX_GATEWAY_EGRESS_BYTES],
    ['gatewayEgressWindowMs', 1000, MAX_GATEWAY_WINDOW_MS],
    ['gatewayMaxResponseLifetimeMs', 1000, MAX_GATEWAY_WINDOW_MS]
  ]
  for (const [field, minimum, maximum] of fields) {
    const value = config[field]
    if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
      throw new Error(`Invalid ${field}: expected an integer from ${minimum} to ${maximum}`)
    }
  }
  if (config.gatewayMaxTransformBytes > config.gatewayMaxResponseBytes) {
    throw new Error('Invalid public Hive gateway finite policy: gatewayMaxTransformBytes must not exceed gatewayMaxResponseBytes')
  }
  if (config.productProfile === 'public-t1-gateway') {
    for (const [field, expected] of Object.entries(PUBLIC_T1_GATEWAY_FINITE_LIMITS)) {
      if (config[field] !== expected) {
        throw new Error(`Invalid public-t1-gateway finite policy: ${field} must equal ${expected}`)
      }
    }
  }
  return config
}

function parseExactInteger (value, label, min, max) {
  let candidate = value
  if (typeof candidate === 'string') {
    if (!/^(?:0|[1-9][0-9]*)$/.test(candidate)) {
      throw new Error(`Invalid ${label}: expected an integer from ${min} to ${max}`)
    }
    candidate = Number(candidate)
  }
  if (!Number.isSafeInteger(candidate) || candidate < min || candidate > max) {
    throw new Error(`Invalid ${label}: expected an integer from ${min} to ${max}`)
  }
  return candidate
}

function parseBoolean (value, label) {
  if (typeof value === 'boolean') return value
  // minimist coerces --flag=1 / --flag=0 to numbers unless the option is
  // declared as a string; accept only those two exact numeric spellings.
  if (value === 1) return true
  if (value === 0) return false
  if (typeof value === 'string') {
    const candidate = value.trim().toLowerCase()
    if (candidate === 'true' || candidate === '1') return true
    if (candidate === 'false' || candidate === '0') return false
  }
  throw new Error(`Invalid ${label}: expected true, false, 1, or 0`)
}

function parseBindHost (value, label) {
  if (typeof value !== 'string' || value !== value.trim() || value.length === 0 || value.length > 253) {
    throw new Error(`Invalid ${label}: expected an IP address or DNS hostname without a port`)
  }
  const host = value.toLowerCase()
  if (isIP(host)) return host
  if (host.includes('..') || !host.split('.').every(candidate => DNS_LABEL.test(candidate))) {
    throw new Error(`Invalid ${label}: expected an IP address or DNS hostname without a port`)
  }
  return host
}

function parseTrustedProxyAddresses (value, label) {
  const candidates = parseCsvList(value, label, MAX_GATEWAY_ALLOWLIST_ENTRIES)
  const addresses = []
  const seen = new Set()
  for (const candidate of candidates) {
    let address = candidate.toLowerCase()
    if (address.startsWith('::ffff:') && isIP(address.slice(7)) === 4) {
      address = address.slice(7)
    }
    if (address.length > 64 || !isIP(address)) {
      throw new Error(`Invalid ${label}: entries must be IP addresses`)
    }
    if (!seen.has(address)) {
      seen.add(address)
      addresses.push(address)
    }
  }
  return addresses
}

function parseCompatibilityHosts (value, label) {
  const candidates = parseCsvList(value, label, MAX_GATEWAY_ALLOWLIST_ENTRIES)
  const hosts = []
  const seen = new Set()
  for (const candidate of candidates) {
    const host = normalizeCompatibilityHost(candidate)
    if (!host) {
      throw new Error(`Invalid ${label}: entries must be canonical IP addresses or DNS hostnames`)
    }
    if (!seen.has(host)) {
      seen.add(host)
      hosts.push(host)
    }
  }
  return hosts
}

function normalizeCompatibilityHost (value) {
  if (value.startsWith('[')) {
    const match = /^\[([0-9a-f:.]+)\](?::([0-9]{1,5}))?$/i.exec(value)
    if (!match || isIP(match[1]) !== 6 || !validOptionalPort(match[2])) return null
    return `[${match[1].toLowerCase()}]`
  }

  const match = /^([a-z0-9.-]+)(?::([0-9]{1,5}))?$/i.exec(value)
  if (!match || !validOptionalPort(match[2])) return null
  let host = match[1].toLowerCase()
  if (host.endsWith('.')) host = host.slice(0, -1)
  if (!host || host.includes('..')) return null
  if (!isIP(host) && !host.split('.').every(candidate => DNS_LABEL.test(candidate))) return null
  return host
}

function validOptionalPort (value) {
  if (value === undefined) return true
  return /^(?:[1-9][0-9]{0,4})$/.test(value) && Number(value) <= 65535
}

function parseHiveAppHostSuffix (value, label) {
  if (typeof value !== 'string' || value !== value.trim()) {
    throw new Error(`Invalid ${label}: expected a DNS suffix such as hive.example.com`)
  }
  const suffix = normalizeHiveAppHostSuffix(value)
  if (!suffix) throw new Error(`Invalid ${label}: expected a DNS suffix such as hive.example.com`)
  return suffix
}

function parseHiveAppPublicKeys (value, label) {
  const candidates = parseCsvList(value, label, MAX_HIVE_APP_PUBLIC_KEYS)
  const normalized = normalizeHiveAppPublicKeys(candidates)
  if (!normalized) {
    throw new Error(`Invalid ${label}: entries must be 64-character hexadecimal app keys`)
  }
  return [...normalized]
}

function parseHiveAppPublicVersions (value, label) {
  let candidate = null
  if (typeof value === 'string' && value.trim().startsWith('{')) {
    try {
      candidate = JSON.parse(value)
    } catch {
      throw new Error(`Invalid ${label}: expected JSON or key=version entries`)
    }
  } else {
    const entries = parseCsvList(value, label, MAX_HIVE_APP_PUBLIC_KEYS)
    candidate = {}
    for (const entry of entries) {
      const match = /^([0-9a-fA-F]{64})=(0|[1-9][0-9]*)$/.exec(entry)
      if (!match) throw new Error(`Invalid ${label}: expected key=version entries`)
      const version = Number(match[2])
      if (!Number.isSafeInteger(version)) throw new Error(`Invalid ${label}: versions must be safe integers`)
      const key = match[1].toLowerCase()
      if (Object.prototype.hasOwnProperty.call(candidate, key)) {
        throw new Error(`Invalid ${label}: duplicate app key`)
      }
      candidate[key] = version
    }
  }
  const normalized = normalizeHiveAppPublicVersions(candidate)
  if (!normalized) {
    throw new Error(`Invalid ${label}: expected app keys mapped to non-negative safe integer versions`)
  }
  return Object.fromEntries(normalized)
}

function parseCsvList (value, label, maxEntries) {
  const rawValues = Array.isArray(value) ? value : [value]
  if (rawValues.length === 0) throw new Error(`Invalid ${label}: expected at least one entry`)

  const entries = []
  for (const raw of rawValues) {
    if (typeof raw !== 'string') throw new Error(`Invalid ${label}: expected a comma-separated list`)
    const parts = raw.split(',')
    for (const part of parts) {
      const entry = part.trim()
      if (!entry) throw new Error(`Invalid ${label}: list entries must not be empty`)
      entries.push(entry)
      if (entries.length > maxEntries) {
        throw new Error(`Invalid ${label}: expected no more than ${maxEntries} entries`)
      }
    }
  }
  return entries
}
