import b4a from 'b4a'

export const HIVE_Z32_ALPHABET = 'ybndrfg8ejkmcpqxot1uwisza345h769'
const HIVE_Z32_KEY_LENGTH = 52
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/
const Z32_VALUES = new Map(Array.from(HIVE_Z32_ALPHABET, (char, value) => [char, value]))

export function encodeHiveAppKey (key) {
  const bytes = b4a.from(key)
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

export function decodeHiveAppKey (label) {
  if (typeof label !== 'string' || label.length !== HIVE_Z32_KEY_LENGTH) return null
  if (label !== label.toLowerCase()) return null

  const output = []
  let accumulator = 0
  let bits = 0

  for (const char of label) {
    const value = Z32_VALUES.get(char)
    if (value === undefined) return null

    accumulator = (accumulator << 5) | value
    bits += 5

    while (bits >= 8) {
      bits -= 8
      output.push((accumulator >>> bits) & 255)
      accumulator &= bits === 0 ? 0 : (1 << bits) - 1
    }
  }

  // A 32-byte key occupies 260 encoded bits. The final four bits are padding
  // and must be zero, otherwise multiple DNS labels could decode to one key.
  if (output.length !== 32 || bits !== 4 || accumulator !== 0) return null

  const bytes = b4a.from(output)
  if (encodeHiveAppKey(bytes) !== label) return null
  return bytes
}

export function normalizeHiveAppHostSuffix (value) {
  if (typeof value !== 'string') return null
  let suffix = value.trim().toLowerCase()
  if (suffix.endsWith('.')) suffix = suffix.slice(0, -1)
  // Leave room for the 52-character app-key label and separating dot.
  if (!suffix || suffix.length > 200 || suffix.includes('..')) return null

  const labels = suffix.split('.')
  if (labels.length < 2 || labels.some(label => !DNS_LABEL.test(label))) return null
  return suffix
}

/**
 * Resolve `<z32-app-key>.<suffix>` without consulting forwarded headers.
 *
 * Returns one of:
 *   { kind: 'none' }                       ordinary compatibility host
 *   { kind: 'invalid', reason }            malformed/intended app host
 *   { kind: 'app', appKey, label, host }   canonical app origin
 */
export function resolveHiveAppHost (hostHeader, configuredSuffix) {
  const suffix = normalizeHiveAppHostSuffix(configuredSuffix)
  if (!suffix) return { kind: 'none' }
  if (typeof hostHeader !== 'string' || !hostHeader) {
    return { kind: 'invalid', reason: 'missing Host header' }
  }

  if (hostHeader !== hostHeader.trim() || hostHeader.includes(',')) {
    return { kind: 'invalid', reason: 'invalid Host header' }
  }

  // Raw IPv6 gateway access is a compatibility host, never an app subdomain.
  if (hostHeader.startsWith('[')) {
    const ipv6 = /^\[[0-9a-f:.]+\](?::([0-9]{1,5}))?$/i.exec(hostHeader)
    if (!ipv6) {
      return { kind: 'invalid', reason: 'invalid Host header' }
    }
    if (ipv6[1]) {
      const port = Number(ipv6[1])
      if (!Number.isSafeInteger(port) || port < 1 || port > 65535) {
        return { kind: 'invalid', reason: 'invalid Host port' }
      }
    }
    return { kind: 'none' }
  }

  const match = /^([a-z0-9.-]+)(?::([0-9]{1,5}))?$/i.exec(hostHeader)
  if (!match) return { kind: 'invalid', reason: 'invalid Host header' }

  if (match[2]) {
    const port = Number(match[2])
    if (!Number.isSafeInteger(port) || port < 1 || port > 65535) {
      return { kind: 'invalid', reason: 'invalid Host port' }
    }
  }

  let hostname = match[1].toLowerCase()
  if (hostname.endsWith('.')) hostname = hostname.slice(0, -1)

  if (hostname === suffix) {
    return { kind: 'invalid', reason: 'missing Hive app key label' }
  }
  if (!hostname.endsWith('.' + suffix)) return { kind: 'none' }

  const label = hostname.slice(0, -(suffix.length + 1))
  if (!label || label.includes('.')) {
    return { kind: 'invalid', reason: 'invalid Hive app hostname' }
  }

  const key = decodeHiveAppKey(label)
  if (!key) return { kind: 'invalid', reason: 'invalid Hive app key label' }

  return {
    kind: 'app',
    appKey: b4a.toString(key, 'hex'),
    label,
    host: `${label}.${suffix}`
  }
}
