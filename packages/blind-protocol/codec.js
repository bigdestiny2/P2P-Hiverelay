import b4a from 'b4a'
import { protocolError } from './errors.js'

const MAX_U64 = (1n << 64n) - 1n

function fail (message) {
  protocolError('BAD_ENCODING', message)
}

function asBuffer (value, field) {
  if (!value || typeof value.byteLength !== 'number') fail(`${field} must be bytes`)
  if (b4a.isBuffer(value)) return value
  if (ArrayBuffer.isView(value)) return b4a.from(value.buffer, value.byteOffset, value.byteLength)
  return b4a.from(value)
}

function assertAvailable (state, length, field) {
  if (!Number.isSafeInteger(length) || length < 0 || state.end - state.start < length) {
    fail(`truncated ${field}`)
  }
}

function assertUnsignedNumber (value, maximum, field) {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) {
    fail(`${field} is outside its unsigned range`)
  }
  return value
}

function asU64 (value, field) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) fail(`${field} must be an unsigned safe integer or bigint`)
    value = BigInt(value)
  }
  if (typeof value !== 'bigint' || value < 0n || value > MAX_U64) fail(`${field} is outside u64`)
  return value
}

function readU16LE (buffer, offset) {
  return buffer[offset] | (buffer[offset + 1] << 8)
}

function readU32LE (buffer, offset) {
  return (buffer[offset] +
    buffer[offset + 1] * 0x100 +
    buffer[offset + 2] * 0x10000 +
    buffer[offset + 3] * 0x1000000)
}

function writeU16LE (buffer, value, offset) {
  buffer[offset] = value
  buffer[offset + 1] = value >>> 8
}

function writeU32LE (buffer, value, offset) {
  buffer[offset] = value
  buffer[offset + 1] = value >>> 8
  buffer[offset + 2] = value >>> 16
  buffer[offset + 3] = value >>> 24
}

function readU64 (buffer, offset, littleEndian) {
  let value = 0n
  if (littleEndian) {
    for (let i = 7; i >= 0; i--) value = (value << 8n) | BigInt(buffer[offset + i])
  } else {
    for (let i = 0; i < 8; i++) value = (value << 8n) | BigInt(buffer[offset + i])
  }
  return value
}

function writeU64 (buffer, value, offset, littleEndian) {
  if (littleEndian) {
    for (let i = 0; i < 8; i++) {
      buffer[offset + i] = Number(value & 0xffn)
      value >>= 8n
    }
  } else {
    for (let i = 7; i >= 0; i--) {
      buffer[offset + i] = Number(value & 0xffn)
      value >>= 8n
    }
  }
}

function fixedUnsigned (bytes, maximum, name) {
  return {
    preencode (state, value) {
      assertUnsignedNumber(value, maximum, name)
      state.end += bytes
    },
    encode (state, value) {
      value = assertUnsignedNumber(value, maximum, name)
      assertAvailable(state, bytes, name)
      for (let i = bytes - 1; i >= 0; i--) {
        state.buffer[state.start + i] = value & 0xff
        value = Math.floor(value / 0x100)
      }
      state.start += bytes
    },
    decode (state) {
      assertAvailable(state, bytes, name)
      let value = 0
      for (let i = 0; i < bytes; i++) value = value * 0x100 + state.buffer[state.start++]
      return value
    }
  }
}

export const u8 = fixedUnsigned(1, 0xff, 'u8')
export const u16be = fixedUnsigned(2, 0xffff, 'u16')
export const u32be = fixedUnsigned(4, 0xffffffff, 'u32')

export const u64be = {
  preencode (state, value) {
    asU64(value, 'u64')
    state.end += 8
  },
  encode (state, value) {
    value = asU64(value, 'u64')
    assertAvailable(state, 8, 'u64')
    writeU64(state.buffer, value, state.start, false)
    state.start += 8
  },
  decode (state) {
    assertAvailable(state, 8, 'u64')
    const value = readU64(state.buffer, state.start, false)
    state.start += 8
    return value
  }
}

// This is compact-encoding's canonical unsigned length/count prefix. The marker
// byte is followed by little-endian payload bytes, and overlong forms are invalid.
export const compactUint = {
  preencode (state, value) {
    value = assertUnsignedNumber(value, Number.MAX_SAFE_INTEGER, 'compact uint')
    state.end += value <= 0xfc ? 1 : value <= 0xffff ? 3 : value <= 0xffffffff ? 5 : 9
  },
  encode (state, value) {
    value = assertUnsignedNumber(value, Number.MAX_SAFE_INTEGER, 'compact uint')
    const bytes = value <= 0xfc ? 1 : value <= 0xffff ? 3 : value <= 0xffffffff ? 5 : 9
    assertAvailable(state, bytes, 'compact uint')
    if (bytes === 1) {
      state.buffer[state.start++] = value
      return
    }
    if (bytes === 3) {
      state.buffer[state.start++] = 0xfd
      writeU16LE(state.buffer, value, state.start)
      state.start += 2
      return
    }
    if (bytes === 5) {
      state.buffer[state.start++] = 0xfe
      writeU32LE(state.buffer, value, state.start)
      state.start += 4
      return
    }
    state.buffer[state.start++] = 0xff
    writeU64(state.buffer, BigInt(value), state.start, true)
    state.start += 8
  },
  decode (state) {
    assertAvailable(state, 1, 'compact uint')
    const marker = state.buffer[state.start++]
    if (marker <= 0xfc) return marker
    if (marker === 0xfd) {
      assertAvailable(state, 2, 'compact uint')
      const value = readU16LE(state.buffer, state.start)
      state.start += 2
      if (value <= 0xfc) fail('non-canonical compact uint')
      return value
    }
    if (marker === 0xfe) {
      assertAvailable(state, 4, 'compact uint')
      const value = readU32LE(state.buffer, state.start)
      state.start += 4
      if (value <= 0xffff) fail('non-canonical compact uint')
      return value
    }
    assertAvailable(state, 8, 'compact uint')
    const value = readU64(state.buffer, state.start, true)
    state.start += 8
    if (value <= 0xffffffffn || value > BigInt(Number.MAX_SAFE_INTEGER)) {
      fail('non-canonical or unsupported compact uint')
    }
    return Number(value)
  }
}

export function fixedBytes (length, name = `bytes[${length}]`) {
  if (!Number.isSafeInteger(length) || length < 0) throw new TypeError('fixed byte length must be non-negative')
  return {
    preencode (state, value) {
      value = asBuffer(value, name)
      if (value.byteLength !== length) fail(`${name} must be exactly ${length} bytes`)
      state.end += length
    },
    encode (state, value) {
      value = asBuffer(value, name)
      if (value.byteLength !== length) fail(`${name} must be exactly ${length} bytes`)
      assertAvailable(state, length, name)
      b4a.copy(value, state.buffer, state.start)
      state.start += length
    },
    decode (state) {
      assertAvailable(state, length, name)
      const value = state.buffer.subarray(state.start, state.start + length)
      state.start += length
      return state.copyBytes === true ? b4a.from(value) : value
    }
  }
}

export function constantBytes (expected, name = 'constant bytes') {
  expected = asBuffer(expected, name)
  const encoding = fixedBytes(expected.byteLength, name)
  return {
    preencode (state, value) {
      if (value == null) value = expected
      value = asBuffer(value, name)
      if (!b4a.equals(value, expected)) fail(`${name} does not match its fixed value`)
      encoding.preencode(state, expected)
    },
    encode (state, value) {
      if (value == null) value = expected
      value = asBuffer(value, name)
      if (!b4a.equals(value, expected)) fail(`${name} does not match its fixed value`)
      encoding.encode(state, expected)
    },
    decode (state) {
      const value = encoding.decode(state)
      if (!b4a.equals(value, expected)) fail(`${name} does not match its fixed value`)
      return value
    }
  }
}

export function exactBytesByClass (classField, classLengths, name = 'class-selected bytes') {
  function selectedLength (parent) {
    const length = parent && classLengths[parent[classField]]
    if (!Number.isSafeInteger(length) || length < 0) fail(`${name} has an unknown ${classField}`)
    return length
  }
  return {
    preencode (state, value, parent) {
      value = asBuffer(value, name)
      const length = selectedLength(parent)
      if (value.byteLength !== length) fail(`${name} must be exactly ${length} bytes`)
      state.end += length
    },
    encode (state, value, parent) {
      value = asBuffer(value, name)
      const length = selectedLength(parent)
      if (value.byteLength !== length) fail(`${name} must be exactly ${length} bytes`)
      assertAvailable(state, length, name)
      b4a.copy(value, state.buffer, state.start)
      state.start += length
    },
    decode (state, parent) {
      const length = selectedLength(parent)
      assertAvailable(state, length, name)
      const value = state.buffer.subarray(state.start, state.start + length)
      state.start += length
      return state.copyBytes === true ? b4a.from(value) : value
    }
  }
}

export function boundedBytes (minimum, maximum, name = 'bounded bytes') {
  if (!Number.isSafeInteger(minimum) || !Number.isSafeInteger(maximum) || minimum < 0 || maximum < minimum) {
    throw new TypeError('invalid bounded byte range')
  }
  return {
    preencode (state, value) {
      value = asBuffer(value, name)
      if (value.byteLength < minimum || value.byteLength > maximum) fail(`${name} length is outside ${minimum}..${maximum}`)
      compactUint.preencode(state, value.byteLength)
      state.end += value.byteLength
    },
    encode (state, value) {
      value = asBuffer(value, name)
      if (value.byteLength < minimum || value.byteLength > maximum) fail(`${name} length is outside ${minimum}..${maximum}`)
      compactUint.encode(state, value.byteLength)
      assertAvailable(state, value.byteLength, name)
      b4a.copy(value, state.buffer, state.start)
      state.start += value.byteLength
    },
    decode (state) {
      const length = compactUint.decode(state)
      if (length < minimum || length > maximum) fail(`${name} length is outside ${minimum}..${maximum}`)
      assertAvailable(state, length, name)
      const value = state.buffer.subarray(state.start, state.start + length)
      state.start += length
      return state.copyBytes === true ? b4a.from(value) : value
    }
  }
}

function canonicalTextValue (value, minimum, maximum, name, asciiOnly) {
  value = asBuffer(value, name)
  if (value.byteLength < minimum || value.byteLength > maximum) {
    fail(`${name} length is outside ${minimum}..${maximum}`)
  }
  for (let i = 0; i < value.byteLength; i++) {
    if (value[i] === 0) fail(`${name} contains an embedded NUL`)
    if (asciiOnly && (value[i] < 0x20 || value[i] > 0x7e)) fail(`${name} must be printable ASCII`)
  }
  const decoded = b4a.toString(value, 'utf8')
  if (!b4a.equals(b4a.from(decoded, 'utf8'), value)) fail(`${name} is not strict UTF-8`)
  if (decoded !== decoded.normalize('NFC')) fail(`${name} must already be NFC`)
  return { bytes: value, text: decoded }
}

function canonicalTextBytes (minimum, maximum, name, asciiOnly) {
  const encoding = boundedBytes(minimum, maximum, name)
  return {
    preencode (state, value) {
      encoding.preencode(state, canonicalTextValue(value, minimum, maximum, name, asciiOnly).bytes)
    },
    encode (state, value) {
      encoding.encode(state, canonicalTextValue(value, minimum, maximum, name, asciiOnly).bytes)
    },
    decode (state) {
      const value = encoding.decode(state)
      canonicalTextValue(value, minimum, maximum, name, asciiOnly)
      return value
    }
  }
}

export function canonicalUtf8Bytes (minimum, maximum, name = 'canonical UTF-8') {
  return canonicalTextBytes(minimum, maximum, name, false)
}

export function canonicalAsciiBytes (minimum, maximum, name = 'canonical ASCII') {
  return canonicalTextBytes(minimum, maximum, name, true)
}

export function validateCanonicalUrl (value, options = {}) {
  const name = options.name || 'canonical URL'
  const { text } = canonicalTextValue(value, 1, 512, name, false)
  const match = /^(https?):\/\/([^/?#]+)(\/[^?#]*)$/.exec(text)
  if (!match) fail(`${name} must contain a canonical scheme, authority, and path`)
  const scheme = match[1]
  const authority = match[2]
  const path = match[3]
  if (authority.includes('@')) fail(`${name} must not contain userinfo`)

  let host
  let portText
  if (authority.startsWith('[')) {
    const end = authority.indexOf(']')
    if (end < 0 || authority[end + 1] !== ':') fail(`${name} requires an explicit port`)
    host = authority.slice(0, end + 1)
    portText = authority.slice(end + 2)
  } else {
    const colon = authority.lastIndexOf(':')
    if (colon <= 0 || authority.indexOf(':') !== colon) fail(`${name} requires an explicit port`)
    host = authority.slice(0, colon)
    portText = authority.slice(colon + 1)
  }
  if (host !== host.toLowerCase()) fail(`${name} host must be lowercase`)
  if (!/^[1-9][0-9]{0,4}$/.test(portText)) fail(`${name} port must use shortest decimal form`)
  const port = Number(portText)
  if (port > 65535) fail(`${name} port is outside 1..65535`)
  if (/%(?![0-9A-F]{2})/.test(path)) fail(`${name} has a non-canonical percent escape`)

  let parsed
  try {
    parsed = new URL(text)
  } catch {
    fail(`${name} is not a valid URL`)
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash ||
      parsed.hostname !== host || parsed.pathname !== path) {
    fail(`${name} contains non-canonical components`)
  }

  const onion = /^[a-z2-7]{56}\.onion$/.test(host)
  if (options.requireOnion === true) {
    if (!onion || (scheme !== 'http' && scheme !== 'https')) fail(`${name} must be a v3 onion URL`)
  } else if (scheme !== 'https' || onion || host.endsWith('.onion')) {
    fail(`${name} must use HTTPS to a non-onion host`)
  }
  return value
}

export function canonicalHttpsUrlBytes (name = 'canonical HTTPS URL') {
  const encoding = canonicalUtf8Bytes(1, 512, name)
  return {
    preencode (state, value) {
      validateCanonicalUrl(value, { name })
      encoding.preencode(state, value)
    },
    encode (state, value) {
      validateCanonicalUrl(value, { name })
      encoding.encode(state, value)
    },
    decode (state) {
      const value = encoding.decode(state)
      validateCanonicalUrl(value, { name })
      return value
    }
  }
}

export function optional (encoding, name = 'optional value') {
  return {
    preencode (state, value) {
      u8.preencode(state, value == null ? 0 : 1)
      if (value != null) encoding.preencode(state, value)
    },
    encode (state, value) {
      u8.encode(state, value == null ? 0 : 1)
      if (value != null) encoding.encode(state, value)
    },
    decode (state) {
      const tag = u8.decode(state)
      if (tag === 0) return null
      if (tag !== 1) fail(`${name} presence tag must be 0 or 1`)
      return encoding.decode(state)
    }
  }
}

export function arrayOf (encoding, minimum, maximum, name = 'array') {
  if (!Number.isSafeInteger(minimum) || !Number.isSafeInteger(maximum) || minimum < 0 || maximum < minimum) {
    throw new TypeError('invalid array bounds')
  }
  return {
    preencode (state, values) {
      if (!Array.isArray(values) || values.length < minimum || values.length > maximum) {
        fail(`${name} count is outside ${minimum}..${maximum}`)
      }
      compactUint.preencode(state, values.length)
      for (const value of values) encoding.preencode(state, value)
    },
    encode (state, values) {
      if (!Array.isArray(values) || values.length < minimum || values.length > maximum) {
        fail(`${name} count is outside ${minimum}..${maximum}`)
      }
      compactUint.encode(state, values.length)
      for (const value of values) encoding.encode(state, value)
    },
    decode (state) {
      const count = compactUint.decode(state)
      if (count < minimum || count > maximum) fail(`${name} count is outside ${minimum}..${maximum}`)
      const values = new Array(count)
      for (let i = 0; i < count; i++) values[i] = encoding.decode(state)
      return values
    }
  }
}

export function struct (fields, options = {}) {
  if (!Array.isArray(fields) || fields.length === 0) throw new TypeError('struct requires fields')
  return {
    preencode (state, value) {
      if (!value || typeof value !== 'object') fail(`${options.name || 'struct'} must be an object`)
      for (const [name, encoding] of fields) encoding.preencode(state, value[name], value)
      if (options.validate) options.validate(value)
    },
    encode (state, value) {
      if (!value || typeof value !== 'object') fail(`${options.name || 'struct'} must be an object`)
      for (const [name, encoding] of fields) encoding.encode(state, value[name], value)
    },
    decode (state) {
      const value = {}
      for (const [name, encoding] of fields) value[name] = encoding.decode(state, value)
      if (options.validate) options.validate(value)
      return value
    }
  }
}

export function constant (encoding, expected, name) {
  return {
    preencode (state, value) {
      if (value == null) value = expected
      if (value !== expected) fail(`${name} must be ${expected}`)
      encoding.preencode(state, expected)
    },
    encode (state, value) {
      if (value == null) value = expected
      if (value !== expected) fail(`${name} must be ${expected}`)
      encoding.encode(state, expected)
    },
    decode (state) {
      const value = encoding.decode(state)
      if (value !== expected) fail(`${name} must be ${expected}`)
      return value
    }
  }
}

export function ranged (encoding, minimum, maximum, name) {
  return {
    preencode (state, value) {
      if (typeof value !== 'number' || value < minimum || value > maximum) fail(`${name} is outside ${minimum}..${maximum}`)
      encoding.preencode(state, value)
    },
    encode (state, value) {
      if (typeof value !== 'number' || value < minimum || value > maximum) fail(`${name} is outside ${minimum}..${maximum}`)
      encoding.encode(state, value)
    },
    decode (state) {
      const value = encoding.decode(state)
      if (value < minimum || value > maximum) fail(`${name} is outside ${minimum}..${maximum}`)
      return value
    }
  }
}

export function encodeCanonical (encoding, value) {
  const state = { start: 0, end: 0, buffer: null, copyBytes: false }
  encoding.preencode(state, value)
  state.buffer = b4a.alloc(state.end)
  state.start = 0
  encoding.encode(state, value)
  if (state.start !== state.end) fail('encoder did not fill its canonical allocation')
  return state.buffer
}

export function decodeCanonical (encoding, input, options = {}) {
  input = asBuffer(input, 'canonical input')
  const state = { start: 0, end: input.byteLength, buffer: input, copyBytes: options.copyBytes === true }
  const value = encoding.decode(state)
  if (state.start !== state.end) fail('trailing bytes after canonical value')
  return value
}
