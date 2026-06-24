import b4a from 'b4a'

export const MAX_SERVICE_CATALOG_ENTRIES = 128
export const MAX_SERVICE_CAPABILITIES = 64
export const MAX_SERVICE_NAME_BYTES = 64
export const MAX_SERVICE_VERSION_BYTES = 64
export const MAX_SERVICE_CAPABILITY_BYTES = 128
export const MAX_SERVICE_DESCRIPTION_BYTES = 512

function utf8Bytes (value) {
  return b4a.byteLength(value)
}

function truncateUtf8 (value, maxBytes) {
  if (utf8Bytes(value) <= maxBytes) return value
  let out = ''
  let used = 0
  for (const ch of value) {
    const size = utf8Bytes(ch)
    if (used + size > maxBytes) break
    out += ch
    used += size
  }
  return out
}

function hasControlChar (value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if (code <= 0x1f || code === 0x7f) return true
  }
  return false
}

function boundedString (value, maxBytes, opts = {}) {
  if (typeof value !== 'string') return null
  const trimmed = opts.trim === false ? value : value.trim()
  if (!trimmed) return null
  if (hasControlChar(trimmed)) return null
  if (utf8Bytes(trimmed) > maxBytes) {
    if (opts.truncate === true) return truncateUtf8(trimmed, maxBytes)
    return null
  }
  return trimmed
}

export function sanitizeServiceCatalogEntry (entry) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return null

  const name = boundedString(entry.name, MAX_SERVICE_NAME_BYTES)
  const version = boundedString(entry.version, MAX_SERVICE_VERSION_BYTES)
  if (!name || !version) return null

  const capabilities = []
  const seen = new Set()
  if (Array.isArray(entry.capabilities)) {
    for (const capability of entry.capabilities) {
      if (capabilities.length >= MAX_SERVICE_CAPABILITIES) break
      const value = boundedString(capability, MAX_SERVICE_CAPABILITY_BYTES)
      if (!value || seen.has(value)) continue
      seen.add(value)
      capabilities.push(value)
    }
  }

  const description = boundedString(entry.description, MAX_SERVICE_DESCRIPTION_BYTES, {
    truncate: true,
    trim: false
  }) || ''

  return { name, version, capabilities, description }
}

export function sanitizeServiceCatalogEntries (services, opts = {}) {
  const maxEntries = Number.isInteger(opts.maxEntries) && opts.maxEntries > 0
    ? Math.min(opts.maxEntries, MAX_SERVICE_CATALOG_ENTRIES)
    : MAX_SERVICE_CATALOG_ENTRIES

  const out = []
  const list = Array.isArray(services) ? services : []
  for (const entry of list) {
    if (out.length >= maxEntries) break
    const clean = sanitizeServiceCatalogEntry(entry)
    if (clean) out.push(clean)
  }
  return out
}

export function serviceCatalogTotal (services) {
  return Array.isArray(services) ? services.length : 0
}
