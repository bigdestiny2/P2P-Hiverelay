import { CONTENT_TYPES, normalizeContentType } from '../constants.js'
import { buildFederationSnapshotPayload } from './api-federation-management.js'
import { queryInt } from './api-validation.js'

export const RELAY_CATALOG_PAGE_SIZE_MAX = 500
export const GATEWAY_CATALOG_PAGE_SIZE_MAX = 200
export const CATALOG_TYPE_ERROR = `type must be one of: ${Array.from(CONTENT_TYPES).join(', ')}`
const CATALOG_ACCEPT_MODES = ['open', 'review', 'allowlist', 'closed']
const MAX_CATALOG_LABEL_BYTES = 128

export function buildRelayCatalogPayload ({
  node,
  url,
  relayKey = relayPublicKeyHex(node),
  maxPageSize = RELAY_CATALOG_PAGE_SIZE_MAX
} = {}) {
  const parsed = asUrl(url)
  const page = queryInt(parsed, 'page', 1, 1, 1_000_000)
  const pageSize = queryInt(parsed, 'pageSize', 50, 1, maxPageSize)
  const requestedType = parsed.searchParams.get('type')
  const type = requestedType ? normalizeContentType(requestedType, null) : null
  if (requestedType && !type) {
    return { ok: false, status: 400, payload: { error: CATALOG_TYPE_ERROR } }
  }

  const parent = parsed.searchParams.get('parent')
  const category = parsed.searchParams.get('category')
  const { entries, counts } = pageCatalogEntries(catalogEntries(node), {
    type,
    parent,
    category,
    page,
    pageSize
  })
  const buckets = bucketCatalogEntries(entries)

  return {
    ok: true,
    payload: {
      version: 2,
      name: 'HiveRelay Content Catalog',
      relayKey: safeCatalogHexKey(relayKey),
      catalogBeeKey: safeCatalogHexKey(node?.catalogBeeKey),
      indexRoom: safeCatalogIndexRoom(node?.indexRoom),
      region: safeCatalogLabel(node?.config?.regions?.[0]),
      operator: safeCatalogLabel(node?.config?.operator),
      filters: {
        type,
        parent: parent || null,
        category: category || null
      },
      pagination: {
        page,
        pageSize,
        total: counts.total,
        totalPages: Math.ceil(counts.total / pageSize),
        hasNext: (page - 1) * pageSize + pageSize < counts.total,
        hasPrev: page > 1
      },
      count: counts,
      apps: buckets.apps,
      drives: buckets.drives,
      resources: buckets.resources,
      datasets: buckets.datasets,
      media: buckets.media,
      entries,
      federation: federationCatalogSnapshot(node),
      acceptMode: safeCatalogAcceptMode(node?._resolveAcceptMode ? node._resolveAcceptMode() : null)
    }
  }
}

export function buildGatewayCatalogPayload ({
  node,
  url,
  maxPageSize = GATEWAY_CATALOG_PAGE_SIZE_MAX
} = {}) {
  const parsed = asUrl(url)
  const page = queryInt(parsed, 'page', 1, 1, 1_000_000)
  const pageSize = queryInt(parsed, 'pageSize', 50, 1, maxPageSize)
  const requestedType = parsed.searchParams.get('type')
  const type = requestedType ? normalizeContentType(requestedType, null) : null
  if (requestedType && !type) {
    return { ok: false, status: 400, payload: { error: CATALOG_TYPE_ERROR } }
  }

  const { entries, counts } = pageCatalogEntries(catalogEntries(node), {
    type,
    page,
    pageSize
  })
  const payload = {
    items: entries,
    page,
    pageSize,
    total: counts.total,
    hasMore: (page - 1) * pageSize + pageSize < counts.total
  }
  const catalogBeeKey = node?.config?.catalogBeeKey
  if (typeof catalogBeeKey === 'string' && /^[0-9a-f]{64}$/i.test(catalogBeeKey)) {
    payload.catalogBeeKey = catalogBeeKey
  }
  return { ok: true, payload }
}

export function catalogEntriesByType ({ node, type, url, maxPageSize = RELAY_CATALOG_PAGE_SIZE_MAX } = {}) {
  const parsed = asUrl(url)
  const normalizedType = normalizeContentType(type, null)
  if (!normalizedType) return []
  const page = queryInt(parsed, 'page', 1, 1, 1_000_000)
  const pageSize = queryInt(parsed, 'pageSize', maxPageSize, 1, maxPageSize)
  return pageCatalogEntries(catalogEntries(node), {
    type: normalizedType,
    page,
    pageSize
  }).entries
}

function asUrl (url) {
  if (url instanceof URL) return url
  return new URL(url || '/', 'http://0.0.0.0')
}

function catalogEntries (node) {
  const registry = node?.appRegistry
  if (!registry || typeof registry.catalog !== 'function') return []
  const entries = registry.catalog({
    redactPrivate: node?.config?.custody?.redactedCatalog !== false
  })
  return Array.isArray(entries) ? entries : []
}

function federationCatalogSnapshot (node) {
  if (relayKernelProfileActive(node)) return null
  if (!node?.federation) return null
  const result = buildFederationSnapshotPayload({ federation: node.federation })
  return result.ok ? result.payload : null
}

function relayKernelProfileActive (node) {
  return !!node && (
    node.mode === 'relaykernel' ||
    (node.config && node.config.productProfile === 'relaykernel')
  )
}

function safeCatalogHexKey (value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/i.test(value) ? value.toLowerCase() : null
}

function safeCatalogIndexRoom (value) {
  return typeof value === 'string' && /^[ybndrfg8ejkmcpqxot1uwisza345h769]{52}$/.test(value) ? value : null
}

function safeCatalogAcceptMode (value) {
  return CATALOG_ACCEPT_MODES.includes(value) ? value : null
}

function safeCatalogLabel (value) {
  if (typeof value !== 'string') return null
  const text = value.trim()
  if (!text || hasControlChar(text)) return null
  return truncateUtf8(text, MAX_CATALOG_LABEL_BYTES)
}

function hasControlChar (value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if (code <= 0x1f || code === 0x7f) return true
  }
  return false
}

function truncateUtf8 (value, maxBytes) {
  if (Buffer.byteLength(value, 'utf8') <= maxBytes) return value
  let out = ''
  let used = 0
  for (const ch of value) {
    const size = Buffer.byteLength(ch, 'utf8')
    if (used + size > maxBytes) break
    out += ch
    used += size
  }
  return out
}

function pageCatalogEntries (entries, {
  type = null,
  parent = null,
  category = null,
  page = 1,
  pageSize = 50
} = {}) {
  const start = (page - 1) * pageSize
  const pageEntries = []
  const counts = {
    total: 0,
    apps: 0,
    drives: 0,
    resources: 0,
    datasets: 0,
    media: 0
  }

  for (const entry of entries) {
    if (!entry || typeof entry !== 'object') continue
    if (type && entry.type !== type) continue
    if (parent && entry.parentKey !== parent) continue
    if (category && !entryHasCategory(entry, category)) continue

    const index = counts.total
    countEntry(counts, entry)
    if (index >= start && pageEntries.length < pageSize) pageEntries.push(entry)
  }

  return { entries: pageEntries, counts }
}

function bucketCatalogEntries (entries) {
  const buckets = {
    apps: [],
    drives: [],
    resources: [],
    datasets: [],
    media: []
  }
  for (const entry of entries) {
    if (entry.type === 'app') buckets.apps.push(entry)
    else if (entry.type === 'drive' && entry.parentKey) buckets.resources.push(entry)
    else if (entry.type === 'drive') buckets.drives.push(entry)
    else if (entry.type === 'dataset') buckets.datasets.push(entry)
    else if (entry.type === 'media') buckets.media.push(entry)
  }
  return buckets
}

function countEntry (counts, entry) {
  counts.total++
  if (entry.type === 'app') counts.apps++
  else if (entry.type === 'drive' && entry.parentKey) counts.resources++
  else if (entry.type === 'drive') counts.drives++
  else if (entry.type === 'dataset') counts.datasets++
  else if (entry.type === 'media') counts.media++
}

function entryHasCategory (entry, category) {
  const categories = Array.isArray(entry.categories) ? entry.categories : []
  const wanted = String(category).toLowerCase()
  return categories.some(value => String(value).toLowerCase() === wanted)
}

function relayPublicKeyHex (node) {
  const key = node?.swarm?.keyPair?.publicKey
  if (!key || typeof key.length !== 'number') return null
  return Buffer.from(key).toString('hex')
}
