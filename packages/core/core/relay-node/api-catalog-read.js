import b4a from 'b4a'
import { CONTENT_TYPES, normalizeContentType } from '../constants.js'
import {
  validateAppCatalogExternalCursor,
  verifyAppCatalogExternalCursor
} from './app-catalog-paged.js'
import { buildFederationSnapshotPayload } from './api-federation-management.js'
import { validatePositiveInt } from './api-validation.js'

export const RELAY_CATALOG_PAGE_SIZE_MAX = 500
export const GATEWAY_CATALOG_PAGE_SIZE_MAX = 200
export const CATALOG_TYPE_ERROR = `type must be one of: ${Array.from(CONTENT_TYPES).join(', ')}`
export const CATALOG_CURSOR_EXPIRED = 'CURSOR_EXPIRED'
export const CATALOG_FILTER_UNAVAILABLE = 'CATALOG_FILTER_UNAVAILABLE'
export const CATALOG_LIMIT_AMBIGUOUS = 'CATALOG_LIMIT_AMBIGUOUS'
const CATALOG_ACCEPT_MODES = ['open', 'review', 'allowlist', 'closed']
const MAX_CATALOG_LABEL_BYTES = 128
const MAX_EXTERNAL_CURSOR_BYTES = 2_048

const CATALOG_READ_ROUTES = Object.freeze({
  'GET /catalog.json': Object.freeze({
    kind: 'catalog'
  }),
  'GET /api/apps': Object.freeze({
    kind: 'legacy-type',
    type: 'app'
  }),
  'GET /api/drives': Object.freeze({
    kind: 'legacy-type',
    type: 'drive'
  })
})

export function resolveCatalogReadRoute (method, path) {
  const route = CATALOG_READ_ROUTES[`${method} ${path}`]
  if (!route) return null
  return { ...route }
}

export function buildCatalogReadRoutePayload ({
  route,
  node,
  url,
  relayKey = relayPublicKeyHex(node),
  maxPageSize = RELAY_CATALOG_PAGE_SIZE_MAX
} = {}) {
  if (!route) {
    return {
      status: 404,
      payload: { error: 'unknown catalog read route' }
    }
  }

  if (route.kind === 'catalog') {
    return buildRelayCatalogPayload({ node, url, relayKey, maxPageSize })
  }

  if (route.kind === 'legacy-type') {
    return catalogEntriesByType({
      node,
      type: route.type,
      url,
      maxPageSize
    })
  }

  return {
    status: 404,
    payload: { error: 'unknown catalog read route' }
  }
}

export function buildRelayCatalogPayload ({
  node,
  url,
  relayKey = relayPublicKeyHex(node),
  maxPageSize = RELAY_CATALOG_PAGE_SIZE_MAX
} = {}) {
  const parsed = asUrl(url)
  const requestedType = parsed.searchParams.get('type')
  const type = requestedType ? normalizeContentType(requestedType, null) : null
  if (requestedType && !type) {
    return { ok: false, status: 400, payload: { error: CATALOG_TYPE_ERROR } }
  }

  const parent = parsed.searchParams.get('parent')
  const category = parsed.searchParams.get('category')
  if (category !== null) return unavailableCategoryFilter()
  const read = readExternalCatalogPage({ node, url: parsed, maxPageSize })
  if (!read.ok) return read
  const entries = filterCatalogPageEntries(read.entries, { type, parent })
  const counts = countCatalogEntries(entries)
  const buckets = bucketCatalogEntries(entries)

  return {
    ok: true,
    payload: {
      version: 3,
      name: 'HiveRelay Content Catalog',
      relayKey: safeCatalogHexKey(relayKey),
      catalogBeeKey: safeCatalogHexKey(node?.catalogBeeKey),
      indexRoom: safeCatalogIndexRoom(node?.indexRoom),
      region: safeCatalogLabel(node?.config?.regions?.[0]),
      operator: safeCatalogLabel(node?.config?.operator),
      filters: {
        type,
        parent: parent || null,
        category: null
      },
      pagination: {
        limit: read.limit,
        nextCursor: read.cursor,
        complete: read.complete
      },
      snapshot: read.snapshot,
      entryCount: read.snapshot.entryCount,
      pageCount: counts,
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
  const requestedType = parsed.searchParams.get('type')
  const type = requestedType ? normalizeContentType(requestedType, null) : null
  if (requestedType && !type) {
    return { ok: false, status: 400, payload: { error: CATALOG_TYPE_ERROR } }
  }
  if (parsed.searchParams.has('category')) return unavailableCategoryFilter()
  const read = readExternalCatalogPage({ node, url: parsed, maxPageSize, status: true })
  if (!read.ok) return read
  const entries = filterCatalogPageEntries(read.entries, {
    type,
    parent: parsed.searchParams.get('parent')
  })
  const payload = {
    items: entries,
    limit: read.limit,
    cursor: read.cursor,
    complete: read.complete,
    snapshot: read.snapshot,
    entryCount: read.snapshot.entryCount
  }
  const catalogBeeKey = node?.config?.catalogBeeKey
  if (typeof catalogBeeKey === 'string' && /^[0-9a-f]{64}$/i.test(catalogBeeKey)) {
    payload.catalogBeeKey = catalogBeeKey
  }
  return { ok: true, payload }
}

export function catalogEntriesByType ({ node, type, url, maxPageSize = RELAY_CATALOG_PAGE_SIZE_MAX } = {}) {
  const normalizedType = normalizeContentType(type, null)
  if (!normalizedType) return { ok: false, status: 400, payload: { error: CATALOG_TYPE_ERROR } }
  const read = readExternalCatalogPage({ node, url, maxPageSize, defaultLimit: maxPageSize })
  if (!read.ok) return read
  return {
    ok: true,
    status: 200,
    payload: {
      entries: filterCatalogPageEntries(read.entries, { type: normalizedType }),
      limit: read.limit,
      cursor: read.cursor,
      complete: read.complete,
      snapshot: read.snapshot,
      entryCount: read.snapshot.entryCount
    }
  }
}

export function readExternalCatalogPage ({
  node,
  url,
  maxPageSize = RELAY_CATALOG_PAGE_SIZE_MAX,
  defaultLimit = 50,
  status = false
} = {}) {
  const parsed = asUrl(url)
  const hardMaxPageSize = status
    ? GATEWAY_CATALOG_PAGE_SIZE_MAX
    : RELAY_CATALOG_PAGE_SIZE_MAX
  const requestedMaxPageSize = Number.isSafeInteger(maxPageSize) && maxPageSize > 0
    ? maxPageSize
    : hardMaxPageSize
  const effectiveMaxPageSize = Math.min(requestedMaxPageSize, hardMaxPageSize)
  const requestedDefaultLimit = Number.isSafeInteger(defaultLimit) && defaultLimit > 0
    ? defaultLimit
    : Math.min(50, effectiveMaxPageSize)
  const effectiveDefaultLimit = Math.min(requestedDefaultLimit, effectiveMaxPageSize)
  const request = parseExternalCatalogRequest(parsed, {
    maxPageSize: effectiveMaxPageSize,
    defaultLimit: effectiveDefaultLimit
  })
  if (!request.ok) return request
  const store = node?.appCatalogStore
  const keyPair = node?.swarm?.keyPair || node?.keyPair || null
  const signerPubkey = cursorSignerPubkey(keyPair)
  if (!store || typeof store.readExternalPage !== 'function' || !keyPair || signerPubkey === null) {
    return { ok: false, status: 503, payload: { error: 'CATALOG_UNAVAILABLE' } }
  }
  if (request.cursor !== null) {
    try {
      request.cursor = verifyAppCatalogExternalCursor(request.cursor, signerPubkey)
    } catch {
      return { ok: false, status: 400, payload: { error: 'INVALID_CATALOG_CURSOR' } }
    }
  }
  try {
    const page = store.readExternalPage({
      cursor: request.cursor,
      limit: request.limit,
      status,
      keyPair
    })
    if (!page || !page.snapshot || !Array.isArray(page.entries)) {
      return { ok: false, status: 503, payload: { error: 'CATALOG_UNAVAILABLE' } }
    }
    return {
      ok: true,
      limit: request.limit,
      entries: page.entries.map(catalogApiEntry),
      snapshot: catalogApiSnapshot(page.snapshot),
      complete: page.complete === true,
      cursor: page.cursor || null
    }
  } catch (err) {
    if (request.cursor !== null && (err?.code === 'CURSOR_EXPIRED' || err?.code === 'HISTORY_EXPIRED')) {
      return { ok: false, status: 409, payload: { error: CATALOG_CURSOR_EXPIRED } }
    }
    return { ok: false, status: 503, payload: { error: 'CATALOG_UNAVAILABLE' } }
  }
}

function asUrl (url) {
  if (url instanceof URL) return url
  return new URL(url || '/', 'http://0.0.0.0')
}

function parseExternalCatalogRequest (url, { maxPageSize, defaultLimit }) {
  const rawPage = url.searchParams.get('page')
  if (rawPage !== null && rawPage !== '' && rawPage !== '1') {
    return { ok: false, status: 400, payload: { error: 'CATALOG_CURSOR_REQUIRED' } }
  }
  if (url.searchParams.has('limit') && url.searchParams.has('pageSize')) {
    return { ok: false, status: 400, payload: { error: CATALOG_LIMIT_AMBIGUOUS } }
  }
  const limitName = url.searchParams.has('limit') ? 'limit' : 'pageSize'
  const rawLimit = url.searchParams.get(limitName)
  let limit = defaultLimit
  if (rawLimit !== null && rawLimit !== '') {
    const parsed = validatePositiveInt(rawLimit, 1, maxPageSize, limitName)
    if (!parsed.ok) return { ok: false, status: 400, payload: { error: parsed.error } }
    limit = parsed.value
  }
  const rawCursor = url.searchParams.get('cursor')
  if (rawCursor === null || rawCursor === '') return { ok: true, limit, cursor: null }
  if (b4a.byteLength(rawCursor, 'utf8') > MAX_EXTERNAL_CURSOR_BYTES) {
    return { ok: false, status: 400, payload: { error: 'INVALID_CATALOG_CURSOR' } }
  }
  try {
    const cursor = JSON.parse(rawCursor)
    if (!cursor || typeof cursor !== 'object' || Array.isArray(cursor)) throw new Error('invalid cursor')
    return { ok: true, limit, cursor: validateAppCatalogExternalCursor(cursor) }
  } catch {
    return { ok: false, status: 400, payload: { error: 'INVALID_CATALOG_CURSOR' } }
  }
}

function catalogApiSnapshot (snapshot) {
  return {
    snapshotId: snapshot.snapshotId,
    highWater: snapshot.highWater,
    rootDigest: snapshot.rootDigest,
    entryCount: snapshot.entryCount,
    senderPubkey: snapshot.senderPubkey
  }
}

function catalogApiEntry (row) {
  if (!Array.isArray(row) || row.length !== 22) throw new Error('invalid canonical catalog row')
  const redacted = row[13] === true
  return {
    rowKey: row[0],
    appKey: row[1],
    appId: row[2],
    type: row[3],
    parentKey: row[4],
    mountPath: row[5],
    version: row[6],
    discoveryKey: row[7],
    blind: row[8],
    storageClass: row[9],
    availabilityClass: row[10],
    privacyTier: row[11],
    seededAt: row[12],
    redacted,
    metadataVisibility: row[14],
    blindContentId: row[15],
    anchored: row[16],
    maxStorageBytes: row[17],
    publisherPubkey: row[18],
    durability: row[19],
    revocable: row[20],
    retainUntil: row[21]
  }
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
  if (b4a.byteLength(value, 'utf8') <= maxBytes) return value
  let out = ''
  let used = 0
  for (const ch of value) {
    const size = b4a.byteLength(ch, 'utf8')
    if (used + size > maxBytes) break
    out += ch
    used += size
  }
  return out
}

function filterCatalogPageEntries (entries, { type = null, parent = null } = {}) {
  return entries.filter(entry => entry && typeof entry === 'object' &&
    (!type || entry.type === type) &&
    (!parent || entry.parentKey === parent))
}

function countCatalogEntries (entries) {
  const counts = {
    total: 0,
    apps: 0,
    drives: 0,
    resources: 0,
    datasets: 0,
    media: 0
  }

  for (const entry of entries) countEntry(counts, entry)
  return counts
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

function unavailableCategoryFilter () {
  return {
    ok: false,
    status: 400,
    payload: {
      error: CATALOG_FILTER_UNAVAILABLE,
      filter: 'category'
    }
  }
}

function relayPublicKeyHex (node) {
  const key = node?.swarm?.keyPair?.publicKey
  if (!key || typeof key.length !== 'number') return null
  return b4a.toString(key, 'hex')
}

function cursorSignerPubkey (keyPair) {
  const key = keyPair?.publicKey
  if (!key || key.byteLength !== 32) return null
  return b4a.toString(key, 'hex')
}
