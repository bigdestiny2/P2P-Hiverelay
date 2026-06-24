import { isValidHexKey } from '../constants.js'

export const MAX_FEDERATION_CHANNEL_LENGTH = 80
export const MAX_FEDERATION_NOTE_LENGTH = 500
export const MAX_FEDERATION_SNAPSHOT_RELAYS = 128
export const MAX_FEDERATION_SNAPSHOT_REPUBLISHED = 256
export const MAX_FEDERATION_SNAPSHOT_PEER_APPS = 128
export const MAX_FEDERATION_SNAPSHOT_LABEL_BYTES = 128
export const MAX_FEDERATION_SNAPSHOT_URL_BYTES = 2048

function errorPayload (message) {
  return { error: message }
}

function errorMessage (err) {
  return err && err.message ? err.message : String(err || 'unknown error')
}

function emitRollbackError (emit, error) {
  if (typeof emit !== 'function') return
  emit('federation-rollback-error', {
    message: errorMessage(error),
    error
  })
}

function validateFederationActionBody (action, body = {}) {
  if (action === 'follow' || action === 'mirror' || action === 'unfollow') {
    if (typeof body.url !== 'string' || !body.url.trim()) {
      return { ok: false, status: 400, payload: errorPayload('url required') }
    }
    const normalized = { ...body, url: body.url.trim() }
    if ((action === 'follow' || action === 'mirror') && body.pubkey !== undefined && body.pubkey !== null) {
      if (typeof body.pubkey !== 'string' || !isValidHexKey(body.pubkey, 64)) {
        return { ok: false, status: 400, payload: errorPayload('pubkey must be 64 hex characters') }
      }
      normalized.pubkey = body.pubkey.toLowerCase()
    }
    return { ok: true, body: normalized }
  }

  if (action === 'republish' || action === 'unrepublish') {
    if (!body.appKey) return { ok: false, status: 400, payload: errorPayload('appKey required') }
    if (!isValidHexKey(body.appKey, 64)) {
      return { ok: false, status: 400, payload: errorPayload('appKey must be 64 hex characters') }
    }
    const normalized = { ...body, appKey: body.appKey.toLowerCase() }
    if (action === 'republish') {
      if (body.sourceUrl !== undefined && body.sourceUrl !== null) {
        if (typeof body.sourceUrl !== 'string') {
          return { ok: false, status: 400, payload: errorPayload('sourceUrl must be a string') }
        }
        normalized.sourceUrl = body.sourceUrl.trim() || null
      }
      if (body.sourcePubkey !== undefined && body.sourcePubkey !== null) {
        if (typeof body.sourcePubkey !== 'string' || !isValidHexKey(body.sourcePubkey, 64)) {
          return { ok: false, status: 400, payload: errorPayload('sourcePubkey must be 64 hex characters') }
        }
        normalized.sourcePubkey = body.sourcePubkey.toLowerCase()
      }
      if (body.channel !== undefined && body.channel !== null) {
        if (typeof body.channel !== 'string') return { ok: false, status: 400, payload: errorPayload('channel must be a string') }
        normalized.channel = body.channel.trim() || null
        if (normalized.channel && normalized.channel.length > MAX_FEDERATION_CHANNEL_LENGTH) {
          return { ok: false, status: 400, payload: errorPayload(`channel exceeds max length (${MAX_FEDERATION_CHANNEL_LENGTH})`) }
        }
      }
      if (body.note !== undefined && body.note !== null) {
        if (typeof body.note !== 'string') return { ok: false, status: 400, payload: errorPayload('note must be a string') }
        normalized.note = body.note.trim() || null
        if (normalized.note && normalized.note.length > MAX_FEDERATION_NOTE_LENGTH) {
          return { ok: false, status: 400, payload: errorPayload(`note exceeds max length (${MAX_FEDERATION_NOTE_LENGTH})`) }
        }
      }
    }
    return { ok: true, body: normalized }
  }

  return { ok: false, status: 400, payload: errorPayload('Unknown federation action') }
}

function buildFederationMutation (action, body) {
  if (action === 'follow') {
    return (federation) => {
      federation.follow(body.url, { pubkey: body.pubkey || null, persist: false })
      return { ok: true, mode: 'follow', url: body.url }
    }
  }

  if (action === 'mirror') {
    return (federation) => {
      federation.mirror(body.url, { pubkey: body.pubkey || null, persist: false })
      return { ok: true, mode: 'mirror', url: body.url }
    }
  }

  if (action === 'unfollow') {
    return (federation) => {
      const removed = federation.unfollow(body.url, { persist: false })
      return { ok: true, removed, url: body.url }
    }
  }

  if (action === 'republish') {
    return (federation) => {
      federation.republish(body.appKey, {
        sourceUrl: body.sourceUrl || null,
        sourcePubkey: body.sourcePubkey || null,
        channel: body.channel || null,
        note: body.note || null,
        persist: false
      })
      return { ok: true, appKey: body.appKey }
    }
  }

  if (action === 'unrepublish') {
    return (federation) => {
      const removed = federation.unrepublish(body.appKey, { persist: false })
      return { ok: true, removed, appKey: body.appKey }
    }
  }
}

export async function runFederationManagementAction ({
  action,
  body = {},
  federation,
  emit = null
}) {
  body = body || {}

  const valid = validateFederationActionBody(action, body)
  if (!valid.ok) {
    return { ok: false, kind: 'bad-request', status: valid.status, payload: valid.payload }
  }
  body = valid.body

  if (!federation) {
    return {
      ok: false,
      kind: 'not-ready',
      status: 503,
      payload: errorPayload('Federation not initialized')
    }
  }

  const snapshot = typeof federation.snapshot === 'function' ? federation.snapshot() : null
  const mutate = buildFederationMutation(action, body)

  try {
    const payload = mutate(federation)
    if (typeof federation.save === 'function') {
      await federation.save({ throwOnError: true })
    }
    return { ok: true, payload }
  } catch (err) {
    if (snapshot && typeof federation.restoreSnapshot === 'function') {
      try {
        federation.restoreSnapshot(snapshot)
      } catch (rollbackErr) {
        emitRollbackError(emit, rollbackErr)
      }
    }

    const message = errorMessage(err)
    if (message.startsWith('Federation:')) {
      return { ok: false, kind: 'bad-request', status: 400, payload: errorPayload(message) }
    }

    return { ok: false, kind: 'federation-persist', error: err }
  }
}

export function buildFederationSnapshotPayload ({
  federation
}) {
  if (!federation || typeof federation.snapshot !== 'function') {
    return {
      ok: false,
      status: 503,
      payload: errorPayload('Federation not initialized')
    }
  }

  const snapshot = federation.snapshot() || {}
  const followed = sanitizeList(snapshot.followed, MAX_FEDERATION_SNAPSHOT_RELAYS, sanitizeRelayEntry)
  const mirrored = sanitizeList(snapshot.mirrored, MAX_FEDERATION_SNAPSHOT_RELAYS, sanitizeRelayEntry)
  const republished = sanitizeList(snapshot.republished, MAX_FEDERATION_SNAPSHOT_REPUBLISHED, sanitizeRepublishedEntry)
  const peerCatalogs = sanitizeList(snapshot.peerCatalogs, MAX_FEDERATION_SNAPSHOT_RELAYS, sanitizePeerCatalogEntry)

  return {
    ok: true,
    payload: {
      followed: followed.items,
      mirrored: mirrored.items,
      republished: republished.items,
      followIntervalMs: safeTimestamp(snapshot.followIntervalMs),
      running: snapshot.running === true,
      peerCatalogs: peerCatalogs.items,
      followedTotal: followed.total,
      mirroredTotal: mirrored.total,
      republishedTotal: republished.total,
      peerCatalogsTotal: peerCatalogs.total,
      followedTruncated: followed.truncated,
      mirroredTruncated: mirrored.truncated,
      republishedTruncated: republished.truncated,
      peerCatalogsTruncated: peerCatalogs.truncated
    }
  }
}

function sanitizeList (source, limit, sanitize) {
  const list = Array.isArray(source) ? source : []
  const items = []
  for (const entry of list) {
    if (items.length >= limit) break
    const clean = sanitize(entry)
    if (clean) items.push(clean)
  }
  return {
    items,
    total: list.length,
    truncated: list.length > items.length
  }
}

function sanitizeRelayEntry (entry) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return null
  const url = safeFederationUrl(entry.url)
  if (!url) return null
  return {
    url,
    pubkey: safeHexKey(entry.pubkey, 64),
    addedAt: safeTimestamp(entry.addedAt)
  }
}

function sanitizeRepublishedEntry (entry) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return null
  const appKey = safeHexKey(entry.appKey, 64)
  if (!appKey) return null
  return {
    appKey,
    sourceUrl: entry.sourceUrl ? safeFederationUrl(entry.sourceUrl) : null,
    sourcePubkey: safeHexKey(entry.sourcePubkey, 64),
    channel: safeSnapshotString(entry.channel, MAX_FEDERATION_CHANNEL_LENGTH),
    note: safeSnapshotString(entry.note, MAX_FEDERATION_NOTE_LENGTH),
    addedAt: safeTimestamp(entry.addedAt)
  }
}

function sanitizePeerCatalogEntry (entry) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return null
  const url = safeFederationUrl(entry.url)
  if (!url) return null
  const apps = sanitizeList(entry.apps, MAX_FEDERATION_SNAPSHOT_PEER_APPS, sanitizePeerCatalogApp)
  return {
    url,
    pubkey: safeHexKey(entry.pubkey, 64),
    region: safeSnapshotString(entry.region, MAX_FEDERATION_SNAPSHOT_LABEL_BYTES),
    operator: safeSnapshotString(entry.operator, MAX_FEDERATION_SNAPSHOT_LABEL_BYTES),
    fetchedAt: safeTimestamp(entry.fetchedAt),
    apps: apps.items,
    appsTotal: apps.total,
    appsTruncated: apps.truncated
  }
}

function sanitizePeerCatalogApp (entry) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return null
  const appKey = safeHexKey(entry.appKey || entry.driveKey || entry.key, 64)
  if (!appKey) return null
  return {
    appKey,
    publisherPubkey: safeHexKey(entry.publisherPubkey || entry.author, 64),
    type: safeSnapshotString(entry.type, MAX_FEDERATION_SNAPSHOT_LABEL_BYTES) || 'app',
    privacyTier: safeSnapshotString(entry.privacyTier, MAX_FEDERATION_SNAPSHOT_LABEL_BYTES) || 'public',
    storageClass: safeSnapshotString(entry.storageClass, MAX_FEDERATION_SNAPSHOT_LABEL_BYTES),
    availabilityClass: safeSnapshotString(entry.availabilityClass, MAX_FEDERATION_SNAPSHOT_LABEL_BYTES),
    blind: entry.blind === true
  }
}

function safeFederationUrl (value) {
  const text = safeSnapshotString(value, MAX_FEDERATION_SNAPSHOT_URL_BYTES)
  if (!text) return null
  let parsed
  try {
    parsed = new URL(text)
  } catch {
    return null
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null
  if (parsed.username || parsed.password) return null
  return text
}

function safeHexKey (value, length) {
  return typeof value === 'string' && isValidHexKey(value, length) ? value.toLowerCase() : null
}

function safeTimestamp (value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : null
}

function safeSnapshotString (value, maxBytes) {
  if (typeof value !== 'string') return null
  const text = value.trim()
  if (!text || hasControlChar(text)) return null
  return truncateUtf8(text, maxBytes)
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
