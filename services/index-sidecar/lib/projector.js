// Projector — polls the relay's public surface and projects it into the room.
//
// Write-amp discipline (the spike measured ~18KB/row Autobase append, and
// updateRow has NO in-place mutate): a row is written only when its CONTENT
// changed. Two subtleties this enforces:
//   1. The change-hash is recorded only AFTER a successful upsert, so a thrown
//      write is retried next pass instead of being lost.
//   2. The hash ignores purely-volatile fields (the relay-directory's
//      re-attestation timestamp + the signed doc/sig), so a relay re-signing
//      its capability doc every fetch does NOT churn an append every poll.
// This suppresses NO-OP writes; a genuinely-changing field still appends once.
// Unbounded input-log growth over a very long life still needs room rotation
// (see INDEX-LAYER.md) — not solved here.
import { createHash } from 'crypto'
import { appManifestRow, pinRegistryRow, relayDirectoryRow } from './mappers.js'
import { validateRow } from './schemas.js'

// Primary key per schema (matches RoomManager.PRIMARY_KEY) — used for the
// change-cache key, restart priming, and stale-row pruning.
const PK = {
  'app-manifest': (r) => r.appId,
  'pin-registry': (r) => r.appKey,
  'relay-directory': (r) => r.pubkey
}

// Fields excluded from the change-hash because they advance on every fetch
// without reflecting a meaningful change (would otherwise append every poll).
function stableForHash (schema, row) {
  if (schema !== 'relay-directory') return row
  const { doc, capabilitySig, health, ...rest } = row
  const stableHealth = health ? { ...health } : undefined
  if (stableHealth) delete stableHealth.lastSeen
  return stableHealth ? { ...rest, health: stableHealth } : rest
}

function rowHash (schema, row) {
  const r = stableForHash(schema, row)
  const canon = JSON.stringify(r, Object.keys(r).sort())
  return createHash('sha1').update(canon).digest('hex')
}

export class Projector {
  constructor ({ relayClient, room, relayPubkey = null, intervalMs = 15000, log = () => {} } = {}) {
    this.relayClient = relayClient
    this.room = room
    this.relayPubkey = relayPubkey
    this.intervalMs = intervalMs
    this.log = log
    this._timer = null
    this._stopped = false
    this._running = false
    this._primed = false
    this._hashes = new Map() // `${schema}:${pk}` -> last written content hash
  }

  // Seed the change-cache from rows already in the room so the first post-
  // restart sync does NOT re-append every (byte-identical) row.
  async prime () {
    if (this._primed) return
    for (const [schema, keyFn] of Object.entries(PK)) {
      const rows = await this.room.list(schema)
      for (const r of rows) {
        const pk = keyFn(r.json || {})
        if (pk != null) this._hashes.set(schema + ':' + pk, rowHash(schema, r.json))
      }
    }
    this._primed = true
  }

  async _writeDebounced (schema, row, pk, stats) {
    const { valid, errors } = validateRow(schema, row)
    if (!valid) { stats.invalid++; this.log(`skip invalid ${schema} row: ${errors[0]}`); return }
    const k = schema + ':' + pk
    const h = rowHash(schema, row)
    if (this._hashes.get(k) === h) { stats.skipped++; return }
    const { action } = await this.room.upsert(schema, row) // throws → hash NOT set → retried next pass
    this._hashes.set(k, h)
    stats[action === 'add' ? 'added' : 'updated']++
  }

  async syncOnce () {
    if (this._running) return null
    this._running = true
    await this.prime()
    const stats = { added: 0, updated: 0, skipped: 0, invalid: 0, removed: 0 }
    // Overall deadline so one slow relay can't wedge a whole pass.
    const controller = new AbortController()
    const deadline = setTimeout(() => controller.abort(), Math.max(Math.min(this.intervalMs * 0.8, 30000), 5000))
    const seen = { 'app-manifest': new Set(), 'pin-registry': new Set(), 'relay-directory': new Set() }
    try {
      const cap = await this.relayClient.getCapability({ signal: controller.signal })
      if (cap && !this.relayPubkey && typeof cap.pubkey === 'string') this.relayPubkey = cap.pubkey

      if (cap) {
        const dir = relayDirectoryRow(cap, null)
        if (dir) { seen['relay-directory'].add(dir.pubkey); await this._writeDebounced('relay-directory', dir, dir.pubkey, stats) }
      }

      const { entries, ok } = await this.relayClient.getCatalog({ signal: controller.signal })
      for (const entry of entries) {
        const manifest = appManifestRow(entry)
        if (manifest) { seen['app-manifest'].add(manifest.appId); await this._writeDebounced('app-manifest', manifest, manifest.appId, stats) }
        const pin = pinRegistryRow(entry, this.relayPubkey)
        if (pin) { seen['pin-registry'].add(pin.appKey); await this._writeDebounced('pin-registry', pin, pin.appKey, stats) }
      }

      // Prune rows for entries that disappeared — ONLY when the source was read
      // completely, so a transient fetch failure never mass-deletes the index.
      if (cap) await this._prune('relay-directory', seen['relay-directory'], stats)
      if (ok) {
        await this._prune('app-manifest', seen['app-manifest'], stats)
        await this._prune('pin-registry', seen['pin-registry'], stats)
      }

      await this.room.update()
      if (stats.added || stats.updated || stats.removed) {
        this.log(`projected: +${stats.added} ~${stats.updated} -${stats.removed} (skipped ${stats.skipped}, invalid ${stats.invalid}, log ${this.room.localLength})`)
      }
      return stats
    } catch (err) {
      this.log('sync error: ' + err.message)
      return { ...stats, error: err.message }
    } finally {
      clearTimeout(deadline)
      this._running = false
    }
  }

  async _prune (schema, seenSet, stats) {
    const prefix = schema + ':'
    for (const k of [...this._hashes.keys()]) {
      if (!k.startsWith(prefix)) continue
      const pk = k.slice(prefix.length)
      if (seenSet.has(pk)) continue
      try {
        await this.room.deleteRow(schema, pk)
        this._hashes.delete(k)
        stats.removed++
      } catch (err) {
        this.log(`prune ${schema} ${pk} failed: ${err.message}`)
      }
    }
  }

  start () {
    this._stopped = false
    const loop = async () => {
      if (this._stopped) return
      await this.syncOnce()
      if (this._stopped) return
      this._timer = setTimeout(loop, this.intervalMs)
      if (this._timer.unref) this._timer.unref()
    }
    loop()
  }

  stop () {
    this._stopped = true
    if (this._timer) { clearTimeout(this._timer); this._timer = null }
  }
}
