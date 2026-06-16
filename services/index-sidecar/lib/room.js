// RoomManager — owns the schema-sheets room: open/create, idempotent schema
// registration, and primary-keyed upsert (so re-projecting a relay updates the
// existing row instead of appending a duplicate). The room is public read-only
// (no encryption key) so any peer can blind-replicate it.
import SchemaSheets from 'schema-sheets'
import z32 from 'z32'
import { discoveryKey as toDiscoveryKey } from 'hypercore-crypto'
import { SCHEMA_NAMES, SCHEMAS } from './schemas.js'

// The field that uniquely identifies a row within each schema — used to keep a
// stable name→rowUuid map so projection upserts rather than duplicates.
const PRIMARY_KEY = {
  'pin-registry': (r) => r.appKey,
  'relay-directory': (r) => r.pubkey,
  'app-manifest': (r) => r.appId,
  verification: (r) => r.subjectAppKey + ':' + r.verifierPubkey
}

export class RoomManager {
  constructor ({ store, roomKey = null, membership = 'relay:index' } = {}) {
    this.store = store
    this._roomKey = roomKey ? (typeof roomKey === 'string' ? z32.decode(roomKey) : roomKey) : null
    this.membership = membership
    this.sheets = null
    this.schemaIds = {} // name -> schemaId
    this.rowIndex = {} // name -> Map(primaryKey -> rowUuid)
    for (const n of SCHEMA_NAMES) this.rowIndex[n] = new Map()
  }

  async open () {
    this.sheets = new SchemaSheets(this.store, this._roomKey, {})
    await this.sheets.ready()
    if (!(await this.sheets.joined())) await this.sheets.join(this.membership)
    await this._ensureSchemas()
    await this._hydrateIndex()
    return this.roomKeyZ32
  }

  get roomKeyZ32 () {
    return this.sheets ? z32.encode(this.sheets.key) : null
  }

  get discoveryKey () {
    if (!this.sheets) return null
    if (this.sheets.base && this.sheets.base.discoveryKey) return this.sheets.base.discoveryKey
    return toDiscoveryKey(this.sheets.key)
  }

  async _ensureSchemas () {
    const existing = await this.sheets.listSchemas()
    const byName = new Map(existing.map(s => [s.name, s.schemaId]))
    for (const name of SCHEMA_NAMES) {
      if (byName.has(name)) {
        this.schemaIds[name] = byName.get(name)
      } else {
        this.schemaIds[name] = await this.sheets.addNewSchema(name, SCHEMAS[name], { v: 1 })
      }
    }
  }

  // Rebuild primaryKey -> rowUuid maps from rows already in the room, so a
  // restart updates existing rows instead of duplicating them.
  async _hydrateIndex () {
    for (const name of SCHEMA_NAMES) {
      const id = this.schemaIds[name]
      if (!id) continue
      const rows = await this.sheets.list(id)
      const keyFn = PRIMARY_KEY[name]
      const map = this.rowIndex[name]
      for (const row of rows) {
        const pk = keyFn(row.json || {})
        if (pk != null && row.uuid && !map.has(pk)) map.set(pk, row.uuid)
      }
    }
  }

  /**
   * Insert or update a row keyed by its schema's primary key. Returns
   * { action: 'add'|'update', uuid }.
   */
  async upsert (schemaName, row) {
    const id = this.schemaIds[schemaName]
    if (!id) throw new Error('unknown schema: ' + schemaName)
    const pk = PRIMARY_KEY[schemaName](row)
    if (pk == null) throw new Error('row missing primary key for ' + schemaName)
    const map = this.rowIndex[schemaName]
    const existing = map.get(pk)
    if (existing) {
      await this.sheets.updateRow(existing, row)
      return { action: 'update', uuid: existing }
    }
    const uuid = await this.sheets.addRow(id, row)
    map.set(pk, uuid)
    return { action: 'add', uuid }
  }

  // Remove a row by primary key (used to prune entries that disappeared from
  // the relay catalogue). No-op if the pk isn't tracked.
  async deleteRow (schemaName, pk) {
    const map = this.rowIndex[schemaName]
    if (!map) return false
    const uuid = map.get(pk)
    if (!uuid) return false
    await this.sheets.deleteRow(uuid)
    map.delete(pk)
    return true
  }

  async list (schemaName, opts = {}) {
    const id = this.schemaIds[schemaName]
    if (!id) return []
    return this.sheets.list(id, opts)
  }

  // Autobase local input-log length — surfaced so the projector can log growth.
  get localLength () {
    return (this.sheets && this.sheets.base && this.sheets.base.local) ? this.sheets.base.local.length : 0
  }

  async update () {
    if (this.sheets && this.sheets.base) await this.sheets.base.update()
  }

  // Await the Autobase view teardown BEFORE closing the store, so the final
  // HyperDB flush can't race the cores being torn down. (SchemaSheets.close()
  // does not await base.close(), so we drive the ordered teardown ourselves.)
  async close () {
    if (!this.sheets) return
    try { if (this.sheets.base) await this.sheets.base.close() } catch (_) {}
    try { await this.store.close() } catch (_) {}
  }
}
