import { EncryptedIntentStore, INTENT_STATE } from '../blind-client/intent.js'

const KEY = /^intent:[0-9a-f]{64}$/
const fail = (code, message) => Object.assign(new Error(message), { code })
const bytes = key => Uint8Array.from(key.slice(7).match(/../g), value => parseInt(value, 16))
const validKey = key => { if (typeof key !== 'string' || !KEY.test(key)) throw fail('INTENT_STORE_INPUT', 'Invalid intent key') }
const size = record => {
  if (!record || typeof record.revision !== 'bigint' || record.revision < 0n || record.revision > (1n << 64n) - 1n ||
      (record.ciphertext === null ? record.revision !== 0n : record.revision === 0n || !(record.ciphertext instanceof Uint8Array))) throw fail('INTENT_CORRUPT', 'Invalid backend record')
  return record.ciphertext === null ? 0 : record.ciphertext.byteLength + 84
}

// Requires an actual lifetime exclusive-writer backend (accepted Node/Bare/Pear),
// not MemoryIntentBackend or a shared multi-tab IndexedDB backend.
export class BoundedNativeIntentBackend {
  constructor (backend, { maxRecords, maxTotalBytes, maxCiphertextBytes = 8 * 1024 * 1024 + 292 }) {
    for (const method of ['ready', 'read', 'compareAndSwap', 'keysPage', 'closeScan', 'close']) {
      if (typeof backend?.[method] !== 'function') throw fail('INTENT_STORE_INPUT', 'Exclusive native backend required')
    }
    if (!Number.isSafeInteger(maxRecords) || maxRecords < 1 || maxRecords > 4096 ||
        !Number.isSafeInteger(maxTotalBytes) || maxTotalBytes < 85 || maxTotalBytes > 1024 * 1024 * 1024 ||
        !Number.isSafeInteger(maxCiphertextBytes) || maxCiphertextBytes < 1 || maxCiphertextBytes > 8 * 1024 * 1024 + 292) throw fail('INTENT_STORE_INPUT', 'Explicit bounded retention policy required')
    this.backend = backend
    this.policy = Object.freeze({ maxRecords, maxTotalBytes, maxCiphertextBytes })
    this.inventory = new Map()
    this.totalBytes = 0
    this._pending = 0
    this._tail = Promise.resolve()
    this._opening = null
    this._closed = false
    this._failed = null
  }

  ready () {
    if (this._closed) return Promise.reject(fail('INTENT_STORE_CLOSED', 'Journal closing'))
    if (this._failed) return Promise.reject(fail('INTENT_STORE_FAILED', 'Reopen and reconcile journal'))
    if (!this._opening) this._opening = this._census().catch(error => { this._failed = error; throw error })
    return this._opening
  }

  async _census () {
    await this.backend.ready()
    let cursor = null
    try {
      do {
        const page = await this.backend.keysPage({ cursor, limit: 64 }); cursor = page.cursor
        for (const key of page.keys) {
          validKey(key)
          if (this.inventory.has(key) || this.inventory.size >= this.policy.maxRecords) throw fail('INTENT_STORE_CAPACITY', 'Store exceeds bounded record inventory')
          const record = await this.backend.read(key)
          const length = size(record)
          if (!length || length > this.policy.maxCiphertextBytes + 84 || this.totalBytes + length > this.policy.maxTotalBytes) throw fail('INTENT_STORE_CAPACITY', 'Store exceeds retained byte capacity')
          this.inventory.set(key, { revision: record.revision, size: length }); this.totalBytes += length
        }
      } while (cursor !== null)
    } finally { if (cursor !== null) await this.backend.closeScan(cursor) }
  }

  _admit (prepare) {
    if (this._closed) return Promise.reject(fail('INTENT_STORE_CLOSED', 'Journal closing'))
    if (this._failed) return Promise.reject(fail('INTENT_STORE_FAILED', 'Reopen and reconcile journal'))
    if (this._pending >= 8) return Promise.reject(fail('INTENT_STORE_BUSY', 'Journal operation capacity reached'))
    let work
    try { work = prepare() } catch (error) { return Promise.reject(error) }
    const opening = this.ready()
    this._pending++
    const result = this._tail.then(async () => {
      await opening
      if (this._failed) throw fail('INTENT_STORE_FAILED', 'Reopen and reconcile journal')
      return work()
    })
    this._tail = result.catch(() => {}).finally(() => { this._pending-- })
    return result
  }

  read (key) {
    return this._admit(() => { validKey(key); return async () => this.backend.read(key) })
  }

  compareAndSwap (key, expectedRevision, ciphertext) {
    return this._admit(() => {
      validKey(key)
      if (typeof expectedRevision !== 'bigint' || expectedRevision < 0n || expectedRevision >= (1n << 64n) - 1n ||
          !(ciphertext instanceof Uint8Array) || ciphertext.byteLength < 1 || ciphertext.byteLength > this.policy.maxCiphertextBytes) throw fail('INTENT_STORE_INPUT', 'Invalid revision or bounded ciphertext')
      const copy = new Uint8Array(ciphertext)
      return async () => {
        const before = this.inventory.get(key)
        if ((before?.revision || 0n) !== expectedRevision) return false
        const nextBytes = this.totalBytes - (before?.size || 0) + copy.byteLength + 84
        if ((!before && this.inventory.size >= this.policy.maxRecords) || nextBytes > this.policy.maxTotalBytes) throw fail('INTENT_STORE_CAPACITY', 'Retained intent capacity reached; unresolved records are never discarded')
        let changed
        try { changed = await this.backend.compareAndSwap(key, expectedRevision, copy) } catch (error) {
          if (['INTENT_STORE_COMMIT_UNKNOWN', 'INTENT_STORE_FAILED'].includes(error.code)) this._failed = error
          throw error
        }
        if (!changed) { this._failed = fail('INTENT_STORE_OWNERSHIP', 'Exclusive backend changed outside journal'); throw this._failed }
        this.inventory.set(key, { revision: expectedRevision + 1n, size: copy.byteLength + 84 })
        this.totalBytes = nextBytes
        return true
      }
    })
  }

  close () {
    if (!this._closePromise) {
      this._closed = true
      this._closePromise = (async () => {
        if (this._opening) await this._opening.catch(() => {})
        await this._tail
        await this.backend.close()
      })()
    }
    return this._closePromise
  }
}

export class DurableIntentJournal {
  constructor ({ backend, sealer, policy, recoveryFloors }) {
    if (!Array.isArray(recoveryFloors) || recoveryFloors.length > policy.maxRecords) throw fail('INTENT_RECOVERY_ANCHOR', 'Explicit externally authenticated recovery floors required (empty only for an authorized fresh journal)')
    this.floors = new Map()
    for (const floor of recoveryFloors) {
      validKey(floor.key)
      if (typeof floor.revision !== 'bigint' || floor.revision < 1n || floor.revision >= 1n << 64n || this.floors.has(floor.key)) throw fail('INTENT_RECOVERY_ANCHOR', 'Invalid or duplicate external revision floor')
      this.floors.set(floor.key, floor.revision)
    }
    this.backend = new BoundedNativeIntentBackend(backend, policy)
    this.store = new EncryptedIntentStore({ backend: this.backend, sealer })
    this._closing = false
  }

  ready () {
    if (this._closing) return Promise.reject(fail('INTENT_STORE_CLOSED', 'Journal closing'))
    if (!this._opening) this._opening = this._recover()
    return this._opening
  }

  async _recover () {
    await this.backend.ready()
    for (const [key, floor] of this.floors) {
      if ((this.backend.inventory.get(key)?.revision || 0n) < floor) throw fail('INTENT_RECOVERY_ROLLBACK', 'Backup missing an externally acknowledged intent revision')
    }
    // Authenticate every existing record with the recovered caller key before any
    // recovery writes. No plaintext intent/capability is stored in the census.
    for (const key of this.backend.inventory.keys()) await this.store.read(bytes(key))
    let uncertain = 0
    for (const key of this.backend.inventory.keys()) {
      const record = await this.store.read(bytes(key))
      if ([INTENT_STATE.SENT, INTENT_STATE.ACKNOWLEDGED].includes(record.value.state)) {
        await this.store.update(bytes(key), value => ({ ...value, state: INTENT_STATE.PENDING_UNKNOWN, mayHaveCommitted: true }))
        uncertain++
      }
    }
    return Object.freeze({ consumer: '@hiverelay/blind-intent-journal-consumer@0.0.0-i01.1', authenticatedRecords: this.backend.inventory.size, uncertain, networkSends: 0 })
  }

  async create (intent) { await this.ready(); return this.store.create(intent) }
  async read (id) { await this.ready(); return this.store.read(id) }
  async update (id, mutate) { await this.ready(); return this.store.update(id, mutate) }
  close () {
    if (!this._closePromise) {
      this._closing = true
      this._closePromise = (async () => {
        if (this._opening) await this._opening.catch(() => {})
        await this.backend.close()
      })()
    }
    return this._closePromise
  }
}
