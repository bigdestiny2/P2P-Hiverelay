// Private I03 successor. Frozen public client/worker artifacts are not modified.
const KEY = /^intent:[0-9a-f]{64}$/
const U64 = (1n << 64n) - 1n
const FORMAT = 'hiverelay-indexeddb-intent-v1'
const fail = (code, message) => Object.assign(new Error(message), { code })
const validKey = key => {
  if (typeof key !== 'string' || !KEY.test(key)) throw fail('INTENT_STORE_INPUT', 'Invalid intent key')
  return key
}
const revision = value => {
  if (typeof value !== 'bigint' || value < 0n || value > U64) throw fail('INTENT_STORE_INPUT', 'Invalid u64 revision')
  return value
}
function bounded (value, max, name) {
  if (!Number.isSafeInteger(value) || value < 1 || value > max) throw fail('INTENT_STORE_INPUT', 'Invalid ' + name)
  return value
}

export class BrowserIntentBackend {
  constructor ({ name, origin, mode, maxRecords, maxTotalBytes, maxCiphertextBytes = 8 * 1024 * 1024 + 292 }) {
    if (!globalThis.isSecureContext || origin !== globalThis.location?.origin || origin === 'null') throw fail('INTENT_STORE_ORIGIN', 'Exact secure origin required')
    if (!/^[a-z][a-z0-9.-]{0,95}$/.test(name) || !['create', 'reopen'].includes(mode)) throw fail('INTENT_STORE_INPUT', 'Explicit database identity and create/reopen mode required')
    this.name = 'hiverelay.private-intent.v1.' + name
    this.mode = mode
    this.policy = Object.freeze({
      format: FORMAT,
      origin,
      maxRecords: bounded(maxRecords, 1000000, 'record capacity'),
      maxTotalBytes: bounded(maxTotalBytes, 1024 * 1024 * 1024, 'total capacity'),
      maxCiphertextBytes: bounded(maxCiphertextBytes, 8 * 1024 * 1024 + 292, 'ciphertext capacity')
    })
    this._db = null
    this._opening = null
    this._pending = new Set()
    this._scans = new Map()
    this._transactions = new Set()
    this._closing = false
    this._failure = null
  }

  ready () {
    if (this._closing) return Promise.reject(fail('INTENT_STORE_CLOSED', 'Backend closing'))
    if (this._failure) return Promise.reject(fail('INTENT_STORE_FAILED', 'Close and recover backend'))
    if (!this._opening) this._opening = this._open().catch(error => { this._failure = error; throw error })
    return this._opening
  }

  _open () {
    return new Promise((resolve, reject) => {
      let reason; let created = false
      const request = indexedDB.open(this.name, 1)
      const timer = setTimeout(() => { reason = fail('INTENT_STORE_OPEN', 'Database open deadline expired'); reject(reason) }, 30000)
      request.onblocked = () => { clearTimeout(timer); reason = fail('INTENT_STORE_BLOCKED', 'Database open blocked'); reject(reason) }
      request.onerror = () => { clearTimeout(timer); reject(reason || fail('INTENT_STORE_OPEN', request.error?.name || 'Open failed')) }
      request.onupgradeneeded = event => {
        if (reason || this._closing) { request.transaction.abort(); return }
        if (this.mode !== 'create' || event.oldVersion !== 0) {
          reason = fail('INTENT_STORE_MISSING', 'Existing database missing or incompatible; never silently recreate')
          request.transaction.abort()
          return
        }
        const db = request.result
        created = true
        db.createObjectStore('records')
        db.createObjectStore('authority').add({ policy: this.policy, records: 0, bytes: 0, generation: '0' }, 'state')
      }
      request.onsuccess = () => {
        clearTimeout(timer)
        const db = request.result
        if (this.mode === 'create' && !created) reason = fail('INTENT_STORE_EXISTS', 'Create requires a fresh database')
        if (reason || this._closing) { db.close(); reject(reason || fail('INTENT_STORE_CLOSED', 'Backend closing')); return }
        if (db.objectStoreNames.length !== 2 || !db.objectStoreNames.contains('records') || !db.objectStoreNames.contains('authority')) {
          db.close(); reject(fail('INTENT_STORE_CORRUPT', 'Unexpected database schema')); return
        }
        this._db = db
        db.onversionchange = () => { this._failure = fail('INTENT_STORE_CHANGED', 'Database version changed'); db.close() }
        db.onclose = () => { this._failure = fail('INTENT_STORE_CLOSED', 'Database connection unexpectedly closed') }
        this._transaction('readonly', (tx, done, abort) => {
          const get = tx.objectStore('authority').get('state')
          get.onsuccess = () => { try { this._state(get.result); done() } catch (error) { abort(error) } }
        }).then(resolve, error => { db.close(); reject(error) })
      }
    })
  }

  _state (state) {
    if (!state || JSON.stringify(state.policy) !== JSON.stringify(this.policy) ||
        !Number.isSafeInteger(state.records) || state.records < 0 || state.records > this.policy.maxRecords ||
        !Number.isSafeInteger(state.bytes) || state.bytes < 0 || state.bytes > this.policy.maxTotalBytes ||
        typeof state.generation !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(state.generation) || BigInt(state.generation) > U64) {
      throw fail('INTENT_STORE_CORRUPT', 'Missing or incompatible capacity authority')
    }
    return state
  }

  _record (record) {
    if (record === undefined) return { revision: 0n, ciphertext: null }
    if (!record || typeof record.revision !== 'string' || !/^[1-9][0-9]{0,19}$/.test(record.revision) || BigInt(record.revision) > U64 ||
        !(record.ciphertext instanceof Uint8Array) || record.ciphertext.byteLength < 1 || record.ciphertext.byteLength > this.policy.maxCiphertextBytes) {
      throw fail('INTENT_STORE_CORRUPT', 'Invalid committed record')
    }
    return { revision: BigInt(record.revision), ciphertext: record.ciphertext.slice() }
  }

  _transaction (mode, work) {
    return new Promise((resolve, reject) => {
      let result; let error; let finished = false
      let tx
      try { tx = this._db.transaction(['records', 'authority'], mode, { durability: 'strict' }) } catch (cause) { reject(fail('INTENT_STORE_UNSUPPORTED', cause.name)); return }
      if (mode === 'readwrite' && tx.durability !== 'strict') { tx.abort(); reject(fail('INTENT_STORE_UNSUPPORTED', 'Strict transaction durability unavailable')); return }
      this._transactions.add(tx)
      const abort = cause => { error = cause; try { tx.abort() } catch {} }
      const timer = setTimeout(() => abort(fail('INTENT_STORE_COMMIT_UNKNOWN', 'Transaction deadline expired')), 30000)
      tx.onabort = () => {
        clearTimeout(timer); this._transactions.delete(tx)
        const cause = error || fail(mode === 'readwrite' ? 'INTENT_STORE_COMMIT_UNKNOWN' : 'INTENT_STORE_READ', tx.error?.name || 'Transaction aborted')
        if (cause.code === 'INTENT_STORE_COMMIT_UNKNOWN') {
          this._failure = cause
          for (const pending of this._transactions) { try { pending.abort() } catch {} }
        }
        reject(cause)
      }
      tx.oncomplete = () => {
        clearTimeout(timer); this._transactions.delete(tx)
        if (this._failure) { reject(fail('INTENT_STORE_COMMIT_UNKNOWN', 'Backend failed before transaction acknowledgment')); return }
        if (!finished) { reject(fail('INTENT_STORE_CORRUPT', 'Transaction completed without a result')); return }
        resolve(result)
      }
      try { work(tx, value => { result = value; finished = true }, abort) } catch (cause) { abort(cause) }
    })
  }

  _admit (work) {
    if (this._closing) return Promise.reject(fail('INTENT_STORE_CLOSED', 'Backend closing'))
    if (this._failure) return Promise.reject(fail('INTENT_STORE_FAILED', 'Close and recover backend'))
    if (this._pending.size >= 8) return Promise.reject(fail('INTENT_STORE_BUSY', 'Operation capacity reached'))
    let operation
    try { operation = work() } catch (error) { return Promise.reject(error) }
    const promise = this.ready().then(() => {
      if (this._failure) throw fail('INTENT_STORE_FAILED', 'Close and recover backend')
      return operation()
    })
    this._pending.add(promise)
    promise.then(() => this._pending.delete(promise), () => this._pending.delete(promise))
    return promise
  }

  read (key) {
    return this._admit(() => {
      validKey(key)
      return () => this._transaction('readonly', (tx, done, abort) => {
        const request = tx.objectStore('records').get(key)
        request.onsuccess = () => { try { done(this._record(request.result)) } catch (error) { abort(error) } }
      })
    })
  }

  compareAndSwap (key, expectedRevision, ciphertext) {
    return this._admit(() => {
      validKey(key); revision(expectedRevision)
      if (!(ciphertext instanceof Uint8Array) || ciphertext.byteLength < 1 || ciphertext.byteLength > this.policy.maxCiphertextBytes) throw fail('INTENT_STORE_INPUT', 'Ciphertext outside bound')
      // Copy only after operation admission, before yielding to the caller.
      const copy = ciphertext.slice()
      return () => this._transaction('readwrite', (tx, done, abort) => {
        const authority = tx.objectStore('authority')
        const records = tx.objectStore('records')
        const getState = authority.get('state')
        getState.onsuccess = () => {
          let state
          try { state = this._state(getState.result) } catch (error) { abort(error); return }
          const getRecord = records.get(key)
          getRecord.onsuccess = () => {
            try {
              const current = this._record(getRecord.result)
              if (current.revision !== expectedRevision) { done(false); return }
              if (expectedRevision === U64 || BigInt(state.generation) === U64) throw fail('INTENT_STORE_EXHAUSTED', 'Revision exhausted')
              const count = state.records + (current.ciphertext === null ? 1 : 0)
              const bytes = state.bytes - (current.ciphertext?.byteLength || 0) + copy.byteLength
              if (count > this.policy.maxRecords || bytes > this.policy.maxTotalBytes) throw fail('INTENT_STORE_CAPACITY', 'Retained intent capacity reached')
              records.put({ revision: String(expectedRevision + 1n), ciphertext: copy }, key)
              authority.put({ policy: this.policy, records: count, bytes, generation: String(BigInt(state.generation) + 1n) }, 'state')
              done(true)
            } catch (error) { abort(error) }
          }
        }
      })
    })
  }

  keysPage ({ cursor = null, limit = 64 } = {}) {
    return this._admit(() => {
      bounded(limit, 256, 'page size')
      const previous = cursor === null ? null : this._scans.get(cursor)
      if (cursor !== null && !previous) throw fail('INTENT_STORE_INPUT', 'Unknown or consumed scan cursor')
      if (cursor === null && this._scans.size >= 4) throw fail('INTENT_STORE_BUSY', 'Scan capacity reached')
      const token = cursor || crypto.randomUUID()
      // Reserve now so concurrent page calls cannot exceed scan admission.
      this._scans.set(token, { busy: true })
      if (previous?.busy) throw fail('INTENT_STORE_BUSY', 'Scan already advancing')
      return () => this._transaction('readonly', (tx, done, abort) => {
        const stateRequest = tx.objectStore('authority').get('state')
        stateRequest.onsuccess = () => {
          try {
            const state = this._state(stateRequest.result)
            if (previous && previous.generation !== state.generation) throw fail('INTENT_SCAN_CHANGED', 'Inventory changed; restart enumeration')
            const keys = []
            const request = tx.objectStore('records').openKeyCursor(previous ? IDBKeyRange.lowerBound(previous.last, true) : null)
            request.onsuccess = () => {
              try {
                const next = request.result
                if (!next) { this._scans.delete(token); done({ keys, cursor: null }); return }
                validKey(next.key)
                if (keys.length === limit) {
                  this._scans.set(token, { last: keys[keys.length - 1], generation: state.generation })
                  done({ keys, cursor: token }); return
                }
                keys.push(next.key); next.continue()
              } catch (error) { this._scans.delete(token); abort(error) }
            }
          } catch (error) { this._scans.delete(token); abort(error) }
        }
      }).catch(error => { this._scans.delete(token); throw error })
    })
  }

  closeScan (cursor) { this._scans.delete(cursor); return Promise.resolve() }

  close () {
    if (this._closePromise) return this._closePromise
    this._closing = true
    this._closePromise = (async () => {
      await Promise.allSettled([...this._pending])
      if (this._opening) await this._opening.catch(() => {})
      this._scans.clear()
      this._db?.close()
    })()
    return this._closePromise
  }
}
