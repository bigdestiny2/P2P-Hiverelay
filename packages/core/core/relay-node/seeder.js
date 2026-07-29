import b4a from 'b4a'
import { EventEmitter } from 'events'
import { readFile, writeFile, rename, unlink, mkdir, stat } from 'fs/promises'
import { dirname } from 'path'
import { positiveStorageBound } from '../../config/storage-cap.js'
import { STORAGE_COMMITMENT_METADATA_OVERHEAD_BYTES } from '../../config/storage-admission-authority.js'
import { isValidHexKey } from '../constants.js'

const PERSIST_SCHEMA_VERSION = 3
const SEEDED_CORE_INVENTORY_MAX_RECORDS = 4096
const TRACKED_STORAGE_MUTATION = Symbol('tracked-storage-mutation')
const TRACKED_STORAGE_REMOVAL = Symbol('tracked-storage-removal')
const TRACKED_CORE_INVENTORY = Symbol('tracked-core-inventory')

export class Seeder extends EventEmitter {
  constructor (store, swarm, opts = {}) {
    super()
    this.store = store
    this.swarm = swarm
    this.maxStorageBytes = opts.maxStorageBytes ?? 50 * 1024 * 1024 * 1024
    this._canAdopt = typeof opts.canAdopt === 'function' ? opts.canAdopt : null
    this.storageAdmission = opts.storageAdmission || null
    this.announceInterval = opts.announceInterval || 15 * 60 * 1000
    this.cores = new Map() // hex key -> { core, interval, bytesStored }
    this._retiringCores = new Map()
    this.totalBytesStored = 0
    this.totalBytesServed = 0
    this.running = false
    this._acceptingSeeds = false
    this._starting = null
    this._stopping = null

    // v0.18.x — persist the set of seeded BARE-core keys so they survive a
    // relay restart. Catalog bees + any /seed-core pin are plain Hypercores
    // (not appRegistry-managed Hyperdrives), so without this they'd be
    // forgotten on restart and the relay would silently stop serving them.
    // Atomic tmp+rename (same pattern as subsidy.json / lease.json).
    this._persistPath = opts.storagePath || null
    this._persistTail = Promise.resolve()
    this._inventoryTail = Promise.resolve()
    // While re-seeding from the persisted list on start(), suppress the
    // per-seedCore write (the file already holds exactly these keys).
    this._restoring = false
    this._ownedAnnouncements = new Map()
    this._ownedAnnouncementTails = new Map()
  }

  start () {
    if (this._starting) return this._starting
    const operation = this._startLifecycle()
    const starting = operation.finally(() => {
      if (this._starting === starting) this._starting = null
    })
    this._starting = starting
    return starting
  }

  async _startLifecycle () {
    if (this._stopping) try { await this._stopping } catch (_) {}
    if (this.running && this._acceptingSeeds) return this
    return this._queueInventoryMutation(() => {
      const run = () => this._startOwned()
      return this.storageAdmission?.runKeyMutation
        ? this.storageAdmission.runKeyMutation('core-inventory', run)
        : run()
    })
  }

  async _startOwned () {
    if (this.cores.size > 0 || this._retiringCores.size > 0 || this._ownedAnnouncements.size > 0) {
      await this._stop()
    }
    this.running = true
    this._acceptingSeeds = true
    // Re-seed cores pinned in a previous run. Their blocks already live in the
    // corestore on disk, so this re-opens + re-announces them (fast) and
    // resumes serving. Per-key failures are non-fatal.
    await this._restorePersisted()
    this._emitSafely('started')
    return this
  }

  async recoverInventoryOnly () {
    let records
    try {
      records = await this._loadPersisted()
    } catch (err) {
      this._emitSafely('recovery-error', { source: 'seeded-cores', error: err && err.message ? err.message : String(err) })
      return false
    }
    for (const record of records) {
      if (this.storageAdmission) {
        const adopted = this.storageAdmission.adoptRecovery(
          `core:${record.key}`,
          positiveStorageBound(record.maxStorageBytes),
          { kind: 'core' }
        )
        if (!adopted) {
          this._emitSafely('recovery-error', { source: 'seeded-cores', error: 'SEEDED_CORE_INVENTORY_ADOPTION_FAILED' })
          return false
        }
      }
    }
    if (this.storageAdmission) this.storageAdmission.markRecoveryReady('cores')
    this._emitSafely('cores-inventory-recovered', { count: records.length, serving: false })
    return true
  }

  async seedCore (publicKeyHex, opts = {}) {
    if (!isValidHexKey(publicKeyHex, 64)) throw new Error('Invalid core key: must be 64 hex characters')
    publicKeyHex = publicKeyHex.toLowerCase()
    if (!opts[TRACKED_CORE_INVENTORY]) {
      return this._queueInventoryMutation(() => {
        const run = () => this.seedCore(publicKeyHex, {
          ...opts,
          [TRACKED_CORE_INVENTORY]: true
        })
        return this.storageAdmission?.runKeyMutation
          ? this.storageAdmission.runKeyMutation('core-inventory', run)
          : run()
      })
    }
    if (!opts[TRACKED_STORAGE_MUTATION] && this.storageAdmission?.runKeyMutation) {
      return this.storageAdmission.runKeyMutation(`core:${publicKeyHex}`, () => this.seedCore(publicKeyHex, {
        ...opts,
        [TRACKED_STORAGE_MUTATION]: true
      }))
    }
    if (!this._acceptingSeeds && !this._restoring) {
      const err = new Error('seeder is not accepting new cores')
      err.code = 'SEEDER_NOT_RUNNING'
      throw err
    }
    const bound = positiveStorageBound(opts.maxStorageBytes)
    const hasBound = Object.prototype.hasOwnProperty.call(opts, 'maxStorageBytes') && opts.maxStorageBytes !== undefined
    if (!this._restoring && hasBound && bound === null) {
      const err = new Error('positive safe-integer maxStorageBytes is required')
      err.code = 'STORAGE_BOUND_REQUIRED'
      throw err
    }
    if (this.cores.has(publicKeyHex)) {
      return this._reconcileExistingCore(this.cores.get(publicKeyHex), bound)
    }

    const recoveryOnly = this._restoring && bound === null
    let reservation = null
    let durableAccepted = false
    if (!this._restoring) {
      if (bound === null) {
        const err = new Error('positive safe-integer maxStorageBytes is required')
        err.code = 'STORAGE_BOUND_REQUIRED'
        throw err
      }
      reservation = this.storageAdmission
        ? this.storageAdmission.reserve(`core:${publicKeyHex}`, bound, { kind: 'core' })
        : { allowed: false, reason: 'storage-admission-unavailable' }
      if (!reservation.allowed) {
        const err = new Error('Storage admission blocked: ' + (reservation.reason || 'insufficient-storage'))
        err.code = 'STORAGE_ADMISSION_BLOCKED'
        err.storageAdmission = reservation
        throw err
      }
    }

    const key = b4a.from(publicKeyHex, 'hex')
    const core = this.store.get({ key })
    let entry = null
    let authoritativeProof = null
    try {
      await core.ready()

      const topic = core.discoveryKey
      this.swarm.join(topic, { server: true, client: true })
      if (typeof this.swarm.flush === 'function') await this.swarm.flush().catch(() => {})

      // The declared reservation is already visible, so signed head discovery
      // is bounded by the complete commitment. No durable row or download
      // range may exist until the exact byteLength proof succeeds.
      let authoritativeSizeBytes = null
      if (!this._restoring) {
        authoritativeProof = await this._authoritativeCoreSize(core)
        authoritativeSizeBytes = authoritativeProof.byteLength
        if (authoritativeSizeBytes > bound) {
          const err = new Error('maxStorageBytes is below the authoritative core size')
          err.code = 'STORAGE_BOUND_BELOW_ACTUAL'
          err.actualBytes = authoritativeSizeBytes
          err.boundBytes = bound
          throw err
        }
      }

      const interval = setInterval(() => {
        if (this.running) {
          try { this.swarm.join(topic, { server: true, client: true }) } catch (_) {}
          this._refreshBoundedDownload(entry).catch(() => {})
        }
      }, this.announceInterval)
      if (interval.unref) interval.unref()

      entry = {
        core,
        range: null,
        rangeSnapshot: null,
        interval,
        topic,
        publicKeyHex,
        maxStorageBytes: bound,
        authoritativeSizeBytes,
        recoveryOnly,
        startedAt: Date.now(),
        bytesStored: 0,
        bytesServed: 0,
        refreshing: null,
        retiringDownloads: []
      }

      entry.onDownload = (index, byteLength) => {
        entry.bytesStored += byteLength
        this.totalBytesStored += byteLength
        this._emitSafely('block-downloaded', { publicKeyHex, index, byteLength })
      }
      entry.onUpload = (index, byteLength) => {
        entry.bytesServed += byteLength
        this.totalBytesServed += byteLength
        this._emitSafely('block-served', { publicKeyHex, index, byteLength })
      }
      entry.onAppend = () => { this._refreshBoundedDownload(entry).catch(() => {}) }
      entry.downloadListenerAttached = core.on('download', entry.onDownload) !== undefined
      entry.uploadListenerAttached = core.on('upload', entry.onUpload) !== undefined
      entry.appendListenerAttached = core.on('append', entry.onAppend) !== undefined

      this.cores.set(publicKeyHex, entry)
      if (!this._restoring) {
        if (!this.storageAdmission.owns(reservation)) throw new Error('storage reservation ownership lost before persistence')
        await this._persist({ throwOnError: true })
        if (!this.storageAdmission.commit(reservation)) {
          this.storageAdmission.failClosed()
          entry.reconciliationRequired = true
          const err = new Error('storage reservation commit failed after durable core persistence')
          err.code = 'STORAGE_RESERVATION_COMMIT_FAILED'
          err.durableAccepted = true
          throw err
        }
        durableAccepted = true
      }

      if (!recoveryOnly) {
        try {
          if (authoritativeProof) {
            await this._installBoundedDownload(entry, authoritativeProof)
            authoritativeProof = null
          } else {
            await this._refreshBoundedDownload(entry)
          }
        } catch (err) {
          this._emitSafely('download-error', { key: publicKeyHex, error: err && err.message ? err.message : String(err) })
        }
      }
      this._emitSafely('seeding-core', { publicKeyHex, length: core.length, maxStorageBytes: bound })
      return entry
    } catch (err) {
      if (durableAccepted) {
        entry.reconciliationRequired = true
        if (this.storageAdmission) this.storageAdmission.failClosed('storage-post-commit-reconciliation-required')
        err.durableAccepted = true
        this._emitSafely('storage-reconciliation-required', { publicKeyHex, error: err && err.message ? err.message : String(err) })
        throw err
      }
      if (!err.durableAccepted) {
        this.cores.delete(publicKeyHex)
      }
      let settlementError = null
      if (!err.durableAccepted && entry) {
        try { await this._releaseEntry(entry) } catch (releaseError) { settlementError = releaseError }
      } else if (!entry) {
        try { await core.close() } catch (closeError) { settlementError = closeError }
      }
      if (authoritativeProof?.coreSnapshot) {
        try { await authoritativeProof.coreSnapshot.close() } catch (_) {}
      }
      // Do not return capacity while a failed core session can still settle
      // requests or materialize tree/data files. close() is the settlement
      // barrier; rollback is deliberately last.
      if (!err.durableAccepted && settlementError) {
        if (this.storageAdmission) this.storageAdmission.failClosed('storage-core-rejected-settlement-failed')
        const failure = new Error('rejected core teardown did not settle')
        failure.code = 'STORAGE_CORE_TEARDOWN_UNSETTLED'
        failure.cause = err
        failure.teardownCause = settlementError
        throw failure
      }
      if (!err.durableAccepted && reservation && this.storageAdmission) {
        if (!this.storageAdmission.rollback(reservation)) {
          this.storageAdmission.failClosed('storage-core-reservation-rollback-failed')
          const failure = new Error('storage core reservation rollback failed')
          failure.code = 'STORAGE_CORE_RESERVATION_ROLLBACK_FAILED'
          failure.cause = err
          throw failure
        }
      }
      throw err
    }
  }

  async _reconcileExistingCore (entry, bound) {
    if (!entry) throw new Error('seeded core entry missing')
    if (entry.reconciliationRequired || this.storageAdmission?.fatalReason) {
      const err = new Error('seeded core storage authority requires reconciliation')
      err.code = 'STORAGE_RECONCILIATION_REQUIRED'
      throw err
    }
    if (bound === null) return entry
    const oldBound = positiveStorageBound(entry.maxStorageBytes)
    if (oldBound === bound && entry.recoveryOnly !== true) return entry
    if (oldBound !== null && bound < oldBound) {
      const err = new Error('lower maxStorageBytes requires unseed before re-pin')
      err.code = 'STORAGE_BOUND_SHRINK_REQUIRES_UNSEED'
      throw err
    }
    if (entry.reconciling) {
      const err = new Error('core storage-bound reconciliation already in progress')
      err.code = 'STORAGE_RESERVATION_IN_PROGRESS'
      throw err
    }

    entry.reconciling = (async () => {
      let authoritativeProof = null
      try {
        authoritativeProof = await this._authoritativeCoreSize(entry.core)
        const authoritativeSizeBytes = authoritativeProof.byteLength
        if (authoritativeSizeBytes > bound) {
          const err = new Error('maxStorageBytes is below the authoritative core size')
          err.code = 'STORAGE_BOUND_BELOW_ACTUAL'
          err.actualBytes = authoritativeSizeBytes
          err.boundBytes = bound
          throw err
        }
        const key = `core:${entry.publicKeyHex}`
        const reservation = this.storageAdmission
          ? this.storageAdmission.reserve(key, bound, {
            kind: 'core',
            authoritativeSizeBytes: oldBound === null ? authoritativeSizeBytes : undefined
          })
          : { allowed: false, reason: 'storage-admission-unavailable' }
        if (!reservation.allowed) {
          const err = new Error('Storage admission blocked: ' + (reservation.reason || 'insufficient-storage'))
          err.code = 'STORAGE_ADMISSION_BLOCKED'
          err.storageAdmission = reservation
          throw err
        }

        const previousBound = entry.maxStorageBytes
        const previousRecoveryOnly = entry.recoveryOnly
        let persisted = false
        entry.maxStorageBytes = bound
        entry.recoveryOnly = false
        try {
          if (!this.storageAdmission.owns(reservation)) throw new Error('storage reservation ownership lost before persistence')
          await this._persist({ throwOnError: true })
          persisted = true
          if (!this.storageAdmission.commit(reservation)) {
            this.storageAdmission.failClosed()
            entry.reconciliationRequired = true
            const err = new Error('storage reservation commit failed after durable core re-pin')
            err.code = 'STORAGE_RESERVATION_COMMIT_FAILED'
            err.durableAccepted = true
            throw err
          }
        } catch (err) {
          if (persisted || err.durableAccepted) {
            entry.reconciliationRequired = true
            this.storageAdmission.failClosed()
            err.durableAccepted = true
            this._emitSafely('storage-reconciliation-required', {
              publicKeyHex: entry.publicKeyHex,
              error: err && err.message ? err.message : String(err)
            })
            throw err
          }
          entry.maxStorageBytes = previousBound
          entry.recoveryOnly = previousRecoveryOnly
          if (!this.storageAdmission.rollback(reservation)) {
            this.storageAdmission.failClosed('storage-core-reservation-rollback-failed')
            const failure = new Error('storage core reservation rollback failed')
            failure.code = 'STORAGE_CORE_RESERVATION_ROLLBACK_FAILED'
            failure.cause = err
            throw failure
          }
          throw err
        }

        try {
          await this._installBoundedDownload(entry, authoritativeProof)
          authoritativeProof = null
        } catch (err) {
          this._emitSafely('download-error', { key: entry.publicKeyHex, error: err && err.message ? err.message : String(err) })
        }
        this._emitSafely('core-storage-bound-reconciled', {
          publicKeyHex: entry.publicKeyHex,
          oldBound,
          maxStorageBytes: bound,
          authoritativeSizeBytes
        })
        return entry
      } finally {
        if (authoritativeProof?.coreSnapshot) {
          try { await authoritativeProof.coreSnapshot.close() } catch (_) {}
        }
      }
    })()

    try {
      return await entry.reconciling
    } finally {
      entry.reconciling = null
    }
  }

  async _authoritativeCoreSize (core, timeoutMs = 10_000) {
    if (!core || typeof core.update !== 'function') throw new Error('authoritative core size unavailable')
    const activeRequests = []
    let timer = null
    let updated = false
    try {
      updated = await new Promise((resolve, reject) => {
        timer = setTimeout(() => {
          if (core.replicator && typeof core.replicator.clearRequests === 'function') {
            try { core.replicator.clearRequests(activeRequests, new Error('CORE_SIZE_TIMEOUT')) } catch (_) {}
          }
          reject(new Error('authoritative core size timeout'))
        }, timeoutMs)
        Promise.resolve(core.update({ wait: true, activeRequests })).then(resolve, reject)
      })
    } finally {
      if (timer) clearTimeout(timer)
      if (core.replicator && typeof core.replicator.clearRequests === 'function' && activeRequests.length > 0) {
        try { core.replicator.clearRequests(activeRequests, new Error('CORE_SIZE_CANCELLED')) } catch (_) {}
      }
    }
    const proved = this._stableCoreSnapshot(core)
    const { length } = proved
    if (core.writable !== true && length === 0 && updated !== true) {
      throw new Error('authoritative core size unavailable')
    }
    if (typeof core.snapshot !== 'function') throw new Error('authoritative core snapshot unavailable')
    let coreSnapshot = null
    try {
      coreSnapshot = core.snapshot({ wait: false })
      if (typeof coreSnapshot.ready === 'function') await coreSnapshot.ready()
      const pinned = this._stableCoreSnapshot(coreSnapshot)
      if (pinned.length !== proved.length || pinned.byteLength !== proved.byteLength || pinned.fork !== proved.fork) {
        throw new Error('authoritative core changed before snapshot')
      }
      return { ...pinned, coreSnapshot }
    } catch (err) {
      if (coreSnapshot) {
        try { await coreSnapshot.close() } catch (_) {}
      }
      throw err
    }
  }

  _stableCoreSnapshot (core, attempts = 4) {
    for (let attempt = 0; attempt < attempts; attempt++) {
      const forkBefore = Number(core.fork ?? 0)
      const lengthBefore = Number(core.length)
      const byteLengthBefore = Number(core.byteLength)
      const lengthMiddle = Number(core.length)
      const byteLengthAfter = Number(core.byteLength)
      const lengthAfter = Number(core.length)
      const forkAfter = Number(core.fork ?? 0)
      if (!Number.isSafeInteger(lengthBefore) || lengthBefore < 0 ||
          !Number.isSafeInteger(byteLengthBefore) || byteLengthBefore < 0 ||
          !Number.isSafeInteger(lengthMiddle) || lengthMiddle < 0 ||
          !Number.isSafeInteger(byteLengthAfter) || byteLengthAfter < 0 ||
          !Number.isSafeInteger(lengthAfter) || lengthAfter < 0 ||
          !Number.isSafeInteger(forkBefore) || forkBefore < 0 || forkBefore !== forkAfter) {
        throw new Error('authoritative core size invalid')
      }
      if (lengthBefore === lengthMiddle && lengthMiddle === lengthAfter &&
          byteLengthBefore === byteLengthAfter) {
        return { length: lengthAfter, byteLength: byteLengthAfter, fork: forkAfter }
      }
    }
    throw new Error('authoritative core size changed during proof')
  }

  /**
   * Announce a writer-owned core whose complete local growth is already bound
   * by another committed authority record (for example OutboxLog's aggregate
   * journal commitment). This deliberately does not enter the seeded-core
   * persistence/download path and cannot be invoked without an opaque handoff
   * issued by the shared StorageAdmissionAuthority.
   */
  async announceAuthorityOwnedCore (core, handoff, descriptor = {}, tracked = false) {
    if (!tracked) {
      return this._queueInventoryMutation(() => {
        const run = () => this.announceAuthorityOwnedCore(core, handoff, descriptor, true)
        return this.storageAdmission?.runMutation
          ? this.storageAdmission.runMutation(run)
          : run()
      })
    }
    if (!this._acceptingSeeds) {
      const err = new Error('seeder is not accepting authority-owned cores')
      err.code = 'SEEDER_NOT_RUNNING'
      throw err
    }
    if (!this.storageAdmission?.validateOwnedHandoff(handoff)) {
      throw new Error('authority-owned core handoff is invalid')
    }
    if (!core || typeof core.ready !== 'function') throw new Error('authority-owned core is unavailable')
    await core.ready()
    if (!this._acceptingSeeds) {
      const err = new Error('seeder stopped during authority-owned core ready')
      err.code = 'SEEDER_STOPPING'
      throw err
    }
    if (core.writable !== true) throw new Error('authority-owned core must be writable')
    if (!this.storageAdmission?.validateOwnedHandoff(handoff)) {
      throw new Error('authority-owned core handoff expired during ready')
    }
    const publicKeyHex = core.key ? b4a.toString(core.key, 'hex') : null
    if (!publicKeyHex) throw new Error('authority-owned core key is unavailable')
    return this._queueOwnedAnnouncement(publicKeyHex, async () => {
      if (!this.storageAdmission?.validateOwnedHandoff(handoff)) {
        throw new Error('authority-owned core handoff expired before announce')
      }
      const existing = this._ownedAnnouncements.get(publicKeyHex)
      if (existing && existing.handoff === handoff && existing.sourceCore === core) {
        // Idempotence is conditional on the SAME still-live authority lease.
        // Returning an entry tied to a released handoff would silently stop
        // re-announcing forever.
        if (!this.storageAdmission.validateOwnedHandoff(existing.handoff)) {
          throw new Error('authority-owned core existing handoff is invalid')
        }
        return existing
      }
      if (existing) {
        await this._releaseOwnedAnnouncement(existing)
        this._ownedAnnouncements.delete(publicKeyHex)
      }

      const session = typeof core.session === 'function' ? core.session() : core
      const topic = session.discoveryKey || core.discoveryKey
      const entry = {
        publicKeyHex,
        core: session,
        sourceCore: core,
        topic,
        interval: null,
        joined: false,
        closed: session === core,
        handoff,
        descriptor: { ...descriptor },
        authorityOwned: true
      }
      this._ownedAnnouncements.set(publicKeyHex, entry)
      try {
        if (session !== core && typeof session.ready === 'function') await session.ready()
        if (!this._acceptingSeeds) {
          const err = new Error('seeder stopped during authority-owned session ready')
          err.code = 'SEEDER_STOPPING'
          throw err
        }
        if (!this.storageAdmission?.validateOwnedHandoff(handoff)) {
          throw new Error('authority-owned core handoff expired before announce')
        }
        this.swarm.join(topic, { server: true, client: true })
        entry.joined = true
        if (typeof this.swarm.flush === 'function') await this.swarm.flush().catch(() => {})
        if (!this._acceptingSeeds) {
          const err = new Error('seeder stopped during authority-owned core announce')
          err.code = 'SEEDER_STOPPING'
          throw err
        }
        entry.interval = setInterval(() => {
          if (!this.running || !this.storageAdmission?.validateOwnedHandoff(handoff)) return
          try { this.swarm.join(topic, { server: true, client: true }) } catch (_) {}
        }, this.announceInterval)
        if (entry.interval.unref) entry.interval.unref()
      } catch (startCause) {
        try {
          await this._releaseOwnedAnnouncement(entry)
          if (this._ownedAnnouncements.get(publicKeyHex) === entry) this._ownedAnnouncements.delete(publicKeyHex)
        } catch (teardownCause) {
          const failure = new Error('authority-owned core startup teardown did not settle')
          failure.code = 'AUTHORITY_OWNED_CORE_START_TEARDOWN_FAILED'
          failure.startCause = startCause
          failure.teardownCause = teardownCause
          throw failure
        }
        throw startCause
      }
      this._emitSafely('seeding-owned-core', {
        publicKeyHex,
        length: Number.isSafeInteger(core.length) ? core.length : 0,
        ...descriptor
      })
      return entry
    })
  }

  _queueOwnedAnnouncement (publicKeyHex, run) {
    const previous = this._ownedAnnouncementTails.get(publicKeyHex) || Promise.resolve()
    const operation = previous.catch(() => {}).then(run)
    const tail = operation.catch(() => {})
    this._ownedAnnouncementTails.set(publicKeyHex, tail)
    tail.finally(() => {
      if (this._ownedAnnouncementTails.get(publicKeyHex) === tail) {
        this._ownedAnnouncementTails.delete(publicKeyHex)
      }
    })
    return operation
  }

  async _releaseOwnedAnnouncement (entry) {
    clearInterval(entry.interval)
    entry.interval = null
    if (entry.joined) {
      await this.swarm.leave(entry.topic)
      entry.joined = false
    }
    if (!entry.closed && entry.core !== entry.sourceCore) {
      await entry.core.close()
      entry.closed = true
    }
  }

  async withdrawAuthorityOwnedCore (coreOrKey, handoff) {
    const publicKeyHex = typeof coreOrKey === 'string'
      ? coreOrKey.toLowerCase()
      : (coreOrKey?.key ? b4a.toString(coreOrKey.key, 'hex') : null)
    if (!isValidHexKey(publicKeyHex, 64)) throw new Error('authority-owned core key is invalid')
    return this._queueOwnedAnnouncement(publicKeyHex, async () => {
      const entry = this._ownedAnnouncements.get(publicKeyHex)
      if (!entry) return false
      // Teardown remains possible after mutation admission closes, so compare
      // the opaque lease by identity instead of requiring it to still validate.
      if (!handoff || entry.handoff !== handoff) {
        throw new Error('authority-owned core withdrawal handoff mismatch')
      }
      await this._releaseOwnedAnnouncement(entry)
      this._ownedAnnouncements.delete(publicKeyHex)
      this._emitSafely('unseeded-owned-core', { publicKeyHex, ...entry.descriptor })
      return true
    })
  }

  _emitSafely (event, ...args) {
    let firstError = null
    for (const listener of this.rawListeners(event)) {
      try { listener.apply(this, args) } catch (err) { if (!firstError) firstError = err }
    }
    if (firstError && event !== 'observer-error') {
      for (const listener of this.rawListeners('observer-error')) {
        try { listener.call(this, { event, error: firstError }) } catch (_) {}
      }
    }
    return this.listenerCount(event) > 0
  }

  async _installBoundedDownload (entry, proof) {
    if (!entry || !proof?.coreSnapshot) return false
    if (entry.retiring) {
      entry.retiringDownloads.push({ range: null, snapshot: proof.coreSnapshot })
      proof.coreSnapshot = null
      await this._drainRetiringDownloads(entry)
      return false
    }
    const pinned = this._stableCoreSnapshot(proof.coreSnapshot)
    if (pinned.length !== proof.length || pinned.byteLength !== proof.byteLength || pinned.fork !== proof.fork) {
      throw new Error('bounded core snapshot no longer matches proof')
    }
    await this._drainRetiringDownloads(entry)
    const nextRange = proof.coreSnapshot.download({ start: 0, end: proof.length })
    const previousRange = entry.range
    const previousSnapshot = entry.rangeSnapshot
    entry.range = nextRange
    entry.rangeSnapshot = proof.coreSnapshot
    proof.coreSnapshot = null
    if (previousRange || previousSnapshot) {
      entry.retiringDownloads.push({ range: previousRange, snapshot: previousSnapshot })
      await this._drainRetiringDownloads(entry)
    }
    try {
      Promise.resolve(nextRange.done()).catch(err => {
        if (this.node?.emit) {
          try { this.node.emit('download-error', { key: entry.publicKeyHex, error: err.message }) } catch (_) {}
        }
      })
    } catch (_) {}
    return true
  }

  async _drainRetiringDownloads (entry) {
    if (!Array.isArray(entry.retiringDownloads)) entry.retiringDownloads = []
    for (const owner of [...entry.retiringDownloads]) {
      if (owner.range) {
        if (typeof owner.range.destroy === 'function') await Promise.resolve(owner.range.destroy())
        owner.range = null
      }
      if (owner.snapshot) {
        if (typeof owner.snapshot.close === 'function') await owner.snapshot.close()
        owner.snapshot = null
      }
      const index = entry.retiringDownloads.indexOf(owner)
      if (index !== -1) entry.retiringDownloads.splice(index, 1)
    }
  }

  async _refreshBoundedDownload (entry) {
    if (!entry || entry.retiring || entry.recoveryOnly || !entry.core || entry.core.closed) return false
    if (entry.refreshing) return entry.refreshing
    entry.refreshing = (async () => {
      const core = entry.core
      let proof = null
      try { proof = await this._authoritativeCoreSize(core) } catch (_) { return false }
      if (entry.retiring) {
        if (proof.coreSnapshot) {
          entry.retiringDownloads.push({ range: null, snapshot: proof.coreSnapshot })
          proof.coreSnapshot = null
          await this._drainRetiringDownloads(entry)
        }
        return false
      }
      const { byteLength } = proof
      if (byteLength > entry.maxStorageBytes) {
        if (entry.range || entry.rangeSnapshot) {
          entry.retiringDownloads.push({ range: entry.range, snapshot: entry.rangeSnapshot })
          entry.range = null
          entry.rangeSnapshot = null
        }
        if (proof.coreSnapshot) {
          entry.retiringDownloads.push({ range: null, snapshot: proof.coreSnapshot })
          proof.coreSnapshot = null
        }
        await this._drainRetiringDownloads(entry)
        this._emitSafely('storage-bound-exceeded', {
          publicKeyHex: entry.publicKeyHex,
          byteLength: Number.isSafeInteger(byteLength) ? byteLength : null,
          maxStorageBytes: entry.maxStorageBytes
        })
        return false
      }
      try {
        return await this._installBoundedDownload(entry, proof)
      } finally {
        if (proof.coreSnapshot) {
          entry.retiringDownloads.push({ range: null, snapshot: proof.coreSnapshot })
          proof.coreSnapshot = null
          await this._drainRetiringDownloads(entry)
        }
      }
    })().finally(() => { entry.refreshing = null })
    return entry.refreshing
  }

  // Release a single entry's live resources WITHOUT touching the persisted
  // set. Shared by unseedCore (intentional removal) and stop() (teardown).
  _releaseEntry (entry) {
    if (!entry || entry.released === true) return Promise.resolve()
    if (entry.releasing) return entry.releasing
    const operation = this._releaseEntryOwned(entry).catch(cause => {
      if (cause?.code === 'STORAGE_CORE_TEARDOWN_UNSETTLED' && cause.cause) throw cause
      const failure = new Error('seeded core teardown did not settle')
      failure.code = 'STORAGE_CORE_TEARDOWN_UNSETTLED'
      failure.cause = cause
      throw failure
    })
    entry.releasing = operation
    operation.then(
      () => { if (entry.releasing === operation) entry.releasing = null },
      () => { if (entry.releasing === operation) entry.releasing = null }
    )
    return operation
  }

  async _releaseEntryOwned (entry) {
    if (!entry || entry.released === true) return
    entry.retiring = true
    if (entry.interval) {
      clearInterval(entry.interval)
      entry.interval = null
    }
    for (const [flag, event, listener] of [
      ['downloadListenerAttached', 'download', entry.onDownload],
      ['uploadListenerAttached', 'upload', entry.onUpload],
      ['appendListenerAttached', 'append', entry.onAppend]
    ]) {
      if (!entry[flag]) continue
      if (typeof entry.core.removeListener !== 'function') {
        const err = new Error(`seeded core ${event} listener cannot be removed`)
        err.code = 'STORAGE_CORE_TEARDOWN_UNSETTLED'
        throw err
      }
      entry.core.removeListener(event, listener)
      entry[flag] = false
    }
    if (entry.refreshing) await entry.refreshing
    await this._drainRetiringDownloads(entry)
    if (entry.range) {
      if (typeof entry.range.destroy === 'function') await Promise.resolve(entry.range.destroy())
      entry.range = null
    }
    if (entry.rangeSnapshot) {
      await entry.rangeSnapshot.close()
      entry.rangeSnapshot = null
    }
    if (!entry.left) {
      await this.swarm.leave(entry.topic)
      entry.left = true
    }
    await entry.core.close()
    entry.released = true
  }

  // Intentional unseed: operator no longer wants this core. Removes it from
  // the persisted set so it is NOT re-seeded on the next start.
  async unseedCore (publicKeyHex, opts = {}) {
    if (!isValidHexKey(publicKeyHex, 64)) throw new Error('Invalid core key: must be 64 hex characters')
    publicKeyHex = publicKeyHex.toLowerCase()
    if (!opts[TRACKED_CORE_INVENTORY]) {
      return this._queueInventoryMutation(() => {
        const run = () => this.unseedCore(publicKeyHex, {
          ...opts,
          [TRACKED_CORE_INVENTORY]: true
        })
        return this.storageAdmission?.runKeyMutation
          ? this.storageAdmission.runKeyMutation('core-inventory', run)
          : run()
      })
    }
    if (!opts[TRACKED_STORAGE_REMOVAL] && this.storageAdmission?.runKeyMutation) {
      return this.storageAdmission.runKeyMutation(`core:${publicKeyHex}`, () => this.unseedCore(publicKeyHex, {
        ...opts,
        [TRACKED_STORAGE_REMOVAL]: true
      }))
    }
    const alreadyRetiring = this._retiringCores.has(publicKeyHex)
    const entry = this.cores.get(publicKeyHex) || this._retiringCores.get(publicKeyHex)
    if (!entry) return

    if (!alreadyRetiring) {
      this.cores.delete(publicKeyHex)
      try {
        await this._persist({ throwOnError: true })
      } catch (err) {
        this.cores.set(publicKeyHex, entry)
        throw err
      }
    }

    try {
      await this._releaseEntry(entry)
    } catch (err) {
      this._retiringCores.set(publicKeyHex, entry)
      if (this.storageAdmission) this.storageAdmission.failClosed('storage-core-retirement-settlement-failed')
      throw err
    }
    this._retiringCores.delete(publicKeyHex)
    if (this.storageAdmission && !this.storageAdmission.release(`core:${publicKeyHex}`)) {
      this._retiringCores.set(publicKeyHex, entry)
      this.storageAdmission.failClosed('storage-core-release-failed')
      const err = new Error('storage core commitment release failed')
      err.code = 'STORAGE_CORE_RELEASE_FAILED'
      throw err
    }
    this.totalBytesStored = Math.max(0, this.totalBytesStored - entry.bytesStored)

    this._emitSafely('unseeded-core', { publicKeyHex })
  }

  hasCapacity (additionalBytes = 0) {
    if (this.storageAdmission) return this.storageAdmission.admission(additionalBytes, { refresh: true }).allowed === true
    if (this._canAdopt) {
      const admission = this._canAdopt(additionalBytes)
      return typeof admission === 'boolean' ? admission : !!(admission && admission.allowed)
    }
    return (this.totalBytesStored + additionalBytes) < this.maxStorageBytes
  }

  getStats () {
    return {
      coresSeeded: this.cores.size,
      totalBytesStored: this.totalBytesStored,
      totalBytesServed: this.totalBytesServed,
      capacityUsedPct: this.maxStorageBytes > 0
        ? Math.round((this.totalBytesStored / this.maxStorageBytes) * 100)
        : (this.totalBytesStored > 0 ? 100 : 0)
    }
  }

  stop () {
    this._acceptingSeeds = false
    if (this._stopping) return this._stopping
    const operation = this._queueInventoryMutation(() => this._stop())
    const stopping = operation.finally(() => {
      if (this._stopping === stopping) this._stopping = null
    })
    this._stopping = stopping
    return stopping
  }

  async _stop () {
    this._acceptingSeeds = false
    this.running = false
    let firstError = null
    for (const [key, entry] of [...this._ownedAnnouncements]) {
      try {
        await this._queueOwnedAnnouncement(key, async () => {
          if (this._ownedAnnouncements.get(key) !== entry) return
          await this._releaseOwnedAnnouncement(entry)
          if (this._ownedAnnouncements.get(key) === entry) this._ownedAnnouncements.delete(key)
        })
      } catch (err) {
        if (!firstError) firstError = err
      }
    }
    // Teardown only — release resources but DO NOT mutate the persisted set,
    // so a restart re-seeds exactly what was pinned. (A persisting unseed here
    // would empty the list on every graceful shutdown.)
    for (const [key, entry] of this.cores) {
      try {
        await this._releaseEntry(entry)
        this.cores.delete(key)
      } catch (err) {
        if (!firstError) firstError = err
      }
    }
    for (const [key, entry] of this._retiringCores) {
      try {
        await this._releaseEntry(entry)
        if (this.storageAdmission && !this.storageAdmission.release(`core:${key}`)) {
          this.storageAdmission.failClosed('storage-core-release-failed')
          const err = new Error('storage core commitment release failed')
          err.code = 'STORAGE_CORE_RELEASE_FAILED'
          throw err
        }
        this._retiringCores.delete(key)
      } catch (err) {
        if (!firstError) firstError = err
      }
    }
    if (firstError) throw firstError
    this._emitSafely('stopped')
  }

  // ─── Persistence (atomic tmp+rename) ───────────────────────────────

  _queueInventoryMutation (run) {
    const operation = this._inventoryTail.catch(() => {}).then(run)
    this._inventoryTail = operation.catch(() => {})
    return operation
  }

  async _restorePersisted () {
    let records
    try {
      records = await this._loadPersisted()
    } catch (err) {
      this._emitSafely('recovery-error', { source: 'seeded-cores', error: err && err.message ? err.message : String(err) })
      return false
    }
    this._restoring = true
    let restored = 0
    try {
      for (const record of records) {
        const key = record.key
        const bound = positiveStorageBound(record.maxStorageBytes)
        if (this.storageAdmission) this.storageAdmission.adoptRecovery(`core:${key}`, bound, { kind: 'core' })
        try {
          await this.seedCore(key, {
            maxStorageBytes: bound,
            [TRACKED_CORE_INVENTORY]: true
          })
          restored++
        } catch (err) {
          this._emitSafely('reseed-error', { publicKeyHex: key, error: err && err.message ? err.message : String(err) })
        }
      }
    } finally {
      this._restoring = false
      if (this.storageAdmission) this.storageAdmission.markRecoveryReady('cores')
    }
    if (restored) this._emitSafely('cores-restored', { count: restored })
    return true
  }

  _persist (opts = {}) {
    if (!this._persistPath) {
      if (opts.throwOnError) return Promise.reject(new Error('seeded-core persistence unavailable'))
      return
    }
    const op = this._persistTail.then(() => this._writePersisted())
    this._persistTail = op.catch(() => {})
    return opts.throwOnError ? op : this._persistTail
  }

  async _writePersisted () {
    const tmp = this._persistPath + '.tmp'
    if (this.cores.size > SEEDED_CORE_INVENTORY_MAX_RECORDS) {
      const err = new Error('SEEDED_CORE_INVENTORY_CARDINALITY_EXCEEDED')
      err.code = 'SEEDED_CORE_INVENTORY_CARDINALITY_EXCEEDED'
      throw err
    }
    const data = JSON.stringify({
      schemaVersion: PERSIST_SCHEMA_VERSION,
      cores: Array.from(this.cores.values()).map(entry => ({
        key: entry.publicKeyHex,
        maxStorageBytes: positiveStorageBound(entry.maxStorageBytes),
        state: positiveStorageBound(entry.maxStorageBytes) === null ? 'unknown-recovery' : 'bounded'
      }))
    })
    const dataBytes = b4a.byteLength(data)
    let targetBytes = 0
    try {
      targetBytes = (await stat(this._persistPath)).size
    } catch (err) {
      if (!err || err.code !== 'ENOENT') throw err
    }
    // Atomic replacement temporarily owns both target and tmp. At least one
    // core reservation is still held while the final row is retired, so prove
    // the pair fits inside the aggregate 64 KiB-per-record metadata allowance.
    const metadataSlots = Math.max(1, this.cores.size)
    const metadataBound = metadataSlots * STORAGE_COMMITMENT_METADATA_OVERHEAD_BYTES
    if (!Number.isSafeInteger(metadataBound) || targetBytes + dataBytes > metadataBound) {
      const err = new Error('SEEDED_CORE_INVENTORY_METADATA_EXCEEDED')
      err.code = 'SEEDED_CORE_INVENTORY_METADATA_EXCEEDED'
      err.targetBytes = targetBytes
      err.tmpBytes = dataBytes
      err.maxBytes = metadataBound
      throw err
    }
    try {
      await mkdir(dirname(this._persistPath), { recursive: true })
      await writeFile(tmp, data)
      await rename(tmp, this._persistPath)
    } catch (err) {
      try { await unlink(tmp) } catch (_) {}
      this._emitSafely('persist-error', err)
      throw err
    }
  }

  async _loadPersisted () {
    if (!this._persistPath) return []
    let raw
    try {
      raw = await readFile(this._persistPath, 'utf8')
    } catch (err) {
      if (err && err.code === 'ENOENT') return []
      const failure = new Error('SEEDED_CORE_INVENTORY_READ_FAILED')
      failure.code = 'SEEDED_CORE_INVENTORY_FAILED'
      failure.cause = err
      throw failure
    }
    let data
    try { data = JSON.parse(raw) } catch (err) {
      const failure = new Error('SEEDED_CORE_INVENTORY_CORRUPT')
      failure.code = 'SEEDED_CORE_INVENTORY_FAILED'
      failure.cause = err
      throw failure
    }
    if (!data || typeof data !== 'object' || !Array.isArray(data.cores)) {
      throw Object.assign(new Error('SEEDED_CORE_INVENTORY_UNSUPPORTED'), { code: 'SEEDED_CORE_INVENTORY_FAILED' })
    }
    if (data.cores.length > SEEDED_CORE_INVENTORY_MAX_RECORDS) {
      throw Object.assign(new Error('SEEDED_CORE_INVENTORY_CARDINALITY_EXCEEDED'), { code: 'SEEDED_CORE_INVENTORY_FAILED' })
    }
    if (data.schemaVersion !== 1 && data.schemaVersion !== 2 && data.schemaVersion !== PERSIST_SCHEMA_VERSION) {
      throw Object.assign(new Error('SEEDED_CORE_INVENTORY_UNSUPPORTED'), { code: 'SEEDED_CORE_INVENTORY_FAILED' })
    }

    const seen = new Set()
    const records = []
    for (const value of data.cores) {
      const key = data.schemaVersion === 1 ? value : value?.key
      const keyPattern = data.schemaVersion === 1 ? /^[0-9a-f]{64}$/i : /^[0-9a-f]{64}$/
      if (typeof key !== 'string' || !keyPattern.test(key)) {
        throw Object.assign(new Error('SEEDED_CORE_INVENTORY_INVALID'), { code: 'SEEDED_CORE_INVENTORY_FAILED' })
      }
      let bound = data.schemaVersion === 1 ? null : positiveStorageBound(value.maxStorageBytes)
      if (data.schemaVersion === 2 && value.maxStorageBytes == null) bound = null
      if (data.schemaVersion === 3) {
        if (value.state === 'unknown-recovery' && value.maxStorageBytes == null) bound = null
        else if (value.state !== 'bounded' || bound === null) {
          throw Object.assign(new Error('SEEDED_CORE_INVENTORY_INVALID'), { code: 'SEEDED_CORE_INVENTORY_FAILED' })
        }
      } else if (data.schemaVersion === 2 && value.maxStorageBytes != null && bound === null) {
        throw Object.assign(new Error('SEEDED_CORE_INVENTORY_INVALID'), { code: 'SEEDED_CORE_INVENTORY_FAILED' })
      }
      const normalized = key.toLowerCase()
      if (seen.has(normalized)) {
        throw Object.assign(new Error('SEEDED_CORE_INVENTORY_DUPLICATE'), { code: 'SEEDED_CORE_INVENTORY_FAILED' })
      }
      seen.add(normalized)
      records.push({
        key: normalized,
        maxStorageBytes: bound
      })
    }
    return records
  }
}
