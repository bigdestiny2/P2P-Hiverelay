export const SHARED_FLIGHT_MAX_WAITERS = 32
export const SHARED_FLIGHT_MAX_OWNER_FLIGHTS = 64
export const SHARED_FLIGHT_MAX_PROCESS_FLIGHTS = 1_024

export const RAW_OPERATION_DEFAULT_TIMEOUT_MS = 5_000
export const RAW_OPERATION_MAX_TIMEOUT_MS = 30_000
export const COMPOSITE_OPERATION_DEFAULT_TIMEOUT_MS = 30_000
export const COMPOSITE_OPERATION_MAX_TIMEOUT_MS = 120_000
export const OWNER_DRAIN_DEFAULT_TIMEOUT_MS = 30_000
export const OWNER_DRAIN_MAX_TIMEOUT_MS = 120_000

const NO_OWNER = Object.freeze({ label: 'shared-flight:no-owner' })

export class SharedFlightError extends Error {
  constructor (code, message, details = null) {
    super(message)
    this.name = 'SharedFlightError'
    this.code = code
    this.details = details
    this.stale = code === 'SHARED_FLIGHT_ORPHANED' || code === 'SHARED_FLIGHT_OWNER_INVALIDATED'
    this.busy = code === 'SHARED_FLIGHT_BUSY'
  }
}

export function parseSharedFlightDeadline (value, fallback, maximum, label = 'shared flight timeout') {
  if (value === undefined) return fallback
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${label} must be a positive safe integer`)
  }
  return Math.min(value, maximum)
}

function flightError (code, operation, reason, extra = null) {
  return new SharedFlightError(code, `${operation}: ${reason}`, {
    operation,
    reason,
    ...(extra || {})
  })
}

function ownerIdentity (owner) {
  return owner && (typeof owner === 'object' || typeof owner === 'function') ? owner : NO_OWNER
}

function entityIdentity (entity) {
  if (!entity || (typeof entity !== 'object' && typeof entity !== 'function')) {
    throw new TypeError('shared flight entity must be an object')
  }
  return entity
}

function operationIdentity (operation) {
  if (typeof operation !== 'string' || operation.length < 1 || operation.length > 128) {
    throw new TypeError('shared flight operation must be a non-empty string of at most 128 characters')
  }
  return operation
}

export class SharedFlightRegistry {
  constructor (opts = {}) {
    this.maxWaiters = parseBound(opts.maxWaiters, SHARED_FLIGHT_MAX_WAITERS, 'maxWaiters')
    this.maxOwnerFlights = parseBound(opts.maxOwnerFlights, SHARED_FLIGHT_MAX_OWNER_FLIGHTS, 'maxOwnerFlights')
    this.maxProcessFlights = parseBound(opts.maxProcessFlights, SHARED_FLIGHT_MAX_PROCESS_FLIGHTS, 'maxProcessFlights')
    this._entities = new WeakMap()
    this._owners = new WeakMap()
    this._active = new Set()
    this._stats = {
      started: 0,
      attached: 0,
      settled: 0,
      rejected: 0,
      timeouts: 0,
      orphaned: 0,
      overflow: 0,
      lateSuppressed: 0,
      closeReleased: 0,
      ownerInvalidations: 0,
      drainTimeouts: 0
    }
  }

  run (entity, operation, start, opts = {}) {
    entity = entityIdentity(entity)
    operation = operationIdentity(operation)
    if (typeof start !== 'function') throw new TypeError('shared flight start must be a function')
    const timeoutMs = parseSharedFlightDeadline(
      opts.timeoutMs,
      opts.defaultTimeoutMs ?? RAW_OPERATION_DEFAULT_TIMEOUT_MS,
      opts.maxTimeoutMs ?? RAW_OPERATION_MAX_TIMEOUT_MS,
      `${operation} timeout`
    )
    const owner = this._owner(ownerIdentity(opts.owner))
    if (!owner.accepting) {
      return Promise.reject(flightError(
        'SHARED_FLIGHT_OWNER_INVALIDATED', operation, 'owner is not accepting new work'
      ))
    }

    let operations = this._entities.get(entity)
    let record = operations && operations.get(operation)
    if (record) {
      if (record.orphaned) {
        return Promise.reject(flightError(
          'SHARED_FLIGHT_ORPHANED', operation,
          'underlying operation is unresolved after a waiter timeout'
        ))
      }
    } else {
      if (this._active.size >= this.maxProcessFlights) {
        this._stats.overflow++
        return Promise.reject(flightError(
          'SHARED_FLIGHT_BUSY', operation, 'process flight limit reached',
          { limit: this.maxProcessFlights }
        ))
      }
      if (owner.flights.size >= this.maxOwnerFlights) {
        this._stats.overflow++
        return Promise.reject(flightError(
          'SHARED_FLIGHT_BUSY', operation, 'owner flight limit reached',
          { limit: this.maxOwnerFlights }
        ))
      }
      if (!operations) {
        operations = new Map()
        this._entities.set(entity, operations)
      }
      record = this._createRecord(entity, operations, operation, start)
      operations.set(operation, record)
    }

    if (record.waiters.size >= this.maxWaiters) {
      this._stats.overflow++
      return Promise.reject(flightError(
        'SHARED_FLIGHT_BUSY', operation, 'waiter limit reached',
        { limit: this.maxWaiters }
      ))
    }
    if (!owner.flights.has(record) && owner.flights.size >= this.maxOwnerFlights) {
      this._stats.overflow++
      return Promise.reject(flightError(
        'SHARED_FLIGHT_BUSY', operation, 'owner flight limit reached',
        { limit: this.maxOwnerFlights }
      ))
    }
    return this._attach(record, owner, timeoutMs)
  }

  invalidateOwner (identity, opts = {}) {
    const state = this._owners.get(ownerIdentity(identity))
    if (!state) return 0
    state.generation++
    if (opts.retire === true) state.accepting = false
    this._stats.ownerInvalidations++
    return state.generation
  }

  activateOwner (identity) {
    const state = this._owner(ownerIdentity(identity))
    state.generation++
    state.accepting = true
    return state.generation
  }

  async drainOwner (identity, opts = {}) {
    const state = this._owners.get(ownerIdentity(identity))
    if (!state || state.flights.size === 0) return true
    const timeoutMs = parseSharedFlightDeadline(
      opts.timeoutMs,
      OWNER_DRAIN_DEFAULT_TIMEOUT_MS,
      OWNER_DRAIN_MAX_TIMEOUT_MS,
      'owner drain timeout'
    )
    let timer = null
    try {
      await Promise.race([
        Promise.allSettled([...state.flights].map(record => record.rawSettled)),
        new Promise((_resolve, reject) => {
          timer = setTimeout(() => {
            this._stats.drainTimeouts++
            reject(flightError(
              'SHARED_FLIGHT_DRAIN_TIMEOUT', 'owner.drain',
              'owned flights did not truly settle', { timeoutMs }
            ))
          }, timeoutMs)
        })
      ])
      return true
    } finally {
      if (timer) clearTimeout(timer)
    }
  }

  closeEntity (entity, reason = 'proved close completion') {
    entity = entityIdentity(entity)
    const operations = this._entities.get(entity)
    if (!operations) return 0
    let released = 0
    for (const record of [...operations.values()]) {
      if (record.terminal) continue
      released++
      this._terminalize(record, flightError(
        'SHARED_FLIGHT_ENTITY_CLOSED', record.operation, reason
      ), true)
    }
    this._entities.delete(entity)
    return released
  }

  getStats (identity = null) {
    let waiters = 0
    let orphanedPending = 0
    for (const record of this._active) {
      waiters += record.waiters.size
      if (record.orphaned) orphanedPending++
    }
    const state = identity === null ? null : this._owners.get(ownerIdentity(identity))
    return {
      pending: this._active.size,
      waiters,
      orphanedPending,
      ...this._stats,
      owner: state
        ? {
            generation: state.generation,
            accepting: state.accepting,
            activeFlights: state.flights.size
          }
        : null
    }
  }

  _owner (identity) {
    let state = this._owners.get(identity)
    if (!state) {
      state = { identity, generation: 0, accepting: true, flights: new Set() }
      this._owners.set(identity, state)
    }
    return state
  }

  _createRecord (entity, operations, operation, start) {
    let settleRaw
    const rawSettled = new Promise(resolve => { settleRaw = resolve })
    const record = {
      entity,
      operations,
      operation,
      waiters: new Set(),
      owners: new Set(),
      orphaned: false,
      terminal: false,
      rawSettled,
      settleRaw
    }
    this._active.add(record)
    this._stats.started++
    Promise.resolve().then(start).then(
      value => this._settle(record, null, value),
      error => this._settle(record, error)
    )
    return record
  }

  _attach (record, owner, timeoutMs) {
    if (!owner.flights.has(record)) {
      owner.flights.add(record)
      record.owners.add(owner)
    }
    const generation = owner.generation
    this._stats.attached++
    return new Promise((resolve, reject) => {
      const waiter = { owner, generation, resolve, reject, timer: null, settled: false }
      record.waiters.add(waiter)
      waiter.timer = setTimeout(() => {
        if (!this._finishWaiter(record, waiter)) return
        this._stats.timeouts++
        if (!record.orphaned) {
          record.orphaned = true
          this._stats.orphaned++
        }
        reject(flightError(
          'SHARED_FLIGHT_TIMEOUT', record.operation,
          'waiter deadline elapsed; unresolved raw flight is now orphaned',
          { timeoutMs }
        ))
      }, timeoutMs)
    })
  }

  _settle (record, error, value) {
    if (record.terminal) {
      this._stats.lateSuppressed++
      record.settleRaw()
      return
    }
    this._stats.settled++
    if (error) this._stats.rejected++
    for (const waiter of [...record.waiters]) {
      if (!this._finishWaiter(record, waiter)) continue
      if (waiter.owner.generation !== waiter.generation || !waiter.owner.accepting) {
        this._stats.lateSuppressed++
        waiter.reject(flightError(
          'SHARED_FLIGHT_OWNER_INVALIDATED', record.operation,
          'result belongs to an invalid owner generation'
        ))
      } else if (error) {
        waiter.reject(error)
      } else {
        waiter.resolve(value)
      }
    }
    this._terminalize(record, null, false)
    record.settleRaw()
  }

  _finishWaiter (record, waiter) {
    if (waiter.settled) return false
    waiter.settled = true
    if (waiter.timer) clearTimeout(waiter.timer)
    waiter.timer = null
    record.waiters.delete(waiter)
    return true
  }

  _terminalize (record, error, closeReleased) {
    if (record.terminal) return
    record.terminal = true
    if (closeReleased) {
      this._stats.closeReleased++
      for (const waiter of [...record.waiters]) {
        if (!this._finishWaiter(record, waiter)) continue
        waiter.reject(error)
      }
      record.settleRaw()
    }
    record.operations.delete(record.operation)
    this._active.delete(record)
    for (const owner of record.owners) owner.flights.delete(record)
    record.owners.clear()
    record.entity = null
    record.operations = null
  }
}

function parseBound (value, maximum, label) {
  if (value === undefined) return maximum
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${label} must be a positive safe integer`)
  }
  return Math.min(value, maximum)
}

export const sharedOperationFlights = new SharedFlightRegistry()

export function sharedCoreInfo (core, opts = {}) {
  if (!core || typeof core.info !== 'function') {
    return Promise.reject(flightError(
      'SHARED_FLIGHT_UNAVAILABLE', 'core.info.storage', 'core.info is unavailable'
    ))
  }
  return sharedOperationFlights.run(
    core,
    'core.info.storage',
    () => core.info({ storage: true }),
    {
      owner: opts.owner ?? core,
      timeoutMs: opts.timeoutMs,
      defaultTimeoutMs: RAW_OPERATION_DEFAULT_TIMEOUT_MS,
      maxTimeoutMs: RAW_OPERATION_MAX_TIMEOUT_MS
    }
  )
}

export function sharedGetBlobs (drive, opts = {}) {
  if (!drive || typeof drive.getBlobs !== 'function') {
    return Promise.reject(flightError(
      'SHARED_FLIGHT_UNAVAILABLE', 'drive.getBlobs', 'drive.getBlobs is unavailable'
    ))
  }
  const entity = drive.core || drive.db?.core || drive
  return sharedOperationFlights.run(
    entity,
    'drive.getBlobs',
    () => drive.getBlobs(),
    {
      owner: opts.owner ?? drive,
      timeoutMs: opts.timeoutMs,
      defaultTimeoutMs: RAW_OPERATION_DEFAULT_TIMEOUT_MS,
      maxTimeoutMs: RAW_OPERATION_MAX_TIMEOUT_MS
    }
  )
}

export function sharedBlobHas (blobCore, start, length, opts = {}) {
  if (!blobCore || typeof blobCore.has !== 'function') {
    return Promise.reject(flightError(
      'SHARED_FLIGHT_UNAVAILABLE', 'blobCore.has', 'blobCore.has is unavailable'
    ))
  }
  if (!Number.isSafeInteger(start) || start < 0 ||
      !Number.isSafeInteger(length) || length < 0 ||
      !Number.isSafeInteger(start + length)) {
    throw new TypeError('blobCore.has range must contain bounded nonnegative safe integers')
  }
  const operation = `blobCore.has.${start}.${length}`
  return sharedOperationFlights.run(
    blobCore,
    operation,
    () => blobCore.has(start, length),
    {
      owner: opts.owner ?? blobCore,
      timeoutMs: opts.timeoutMs,
      defaultTimeoutMs: COMPOSITE_OPERATION_DEFAULT_TIMEOUT_MS,
      maxTimeoutMs: COMPOSITE_OPERATION_MAX_TIMEOUT_MS
    }
  )
}

export function closeSharedDriveEntity (drive, reason) {
  if (!drive) return 0
  return sharedOperationFlights.closeEntity(drive.core || drive.db?.core || drive, reason)
}
