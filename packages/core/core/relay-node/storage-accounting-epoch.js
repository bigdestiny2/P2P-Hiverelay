import { lstat as fsLstat, opendir as fsOpendir } from 'fs/promises'
import { join } from 'path'
import b4a from 'b4a'

const MIB = 1024 * 1024
const PATH_RECORD_OVERHEAD_BYTES = 256
const FRAME_OVERHEAD_BYTES = 256
const IDENTITY_RECORD_OVERHEAD_BYTES = 64

export const STORAGE_ACCOUNTING_EPOCH_HARD_LIMITS = Object.freeze({
  operationCap: 800_000,
  cleanupReserve: 129,
  ordinaryOperationLimit: 799_871,
  normalDeadlineMs: 28_800_000,
  cleanupDeadlineMs: 900_000,
  operationsPerSecond: 32,
  javascriptSliceMs: 10,
  maxOpenDirectories: 64,
  maxPathBytes: 4096,
  maxDepth: 256,
  maxQueuedPathBytes: 32 * MIB,
  maxBookkeepingBytes: 64 * MIB,
  maxEntries: 250_000,
  maxDirectories: 50_000
})

function positiveSafeInteger (value, name) {
  if (typeof value !== 'number' || !Number.isFinite(value) ||
      !Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${name} must be a positive safe integer number`)
  }
  return value
}

function boundedOption (options, name, hardMaximum) {
  if (!Object.prototype.hasOwnProperty.call(options, name) || options[name] === undefined) {
    return hardMaximum
  }
  return Math.min(positiveSafeInteger(options[name], name), hardMaximum)
}

export function parseStorageAccountingEpochLimits (options = {}) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    throw new TypeError('storage accounting epoch limits must be an object')
  }
  const hard = STORAGE_ACCOUNTING_EPOCH_HARD_LIMITS
  return Object.freeze({
    operationCap: hard.operationCap,
    cleanupReserve: hard.cleanupReserve,
    ordinaryOperationLimit: hard.ordinaryOperationLimit,
    normalDeadlineMs: hard.normalDeadlineMs,
    cleanupDeadlineMs: hard.cleanupDeadlineMs,
    operationsPerSecond: boundedOption(options, 'operationsPerSecond', hard.operationsPerSecond),
    javascriptSliceMs: boundedOption(options, 'javascriptSliceMs', hard.javascriptSliceMs),
    maxOpenDirectories: boundedOption(options, 'maxOpenDirectories', hard.maxOpenDirectories),
    maxPathBytes: boundedOption(options, 'maxPathBytes', hard.maxPathBytes),
    maxDepth: boundedOption(options, 'maxDepth', hard.maxDepth),
    maxQueuedPathBytes: boundedOption(options, 'maxQueuedPathBytes', hard.maxQueuedPathBytes),
    maxBookkeepingBytes: boundedOption(options, 'maxBookkeepingBytes', hard.maxBookkeepingBytes),
    maxEntries: boundedOption(options, 'maxEntries', hard.maxEntries),
    maxDirectories: boundedOption(options, 'maxDirectories', hard.maxDirectories)
  })
}

class StorageAccountingEpochError extends Error {
  constructor (code, message) {
    super(message)
    this.code = code
  }
}

function operationLimitError (phase) {
  return new StorageAccountingEpochError(
    'EACCOUNTINGOPERATIONS',
    `storage accounting ${phase} operation limit exceeded`
  )
}

export class StorageAccountingOperationBudget {
  constructor () {
    this.ordinary = 0
    this.cleanup = 0
  }

  chargeOrdinary () {
    if (this.ordinary >= STORAGE_ACCOUNTING_EPOCH_HARD_LIMITS.ordinaryOperationLimit) {
      throw operationLimitError('ordinary')
    }
    this.ordinary++
    return this.ordinary
  }

  chargeCleanup () {
    if (this.cleanup >= STORAGE_ACCOUNTING_EPOCH_HARD_LIMITS.cleanupReserve) {
      throw operationLimitError('cleanup')
    }
    this.cleanup++
    return this.cleanup
  }

  snapshot () {
    return Object.freeze({
      ordinary: this.ordinary,
      cleanup: this.cleanup,
      total: this.ordinary + this.cleanup,
      ordinaryLimit: STORAGE_ACCOUNTING_EPOCH_HARD_LIMITS.ordinaryOperationLimit,
      cleanupLimit: STORAGE_ACCOUNTING_EPOCH_HARD_LIMITS.cleanupReserve,
      totalLimit: STORAGE_ACCOUNTING_EPOCH_HARD_LIMITS.operationCap
    })
  }
}

function defaultClock () {
  return {
    now: () => Date.now(),
    sleep: (ms) => new Promise(resolve => setTimeout(resolve, ms)),
    setTimeout: (fn, ms) => setTimeout(fn, ms),
    clearTimeout: (timer) => clearTimeout(timer)
  }
}

function normalizedClock (clock) {
  const source = clock || defaultClock()
  for (const name of ['now', 'sleep', 'setTimeout', 'clearTimeout']) {
    if (typeof source[name] !== 'function') {
      throw new TypeError(`storage accounting clock.${name} must be a function`)
    }
  }
  return {
    now: source.now.bind(source),
    sleep: source.sleep.bind(source),
    setTimeout: source.setTimeout.bind(source),
    clearTimeout: source.clearTimeout.bind(source)
  }
}

function normalizedFs (fs) {
  const source = fs || { lstat: fsLstat, opendir: fsOpendir }
  if (typeof source.lstat !== 'function' || typeof source.opendir !== 'function') {
    throw new TypeError('storage accounting fs must provide lstat and opendir functions')
  }
  return {
    lstat: source.lstat.bind(source),
    opendir: source.opendir.bind(source)
  }
}

function deepFreeze (value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value
  for (const item of Object.values(value)) deepFreeze(item)
  return Object.freeze(value)
}

function boundedMessage (value) {
  const text = typeof value === 'string' ? value : String(value || 'storage accounting epoch failed')
  return text.length <= 512 ? text : text.slice(0, 512)
}

function epochError (err, operation = null) {
  if (err instanceof StorageAccountingEpochError) return err
  const rawCode = err && typeof err.code === 'string' && err.code ? err.code : 'EACCOUNTINGIO'
  const detail = err && err.message ? err.message : String(err || 'unknown filesystem error')
  return new StorageAccountingEpochError(
    rawCode,
    boundedMessage(operation ? `${operation}: ${detail}` : detail)
  )
}

function identityPart (value, field) {
  if (typeof value === 'bigint' && value >= 0n) {
    const text = value.toString(10)
    if (text.length <= 32) return text
  }
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) {
    return String(value)
  }
  throw new StorageAccountingEpochError(
    'EACCOUNTINGIDENTITY',
    `storage accounting ${field} is not a nonnegative filesystem identity`
  )
}

function statShape (stat) {
  if (!stat || typeof stat !== 'object') {
    throw new StorageAccountingEpochError('EACCOUNTINGSTAT', 'storage accounting received invalid stat metadata')
  }
  const symlink = typeof stat.isSymbolicLink === 'function' && stat.isSymbolicLink()
  const directory = typeof stat.isDirectory === 'function' && stat.isDirectory()
  const file = typeof stat.isFile === 'function' && stat.isFile()
  return {
    dev: identityPart(stat.dev, 'device'),
    ino: identityPart(stat.ino, 'inode'),
    symlink,
    directory,
    file,
    stat
  }
}

function allocatedBytes (stat) {
  if (stat.blocks !== undefined && stat.blocks !== null) {
    if (!Number.isSafeInteger(stat.blocks) || stat.blocks < 0) {
      throw new StorageAccountingEpochError('EACCOUNTINGINTEGER', 'storage accounting blocks is not a nonnegative safe integer')
    }
    const bytes = stat.blocks * 512
    if (!Number.isSafeInteger(bytes)) {
      throw new StorageAccountingEpochError('EACCOUNTINGINTEGER', 'storage accounting allocated byte count overflowed')
    }
    return bytes
  }
  if (!Number.isSafeInteger(stat.size) || stat.size < 0) {
    throw new StorageAccountingEpochError('EACCOUNTINGINTEGER', 'storage accounting size is not a nonnegative safe integer')
  }
  return stat.size
}

function vanishedEntry (err) {
  return err && (err.code === 'ENOENT' || err.code === 'ENOTDIR')
}

function pathBytes (path) {
  return b4a.byteLength(path, 'utf8')
}

export class StorageAccountingEpoch {
  constructor (storagePath, options = {}) {
    if (typeof storagePath !== 'string' || storagePath.length === 0) {
      throw new TypeError('storage accounting storagePath must be a nonempty string')
    }
    if (!options || typeof options !== 'object' || Array.isArray(options)) {
      throw new TypeError('storage accounting epoch options must be an object')
    }

    this.storagePath = storagePath
    this.fs = normalizedFs(options.fs)
    this.clock = normalizedClock(options.clock)
    this.limits = parseStorageAccountingEpochLimits(options.limits)
    this.onProgress = typeof options.onProgress === 'function' ? options.onProgress : null
    this.canRetryClose = typeof options.canRetryClose === 'function'
      ? options.canRetryClose
      : () => false

    this.budget = new StorageAccountingOperationBudget()
    this.state = 'idle'
    this.entries = 0
    this.directories = 0
    this.bytes = 0
    this._frames = []
    this._deferred = []
    this._reservedRecords = new Set()
    this._visited = new Set()
    this._visitedBookkeepingBytes = 0
    this._queuedPathBytes = 0
    this._bookkeepingBytes = 0
    this._peakOpenDirectories = 0
    this._peakQueuedPaths = 0
    this._peakQueuedPathBytes = 0
    this._peakBookkeepingBytes = 0
    this._peakOperationsInFlight = 0
    this._operationsInFlight = 0
    this._cursor = null
    this._rootIdentity = null
    this._lastOperationStartedAt = null
    this._jsSliceStartedAt = null
    this._jsUsedMs = 0
    this._normalTimer = null
    this._cleanupTimer = null
    this._normalFenceWaiters = new Set()
    this._cleanupFenceWaiters = new Set()
    this._cleanupFencePromise = new Promise(resolve => { this._resolveCleanupFence = resolve })
    this._inFlightSettlements = new Set()
    this._lateResourceDisposals = new Set()
    this._unreleasedLateResources = 0
    this._lateDisposalError = null
    this._normalDeadlineAt = null
    this._cleanupDeadlineAt = null
    this._fence = null
    this._primaryError = null
    this._cleanupExpired = false
    this._stopRequested = false
    this._runPromise = null
    this._result = null
    this.observedAt = null
  }

  run () {
    if (!this._runPromise) this._runPromise = this._run()
    return this._runPromise
  }

  stop () {
    this._stopRequested = true
    if (this.observedAt !== null && !this._fence) {
      const err = new StorageAccountingEpochError('EACCOUNTINGSTOPPED', 'storage accounting epoch stopped')
      this._installFence('stopped', err, this._now())
    }
    return this.run()
  }

  getProgress () {
    return deepFreeze(this._progressSnapshot())
  }

  async _run () {
    this.observedAt = this._now()
    this._jsSliceStartedAt = this.observedAt
    this._normalDeadlineAt = this._safeAdd(this.observedAt, this.limits.normalDeadlineMs)
    this.state = 'running'
    this._armNormalDeadline()

    try {
      if (this._stopRequested) {
        throw new StorageAccountingEpochError('EACCOUNTINGSTOPPED', 'storage accounting epoch stopped')
      }
      await this._traverse()
      this._assertNotFenced()
      this._installFence('success', null, this._now())
    } catch (err) {
      const normalized = epochError(err)
      if (!this._primaryError) this._primaryError = normalized
      if (!this._fence) this._installFence('failure', normalized, this._now())
    }

    await this._cleanup()
    return this._finish()
  }

  async _traverse () {
    const root = this._newRecord(this.storagePath, 0)
    this._reserveRecord(root)
    let rootStat
    try {
      rootStat = await this._ordinaryOperation('initial root identity', () => this.fs.lstat(root.path))
    } catch (err) {
      throw epochError(err, 'initial root identity')
    }
    this._assertNotFenced()

    root.identity = await this._js(() => this._validateRoot(rootStat))
    this._rootIdentity = root.identity
    this._rememberIdentity(root.identity)
    await this._openRecord(root, { root: true, reserved: true })

    while (this._frames.length > 0 || this._deferred.length > 0) {
      this._assertNotFenced()

      if (this._deferred.length > 0 && this._frames.length < this.limits.maxOpenDirectories) {
        const record = this._deferred[this._deferred.length - 1]
        await this._openRecord(record, { queued: true })
        continue
      }

      const frame = this._frames[this._frames.length - 1]
      this._cursor = { path: frame.path, depth: frame.depth }
      let entry
      try {
        entry = await this._ordinaryOperation('directory read', () => frame.dir.read())
      } catch (err) {
        throw epochError(err, 'directory read')
      }

      if (entry === null) {
        this._assertNotFenced()
        let finalStat
        try {
          finalStat = await this._ordinaryOperation('post-directory identity', () => this.fs.lstat(frame.path))
        } catch (err) {
          throw epochError(err, 'post-directory identity')
        }
        this._assertNotFenced()
        await this._js(() => this._validateDirectoryIdentity(finalStat, frame.identity))
        try {
          await this._ordinaryOperation(
            'normal directory close',
            () => frame.dir.close(),
            { onLateSuccess: () => this._releaseFrame(frame) }
          )
        } catch (err) {
          throw epochError(err, 'normal directory close')
        }
        this._releaseFrame(frame)
        continue
      }

      this.entries++
      if (this.entries > this.limits.maxEntries) {
        throw new StorageAccountingEpochError('EACCOUNTINGENTRIES', 'storage accounting entry limit exceeded')
      }
      this._assertNotFenced()
      await this._processEntry(frame, entry)
    }
  }

  async _processEntry (frame, entry) {
    if (!entry || typeof entry.name !== 'string' || entry.name.length === 0) {
      throw new StorageAccountingEpochError('EACCOUNTINGDIRENT', 'storage accounting received an invalid directory entry')
    }
    const depth = frame.depth + 1
    if (depth > this.limits.maxDepth) {
      throw new StorageAccountingEpochError('EACCOUNTINGDEPTH', 'storage accounting path depth limit exceeded')
    }
    const childPath = await this._js(() => join(frame.path, entry.name))
    const record = this._newRecord(childPath, depth)
    this._reserveRecord(record)

    let childStat
    try {
      childStat = await this._ordinaryOperation('entry identity', () => this.fs.lstat(record.path))
    } catch (err) {
      if (vanishedEntry(err)) {
        this._releaseRecord(record)
        return
      }
      this._releaseRecord(record)
      throw epochError(err, 'entry identity')
    }
    this._assertNotFenced()

    let shape
    try {
      shape = await this._js(() => this._validateEntry(childStat))
    } catch (err) {
      this._releaseRecord(record)
      throw err
    }
    record.identity = { dev: shape.dev, ino: shape.ino }

    if (shape.file) {
      let allocated
      try {
        allocated = await this._js(() => allocatedBytes(shape.stat))
      } finally {
        this._releaseRecord(record)
      }
      const total = this.bytes + allocated
      if (!Number.isSafeInteger(total)) {
        throw new StorageAccountingEpochError('EACCOUNTINGINTEGER', 'storage accounting byte total overflowed')
      }
      this.bytes = total
      return
    }

    if (!shape.directory) {
      this._releaseRecord(record)
      throw new StorageAccountingEpochError('EACCOUNTINGTYPE', 'storage accounting encountered an unsupported entry type')
    }

    const identityKey = this._identityKey(record.identity)
    if (this._visited.has(identityKey)) {
      this._releaseRecord(record)
      return
    }
    this._rememberIdentity(record.identity)

    if (this.directories >= this.limits.maxDirectories) {
      this._releaseRecord(record)
      throw new StorageAccountingEpochError('EACCOUNTINGDIRECTORIES', 'storage accounting directory limit exceeded')
    }

    if (this._frames.length >= this.limits.maxOpenDirectories) {
      this._enqueueRecord(record)
      return
    }
    await this._openRecord(record, { reserved: true })
  }

  async _openRecord (record, { root = false, queued = false, reserved = false } = {}) {
    if (this.directories >= this.limits.maxDirectories) {
      if (queued) this._removeQueuedRecord(record)
      else if (reserved) this._releaseRecord(record)
      throw new StorageAccountingEpochError('EACCOUNTINGDIRECTORIES', 'storage accounting directory limit exceeded')
    }

    const extraFrameBytes = FRAME_OVERHEAD_BYTES
    if (this._bookkeepingBytes + extraFrameBytes > this.limits.maxBookkeepingBytes) {
      if (queued) this._removeQueuedRecord(record)
      else if (reserved) this._releaseRecord(record)
      throw new StorageAccountingEpochError('EACCOUNTINGBOOKKEEPING', 'storage accounting bookkeeping limit exceeded')
    }

    let dir
    try {
      dir = await this._ordinaryOperation(
        'directory open',
        () => this.fs.opendir(record.path, { bufferSize: 1 }),
        { disposeLateResult: value => this._disposeLateDirectory(value) }
      )
    } catch (err) {
      if (!root && err && err.code === 'ENOENT') {
        if (queued) this._removeQueuedRecord(record)
        else if (reserved) this._releaseRecord(record)
        return false
      }
      if (queued) this._removeQueuedRecord(record)
      else if (reserved) this._releaseRecord(record)
      throw epochError(err, 'directory open')
    }

    if (!dir || typeof dir.read !== 'function' || typeof dir.close !== 'function') {
      if (queued) this._removeQueuedRecord(record)
      else if (reserved) this._releaseRecord(record)
      throw new StorageAccountingEpochError('EACCOUNTINGDIR', 'storage accounting opendir returned an invalid handle')
    }

    if (queued) this._removeQueuedRecord(record, { release: false })
    const frame = {
      path: record.path,
      pathBytes: record.pathBytes,
      depth: record.depth,
      identity: record.identity,
      bookkeepingBytes: record.bookkeepingBytes + FRAME_OVERHEAD_BYTES,
      dir,
      cleanupAttempts: 0
    }
    this._bookkeepingBytes += FRAME_OVERHEAD_BYTES
    this._frames.push(frame)
    record.reserved = false
    this._reservedRecords.delete(record)
    this.directories++
    this._updatePeaks()
    return true
  }

  async _cleanup () {
    this.state = 'cleanup'
    if (this._inFlightSettlements.size > 0) {
      const settled = await Promise.race([
        Promise.allSettled([...this._inFlightSettlements]).then(() => true),
        this._cleanupFencePromise.then(() => false)
      ])
      if (!settled) this._cleanupExpired = true
    }
    for (const frame of [...this._frames].reverse()) {
      if (this._cleanupExpired) break
      let closed = false
      for (let attempt = 0; attempt < 2; attempt++) {
        if (this._cleanupExpired || this._now() >= this._cleanupDeadlineAt) {
          this._cleanupExpired = true
          break
        }
        frame.cleanupAttempts++
        try {
          await this._cleanupOperation('cleanup directory close', () => frame.dir.close())
          if (this._cleanupExpired) break
          closed = true
          break
        } catch (err) {
          if (!this._primaryError) this._primaryError = epochError(err, 'cleanup directory close')
          if (attempt === 0 && !this.canRetryClose(frame.dir, err)) break
        }
      }
      if (closed) this._releaseFrame(frame)
    }

    while (this._deferred.length > 0) {
      this._removeQueuedRecord(this._deferred[this._deferred.length - 1])
    }
    for (const record of [...this._reservedRecords]) this._releaseRecord(record)
    this._visited.clear()
    this._bookkeepingBytes -= this._visitedBookkeepingBytes
    this._visitedBookkeepingBytes = 0

    const canComplete = this._fence && this._fence.kind === 'success' &&
      !this._stopRequested && !this._cleanupExpired && this._frames.length === 0 &&
      this._unreleasedLateResources === 0 && !this._lateDisposalError
    if (canComplete) {
      let terminalStat
      try {
        terminalStat = await this._cleanupOperation('terminal root identity', () => this.fs.lstat(this.storagePath))
        if (this._cleanupExpired) {
          throw new StorageAccountingEpochError('EACCOUNTINGCLEANUPDEADLINE', 'storage accounting cleanup deadline exceeded')
        }
        await this._js(() => this._validateDirectoryIdentity(terminalStat, this._rootIdentity))
      } catch (err) {
        if (!this._primaryError) this._primaryError = epochError(err, 'terminal root identity')
      }
    }

    if (this._cleanupTimer !== null) {
      this.clock.clearTimeout(this._cleanupTimer)
      this._cleanupTimer = null
    }
  }

  _finish () {
    if (this._normalTimer !== null) {
      this.clock.clearTimeout(this._normalTimer)
      this._normalTimer = null
    }
    const finishedAt = this._now()
    const complete = this._fence && this._fence.kind === 'success' &&
      !this._stopRequested && !this._cleanupExpired &&
      this._frames.length === 0 && this._unreleasedLateResources === 0 &&
      !this._lateDisposalError && !this._primaryError
    const failedDrain = this._frames.length > 0 || this._cleanupExpired ||
      this._unreleasedLateResources > 0 || !!this._lateDisposalError
    this.state = complete ? 'complete' : (failedDrain ? 'failed-drain' : 'incomplete')

    const operations = this.budget.snapshot()
    const progress = this._progressSnapshot()
    if (complete) {
      this._result = deepFreeze({
        complete: true,
        bytes: this.bytes,
        observedAt: this.observedAt,
        completedAt: finishedAt,
        durationMs: this._duration(this.observedAt, finishedAt),
        incompleteReason: null,
        error: null,
        progress,
        operations
      })
    } else {
      const error = this._lateDisposalError || this._primaryError || new StorageAccountingEpochError(
        this._cleanupExpired ? 'EACCOUNTINGCLEANUPDEADLINE' : 'EACCOUNTINGINCOMPLETE',
        this._cleanupExpired
          ? 'storage accounting cleanup deadline exceeded'
          : 'storage accounting epoch incomplete'
      )
      this._result = deepFreeze({
        complete: false,
        bytes: null,
        observedAt: this.observedAt,
        completedAt: null,
        finishedAt,
        durationMs: this._duration(this.observedAt, finishedAt),
        incompleteReason: error.code,
        error: { code: error.code, message: boundedMessage(error.message) },
        progress,
        operations,
        failedDrain
      })
    }

    this._notifyProgress()
    return this._result
  }

  async _ordinaryOperation (label, operation, options) {
    return this._operation('ordinary', label, operation, options)
  }

  async _cleanupOperation (label, operation) {
    return this._operation('cleanup', label, operation)
  }

  async _operation (phase, label, operation, options = {}) {
    await this._respectJsBudget()
    await this._paceOperations()
    const now = this._now()
    if (phase === 'ordinary') {
      if (this._fence || now >= this._normalDeadlineAt) {
        if (!this._fence) {
          const err = new StorageAccountingEpochError('EACCOUNTINGDEADLINE', 'storage accounting normal deadline exceeded')
          this._installFence('deadline', err, this._normalDeadlineAt)
        }
        this._assertNotFenced()
      }
      this.budget.chargeOrdinary()
    } else {
      if (!this._fence) throw new StorageAccountingEpochError('EACCOUNTINGPHASE', 'cleanup operation began before the epoch fence')
      if (this._cleanupExpired || now >= this._cleanupDeadlineAt) {
        this._cleanupExpired = true
        throw new StorageAccountingEpochError('EACCOUNTINGCLEANUPDEADLINE', 'storage accounting cleanup deadline exceeded')
      }
      this.budget.chargeCleanup()
    }

    this._lastOperationStartedAt = now
    this._operationsInFlight++
    this._peakOperationsInFlight = Math.max(this._peakOperationsInFlight, this._operationsInFlight)
    const outcome = Promise.resolve().then(operation).then(
      value => ({ settled: true, value }),
      error => ({ settled: true, error: epochError(error, label) })
    )
    const rawSettled = outcome.then(() => {
      this._operationsInFlight--
      this._inFlightSettlements.delete(rawSettled)
    })
    this._inFlightSettlements.add(rawSettled)
    const result = await this._waitForOperation(outcome, phase)
    if (!result.settled) {
      if (typeof options.disposeLateResult === 'function') {
        this._ownLateResult(outcome, label, options.disposeLateResult)
      }
      if (typeof options.onLateSuccess === 'function') {
        this._ownLateSuccess(outcome, label, options.onLateSuccess)
      }
      if (phase === 'ordinary') {
        throw this._primaryError || new StorageAccountingEpochError(
          'EACCOUNTINGDEADLINE',
          'storage accounting normal deadline exceeded'
        )
      }
      this._cleanupExpired = true
      throw new StorageAccountingEpochError(
        'EACCOUNTINGCLEANUPDEADLINE',
        'storage accounting cleanup deadline exceeded'
      )
    }
    if (result.error) throw result.error
    return result.value
  }

  _waitForOperation (outcome, phase) {
    const waiters = phase === 'ordinary' ? this._normalFenceWaiters : this._cleanupFenceWaiters
    // A shared pending promise keeps every losing Promise.race reaction until
    // the epoch ends. Subscribe only while this operation is being awaited.
    return new Promise(resolve => {
      const onFence = () => {
        waiters.delete(onFence)
        resolve({ settled: false })
      }
      waiters.add(onFence)
      outcome.then(result => {
        waiters.delete(onFence)
        resolve(result)
      })
    })
  }

  _ownLateResult (outcome, label, disposeLateResult) {
    this._unreleasedLateResources++
    const disposal = outcome.then(async result => {
      if (result.error) {
        this._unreleasedLateResources--
        return
      }
      try {
        await disposeLateResult(result.value)
        this._unreleasedLateResources--
      } catch (err) {
        this._lateDisposalError = this._lateDisposalError || epochError(err, `late ${label} disposal`)
      }
    }).finally(() => {
      this._lateResourceDisposals.delete(disposal)
      this._inFlightSettlements.delete(disposal)
    })
    this._lateResourceDisposals.add(disposal)
    this._inFlightSettlements.add(disposal)
  }

  _ownLateSuccess (outcome, label, onLateSuccess) {
    const settlement = outcome.then(async result => {
      if (result.error) return
      try {
        await onLateSuccess(result.value)
      } catch (err) {
        this._lateDisposalError = this._lateDisposalError || epochError(err, `late ${label} completion`)
      }
    }).finally(() => {
      this._inFlightSettlements.delete(settlement)
    })
    this._inFlightSettlements.add(settlement)
  }

  async _disposeLateDirectory (dir) {
    if (!dir || typeof dir.close !== 'function') return
    await this._respectJsBudget()
    await this._paceOperations()
    const now = this._now()
    if (this._cleanupExpired || now >= this._cleanupDeadlineAt) {
      this._cleanupExpired = true
      throw new StorageAccountingEpochError(
        'EACCOUNTINGCLEANUPDEADLINE',
        'storage accounting cleanup deadline exceeded before late directory close'
      )
    }
    this.budget.chargeCleanup()
    this._lastOperationStartedAt = now
    this._operationsInFlight++
    this._peakOperationsInFlight = Math.max(this._peakOperationsInFlight, this._operationsInFlight)
    try {
      await dir.close()
    } finally {
      this._operationsInFlight--
    }
  }

  async _paceOperations () {
    if (this._lastOperationStartedAt === null) return
    const gap = Math.ceil(1000 / this.limits.operationsPerSecond)
    const remaining = this._lastOperationStartedAt + gap - this._now()
    if (remaining > 0) await this.clock.sleep(remaining)
  }

  async _respectJsBudget () {
    const now = this._now()
    if (now - this._jsSliceStartedAt >= 1000) {
      this._jsSliceStartedAt = now
      this._jsUsedMs = 0
      return
    }
    if (this._jsUsedMs < this.limits.javascriptSliceMs) return
    const wait = this._jsSliceStartedAt + 1000 - now
    if (wait > 0) await this.clock.sleep(wait)
    this._jsSliceStartedAt = this._now()
    this._jsUsedMs = 0
  }

  async _js (operation) {
    await this._respectJsBudget()
    const startedAt = this._now()
    try {
      return operation()
    } finally {
      const finishedAt = this._now()
      if (finishedAt >= startedAt) this._jsUsedMs += finishedAt - startedAt
    }
  }

  _armNormalDeadline () {
    this._normalTimer = this.clock.setTimeout(() => {
      if (this._fence) return
      const err = new StorageAccountingEpochError('EACCOUNTINGDEADLINE', 'storage accounting normal deadline exceeded')
      this._primaryError = this._primaryError || err
      this._installFence('deadline', err, this._normalDeadlineAt)
    }, this.limits.normalDeadlineMs)
    if (this._normalTimer && typeof this._normalTimer.unref === 'function') this._normalTimer.unref()
  }

  _installFence (kind, err, at) {
    if (this._fence) return false
    this._fence = { kind, at }
    for (const onFence of this._normalFenceWaiters) onFence()
    if (err && !this._primaryError) this._primaryError = err
    if (this._normalTimer !== null) {
      this.clock.clearTimeout(this._normalTimer)
      this._normalTimer = null
    }
    this._cleanupDeadlineAt = this._safeAdd(at, this.limits.cleanupDeadlineMs)
    const delay = Math.max(0, this._cleanupDeadlineAt - this._now())
    this._cleanupTimer = this.clock.setTimeout(() => {
      this._cleanupExpired = true
      this._resolveCleanupFence({ kind: 'cleanup-deadline', at: this._cleanupDeadlineAt })
      for (const onFence of this._cleanupFenceWaiters) onFence()
    }, delay)
    if (this._cleanupTimer && typeof this._cleanupTimer.unref === 'function') this._cleanupTimer.unref()
    return true
  }

  _assertNotFenced () {
    if (!this._fence) return
    if (this._primaryError) throw this._primaryError
    throw new StorageAccountingEpochError('EACCOUNTINGFENCED', 'storage accounting epoch is fenced')
  }

  _validateRoot (stat) {
    const shape = statShape(stat)
    if (shape.symlink) {
      throw new StorageAccountingEpochError('ESTORAGESYMLINK', 'storage accounting root is a symbolic link')
    }
    if (!shape.directory) {
      throw new StorageAccountingEpochError('EACCOUNTINGROOT', 'storage accounting root is not a directory')
    }
    return { dev: shape.dev, ino: shape.ino }
  }

  _validateEntry (stat) {
    const shape = statShape(stat)
    if (shape.symlink) {
      throw new StorageAccountingEpochError('ESTORAGESYMLINK', 'storage accounting tree contains a symbolic link')
    }
    if (shape.dev !== this._rootIdentity.dev) {
      throw new StorageAccountingEpochError('EXDEV', 'storage accounting tree crosses a filesystem boundary')
    }
    return shape
  }

  _validateDirectoryIdentity (stat, expected) {
    const shape = statShape(stat)
    if (shape.symlink || !shape.directory || shape.dev !== expected.dev || shape.ino !== expected.ino) {
      throw new StorageAccountingEpochError('ESTORAGEIDENTITY', 'storage accounting directory identity changed during traversal')
    }
    if (shape.dev !== this._rootIdentity.dev) {
      throw new StorageAccountingEpochError('EXDEV', 'storage accounting tree crosses a filesystem boundary')
    }
  }

  _newRecord (path, depth) {
    const bytes = pathBytes(path)
    if (bytes <= 0 || bytes > this.limits.maxPathBytes) {
      throw new StorageAccountingEpochError('EACCOUNTINGPATH', 'storage accounting UTF-8 path limit exceeded')
    }
    return {
      path,
      pathBytes: bytes,
      depth,
      identity: null,
      bookkeepingBytes: bytes + PATH_RECORD_OVERHEAD_BYTES,
      reserved: false,
      queued: false
    }
  }

  _reserveRecord (record) {
    if (record.reserved) return
    if (this._bookkeepingBytes + record.bookkeepingBytes > this.limits.maxBookkeepingBytes) {
      throw new StorageAccountingEpochError('EACCOUNTINGBOOKKEEPING', 'storage accounting bookkeeping limit exceeded')
    }
    record.reserved = true
    this._reservedRecords.add(record)
    this._bookkeepingBytes += record.bookkeepingBytes
    this._updatePeaks()
  }

  _releaseRecord (record) {
    if (!record || !record.reserved) return
    record.reserved = false
    this._reservedRecords.delete(record)
    this._bookkeepingBytes -= record.bookkeepingBytes
  }

  _enqueueRecord (record) {
    const nextQueuedBytes = this._queuedPathBytes + record.pathBytes
    if (nextQueuedBytes > this.limits.maxQueuedPathBytes) {
      this._releaseRecord(record)
      throw new StorageAccountingEpochError('EACCOUNTINGQUEUE', 'storage accounting queued path byte limit exceeded')
    }
    record.queued = true
    this._deferred.push(record)
    this._queuedPathBytes = nextQueuedBytes
    this._updatePeaks()
  }

  _removeQueuedRecord (record, { release = true } = {}) {
    const index = this._deferred.lastIndexOf(record)
    if (index !== -1) this._deferred.splice(index, 1)
    if (record.queued) {
      record.queued = false
      this._queuedPathBytes -= record.pathBytes
    }
    if (release) this._releaseRecord(record)
  }

  _releaseFrame (frame) {
    const index = this._frames.lastIndexOf(frame)
    if (index === -1) return false
    this._frames.splice(index, 1)
    this._bookkeepingBytes -= frame.bookkeepingBytes
    return true
  }

  _rememberIdentity (identity) {
    const key = this._identityKey(identity)
    if (this._visited.has(key)) return
    const bytes = pathBytes(key) + IDENTITY_RECORD_OVERHEAD_BYTES
    if (this._bookkeepingBytes + bytes > this.limits.maxBookkeepingBytes) {
      throw new StorageAccountingEpochError('EACCOUNTINGBOOKKEEPING', 'storage accounting bookkeeping limit exceeded')
    }
    this._visited.add(key)
    this._bookkeepingBytes += bytes
    this._visitedBookkeepingBytes += bytes
    this._updatePeaks()
  }

  _identityKey (identity) {
    return `${identity.dev}:${identity.ino}`
  }

  _updatePeaks () {
    this._peakOpenDirectories = Math.max(this._peakOpenDirectories, this._frames.length)
    this._peakQueuedPaths = Math.max(this._peakQueuedPaths, this._deferred.length)
    this._peakQueuedPathBytes = Math.max(this._peakQueuedPathBytes, this._queuedPathBytes)
    this._peakBookkeepingBytes = Math.max(this._peakBookkeepingBytes, this._bookkeepingBytes)
  }

  _progressSnapshot () {
    return {
      state: this.state,
      cursor: this._cursor ? { ...this._cursor } : null,
      entries: this.entries,
      directories: this.directories,
      openDirectories: this._frames.length,
      queuedPaths: this._deferred.length,
      queuedPathBytes: this._queuedPathBytes,
      bookkeepingBytes: this._bookkeepingBytes,
      peakOpenDirectories: this._peakOpenDirectories,
      peakQueuedPaths: this._peakQueuedPaths,
      peakQueuedPathBytes: this._peakQueuedPathBytes,
      peakBookkeepingBytes: this._peakBookkeepingBytes,
      operationsInFlight: this._operationsInFlight,
      unreleasedLateResources: this._unreleasedLateResources,
      peakOperationsInFlight: this._peakOperationsInFlight,
      fence: this._fence ? { ...this._fence } : null,
      normalDeadlineAt: this._normalDeadlineAt,
      cleanupDeadlineAt: this._cleanupDeadlineAt
    }
  }

  _notifyProgress () {
    if (!this.onProgress) return
    try {
      this.onProgress(this.getProgress())
    } catch {}
  }

  _now () {
    const value = this.clock.now()
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new StorageAccountingEpochError('EACCOUNTINGCLOCK', 'storage accounting clock returned an invalid timestamp')
    }
    return value
  }

  _safeAdd (left, right) {
    const value = left + right
    if (!Number.isSafeInteger(value)) {
      throw new StorageAccountingEpochError('EACCOUNTINGCLOCK', 'storage accounting deadline overflowed')
    }
    return value
  }

  _duration (startedAt, finishedAt) {
    if (finishedAt < startedAt) return 0
    const value = finishedAt - startedAt
    return Number.isSafeInteger(value) ? value : 0
  }
}

export function runStorageAccountingEpoch (storagePath, options = {}) {
  return new StorageAccountingEpoch(storagePath, options).run()
}
