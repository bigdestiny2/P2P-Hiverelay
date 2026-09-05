const BEGIN = 0
export const MAX_POPULATION_CONSUMERS = 32
export const MAX_POPULATION_RECORDS = 262_144
export const MAX_TOMBSTONE_GC_PER_PAGE = 64

function budget (value, max) {
  if (!Number.isSafeInteger(value) || value < 1 || value > max) {
    throw new RangeError(`population budget must be a safe integer in [1,${max}]`)
  }
  return value
}

/**
 * Membership-only generation index. Values remain in the caller-owned Map;
 * this index records insert/reinsert/delete fences without retaining values.
 */
export class GenerationPopulation {
  constructor (opts = {}) {
    this.name = typeof opts.name === 'string' && opts.name ? opts.name : 'population'
    this.maxRecords = budget(opts.maxRecords ?? MAX_POPULATION_RECORDS, MAX_POPULATION_RECORDS)
    this.maxConsumers = budget(opts.maxConsumers ?? MAX_POPULATION_CONSUMERS, MAX_POPULATION_CONSUMERS)
    if (!Array.isArray(opts.allowedConsumers) || opts.allowedConsumers.length === 0 ||
        opts.allowedConsumers.length > this.maxConsumers ||
        opts.allowedConsumers.some(name => typeof name !== 'string' || name.length === 0) ||
        new Set(opts.allowedConsumers).size !== opts.allowedConsumers.length) {
      throw new TypeError(`${this.name}: fixed population consumer names are required`)
    }
    this.allowedConsumers = new Set(opts.allowedConsumers)
    this.lastIssuedGeneration = 0
    this._records = new Map()
    this._membership = new Map()
    this._head = null
    this._tail = null
    this._consumers = new Map()
  }

  get recordCount () { return this._records.size }
  get consumerCount () { return this._consumers.size }

  _issue () {
    if (this.lastIssuedGeneration >= Number.MAX_SAFE_INTEGER) {
      const err = new Error(`${this.name}: generation exhausted; operator rebuild required`)
      err.code = 'POPULATION_GENERATION_EXHAUSTED'
      throw err
    }
    if (this._records.size >= this.maxRecords) {
      const err = new Error(`${this.name}: generation index backpressure`)
      err.code = 'POPULATION_INDEX_BACKPRESSURE'
      throw err
    }
    return ++this.lastIssuedGeneration
  }

  _appendRecord (record) {
    record.previousGeneration = this._tail
    record.nextGeneration = null
    if (this._tail !== null) this._records.get(this._tail).nextGeneration = record.generation
    else this._head = record.generation
    this._tail = record.generation
    this._records.set(record.generation, record)
  }

  insert (key) {
    if (typeof key !== 'string' || key.length === 0) throw new TypeError(`${this.name}: key is required`)
    const existingGeneration = this._membership.get(key)
    if (existingGeneration !== undefined) return existingGeneration
    const generation = this._issue()
    this._appendRecord({ generation, key, kind: 'member', deletedGeneration: null })
    this._membership.set(key, generation)
    return generation
  }

  delete (key) {
    const memberGeneration = this._membership.get(key)
    // Every delete, including one for an absent key, consumes a fresh fence.
    const deletedGeneration = this._issue()
    if (memberGeneration !== undefined) {
      const member = this._records.get(memberGeneration)
      if (member) member.deletedGeneration = deletedGeneration
      this._membership.delete(key)
    }
    this._appendRecord({ generation: deletedGeneration, key, kind: 'tombstone', memberGeneration })
    return memberGeneration !== undefined
  }

  has (key) { return this._membership.has(key) }

  register (name) {
    if (typeof name !== 'string' || name.length === 0 ||
        (this.allowedConsumers.size > 0 && !this.allowedConsumers.has(name))) {
      const err = new Error(`${this.name}: unknown population consumer`)
      err.code = 'POPULATION_CONSUMER_INVALID'
      throw err
    }
    if (this._consumers.has(name)) {
      const err = new Error(`${this.name}: duplicate population consumer`)
      err.code = 'POPULATION_CONSUMER_DUPLICATE'
      throw err
    }
    if (this._consumers.size >= this.maxConsumers) {
      const err = new Error(`${this.name}: population consumer limit reached`)
      err.code = 'POPULATION_CONSUMER_LIMIT'
      throw err
    }
    const registrationHighWater = this.lastIssuedGeneration
    const cursor = {
      name,
      registrationHighWater,
      completedHighWater: registrationHighWater,
      highWaterGeneration: registrationHighWater,
      positionGeneration: BEGIN,
      cyclesCompleted: 0
    }
    this._consumers.set(name, cursor)
    return { ...cursor }
  }

  unregister (name) {
    return this._consumers.delete(name)
  }

  isRegistered (name) { return this._consumers.has(name) }

  _unlink (generation) {
    const record = this._records.get(generation)
    if (!record) return false
    for (const cursor of this._consumers.values()) {
      if (cursor.positionGeneration === generation) cursor.positionGeneration = record.previousGeneration ?? BEGIN
    }
    if (record.previousGeneration !== null) {
      const previous = this._records.get(record.previousGeneration)
      if (previous) previous.nextGeneration = record.nextGeneration
    } else {
      this._head = record.nextGeneration
    }
    if (record.nextGeneration !== null) {
      const next = this._records.get(record.nextGeneration)
      if (next) next.previousGeneration = record.previousGeneration
    } else {
      this._tail = record.previousGeneration
    }
    return this._records.delete(generation)
  }

  _tombstoneReclaimable (record) {
    for (const cursor of this._consumers.values()) {
      if (cursor.completedHighWater < record.generation) return false
    }
    return true
  }

  page (name, requestedBudget, resolve) {
    const cursor = this._consumers.get(name)
    if (!cursor) {
      const err = new Error(`${this.name}: population consumer is not registered`)
      err.code = 'POPULATION_CONSUMER_NOT_REGISTERED'
      throw err
    }
    const limit = budget(requestedBudget, 64)
    const entries = []
    let examined = 0
    let gcExamined = 0
    let reclaimed = 0
    let generation = cursor.positionGeneration === BEGIN
      ? this._head
      : this._records.get(cursor.positionGeneration)?.nextGeneration ?? this._head

    while (generation !== null && examined < limit) {
      const record = this._records.get(generation)
      if (!record) break
      if (record.generation > cursor.highWaterGeneration) break
      const next = record.nextGeneration
      cursor.positionGeneration = record.generation
      examined++
      if (record.kind === 'member' && record.deletedGeneration === null &&
          this._membership.get(record.key) === record.generation) {
        const value = typeof resolve === 'function' ? resolve(record.key) : record.key
        if (value !== undefined) entries.push({ key: record.key, value, generation: record.generation })
      } else if (record.kind === 'tombstone') {
        gcExamined++
        if (reclaimed < MAX_TOMBSTONE_GC_PER_PAGE && this._tombstoneReclaimable(record)) {
          if (record.memberGeneration !== undefined) this._unlink(record.memberGeneration)
          this._unlink(record.generation)
          reclaimed++
        }
      }
      generation = next
    }

    const complete = generation === null || generation > cursor.highWaterGeneration
    const completedHighWater = complete ? cursor.highWaterGeneration : cursor.completedHighWater
    if (complete) {
      cursor.completedHighWater = completedHighWater
      cursor.cyclesCompleted++
      cursor.positionGeneration = BEGIN
      cursor.highWaterGeneration = this.lastIssuedGeneration
    }
    return {
      entries,
      examined,
      gcExamined,
      reclaimed,
      complete,
      completedHighWater,
      nextHighWater: cursor.highWaterGeneration,
      cyclesCompleted: cursor.cyclesCompleted
    }
  }

  snapshot () {
    return {
      name: this.name,
      lastIssuedGeneration: this.lastIssuedGeneration,
      records: this._records.size,
      live: this._membership.size,
      consumers: [...this._consumers.values()].map(cursor => ({ ...cursor }))
    }
  }
}

export { BEGIN as POPULATION_CURSOR_BEGIN }
