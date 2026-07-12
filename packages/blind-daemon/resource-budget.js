import { operationProfile } from '@hiverelay/blind-protocol'

function busy (message) {
  const error = new Error(message)
  error.code = 'BUSY'
  throw error
}

function boundedInteger (value, field, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new TypeError(`${field} must be an integer within 1..${maximum}`)
  }
  return value
}

function nonnegativeInteger (value, field) {
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`${field} must be a non-negative safe integer`)
  return value
}

function checkedTotal (values) {
  let total = 0
  for (const [field, value] of values) {
    const checked = nonnegativeInteger(value, field)
    if (total > Number.MAX_SAFE_INTEGER - checked) throw new TypeError('reservation byte total overflows')
    total += checked
  }
  if (total < 1) throw new TypeError('reservation must cover at least one byte')
  return total
}

function keyFor (familyId, operationId) {
  return `${familyId}:${operationId}`
}

export class ResourceBudget {
  constructor (options = {}) {
    this.maxItems = boundedInteger(options.maxItems == null ? 1024 : options.maxItems, 'maxItems', 1_000_000)
    this.maxBytes = boundedInteger(options.maxBytes == null ? 64 * 1024 * 1024 : options.maxBytes,
      'maxBytes', 1024 * 1024 * 1024)
    this.reservePercent = options.reservePercent == null ? 5 : options.reservePercent
    if (!Number.isInteger(this.reservePercent) || this.reservePercent < 5 || this.reservePercent > 50) {
      throw new TypeError('reservePercent must be within 5..50')
    }
    this.reservedItems = Math.max(1, Math.ceil(this.maxItems * this.reservePercent / 100))
    this.reservedBytes = Math.max(1, Math.ceil(this.maxBytes * this.reservePercent / 100))
    this.generalItemLimit = Math.max(0, this.maxItems - this.reservedItems)
    this.generalByteLimit = Math.max(0, this.maxBytes - this.reservedBytes)
    this.items = 0
    this.bytes = 0
    this.byOperation = new Map()
    this.quotas = new Map()
    for (const quota of options.operationQuotas || []) {
      if (!quota || !operationProfile(quota.familyId, quota.operationId)) {
        throw new TypeError('operation quota references an unknown operation')
      }
      const key = keyFor(quota.familyId, quota.operationId)
      if (this.quotas.has(key)) throw new TypeError('operation quotas must be unique')
      this.quotas.set(key, Object.freeze({
        maxItems: boundedInteger(quota.maxItems, 'operation quota maxItems', this.maxItems),
        maxBytes: boundedInteger(quota.maxBytes, 'operation quota maxBytes', this.maxBytes)
      }))
    }
  }

  acquire (input) {
    if (!input || !operationProfile(input.familyId, input.operationId)) {
      throw new TypeError('budget reservation references an unknown operation')
    }
    const bytes = input.bytes == null
      ? checkedTotal([
        ['requestBytes', input.requestBytes ?? 0],
        ['responseBytes', input.responseBytes ?? 0],
        ['stagingBytes', input.stagingBytes ?? 0]
      ])
      : boundedInteger(input.bytes, 'reservation bytes')
    if (bytes > this.maxBytes) busy('one operation exceeds the bounded daemon byte budget')
    const critical = input.critical === true
    const itemLimit = critical ? this.maxItems : this.generalItemLimit
    const byteLimit = critical ? this.maxBytes : this.generalByteLimit
    if (this.items + 1 > itemLimit || this.bytes + bytes > byteLimit) {
      busy('bounded daemon resource budget is saturated')
    }
    const key = keyFor(input.familyId, input.operationId)
    const current = this.byOperation.get(key) || { items: 0, bytes: 0 }
    const quota = this.quotas.get(key)
    if (quota && (current.items + 1 > quota.maxItems || current.bytes + bytes > quota.maxBytes)) {
      busy('bounded per-operation quota is saturated')
    }
    this.items++
    this.bytes += bytes
    current.items++
    current.bytes += bytes
    this.byOperation.set(key, current)
    let released = false
    return Object.freeze({
      bytes,
      release: () => {
        if (released) return
        released = true
        this.items--
        this.bytes -= bytes
        current.items--
        current.bytes -= bytes
        if (current.items === 0) this.byOperation.delete(key)
      }
    })
  }

  utilizationBand () {
    const ratio = Math.max(this.items / this.maxItems, this.bytes / this.maxBytes)
    if (ratio === 0) return 0
    if (ratio <= 0.125) return 1
    if (ratio <= 0.25) return 2
    if (ratio <= 0.5) return 3
    if (ratio <= 0.7) return 4
    if (ratio <= 0.85) return 5
    if (ratio < 1) return 6
    return 7
  }
}
