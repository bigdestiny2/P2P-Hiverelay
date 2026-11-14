function strictPositiveInteger (value, label, max = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < 1 || value > max) {
    throw new RangeError(`${label} must be a safe integer in [1,${max}]`)
  }
  return value
}

export class CompletionScheduler {
  constructor (opts = {}) {
    if (typeof opts.run !== 'function') throw new TypeError('completion scheduler run function is required')
    this.name = typeof opts.name === 'string' && opts.name ? opts.name : 'completion-pass'
    this.enabled = opts.enabled !== false
    this.intervalMs = strictPositiveInteger(opts.intervalMs, `${this.name} intervalMs`)
    this.retryMinMs = strictPositiveInteger(opts.retryMinMs ?? 1000, `${this.name} retryMinMs`)
    this.retryMaxMs = strictPositiveInteger(opts.retryMaxMs ?? 30 * 60 * 1000, `${this.name} retryMaxMs`)
    if (this.retryMinMs > this.retryMaxMs) throw new RangeError(`${this.name} retry range is invalid`)
    this.run = opts.run
    this._timer = null
    this._flight = null
    this._dirty = false
    this._stopping = false
    this._retryMs = this.retryMinMs
    this._state = {
      running: false,
      triggers: 0,
      coalescedTriggers: 0,
      skippedTriggers: 0,
      passes: 0,
      failures: 0,
      lastStartedAt: null,
      lastCompletedAt: null,
      lastDurationMs: null,
      lastError: null
    }
  }

  start ({ immediate = true } = {}) {
    if (!this.enabled || this._stopping) return false
    if (immediate) this.trigger('start')
    else this._arm(this.intervalMs)
    return true
  }

  trigger () {
    this._state.triggers++
    if (!this.enabled || this._stopping) {
      this._state.skippedTriggers++
      return false
    }
    if (this._flight) {
      this._dirty = true
      this._state.coalescedTriggers++
      return false
    }
    if (this._timer) {
      clearTimeout(this._timer)
      this._timer = null
    }
    this._launch()
    return true
  }

  _arm (delayMs) {
    if (!this.enabled || this._stopping || this._timer || this._flight) return
    this._timer = setTimeout(() => {
      this._timer = null
      this._launch()
    }, delayMs)
    if (this._timer.unref) this._timer.unref()
  }

  _launch () {
    if (!this.enabled || this._stopping || this._flight) return
    const startedAt = Date.now()
    this._state.running = true
    this._state.lastStartedAt = startedAt
    const flight = Promise.resolve().then(() => this.run()).then(
      (result) => {
        this._state.passes++
        this._state.lastError = null
        this._retryMs = this.retryMinMs
        if (result && result.complete === false) this._dirty = true
        return result
      },
      (err) => {
        this._state.failures++
        this._state.lastError = err && err.message ? err.message : String(err)
        this._retryMs = Math.min(this.retryMaxMs, this._retryMs * 2)
        throw err
      }
    ).finally(() => {
      const completedAt = Date.now()
      this._state.running = false
      this._state.lastCompletedAt = completedAt
      this._state.lastDurationMs = Math.max(0, completedAt - startedAt)
      if (this._flight === flight) this._flight = null
      if (this._stopping || !this.enabled) return
      const dirty = this._dirty
      this._dirty = false
      this._arm(dirty ? 1 : (this._state.lastError ? this._retryMs : this.intervalMs))
    })
    // The owner observes failures through snapshot()/its wrapped run handler;
    // keep timer-driven rejections from becoming process-level unhandled gaps.
    flight.catch(() => {})
    this._flight = flight
  }

  async stop () {
    this._stopping = true
    this.enabled = false
    this._dirty = false
    if (this._timer) clearTimeout(this._timer)
    this._timer = null
    if (this._flight) await this._flight.catch(() => {})
  }

  snapshot () {
    return {
      name: this.name,
      enabled: this.enabled,
      stopping: this._stopping,
      scheduled: this._timer !== null,
      dirty: this._dirty,
      retryMs: this._retryMs,
      ...this._state
    }
  }
}

export { strictPositiveInteger }
