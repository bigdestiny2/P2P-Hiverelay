import { EventEmitter } from 'events'

export const MAX_CIRCUIT_DURATION_MS = 10 * 60 * 1000 // 10 minutes default
export const MAX_CIRCUIT_BYTES = 64 * 1024 * 1024 // 64 MB per circuit
export const MAX_CIRCUITS_PER_PEER = 5
export const MAX_CIRCUIT_RATE_BYTES_PER_SECOND = 1024 * 1024 // 1 MiB/s per circuit

function forward (from, to, circuit, circuitId, relay) {
  const canPause = typeof from.pause === 'function'
  const canResume = typeof from.resume === 'function'

  from.on('data', (chunk) => {
    if (circuit.bytesRelayed + chunk.byteLength > relay.maxCircuitBytes) {
      relay._closeCircuit(circuitId, 'BYTES_EXCEEDED')
      return
    }
    if (!relay._admitCircuitRate(circuit, chunk.byteLength)) {
      relay._closeCircuit(circuitId, 'RATE_EXCEEDED')
      return
    }
    if (relay._isOverBandwidthLimit()) {
      relay._closeCircuit(circuitId, 'BANDWIDTH_EXCEEDED')
      return
    }
    circuit.bytesRelayed += chunk.byteLength
    relay.totalBytesRelayed += chunk.byteLength
    relay._recordBandwidth(chunk.byteLength)
    if (!to.write(chunk) && canPause) from.pause()
  })

  if (typeof to.on === 'function' && canResume) {
    to.on('drain', () => from.resume())
  }
}

export class Relay extends EventEmitter {
  constructor (swarm, opts = {}) {
    super()
    this.swarm = swarm
    this.maxBandwidthMbps = opts.maxBandwidthMbps || 100
    this.maxConnections = opts.maxConnections || 256
    this.maxCircuitDuration = hardCappedPositiveInteger(opts.maxCircuitDuration, MAX_CIRCUIT_DURATION_MS, MAX_CIRCUIT_DURATION_MS)
    this.maxCircuitBytes = hardCappedPositiveInteger(opts.maxCircuitBytes, MAX_CIRCUIT_BYTES, MAX_CIRCUIT_BYTES)

    // Active circuits: circuitId -> { source, dest, bytesRelayed, startedAt, timer, sourcePeerKey }
    this.circuits = new Map()
    // Per-peer circuit tracking: peer pubkey hex -> count
    this.circuitsPerPeer = new Map()
    this.maxCircuitsPerPeer = hardCappedPositiveInteger(opts.maxCircuitsPerPeer, MAX_CIRCUITS_PER_PEER, MAX_CIRCUITS_PER_PEER)
    this.maxCircuitRateBytesPerSecond = hardCappedPositiveInteger(
      opts.maxCircuitRateBytesPerSecond,
      MAX_CIRCUIT_RATE_BYTES_PER_SECOND,
      MAX_CIRCUIT_RATE_BYTES_PER_SECOND
    )
    this.totalBytesRelayed = 0
    this.totalCircuitsServed = 0
    this.running = false

    // Bandwidth tracking — time-bucketed counters (second granularity)
    this._bandwidthBuckets = new Map() // second-timestamp -> bytes
    this._bandwidthTotal = 0
    this._bandwidthWindowSec = 60 // 60-second sliding window
    this._bandwidthLastPruneSec = -1 // last wall-clock second we pruned; amortizes the prune to once/sec on the data hot path
    this.maxBandwidthBytes = Math.floor((this.maxBandwidthMbps * 1_000_000 / 8) * this._bandwidthWindowSec)
  }

  async start () {
    this.running = true
    this.emit('started')
  }

  /**
   * Create a relay circuit between two peers.
   * The relay forwards opaque encrypted bytes — it cannot read the content.
   *
   * @param {string} circuitId - Unique circuit identifier
   * @param {object} source - Source duplex stream (from requesting peer)
   * @param {object} dest - Destination duplex stream (to target peer)
   * @returns {object} Circuit info
   */
  createCircuit (circuitId, source, dest, sourcePeerKey) {
    if (this.circuits.size >= this.maxConnections) {
      throw new Error('RELAY_AT_CAPACITY')
    }

    if (sourcePeerKey) {
      const current = this.circuitsPerPeer.get(sourcePeerKey) || 0
      if (current >= this.maxCircuitsPerPeer) {
        throw new Error('PEER_AT_CAPACITY')
      }
      this.circuitsPerPeer.set(sourcePeerKey, current + 1)
    }

    const circuit = {
      id: circuitId,
      source,
      dest,
      sourcePeerKey: sourcePeerKey || null,
      bytesRelayed: 0,
      startedAt: Date.now(),
      rateWindowStartedAt: 0,
      rateWindowBytes: 0,
      timer: null
    }

    // Bidirectional forwarding with backpressure
    forward(source, dest, circuit, circuitId, this)
    forward(dest, source, circuit, circuitId, this)

    // Clean up on either side closing
    const onClose = () => this._closeCircuit(circuitId, 'PEER_CLOSED')
    source.on('close', onClose)
    source.on('error', onClose)
    dest.on('close', onClose)
    dest.on('error', onClose)

    // Max duration timer
    circuit.timer = setTimeout(() => {
      this._closeCircuit(circuitId, 'DURATION_EXCEEDED')
    }, this.maxCircuitDuration)

    this.circuits.set(circuitId, circuit)
    this.totalCircuitsServed++

    this.emit('circuit-created', {
      circuitId,
      maxBytes: this.maxCircuitBytes,
      maxDuration: this.maxCircuitDuration
    })

    return circuit
  }

  _closeCircuit (circuitId, reason = 'UNKNOWN') {
    const circuit = this.circuits.get(circuitId)
    if (!circuit) return

    // Cancel timer FIRST to prevent re-entrant calls
    if (circuit.timer) {
      clearTimeout(circuit.timer)
      circuit.timer = null
    }

    // Then remove from map
    this.circuits.delete(circuitId)

    // Decrement per-peer count
    if (circuit.sourcePeerKey) {
      const count = this.circuitsPerPeer.get(circuit.sourcePeerKey) || 0
      if (count <= 1) {
        this.circuitsPerPeer.delete(circuit.sourcePeerKey)
      } else {
        this.circuitsPerPeer.set(circuit.sourcePeerKey, count - 1)
      }
    }

    // Then clean up streams
    try { circuit.source.destroy() } catch {}
    try { circuit.dest.destroy() } catch {}

    this.emit('circuit-closed', {
      circuitId,
      reason,
      bytesRelayed: circuit.bytesRelayed,
      durationMs: Date.now() - circuit.startedAt
    })
  }

  /**
   * Drop bandwidth buckets older than the sliding window. Idempotent within
   * a single wall-clock second: on a saturated circuit this is called on
   * every data frame, but the loop body only runs once per second — every
   * other call early-returns on the guard. (Previously the prune loop ran
   * twice per frame: once in _isOverBandwidthLimit and once in
   * _recordBandwidth. Same result, a fraction of the work.)
   */
  _pruneBandwidth (nowSec) {
    if (nowSec === this._bandwidthLastPruneSec) return
    this._bandwidthLastPruneSec = nowSec
    const cutoff = nowSec - this._bandwidthWindowSec
    for (const [ts, bytes] of this._bandwidthBuckets) {
      if (ts < cutoff) {
        this._bandwidthTotal -= bytes
        this._bandwidthBuckets.delete(ts)
      } else break // Map preserves insertion order
    }
  }

  _addBandwidth (bytes, nowSec) {
    this._bandwidthBuckets.set(nowSec, (this._bandwidthBuckets.get(nowSec) || 0) + bytes)
    this._bandwidthTotal += bytes
  }

  /**
   * Check if current throughput exceeds the configured bandwidth cap.
   */
  _isOverBandwidthLimit () {
    this._pruneBandwidth(Math.floor(Date.now() / 1000))
    return this._bandwidthTotal > this.maxBandwidthBytes
  }

  _recordBandwidth (bytes) {
    const now = Math.floor(Date.now() / 1000)
    this._pruneBandwidth(now)
    this._addBandwidth(bytes, now)
  }

  // ─── v0.8.19: protomux-channel-based circuit accounting ──────────
  //
  // The original createCircuit() forwarded raw bytes between two
  // duplex streams. That model never worked over protomux (channels
  // don't have an exposed underlying stream you can safely forward).
  // The new model: CircuitRelay does the byte forwarding via protomux
  // data messages; Relay just tracks counters and applies caps.
  //
  // These methods are channel-agnostic — they accept the same opaque
  // circuitId hex CircuitRelay uses, and return bool for accept/reject.

  /**
   * Register a new circuit for accounting. Returns false if the relay
   * is at capacity or this peer is at their per-peer circuit limit.
   * @param {string} circuitId - hex string identifier
   * @param {string} sourcePeerKey - hex pubkey of the source peer (for per-peer cap)
   * @param {number} [maxBytes] - per-circuit byte cap (defaults to this.maxCircuitBytes)
   * @returns {boolean} true if accepted, false if rejected
   */
  registerCircuit (circuitId, sourcePeerKey, maxBytes) {
    if (this.circuits.size >= this.maxConnections) return false

    if (sourcePeerKey) {
      const current = this.circuitsPerPeer.get(sourcePeerKey) || 0
      if (current >= this.maxCircuitsPerPeer) return false
      this.circuitsPerPeer.set(sourcePeerKey, current + 1)
    }

    const circuit = {
      id: circuitId,
      source: null, // legacy field; null in the new model
      dest: null,
      sourcePeerKey: sourcePeerKey || null,
      bytesRelayed: 0,
      startedAt: Date.now(),
      maxBytes: hardCappedPositiveInteger(maxBytes, this.maxCircuitBytes, this.maxCircuitBytes),
      rateWindowStartedAt: 0,
      rateWindowBytes: 0,
      timer: null
    }

    // Max-duration safety timer — if CircuitRelay doesn't call closeCircuit
    // within the window, we tear down accounting on our own.
    circuit.timer = setTimeout(() => {
      this.closeCircuit(circuitId, 'DURATION_EXCEEDED')
    }, this.maxCircuitDuration)

    this.circuits.set(circuitId, circuit)
    this.totalCircuitsServed++

    this.emit('circuit-created', {
      circuitId,
      maxBytes: circuit.maxBytes,
      maxDuration: this.maxCircuitDuration
    })

    return true
  }

  /**
   * Record bytes relayed for a circuit. Returns false if the per-circuit
   * byte cap or the relay-wide bandwidth cap has been reached; caller
   * should close the circuit. Returns true to continue.
   */
  recordCircuitBytes (circuitId, bytes) {
    const circuit = this.circuits.get(circuitId)
    if (!circuit) return false

    if (circuit.bytesRelayed + bytes > circuit.maxBytes) return false
    if (!this._admitCircuitRate(circuit, bytes)) return false

    // Single timestamp + single (amortized) prune for the whole admit:
    // the previous code called _isOverBandwidthLimit() and _recordBandwidth()
    // back to back, each taking its own Date.now() and pruning the bucket
    // Map — duplicated work on the per-frame data hot path.
    const now = Math.floor(Date.now() / 1000)
    this._pruneBandwidth(now)
    if (this._bandwidthTotal > this.maxBandwidthBytes) return false

    circuit.bytesRelayed += bytes
    this.totalBytesRelayed += bytes
    this._addBandwidth(bytes, now)
    return true
  }

  _admitCircuitRate (circuit, bytes, now = Date.now()) {
    if (!Number.isSafeInteger(this.maxCircuitRateBytesPerSecond) || this.maxCircuitRateBytesPerSecond <= 0) return true
    if (!circuit || !Number.isSafeInteger(bytes) || bytes < 0) return false
    if (!Number.isFinite(circuit.rateWindowStartedAt) || now - circuit.rateWindowStartedAt >= 1000) {
      circuit.rateWindowStartedAt = now
      circuit.rateWindowBytes = 0
    }
    if (circuit.rateWindowBytes + bytes > this.maxCircuitRateBytesPerSecond) return false
    circuit.rateWindowBytes += bytes
    return true
  }

  /**
   * Close a circuit and decrement counters. Idempotent.
   */
  closeCircuit (circuitId, reason = 'UNKNOWN') {
    const circuit = this.circuits.get(circuitId)
    if (!circuit) return

    if (circuit.timer) {
      clearTimeout(circuit.timer)
      circuit.timer = null
    }
    this.circuits.delete(circuitId)

    if (circuit.sourcePeerKey) {
      const count = this.circuitsPerPeer.get(circuit.sourcePeerKey) || 0
      if (count <= 1) this.circuitsPerPeer.delete(circuit.sourcePeerKey)
      else this.circuitsPerPeer.set(circuit.sourcePeerKey, count - 1)
    }

    // Legacy createCircuit set source/dest to stream refs — only destroy
    // if they look like streams (have a destroy method). In the new model
    // they're null, so this is a no-op.
    if (circuit.source && typeof circuit.source.destroy === 'function') {
      try { circuit.source.destroy() } catch {}
    }
    if (circuit.dest && typeof circuit.dest.destroy === 'function') {
      try { circuit.dest.destroy() } catch {}
    }

    this.emit('circuit-closed', {
      circuitId,
      reason,
      bytesRelayed: circuit.bytesRelayed,
      durationMs: Date.now() - circuit.startedAt
    })
  }

  getStats () {
    return {
      activeCircuits: this.circuits.size,
      totalCircuitsServed: this.totalCircuitsServed,
      totalBytesRelayed: this.totalBytesRelayed,
      capacityUsedPct: Math.round((this.circuits.size / this.maxConnections) * 100),
      peersWithCircuits: this.circuitsPerPeer.size
    }
  }

  async stop () {
    this.running = false
    for (const circuitId of [...this.circuits.keys()]) {
      this._closeCircuit(circuitId, 'SHUTDOWN')
    }
    this.circuitsPerPeer.clear()
    this.emit('stopped')
  }
}

function hardCappedPositiveInteger (value, fallback, hardCap) {
  const candidate = Number.isSafeInteger(value) && value > 0 ? value : fallback
  return Math.min(candidate, hardCap)
}
