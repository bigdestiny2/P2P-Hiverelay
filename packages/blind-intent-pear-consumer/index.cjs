const { isAbsolute } = require('node:path')
const { createHash } = require('node:crypto')
const { readFileSync } = require('node:fs')
const { fileURLToPath } = require('node:url')
const PearRuntime = require('pear-runtime')
const TextDecoder = require('text-decoder')

const MAX_CIPHERTEXT = 8 * 1024 * 1024 + 264 + 28
const MAX_MESSAGE = MAX_CIPHERTEXT * 2 + 65536
const PHASES = new Set(['before-write', 'after-file-sync', 'after-publication', 'before-directory-sync', 'after-directory-sync'])
function failure (code, message) { return Object.assign(new Error(message), { code }) }

// This private package is a local worker consumer. It never chooses an entry
// from caller input and never handles a sealing key or plaintext intent.
class PearIntentBackend {
  constructor (directory, { timeoutMs = 30000, pauseAtPhase = null, onPhase = null } = {}) {
    if (typeof directory !== 'string' || !isAbsolute(directory) || Buffer.byteLength(directory) > 4096) throw failure('INTENT_STORE_INPUT', 'caller must supply a bounded absolute private application storage directory')
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 120000) throw failure('INTENT_STORE_INPUT', 'worker deadline must be within 100..120000 ms')
    if (pauseAtPhase !== null && (!PHASES.has(pauseAtPhase) || typeof onPhase !== 'function')) throw failure('INTENT_STORE_INPUT', 'phase pause requires a known phase and callback')
    if (!((process.platform === 'darwin' && process.arch === 'arm64') || (process.platform === 'linux' && process.arch === 'x64'))) throw failure('INTENT_STORE_PLATFORM', 'Pear intent worker target is unqualified')
    if (require('pear-runtime/package').version !== '1.3.1' || require('bare-sidecar/package').version !== '0.5.2') throw failure('INTENT_STORE_PLATFORM', 'Pear worker cohort differs from the qualified exact versions')
    this._timeoutMs = timeoutMs
    this._onPhase = onPhase
    this._pending = new Map()
    this._operations = new Set()
    this._nextId = 1
    this._closing = false
    this._failed = null
    this._buffer = ''
    this._decoder = new TextDecoder()
    this._events = []
    this._ipc = PearRuntime.run(require.resolve('./worker.mjs'))
    // The exact sidecar cohort exposes its ChildProcess here. Retain that
    // specific process handle for bounded fatal cleanup, never a recycled PID.
    this._process = this._ipc._process
    this._exit = new Promise(resolve => { this._resolveExit = resolve })
    this._closed = new Promise(resolve => { this._resolveClosed = resolve })
    this._ipc.on('data', bytes => this._data(bytes))
    this._ipc.on('error', error => this._fail(error))
    this._process.on('error', error => {
      // A failed spawn emits close without exit. Resolve the lifecycle wait
      // as a spawn failure so close cannot hang waiting for an absent process.
      if (!this._process.pid) this._resolveExit({ code: null, signal: null, spawnError: error.code })
      this._fail(error)
    })
    this._ipc.on('exit', (code, signal) => {
      this._events.push('exit')
      this._resolveExit({ code, signal })
      if (!this._drained) this._fail(failure('INTENT_STORE_WORKER_UNKNOWN', 'worker exited without proving backend drain'))
    })
    this._ipc.on('close', () => { this._events.push('close'); this._resolveClosed(); if (!this._drained) this._fail(failure('INTENT_STORE_WORKER_UNKNOWN', 'worker pipe closed without proving backend drain')) })
    this._stderr = ''
    this._ipc.stderr.on('data', bytes => {
      this._stderr += bytes
      if (this._stderr.length > 65536) this._fail(failure('INTENT_STORE_WORKER_UNKNOWN', 'worker diagnostics exceeded their bound'))
    })
    this._ipc.stdout.resume()
    this._readyPromise = this._request('open', { directory, pauseAtPhase }).then(result => {
      if (result.runtime !== 'v1.29.4' || result.platform !== process.platform || result.arch !== process.arch) throw failure('INTENT_STORE_PLATFORM', 'actual embedded worker differs from the qualified runtime')
      if (!Array.isArray(result.nativeLibraries) || result.nativeLibraries.length > 128) throw failure('INTENT_STORE_PLATFORM', 'worker did not return a bounded loaded native inventory')
      const executableSha256 = createHash('sha256').update(readFileSync(result.executable)).digest('hex')
      const nativeLibraries = result.nativeLibraries.map(url => {
        if (url.startsWith('builtin:')) return { url, embeddedExecutableSha256: executableSha256 }
        const path = fileURLToPath(url)
        const bytes = readFileSync(path)
        return { path, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') }
      })
      this.runtime = Object.freeze({ ...result, nativeLibraries, executableSha256 })
      return this.runtime
    }).catch(error => { this._fail(error); throw error })
    this._readyPromise.catch(() => {})
  }

  _fail (error) {
    this._failed ||= error
    for (const item of this._pending.values()) { clearTimeout(item.timer); item.reject(this._failed) }
    this._pending.clear()
    if (this._process.exitCode === null && this._process.signalCode === null) this._process.kill('SIGKILL')
  }

  _data (bytes) {
    this._buffer += this._decoder.push(bytes)
    while (this._buffer.includes('\n')) {
      const end = this._buffer.indexOf('\n')
      if (end > MAX_MESSAGE) return this._fail(failure('INTENT_STORE_WORKER_UNKNOWN', 'worker response exceeded its bound'))
      const line = this._buffer.slice(0, end)
      this._buffer = this._buffer.slice(end + 1)
      let message
      try { message = JSON.parse(line) } catch { return this._fail(failure('INTENT_STORE_WORKER_UNKNOWN', 'invalid worker response')) }
      if (message.event === 'phase') {
        Promise.resolve().then(() => this._onPhase?.(message.phase)).then(() => {
          if (!this._failed) this._ipc.write(JSON.stringify({ op: 'resume' }) + '\n')
        }, error => this._fail(error))
        continue
      }
      const pending = this._pending.get(message.id)
      if (!pending) return this._fail(failure('INTENT_STORE_WORKER_UNKNOWN', 'worker response has no outstanding request'))
      this._pending.delete(message.id)
      clearTimeout(pending.timer)
      if (message.error) pending.reject(failure(message.error.code, message.error.message))
      else {
        if (pending.op === 'close' && message.result?.drained === true) { this._drained = true; this._events.push('drained') }
        pending.resolve(message.result)
      }
    }
    if (this._buffer.length > MAX_MESSAGE) this._fail(failure('INTENT_STORE_WORKER_UNKNOWN', 'worker response exceeded its bound'))
  }

  _request (op, args = {}) {
    if (this._failed) return Promise.reject(this._failed)
    if (this._pending.size >= 8) return Promise.reject(failure('INTENT_STORE_BUSY', 'worker operation admission is full'))
    const id = this._nextId++
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => this._fail(failure('INTENT_STORE_WORKER_UNKNOWN', 'worker operation deadline expired')), this._timeoutMs)
      this._pending.set(id, { resolve, reject, timer, op })
      this._ipc.write(JSON.stringify({ id, op, ...args }) + '\n', error => { if (error) this._fail(error) })
    })
  }

  async ready () {
    const runtime = await this._readyPromise
    if (this._failed) throw this._failed
    if (this._closing) throw failure('INTENT_STORE_CLOSED', 'worker backend is closing')
    return runtime
  }

  _operation (op, argumentsFactory) {
    if (this._failed) return Promise.reject(this._failed)
    if (this._closing) return Promise.reject(failure('INTENT_STORE_CLOSED', 'worker backend is closing'))
    if (this._operations.size >= 8) return Promise.reject(failure('INTENT_STORE_BUSY', 'worker operation admission is full'))
    // Admit before copying ciphertext or waiting for worker startup.
    let args
    try { args = argumentsFactory() } catch (error) { return Promise.reject(error) }
    const operation = this._readyPromise.then(() => this._request(op, args)).finally(() => this._operations.delete(operation))
    this._operations.add(operation)
    return operation
  }

  async read (key) {
    if (typeof key !== 'string' || !/^intent:[0-9a-f]{64}$/.test(key)) throw failure('INTENT_STORE_INPUT', 'invalid intent key')
    const record = await this._operation('read', () => ({ key }))
    return { revision: BigInt(record.revision), ciphertext: record.ciphertext === null ? null : Buffer.from(record.ciphertext, 'hex') }
  }

  compareAndSwap (key, revision, ciphertext) {
    if (!(ciphertext instanceof Uint8Array) || ciphertext.length < 1 || ciphertext.length > MAX_CIPHERTEXT || (typeof SharedArrayBuffer !== 'undefined' && ciphertext.buffer instanceof SharedArrayBuffer)) return Promise.reject(failure('INTENT_STORE_INPUT', 'ciphertext must be bounded unshared opaque bytes'))
    if (typeof key !== 'string' || !/^intent:[0-9a-f]{64}$/.test(key)) return Promise.reject(failure('INTENT_STORE_INPUT', 'invalid intent key'))
    if (typeof revision !== 'bigint' || revision < 0n || revision >= 1n << 64n) return Promise.reject(failure('INTENT_STORE_INPUT', 'revision must be u64'))
    return this._operation('cas', () => ({ key, revision: String(revision), ciphertext: Buffer.from(ciphertext).toString('hex') }))
  }

  keysPage ({ cursor = null, limit = 64 } = {}) {
    if ((cursor !== null && (typeof cursor !== 'string' || cursor.length > 64)) || !Number.isSafeInteger(limit) || limit < 1 || limit > 256) return Promise.reject(failure('INTENT_STORE_INPUT', 'invalid bounded scan request'))
    return this._operation('keysPage', () => ({ cursor, limit }))
  }

  closeScan (cursor) {
    if (typeof cursor !== 'string' || cursor.length > 64) return Promise.reject(failure('INTENT_STORE_INPUT', 'invalid scan cursor'))
    return this._operation('closeScan', () => ({ cursor }))
  }

  close () {
    if (this._closePromise) return this._closePromise
    this._closing = true
    this._closePromise = (async () => {
      try {
        await this._readyPromise
        await Promise.allSettled([...this._operations])
        // Stop admission, settle every accepted operation, then await the real
        // backend close and its separate process/pipe completion receipts.
        const result = await this._request('close')
        if (!result?.drained) throw failure('INTENT_STORE_WORKER_UNKNOWN', 'worker did not acknowledge drain')
        const deadline = setTimeout(() => this._fail(failure('INTENT_STORE_WORKER_UNKNOWN', 'drained worker did not exit')), this._timeoutMs)
        try {
          const [exit] = await Promise.all([this._exit, this._closed])
          if (exit.code !== 0 || exit.signal !== null || this._failed) throw this._failed || failure('INTENT_STORE_WORKER_UNKNOWN', 'worker exit was unclean')
          this.lifecycle = Object.freeze({ drained: true, exit, events: [...this._events] })
        } finally { clearTimeout(deadline) }
      } catch (error) {
        this._fail(error)
        await Promise.all([this._exit, this._closed])
        throw error
      }
    })()
    return this._closePromise
  }
}

module.exports = { PearIntentBackend }
