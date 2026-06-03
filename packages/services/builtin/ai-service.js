/**
 * AI Inference Service
 *
 * Provides AI/ML inference as a decentralized service.
 * Relay nodes with GPU resources can offer inference,
 * apps consume it without managing their own models.
 *
 * Architecture:
 *   - Provider mode: Node has a model loaded, accepts inference requests
 *   - Consumer mode: Node discovers AI providers and routes requests
 *   - Marketplace: Providers compete on price/latency, earn sats
 *
 * Phase 1: HTTP-compatible inference proxy (wraps local/remote LLM APIs)
 * Phase 2: Native ONNX/GGML runtime for local inference
 *
 * Capabilities:
 *   - infer: Run inference on a model
 *   - models: List available models
 *   - register-model: Register a model endpoint
 *   - remove-model: Remove a model endpoint
 *   - embed: Generate embeddings
 *   - status: Provider status and queue depth
 */

import { ServiceProvider } from 'p2p-hiverelay/core/services/provider.js'
import { randomBytes } from 'crypto'
import dns from 'node:dns/promises'
import net from 'node:net'

const JOB_STATES = {
  PENDING: 'pending',
  RUNNING: 'running',
  COMPLETE: 'complete',
  FAILED: 'failed'
}

export class AIService extends ServiceProvider {
  constructor (opts = {}) {
    super()
    this.models = new Map() // modelId -> ModelEntry
    this.jobs = new Map() // jobId -> InferenceJob
    this.maxQueue = opts.maxQueue ?? 100
    this.maxJobsPerCaller = opts.maxJobsPerCaller ?? 20
    this.maxConcurrent = opts.maxConcurrent ?? 2
    this.maxInputBytes = opts.maxInputBytes ?? 256 * 1024
    this.maxOutputBytes = opts.maxOutputBytes ?? 512 * 1024
    this.allowRemoteModelRegistration = opts.allowRemoteModelRegistration === true
    this.maxCompletedJobAge = opts.maxCompletedJobAge || 3600_000
    this._running = 0
    this._queue = []
    this._cleanupTimer = null
  }

  manifest () {
    return {
      name: 'ai',
      version: '1.0.0',
      description: 'AI/ML inference as a decentralized service — LLM, embeddings, classification',
      capabilities: [
        'infer', 'list-models', 'register-model',
        'remove-model', 'embed', 'status'
      ]
    }
  }

  async start () {
    this._cleanupTimer = setInterval(() => this._cleanupCompletedJobs(), 60_000)
    if (this._cleanupTimer.unref) this._cleanupTimer.unref()
  }

  /**
   * Register a model endpoint.
   * @param {object} params - { modelId, type, endpoint?, handler? }
   *   endpoint: HTTP URL for remote model (e.g., http://localhost:11434/api/generate)
   *   handler: async function for local/custom inference
   */
  async 'register-model' (params, context = {}) {
    if (!this._isAdminContext(context) && !this.allowRemoteModelRegistration) {
      throw new Error('ACCESS_DENIED: model registration requires relay-admin/local context')
    }

    const { modelId, type, endpoint, config } = params
    if (!modelId || !type) throw new Error('AI_MISSING_PARAMS: need modelId and type')

    if (this.models.has(modelId)) throw new Error(`AI_MODEL_EXISTS: ${modelId}`)

    // Validate endpoint URL if provided. The same helper re-validates and
    // pins the connection at inference time (see _httpInfer), so a model that
    // passes here cannot be rebound to a private target later.
    if (endpoint) {
      await this._assertEndpointSafe(endpoint)
    }

    const entry = {
      modelId,
      type, // 'llm', 'embedding', 'classification', 'image', 'custom'
      endpoint: endpoint || null,
      config: config || {},
      handler: null, // Set programmatically, not via RPC
      registeredAt: Date.now(),
      stats: { requests: 0, errors: 0, totalTokens: 0, totalLatencyMs: 0 }
    }

    this.models.set(modelId, entry)
    return { modelId, type, registered: true }
  }

  /**
   * Register a handler function directly (programmatic, not via RPC).
   */
  registerHandler (modelId, handler) {
    const entry = this.models.get(modelId)
    if (!entry) throw new Error(`AI_MODEL_NOT_FOUND: ${modelId}`)
    entry.handler = handler
  }

  async 'remove-model' (params, context = {}) {
    if (!this._isAdminContext(context) && !this.allowRemoteModelRegistration) {
      throw new Error('ACCESS_DENIED: model removal requires relay-admin/local context')
    }
    const removed = this.models.delete(params.modelId)
    return { modelId: params.modelId, removed }
  }

  async 'list-models' () {
    const list = []
    for (const [id, entry] of this.models) {
      list.push({
        modelId: id,
        type: entry.type,
        hasEndpoint: !!entry.endpoint,
        hasHandler: !!entry.handler,
        stats: entry.stats
      })
    }
    return list
  }

  /**
   * Run inference on a model.
   */
  async infer (params, context = {}) {
    const { modelId, input, options } = params
    if (!modelId || input === undefined) {
      throw new Error('AI_MISSING_PARAMS: need modelId and input')
    }

    const model = this.models.get(modelId)
    if (!model) throw new Error(`AI_MODEL_NOT_FOUND: ${modelId}`)

    this._assertSizeLimit(input, this.maxInputBytes, 'AI_INPUT_TOO_LARGE')

    if (this._countActiveJobs() >= this.maxQueue) {
      throw new Error('AI_QUEUE_FULL')
    }

    const owner = this._callerKey(context)
    if (this._countActiveJobs(owner) >= this.maxJobsPerCaller) {
      throw new Error('AI_CALLER_QUEUE_FULL')
    }

    const jobId = randomBytes(16).toString('hex')
    const job = {
      id: jobId,
      modelId,
      input,
      options: options || {},
      owner,
      state: JOB_STATES.PENDING,
      result: null,
      error: null,
      createdAt: Date.now(),
      completedAt: null
    }

    this.jobs.set(jobId, job)

    // If we can run immediately, do it
    if (this._running < this.maxConcurrent) {
      await this._runJob(job, model)
    } else {
      this._queue.push(jobId)
    }

    return {
      jobId,
      state: job.state,
      result: job.state === JOB_STATES.COMPLETE ? job.result : undefined,
      error: job.state === JOB_STATES.FAILED ? job.error : undefined
    }
  }

  /**
   * Generate embeddings.
   */
  async embed (params, context = {}) {
    const { modelId, input } = params
    if (!modelId || !input) throw new Error('AI_MISSING_PARAMS: need modelId and input')
    this._assertSizeLimit(input, this.maxInputBytes, 'AI_INPUT_TOO_LARGE')

    const model = this.models.get(modelId)
    if (!model) throw new Error(`AI_MODEL_NOT_FOUND: ${modelId}`)

    if (model.type !== 'embedding' && model.type !== 'llm') {
      throw new Error('AI_WRONG_TYPE: model does not support embeddings')
    }

    const startTime = Date.now()
    let result

    if (model.handler) {
      result = await model.handler({
        type: 'embed',
        input,
        options: params.options || {},
        context
      })
    } else if (model.endpoint) {
      result = await this._httpInfer(model, { type: 'embed', input })
    } else {
      throw new Error('AI_NO_BACKEND: model has no handler or endpoint')
    }

    this._assertSizeLimit(result, this.maxOutputBytes, 'AI_OUTPUT_TOO_LARGE')

    model.stats.requests++
    model.stats.totalLatencyMs += Date.now() - startTime

    return result
  }

  async status () {
    const modelStats = {}
    for (const [id, model] of this.models) {
      modelStats[id] = {
        type: model.type,
        avgLatencyMs: model.stats.requests > 0
          ? Math.round(model.stats.totalLatencyMs / model.stats.requests)
          : 0,
        ...model.stats
      }
    }

    return {
      models: this.models.size,
      queueDepth: this._queue.length,
      running: this._running,
      maxConcurrent: this.maxConcurrent,
      totalJobs: this.jobs.size,
      modelStats
    }
  }

  async _runJob (job, model) {
    this._running++
    job.state = JOB_STATES.RUNNING
    const startTime = Date.now()

    try {
      let result
      if (model.handler) {
        result = await model.handler({ type: 'infer', input: job.input, options: job.options })
      } else if (model.endpoint) {
        result = await this._httpInfer(model, { type: 'infer', input: job.input })
      } else {
        throw new Error('AI_NO_BACKEND: model has no handler or endpoint')
      }

      this._assertSizeLimit(result, this.maxOutputBytes, 'AI_OUTPUT_TOO_LARGE')
      job.state = JOB_STATES.COMPLETE
      job.result = result
      job.completedAt = Date.now()

      model.stats.requests++
      model.stats.totalLatencyMs += Date.now() - startTime
      if (result && result.tokens) model.stats.totalTokens += result.tokens
    } catch (err) {
      job.state = JOB_STATES.FAILED
      job.error = err.message
      job.completedAt = Date.now()
      model.stats.errors++
    } finally {
      this._running--
      this._processQueue()
    }
  }

  _processQueue () {
    while (this._running < this.maxConcurrent && this._queue.length > 0) {
      const jobId = this._queue.shift()
      const job = this.jobs.get(jobId)
      if (!job || job.state !== JOB_STATES.PENDING) continue
      const model = this.models.get(job.modelId)
      if (!model) continue
      this._runJob(job, model)
    }
  }

  /**
   * HTTP inference for endpoint-based models.
   * Supports Ollama and OpenAI-compatible APIs.
   *
   * Re-validates the endpoint at call time and pins the socket to the exact
   * address(es) that just passed validation. This closes the DNS-rebinding
   * TOCTOU window: even if a hostname's DNS record changed to a private/
   * internal target after register-model, the connection can only land on a
   * vetted address.
   */
  async _httpInfer (model, request) {
    const { url, pinnedAddresses } = await this._assertEndpointSafe(model.endpoint)

    const isHttps = url.protocol === 'https:'
    const { request: httpRequest } = await import(isHttps ? 'node:https' : 'node:http')
    const format = model.config.format || this._detectFormat(url)

    const payload = this._buildPayload(model, request, format)
    const path = this._resolvePath(url, request, format)
    const maxBytes = this.maxOutputBytes

    // Pin DNS resolution to the addresses we already validated. Node skips
    // `lookup` entirely for IP-literal hostnames (already validated above).
    const pinnedLookup = (hostname, options, callback) => {
      const cb = typeof options === 'function' ? options : callback
      const opts = typeof options === 'function' ? {} : (options || {})
      if (opts.all) {
        cb(null, pinnedAddresses.map(r => ({ address: r.address, family: r.family })))
      } else {
        cb(null, pinnedAddresses[0].address, pinnedAddresses[0].family)
      }
    }

    return new Promise((resolve, reject) => {
      const req = httpRequest({
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port || (isHttps ? 443 : 80),
        path,
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        timeout: model.config.timeout || 60_000,
        lookup: pinnedLookup
      }, (res) => {
        let body = ''
        let aborted = false
        res.on('data', chunk => {
          if (aborted) return
          body += chunk
          if (body.length > maxBytes) {
            aborted = true
            req.destroy()
            reject(new Error('AI_OUTPUT_TOO_LARGE'))
          }
        })
        res.on('end', () => {
          if (aborted) return
          try {
            const parsed = JSON.parse(body)
            resolve(this._normalizeResponse(parsed, format))
          } catch {
            resolve({ raw: body })
          }
        })
      })

      req.on('error', reject)
      req.on('timeout', () => {
        req.destroy()
        reject(new Error('AI_TIMEOUT'))
      })

      req.write(JSON.stringify(payload))
      req.end()
    })
  }

  /**
   * Parse, validate, and resolve an endpoint URL for SSRF safety.
   * Returns { url, pinnedAddresses } where pinnedAddresses are the vetted
   * IP records the caller should pin the connection to.
   *
   * Rules:
   *   - Only http/https.
   *   - An explicit loopback host (`localhost`, 127.0.0.0/8, ::1) is allowed
   *     for local models (Ollama, etc.).
   *   - A literal non-loopback IP must be public.
   *   - A hostname is resolved via dns.lookup({ all: true }) and EVERY
   *     resolved record must be public — a single private answer is rejected.
   */
  async _assertEndpointSafe (endpoint) {
    let url
    try { url = new URL(endpoint) } catch { throw new Error('AI_INVALID_ENDPOINT: malformed URL') }
    if (!['http:', 'https:'].includes(url.protocol)) {
      throw new Error('AI_INVALID_ENDPOINT: only http/https allowed')
    }

    let host = url.hostname
    if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1)

    const family = net.isIP(host) // 0 if not an IP literal
    const explicitLoopback = host === 'localhost' || (family !== 0 && this._isLoopbackIP(host))

    if (explicitLoopback) {
      // Local model endpoint — permitted. Pin to loopback.
      const pinnedAddresses = family !== 0
        ? [{ address: host, family }]
        : [{ address: '127.0.0.1', family: 4 }]
      return { url, pinnedAddresses }
    }

    if (family !== 0) {
      // Literal non-loopback IP — must be public.
      if (this._isPrivateIP(host)) {
        throw new Error('AI_INVALID_ENDPOINT: private/internal IPs not allowed for remote models')
      }
      return { url, pinnedAddresses: [{ address: host, family }] }
    }

    // Hostname: resolve ALL records and require every one to be public.
    let resolved
    try {
      resolved = await dns.lookup(host, { all: true })
    } catch {
      throw new Error('AI_INVALID_ENDPOINT: could not resolve hostname')
    }
    if (!resolved || resolved.length === 0) {
      throw new Error('AI_INVALID_ENDPOINT: hostname did not resolve')
    }
    for (const rec of resolved) {
      if (this._isPrivateIP(rec.address)) {
        throw new Error('AI_INVALID_ENDPOINT: hostname resolves to private/internal IP')
      }
    }
    return { url, pinnedAddresses: resolved.map(r => ({ address: r.address, family: r.family })) }
  }

  _detectFormat (url) {
    if (url.port === '11434' || url.pathname.startsWith('/api/')) return 'ollama'
    if (url.pathname.includes('/v1/')) return 'openai'
    return 'generic'
  }

  _resolvePath (url, request, format) {
    // If endpoint already has a specific path, use it
    if (url.pathname !== '/' && url.pathname !== '') return url.pathname

    if (format === 'ollama') {
      if (request.type === 'embed') return '/api/embed'
      return Array.isArray(request.input) ? '/api/chat' : '/api/generate'
    }
    if (format === 'openai') {
      if (request.type === 'embed') return '/v1/embeddings'
      return Array.isArray(request.input) ? '/v1/chat/completions' : '/v1/completions'
    }
    return url.pathname || '/'
  }

  _buildPayload (model, request, format) {
    const input = request.input

    if (format === 'ollama') {
      if (request.type === 'embed') {
        return { model: model.modelId, input }
      }
      // Chat-style input: array of messages
      if (Array.isArray(input)) {
        return { model: model.modelId, messages: input, stream: false }
      }
      // Simple prompt string
      return { model: model.modelId, prompt: String(input), stream: false }
    }

    if (format === 'openai') {
      if (request.type === 'embed') {
        return { model: model.modelId, input }
      }
      if (Array.isArray(input)) {
        return { model: model.modelId, messages: input, stream: false }
      }
      return { model: model.modelId, prompt: String(input), stream: false }
    }

    // Generic: pass through as-is
    return { model: model.modelId, ...request }
  }

  _normalizeResponse (parsed, format) {
    if (format === 'ollama') {
      return {
        text: parsed.response || parsed.message?.content || null,
        tokens: parsed.eval_count || 0,
        model: parsed.model || null,
        done: parsed.done,
        raw: parsed
      }
    }
    if (format === 'openai') {
      const choice = parsed.choices?.[0]
      return {
        text: choice?.text || choice?.message?.content || null,
        tokens: parsed.usage?.total_tokens || 0,
        model: parsed.model || null,
        raw: parsed
      }
    }
    return parsed
  }

  async stop () {
    if (this._cleanupTimer) {
      clearInterval(this._cleanupTimer)
      this._cleanupTimer = null
    }
    for (const [, job] of this.jobs) {
      if (job.state === JOB_STATES.PENDING) {
        job.state = JOB_STATES.FAILED
        job.error = 'SERVICE_STOPPED'
        job.completedAt = Date.now()
      }
    }
    this._queue = []
    this.jobs.clear()
  }

  _callerKey (context = {}) {
    if (context.remotePubkey) return context.remotePubkey
    if (context.userId) return context.userId
    if (context.caller === 'local' || context.role === 'local') return 'local'
    return 'anonymous'
  }

  _isAdminContext (context) {
    if (!context) return false
    return context.role === 'relay-admin' || context.role === 'local' || context.caller === 'local'
  }

  /**
   * Normalize an IP string: lowercase, strip IPv6 zone id, and decode
   * IPv4-mapped IPv6 forms (::ffff:192.168.0.1 and ::ffff:c0a8:0001) to their
   * dotted-quad equivalent so range checks can't be bypassed.
   */
  _normalizeIP (ip) {
    if (ip === null || ip === undefined) return ''
    let v = String(ip).toLowerCase().trim()
    const zone = v.indexOf('%')
    if (zone !== -1) v = v.slice(0, zone)
    if (v.startsWith('::ffff:')) {
      const tail = v.slice(7)
      if (net.isIPv4(tail)) {
        v = tail
      } else {
        const m = tail.match(/^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/)
        if (m) {
          const hi = parseInt(m[1], 16)
          const lo = parseInt(m[2], 16)
          v = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`
        }
      }
    }
    return v
  }

  _isLoopbackIP (ip) {
    const v = this._normalizeIP(ip)
    if (v === '::1') return true
    if (/^127\./.test(v)) return true
    return false
  }

  _isPrivateIP (ip) {
    if (!ip) return true
    const v = this._normalizeIP(ip)
    // Unspecified address
    if (v === '0.0.0.0' || v === '::' || v === '0:0:0:0:0:0:0:0') return true
    // Anything that isn't a recognizable IP after normalization fails closed.
    const fam = net.isIP(v)
    if (fam === 0) return true

    if (fam === 4) {
      // 0.0.0.0/8 ("this network")
      if (/^0\./.test(v)) return true
      // 127.0.0.0/8 loopback
      if (/^127\./.test(v)) return true
      // 10.0.0.0/8
      if (/^10\./.test(v)) return true
      // 172.16.0.0/12
      if (/^172\.(1[6-9]|2\d|3[01])\./.test(v)) return true
      // 192.168.0.0/16
      if (/^192\.168\./.test(v)) return true
      // 169.254.0.0/16 link-local
      if (/^169\.254\./.test(v)) return true
      // 100.64.0.0/10 carrier-grade NAT
      if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(v)) return true
      return false
    }

    // IPv6
    if (v === '::1') return true            // loopback
    if (/^fe[89ab]/.test(v)) return true     // link-local fe80::/10
    if (/^f[cd]/.test(v)) return true        // unique local fc00::/7
    return false
  }

  _cleanupCompletedJobs () {
    const now = Date.now()
    for (const [id, job] of this.jobs) {
      if ((job.state === 'complete' || job.state === 'failed' || job.state === 'cancelled') &&
          job.completedAt && (now - job.completedAt) > this.maxCompletedJobAge) {
        this.jobs.delete(id)
      }
    }
  }

  _countActiveJobs (owner = null) {
    let total = 0
    for (const [, job] of this.jobs) {
      if (owner && job.owner !== owner) continue
      if (job.state === JOB_STATES.PENDING || job.state === JOB_STATES.RUNNING) total++
    }
    return total
  }

  _assertSizeLimit (value, limit, code) {
    if (!limit || limit <= 0) return
    let size = 0
    try {
      size = Buffer.byteLength(JSON.stringify(value || null))
    } catch {
      throw new Error(`${code}: payload is not serializable`)
    }
    if (size > limit) {
      throw new Error(`${code}: payload exceeds ${limit} bytes`)
    }
  }
}
