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
 * Phase 2: Optional qvac-backed local inference via @qvac/sdk
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
    const aiOpts = opts.ai && typeof opts.ai === 'object' ? opts.ai : {}
    const cfg = { ...opts, ...aiOpts }
    const qvacCfg = cfg.qvac === false ? { enabled: false } : (cfg.qvac || {})

    this.models = new Map() // modelId -> ModelEntry
    this.jobs = new Map() // jobId -> InferenceJob
    this.maxQueue = cfg.maxQueue ?? 100
    this.maxJobsPerCaller = cfg.maxJobsPerCaller ?? 20
    this.maxConcurrent = cfg.maxConcurrent ?? 2
    this.maxInputBytes = cfg.maxInputBytes ?? 256 * 1024
    this.maxOutputBytes = cfg.maxOutputBytes ?? 512 * 1024
    this.allowRemoteModelRegistration = cfg.allowRemoteModelRegistration === true
    this.maxCompletedJobAge = cfg.maxCompletedJobAge || 3600_000
    this.qvac = {
      enabled: qvacCfg.enabled !== false,
      moduleName: qvacCfg.moduleName || qvacCfg.module || '@qvac/sdk',
      importModule: qvacCfg.importModule || null,
      prefer: qvacCfg.prefer === true || qvacCfg.preferQvac === true || cfg.preferQvac === true,
      autoUnload: qvacCfg.autoUnload !== false,
      failOnUnavailable: qvacCfg.failOnUnavailable === true,
      models: Array.isArray(qvacCfg.models) ? qvacCfg.models : [],
      checked: !!qvacCfg.sdk,
      available: !!qvacCfg.sdk,
      error: null
    }
    this._qvacSdk = qvacCfg.sdk || null
    this._qvacLoadPromise = null
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
    await this._registerConfiguredQvacModels()
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

    const qvac = this._buildQvacModelConfig(params)
    const backend = this._resolveModelBackend(params, qvac)

    const entry = {
      modelId,
      type, // 'llm', 'embedding', 'classification', 'image', 'custom'
      backend,
      endpoint: endpoint || null,
      config: config || {},
      qvac,
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
    const entry = this.models.get(params.modelId)
    if (entry) await this._unloadQvacModel(entry)
    const removed = this.models.delete(params.modelId)
    return { modelId: params.modelId, removed }
  }

  async 'list-models' () {
    const list = []
    for (const [id, entry] of this.models) {
      list.push({
        modelId: id,
        type: entry.type,
        backend: this._publicBackend(entry),
        hasEndpoint: !!entry.endpoint,
        hasHandler: !!entry.handler,
        qvac: entry.qvac ? this._publicQvacModelStatus(entry) : undefined,
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
      context,
      state: JOB_STATES.PENDING,
      result: null,
      error: null,
      createdAt: Date.now(),
      completedAt: null
    }

    this.jobs.set(jobId, job)

    // If we can run immediately, do it
    if (this._running < this.maxConcurrent) {
      await this._runJob(job, model, context)
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
    const result = await this._executeModel(model, {
      type: 'embed',
      input,
      options: params.options || {},
      context
    })

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
      qvac: this._qvacStatus(),
      modelStats
    }
  }

  async _runJob (job, model, context = {}) {
    this._running++
    job.state = JOB_STATES.RUNNING
    const startTime = Date.now()

    try {
      const result = await this._executeModel(model, {
        type: 'infer',
        input: job.input,
        options: job.options,
        context: context || job.context || {}
      })

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
      this._runJob(job, model, job.context || {})
    }
  }

  async _executeModel (model, request) {
    if (model.handler) {
      return model.handler({
        type: request.type,
        input: request.input,
        options: request.options || {},
        context: request.context || {}
      })
    }

    if (this._shouldUseQvac(model)) {
      try {
        return await this._qvacInfer(model, request)
      } catch (err) {
        if (this._isQvacUnavailableError(err) && model.endpoint && model.qvac?.fallbackToHttp !== false) {
          return this._httpInfer(model, { type: request.type, input: request.input })
        }
        throw err
      }
    }

    if (model.endpoint) {
      return this._httpInfer(model, { type: request.type, input: request.input })
    }

    if (model.qvac) {
      throw this._qvacUnavailableError('qvac backend is configured but @qvac/sdk is not available')
    }

    throw new Error('AI_NO_BACKEND: model has no handler or endpoint')
  }

  _resolveModelBackend (params, qvac) {
    const requested = params.backend || params.config?.backend
    if (requested) return requested
    if (qvac) return 'qvac'
    if (params.endpoint) return 'http'
    return null
  }

  _publicBackend (entry) {
    if (entry.handler) return 'handler'
    if (entry.backend) return entry.backend
    if (entry.endpoint) return 'http'
    if (entry.qvac) return 'qvac'
    return null
  }

  _buildQvacModelConfig (params) {
    const config = params.config || {}
    const qvac = params.qvac || config.qvac || null
    const hasQvacFields = params.backend === 'qvac' ||
      config.backend === 'qvac' ||
      !!qvac ||
      params.modelSrc !== undefined ||
      params.qvacModelId !== undefined ||
      params.loadedModelId !== undefined ||
      params.modelConfig !== undefined ||
      params.delegate !== undefined

    if (!hasQvacFields) return null

    const modelSrc = params.modelSrc ??
      qvac?.modelSrc ??
      config.modelSrc ??
      null
    const loadedModelId = params.loadedModelId ??
      params.qvacModelId ??
      qvac?.loadedModelId ??
      qvac?.qvacModelId ??
      null
    const modelType = params.modelType ??
      qvac?.modelType ??
      config.modelType ??
      this._inferQvacModelType(params.type)

    return {
      modelSrc: loadedModelId ? modelSrc : (modelSrc ?? params.modelId),
      modelType,
      modelConfig: params.modelConfig ?? qvac?.modelConfig ?? config.modelConfig ?? {},
      loadedModelId,
      delegate: params.delegate ?? qvac?.delegate ?? config.delegate ?? null,
      loadOptions: qvac?.loadOptions || {},
      completionOptions: qvac?.completionOptions || {},
      embedOptions: qvac?.embedOptions || {},
      fallbackToHttp: qvac?.fallbackToHttp !== false,
      unloadOnStop: qvac?.unloadOnStop ?? qvac?.autoUnload ?? this.qvac.autoUnload,
      loadedByHiveRelay: false,
      loadedAt: loadedModelId ? Date.now() : null
    }
  }

  _inferQvacModelType (type) {
    if (type === 'embedding') return 'embedding'
    if (type === 'llm') return 'llm'
    return type || undefined
  }

  _shouldUseQvac (model) {
    if (!model.qvac) return false
    if (model.backend === 'qvac') return true
    if (this.qvac.prefer && !model.handler) return true
    return !model.endpoint
  }

  async _qvacInfer (model, request) {
    if (request.type === 'embed') return this._qvacEmbed(model, request)
    return this._qvacCompletion(model, request)
  }

  async _loadQvacSdk () {
    if (this._qvacSdk) return this._qvacSdk
    if (!this.qvac.enabled) {
      throw this._qvacUnavailableError('qvac backend is disabled')
    }
    if (this._qvacLoadPromise) return this._qvacLoadPromise

    this._qvacLoadPromise = (async () => {
      try {
        const loader = this.qvac.importModule || ((name) => import(name))
        const sdk = await loader(this.qvac.moduleName)
        if (!sdk || typeof sdk !== 'object') {
          throw new Error('module did not export an SDK object')
        }
        this._qvacSdk = sdk
        this.qvac.checked = true
        this.qvac.available = true
        this.qvac.error = null
        return sdk
      } catch (err) {
        this.qvac.checked = true
        this.qvac.available = false
        this.qvac.error = err.message || String(err)
        this._qvacLoadPromise = null
        throw this._qvacUnavailableError(`${this.qvac.moduleName} is not installed or could not be loaded (${this.qvac.error})`)
      }
    })()

    return this._qvacLoadPromise
  }

  async _ensureQvacModel (model) {
    const qvac = model.qvac
    if (!qvac) throw this._qvacUnavailableError('model is not configured for qvac')
    if (qvac.loadedModelId) return qvac.loadedModelId

    const sdk = await this._loadQvacSdk()
    if (typeof sdk.loadModel !== 'function') {
      throw new Error('AI_QVAC_UNSUPPORTED: @qvac/sdk does not export loadModel')
    }
    if (qvac.modelSrc === undefined || qvac.modelSrc === null || qvac.modelSrc === '') {
      throw new Error('AI_QVAC_MODEL_NOT_CONFIGURED: qvac model needs modelSrc or loadedModelId')
    }

    const loadParams = {
      ...qvac.loadOptions,
      modelSrc: qvac.modelSrc
    }
    if (qvac.modelType) loadParams.modelType = qvac.modelType
    if (qvac.modelConfig && Object.keys(qvac.modelConfig).length > 0) {
      loadParams.modelConfig = qvac.modelConfig
    }
    if (qvac.delegate) loadParams.delegate = qvac.delegate

    const loaded = await sdk.loadModel(loadParams)
    qvac.loadedModelId = this._extractQvacModelId(loaded)
    qvac.loadedByHiveRelay = true
    qvac.loadedAt = Date.now()
    return qvac.loadedModelId
  }

  _extractQvacModelId (loaded) {
    if (typeof loaded === 'string') return loaded
    if (loaded && typeof loaded === 'object') {
      if (typeof loaded.modelId === 'string') return loaded.modelId
      if (typeof loaded.id === 'string') return loaded.id
      if (typeof loaded.value === 'string') return loaded.value
    }
    return String(loaded)
  }

  async _qvacCompletion (model, request) {
    const sdk = await this._loadQvacSdk()
    if (typeof sdk.completion !== 'function') {
      throw new Error('AI_QVAC_UNSUPPORTED: @qvac/sdk does not export completion')
    }

    const loadedModelId = await this._ensureQvacModel(model)
    const qvacOptions = request.options?.qvac || {}
    const completionParams = {
      ...model.qvac.completionOptions,
      ...qvacOptions,
      modelId: loadedModelId,
      history: this._toQvacHistory(request.input)
    }
    if (completionParams.stream === undefined) completionParams.stream = false
    if (model.qvac.delegate && completionParams.delegate === undefined) {
      completionParams.delegate = model.qvac.delegate
    }

    const run = sdk.completion(completionParams)
    const final = await this._resolveQvacRun(run)
    return this._normalizeQvacCompletion(final, model, loadedModelId)
  }

  async _qvacEmbed (model, request) {
    const sdk = await this._loadQvacSdk()
    if (typeof sdk.embed !== 'function') {
      throw new Error('AI_QVAC_UNSUPPORTED: @qvac/sdk does not export embed')
    }

    const loadedModelId = await this._ensureQvacModel(model)
    const qvacOptions = request.options?.qvac || {}
    const embedParams = {
      ...model.qvac.embedOptions,
      ...qvacOptions,
      modelId: loadedModelId,
      text: this._toQvacText(request.input)
    }
    if (model.qvac.delegate && embedParams.delegate === undefined) {
      embedParams.delegate = model.qvac.delegate
    }

    const result = await sdk.embed(embedParams)
    return this._normalizeQvacEmbed(result, model, loadedModelId)
  }

  _toQvacHistory (input) {
    if (Array.isArray(input)) return input.map(msg => this._normalizeQvacMessage(msg))
    if (input && typeof input === 'object') {
      if (Array.isArray(input.history)) return input.history.map(msg => this._normalizeQvacMessage(msg))
      if (Array.isArray(input.messages)) return input.messages.map(msg => this._normalizeQvacMessage(msg))
      if (input.prompt !== undefined) {
        return [{ role: 'user', content: String(input.prompt) }]
      }
      if (input.text !== undefined) {
        return [{ role: 'user', content: String(input.text) }]
      }
    }
    return [{ role: 'user', content: String(input) }]
  }

  _normalizeQvacMessage (msg) {
    if (typeof msg === 'string') return { role: 'user', content: msg }
    if (!msg || typeof msg !== 'object') return { role: 'user', content: String(msg) }
    return {
      role: msg.role || 'user',
      content: msg.content !== undefined ? String(msg.content) : String(msg.text ?? '')
    }
  }

  _toQvacText (input) {
    if (typeof input === 'string') return input
    if (input && typeof input === 'object') {
      if (input.text !== undefined) return String(input.text)
      if (input.input !== undefined) return String(input.input)
      if (input.prompt !== undefined) return String(input.prompt)
    }
    return String(input)
  }

  async _resolveQvacRun (run) {
    let value = run
    if (value && typeof value.then === 'function') value = await value
    if (!value) return value
    if (value.final && typeof value.final.then === 'function') return value.final
    if (typeof value.final === 'function') return value.final()
    if (value.text && typeof value.text.then === 'function') {
      return { text: await value.text, stats: await this._maybeAwait(value.stats) }
    }
    if (value.tokenStream && value.tokenStream[Symbol.asyncIterator]) {
      return { text: await this._collectAsyncText(value.tokenStream), stats: await this._maybeAwait(value.stats) }
    }
    if (value.events && value.events[Symbol.asyncIterator]) {
      return { text: await this._collectQvacEventText(value.events), stats: await this._maybeAwait(value.stats) }
    }
    return value
  }

  async _maybeAwait (value) {
    if (value && typeof value.then === 'function') return value
    return value
  }

  async _collectAsyncText (iterable) {
    let text = ''
    for await (const chunk of iterable) text += String(chunk)
    return text
  }

  async _collectQvacEventText (events) {
    let text = ''
    for await (const event of events) {
      if (event?.type === 'contentDelta') text += event.text || ''
      else if (event?.text && event?.type !== 'thinkingDelta') text += event.text
    }
    return text
  }

  _normalizeQvacCompletion (final, model, loadedModelId) {
    if (typeof final === 'string') {
      return {
        text: final,
        tokens: 0,
        model: model.modelId,
        backend: 'qvac',
        qvac: { modelId: loadedModelId },
        raw: final
      }
    }

    const stats = final?.stats || final?.usage || {}
    return {
      text: final?.content ?? final?.text ?? final?.rawText ?? final?.message?.content ?? final?.output ?? final?.response ?? null,
      tokens: this._qvacTokenCount(final, stats),
      model: model.modelId,
      backend: 'qvac',
      qvac: { modelId: loadedModelId },
      raw: final
    }
  }

  _normalizeQvacEmbed (result, model, loadedModelId) {
    const embedding = Array.isArray(result) ? result : (result?.embedding || result?.embeddings || null)
    const stats = result?.stats || result?.usage || {}
    return {
      embedding,
      tokens: this._qvacTokenCount(result, stats),
      model: model.modelId,
      backend: 'qvac',
      qvac: { modelId: loadedModelId },
      raw: result
    }
  }

  _qvacTokenCount (result, stats) {
    return stats?.totalTokens ??
      stats?.total_tokens ??
      stats?.tokens ??
      stats?.promptTokens ??
      stats?.prompt_tokens ??
      result?.tokens ??
      0
  }

  _qvacUnavailableError (message) {
    const err = new Error(`AI_QVAC_UNAVAILABLE: ${message}`)
    err.qvacUnavailable = true
    return err
  }

  _isQvacUnavailableError (err) {
    return !!err?.qvacUnavailable || String(err?.message || '').startsWith('AI_QVAC_UNAVAILABLE')
  }

  _publicQvacModelStatus (entry) {
    return {
      loaded: !!entry.qvac.loadedModelId,
      loadedByHiveRelay: entry.qvac.loadedByHiveRelay === true,
      modelType: entry.qvac.modelType || null,
      hasModelSrc: entry.qvac.modelSrc !== undefined && entry.qvac.modelSrc !== null,
      delegated: !!entry.qvac.delegate
    }
  }

  _qvacStatus () {
    return {
      enabled: this.qvac.enabled,
      module: this.qvac.moduleName,
      checked: this.qvac.checked,
      available: this._qvacSdk ? true : this.qvac.available,
      error: this.qvac.error
    }
  }

  async _registerConfiguredQvacModels () {
    for (const spec of this.qvac.models) {
      if (!spec || !spec.modelId || this.models.has(spec.modelId)) continue
      await this['register-model']({
        ...spec,
        backend: spec.backend || 'qvac',
        qvac: spec.qvac || {
          modelSrc: spec.modelSrc,
          modelType: spec.modelType,
          modelConfig: spec.modelConfig,
          delegate: spec.delegate,
          loadedModelId: spec.loadedModelId,
          completionOptions: spec.completionOptions,
          embedOptions: spec.embedOptions
        }
      }, { role: 'local' })

      if (spec.preload === true) {
        const model = this.models.get(spec.modelId)
        try {
          await this._ensureQvacModel(model)
        } catch (err) {
          if (this.qvac.failOnUnavailable) throw err
        }
      }
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
    await this._unloadQvacModels()
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

  async _unloadQvacModels () {
    for (const [, model] of this.models) {
      await this._unloadQvacModel(model)
    }
  }

  async _unloadQvacModel (model) {
    if (!this._qvacSdk || typeof this._qvacSdk.unloadModel !== 'function') return false
    const qvac = model.qvac
    if (!qvac?.loadedModelId || qvac.loadedByHiveRelay !== true || qvac.unloadOnStop === false) return false
    try {
      await this._qvacSdk.unloadModel({ modelId: qvac.loadedModelId })
      qvac.loadedModelId = null
      qvac.loadedByHiveRelay = false
      qvac.loadedAt = null
      return true
    } catch (_) {
      // Stop/remove should not make the service registry fail because a
      // native runtime could not unload a model during shutdown.
      return false
    }
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
    if (v === '::1') return true // loopback
    if (/^fe[89ab]/.test(v)) return true // link-local fe80::/10
    if (/^f[cd]/.test(v)) return true // unique local fc00::/7
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
