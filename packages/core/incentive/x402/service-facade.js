import {
  X402_PROTOCOL_VERSION,
  normalizeX402Config,
  x402SdkRoutes
} from './config.js'
import { X402ClaimStore } from './claim-store.js'

const PAYMENT_SIGNATURE_HEADER = 'payment-signature'
const IDEMPOTENCY_HEADER = 'x-hiverelay-idempotency-key'
const NO_STORE_HEADERS = Object.freeze({
  'Cache-Control': 'no-store, private, max-age=0',
  Pragma: 'no-cache',
  Vary: 'PAYMENT-SIGNATURE'
})

export class X402ServiceFacade {
  constructor (opts = {}) {
    this.config = normalizeX402Config(opts.config)
    this.serverFactory = opts.serverFactory || createOfficialX402Server
    this.claims = opts.claimStore || new X402ClaimStore({
      ttlMs: this.config.claimTtlMs,
      maxClaims: this.config.maxClaims
    })
    this._serverPromise = null
  }

  route (method, path) {
    if (!this.config.enabled) return null
    return this.config.routes[`${method} ${path}`] || null
  }

  async handle ({ req, url, readBody, execute }) {
    const path = url.pathname
    const route = this.route(req.method, path)
    if (!route) return { handled: false }

    let server
    try {
      server = await this._server()
    } catch (err) {
      return jsonResult(503, {
        error: 'x402 payment verifier is unavailable',
        errorCode: 'x402-unavailable',
        detail: safeErrorMessage(err)
      }, { 'Retry-After': '30' })
    }

    const duplicateHeader = hasDuplicateHeader(req, PAYMENT_SIGNATURE_HEADER)
    const adapter = createNodeHttpAdapter(req, url, this.config.publicBaseUrl, duplicateHeader)
    const context = {
      adapter,
      method: req.method,
      path
    }

    if (duplicateHeader) {
      return this._challenge(server, context, 'duplicate PAYMENT-SIGNATURE headers')
    }

    let payment
    try {
      payment = await server.processHTTPRequest(context)
    } catch (err) {
      return jsonResult(503, {
        error: 'x402 payment verification failed',
        errorCode: 'x402-verifier-error',
        detail: safeErrorMessage(err)
      }, { 'Retry-After': '30' })
    }

    if (payment.type === 'no-payment-required') return { handled: false }
    if (payment.type === 'payment-error') return instructionResult(payment.response)

    const paymentHeader = adapter.getHeader(PAYMENT_SIGNATURE_HEADER)
    const claim = this.claims.claim(paymentHeader, `${req.method} ${path}`)
    if (!claim.ok) {
      await cancelVerifiedPayment(payment, 'after_verify_aborted', new Error('payment replay rejected'), 402)
      const reason = claim.full ? 'payment claim capacity reached' : 'payment authorization already claimed'
      return this._challenge(server, context, reason)
    }

    const idempotencyKey = headerValue(req, IDEMPOTENCY_HEADER)
    if (route.requireIdempotencyKey && !validIdempotencyKey(idempotencyKey)) {
      this.claims.release(claim.id)
      await cancelVerifiedPayment(payment, 'handler_failed', new Error('idempotency key required'), 400)
      return jsonResult(400, {
        error: `valid ${IDEMPOTENCY_HEADER} header required`,
        errorCode: 'x402-idempotency-key-required'
      })
    }

    let body
    try {
      body = req.method === 'GET' ? queryParamsObject(url) : await readBody()
    } catch {
      this.claims.release(claim.id)
      await cancelVerifiedPayment(payment, 'handler_failed', new Error('invalid request body'), 400)
      return jsonResult(400, { error: 'invalid body', errorCode: 'invalid-body' })
    }

    let result
    try {
      result = await execute(route, body, {
        transport: 'x402-http',
        caller: 'remote',
        role: 'authenticated-user',
        authenticated: true,
        x402: {
          version: X402_PROTOCOL_VERSION,
          idempotencyKey: idempotencyKey || null,
          requirements: payment.paymentRequirements
        }
      })
    } catch (err) {
      this.claims.release(claim.id)
      await cancelVerifiedPayment(payment, 'handler_threw', err, 400)
      return jsonResult(400, {
        error: safeServiceError(err),
        errorCode: 'x402-service-call-failed'
      })
    }

    const responseBody = { ok: true, result }
    let settlement
    try {
      settlement = await server.processSettlement(
        payment.paymentPayload,
        payment.paymentRequirements,
        payment.declaredExtensions,
        {
          request: context,
          responseBody: Buffer.from(JSON.stringify(responseBody)),
          responseHeaders: { 'Content-Type': 'application/json' }
        }
      )
    } catch (err) {
      return jsonResult(503, {
        error: 'x402 settlement failed after service execution',
        errorCode: 'x402-settlement-error',
        retryWithNewPayment: true,
        detail: safeErrorMessage(err)
      }, { 'Retry-After': '30' })
    }

    if (!settlement.success) return instructionResult(settlement.response)
    return jsonResult(200, responseBody, settlement.headers)
  }

  async _server () {
    if (!this._serverPromise) {
      this._serverPromise = this.serverFactory({
        config: this.config,
        routes: x402SdkRoutes(this.config)
      }).catch(err => {
        this._serverPromise = null
        throw err
      })
    }
    return this._serverPromise
  }

  async _challenge (server, context, reason) {
    const unpaidContext = {
      ...context,
      adapter: withoutPaymentSignature(context.adapter)
    }
    try {
      const challenge = await server.processHTTPRequest(unpaidContext)
      if (challenge.type === 'payment-error') {
        const response = instructionResult(challenge.response)
        response.payload = {
          error: reason,
          errorCode: 'x402-payment-required'
        }
        return response
      }
    } catch {}
    return jsonResult(402, { error: reason, errorCode: 'x402-payment-required' })
  }
}

export async function createOfficialX402Server ({ config, routes }) {
  const [
    { HTTPFacilitatorClient, x402ResourceServer: X402ResourceServer },
    { x402HTTPResourceServer: X402HTTPResourceServer },
    { registerExactEvmScheme }
  ] = await Promise.all([
    import('@x402/core/server'),
    import('@x402/core/http'),
    import('@x402/evm/exact/server')
  ])

  const facilitator = new HTTPFacilitatorClient({ url: config.facilitatorUrl })
  const resourceServer = new X402ResourceServer(facilitator)
  const networks = uniqueNetworks(config)
  registerExactEvmScheme(resourceServer, { networks })
  const httpServer = new X402HTTPResourceServer(resourceServer, routes)
  await httpServer.initialize()
  return httpServer
}

function uniqueNetworks (config) {
  const networks = new Set()
  for (const route of Object.values(config.routes)) {
    for (const accept of route.accepts) networks.add(accept.network)
  }
  return [...networks]
}

function createNodeHttpAdapter (req, url, publicBaseUrl, suppressPaymentHeader) {
  return {
    getHeader (name) {
      if (suppressPaymentHeader && name.toLowerCase() === PAYMENT_SIGNATURE_HEADER) return undefined
      return headerValue(req, name)
    },
    getMethod () {
      return req.method
    },
    getPath () {
      return url.pathname
    },
    getUrl () {
      return new URL(url.pathname + url.search, publicBaseUrl).toString()
    },
    getAcceptHeader () {
      return 'application/json'
    },
    getUserAgent () {
      return headerValue(req, 'user-agent') || ''
    },
    getQueryParams () {
      return queryParamsObject(url)
    },
    getQueryParam (name) {
      const values = url.searchParams.getAll(name)
      if (values.length === 0) return undefined
      return values.length === 1 ? values[0] : values
    }
  }
}

function withoutPaymentSignature (adapter) {
  return {
    ...adapter,
    getHeader (name) {
      if (name.toLowerCase() === PAYMENT_SIGNATURE_HEADER || name.toLowerCase() === 'x-payment') {
        return undefined
      }
      return adapter.getHeader(name)
    }
  }
}

function queryParamsObject (url) {
  const params = {}
  for (const [key, value] of url.searchParams) {
    if (params[key] === undefined) params[key] = value
    else if (Array.isArray(params[key])) params[key].push(value)
    else params[key] = [params[key], value]
  }
  return params
}

function headerValue (req, name) {
  const value = req?.headers?.[name.toLowerCase()]
  if (Array.isArray(value)) return value.length === 1 ? String(value[0]) : undefined
  return value == null ? undefined : String(value)
}

function hasDuplicateHeader (req, name) {
  const lower = name.toLowerCase()
  const raw = Array.isArray(req?.rawHeaders) ? req.rawHeaders : []
  let seen = 0
  for (let i = 0; i < raw.length; i += 2) {
    if (String(raw[i]).toLowerCase() === lower) seen++
  }
  return seen > 1 || Array.isArray(req?.headers?.[lower])
}

function validIdempotencyKey (value) {
  return typeof value === 'string' && /^[A-Za-z0-9._:-]{16,128}$/.test(value)
}

async function cancelVerifiedPayment (payment, reason, error, responseStatus) {
  try {
    await payment.cancellationDispatcher.cancel({ reason, error, responseStatus })
  } catch {}
}

function instructionResult (instructions = {}) {
  return {
    handled: true,
    status: instructions.status || 402,
    headers: {
      ...instructions.headers,
      ...NO_STORE_HEADERS
    },
    payload: instructions.body == null ? {} : instructions.body
  }
}

function jsonResult (status, payload, headers = {}) {
  return {
    handled: true,
    status,
    headers: {
      ...headers,
      ...NO_STORE_HEADERS
    },
    payload
  }
}

function safeServiceError (err) {
  const message = safeErrorMessage(err)
  if (/^[A-Z][A-Z0-9_-]+:/.test(message)) return message
  return 'service call failed'
}

function safeErrorMessage (err) {
  const message = err && err.message ? String(err.message) : String(err || 'unknown error')
  return message.length > 256 ? message.slice(0, 256) : message
}
