import b4a from 'b4a'
import {
  FAMILY,
  FAMILY_ROUTES,
  OUTER_CLASS,
  PROTOCOL,
  TRANSPORT_ID,
  TRANSPORT_SUPPORT
} from '@hiverelay/blind-protocol/wire-runtime-authority'
import { asBytes } from './bytes.js'
import { BlindClientError, fail } from './errors.js'
import { unwrapVerifiedEndpoint } from './verified-endpoint.js'
import { decodeUnaryResponse, encodeUnaryRequest } from './wire.js'
import { selectedOperationProfile } from './selected-operation-profile.js'

function resolvedEndpoint (value) {
  const verified = unwrapVerifiedEndpoint(value)
  if (verified) return verified
  fail('UNVERIFIED_ENDPOINT', 'ordinary relay operations require an opaque VerifiedEndpoint')
}

function endpointUrl (endpoint, familyId, allowInsecureLoopback) {
  if (!endpoint || typeof endpoint !== 'object') fail('BAD_CLIENT_INPUT', 'signed transport endpoint is required')
  if (!Number.isInteger(endpoint.endpointId) || endpoint.endpointId < 1 || endpoint.endpointId > 255) {
    fail('BAD_CLIENT_INPUT', 'endpointId must be within 1..255')
  }
  if (endpoint.transportId !== TRANSPORT_ID.HTTPS_DIRECT) fail('TRANSPORT_MISMATCH', 'endpoint is not HTTPS_DIRECT')
  const raw = asBytes(endpoint.canonicalUrl, 'endpoint canonicalUrl')
  const text = b4a.toString(raw, 'utf8')
  let url
  try {
    url = new URL(text)
  } catch (error) {
    fail('BAD_CLIENT_INPUT', 'endpoint canonicalUrl is invalid', { cause: error })
  }
  const route = FAMILY_ROUTES[familyId]
  if (!route || url.pathname !== FAMILY_ROUTES[FAMILY.DESCRIBE] || url.search || url.hash || url.username || url.password) {
    fail('TRANSPORT_MISMATCH', 'endpoint URL is not the signed generic listener-authority anchor')
  }
  const loopback = url.hostname === '127.0.0.1' || url.hostname === '::1' || url.hostname === '[::1]'
  if (url.protocol !== 'https:' && !(allowInsecureLoopback && loopback && url.protocol === 'http:')) {
    fail('TRANSPORT_MISMATCH', 'direct endpoint must use HTTPS')
  }
  url.pathname = route
  return url.href
}

function assertEndpointSupportsRequest (endpoint, encoded) {
  if (endpoint.qualifiedFamilyId !== encoded.familyId ||
      endpoint.qualifiedOperationId !== encoded.operationId ||
      endpoint.transportSupportBit !== TRANSPORT_SUPPORT.DIRECT_HTTP) {
    fail('TRANSPORT_MISMATCH', 'VerifiedEndpoint was not qualified for this exact direct operation')
  }
  if (!Number.isInteger(endpoint.envelopeClassBits) || (endpoint.envelopeClassBits & ~0x007e) !== 0 ||
      (endpoint.envelopeClassBits & (1 << encoded.outerClass)) === 0) {
    fail('TRANSPORT_MISMATCH', 'endpoint did not advertise the selected outer class')
  }
  const profile = selectedOperationProfile(encoded.familyId, encoded.operationId)
  if ((profile.transportSupportBits & TRANSPORT_SUPPORT.DIRECT_HTTP) === 0) {
    fail('TRANSPORT_MISMATCH', 'operation is not available over direct HTTP')
  }
}

function deadlineForFamily (familyId, override) {
  const maximum = familyId === FAMILY.INBOX ? 35_000 : 15_000
  if (override == null) return maximum
  if (!Number.isSafeInteger(override) || override < 1 || override > maximum) {
    fail('BAD_CLIENT_INPUT', `timeoutMillis must be within 1..${maximum}`)
  }
  return override
}

function abortScope (parent, timeoutMillis) {
  const controller = new AbortController()
  const abort = () => controller.abort(parent && parent.reason)
  if (parent) {
    if (parent.aborted) abort()
    else parent.addEventListener('abort', abort, { once: true })
  }
  const timer = setTimeout(() => controller.abort(new Error('blind direct request deadline elapsed')), timeoutMillis)
  return {
    signal: controller.signal,
    close () {
      clearTimeout(timer)
      if (parent) parent.removeEventListener('abort', abort)
    }
  }
}

async function readExactResponse (response, exactBytes, signal) {
  const declared = response.headers && response.headers.get ? response.headers.get('content-length') : null
  const contentEncoding = response.headers && response.headers.get ? response.headers.get('content-encoding') : null
  const transferEncoding = response.headers && response.headers.get ? response.headers.get('transfer-encoding') : null
  if (contentEncoding != null || transferEncoding != null) {
    fail('RELAY_PROTOCOL_VIOLATION', 'encoded or transfer-framed response bodies are forbidden')
  }
  if (declared == null) fail('RELAY_PROTOCOL_VIOLATION', 'response requires an exact content-length')
  if (declared != null && !/^(0|[1-9][0-9]*)$/.test(declared)) fail('RELAY_PROTOCOL_VIOLATION', 'response content-length is not canonical')
  if (declared != null && Number(declared) !== exactBytes) fail('RELAY_PROTOCOL_VIOLATION', 'response content-length changed the selected class')
  if (!response.body || typeof response.body.getReader !== 'function') {
    fail('TRANSPORT_UNAVAILABLE', 'a bounded streaming response is required')
  }
  const reader = response.body.getReader()
  const output = b4a.alloc(exactBytes)
  let total = 0
  const onAbort = () => Promise.resolve(reader.cancel(signal.reason)).catch(() => {})
  if (signal) {
    if (signal.aborted) onAbort()
    else signal.addEventListener('abort', onAbort, { once: true })
  }
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      const chunk = asBytes(value, 'direct response chunk')
      total += chunk.byteLength
      if (total > exactBytes) fail('RELAY_PROTOCOL_VIOLATION', 'response exceeds the selected class')
      b4a.copy(chunk, output, total - chunk.byteLength)
    }
  } finally {
    if (signal) signal.removeEventListener('abort', onAbort)
    if (total > exactBytes && typeof reader.cancel === 'function') await reader.cancel().catch(() => {})
    if (typeof reader.releaseLock === 'function') reader.releaseLock()
  }
  if (total !== exactBytes) fail('RELAY_PROTOCOL_VIOLATION', 'response is shorter than the selected class')
  return output
}

export class BlindDirectHttpClient {
  constructor (options = {}) {
    this.runtime = options.runtime
    this.fetch = options.fetch || globalThis.fetch
    if (typeof this.fetch !== 'function') fail('TRANSPORT_UNAVAILABLE', 'fetch implementation is required')
    this.allowInsecureLoopback = options.allowInsecureLoopback === true
  }

  async request (options) {
    if (!options || typeof options !== 'object') fail('BAD_CLIENT_INPUT', 'direct request options are required')
    const encoded = encodeUnaryRequest({ ...options, runtime: this.runtime })
    const endpoint = resolvedEndpoint(options.endpoint)
    assertEndpointSupportsRequest(endpoint, encoded)
    const url = endpointUrl(endpoint, encoded.familyId, this.allowInsecureLoopback)
    const scope = abortScope(options.signal, deadlineForFamily(encoded.familyId, options.timeoutMillis))
    try {
      const response = await this.fetch(url, {
        method: 'POST',
        headers: [
          ['content-type', PROTOCOL.mediaType]
        ],
        body: encoded.body,
        credentials: 'omit',
        cache: 'no-store',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
        signal: scope.signal
      })
      if (!response || response.status !== 200) fail('TRANSPORT_FAILURE', 'blind direct transport returned a non-protocol status')
      const contentType = response.headers && response.headers.get ? response.headers.get('content-type') : null
      if (contentType !== PROTOCOL.mediaType) fail('RELAY_PROTOCOL_VIOLATION', 'response media type is not the blind protocol')
      const bytes = await readExactResponse(response, OUTER_CLASS[encoded.outerClass], scope.signal)
      return decodeUnaryResponse(bytes, encoded)
    } catch (error) {
      if (error instanceof BlindClientError) throw error
      fail('TRANSPORT_FAILURE', 'blind direct transport failed', { cause: error })
    } finally {
      scope.close()
    }
  }
}
