import b4a from 'b4a'
import {
  FAMILY,
  FAMILY_ROUTES,
  OPERATION,
  OUTER_CLASS,
  PROTOCOL
} from '@hiverelay/blind-protocol/wire-runtime-authority'
import { asBytes } from './bytes.js'
import { BlindClientError, fail } from './errors.js'
import { createDescribeGetRequest, verifyDescriptorBytes } from './describe.js'
import { decodeUnaryResponse, encodeUnaryRequest } from './wire.js'

const MAX_TIMEOUT_MILLIS = 15_000

function bootstrapUrl (value, allowInsecureLoopback) {
  const text = b4a.toString(asBytes(value, 'bootstrap canonicalUrl'), 'utf8')
  let url
  try {
    url = new URL(text)
  } catch (error) {
    fail('BAD_CLIENT_INPUT', 'bootstrap canonicalUrl is invalid', { cause: error })
  }
  if (url.pathname !== FAMILY_ROUTES[FAMILY.DESCRIBE] || url.search || url.hash ||
      url.username || url.password) {
    fail('TRANSPORT_MISMATCH', 'bootstrap URL is not the fixed DESCRIBE listener anchor')
  }
  const loopback = url.hostname === '127.0.0.1' || url.hostname === '::1' || url.hostname === '[::1]'
  if (url.protocol !== 'https:' && !(allowInsecureLoopback && loopback && url.protocol === 'http:')) {
    fail('TRANSPORT_MISMATCH', 'descriptor bootstrap must use HTTPS')
  }
  return url.href
}

function timeoutMillis (value) {
  if (value == null) return MAX_TIMEOUT_MILLIS
  if (!Number.isSafeInteger(value) || value < 1 || value > MAX_TIMEOUT_MILLIS) {
    fail('BAD_CLIENT_INPUT', `timeoutMillis must be within 1..${MAX_TIMEOUT_MILLIS}`)
  }
  return value
}

function abortScope (parent, timeout) {
  const controller = new AbortController()
  const abort = () => controller.abort(parent && parent.reason)
  if (parent) {
    if (parent.aborted) abort()
    else parent.addEventListener('abort', abort, { once: true })
  }
  const timer = setTimeout(() => controller.abort(new Error('descriptor bootstrap deadline elapsed')), timeout)
  return {
    signal: controller.signal,
    close () {
      clearTimeout(timer)
      if (parent) parent.removeEventListener('abort', abort)
    }
  }
}

async function readExact (response, exactBytes, signal) {
  const declared = response.headers && response.headers.get ? response.headers.get('content-length') : null
  const contentEncoding = response.headers && response.headers.get ? response.headers.get('content-encoding') : null
  const transferEncoding = response.headers && response.headers.get ? response.headers.get('transfer-encoding') : null
  if (contentEncoding != null || transferEncoding != null) {
    fail('RELAY_PROTOCOL_VIOLATION', 'encoded or transfer-framed bootstrap responses are forbidden')
  }
  if (declared == null || !/^(0|[1-9][0-9]*)$/.test(declared) || Number(declared) !== exactBytes) {
    fail('RELAY_PROTOCOL_VIOLATION', 'bootstrap response must declare the exact selected class')
  }
  if (!response.body || typeof response.body.getReader !== 'function') {
    fail('TRANSPORT_UNAVAILABLE', 'a bounded streaming bootstrap response is required')
  }
  const reader = response.body.getReader()
  const output = b4a.alloc(exactBytes)
  let total = 0
  const onAbort = () => Promise.resolve(reader.cancel(signal.reason)).catch(() => {})
  if (signal.aborted) onAbort()
  else signal.addEventListener('abort', onAbort, { once: true })
  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      const chunk = asBytes(value, 'bootstrap response chunk')
      total += chunk.byteLength
      if (total > exactBytes) fail('RELAY_PROTOCOL_VIOLATION', 'bootstrap response exceeds the selected class')
      b4a.copy(chunk, output, total - chunk.byteLength)
    }
  } finally {
    signal.removeEventListener('abort', onAbort)
    if (total > exactBytes && typeof reader.cancel === 'function') await reader.cancel().catch(() => {})
    if (typeof reader.releaseLock === 'function') reader.releaseLock()
  }
  if (total !== exactBytes) fail('RELAY_PROTOCOL_VIOLATION', 'bootstrap response is shorter than the selected class')
  return output
}

// This is deliberately not a generic raw-endpoint transport. It can perform
// only DESCRIBE.GET. Hash-named history reads return only after exact hash,
// signature and supported-profile verification. Current-head discovery omits
// only the expected hash; it still verifies the signed current descriptor and
// must be chained to an independently authenticated genesis pin by its caller.
export class BlindDescriptorBootstrapHttpClient {
  constructor (options = {}) {
    this.runtime = options.runtime
    this.fetch = options.fetch || globalThis.fetch
    if (typeof this.fetch !== 'function') fail('TRANSPORT_UNAVAILABLE', 'fetch implementation is required')
    this.allowInsecureLoopback = options.allowInsecureLoopback === true
  }

  async fetchVerifiedDescriptor (options) {
    if (!options || typeof options !== 'object') fail('BAD_CLIENT_INPUT', 'descriptor bootstrap options are required')
    const expectedDescriptorHash = b4a.from(asBytes(
      options.expectedDescriptorHash, 'expectedDescriptorHash', 32))
    return this._fetchVerifiedDescriptor(options, expectedDescriptorHash)
  }

  async fetchVerifiedDescriptorHead (options) {
    if (!options || typeof options !== 'object') fail('BAD_CLIENT_INPUT', 'descriptor bootstrap options are required')
    if (options.history === true) {
      fail('BAD_CLIENT_INPUT', 'current descriptor head discovery cannot be a history read')
    }
    return this._fetchVerifiedDescriptor(options, null)
  }

  async _fetchVerifiedDescriptor (options, expectedDescriptorHash) {
    const describe = createDescribeGetRequest({
      runtime: this.runtime,
      descriptorHash: expectedDescriptorHash,
      clientNonce: options.clientNonce
    })
    const encoded = encodeUnaryRequest({
      runtime: this.runtime,
      requestId: options.requestId,
      familyId: FAMILY.DESCRIBE,
      operationId: OPERATION.DESCRIBE.GET,
      expectedResultBodyBytes: describe.wire.expectedResultBodyBytes,
      body: describe.requestBytes
    })
    const scope = abortScope(options.signal, timeoutMillis(options.timeoutMillis))
    try {
      const response = await this.fetch(bootstrapUrl(options.canonicalUrl, this.allowInsecureLoopback), {
        method: 'POST',
        headers: [['content-type', PROTOCOL.mediaType]],
        body: encoded.body,
        credentials: 'omit',
        cache: 'no-store',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
        signal: scope.signal
      })
      if (!response || response.status !== 200) {
        fail('TRANSPORT_FAILURE', 'descriptor bootstrap returned a non-protocol status')
      }
      const contentType = response.headers && response.headers.get ? response.headers.get('content-type') : null
      if (contentType !== PROTOCOL.mediaType) {
        fail('RELAY_PROTOCOL_VIOLATION', 'bootstrap response media type is not the blind protocol')
      }
      const bytes = await readExact(response, OUTER_CLASS[encoded.outerClass], scope.signal)
      const result = decodeUnaryResponse(bytes, encoded)
      if (!result.ok) fail('TRANSPORT_FAILURE', 'descriptor bootstrap returned a canonical relay error')
      return verifyDescriptorBytes(result.body, {
        expectedDescriptorHash: expectedDescriptorHash == null ? undefined : expectedDescriptorHash,
        nowEpoch: options.nowEpoch,
        history: expectedDescriptorHash != null && options.history === true,
        supportedProtocolProfiles: options.supportedProtocolProfiles,
        supportedTransportProfiles: options.supportedTransportProfiles
      })
    } catch (error) {
      if (error instanceof BlindClientError) throw error
      fail('TRANSPORT_FAILURE', 'descriptor bootstrap failed', { cause: error })
    } finally {
      scope.close()
    }
  }
}
