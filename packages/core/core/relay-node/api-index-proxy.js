import { formatErr } from '../error-prefixes.js'

export const INDEX_PROXY_RESPONSE_LIMIT = 5 * 1024 * 1024
export const INDEX_PROXY_TIMEOUT_MS = 8000

export function buildIndexProxyDisabledResponse () {
  return {
    kind: 'json',
    status: 501,
    payload: {
      error: 'index sidecar not configured',
      errorCode: 'index-disabled'
    }
  }
}

export function buildIndexProxyTarget (base, url) {
  return String(base) + url.pathname + (url.search || '')
}

export async function buildIndexProxyRouteResponse ({
  base,
  url,
  fetchImpl = globalThis.fetch,
  createAbortController = () => new AbortController(),
  setTimeoutFn = setTimeout,
  clearTimeoutFn = clearTimeout,
  limitBytes = INDEX_PROXY_RESPONSE_LIMIT,
  timeoutMs = INDEX_PROXY_TIMEOUT_MS
} = {}) {
  if (!base) return buildIndexProxyDisabledResponse()

  const target = buildIndexProxyTarget(base, url)
  const controller = createAbortController()
  const timer = setTimeoutFn(() => controller.abort(), timeoutMs)

  try {
    const upstream = await fetchImpl(target, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      signal: controller.signal
    })

    const declared = parseInt(upstream.headers.get('content-length') || '', 10)
    if (Number.isFinite(declared) && declared > limitBytes) {
      controller.abort()
      return indexProxyTooLargeResponse()
    }

    const reader = upstream.body && upstream.body.getReader ? upstream.body.getReader() : null
    if (!reader) {
      const text = await upstream.text()
      if (Buffer.byteLength(text) > limitBytes) return indexProxyTooLargeResponse()
      return {
        kind: 'text',
        status: upstream.status,
        text,
        headers: { 'Content-Type': 'application/json' }
      }
    }

    const chunks = []
    let total = 0
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      const chunk = Buffer.from(value)
      total += chunk.length
      if (total > limitBytes) {
        controller.abort()
        return indexProxyTooLargeResponse()
      }
      chunks.push(chunk)
    }

    return {
      kind: 'buffer',
      status: upstream.status,
      body: Buffer.concat(chunks),
      headers: { 'Content-Type': 'application/json' }
    }
  } catch (err) {
    const status = err.name === 'AbortError' ? 504 : 502
    return {
      kind: 'json',
      status,
      payload: {
        error: formatErr('UNSUPPORTED', 'index sidecar unreachable'),
        errorCode: 'index-unreachable'
      },
      event: {
        name: 'index-proxy-error',
        detail: { error: err, status }
      }
    }
  } finally {
    clearTimeoutFn(timer)
  }
}

function indexProxyTooLargeResponse () {
  return {
    kind: 'json',
    status: 502,
    payload: { error: 'index response too large' }
  }
}
