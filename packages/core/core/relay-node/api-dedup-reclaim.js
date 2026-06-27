import { formatErr } from '../error-prefixes.js'

const RECLAIM_UNAVAILABLE = 'dedup reclaim not available (eviction manager not enabled)'

function badRequest (message) {
  return { error: formatErr('BAD_REQUEST', message) }
}

function parseNonNegativeInteger (body, name, defaultValue) {
  if (body[name] === undefined) return { ok: true, value: defaultValue }
  if (!Number.isSafeInteger(body[name]) || body[name] < 0) {
    return { ok: false, message: `${name} must be a non-negative integer` }
  }
  return { ok: true, value: body[name] }
}

function parsePositiveInteger (body, name) {
  if (body[name] === undefined) return { ok: true, value: undefined }
  if (!Number.isSafeInteger(body[name]) || body[name] <= 0) {
    return { ok: false, message: `${name} must be a positive integer` }
  }
  return { ok: true, value: body[name] }
}

export function parseDedupReclaimOptions (body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { ok: false, message: 'JSON body object required' }
  }

  const retainVersions = parseNonNegativeInteger(body, 'retainVersions', 0)
  if (!retainVersions.ok) return retainVersions

  const max = parsePositiveInteger(body, 'max')
  if (!max.ok) return max

  return {
    ok: true,
    options: {
      dryRun: body.execute !== true,
      retainVersions: retainVersions.value,
      max: max.value
    }
  }
}

export async function runDedupReclaimAction ({ body, node, emit = () => {} } = {}) {
  const parsed = parseDedupReclaimOptions(body)
  if (!parsed.ok) {
    return {
      ok: false,
      status: 400,
      payload: badRequest(parsed.message)
    }
  }

  const reclaim = node?.eviction?.reclaimSuperseded
  if (typeof reclaim !== 'function') {
    return {
      ok: false,
      status: 503,
      payload: { error: RECLAIM_UNAVAILABLE }
    }
  }

  try {
    const out = await reclaim.call(node.eviction, parsed.options)
    return {
      ok: true,
      status: 200,
      payload: { ok: true, ...out }
    }
  } catch (err) {
    emit('dedup-reclaim-error', { error: err })
    return {
      ok: false,
      status: 500,
      payload: { error: formatErr('RECLAIM_FAILED', 'dedup reclaim failed') }
    }
  }
}
