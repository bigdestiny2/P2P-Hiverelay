export function resolveMetricsRoute (method, path) {
  if (method !== 'GET') return null
  if (path === '/metrics') return { kind: 'metrics' }
  return null
}

export function buildMetricsRouteResponse ({
  metrics,
  authFailureLines = ''
} = {}) {
  if (!metrics || typeof metrics.toPrometheus !== 'function') {
    return {
      ok: false,
      status: 503,
      payload: { error: 'Metrics not enabled' }
    }
  }

  return {
    ok: true,
    status: 200,
    text: metrics.toPrometheus() + authFailureLines
  }
}
