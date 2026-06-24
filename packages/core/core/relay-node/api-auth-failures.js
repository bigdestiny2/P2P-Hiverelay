export const AUTH_FAILURE_ROUTE_SAFE_CHAR = /^[A-Za-z0-9._~!$&'()*+,;=:@/-]$/

export function sanitizeAuthFailureRouteChars (value) {
  let out = ''
  const text = String(value || '')
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]
    const code = text.charCodeAt(i)
    out += (code <= 31 || code === 127 || !AUTH_FAILURE_ROUTE_SAFE_CHAR.test(ch)) ? ':' : ch
  }
  return out
}

export function authFailureRoute (req) {
  const raw = String((req && req.url) || '/').split('?')[0].slice(0, 200)
  const collapsed = raw.replace(/[0-9a-fA-F]{16,}/g, ':hex')
  const safe = sanitizeAuthFailureRouteChars(collapsed)
    .replace(/:{2,}/g, ':')
    .replace(/:\//g, '/')
    .slice(0, 200)
  return safe.startsWith('/') ? safe || '/' : '/' + safe
}

export function escapePrometheusLabelValue (value) {
  return String(value)
    .replace(/\\/g, '\\\\')
    .replace(/\n/g, '\\n')
    .replace(/"/g, '\\"')
}
