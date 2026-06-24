export function escapeHtmlAttr (value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
}

export function injectUiTokenMeta (html, token) {
  const body = String(html)
  const tag = `<meta name="hiverelay-ui-token" content="${escapeHtmlAttr(token)}">`
  return body.includes('<head>') ? body.replace('<head>', '<head>\n' + tag) : tag + body
}

export function buildDashboardHtmlResponse (html, opts = {}) {
  const exposeToken = opts.exposeToken === true
  const apiKey = opts.apiKey
  return {
    html: exposeToken && apiKey ? injectUiTokenMeta(html, apiKey) : String(html),
    noStore: exposeToken
  }
}

export function setDashboardSecurityHeaders (res) {
  res.setHeader('Content-Type', 'text/html; charset=utf-8')
  res.setHeader('X-Content-Type-Options', 'nosniff')
  res.setHeader('Referrer-Policy', 'no-referrer')
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()')
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "base-uri 'none'",
      "object-src 'none'",
      "form-action 'self'",
      "img-src 'self' data: https:",
      "script-src 'self' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline'",
      "connect-src 'self' ws: wss:"
    ].join('; ')
  )
}
