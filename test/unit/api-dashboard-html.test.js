import test from 'brittle'
import {
  buildDashboardHtmlResponse,
  escapeHtmlAttr,
  injectUiTokenMeta,
  setDashboardSecurityHeaders
} from 'p2p-hiverelay/core/relay-node/api-dashboard-html.js'

function fakeRes () {
  return {
    headers: {},
    setHeader (name, value) {
      this.headers[name.toLowerCase()] = value
    }
  }
}

test('api dashboard html: token meta is attribute-escaped and injected into head', (t) => {
  const html = '<html><head><title>x</title></head><body></body></html>'
  const out = injectUiTokenMeta(html, 'a&"><script>x')
  t.ok(out.includes('<head>\n<meta name="hiverelay-ui-token" content="a&amp;&quot;&gt;&lt;script&gt;x">'))
  t.absent(out.includes('content="a&"><script>x"'))
  t.is(escapeHtmlAttr('a&"><'), 'a&amp;&quot;&gt;&lt;')
})

test('api dashboard html: token meta is prepended when no head tag exists', (t) => {
  const out = injectUiTokenMeta('<body>ok</body>', 'tok')
  t.ok(out.startsWith('<meta name="hiverelay-ui-token" content="tok"><body>ok</body>'))
})

test('api dashboard html: response builder injects only when exposeToken has a key', (t) => {
  const html = '<head></head>'
  t.alike(buildDashboardHtmlResponse(html), { html, noStore: false })
  t.alike(buildDashboardHtmlResponse(html, { exposeToken: true }), { html, noStore: true })
  const withToken = buildDashboardHtmlResponse(html, { exposeToken: true, apiKey: 'tok' })
  t.ok(withToken.html.includes('content="tok"'))
  t.ok(withToken.noStore)
})

test('api dashboard html: security headers set browser hardening policy', (t) => {
  const res = fakeRes()
  setDashboardSecurityHeaders(res)

  t.is(res.headers['content-type'], 'text/html; charset=utf-8')
  t.is(res.headers['x-content-type-options'], 'nosniff')
  t.is(res.headers['referrer-policy'], 'no-referrer')
  t.ok(res.headers['permissions-policy'].includes('camera=()'))
  t.ok(res.headers['content-security-policy'].includes("default-src 'self'"))
  t.ok(res.headers['content-security-policy'].includes("base-uri 'none'"))
  t.ok(res.headers['content-security-policy'].includes("object-src 'none'"))
  t.ok(res.headers['content-security-policy'].includes("connect-src 'self' ws: wss:"))
})
