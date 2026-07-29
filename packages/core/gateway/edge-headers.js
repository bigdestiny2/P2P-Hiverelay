/**
 * Gateway edge header & advertisement policy (R3/R5/R6/R7).
 *
 * One module defines which isolation/privacy headers the HTTPS gateway emits
 * per lane and per ingress, so the policy cannot drift between the response
 * paths (JSON errors, directory listings, transformed HTML, streamed bytes,
 * and R1 verify bundles all pass through HyperGateway._handleRequest).
 *
 * Lanes and ingresses (docs/HTTPS-GATEWAY.md):
 *   - path lane       — shared-origin /v1/hyper/<key>/<path> (clearnet + onion)
 *   - app-origin lane — per-app z32 subdomains, exact bytes (clearnet)
 *   - onion ingress   — the Tor read plane; vport 80 forwards to the same
 *                       gateway, so ingress is detected from the `.onion`
 *                       Host. A spoofed `.onion` Host on clearnet only earns
 *                       the stricter CSP — the policy fails safe.
 *
 * Header matrix (lane × ingress):
 *
 *   header                       path lane        app-origin lane   onion ingress
 *   Service-Worker-Allowed       stripped (R3)    untouched*        stripped (R3)
 *   Content-Security-Policy      —                —                 ONION_READ_PLANE_CSP (R5)
 *   Cross-Origin-Opener-Policy   same-origin      same-origin       same-origin (R6)
 *   Cross-Origin-Resource-Policy cross-origin     same-origin       cross-origin (R6)
 *   Referrer-Policy              no-referrer      no-referrer       no-referrer (R6)
 *   Link                         hive:// canonical hint (R7, both lanes)
 *
 *   *R3 scopes the strip to the shared origin: on the app-origin lane the app
 *   owns its whole origin, so a worker there shadows only that same app (and
 *   the lane's bytes stay exact/untouched by design). On the shared path lane
 *   one app's Service-Worker-Allowed could widen a worker's scope beyond its
 *   own /<key>/ prefix and shadow every other app on the origin, so the lane
 *   is stateless-only.
 *
 * R3 — path-lane stateless-only policy. The gateway never copies drive entry
 * metadata into response headers and response bodies cannot carry headers, so
 * no app can set Service-Worker-Allowed through content today. The strip is
 * still installed as a structural guard at response commit (writeHead), so a
 * future emission path cannot accidentally reintroduce it.
 *
 * R5 — onion-ingress CSP default. The onion read plane exists to READ
 * declared-public bytes with client-IP privacy; the default below denies
 * script execution and network beacons outright while still letting a static
 * document render its own images/styles/fonts/media. 'self' is exactly what
 * the path lane's absolute→relative HTML rewrite produces, so the rewrite
 * and the CSP compose instead of fighting. An app may layer its own CSP via
 * <meta http-equiv>, but a meta policy can only tighten the effective one —
 * never loosen this header floor — so the shared-origin posture cannot be
 * weakened by content.
 *
 * R6 — COOP/CORP/Referrer-Policy, matching the existing Origin-Agent-Cluster:
 * ?1 / nosniff discipline. COOP same-origin is the browsing-context-group
 * counterpart of origin-keyed agent clusters. Referrer-Policy no-referrer
 * because the path names the drive key and the exact file being read — the
 * same no-referrer discipline as the operator dashboard. CORP follows each
 * lane's established cross-origin posture: the compatibility path lane
 * already answers CORS clients with Access-Control-Allow-Origin: * (the
 * house rule for public credential-free read planes — blind evidence GETs,
 * blind-edge), so it declares cross-origin; app origins never inherit
 * compatibility CORS, so they additionally deny no-cors subresource
 * embedding with same-origin.
 *
 * R7 — canonical upgrade hint. The app-origin lane already emitted
 * Link: <hive://<key>/<path>>; rel="canonical"; the path lane now emits the
 * same hint so a capable client can leave HTTPS for the native P2P scheme
 * (the blind/tier 403s even point there: "use the authorized native P2P
 * transport"). The signed hiverelay-gateway-advertisement-v1 record remains
 * the spec-level Phase-2 operator advertisement; the signed capability doc
 * plus these per-resource canonical links are the implemented surfaces.
 */

export const SERVICE_WORKER_ALLOWED_HEADER = 'Service-Worker-Allowed'

/**
 * Restrictive CSP default for the onion read plane (R5). Pinned as a constant
 * so tests assert the exact advertised value instead of a shape.
 */
export const ONION_READ_PLANE_CSP =
  "default-src 'none'; script-src 'none'; connect-src 'none'; " +
  "img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self'; media-src 'self'; " +
  "form-action 'none'; base-uri 'none'; frame-ancestors 'none'"

export const GATEWAY_CROSS_ORIGIN_OPENER_POLICY = 'same-origin'
export const PATH_LANE_CROSS_ORIGIN_RESOURCE_POLICY = 'cross-origin'
export const APP_ORIGIN_CROSS_ORIGIN_RESOURCE_POLICY = 'same-origin'
export const GATEWAY_REFERRER_POLICY = 'no-referrer'

/**
 * The onion read plane terminates inside tor and forwards plain HTTP to the
 * gateway, so the only honest ingress signal at this layer is the Host the
 * client asked Tor for: a `.onion` name. Port suffixes and a trailing root
 * dot still count; lookalikes (evil.com suffix games) do not.
 */
export function isOnionReadPlaneHost (hostHeader) {
  if (typeof hostHeader !== 'string') return false
  let hostname = hostHeader.trim().toLowerCase()
  if (!hostname || hostname.startsWith('[')) return false // IPv6 literal, never an onion name
  const colon = hostname.lastIndexOf(':')
  if (colon !== -1) hostname = hostname.slice(0, colon)
  if (hostname.endsWith('.')) hostname = hostname.slice(0, -1)
  return hostname.endsWith('.onion')
}

/**
 * Apply the R5/R6 edge headers for one gateway response. Idempotent — the
 * GatewayServer app-origin lane and HyperGateway may both run it for one
 * request without changing the result.
 */
export function applyGatewayEdgeHeaders (res, { exactBytes = false, onionIngress = false } = {}) {
  res.setHeader('Cross-Origin-Opener-Policy', GATEWAY_CROSS_ORIGIN_OPENER_POLICY)
  res.setHeader(
    'Cross-Origin-Resource-Policy',
    exactBytes ? APP_ORIGIN_CROSS_ORIGIN_RESOURCE_POLICY : PATH_LANE_CROSS_ORIGIN_RESOURCE_POLICY
  )
  res.setHeader('Referrer-Policy', GATEWAY_REFERRER_POLICY)
  if (onionIngress) res.setHeader('Content-Security-Policy', ONION_READ_PLANE_CSP)
}

/**
 * R3 structural strip: wrap writeHead so a shared-origin path-lane response
 * can never commit a Service-Worker-Allowed header — neither one queued via
 * setHeader nor one handed to writeHead directly (that argument bypasses the
 * setHeader queue removeHeader sees).
 */
export function guardPathLaneStatelessHeaders (res) {
  const writeHead = res.writeHead
  res.writeHead = function (...args) {
    res.removeHeader(SERVICE_WORKER_ALLOWED_HEADER)
    return writeHead.apply(this, args.map(withoutServiceWorkerAllowed))
  }
  return res
}

function withoutServiceWorkerAllowed (arg) {
  if (Array.isArray(arg)) {
    // Raw [name, value, name, value] form.
    const filtered = []
    for (let i = 0; i < arg.length; i += 2) {
      if (String(arg[i]).toLowerCase() === 'service-worker-allowed') continue
      filtered.push(arg[i], arg[i + 1])
    }
    return filtered
  }
  if (arg && typeof arg === 'object') {
    const filtered = {}
    for (const [name, value] of Object.entries(arg)) {
      if (name.toLowerCase() !== 'service-worker-allowed') filtered[name] = value
    }
    return filtered
  }
  return arg
}

/**
 * R7 path-lane upgrade hint: the canonical hive:// URI of the requested
 * resource. The app-origin lane additionally points rel="describedby" at its
 * per-app /.well-known/hiverelay-app.json document; the path lane has no
 * per-app document, so it emits the plain canonical form.
 */
export function buildHivePathLinkHeader (keyHex, filePath) {
  const canonical = new URL(`hive://${keyHex}/`)
  canonical.pathname = filePath
  return `<${canonical.href}>; rel="canonical"`
}
