/**
 * Local HTTP API for agent integration
 *
 * Lightweight REST API using Node.js built-in http module.
 * Enables agents (Hermes, OpenClaw) to query and control the relay
 * node without importing the module directly.
 *
 * Security features:
 *   - Configurable bind address (opts.apiHost, default '0.0.0.0')
 *   - Configurable CORS origins (opts.corsOrigins, default deny)
 *   - Per-IP rate limiting to prevent abuse
 *   - Hex key input validation on all POST routes
 */

import { createServer } from 'http'
import { readFile } from 'fs/promises'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'
import { createRequire } from 'module'
import { EventEmitter } from 'events'
import { DashboardFeed } from './ws-feed.js'
import { PokerFeed } from './ws-feed-poker.js'
import { HyperGateway } from '../../gateway/hyper-gateway.js'
import {
  isValidHexKey
} from '../constants.js'
import { buildCapabilityDoc } from '../capability-doc.js'
import { ERR, formatErr } from '../error-prefixes.js'
import { SetupWizard } from '../wizard.js'
import { isTransientCoreError, TRANSIENT_RETRY_AFTER_SECONDS } from '../transient-core-errors.js'
import {
  authFailureRoute,
  escapePrometheusLabelValue,
  sanitizeAuthFailureRouteChars
} from './api-auth-failures.js'
import {
  constantTimeStringEqual,
  hasLoopbackHostHeader,
  hasLoopbackOrigin,
  isLoopbackLocalRequest
} from './api-auth-helpers.js'
import { queryInt } from './api-validation.js'
import { readJsonBody } from './api-body.js'
import { buildCorsDecision, getAllowedOrigin } from './api-cors.js'
import { buildDashboardHtmlResponse, setDashboardSecurityHeaders } from './api-dashboard-html.js'
import { resolveDashboardGetRoute } from './api-dashboard-routes.js'
import { getPostJsonContentTypeProblem } from './api-request.js'
import { appendVaryHeader, writeJson, writeText } from './api-response.js'
import {
  checkApiRateLimit,
  checkEndpointRateLimit,
  clientIpFromRequest,
  sweepRateLimitMap
} from './api-rate-limit.js'
import { runConfigUpdateAction } from './api-config-update.js'
import {
  BUILTIN_SERVICE_PLUGINS,
  SERVICE_PLUGIN_BUNDLES,
  activeServiceNames,
  configuredBuiltinServicePlugins,
  normalizeManageServicePlugins,
  serviceConfigPayload
} from './api-service-config.js'
import { runServiceManagementAction } from './api-service-management.js'
import { buildServiceCatalogPayload } from './api-service-read.js'
import { buildRouterInfoPayload } from './api-router-read.js'
import { buildStatusPayload } from './api-status-read.js'
import {
  exportBandwidthReceipts,
  pokerUsageTelemetryPayload,
  sumReceiptBytes,
  tableWriterCount,
  usageTelemetryPayload
} from './api-usage-telemetry.js'
import {
  bandwidthOverview,
  buildOverviewPayload,
  registryOverview,
  reputationOverview
} from './api-overview.js'
import {
  buildAutoHealPayload,
  buildHealthDetailPayload,
  buildMetricsHistoryPayload,
  buildStorageTopPayload
} from './api-operator-telemetry.js'
import {
  buildManageAIModelRegistration,
  buildManageAIModelsPayload,
  manageAIModelStatus,
  publicManageAIModelError
} from './api-ai-models.js'
import {
  buildAnchorProofPayload,
  buildAnchorStatusPayload,
  isDetailedAnchorStatusQuery
} from './api-anchor-status.js'
import {
  buildNetworkStatePayload,
  isDetailedNetworkStateQuery
} from './api-network-state.js'
import {
  buildSubsidyClaimPayload,
  buildSubsidyStatusPayload,
  updateSubsidyDestination
} from './api-subsidy.js'
import {
  buildLeaseStatusPayload,
  runLeaseConfigAction
} from './api-lease.js'
import { runWizardAction } from './api-wizard-actions.js'
import {
  runModeSwitchAction,
  runTransportToggleAction
} from './api-mode-transport.js'
import {
  runDeviceManagementAction,
  runPairingManagementAction
} from './api-device-pairing.js'
import { runDispatchAction } from './api-dispatch.js'
import {
  buildPendingCatalogPayload,
  runCatalogAllowlistAction,
  runCatalogAppAction,
  runCatalogModeAction,
  runLegacyAutoAcceptAction,
  runRegistryCancelAction
} from './api-catalog-management.js'
import {
  buildRelayCatalogPayload,
  catalogEntriesByType
} from './api-catalog-read.js'
import { buildRegistryStatusPayload } from './api-registry-status.js'
import {
  runOperatorCustodyAction,
  runPublisherCustodyAction
} from './api-custody-management.js'
import { buildCustodyStatusPayload, redactCustodyStatus } from './api-custody-status.js'
import {
  buildFederationSnapshotPayload,
  runFederationManagementAction
} from './api-federation-management.js'
import {
  runOperatorSeedAction,
  runPublisherSeedAction,
  runRegistryPublishAction
} from './api-seed-publish.js'
import {
  runOperatorUnseedAction,
  runPublisherUnseedAction
} from './api-unseed-actions.js'
import {
  runAuthorManifestFetchAction,
  runAuthorManifestPublishAction,
  runForkProofPublishAction
} from './api-signed-ingress.js'
import { buildForkProofsPayload } from './api-fork-proofs.js'
import {
  buildReputationLeaderboardPayload,
  buildReputationRecordPayload
} from './api-reputation-read.js'
import { buildHealthResponse } from './api-health.js'
import {
  buildAlertLogPayload,
  runAlertTestAction
} from './api-alert-management.js'
import { runEvictionPurgeAction } from './api-eviction-purge.js'
import { runDedupReclaimAction } from './api-dedup-reclaim.js'
import { runLifecycleAction } from './api-lifecycle-actions.js'
import {
  buildGatewayStatsPayload,
  sanitizeGatewayStats
} from './api-gateway-stats.js'
import {
  buildDeviceStatusPayload,
  buildModeCatalogPayload,
  buildPairingStatusPayload,
  buildServiceRegistrySnapshot,
  buildTransportStatusPayload
} from './api-management-snapshots.js'
import {
  buildDelegationRevocationsPayload,
  runDelegationRevokeAction
} from './api-delegation-management.js'
import {
  buildSafeConfigPayload,
  restoreWizardConfig,
  snapshotWizardConfig
} from './api-safe-config.js'
import { buildPeerListPayload } from './api-peer-state.js'
import { redactIp } from '../privacy.js'

const __dirname = dirname(fileURLToPath(import.meta.url))

// Lazily-created CommonJS `require` for the rare synchronous file reads this
// module does (package version lookup). One instance per process.
let _cachedSyncRequire = null
function _getSyncRequire () {
  if (_cachedSyncRequire) return _cachedSyncRequire
  _cachedSyncRequire = createRequire(import.meta.url)
  return _cachedSyncRequire
}

const DEFAULT_PORT = 9100

const MANAGEMENT_AUTH_ERROR = 'Unauthorized — management API requires API key or localhost access'
const CONFIG_PERSIST_FAILED_MESSAGE = 'failed to persist config; check storage permissions and disk space'
const FEDERATION_PERSIST_FAILED_MESSAGE = 'failed to persist federation state; check storage permissions and disk space'
const DEVICE_PERSIST_FAILED_MESSAGE = 'failed to persist device allowlist; check storage permissions and disk space'
const WIZARD_PERSIST_FAILED_MESSAGE = 'failed to persist wizard state; check storage permissions and disk space'
const SUBSIDY_PERSIST_FAILED_MESSAGE = 'failed to persist subsidy state; check storage permissions and disk space'
const MANIFEST_PERSIST_FAILED_MESSAGE = 'failed to persist seeding manifest; check storage permissions and disk space'
const FORK_PERSIST_FAILED_MESSAGE = 'failed to persist fork proof; check storage permissions and disk space'
export class RelayAPI extends EventEmitter {
  constructor (relayNode, opts = {}) {
    super()
    this.node = relayNode
    // Nullish-coalesce so `apiPort: 0` (OS-selected port, used in tests) is
    // honored instead of falling through to the default 9100.
    this.port = (opts.apiPort !== undefined && opts.apiPort !== null) ? opts.apiPort : DEFAULT_PORT
    this.host = opts.apiHost || '0.0.0.0'
    this.corsOrigins = opts.corsOrigins || []
    this.trustProxy = opts.trustProxy || false
    // When true, the served dashboard/wizard HTML embeds the management
    // token so the browser UI can authenticate behind a trusted proxy.
    // See config/default.js `ui.exposeToken` for the security contract.
    this._uiExposeToken = opts.uiExposeToken || false
    // Simple mode (Blindspark appliance packaging): /dashboard serves the
    // single-page blindspark.html and the full operator tabs (network,
    // payments, calculator, leaderboard, catalog, docs) redirect back to
    // it. PC operators leave this off for the full multi-tab dashboard.
    this._uiSimple = opts.uiSimple || false
    this.server = null

    // API key for authenticated endpoints (manage, seed, unseed)
    // Read from opts, env var, or generate a random one
    this._apiKey = opts.apiKey || process.env.HIVERELAY_API_KEY || null

    // Per-IP request counts: ip -> { count, resetAt }
    this._rateLimits = new Map()
    this._endpointRateLimits = new Map()
    this._rateLimitCleanup = null

    // Auth-failure observability. A 401 from _requireAuth fires before the
    // request body is parsed, so without these counters a refused publisher
    // leaves zero server-side trace (surfaced by the 0/5-acceptances
    // incident where every relay 401'd a /seed pin and nothing was logged).
    // Counted per normalized route, surfaced on /metrics, warn-logged with
    // a per-route throttle so a 401 flood can't flood the log.
    this._authFailures = new Map() // normalized route -> count
    this._authFailureTotal = 0
    this._authFailureLogAt = new Map() // normalized route -> last warn ts
    this._dashboardHtml = null
    this._blindsparkHtml = null
    this._networkHtml = null
    this._docsHtml = null
    this._wizardHtml = null
    this._dashboardFeed = null
    this._pokerFeed = null
    this._wizard = null // lazily constructed by _getWizard() on first /api/wizard hit
    this._gateway = new HyperGateway(relayNode, { store: relayNode.store })
  }

  async start () {
    this.server = createServer((req, res) => this._handle(req, res))

    // Clean stale rate limit entries every 2 minutes. unref so it never
    // keeps the process alive on its own — callers rely on api.stop() for
    // deterministic teardown, but an unref'd interval means "forgot to
    // stop()" in a test doesn't hang the Node event loop.
    this._rateLimitCleanup = setInterval(() => {
      const now = Date.now()
      sweepRateLimitMap(this._rateLimits, now)
      sweepRateLimitMap(this._endpointRateLimits, now)
    }, 120_000)
    if (this._rateLimitCleanup.unref) this._rateLimitCleanup.unref()

    // Warn if binding to non-loopback without an API key — all requests
    // will pass the localhost auth check when behind a reverse proxy.
    if (!this._apiKey && this.host !== '127.0.0.1' && this.host !== '::1') {
      const msg = `[SECURITY WARNING] API binding to ${this.host}:${this.port} without an API key. ` +
        'Management endpoints are protected only by localhost check, which is ineffective behind a reverse proxy. ' +
        'Set an API key via HIVERELAY_API_KEY or opts.apiKey.'
      if (this.node && typeof this.node.emit === 'function') {
        this.node.emit('security-warning', { message: msg })
      }
      console.warn(msg)
    }

    // With trustProxy on and no API key, the localhost auth fallback is
    // disabled (it can't be trusted — see _isLocalRequest), so management
    // and local-only routes are unreachable until a key is set. Tell the
    // operator explicitly rather than letting them hit silent 401s.
    if (!this._apiKey && this.trustProxy) {
      const msg = '[SECURITY WARNING] trustProxy is enabled with no API key. ' +
        'The localhost auth fallback is disabled in this mode (X-Forwarded-For is spoofable), ' +
        'so management and local-only endpoints will reject all requests. ' +
        'Set an API key via HIVERELAY_API_KEY or opts.apiKey.'
      if (this.node && typeof this.node.emit === 'function') {
        this.node.emit('security-warning', { message: msg })
      }
      console.warn(msg)
    }

    // exposeToken embeds the management token into served HTML. That is
    // only safe behind an authenticating proxy with the port unpublished
    // to the host/LAN — anyone who can load the page can read the token.
    // Warn loudly, and refuse to expose a token we don't have.
    if (this._uiExposeToken) {
      if (!this._apiKey) {
        // Nothing to embed and management would be unreachable; disable.
        this._uiExposeToken = false
        const msg = '[SECURITY WARNING] ui.exposeToken is set but no API key is configured ' +
          '(no HIVERELAY_API_KEY/apiKey, and $APP_SEED missing or too short to derive one). ' +
          'Token exposure disabled; the management UI will be localhost-only.'
        if (this.node && typeof this.node.emit === 'function') {
          this.node.emit('security-warning', { message: msg })
        }
        console.warn(msg)
      } else {
        const msg = '[SECURITY NOTICE] ui.exposeToken is enabled — the management token is ' +
          'embedded in served dashboard/wizard HTML so the UI can authenticate behind a ' +
          'reverse proxy. Ensure this API port is reachable ONLY through an authenticating ' +
          'proxy and is NEVER published to the host/LAN.'
        if (this.node && typeof this.node.emit === 'function') {
          this.node.emit('security-warning', { message: msg })
        }
        console.warn(msg)
      }
    }

    // Retry on EADDRINUSE — when self-heal restarts the node, the previous
    // server.close() resolves but the OS socket may still be in TIME_WAIT.
    // Retry with exponential backoff so a fast restart doesn't fail outright.
    const maxRetries = 5
    const baseDelay = 1000
    let attempt = 0

    const tryListen = () => new Promise((resolve, reject) => {
      const onError = (err) => {
        this.server.removeListener('listening', onListening)
        reject(err)
      }
      const onListening = () => {
        this.server.removeListener('error', onError)
        // Start WebSocket live feed for dashboard clients
        this._dashboardFeed = new DashboardFeed({
          server: this.server,
          node: this.node,
          corsOrigins: this.corsOrigins,
          apiKey: this._apiKey
        })
        this._dashboardFeed.start()

        // Poker table live feed (/api/poker/:table/events). Coexists with the
        // dashboard feed on the same upgrade event; resolves the running
        // PokerApp lazily so it serves whether poker is enabled at boot or
        // toggled on later.
        this._pokerFeed = new PokerFeed({
          server: this.server,
          getPokerApp: () => {
            const pk = this._getPokerServiceProvider()
            return pk.ok ? pk.provider : null
          }
        })
        this._pokerFeed.start()

        this.emit('started', { port: this.port })
        resolve()
      }
      this.server.once('error', onError)
      this.server.once('listening', onListening)
      this.server.listen(this.port, this.host)
    })

    while (true) {
      try {
        await tryListen()
        return
      } catch (err) {
        if (err.code !== 'EADDRINUSE' || attempt >= maxRetries) throw err
        attempt++
        const delay = baseDelay * Math.pow(2, attempt - 1) // 1s, 2s, 4s, 8s, 16s
        if (this.node && typeof this.node.emit === 'function') {
          this.node.emit('api-bind-retry', { port: this.port, attempt, maxRetries, delay })
        }
        // Re-create the server because the previous one is in a failed state
        await new Promise(resolve => setTimeout(resolve, delay))
        this.server = createServer((req, res) => this._handle(req, res))
      }
    }
  }

  _checkRateLimit (ip) {
    return checkApiRateLimit(this._rateLimits, ip)
  }

  /**
   * Per-endpoint rate-limit gate (closes attack 8.1). For sensitive
   * paths listed in ENDPOINT_RATE_LIMITS, enforce a stricter ceiling
   * on top of the general per-IP limit. Returns true if the request
   * is under the cap.
   */
  _checkEndpointRateLimit (ip, path) {
    return checkEndpointRateLimit(this._endpointRateLimits, ip, path)
  }

  /**
   * Check if the request has a valid API key.
   * Checks Authorization: Bearer <key> header.
   * If no API key is configured, management endpoints are localhost-only.
   */
  _checkAuth (req) {
    // If API key is configured, require it
    if (this._apiKey) {
      const auth = req.headers.authorization || ''
      return constantTimeStringEqual(auth, 'Bearer ' + this._apiKey)
    }

    // No API key configured — restrict to localhost only
    return this._isLocalRequest(req)
  }

  /**
   * Extract the real client IP from the request.
   * When trustProxy is enabled, reads X-Forwarded-For or X-Real-IP headers.
   * Otherwise falls back to socket remoteAddress.
   */
  _getClientIP (req) {
    return clientIpFromRequest(req, this.trustProxy)
  }

  _isLocalRequest (req) {
    // Authorization must be based on the REAL socket address, never on
    // _getClientIP — that honors X-Forwarded-For / X-Real-IP, which are
    // attacker-controlled, so trusting them here let a remote caller spoof
    // `X-Forwarded-For: 127.0.0.1` and pass every localhost-gated check
    // (the API-key-less auth fallback AND the dispatch local-only route
    // gate for identity.sign).
    //
    // And when trustProxy is set the relay sits behind a reverse proxy, so
    // a 127.0.0.1 socket is the proxy forwarding an arbitrary external
    // request — not a trusted local admin. We cannot distinguish the two,
    // so localhost is never sufficient for authorization in that mode;
    // an API key is required (see the startup warning in start()).
    return isLoopbackLocalRequest(req, this.trustProxy)
  }

  _hasLoopbackHostHeader (req) {
    return hasLoopbackHostHeader(req)
  }

  _hasLoopbackOrigin (req) {
    return hasLoopbackOrigin(req)
  }

  _requireAuth (req, res, errorMessage) {
    if (this._checkAuth(req)) return true
    this._recordAuthFailure(req)
    // `error` is the legacy human-readable string — kept for back-compat so
    // existing clients string-matching on it don't break. `errorCode` is the
    // machine-readable prefix form new clients should branch
    // on: err.body.errorCode === 'auth-required' → retry after sign-in.
    this._json(res, {
      error: errorMessage,
      errorCode: ERR.AUTH_REQUIRED.trim().replace(/:$/, '')
    }, 401)
    return false
  }

  _recordAuthFailure (req) {
    const route = this._authFailureRoute(req)
    this._authFailureTotal++
    if (this._authFailures.has(route) || this._authFailures.size < 64) {
      this._authFailures.set(route, (this._authFailures.get(route) || 0) + 1)
    }
    const now = Date.now()
    const last = this._authFailureLogAt.get(route) || 0
    if (now - last >= 10_000) {
      this._authFailureLogAt.set(route, now)
      // Real socket address, not _getClientIP — XFF is attacker-controlled
      // and this line exists precisely to attribute unauthenticated calls.
      // Redacted to a per-process salted digest: still distinguishes/ correlates
      // a 401 burst by source, without writing raw IPs to the log.
      const ip = redactIp((req.socket && req.socket.remoteAddress) || null)
      const routeCount = this._authFailures.get(route) || this._authFailureTotal
      console.warn(`[api] 401 auth failure on ${route} from ${ip} (${routeCount} on this route, ${this._authFailureTotal} total)`)
    }
  }

  // Peer-identifier redaction posture for public payloads. Defaults ON; an
  // operator can expose raw pubkeys via config.privacy.redactPeerIdentifiers=false.
  _redactPeers () {
    const privacy = this.node && this.node.config && this.node.config.privacy
    return !(privacy && privacy.redactPeerIdentifiers === false)
  }

  _authFailureRoute (req) {
    return authFailureRoute(req)
  }

  _sanitizeAuthFailureRouteChars (value) {
    return sanitizeAuthFailureRouteChars(value)
  }

  _authFailureMetricsLines () {
    if (this._authFailureTotal === 0) return ''
    const lines = [
      '# HELP hiverelay_auth_failures_total Requests rejected with 401 by API-key auth, by route (hex ids collapsed to :hex)',
      '# TYPE hiverelay_auth_failures_total counter'
    ]
    for (const [route, count] of this._authFailures) {
      const label = escapePrometheusLabelValue(route)
      lines.push(`hiverelay_auth_failures_total{route="${label}"} ${count}`)
    }
    return '\n' + lines.join('\n') + '\n'
  }

  async _handle (req, res) {
    const ip = this._getClientIP(req) || '127.0.0.1'
    const requestOrigin = req.headers.origin
    const requestPath = new URL(req.url, `http://0.0.0.0:${this.port}`).pathname
    const cors = buildCorsDecision(this.corsOrigins, requestOrigin, requestPath)

    // CORS headers on all responses
    if (cors.varyOrigin) {
      appendVaryHeader(res, 'Origin')
    }
    if (cors.allowedOrigin) {
      res.setHeader('Access-Control-Allow-Origin', cors.allowedOrigin)
    }
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization')

    // Handle CORS preflight
    if (req.method === 'OPTIONS') {
      if (cors.preflightDenied) {
        return this._json(res, { error: 'CORS origin denied' }, 403)
      }
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
      res.writeHead(204)
      res.end()
      return
    }

    // Rate limit check
    if (!this._checkRateLimit(ip)) {
      return this._json(res, { error: 'Too many requests' }, 429, { 'Retry-After': '60' })
    }

    const url = new URL(req.url, `http://0.0.0.0:${this.port}`)
    const path = url.pathname

    // Per-endpoint stricter rate limit (closes attack 8.1). Applied
    // after general limit so the general limit still bounds total
    // request volume.
    if (!this._checkEndpointRateLimit(ip, path)) {
      return this._json(res, {
        error: formatErr('RATE_LIMITED', 'too many requests to ' + path),
        errorCode: 'rate-limited'
      }, 429, { 'Retry-After': '60' })
    }

    try {
      // Hyper Gateway — serve Hyperdrive content over HTTP
      if (path.startsWith('/v1/hyper/')) {
        return this._gateway.handle(req, res)
      }

      // Gateway stats endpoint
      if (req.method === 'GET' && path === '/api/gateway') {
        const result = buildGatewayStatsPayload({ gateway: this._gateway })
        return this._json(res, result.payload, result.status || 200)
      }

      // Index-layer query routes (§2 of the schema-sheets contract). The index
      // is hosted out-of-process by the sidecar; the relay reverse-proxies the
      // read-only GET routes so the desktop hits a single gatewayUrl. Disabled
      // (501) until config.indexSidecarUrl points at a running sidecar. Only
      // GET passthrough of method+path+query — no client headers/IP forwarded.
      if (req.method === 'GET' && (path === '/api/index/room' || path.startsWith('/index/'))) {
        return this._proxyIndex(req, res, url)
      }

      // Poker honest-usage measure (operator earnings/activity view) — derived
      // from the PLAYER-signed log, so the relay cannot forge the count. This is
      // poker's payout-relevant signal: a per-table append + writer-seat tally,
      // counts ONLY — never card/hole/payload data. Sits ahead of the generic
      // /api/poker/* mount so "usage" isn't routed as a table key. Auth-gated.
      if (path === '/api/poker/usage' && req.method === 'GET') {
        if (!this._requireAuth(req, res, MANAGEMENT_AUTH_ERROR)) return
        const pk = this._getPokerServiceProvider()
        const provider = pk.ok ? pk.provider : this._getPokerApp()
        if (!provider) return this._json(res, { error: pk.error }, pk.status)
        const tables = typeof provider.listTables === 'function' ? provider.listTables() : []
        let appends = 0
        let seats = 0
        const perTable = tables.map((t) => {
          const rawAppends = Number(t && t.length)
          const a = Number.isFinite(rawAppends) && rawAppends > 0 ? rawAppends : 0
          const w = tableWriterCount(t && t.writers)
          appends += a
          seats += w
          return { tableKey: t.tableKey, appends: a, writers: w, lastTs: t.lastTs || null }
        })
        return this._json(res, {
          enabled: true,
          service: 'poker',
          tables: tables.length,
          appends, // total player-signed log entries (relay-unforgeable)
          seats,
          perTable,
          note: 'appends = player-signed log entries (the relay cannot forge them). Counts only — no card/hole/payload data.'
        })
      }

      // Poker substrate (card-blind SignedLog) — served only when the 'poker'
      // service is enabled + running. handlePokerRoute does its own CORS + body
      // parsing, so it sits here ahead of any JSON/body guard. Table CREATE is
      // gated (anti-DoS on the maxTables cap); GET reads + signed /move stay open
      // (the signed log entry is itself the authorization). The adapter lives in
      // the optional p2p-hiveservices package, so it is dynamic-imported — core
      // stays decoupled when services aren't installed.
      if (path === '/api/poker' || path.startsWith('/api/poker/')) {
        const pk = this._getPokerServiceProvider()
        if (!pk.ok) return this._json(res, { error: pk.error }, pk.status)
        if (req.method === 'POST' && path === '/api/poker/tables') {
          if (!this._requireAuth(req, res, 'Unauthorized — API key required to create a poker table')) return
        }
        if (!this._handlePokerRoute) {
          this._handlePokerRoute = (await import('p2p-hiveservices/builtin/poker/http-adapter.js')).handlePokerRoute
        }
        const handled = await this._handlePokerRoute(req, res, { pokerApp: pk.provider })
        if (handled) return
        return this._json(res, { error: 'not found' }, 404)
      }

      // Honest metering — counterparty-signed usage receipts. A consumer submits
      // a receipt IT signed ("relay R provided <service>.<cap>, N units"); the
      // relay verifies the signature + dedups replays, then aggregates. Only
      // verified receipts are payout-eligible — the registry's own per-service
      // call counters are self-reported (statsVerified:false). POST is open: the
      // receipt's own signature IS the authorization (rejected unless it
      // verifies + is non-replayed); it carries no payload/content/IP. The
      // digest view is auth-gated (operator earnings evidence).
      if (path === '/api/usage/receipt' && req.method === 'POST') {
        if (!this.node.usageLedger) return this._json(res, { error: 'metering unavailable' }, 503)
        let body
        try { body = await this._readBody(req) } catch { return this._json(res, { error: 'invalid body' }, 400) }
        const result = this.node.usageLedger.record(body)
        return this._json(res, result, result.ok ? 200 : 400)
      }
      if (path === '/api/usage' && req.method === 'GET') {
        if (!this._requireAuth(req, res, MANAGEMENT_AUTH_ERROR)) return
        if (this.node._bandwidthReceipt) return this._json(res, this._getUsageTelemetryPayload())
        const verified = this.node.usageLedger
          ? this.node.usageLedger.digest()
          : { count: 0, totals: {}, receiptRoot: null }
        return this._json(res, {
          verified, // counterparty-signed, payout-eligible
          note: 'verified = counterparty-signed receipts (payout-eligible). Per-service registry stats are self-reported (statsVerified:false) and are NOT payout-eligible.'
        })
      }

      // Catalog endpoint — typed content catalog (apps, drives, resources, datasets, media)
      if (req.method === 'GET' && path === '/catalog.json') {
        const result = buildRelayCatalogPayload({ node: this.node, url })
        return this._json(res, result.payload, result.status || 200)
      }

      // GET routes
      if (req.method === 'GET') {
        if (path === '/health') {
          // v0.8.28 (#27): include disk status in the health payload.
          // When config.diskHealthGate=true AND disk.status='critical',
          // return 503 so load balancers / uptime monitors can drain
          // traffic away from a relay that's about to run out of disk.
          // Default behavior unchanged (still returns 200 even on
          // critical) to preserve existing operator expectations.
          const result = buildHealthResponse({
            node: this.node,
            version: this._relayVersion()
          })
          return this._json(res, result.payload, result.status)
        }

        if (path === '/status') {
          const result = buildStatusPayload({ node: this.node })
          return this._json(res, result.payload, result.status || 200)
        }

        if (path === '/metrics') {
          if (this.node.metrics) {
            return writeText(res, this.node.metrics.toPrometheus() + this._authFailureMetricsLines())
          }
          return this._json(res, { error: 'Metrics not enabled' }, 503)
        }

        if (path === '/peers') {
          return this._json(res, buildPeerListPayload({
            swarm: this.node.swarm,
            redact: this._redactPeers()
          }))
        }

        // --- Dashboard endpoints ---
        const dashboardRoute = await this._resolveDashboardGetRoute(req, path)
        if (dashboardRoute) return this._sendDashboardGetRoute(res, dashboardRoute)

        if (path === '/api/health-detail') {
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for /api/health-detail')) return
          const result = buildHealthDetailPayload({ node: this.node })
          return this._json(res, result.payload, result.status || 200)
        }

        // Capability advertisement — served at /.well-known/hiverelay.json so
        // clients can machine-detect what this relay offers (version, accept
        // policy, fees, features) without speaking Hypercore first. Also
        // mirrored at /api/capabilities for convenience. Both responses are
        // identical and cheap (<1ms to build).
        if (path === '/.well-known/hiverelay.json' || path === '/api/capabilities') {
          const doc = buildCapabilityDoc({
            relay: this.node,
            version: this._relayVersion(),
            runtime: 'node'
          })
          res.setHeader('Cache-Control', 'public, max-age=60')
          return this._json(res, doc)
        }

        // Author seeding manifest fetch. Clients GET this to discover which
        // relays an author uses for seeding. Returns 404 if we haven't cached
        // a manifest for this author — that's a normal state, not an error.
        const authorMatch = path.match(/^\/api\/authors\/([0-9a-f]{64})\/seeding\.json$/i)
        if (authorMatch) {
          const result = runAuthorManifestFetchAction({
            manifestStore: this.node.manifestStore,
            pubkey: authorMatch[1]
          })
          return this._json(res, result.payload, result.status || 200, result.headers || null)
        }

        if (path === '/api/forks/proofs') {
          const result = buildForkProofsPayload({ forkDetector: this.node.forkDetector })
          return this._json(res, result.payload, result.status || 200, result.headers || null)
        }

        // First-run setup wizard — serves the current state machine. The
        // dashboard checks `isComplete` on load and either renders the
        // wizard or the main UI. Auth: API key (bearer) or localhost. In
        // exposeToken mode the UI supplies the embedded token; without a
        // key configured this reduces to the original localhost-only gate.
        if (path === '/api/wizard') {
          if (!this._requireAuth(req, res, 'Unauthorized — wizard requires API key or localhost')) return
          const wizard = await this._getWizard()
          return this._json(res, wizard.snapshot())
        }

        // Largest measured drives — operator visibility for storage
        // triage and the input for manual purges. Management auth.
        if (path === '/api/storage/top') {
          if (!this._requireAuth(req, res, 'Unauthorized — storage top requires API key or localhost')) return
          const n = this._queryInt(url, 'n', 30, 1, 100)
          const result = buildStorageTopPayload({ storageAccounting: this.node.storageAccounting, n })
          return this._json(res, result.payload, result.status || 200)
        }

        // Operator subsidy status (Phase 1). Accrued ESTIMATE + payout
        // destination — operator-private, so management auth (bearer or
        // localhost), same gate as the wizard. {enabled:false} when the
        // subsidy is off so the dashboard card knows to stay hidden.
        if (path === '/api/subsidy') {
          if (!this._requireAuth(req, res, 'Unauthorized — subsidy status requires API key or localhost')) return
          const result = buildSubsidyStatusPayload({
            config: this.node.config,
            subsidyAccrual: this.node.subsidyAccrual
          })
          return this._json(res, result.payload, result.status || 200)
        }

        // Paid pin-lease status (operator-facing). {enabled:false} when off so
        // the dashboard card stays hidden. activeLeases is counted live from
        // the registry (entries currently under a paid, unexpired lease).
        if (path === '/api/lease') {
          if (!this._checkAuth(req)) {
            return this._json(res, { error: formatErr('NOT_ALLOWED', 'lease status requires API key or localhost') }, 403)
          }
          const result = buildLeaseStatusPayload({
            leaseManager: this.node.leaseManager,
            appRegistry: this.node.appRegistry
          })
          return this._json(res, result.payload, result.status || 200)
        }

        // Signed subsidy claim export — what the Phase-2 coordinator
        // fetches (and independently verifies) to dispatch payouts.
        if (path === '/api/subsidy/claim') {
          if (!this._requireAuth(req, res, 'Unauthorized — subsidy claim requires API key or localhost')) return
          const result = buildSubsidyClaimPayload({ subsidyAccrual: this.node.subsidyAccrual })
          return this._json(res, result.payload, result.status || 200)
        }

        if (path === '/api/alerts') {
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for /api/alerts')) return
          const result = buildAlertLogPayload({ alertManager: this.node.alertManager, url })
          return this._json(res, result.payload, result.status || 200)
        }

        if (path === '/api/auto-heal') {
          // Read-only operator telemetry. Surfaces the AutoHeal scheduler's
          // current view of archive-tier drives + which ones are below
          // diversity threshold + per-drive backoff state. Useful for the
          // dashboard, ops monitoring, and debugging recruitment decisions.
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for /api/auto-heal')) return
          const result = buildAutoHealPayload({ autoHeal: this.node.autoHeal })
          return this._json(res, result.payload, result.status || 200)
        }

        if (path === '/api/overview') {
          // Unauthenticated like /status — redact transport secrets unless
          // the caller is authenticated.
          const authed = this._checkAuth(req)
          const stats = this.node.getStats({ includeSecrets: authed })
          const uptimeMs = this.node.metrics ? Date.now() - this.node.metrics.startedAt : 0
          const config = this.node.config || {}

          return this._json(res, buildOverviewPayload({
            stats,
            config,
            memory: process.memoryUsage(),
            uptimeMs,
            errors: this.node.metrics ? this.node.metrics._errorCount : 0,
            reputation: reputationOverview(this.node.reputation),
            tor: authed && this.node.torTransport ? this.node.torTransport.getInfo() : null,
            holesailKey: authed && this.node.holesailTransport ? this.node.holesailTransport.connectionKey : null,
            health: this.node.getHealthStatus(),
            bandwidth: bandwidthOverview(this.node._bandwidthReceipt),
            registry: registryOverview(this.node.seedingRegistry, config),
            gateway: this._gateway ? sanitizeGatewayStats(this._gateway.getStats()) : null
          }))
        }

        if (path === '/api/history') {
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for /api/history')) return
          const minutes = this._queryInt(url, 'minutes', 60, 1, 24 * 60)
          const result = buildMetricsHistoryPayload({ metrics: this.node.metrics, minutes })
          return this._json(res, result.payload, result.status || 200)
        }

        if (path === '/api/apps') {
          return this._json(res, catalogEntriesByType({ node: this.node, type: 'app', url }))
        }

        if (path === '/api/drives') {
          return this._json(res, catalogEntriesByType({ node: this.node, type: 'drive', url }))
        }

        if (req.method === 'GET' && path.startsWith('/api/custody/') && path.endsWith('/status')) {
          if (!this.node.seedingRegistry) return this._json(res, { error: 'Registry not running' }, 503)
          const intentId = path.slice('/api/custody/'.length, -'/status'.length)
          if (!isValidHexKey(intentId, 64)) return this._json(res, { error: 'intentId must be 64 hex characters' }, 400)
          const status = this.node.seedingRegistry.getCustodyStatus(intentId)
          const detailed = url.searchParams.get('detailed') === '1' || url.searchParams.get('detailed') === 'true'
          if (detailed) {
            if (!this._requireAuth(req, res, 'Unauthorized — API key required for detailed custody status')) return
            return this._json(res, buildCustodyStatusPayload(status, { detailed: true }))
          }
          return this._json(res, buildCustodyStatusPayload(status))
        }

        // Anchor proof — signed attestation for a single drive. Returns
        // the relay's claim that it has blocks for the requested drive,
        // along with a current-version snapshot signed with the relay's
        // identity key. Verifiers fetch this from N relays and compare
        // — divergent signed attestations are detectable.
        //
        //   GET /api/anchors/<appKey>/proof
        //
        // Response: { appKey, anchored, version, anchoredAt, attestedAt,
        //             relayPubkey, signature } where signature signs:
        //             utf8('hiverelay-anchor-proof-v1') || appKey ||
        //             uint64(version) || uint64(attestedAt) ||
        //             uint8(anchored ? 1 : 0)
        if (path.startsWith('/api/anchors/') && path.endsWith('/proof')) {
          const result = await buildAnchorProofPayload({
            node: this.node,
            appKey: path.slice('/api/anchors/'.length, -'/proof'.length)
          })
          return this._json(res, result.payload, result.status || 200)
        }

        // Anchor status — distinguishes "we accepted seeding" from "we
        // actually have replicated blocks." Operators + clients can use
        // this to detect ghost entries that need re-replication.
        if (path === '/api/anchors') {
          const detailed = isDetailedAnchorStatusQuery(url.searchParams.get('detailed'))
          if (detailed && !this._requireAuth(req, res, 'Unauthorized — API key required for detailed anchor status')) return
          const result = buildAnchorStatusPayload({
            appRegistry: this.node.appRegistry,
            detailed,
            lastCheckedAt: this.node._lastAnchorCheckAt || null
          })
          return this._json(res, result.payload, result.status || 200)
        }

        if (path === '/api/peers') {
          return this._json(res, buildPeerListPayload({
            swarm: this.node.swarm,
            connections: this.node.connections,
            reputation: this.node.reputation,
            redact: this._redactPeers()
          }))
        }

        if (path === '/api/network') {
          const detailed = isDetailedNetworkStateQuery(url.searchParams.get('detailed'))
          if (detailed && !this._requireAuth(req, res, 'Unauthorized — API key required for detailed network state')) return
          const result = buildNetworkStatePayload({
            networkDiscovery: this.node.networkDiscovery,
            detailed
          })
          return this._json(res, result.payload, result.status || 200)
        }

        if (path === '/api/registry/pending' || path === '/api/manage/catalog/pending') {
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for ' + path)) return
          return this._json(res, buildPendingCatalogPayload({
            pendingRequests: this.node._pendingRequests,
            resolveAcceptMode: this.node._resolveAcceptMode
              ? () => this.node._resolveAcceptMode()
              : null
          }))
        }

        if (path === '/api/manage/federation') {
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for /api/manage/federation')) return
          const result = buildFederationSnapshotPayload({ federation: this.node.federation })
          return this._json(res, result.payload, result.status || 200)
        }

        if (path === '/api/manage/delegation/revocations') {
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for /api/manage/delegation/revocations')) return
          return this._json(res, buildDelegationRevocationsPayload({
            listRevocations: this.node.listRevocations ? () => this.node.listRevocations() : null
          }))
        }

        if (path === '/api/registry') {
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for /api/registry')) return
          const result = await buildRegistryStatusPayload({ registry: this.node.seedingRegistry })
          return this._json(res, result.payload, result.status || 200)
        }

        if (path === '/api/reputation') {
          const result = buildReputationLeaderboardPayload({ reputation: this.node.reputation })
          return this._json(res, result.payload, result.status || 200, result.headers || null)
        }

        if (path.startsWith('/api/reputation/')) {
          const result = buildReputationRecordPayload({
            reputation: this.node.reputation,
            pubkey: path.slice('/api/reputation/'.length)
          })
          return this._json(res, result.payload, result.status || 200, result.headers || null)
        }
      }

      // ─── Services & Router ───
      if (req.method === 'GET' && path === '/api/v1/services') {
        const result = buildServiceCatalogPayload({ registry: this.node.serviceRegistry })
        return this._json(res, result.payload, result.status || 200, result.headers || null)
      }

      if (req.method === 'GET' && path === '/api/v1/router') {
        const result = buildRouterInfoPayload({ router: this.node.router })
        return this._json(res, result.payload, result.status || 200, result.headers || null)
      }

      // ─── Content-Type validation for POST requests ─────────────────
      const contentTypeProblem = getPostJsonContentTypeProblem(req)
      if (contentTypeProblem) {
        if (contentTypeProblem.close) res.shouldKeepAlive = false
        return this._json(res, { error: contentTypeProblem.error }, 400, contentTypeProblem.close ? { Connection: 'close' } : null)
      }

      if (path.startsWith('/api/poker/') && path !== '/api/poker/usage') {
        return this._handlePokerHttpRoute(req, res)
      }

      if (req.method === 'POST' && path === '/api/v1/dispatch') {
        if (!this._requireAuth(req, res, 'Unauthorized — API key required for /api/v1/dispatch')) return
        const body = await this._readBody(req)
        return this._handleDispatch(res, body, this._isLocalRequest(req))
      }

      // POST routes
      if (req.method === 'POST') {
        const body = await this._readBody(req)

        // Seeding manifest publish. Any signed, verified manifest is
        // accepted — no API key required, because the signature on the
        // manifest IS the authorization. Unsigned or tampered manifests
        // are rejected at the signature-verification step below.
        if (path === '/api/authors/seeding.json') {
          const result = await runAuthorManifestPublishAction({
            body,
            manifestStore: this.node.manifestStore
          })
          if (!result.ok && result.kind === 'manifest-persist') return this._manifestPersistErrorResponse(res, result.error)
          return this._json(res, result.payload, result.status || 200)
        }

        // Fork-proof gossip — receive a fork proof from a federation
        // peer or a client that observed equivocation.
        //
        // Wire requirement (closes attack 8.2 from SECURITY-STRATEGY.md):
        // every cross-network fork proof MUST be signed by the
        // observer's identity key. Unsigned proofs accepted via this
        // endpoint would let any anonymous actor flood quarantines.
        if (path === '/api/forks/proof') {
          const result = await runForkProofPublishAction({
            body,
            forkDetector: this.node.forkDetector
          })
          if (!result.ok && result.kind === 'fork-persist') return this._forkPersistErrorResponse(res, result.error)
          return this._json(res, result.payload, result.status || 200)
        }

        // ─── Setup wizard mutations ──────────────────────────────
        // POST endpoints, one per wizard step. Auth: API key (bearer) or
        // localhost — _checkAuth reduces to the original localhost-only
        // gate when no key is configured (fleet/default), and accepts the
        // embedded token in exposeToken mode. The dashboard front-end
        // calls these in sequence as the operator clicks through the flow.
        // Operator-initiated purge (option-A disk recovery): unseed +
        // purge cores from disk + tombstone for each listed appKey,
        // bypassing the sweep's replica-census gates — the authenticated
        // operator is the authorization. Archive-tier and custody-bound
        // entries are refused per-key (durability promises hold even
        // here); results are reported per key, not all-or-nothing.
        if (path === '/api/eviction/purge') {
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for /api/eviction/purge')) return
          const result = await runEvictionPurgeAction({
            body,
            node: this.node
          })
          return this._json(res, result.payload, result.status || 200)
        }

        // Single-relay dedup: reclaim disk held by SUPERSEDED app versions
        // (stale versions the catalog already hides). DRY-RUN by default —
        // pass { execute: true } to actually unseed+tombstone+purge. Gated by
        // assertPurgable (archive/custody/lease are never reclaimed even when
        // superseded). Distinct from /api/eviction/purge (operator names keys)
        // and from the disk-pressure sweep (fleet over-replication).
        if (path === '/api/dedup/reclaim') {
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for /api/dedup/reclaim')) return
          const result = await runDedupReclaimAction({
            body,
            node: this.node,
            emit: (...args) => this.emit(...args)
          })
          return this._json(res, result.payload, result.status || 200)
        }

        // Set/replace the subsidy payout destination (operator's own
        // lightning address / BOLT12 offer / on-chain address — the relay
        // never holds funds). Management auth, same gate as the wizard.
        if (path === '/api/subsidy/destination') {
          if (!this._requireAuth(req, res, 'Unauthorized — subsidy destination requires API key or localhost')) return
          const result = await updateSubsidyDestination({
            body,
            config: this.node.config,
            wizard: this._wizard,
            subsidyAccrual: this.node.subsidyAccrual,
            persistConfig: () => this._persistConfig(),
            emit: (...args) => this.emit(...args)
          })
          if (!result.ok) {
            if (result.kind === 'wizard-persist') return this._wizardPersistErrorResponse(res, result.error)
            if (result.kind === 'config-persist') return this._configPersistErrorResponse(res)
            if (result.kind === 'subsidy-persist') return this._subsidyPersistErrorResponse(res, result.error)
            return this._json(res, { error: formatErr('BAD_REQUEST', result.message) }, 400)
          }
          return this._json(res, result.payload)
        }

        // Set the paid-seeding rate at runtime. Enabling/disabling the lease
        // requires the config flag + restart (the manager + LN provider are
        // wired at boot); the per-GiB-day rate is live-settable here.
        if (path === '/api/lease/config') {
          if (!this._checkAuth(req)) {
            return this._json(res, { error: formatErr('NOT_ALLOWED', 'lease config requires API key or localhost') }, 403)
          }
          const result = await runLeaseConfigAction({
            body,
            leaseManager: this.node.leaseManager
          })
          return this._json(res, result.payload, result.status || 200)
        }

        if (path.startsWith('/api/wizard/')) {
          if (!this._requireAuth(req, res, 'Unauthorized — wizard requires API key or localhost')) return
          const wizard = await this._getWizard()
          const action = path.slice('/api/wizard/'.length)
          const result = await runWizardAction({
            wizard,
            action,
            body,
            applyConfig: this.node._applyWizardConfig ? cfg => this.node._applyWizardConfig(cfg) : null,
            persistConfig: () => this._persistConfig(),
            snapshotConfig: () => this._snapshotWizardConfig(),
            restoreConfig: snapshot => this._restoreWizardConfig(snapshot),
            emit: (...args) => this.emit(...args)
          })
          if (!result.ok) {
            if (result.kind === 'not-found') return this._json(res, { error: formatErr('NOT_FOUND', result.message) }, 404)
            if (result.kind === 'apply-config') {
              const message = result.error && result.error.message ? result.error.message : String(result.error || 'unknown error')
              return this._json(res, { error: formatErr('UNSUPPORTED', 'failed to apply wizard config: ' + message) }, 500)
            }
            if (result.kind === 'config-persist') return this._configPersistErrorResponse(res)
            if (result.kind === 'wizard-persist') return this._wizardPersistErrorResponse(res, result.error)
            return this._json(res, { error: formatErr('BAD_REQUEST', result.message) }, 400)
          }
          return this._json(res, result.payload)
        }

        if (path === '/api/alerts/test') {
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for /api/alerts/test')) return
          const result = runAlertTestAction({ body, alertManager: this.node.alertManager })
          return this._json(res, result.payload, result.status || 200)
        }

        if (path === '/seed') {
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for /seed')) return
          return this._handleOperatorSeed(res, body)
        }

        // Pin a BARE Hypercore by public key (no Hyperdrive wrapper). seedApp
        // above opens a Hyperdrive; a Hyperbee — e.g. a replicable catalog bee
        // (scripts/publish-catalog-bee.js) — is a plain Hypercore and must be
        // seeded via Seeder.seedCore instead. Operator-authed: the operator
        // pins their own catalog/index cores. Content stays opaque (the relay
        // replicates blocks; it does not interpret the bee).
        if (path === '/seed-core') {
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for /seed-core')) return
          if (!this.node.seeder || typeof this.node.seeder.seedCore !== 'function') {
            return this._json(res, { error: 'seeder not available' }, 503)
          }
          const coreKey = typeof body.coreKey === 'string'
            ? body.coreKey.trim().toLowerCase()
            : (typeof body.appKey === 'string' ? body.appKey.trim().toLowerCase() : null)
          if (!coreKey || !isValidHexKey(coreKey, 64)) {
            return this._json(res, { error: 'coreKey must be 64 hex characters' }, 400)
          }
          try {
            const entry = await this.node.seeder.seedCore(coreKey)
            // Optionally advertise this core as THE relay's catalog bee, so
            // /catalog.json surfaces it for consumers to replicate.
            let catalogBee = false
            if (body.catalog === true && typeof this.node.setCatalogBeeKey === 'function') {
              await this.node.setCatalogBeeKey(coreKey)
              catalogBee = true
            }
            return this._json(res, { ok: true, coreKey, length: entry && entry.core ? entry.core.length : 0, catalogBee })
          } catch (err) {
            return this._custodyErrorResponse(res, err)
          }
        }

        // Publish this relay's index-room pointer. Called by the index sidecar
        // (loopback) once its schema-sheets room is ready, so the relay can
        // advertise it in the capability doc + /catalog.json. Operator-authed.
        if (path === '/api/manage/index-room') {
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for /api/manage/index-room')) return
          if (typeof this.node.setIndexRoom !== 'function') {
            return this._json(res, { error: 'index room not supported' }, 503)
          }
          const room = typeof body.room === 'string' ? body.room.trim() : null
          if (!room || !/^[ybndrfg8ejkmcpqxot1uwisza345h769]{52}$/.test(room)) {
            return this._json(res, { error: 'room must be a 52-char z32 key' }, 400)
          }
          try {
            await this.node.setIndexRoom(room)
            return this._json(res, { ok: true, indexRoom: room })
          } catch (err) {
            return this._json(res, { error: err.message }, 400)
          }
        }

        if (path === '/registry/publish') {
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for /registry/publish')) return
          return this._handleRegistryPublish(res, body)
        }

        if (path === '/api/custody/intent') {
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for /api/custody/intent')) return
          return this._handleOperatorCustodyAction(res, 'intent', body)
        }

        if (path.startsWith('/api/custody/') && path.endsWith('/commit')) {
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for /api/custody/:intentId/commit')) return
          const intentId = path.slice('/api/custody/'.length, -'/commit'.length)
          return this._handleOperatorCustodyAction(res, 'commit', body, intentId)
        }

        if (path.startsWith('/api/custody/') && path.endsWith('/source-retired')) {
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for /api/custody/:intentId/source-retired')) return
          const intentId = path.slice('/api/custody/'.length, -'/source-retired'.length)
          return this._handleOperatorCustodyAction(res, 'source-retired', body, intentId)
        }

        if (path === '/api/custody/proof') {
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for /api/custody/proof')) return
          return this._handleOperatorCustodyAction(res, 'proof', body)
        }

        if (path.startsWith('/api/custody/') && path.endsWith('/witness')) {
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for /api/custody/:intentId/witness')) return
          const intentId = path.slice('/api/custody/'.length, -'/witness'.length)
          return this._handleOperatorCustodyAction(res, 'witness', body, intentId)
        }

        if (path.startsWith('/api/custody/') && path.endsWith('/non-serving-proof')) {
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for /api/custody/:intentId/non-serving-proof')) return
          const intentId = path.slice('/api/custody/'.length, -'/non-serving-proof'.length)
          return this._handleOperatorCustodyAction(res, 'non-serving-proof', body, intentId)
        }

        if (path === '/registry/auto-accept') {
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for /registry/auto-accept')) return
          return this._handleLegacyAutoAccept(res, body)
        }

        if (path === '/registry/approve') {
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for /registry/approve')) return
          return this._handleCatalogAppAction(res, 'approve', body)
        }

        if (path === '/registry/reject') {
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for /registry/reject')) return
          return this._handleCatalogAppAction(res, 'reject', body)
        }

        if (path === '/registry/cancel') {
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for /registry/cancel')) return
          return this._handleRegistryCancel(res, body)
        }

        // ─── /api/manage/catalog/* — operator catalog controls ───────────
        // Replaces the older /registry/{auto-accept,approve,reject} endpoints
        // with a clearer surface aligned to the per-relay local-catalog model.

        if (path === '/api/manage/catalog/mode') {
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for /api/manage/catalog/mode')) return
          return this._handleCatalogMode(res, body)
        }

        if (path === '/api/manage/catalog/allowlist') {
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for /api/manage/catalog/allowlist')) return
          return this._handleCatalogAllowlist(res, body)
        }

        if (path === '/api/manage/catalog/approve') {
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for /api/manage/catalog/approve')) return
          return this._handleCatalogAppAction(res, 'approve', body)
        }

        if (path === '/api/manage/catalog/reject') {
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for /api/manage/catalog/reject')) return
          return this._handleCatalogAppAction(res, 'reject', body)
        }

        if (path === '/api/manage/catalog/remove') {
          // Operator-initiated removal of an app from the local catalog (and unseed).
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for /api/manage/catalog/remove')) return
          return this._handleCatalogAppAction(res, 'remove', body)
        }

        // ─── /api/manage/federation/* — explicit cross-relay federation ──

        if (path === '/api/manage/federation/follow') {
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for /api/manage/federation/follow')) return
          return this._handleFederationManagement(res, 'follow', body)
        }

        if (path === '/api/manage/federation/mirror') {
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for /api/manage/federation/mirror')) return
          return this._handleFederationManagement(res, 'mirror', body)
        }

        if (path === '/api/manage/federation/unfollow') {
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for /api/manage/federation/unfollow')) return
          return this._handleFederationManagement(res, 'unfollow', body)
        }

        if (path === '/api/manage/federation/republish') {
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for /api/manage/federation/republish')) return
          return this._handleFederationManagement(res, 'republish', body)
        }

        if (path === '/api/manage/federation/unrepublish') {
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for /api/manage/federation/unrepublish')) return
          return this._handleFederationManagement(res, 'unrepublish', body)
        }

        // ─── /api/manage/delegation/* — device-attestation revocation ────

        if (path === '/api/manage/delegation/revoke') {
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for /api/manage/delegation/revoke')) return
          const result = runDelegationRevokeAction({ body, node: this.node })
          return this._json(res, result.payload, result.status || 200)
        }

        if (path === '/unseed') {
          // Operator unseed — requires API key (use /api/v1/unseed for developer-signed unseed)
          if (!this._requireAuth(req, res, 'Unauthorized — API key required for /unseed (use /api/v1/unseed for developer-signed unseed)')) return
          const result = await runOperatorUnseedAction({ body, node: this.node })
          return this._json(res, result.payload, result.status || 200)
        }

        // ─── Developer Authenticated Unseed (Kill Switch) ───────────
        if (path === '/api/v1/unseed') {
          const result = await runPublisherUnseedAction({ body, node: this.node })
          return this._json(res, result.payload, result.status || 200)
        }

        // ─── Publisher-signed seed (no operator API key required) ────
        // Mirrors /seed but verifies a publisher Ed25519 signature over
        // the canonical v2 seed-request payload (the same scheme the
        // Protomux SeedProtocol uses). This lets app developers drive
        // seed acceptance against operator-run relays without holding
        // the operator's API key — same trust model as /api/v1/unseed,
        // extended to the publish side. Crucially this is the path that
        // accepts custodyIntentId/blindContentId/ciphertextRoot and
        // triggers the auto-emit custody-receipt downstream.
        if (path === '/api/v1/seed') {
          return this._handlePublisherSeed(res, body)
        }

        // ─── Publisher-signed custody pipeline (no operator API key) ─
        // Each entry is itself Ed25519-signed by the publisher (the
        // signature lives on body.signature). The relay's
        // _verifiedCustodyEntry validates the embedded signature before
        // append, so the publisher's signing key IS the authorization.
        // We pass `null` as the keypair so the registry refuses to
        // fall back to relay-side signing — body MUST be pre-signed.
        if (path === '/api/v1/custody/intent') {
          return this._handlePublisherCustodyAction(res, 'intent', body)
        }

        if (path.startsWith('/api/v1/custody/') && path.endsWith('/commit')) {
          const intentId = path.slice('/api/v1/custody/'.length, -'/commit'.length)
          return this._handlePublisherCustodyAction(res, 'commit', body, intentId)
        }

        if (path.startsWith('/api/v1/custody/') && path.endsWith('/source-retired')) {
          const intentId = path.slice('/api/v1/custody/'.length, -'/source-retired'.length)
          return this._handlePublisherCustodyAction(res, 'source-retired', body, intentId)
        }

        // ─── Live Management API (requires API key or localhost) ─────

        if (path.startsWith('/api/manage/')) {
          if (!this._requireAuth(req, res, MANAGEMENT_AUTH_ERROR)) return
        }

        if (path === '/api/manage/ai/models') {
          return this._handleManageAIModelRegister(res, body)
        }

        if (path === '/api/manage/ai/models/remove') {
          return this._handleManageAIModelRemove(res, body)
        }

        if (path === '/api/manage/config') {
          return this._handleConfigUpdate(res, body)
        }

        if (path === '/api/manage/services/config') {
          return this._handleServiceConfigUpdate(res, body)
        }

        if (path === '/api/manage/services') {
          return this._handleServiceManagement(res, body)
        }

        // Persist the Services-layer opt-in (enable + which builtins). Applied
        // on restart (the registry is constructed at boot). config + restart,
        // same posture as subsidy/lease — keeps services off by default.
        if (path === '/api/manage/services/config') {
          if (!this.node.setServicesConfig) {
            return this._json(res, { error: formatErr('UNSUPPORTED', 'services config not supported') }, 503)
          }
          const saved = await this.node.setServicesConfig({
            enabled: body && body.enabled === true,
            plugins: body && Array.isArray(body.plugins) ? body.plugins : []
          })
          return this._json(res, { ok: true, ...saved, restartRequired: true })
        }

        if (path === '/api/manage/mode') {
          return this._handleModeSwitch(res, body)
        }

        if (path === '/api/manage/devices') {
          return this._handleDeviceManagement(res, body)
        }

        if (path === '/api/manage/pairing') {
          return this._handlePairingManagement(res, body)
        }

        if (path === '/api/manage/transport') {
          return this._handleTransportToggle(res, body)
        }

        if (path === '/api/manage/restart') {
          const result = runLifecycleAction({
            action: 'restart',
            node: this.node,
            emit: (...args) => this.emit(...args)
          })
          return this._json(res, result.payload, result.status || 200)
        }

        if (path === '/api/manage/shutdown') {
          const result = runLifecycleAction({
            action: 'shutdown',
            node: this.node
          })
          return this._json(res, result.payload, result.status || 200)
        }
      }

      // GET — Management info endpoints (require auth)
      if (req.method === 'GET') {
        if (path.startsWith('/api/manage/') && !this._requireAuth(req, res, MANAGEMENT_AUTH_ERROR)) return

        if (path === '/api/manage/config') {
          return this._json(res, {
            config: this._getSafeConfig(),
            mode: this.node._operatingMode || 'standard'
          })
        }

        if (path === '/api/manage/ai/models') {
          return this._handleManageAIModelsList(res)
        }

        if (path === '/api/manage/services/available') {
          return this._json(res, this._getServiceConfigPayload())
        }

        if (path === '/api/manage/services') {
          const snapshot = buildServiceRegistrySnapshot(this.node.serviceRegistry)
          return this._json(res, {
            enabled: !!this.node.serviceRegistry,
            ...snapshot,
            statsVerified: false,
            services: snapshot.services.map(service => ({
              ...service,
              capabilities: Array.isArray(service.methods) ? service.methods : []
            }))
          })
        }

        if (path === '/api/manage/transports') {
          return this._json(res, buildTransportStatusPayload(this.node))
        }

        if (path === '/api/manage/devices') {
          return this._json(res, buildDeviceStatusPayload(this.node))
        }

        if (path === '/api/manage/pairing') {
          return this._json(res, buildPairingStatusPayload(this.node))
        }

        if (path === '/api/manage/modes') {
          return this._json(res, buildModeCatalogPayload(this.node._operatingMode || 'relay-core'))
        }
      }

      // 404
      this._json(res, { error: 'Not found' }, 404)
    } catch (err) {
      if (err && err.message === 'Invalid JSON body') {
        return this._json(res, { error: 'Invalid JSON body' }, 400)
      }
      if (err && err.message === 'JSON body must be an object') {
        return this._json(res, { error: 'JSON body must be an object' }, 400)
      }
      if (err && err.message === 'Request body too large') {
        res.shouldKeepAlive = false
        return this._json(res, { error: 'Request body too large' }, 413, { Connection: 'close' })
      }
      this.emit('error', { context: 'api-handler', error: err })
      this._json(res, { error: 'Internal server error' }, 500)
    }
  }

  /**
   * Determine the Access-Control-Allow-Origin value for this request.
   * Returns the origin string to set, or null if the origin is not allowed.
   */
  _getAllowedOrigin (requestOrigin) {
    return getAllowedOrigin(this.corsOrigins, requestOrigin)
  }

  // Resolve a dashboard asset across the two layouts this package ships
  // in. The git-tracked source lives at the repo root (/dashboard) — that
  // is what a fresh clone and the Docker image (`COPY . .` → /app) have.
  // Some long-lived installs also have a legacy copy at
  // packages/core/dashboard. Probe repo-root first, fall back to legacy,
  // and cache the working dir so we only probe once.
  async _readDashboardFile (filename) {
    if (this._dashboardDir) {
      return readFile(join(this._dashboardDir, filename), 'utf-8')
    }
    const candidates = [
      join(__dirname, '..', '..', '..', '..', 'dashboard'), // repo root
      join(__dirname, '..', '..', 'dashboard') // legacy packages/core
    ]
    let lastErr
    for (const dir of candidates) {
      try {
        const content = await readFile(join(dir, filename), 'utf-8')
        this._dashboardDir = dir
        return content
      } catch (err) {
        lastErr = err
      }
    }
    throw lastErr
  }

  async _serveDashboard (res, cacheKey, filename) {
    if (!this[cacheKey]) {
      this[cacheKey] = await this._readDashboardFile(filename)
    }
    const body = buildDashboardHtmlResponse(this[cacheKey], {
      exposeToken: this._uiExposeToken,
      apiKey: this._apiKey
    })
    // In exposeToken mode, embed the management token so the UI's bundled
    // fetch wrapper can send it as `Authorization: Bearer`. Injected per
    // response (not cached) and only when a key exists — start() disables
    // exposeToken otherwise. The page's <head> already ships an inert
    // reader for this meta; absent the tag it's a no-op (localhost path).
    this._setDashboardSecurityHeaders(res)
    // The token is request-scoped and must never be cached by a shared
    // proxy/browser cache.
    if (body.noStore) res.setHeader('Cache-Control', 'no-store, max-age=0')
    res.writeHead(200)
    res.end(body.html)
  }

  async _resolveDashboardGetRoute (req, path) {
    let wizardComplete = null
    if (path === '/') {
      const wizard = await this._getWizard()
      wizardComplete = wizard.isComplete()
    }
    return resolveDashboardGetRoute({
      path,
      uiSimple: this._uiSimple,
      uiExposeToken: this._uiExposeToken,
      isLocalRequest: this._isLocalRequest(req),
      wizardComplete
    })
  }

  _sendDashboardGetRoute (res, route) {
    if (route.kind === 'serve') return this._serveDashboard(res, route.cacheKey, route.filename)
    if (route.kind === 'redirect') {
      res.setHeader('Location', route.location)
      res.writeHead(302)
      res.end()
      return
    }
    if (route.kind === 'forbidden') {
      res.setHeader('Content-Type', route.contentType || 'text/plain')
      res.writeHead(403)
      res.end(route.message || 'Forbidden\n')
    }
  }

  _setDashboardSecurityHeaders (res) {
    return setDashboardSecurityHeaders(res)
  }

  _json (res, data, status = 200, headers = null) {
    return writeJson(res, data, status, headers)
  }

  /**
   * Reverse-proxy a read-only index query to the sidecar. The schema-sheets
   * index lives out-of-process (corestore-7/hc11, dependency-isolated); the
   * relay forwards only the method + path + query string so the desktop can
   * use a single gatewayUrl (contract §2.2). No client headers, cookies, or
   * IP are forwarded — the sidecar sees only the relay (loopback). Returns
   * 501 when no sidecar is configured. 8s timeout; the 5MB cap is enforced
   * INCREMENTALLY (Content-Length precheck + streamed byte budget) so a buggy
   * or compromised sidecar can't OOM the relay by sending a huge body.
   */
  async _proxyIndex (req, res, url) {
    const base = this.node.indexSidecarUrl
    if (!base) {
      return this._json(res, { error: 'index sidecar not configured', errorCode: 'index-disabled' }, 501)
    }
    const CAP = 5 * 1024 * 1024
    const target = base + url.pathname + (url.search || '')
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), 8000)
    try {
      const upstream = await fetch(target, {
        method: 'GET',
        headers: { Accept: 'application/json' },
        signal: controller.signal
      })
      // Reject up front if the upstream declares an over-cap body.
      const declared = parseInt(upstream.headers.get('content-length') || '', 10)
      if (Number.isFinite(declared) && declared > CAP) {
        controller.abort()
        return this._json(res, { error: 'index response too large' }, 502)
      }
      // Stream and enforce the cap as bytes arrive — never buffer past CAP.
      const reader = upstream.body && upstream.body.getReader ? upstream.body.getReader() : null
      if (!reader) {
        const text = await upstream.text()
        if (text.length > CAP) return this._json(res, { error: 'index response too large' }, 502)
        res.writeHead(upstream.status, { 'Content-Type': 'application/json' })
        return res.end(text)
      }
      const chunks = []
      let total = 0
      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        total += value.length
        if (total > CAP) {
          controller.abort()
          return this._json(res, { error: 'index response too large' }, 502)
        }
        chunks.push(Buffer.from(value))
      }
      res.writeHead(upstream.status, { 'Content-Type': 'application/json' })
      res.end(Buffer.concat(chunks))
    } catch (err) {
      const code = err.name === 'AbortError' ? 504 : 502
      return this._json(res, { error: 'index sidecar unreachable', detail: err.message }, code)
    } finally {
      clearTimeout(timer)
    }
  }

  /**
   * Convert a thrown error from a store-touching code path (seedApp,
   * publishCustodyIntent, publishCustodyCommit, publishSourceRetired)
   * into a structured HTTP response.
   *
   * Transient corestore/hypercore lifecycle errors ("The corestore is
   * closed", "Cannot make sessions on a closing core") get a 503 with a
   * Retry-After header so consumers retry instead of giving up. Other
   * errors fall through to the existing 400 default — same shape as
   * before this change, no behaviour change for the malformed-request
   * cases.
   */
  _custodyErrorResponse (res, err) {
    const message = err && err.message ? err.message : String(err || 'unknown error')
    if (isTransientCoreError(err)) {
      return this._json(res, {
        error: message,
        retryable: true,
        hint: 'transient corestore/hypercore lifecycle state; retry the request'
      }, 503, { 'Retry-After': String(TRANSIENT_RETRY_AFTER_SECONDS) })
    }
    return this._json(res, { error: message }, 400)
  }

  /**
   * Lazily construct + load the SetupWizard. We don't create it eagerly
   * because relays running in non-interactive mode (CLI flags only,
   * env-var configs) never need it — wizard.json never gets written
   * unless the operator actually visits /api/wizard.
   *
   * Cached on first use; survives subsequent requests in the same
   * process. Goes away on container restart, then re-loaded from disk.
   */
  async _getWizard () {
    if (this._wizard) return this._wizard
    const storageDir = this.node.config && this.node.config.storage
      ? this.node.config.storage
      : '/data'
    this._wizard = new SetupWizard({
      storagePath: join(storageDir, 'wizard.json')
    })
    try { await this._wizard.load() } catch (err) {
      this.emit('wizard-error', { message: 'wizard load failed', error: err })
    }
    return this._wizard
  }

  // Lazy-read the package version from the core workspace's package.json.
  // Cached on first call; if reading fails we just return null rather than
  // crash the endpoint. Path calculation is relative to this file:
  //   packages/core/core/relay-node/api.js  →  packages/core/package.json
  _relayVersion () {
    if (this._cachedVersion !== undefined) return this._cachedVersion
    try {
      const pkgPath = join(__dirname, '..', '..', 'package.json')
      // Synchronous read via a freshly-created CommonJS `require` — avoids
      // turning this helper async (it's called from inside sync HTTP
      // handlers) and sidesteps the ESM top-level-await restriction. One
      // read per process, result cached.
      const req = _getSyncRequire()
      const { readFileSync } = req('fs')
      const raw = readFileSync(pkgPath, 'utf8')
      const pkg = JSON.parse(raw)
      this._cachedVersion = pkg.version || null
    } catch (_) {
      this._cachedVersion = null
    }
    return this._cachedVersion
  }

  _readBody (req, maxBytes = 65536) {
    return readJsonBody(req, maxBytes)
  }

  // ─── Management Handlers ──────────────────────────────────────────

  _queryInt (url, name, defaultValue, min, max) {
    return queryInt(url, name, defaultValue, min, max)
  }

  async _handleDispatch (res, body, isLocalRequest = false) {
    const result = await runDispatchAction({
      body,
      router: this.node.router,
      isLocalRequest
    })
    return this._json(res, result.payload, result.status || 200)
  }

  _getAIServiceProvider () {
    const registry = this.node.serviceRegistry
    const services = registry && registry.services
    const entry = services && typeof services.get === 'function' ? services.get('ai') : null
    if (!entry) {
      return { ok: false, status: 503, error: 'AI service is not registered on this relay' }
    }

    if (entry.status && entry.status !== 'running') {
      return { ok: false, status: 503, error: 'AI service is not running (status=' + entry.status + ')' }
    }

    const provider = entry.provider || entry
    if (!provider || typeof provider['list-models'] !== 'function' ||
        typeof provider['register-model'] !== 'function' ||
        typeof provider['remove-model'] !== 'function') {
      return { ok: false, status: 503, error: 'AI service does not expose model management methods' }
    }

    return { ok: true, provider, entry }
  }

  // Resolve the running PokerApp provider from the registry (mirror of
  // _getAIServiceProvider). Used by the /api/poker/* gateway mount.
  _getPokerServiceProvider () {
    const registry = this.node.serviceRegistry
    const services = registry && registry.services
    const entry = services && typeof services.get === 'function' ? services.get('poker') : null
    if (!entry) {
      return { ok: false, status: 503, error: 'Poker service is not enabled on this relay' }
    }
    if (entry.status && entry.status !== 'running') {
      return { ok: false, status: 503, error: 'Poker service is not running (status=' + entry.status + ')' }
    }
    const provider = entry.provider || entry
    if (!provider || typeof provider.listTables !== 'function') {
      return { ok: false, status: 503, error: 'Poker service does not expose the substrate methods' }
    }
    return { ok: true, provider, entry }
  }

  async _handleManageAIModelsList (res) {
    const service = this._getAIServiceProvider()
    if (!service.ok) return this._json(res, { error: service.error }, service.status)
    try {
      return this._json(res, await this._manageAIModelsPayload(service.provider))
    } catch (err) {
      const error = publicManageAIModelError(err, 'AI model list failed')
      this.emit('ai-model-error', { action: 'list', error: err && err.message ? err.message : String(err || 'unknown error') })
      return this._json(res, { error }, 500)
    }
  }

  async _handleManageAIModelRegister (res, body) {
    const service = this._getAIServiceProvider()
    if (!service.ok) return this._json(res, { error: service.error }, service.status)

    const request = this._buildManageAIModelRegistration(body)
    if (!request.ok) return this._json(res, { error: request.error }, 400)

    try {
      const result = await service.provider['register-model'](request.params, {
        role: 'relay-admin',
        caller: 'manage-api',
        authenticated: true,
        node: this.node
      })
      const payload = await this._manageAIModelsPayload(service.provider)
      const model = payload.models.find(m => m.modelId === request.params.modelId) || null
      return this._json(res, {
        ok: true,
        action: 'registered',
        ...result,
        model,
        qvac: payload.qvac
      })
    } catch (err) {
      const message = publicManageAIModelError(err, 'AI model registration failed')
      const status = message === 'AI model registration failed' ? 500 : (message.startsWith('ACCESS_DENIED') ? 403 : 400)
      this.emit('ai-model-error', { action: 'register', error: err && err.message ? err.message : String(err || 'unknown error'), publicError: message })
      return this._json(res, { error: message }, status)
    }
  }

  async _handleManageAIModelRemove (res, body) {
    const service = this._getAIServiceProvider()
    if (!service.ok) return this._json(res, { error: service.error }, service.status)

    const modelId = body && typeof body.modelId === 'string' ? body.modelId.trim() : ''
    if (!modelId) return this._json(res, { error: 'modelId required' }, 400)

    try {
      const result = await service.provider['remove-model']({ modelId }, {
        role: 'relay-admin',
        caller: 'manage-api',
        authenticated: true,
        node: this.node
      })
      const payload = await this._manageAIModelsPayload(service.provider)
      return this._json(res, {
        ok: true,
        action: 'removed',
        modelId,
        removed: !!result.removed,
        qvac: payload.qvac,
        count: payload.count,
        qvacCount: payload.qvacCount
      })
    } catch (err) {
      const message = publicManageAIModelError(err, 'AI model removal failed')
      const status = message === 'AI model removal failed' ? 500 : (message.startsWith('ACCESS_DENIED') ? 403 : 400)
      this.emit('ai-model-error', { action: 'remove', error: err && err.message ? err.message : String(err || 'unknown error'), publicError: message })
      return this._json(res, { error: message }, status)
    }
  }

  _buildManageAIModelRegistration (body) {
    return buildManageAIModelRegistration(body)
  }

  async _manageAIModelsPayload (provider) {
    const models = await provider['list-models']({}, {
      role: 'relay-admin',
      caller: 'manage-api',
      authenticated: true
    })
    const status = typeof provider.status === 'function'
      ? await provider.status({}, {
        role: 'relay-admin',
        caller: 'manage-api',
        authenticated: true
      })
      : null
    return buildManageAIModelsPayload(models, status)
  }

  _manageAIModelStatus (model, qvacStatus) {
    return manageAIModelStatus(model, qvacStatus)
  }

  async _handleLegacyAutoAccept (res, body) {
    const result = await runLegacyAutoAcceptAction({
      body,
      config: this.node.config,
      persistConfig: () => this._persistConfig(),
      emit: (...args) => this.emit(...args)
    })
    if (!result.ok && result.kind === 'config-persist') return this._configPersistErrorResponse(res)
    return this._json(res, result.payload, result.status || 200)
  }

  async _handleCatalogMode (res, body) {
    const result = await runCatalogModeAction({
      body,
      config: this.node.config,
      persistConfig: () => this._persistConfig(),
      emit: (...args) => this.emit(...args)
    })
    if (!result.ok && result.kind === 'config-persist') return this._configPersistErrorResponse(res)
    return this._json(res, result.payload, result.status || 200)
  }

  async _handleCatalogAllowlist (res, body) {
    const result = await runCatalogAllowlistAction({
      body,
      config: this.node.config,
      persistConfig: () => this._persistConfig(),
      emit: (...args) => this.emit(...args)
    })
    if (!result.ok && result.kind === 'config-persist') return this._configPersistErrorResponse(res)
    return this._json(res, result.payload, result.status || 200)
  }

  async _handleCatalogAppAction (res, action, body) {
    const result = await runCatalogAppAction({
      action,
      body,
      node: this.node
    })
    return this._json(res, result.payload, result.status || 200)
  }

  async _handleRegistryCancel (res, body) {
    const result = await runRegistryCancelAction({
      body,
      node: this.node
    })
    return this._json(res, result.payload, result.status || 200)
  }

  async _handleOperatorSeed (res, body) {
    const result = await runOperatorSeedAction({
      body,
      node: this.node
    })
    return this._json(res, result.payload, result.status || 200)
  }

  async _handleRegistryPublish (res, body) {
    const result = await runRegistryPublishAction({
      body,
      node: this.node
    })
    return this._json(res, result.payload, result.status || 200)
  }

  async _handlePublisherSeed (res, body) {
    const result = await runPublisherSeedAction({
      body,
      node: this.node
    })
    if (!result.ok && result.kind === 'seed-error') return this._custodyErrorResponse(res, result.error)
    return this._json(res, result.payload, result.status || 200)
  }

  async _handleOperatorCustodyAction (res, action, body, intentId = null) {
    const result = await runOperatorCustodyAction({
      action,
      body,
      intentId,
      node: this.node
    })
    return this._json(res, result.payload, result.status || 200)
  }

  async _handlePublisherCustodyAction (res, action, body, intentId = null) {
    const result = await runPublisherCustodyAction({
      action,
      body,
      intentId,
      node: this.node
    })
    if (!result.ok && result.kind === 'custody-error') return this._custodyErrorResponse(res, result.error)
    return this._json(res, result.payload, result.status || 200)
  }

  async _handleFederationManagement (res, action, body) {
    const result = await runFederationManagementAction({
      action,
      body,
      federation: this.node.federation,
      emit: (...args) => this.emit(...args)
    })
    if (!result.ok && result.kind === 'federation-persist') return this._federationPersistErrorResponse(res, result.error)
    return this._json(res, result.payload, result.status || 200)
  }

  async _handleConfigUpdate (res, body) {
    const result = await runConfigUpdateAction({
      body,
      config: this.node.config,
      persistConfig: () => this._persistConfig(),
      safeConfigPayload: () => this._getSafeConfig()
    })
    if (!result.ok && result.kind === 'config-persist') return this._configPersistErrorResponse(res)
    return this._json(res, result.payload, result.status || 200)
  }

  _normalizeManageServicePlugins (plugins) {
    return normalizeManageServicePlugins(plugins)
  }

  _activeServiceNames () {
    return activeServiceNames(this.node.serviceRegistry)
  }

  _getConfiguredBuiltinServicePlugins () {
    return configuredBuiltinServicePlugins(this.node.config)
  }

  _getServiceConfigPayload () {
    return serviceConfigPayload(this.node.config, this.node.serviceRegistry)
  }

  _getUsageTelemetryPayload () {
    const stats = typeof this.node.getStats === 'function' ? this.node.getStats() : {}
    return usageTelemetryPayload(this.node._bandwidthReceipt, stats)
  }

  _exportBandwidthReceipts () {
    return exportBandwidthReceipts(this.node._bandwidthReceipt)
  }

  _sumReceiptBytes (receipts) {
    return sumReceiptBytes(receipts)
  }

  _getPokerUsageTelemetryPayload () {
    return pokerUsageTelemetryPayload(this._getPokerApp())
  }

  _getPokerApp () {
    if (this.node.pokerApp) return this.node.pokerApp
    if (this.node._pokerApp) return this.node._pokerApp
    if (this.node.poker && typeof this.node.poker.listTables === 'function') return this.node.poker
    const services = this.node.serviceRegistry && this.node.serviceRegistry.services
    const entry = services && typeof services.get === 'function' ? services.get('poker') : null
    if (!entry) return null
    if (entry.provider && typeof entry.provider.listTables === 'function') return entry.provider
    if (typeof entry.listTables === 'function') return entry
    return null
  }

  async _handlePokerHttpRoute (req, res) {
    const pokerApp = this._getPokerApp()
    if (!pokerApp) {
      return this._json(res, { error: formatErr('NOT_ENABLED', 'poker service is not enabled on this relay') }, 503)
    }
    let handlePokerRoute
    try {
      const mod = await import('p2p-hiveservices/builtin/poker/http-adapter.js')
      handlePokerRoute = mod.handlePokerRoute
    } catch (err) {
      return this._json(res, { error: formatErr('UNSUPPORTED', 'poker HTTP adapter unavailable: ' + err.message) }, 503)
    }
    const handled = await handlePokerRoute(req, res, { pokerApp })
    if (!handled) return this._json(res, { error: formatErr('NOT_FOUND', 'poker route not found') }, 404)
  }

  _tableWriterCount (writers) {
    return tableWriterCount(writers)
  }

  async _handleServiceConfigUpdate (res, body) {
    if (!body || typeof body !== 'object') {
      return this._json(res, { error: 'request body required' }, 400)
    }
    const normalized = this._normalizeManageServicePlugins(body.plugins)
    if (!normalized.ok) {
      return this._json(res, {
        error: normalized.error,
        available: normalized.available || BUILTIN_SERVICE_PLUGINS,
        bundles: normalized.bundles || SERVICE_PLUGIN_BUNDLES
      }, 400)
    }

    const enabled = body.enabled !== false && normalized.plugins.length > 0
    const previousEnableServices = this.node.config.enableServices
    const previousPlugins = this.node.config.plugins
    this.node.config.enableServices = enabled
    this.node.config.plugins = normalized.plugins

    if (!await this._persistConfigOrRespond(res, () => {
      this.node.config.enableServices = previousEnableServices
      this.node.config.plugins = previousPlugins
    })) return

    return this._json(res, {
      ok: true,
      restartRequired: true,
      config: this._getServiceConfigPayload()
    })
  }

  async _handleServiceManagement (res, body) {
    const result = await runServiceManagementAction({
      body,
      registry: this.node.serviceRegistry,
      config: this.node.config,
      node: this.node,
      store: this.node.store,
      persistConfig: () => this._persistConfig(),
      serviceConfigPayload: () => this._getServiceConfigPayload()
    })
    if (!result.ok && result.kind === 'config-persist') return this._configPersistErrorResponse(res)
    return this._json(res, result.payload, result.status || 200)
  }

  async _handleModeSwitch (res, body) {
    const result = await runModeSwitchAction({
      body,
      node: this.node,
      persistConfig: () => this._persistConfig(),
      emit: (...args) => this.emit(...args)
    })
    if (!result.ok && result.kind === 'config-persist') return this._configPersistErrorResponse(res)
    return this._json(res, result.payload, result.status || 200)
  }

  async _handleDeviceManagement (res, body) {
    const result = await runDeviceManagementAction({
      body,
      node: this.node
    })
    if (!result.ok && result.kind === 'device-persist') return this._devicePersistErrorResponse(res, result.error)
    return this._json(res, result.payload, result.status || 200)
  }

  _handlePairingManagement (res, body) {
    const result = runPairingManagementAction({
      body,
      node: this.node
    })
    return this._json(res, result.payload, result.status || 200)
  }

  async _handleTransportToggle (res, body) {
    const result = await runTransportToggleAction({
      body,
      config: this.node.config,
      persistConfig: () => this._persistConfig()
    })
    if (!result.ok && result.kind === 'config-persist') return this._configPersistErrorResponse(res)
    return this._json(res, result.payload, result.status || 200)
  }

  _redactCustodyStatus (status = {}) {
    return redactCustodyStatus(status)
  }

  _getSafeConfig () {
    return buildSafeConfigPayload(this.node)
  }

  _snapshotWizardConfig () {
    return snapshotWizardConfig(this.node.config)
  }

  _restoreWizardConfig (snapshot) {
    return restoreWizardConfig(this.node.config, snapshot)
  }

  async _persistConfig () {
    try {
      const { saveConfig } = await import('../../config/loader.js')
      return saveConfig(this._getSafeConfig())
    } catch (err) {
      this.emit('config-persist-error', {
        message: err && err.message ? err.message : String(err || 'unknown error'),
        error: err
      })
      throw err
    }
  }

  async _persistConfigOrRespond (res, rollback = null) {
    try {
      await this._persistConfig()
      return true
    } catch (_) {
      if (typeof rollback === 'function') {
        try {
          await rollback()
        } catch (err) {
          this.emit('config-rollback-error', {
            message: err && err.message ? err.message : String(err || 'unknown error'),
            error: err
          })
        }
      }
      this._configPersistErrorResponse(res)
      return false
    }
  }

  _configPersistErrorResponse (res) {
    return this._json(res, {
      error: formatErr('PERSIST_FAILED', CONFIG_PERSIST_FAILED_MESSAGE),
      errorCode: 'persist-failed'
    }, 500)
  }

  _federationPersistErrorResponse (res, err) {
    this.emit('federation-persist-error', {
      message: err && err.message ? err.message : String(err || 'unknown error'),
      error: err
    })
    return this._json(res, {
      error: formatErr('PERSIST_FAILED', FEDERATION_PERSIST_FAILED_MESSAGE),
      errorCode: 'persist-failed'
    }, 500)
  }

  _devicePersistErrorResponse (res, err) {
    this.emit('device-persist-error', {
      message: err && err.message ? err.message : String(err || 'unknown error'),
      error: err
    })
    return this._json(res, {
      error: formatErr('PERSIST_FAILED', DEVICE_PERSIST_FAILED_MESSAGE),
      errorCode: 'persist-failed'
    }, 500)
  }

  _wizardPersistErrorResponse (res, err) {
    this.emit('wizard-persist-error', {
      message: err && err.message ? err.message : String(err || 'unknown error'),
      error: err
    })
    return this._json(res, {
      error: formatErr('PERSIST_FAILED', WIZARD_PERSIST_FAILED_MESSAGE),
      errorCode: 'persist-failed'
    }, 500)
  }

  _subsidyPersistErrorResponse (res, err) {
    this.emit('subsidy-persist-error', {
      message: err && err.message ? err.message : String(err || 'unknown error'),
      error: err
    })
    return this._json(res, {
      error: formatErr('PERSIST_FAILED', SUBSIDY_PERSIST_FAILED_MESSAGE),
      errorCode: 'persist-failed'
    }, 500)
  }

  _manifestPersistErrorResponse (res, err) {
    this.emit('manifest-persist-error', {
      message: err && err.message ? err.message : String(err || 'unknown error'),
      error: err
    })
    return this._json(res, {
      error: formatErr('PERSIST_FAILED', MANIFEST_PERSIST_FAILED_MESSAGE),
      errorCode: 'persist-failed'
    }, 500)
  }

  _forkPersistErrorResponse (res, err) {
    this.emit('fork-persist-error', {
      message: err && err.message ? err.message : String(err || 'unknown error'),
      error: err
    })
    return this._json(res, {
      error: formatErr('PERSIST_FAILED', FORK_PERSIST_FAILED_MESSAGE),
      errorCode: 'persist-failed'
    }, 500)
  }

  async stop () {
    if (this._dashboardFeed) {
      try { await this._dashboardFeed.stop() } catch (_) {}
      this._dashboardFeed = null
    }

    if (this._pokerFeed) {
      this._pokerFeed.stop()
      this._pokerFeed = null
    }

    if (this._gateway) {
      // Never let a gateway-close failure abort the rest of teardown —
      // skipping server.close() below would leak the listening socket and
      // cause EADDRINUSE when start() re-binds the port on a self-heal
      // restart.
      try { await this._gateway.close() } catch (err) {
        this.emit('gateway-close-error', { error: err.message })
      }
    }

    if (this._rateLimitCleanup) {
      clearInterval(this._rateLimitCleanup)
      this._rateLimitCleanup = null
    }
    this._rateLimits.clear()
    this._endpointRateLimits.clear()

    if (!this.server) return
    return new Promise((resolve) => {
      // Terminate idle keep-alive connections so close() doesn't stall
      // waiting for dashboard/WS clients to disconnect (Node 18.2+).
      if (typeof this.server.closeIdleConnections === 'function') {
        try { this.server.closeIdleConnections() } catch (_) {}
      }
      if (typeof this.server.closeAllConnections === 'function') {
        // stop() is an operator-requested shutdown/restart. Active HTTP
        // requests should not be allowed to keep the API process alive
        // indefinitely after the listener has stopped accepting new work.
        try { this.server.closeAllConnections() } catch (_) {}
        setImmediate(() => {
          try { this.server?.closeAllConnections() } catch (_) {}
        })
      }
      this.server.close(() => {
        this.server = null
        this.emit('stopped')
        resolve()
      })
    })
  }
}
