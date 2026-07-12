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
import { readJsonBody } from './api-body.js'
import { buildCorsDecision, getAllowedOrigin } from './api-cors.js'
import { buildDashboardHtmlResponse, setDashboardSecurityHeaders } from './api-dashboard-html.js'
import { resolveDashboardGetRoute } from './api-dashboard-routes.js'
import { buildIndexProxyRouteResponse } from './api-index-proxy.js'
import { getPostJsonContentTypeProblem } from './api-request.js'
import {
  isHyperGatewayRoute,
  isIndexProxyRoute,
  isManagementApiRoute,
  isOutboxLogHttpReadRequest,
  isOutboxLogHttpRoute,
  isPokerHttpRoute,
  isRepairTicketHttpRoute,
  isShardHttpRoute,
  isWitnessLogHttpRoute,
  resolvePokerHttpRoutePolicy
} from './api-route-mounts.js'
import { appendVaryHeader, writeJson, writeText } from './api-response.js'
import {
  checkApiRateLimit,
  checkEndpointRateLimit,
  clientIpFromRequest,
  sweepRateLimitMap
} from './api-rate-limit.js'
import {
  resolveConfigUpdateRoute,
  runConfigUpdateAction
} from './api-config-update.js'
import {
  resolveServiceConfigUpdateRoute,
  runServiceConfigUpdateAction,
  serviceConfigPayload
} from './api-service-config.js'
import {
  resolveServiceManagementRoute,
  runServiceManagementAction
} from './api-service-management.js'
import {
  resolveAIServiceProvider,
  resolveNotifyServiceProvider,
  resolveOutboxLogServiceProvider,
  resolvePokerServiceProvider,
  resolveRepairTicketServiceProvider,
  resolveShardServiceProvider,
  resolveWitnessLogServiceProvider
} from './api-service-provider.js'
import {
  buildServiceReadRoutePayload,
  resolveServiceReadRoute
} from './api-service-read.js'
import {
  notifyQueryParams,
  resolveNotifyRoute,
  runNotifyRouteAction
} from './api-notify.js'
import {
  buildRouterInfoRoutePayload,
  resolveRouterReadRoute
} from './api-router-read.js'
import {
  buildMetricsRouteResponse,
  resolveMetricsRoute
} from './api-metrics.js'
import {
  buildStatusRoutePayload,
  resolveStatusRoute
} from './api-status-read.js'
import {
  buildUsageTelemetryRoutePayload,
  resolveUsageTelemetryRoute,
  usageTelemetryPayload
} from './api-usage-telemetry.js'
import {
  buildOverviewRouteResponse,
  resolveOverviewRoute
} from './api-overview.js'
import {
  buildOperatorTelemetryRoutePayload,
  resolveOperatorTelemetryRoute
} from './api-operator-telemetry.js'
import {
  buildAccountingReceiptRoutePayload,
  resolveAccountingReceiptRoute
} from './api-accounting-receipt.js'
import {
  buildPokerHttpAdapterUnavailableResponse,
  loadPokerHttpAdapterModule,
  resolvePokerHttpRouteHandler
} from './api-poker-http-adapter.js'
import {
  buildOutboxLogHttpAdapterUnavailableResponse,
  loadOutboxLogHttpAdapterModule,
  resolveOutboxLogHttpAdapter
} from './api-outboxlog-http-adapter.js'
import {
  buildWitnessLogHttpAdapterUnavailableResponse,
  loadWitnessLogHttpAdapterModule,
  resolveWitnessLogHttpAdapter
} from './api-witnesslog-http-adapter.js'
import {
  buildRepairTicketHttpAdapterUnavailableResponse,
  loadRepairTicketHttpAdapterModule,
  resolveRepairTicketHttpAdapter
} from './api-repairticket-http-adapter.js'
import {
  buildShardHttpAdapterUnavailableResponse,
  loadShardHttpAdapterModule,
  resolveShardHttpAdapter
} from './api-shard-http-adapter.js'
import {
  buildCapabilityRoutePayload,
  resolveCapabilityRoute
} from './api-capabilities.js'
import {
  resolveAIModelManagementRoute,
  runAIModelManagementRouteAction
} from './api-ai-models.js'
import {
  buildAnchorProofRoutePayload,
  buildAnchorStatusRoutePayload,
  buildAnchorStatusRouteContext,
  resolveAnchorProofRoute,
  resolveAnchorStatusRoute
} from './api-anchor-status.js'
import {
  buildNetworkStateRoutePayload,
  buildNetworkStateRouteContext,
  resolveNetworkStateRoute
} from './api-network-state.js'
import {
  buildSubsidyRoutePayload,
  resolveSubsidyRoute,
  updateSubsidyDestination
} from './api-subsidy.js'
import {
  RetrievabilityProofProvider,
  resolveRetrievabilityProofRoute,
  runRetrievabilityProofAction
} from './retrievability-proof.js'
import {
  buildLeaseRoutePayload,
  resolveLeaseRoute,
  runLeaseConfigAction
} from './api-lease.js'
import {
  buildWizardSnapshotRoutePayload,
  resolveWizardSnapshotRoute,
  runWizardAction,
  wizardActionFromPath
} from './api-wizard-actions.js'
import {
  resolveModeTransportManagementRoute,
  runModeTransportManagementRouteAction
} from './api-mode-transport.js'
import {
  resolveDevicePairingManagementRoute,
  runDevicePairingManagementRouteAction
} from './api-device-pairing.js'
import {
  resolveDispatchRoute,
  runDispatchAction
} from './api-dispatch.js'
import {
  buildPendingCatalogRoutePayload,
  resolveCatalogManagementRoute,
  resolvePendingCatalogRoute,
  runCatalogManagementRouteAction
} from './api-catalog-management.js'
import {
  buildCatalogReadRoutePayload,
  resolveCatalogReadRoute
} from './api-catalog-read.js'
import {
  buildRegistryStatusRoutePayload,
  resolveRegistryStatusRoute
} from './api-registry-status.js'
import {
  resolveOperatorCustodyRoute,
  resolvePublisherCustodyRoute,
  runOperatorCustodyRouteAction,
  runPublisherCustodyRouteAction
} from './api-custody-management.js'
import {
  buildCustodyStatusRoutePayload,
  resolveCustodyStatusRoute
} from './api-custody-status.js'
import {
  buildFederationSnapshotRoutePayload,
  resolveFederationManagementRoute,
  resolveFederationSnapshotRoute,
  runFederationManagementRouteAction
} from './api-federation-management.js'
import {
  resolveSeedPublishRoute,
  runSeedPublishRouteAction
} from './api-seed-publish.js'
import {
  resolveSeedCoreRoute,
  runSeedCoreAction
} from './api-seed-core.js'
import {
  resolveUnseedRoute,
  runOperatorUnseedAction,
  runPublisherUnseedAction
} from './api-unseed-actions.js'
import {
  authorManifestPubkeyFromPath,
  buildAuthorManifestFetchRoutePayload,
  resolveSignedIngressRoute,
  runAuthorManifestPublishAction,
  runForkProofPublishAction
} from './api-signed-ingress.js'
import {
  buildForkProofsRoutePayload,
  resolveForkProofReadRoute
} from './api-fork-proofs.js'
import {
  buildReputationLeaderboardRoutePayload,
  buildReputationRecordRoutePayload,
  resolveReputationLeaderboardRoute,
  resolveReputationRecordRoute
} from './api-reputation-read.js'
import {
  buildHealthResponse,
  resolveHealthRoute
} from './api-health.js'
import {
  resolveAlertManagementRoute,
  runAlertManagementRouteAction
} from './api-alert-management.js'
import {
  resolveEvictionPurgeRoute,
  runEvictionPurgeAction
} from './api-eviction-purge.js'
import {
  resolveDedupReclaimRoute,
  runDedupReclaimAction
} from './api-dedup-reclaim.js'
import {
  resolveIndexRoomRoute,
  runIndexRoomAction
} from './api-index-room.js'
import {
  resolveLifecycleManagementRoute,
  runLifecycleAction
} from './api-lifecycle-actions.js'
import {
  buildGatewayStatsRoutePayload,
  resolveGatewayStatsRoute
} from './api-gateway-stats.js'
import {
  buildManagementSnapshotRoutePayload,
  resolveManagementSnapshotRoute
} from './api-management-snapshots.js'
import {
  configPersistFailureResult,
  persistErrorMessage,
  wizardPersistFailureResult
} from './api-persist-failures.js'
import {
  buildDelegationRevocationsRoutePayload,
  resolveDelegationManagementRoute,
  runDelegationRevokeAction
} from './api-delegation-management.js'
import {
  buildSafeConfigPayload,
  restoreWizardConfig,
  snapshotWizardConfig
} from './api-safe-config.js'
import {
  buildPeerStateRoutePayload,
  resolvePeerStateRoute
} from './api-peer-state.js'
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

    // Operator-provisioned admin credential for the OutboxLog takedown surface
    // (/api/admin/takedown|restore|takedowns). Separate from _apiKey and from
    // the browser sync token by design: only an operator who sets this up front
    // can take content down. When unset the admin surface stays 404
    // (safe-by-default) — the takedown routes are simply not enabled. Read from
    // opts, config.outboxlog.adminKey, or the HIVERELAY_OUTBOXLOG_ADMIN_KEY env
    // var, mirroring how HIVERELAY_API_KEY is wired.
    this._outboxLogAdminKey = opts.outboxLogAdminKey || process.env.HIVERELAY_OUTBOXLOG_ADMIN_KEY || null

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
    this._loadPokerHttpAdapter = opts.loadPokerHttpAdapter || loadPokerHttpAdapterModule
    this._loadOutboxLogHttpAdapter = opts.loadOutboxLogHttpAdapter || loadOutboxLogHttpAdapterModule
    this._loadWitnessLogHttpAdapter = opts.loadWitnessLogHttpAdapter || loadWitnessLogHttpAdapterModule
    this._loadRepairTicketHttpAdapter = opts.loadRepairTicketHttpAdapter || loadRepairTicketHttpAdapterModule
    this._loadShardHttpAdapter = opts.loadShardHttpAdapter || loadShardHttpAdapterModule
    this._outboxLogHttpAdapter = null
    this._witnessLogHttpAdapter = null
    this._repairTicketHttpAdapter = null
    this._shardHttpAdapter = null
    this._outboxLogHttpAuth = opts.outboxLogHttpAuth || null
    this._outboxLogHttpAdminAuth = opts.outboxLogHttpAdminAuth || null
    this._outboxLogHttpState = opts.outboxLogHttpState || null
    this._witnessLogHttpState = opts.witnessLogHttpState || null
    this._repairTicketHttpState = opts.repairTicketHttpState || null
    this._shardHttpState = opts.shardHttpState || null
    this._gateway = new HyperGateway(relayNode, {
      store: relayNode.store,
      requireLifecycleDriveAuthority: true
    })
    this._retrievabilityProofProvider = new RetrievabilityProofProvider()
  }

  async start () {
    this._retrievabilityProofProvider.start({ node: this.node })
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
            const pk = resolvePokerServiceProvider(this.node)
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
    // The outboxlog HTTP surface is a PUBLIC, app-agnostic blind pipe: any browser
    // or app may call it, auth is a bearer token in a header (no cookies), so it
    // gets ACAO '*' plus the outboxlog auth headers. The global handler runs BEFORE
    // the outboxlog adapter, so without this a cross-origin preflight (which only
    // browsers send — Node clients don't, hence local tests passed) is denied 403 or
    // returned without X-Pear-Token, breaking every authenticated browser call.
    // buildCorsDecision already extends the same public treatment to poker.
    const publicOutboxLog = isOutboxLogHttpRoute(requestPath)
    if (cors.allowedOrigin || publicOutboxLog) {
      res.setHeader('Access-Control-Allow-Origin', publicOutboxLog ? '*' : cors.allowedOrigin)
    }
    res.setHeader('Access-Control-Allow-Headers', publicOutboxLog
      ? 'Content-Type, X-Pear-Token, X-Pear-Admin-Token'
      : 'Content-Type, Authorization')

    // Handle CORS preflight
    if (req.method === 'OPTIONS') {
      if (cors.preflightDenied && !publicOutboxLog) {
        return this._json(res, { error: 'CORS origin denied' }, 403)
      }
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
      res.writeHead(204)
      res.end()
      return
    }

    // Rate limit check. Outboxlog READ routes are exempt from the coarse
    // per-IP budget: a cold browser boot legitimately bursts ~10+ reads of
    // signed rows the client re-verifies anyway, and the budget was what
    // dropped returning visitors to an empty feed. The outboxlog adapter
    // still enforces its own (much higher) per-IP bucket on these routes,
    // so the exemption narrows the gate — it does not remove it.
    const outboxLogRead = publicOutboxLog && isOutboxLogHttpReadRequest(req.method, requestPath)
    if (!outboxLogRead && !this._checkRateLimit(ip)) {
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
      if (isHyperGatewayRoute(path)) {
        return this._gateway.handle(req, res)
      }

      const gatewayStatsRoute = resolveGatewayStatsRoute(req.method, path)

      // Gateway stats endpoint
      if (gatewayStatsRoute && gatewayStatsRoute.kind === 'gateway-stats') {
        const result = buildGatewayStatsRoutePayload({
          route: gatewayStatsRoute,
          gateway: this._gateway
        })
        return this._json(res, result.payload, result.status || 200)
      }

      // Index-layer query routes (§2 of the schema-sheets contract). The index
      // is hosted out-of-process by the sidecar; the relay reverse-proxies the
      // read-only GET routes so the desktop hits a single gatewayUrl. Disabled
      // (501) until config.indexSidecarUrl points at a running sidecar. Only
      // GET passthrough of method+path+query — no client headers/IP forwarded.
      if (isIndexProxyRoute(req.method, path)) {
        return this._proxyIndex(req, res, url)
      }

      // OutboxLog Peerit bridge mount. The route behavior lives in the optional
      // p2p-hiveservices package and is covered there; core only resolves the
      // running provider and lazily delegates the exact token/sync/swarm routes.
      if (isOutboxLogHttpRoute(path)) {
        const outbox = resolveOutboxLogServiceProvider(this.node)
        if (!outbox.ok) return this._json(res, { error: outbox.error }, outbox.status)
        let adapter
        try {
          adapter = await resolveOutboxLogHttpAdapter({
            cachedAdapter: this._outboxLogHttpAdapter,
            loadAdapter: this._loadOutboxLogHttpAdapter
          })
          this._outboxLogHttpAdapter = adapter
          if (!this._outboxLogHttpAuth) this._outboxLogHttpAuth = adapter.createOutboxLogTokenAuth()
          if (!this._outboxLogHttpState) this._outboxLogHttpState = adapter.createOutboxLogHttpState()
          // Construct the takedown admin auth only when the operator has
          // provisioned a credential. No credential => adminAuth stays null =>
          // the adapter serves the /api/admin/* surface as 404 (safe-by-default).
          if (!this._outboxLogHttpAdminAuth && this._outboxLogAdminKey) {
            this._outboxLogHttpAdminAuth = adapter.createOutboxLogAdminAuth({ tokens: [this._outboxLogAdminKey] })
          }
        } catch (err) {
          const unavailable = buildOutboxLogHttpAdapterUnavailableResponse(err)
          this.emit(unavailable.event.name, unavailable.event.detail)
          return this._json(res, unavailable.payload, unavailable.status)
        }
        const handled = await adapter.handleOutboxLogRoute(req, res, {
          outboxLogApp: outbox.provider,
          auth: this._outboxLogHttpAuth,
          adminAuth: this._outboxLogHttpAdminAuth,
          state: this._outboxLogHttpState,
          allowOrigin: this.corsOrigins && this.corsOrigins.length ? this.corsOrigins : '*',
          trustProxy: this.trustProxy
        })
        if (handled) return
        return this._json(res, { error: 'not found' }, 404)
      }

      // WitnessLog availability observations. Like OutboxLog, the protocol
      // implementation is optional and service-owned; Core only brokers the
      // running provider to a lazily-loaded HTTP adapter.
      if (isWitnessLogHttpRoute(path)) {
        const witness = resolveWitnessLogServiceProvider(this.node)
        if (!witness.ok) return this._json(res, { error: witness.error }, witness.status)
        let adapter
        try {
          adapter = await resolveWitnessLogHttpAdapter({
            cachedAdapter: this._witnessLogHttpAdapter,
            loadAdapter: this._loadWitnessLogHttpAdapter
          })
          this._witnessLogHttpAdapter = adapter
          if (!this._witnessLogHttpState) this._witnessLogHttpState = adapter.createWitnessLogHttpState()
        } catch (err) {
          const unavailable = buildWitnessLogHttpAdapterUnavailableResponse(err)
          this.emit(unavailable.event.name, unavailable.event.detail)
          return this._json(res, unavailable.payload, unavailable.status)
        }
        const handled = await adapter.handleWitnessLogRoute(req, res, {
          witnessLogApp: witness.provider,
          state: this._witnessLogHttpState,
          allowOrigin: this.corsOrigins && this.corsOrigins.length ? this.corsOrigins : '*',
          trustProxy: this.trustProxy
        })
        if (handled) return
        return this._json(res, { error: 'not found' }, 404)
      }

      // RepairTicket self-healing loop. Service-owned records make Core a
      // broker only: it verifies there is a running provider, then delegates
      // repair tickets/claims/receipts/closures to the optional adapter.
      if (isRepairTicketHttpRoute(path)) {
        const repair = resolveRepairTicketServiceProvider(this.node)
        if (!repair.ok) return this._json(res, { error: repair.error }, repair.status)
        let adapter
        try {
          adapter = await resolveRepairTicketHttpAdapter({
            cachedAdapter: this._repairTicketHttpAdapter,
            loadAdapter: this._loadRepairTicketHttpAdapter
          })
          this._repairTicketHttpAdapter = adapter
          if (!this._repairTicketHttpState) this._repairTicketHttpState = adapter.createRepairTicketHttpState()
        } catch (err) {
          const unavailable = buildRepairTicketHttpAdapterUnavailableResponse(err)
          this.emit(unavailable.event.name, unavailable.event.detail)
          return this._json(res, unavailable.payload, unavailable.status)
        }
        const handled = await adapter.handleRepairTicketRoute(req, res, {
          repairTicketApp: repair.provider,
          state: this._repairTicketHttpState,
          allowOrigin: this.corsOrigins && this.corsOrigins.length ? this.corsOrigins : '*',
          trustProxy: this.trustProxy
        })
        if (handled) return
        return this._json(res, { error: 'not found' }, 404)
      }

      // Blind shard store — content-addressed custody-shard dispersal surface.
      // GET/HEAD/prove/DELETE are content-neutral (opaque bytes by hash); PUT is
      // authorized by a signed pin the service verifies against a custody intent
      // this relay has indexed (relayPubkey -> shareIndex -> shard). Core is a
      // broker: resolve the running provider, then delegate the resolved route to
      // the optional service-owned adapter. The adapter writes the response.
      if (isShardHttpRoute(path)) {
        const shard = resolveShardServiceProvider(this.node)
        if (!shard.ok) return this._json(res, { error: shard.error }, shard.status)
        let adapter
        try {
          adapter = await resolveShardHttpAdapter({
            cachedAdapter: this._shardHttpAdapter,
            loadAdapter: this._loadShardHttpAdapter
          })
          this._shardHttpAdapter = adapter
          if (!this._shardHttpState) this._shardHttpState = adapter.createShardHttpState()
        } catch (err) {
          const unavailable = buildShardHttpAdapterUnavailableResponse(err)
          this.emit(unavailable.event.name, unavailable.event.detail)
          return this._json(res, unavailable.payload, unavailable.status)
        }
        const route = adapter.resolveShardRoute(req.method, path)
        if (!route) return this._json(res, { error: 'not found' }, 404)
        const handled = await adapter.handleShardHttp(shard.provider, route, req, res, {
          url,
          state: this._shardHttpState,
          trustProxy: this.trustProxy
        })
        if (handled) return
        return this._json(res, { error: 'not found' }, 404)
      }

      const usageRoute = resolveUsageTelemetryRoute(req.method, path)
      const catalogReadRoute = resolveCatalogReadRoute(req.method, path)
      const serviceReadRoute = resolveServiceReadRoute(req.method, path)
      const routerReadRoute = resolveRouterReadRoute(req.method, path)
      const notifyRoute = resolveNotifyRoute(req.method, path)

      // Poker honest-usage measure (operator earnings/activity view) — derived
      // from the PLAYER-signed log, so the relay cannot forge the count. This is
      // poker's payout-relevant signal: a per-table append + writer-seat tally,
      // counts ONLY — never card/hole/payload data. Sits ahead of the generic
      // /api/poker/* mount so "usage" isn't routed as a table key. Auth-gated.
      if (usageRoute && usageRoute.kind === 'poker-usage') {
        if (!this._requireAuth(req, res, usageRoute.authMessage)) return
        const pk = resolvePokerServiceProvider(this.node)
        const provider = pk.ok ? pk.provider : this._getPokerApp()
        // No provider is NOT an error here: this is the operator's telemetry
        // view, and "poker isn't enabled" is a valid answer. The payload
        // builder returns { enabled: false, tables: 0, ... } for a null
        // provider — the contract the release-image smoke gate checks on a
        // stock (no-services) boot. 503ing instead kept every Release
        // surfaces run red from v0.24.0 through v0.24.3.
        const result = buildUsageTelemetryRoutePayload({
          route: usageRoute,
          pokerProvider: provider || null
        })
        return this._json(res, result.payload, result.status || 200)
      }

      // Poker substrate (card-blind SignedLog) — served only when the 'poker'
      // service is enabled + running. handlePokerRoute does its own CORS + body
      // parsing, so it sits here ahead of any JSON/body guard. Table CREATE is
      // gated (anti-DoS on the maxTables cap); GET reads + signed /move stay open
      // (the signed log entry is itself the authorization). The adapter lives in
      // the optional p2p-hiveservices package, so it is dynamic-imported — core
      // stays decoupled when services aren't installed.
      if (isPokerHttpRoute(path)) {
        const pk = resolvePokerServiceProvider(this.node)
        if (!pk.ok) return this._json(res, { error: pk.error }, pk.status)
        const pokerRoutePolicy = resolvePokerHttpRoutePolicy(req.method, path)
        if (pokerRoutePolicy && pokerRoutePolicy.authRequired) {
          if (!this._requireAuth(req, res, pokerRoutePolicy.authMessage)) return
        }
        let handlePokerRoute
        try {
          handlePokerRoute = await resolvePokerHttpRouteHandler({
            cachedHandler: this._handlePokerRoute,
            loadAdapter: this._loadPokerHttpAdapter
          })
          this._handlePokerRoute = handlePokerRoute
        } catch (err) {
          const unavailable = buildPokerHttpAdapterUnavailableResponse(err)
          this.emit(unavailable.event.name, unavailable.event.detail)
          return this._json(res, unavailable.payload, unavailable.status)
        }
        const handled = await handlePokerRoute(req, res, { pokerApp: pk.provider })
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
      if (usageRoute && usageRoute.kind === 'receipt-submit') {
        let body
        try { body = await this._readBody(req) } catch { return this._json(res, { error: 'invalid body' }, 400) }
        const result = buildUsageTelemetryRoutePayload({
          route: usageRoute,
          usageLedger: this.node.usageLedger,
          body
        })
        return this._json(res, result.payload, result.status || 200)
      }
      if (usageRoute && usageRoute.kind === 'usage-digest') {
        if (!this._requireAuth(req, res, usageRoute.authMessage)) return
        const result = buildUsageTelemetryRoutePayload({
          route: usageRoute,
          usageLedger: this.node.usageLedger,
          bandwidthReceiptPayload: this.node._bandwidthReceipt ? this._getUsageTelemetryPayload() : null
        })
        return this._json(res, result.payload, result.status || 200)
      }

      // Catalog endpoint — typed content catalog (apps, drives, resources, datasets, media)
      if (catalogReadRoute && catalogReadRoute.kind === 'catalog') {
        const result = buildCatalogReadRoutePayload({
          route: catalogReadRoute,
          node: this.node,
          url
        })
        return this._json(res, result.payload, result.status || 200)
      }

      // GET routes
      if (req.method === 'GET') {
        const peerStateRoute = resolvePeerStateRoute(req.method, path)
        const healthRoute = resolveHealthRoute(req.method, path)
        const statusRoute = resolveStatusRoute(req.method, path)
        const metricsRoute = resolveMetricsRoute(req.method, path)
        const wizardSnapshotRoute = resolveWizardSnapshotRoute(req.method, path)

        if (healthRoute && healthRoute.kind === 'health') {
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

        if (statusRoute && statusRoute.kind === 'status') {
          const result = buildStatusRoutePayload({
            route: statusRoute,
            node: this.node
          })
          return this._json(res, result.payload, result.status || 200)
        }

        if (metricsRoute && metricsRoute.kind === 'metrics') {
          const result = buildMetricsRouteResponse({
            metrics: this.node.metrics,
            authFailureLines: this._authFailureMetricsLines()
          })
          if (!result.ok) return this._json(res, result.payload, result.status || 503)
          return writeText(res, result.text, result.status || 200)
        }

        if (peerStateRoute && peerStateRoute.kind === 'legacy-peer-list') {
          const result = buildPeerStateRoutePayload({
            route: peerStateRoute,
            swarm: this.node.swarm,
            redact: this._redactPeers()
          })
          return this._json(res, result.payload, result.status || 200)
        }

        // --- Dashboard endpoints ---
        const dashboardRoute = await this._resolveDashboardGetRoute(req, path)
        if (dashboardRoute) return this._sendDashboardGetRoute(res, dashboardRoute)

        const operatorTelemetryRoute = resolveOperatorTelemetryRoute(req.method, path)
        if (operatorTelemetryRoute && operatorTelemetryRoute.kind === 'health-detail') {
          if (!this._requireAuth(req, res, operatorTelemetryRoute.authMessage)) return
          const result = buildOperatorTelemetryRoutePayload({ route: operatorTelemetryRoute, node: this.node, url })
          return this._json(res, result.payload, result.status || 200)
        }

        // Capability advertisement — served at /.well-known/hiverelay.json so
        // clients can machine-detect what this relay offers (version, accept
        // policy, fees, features) without speaking Hypercore first. Also
        // mirrored at /api/capabilities for convenience. Both responses are
        // identical and cheap (<1ms to build).
        const capabilityRoute = resolveCapabilityRoute(req.method, path)
        if (capabilityRoute && capabilityRoute.kind === 'capability-doc') {
          const result = buildCapabilityRoutePayload({
            node: this.node,
            version: this._relayVersion(),
            runtime: 'node'
          })
          return this._json(res, result.payload, result.status || 200, result.headers || null)
        }

        // Author seeding manifest fetch. Clients GET this to discover which
        // relays an author uses for seeding. Returns 404 if we haven't cached
        // a manifest for this author — that's a normal state, not an error.
        const authorPubkey = authorManifestPubkeyFromPath(path)
        if (authorPubkey) {
          const result = buildAuthorManifestFetchRoutePayload({
            manifestStore: this.node.manifestStore,
            path
          })
          return this._json(res, result.payload, result.status || 200, result.headers || null)
        }

        const forkProofReadRoute = resolveForkProofReadRoute(req.method, path)
        if (forkProofReadRoute && forkProofReadRoute.kind === 'fork-proof-list') {
          const result = buildForkProofsRoutePayload({
            route: forkProofReadRoute,
            forkDetector: this.node.forkDetector
          })
          return this._json(res, result.payload, result.status || 200, result.headers || null)
        }

        // First-run setup wizard — serves the current state machine. The
        // dashboard checks `isComplete` on load and either renders the
        // wizard or the main UI. Auth: API key (bearer) or localhost. In
        // exposeToken mode the UI supplies the embedded token; without a
        // key configured this reduces to the original localhost-only gate.
        if (wizardSnapshotRoute && wizardSnapshotRoute.kind === 'wizard-snapshot') {
          if (!this._requireAuth(req, res, wizardSnapshotRoute.authMessage)) return
          const result = await buildWizardSnapshotRoutePayload({
            route: wizardSnapshotRoute,
            getWizard: () => this._getWizard()
          })
          return this._json(res, result.payload, result.status || 200)
        }

        // Largest measured drives — operator visibility for storage
        // triage and the input for manual purges. Management auth.
        if (operatorTelemetryRoute && operatorTelemetryRoute.kind === 'storage-top') {
          if (!this._requireAuth(req, res, operatorTelemetryRoute.authMessage)) return
          const result = buildOperatorTelemetryRoutePayload({ route: operatorTelemetryRoute, node: this.node, url })
          return this._json(res, result.payload, result.status || 200)
        }

        const accountingReceiptRoute = resolveAccountingReceiptRoute(req.method, path)
        if (accountingReceiptRoute && accountingReceiptRoute.kind === 'receipt') {
          if (!this._requireAuth(req, res, accountingReceiptRoute.authMessage)) return
          const result = await buildAccountingReceiptRoutePayload({
            route: accountingReceiptRoute,
            node: this.node,
            url
          })
          return this._json(res, result.payload, result.status || 200)
        }

        // Operator subsidy status (Phase 1). Accrued ESTIMATE + payout
        // destination — operator-private, so management auth (bearer or
        // localhost), same gate as the wizard. {enabled:false} when the
        // subsidy is off so the dashboard card knows to stay hidden.
        const subsidyRoute = resolveSubsidyRoute(req.method, path)
        if (subsidyRoute && subsidyRoute.kind === 'status') {
          if (!this._requireAuth(req, res, subsidyRoute.authMessage)) return
          const result = buildSubsidyRoutePayload({
            route: subsidyRoute,
            config: this.node.config,
            subsidyAccrual: this.node.subsidyAccrual
          })
          return this._json(res, result.payload, result.status || 200)
        }

        // Paid pin-lease status (operator-facing). {enabled:false} when off so
        // the dashboard card stays hidden. activeLeases is counted live from
        // the registry (entries currently under a paid, unexpired lease).
        const leaseRoute = resolveLeaseRoute(req.method, path)
        if (leaseRoute && leaseRoute.kind === 'status') {
          if (!this._checkAuth(req)) {
            return this._json(res, { error: formatErr('NOT_ALLOWED', leaseRoute.authMessage) }, 403)
          }
          const result = buildLeaseRoutePayload({
            route: leaseRoute,
            leaseManager: this.node.leaseManager,
            appRegistry: this.node.appRegistry
          })
          return this._json(res, result.payload, result.status || 200)
        }

        // Signed subsidy claim export — what the Phase-2 coordinator
        // fetches (and independently verifies) to dispatch payouts.
        if (subsidyRoute && subsidyRoute.kind === 'claim') {
          if (!this._requireAuth(req, res, subsidyRoute.authMessage)) return
          const result = buildSubsidyRoutePayload({
            route: subsidyRoute,
            subsidyAccrual: this.node.subsidyAccrual
          })
          return this._json(res, result.payload, result.status || 200)
        }

        const alertRoute = resolveAlertManagementRoute(req.method, path)
        if (alertRoute && alertRoute.kind === 'log') {
          if (!this._requireAuth(req, res, alertRoute.authMessage)) return
          const result = runAlertManagementRouteAction({
            route: alertRoute,
            alertManager: this.node.alertManager,
            url
          })
          return this._json(res, result.payload, result.status || 200)
        }

        if (operatorTelemetryRoute && operatorTelemetryRoute.kind === 'auto-heal') {
          // Read-only operator telemetry. Surfaces the AutoHeal scheduler's
          // current view of archive-tier drives + which ones are below
          // diversity threshold + per-drive backoff state. Useful for the
          // dashboard, ops monitoring, and debugging recruitment decisions.
          if (!this._requireAuth(req, res, operatorTelemetryRoute.authMessage)) return
          const result = buildOperatorTelemetryRoutePayload({ route: operatorTelemetryRoute, node: this.node, url })
          return this._json(res, result.payload, result.status || 200)
        }

        const overviewRoute = resolveOverviewRoute(req.method, path)
        if (overviewRoute && overviewRoute.kind === 'overview') {
          // Unauthenticated like /status — redact transport secrets unless
          // the caller is authenticated.
          const authed = this._checkAuth(req)
          const result = buildOverviewRouteResponse({
            route: overviewRoute,
            node: this.node,
            authed,
            memory: process.memoryUsage(),
            gateway: this._gateway
          })
          return this._json(res, result.payload, result.status || 200)
        }

        if (operatorTelemetryRoute && operatorTelemetryRoute.kind === 'history') {
          if (!this._requireAuth(req, res, operatorTelemetryRoute.authMessage)) return
          const result = buildOperatorTelemetryRoutePayload({ route: operatorTelemetryRoute, node: this.node, url })
          return this._json(res, result.payload, result.status || 200)
        }

        if (catalogReadRoute && catalogReadRoute.kind === 'legacy-type') {
          const result = buildCatalogReadRoutePayload({
            route: catalogReadRoute,
            node: this.node,
            url
          })
          return this._json(res, result.payload, result.status || 200)
        }

        const custodyStatusRoute = resolveCustodyStatusRoute(req.method, path)
        if (custodyStatusRoute && custodyStatusRoute.kind === 'custody-status') {
          const result = buildCustodyStatusRoutePayload({
            path,
            url,
            registry: this.node.seedingRegistry,
            disabled: this._custodyApiDisabled()
          })
          if (result.requiresAuth) {
            if (!this._requireAuth(req, res, result.authMessage)) return
          }
          return this._json(res, result.payload, result.status || 200)
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
        const anchorProofRoute = resolveAnchorProofRoute(req.method, path)
        if (anchorProofRoute && anchorProofRoute.kind === 'anchor-proof') {
          const result = await buildAnchorProofRoutePayload({
            node: this.node,
            path
          })
          return this._json(res, result.payload, result.status || 200)
        }

        // Anchor status — distinguishes "we accepted seeding" from "we
        // actually have replicated blocks." Operators + clients can use
        // this to detect ghost entries that need re-replication.
        const anchorStatusRoute = resolveAnchorStatusRoute(req.method, path)
        if (anchorStatusRoute && anchorStatusRoute.kind === 'anchor-status') {
          const route = buildAnchorStatusRouteContext(url)
          if (route.requiresAuth && !this._requireAuth(req, res, 'Unauthorized — API key required for detailed anchor status')) return
          const result = buildAnchorStatusRoutePayload({
            route: anchorStatusRoute,
            context: route,
            appRegistry: this.node.appRegistry,
            lastCheckedAt: this.node._lastAnchorCheckAt || null
          })
          return this._json(res, result.payload, result.status || 200)
        }

        if (peerStateRoute && peerStateRoute.kind === 'peer-list') {
          const result = buildPeerStateRoutePayload({
            route: peerStateRoute,
            swarm: this.node.swarm,
            connections: this.node.connections,
            reputation: this.node.reputation,
            redact: this._redactPeers()
          })
          return this._json(res, result.payload, result.status || 200)
        }

        const networkStateRoute = resolveNetworkStateRoute(req.method, path)
        if (networkStateRoute && networkStateRoute.kind === 'network-state') {
          const route = buildNetworkStateRouteContext(url)
          if (route.requiresAuth && !this._requireAuth(req, res, 'Unauthorized — API key required for detailed network state')) return
          const result = buildNetworkStateRoutePayload({
            route: networkStateRoute,
            context: route,
            networkDiscovery: this.node.networkDiscovery
          })
          return this._json(res, result.payload, result.status || 200)
        }

        const pendingCatalogRoute = resolvePendingCatalogRoute(req.method, path)
        if (pendingCatalogRoute && pendingCatalogRoute.kind === 'pending-catalog') {
          if (!this._requireAuth(req, res, pendingCatalogRoute.authMessage)) return
          const result = buildPendingCatalogRoutePayload({
            route: pendingCatalogRoute,
            pendingRequests: this.node._pendingRequests,
            resolveAcceptMode: this.node._resolveAcceptMode
              ? () => this.node._resolveAcceptMode()
              : null
          })
          return this._json(res, result.payload, result.status || 200)
        }

        const federationSnapshotRoute = resolveFederationSnapshotRoute(req.method, path)
        if (federationSnapshotRoute && federationSnapshotRoute.kind === 'federation-snapshot') {
          if (!this._requireAuth(req, res, federationSnapshotRoute.authMessage)) return
          const result = buildFederationSnapshotRoutePayload({
            route: federationSnapshotRoute,
            federation: this.node.federation,
            disabled: this._federationApiDisabled()
          })
          return this._json(res, result.payload, result.status || 200)
        }

        const delegationRoute = resolveDelegationManagementRoute(req.method, path)
        if (delegationRoute && delegationRoute.kind === 'list') {
          if (!this._requireAuth(req, res, delegationRoute.authMessage)) return
          const result = buildDelegationRevocationsRoutePayload({
            route: delegationRoute,
            listRevocations: this.node.listRevocations ? () => this.node.listRevocations() : null
          })
          return this._json(res, result.payload, result.status || 200)
        }

        const registryStatusRoute = resolveRegistryStatusRoute(req.method, path)
        if (registryStatusRoute && registryStatusRoute.kind === 'registry-status') {
          if (!this._requireAuth(req, res, registryStatusRoute.authMessage)) return
          const result = await buildRegistryStatusRoutePayload({
            route: registryStatusRoute,
            registry: this.node.seedingRegistry
          })
          return this._json(res, result.payload, result.status || 200)
        }

        const reputationLeaderboardRoute = resolveReputationLeaderboardRoute(req.method, path)
        if (reputationLeaderboardRoute && reputationLeaderboardRoute.kind === 'reputation-leaderboard') {
          const result = buildReputationLeaderboardRoutePayload({
            route: reputationLeaderboardRoute,
            reputation: this.node.reputation
          })
          return this._json(res, result.payload, result.status || 200, result.headers || null)
        }

        const reputationRecordRoute = resolveReputationRecordRoute(req.method, path)
        if (reputationRecordRoute && reputationRecordRoute.kind === 'reputation-record') {
          const result = buildReputationRecordRoutePayload({
            reputation: this.node.reputation,
            path
          })
          return this._json(res, result.payload, result.status || 200, result.headers || null)
        }
      }

      // ─── Services & Router ───
      if (serviceReadRoute && serviceReadRoute.kind === 'service-catalog') {
        const result = buildServiceReadRoutePayload({
          route: serviceReadRoute,
          registry: this.node.serviceRegistry
        })
        return this._json(res, result.payload, result.status || 200, result.headers || null)
      }

      if (routerReadRoute && routerReadRoute.kind === 'router-info') {
        const result = buildRouterInfoRoutePayload({
          route: routerReadRoute,
          router: this.node.router
        })
        return this._json(res, result.payload, result.status || 200, result.headers || null)
      }

      if (notifyRoute && !notifyRoute.management && req.method === 'GET') {
        const result = await runNotifyRouteAction({
          route: notifyRoute,
          providerResult: resolveNotifyServiceProvider(this.node),
          body: notifyQueryParams(url)
        })
        return this._json(res, result.payload, result.status || 200, result.headers || null)
      }

      // ─── Content-Type validation for POST requests ─────────────────
      const contentTypeProblem = getPostJsonContentTypeProblem(req)
      if (contentTypeProblem) {
        if (contentTypeProblem.close) res.shouldKeepAlive = false
        return this._json(res, { error: contentTypeProblem.error }, 400, contentTypeProblem.close ? { Connection: 'close' } : null)
      }

      const dispatchRoute = resolveDispatchRoute(req.method, path)
      if (dispatchRoute && dispatchRoute.kind === 'dispatch') {
        if (!this._requireAuth(req, res, dispatchRoute.authMessage)) return
        const body = await this._readBody(req)
        const result = await runDispatchAction({
          body,
          router: this.node.router,
          isLocalRequest: this._isLocalRequest(req)
        })
        return this._json(res, result.payload, result.status || 200)
      }

      // POST routes
      if (req.method === 'POST') {
        const body = await this._readBody(req)

        if (notifyRoute && !notifyRoute.management) {
          const result = await runNotifyRouteAction({
            route: notifyRoute,
            providerResult: resolveNotifyServiceProvider(this.node),
            body
          })
          return this._json(res, result.payload, result.status || 200, result.headers || null)
        }

        // Seeding manifest publish. Any signed, verified manifest is
        // accepted — no API key required, because the signature on the
        // manifest IS the authorization. Unsigned or tampered manifests
        // are rejected at the signature-verification step below.
        const signedIngressRoute = resolveSignedIngressRoute(req.method, path)
        if (signedIngressRoute && signedIngressRoute.kind === 'author-manifest-publish') {
          const result = await runAuthorManifestPublishAction({
            body,
            manifestStore: this.node.manifestStore,
            emit: (...args) => this.emit(...args)
          })
          return this._json(res, result.payload, result.status || 200)
        }

        // Fork-proof gossip — receive a fork proof from a federation
        // peer or a client that observed equivocation.
        //
        // Wire requirement (closes attack 8.2 from SECURITY-STRATEGY.md):
        // every cross-network fork proof MUST be signed by the
        // observer's identity key. Unsigned proofs accepted via this
        // endpoint would let any anonymous actor flood quarantines.
        if (signedIngressRoute && signedIngressRoute.kind === 'fork-proof-publish') {
          const result = await runForkProofPublishAction({
            body,
            forkDetector: this.node.forkDetector,
            emit: (...args) => this.emit(...args)
          })
          return this._json(res, result.payload, result.status || 200)
        }

        // Core proof-of-retrievability endpoint. This mirrors the
        // storage-proof service request shape but does not require the optional
        // services runtime, which lets the RelayKernel profile expose proof as
        // a kernel-compatible surface while legacy service clients continue to
        // work unchanged.
        const retrievabilityProofRoute = resolveRetrievabilityProofRoute(req.method, path)
        if (retrievabilityProofRoute && retrievabilityProofRoute.kind === 'retrievability-proof') {
          const result = await runRetrievabilityProofAction({
            body,
            provider: this._retrievabilityProofProvider,
            context: { caller: ip }
          })
          return this._json(res, result.payload, result.status || 200, result.headers || null)
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
        const evictionPurgeRoute = resolveEvictionPurgeRoute(req.method, path)
        if (evictionPurgeRoute && evictionPurgeRoute.kind === 'eviction-purge') {
          if (!this._requireAuth(req, res, evictionPurgeRoute.authMessage)) return
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
        const dedupReclaimRoute = resolveDedupReclaimRoute(req.method, path)
        if (dedupReclaimRoute && dedupReclaimRoute.kind === 'dedup-reclaim') {
          if (!this._requireAuth(req, res, dedupReclaimRoute.authMessage)) return
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
        const subsidyRoute = resolveSubsidyRoute(req.method, path)
        if (subsidyRoute && subsidyRoute.kind === 'destination') {
          if (!this._requireAuth(req, res, subsidyRoute.authMessage)) return
          const result = await updateSubsidyDestination({
            body,
            config: this.node.config,
            wizard: this._wizard,
            subsidyAccrual: this.node.subsidyAccrual,
            persistConfig: () => this._persistConfig(),
            emit: (...args) => this.emit(...args)
          })
          if (!result.ok) {
            if (result.kind === 'wizard-persist' || result.kind === 'config-persist') return this._persistFailureResponse(res, result)
            if (result.payload) return this._json(res, result.payload, result.status || 400)
            return this._json(res, { error: formatErr('BAD_REQUEST', result.message) }, 400)
          }
          return this._json(res, result.payload)
        }

        // Set the paid-seeding rate at runtime. Enabling/disabling the lease
        // requires the config flag + restart (the manager + LN provider are
        // wired at boot); the per-GiB-day rate is live-settable here.
        const leaseRoute = resolveLeaseRoute(req.method, path)
        if (leaseRoute && leaseRoute.kind === 'config') {
          if (!this._checkAuth(req)) {
            return this._json(res, { error: formatErr('NOT_ALLOWED', leaseRoute.authMessage) }, 403)
          }
          const result = await runLeaseConfigAction({
            body,
            leaseManager: this.node.leaseManager
          })
          return this._json(res, result.payload, result.status || 200)
        }

        const wizardAction = wizardActionFromPath(path)
        if (wizardAction !== null) {
          if (!this._requireAuth(req, res, 'Unauthorized — wizard requires API key or localhost')) return
          const wizard = await this._getWizard()
          const result = await runWizardAction({
            wizard,
            action: wizardAction,
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
            if (result.kind === 'config-persist' || result.kind === 'wizard-persist') return this._persistFailureResponse(res, result)
            return this._json(res, { error: formatErr('BAD_REQUEST', result.message) }, 400)
          }
          return this._json(res, result.payload)
        }

        const alertRoute = resolveAlertManagementRoute(req.method, path)
        if (alertRoute && alertRoute.kind === 'test') {
          if (!this._requireAuth(req, res, alertRoute.authMessage)) return
          const result = runAlertManagementRouteAction({
            route: alertRoute,
            body,
            alertManager: this.node.alertManager
          })
          return this._json(res, result.payload, result.status || 200)
        }

        const seedPublishRoute = resolveSeedPublishRoute(req.method, path)
        if (seedPublishRoute && seedPublishRoute.kind === 'operator-seed') {
          if (!this._requireAuth(req, res, seedPublishRoute.authMessage)) return
          const result = await runSeedPublishRouteAction({
            route: seedPublishRoute,
            body,
            node: this.node,
            disabled: this._custodyApiDisabled()
          })
          if (!result.ok && result.kind === 'seed-error') return this._custodyErrorResponse(res, result.error)
          return this._json(res, result.payload, result.status || 200)
        }

        const seedCoreRoute = resolveSeedCoreRoute(req.method, path)
        if (seedCoreRoute && seedCoreRoute.kind === 'seed-core') {
          if (!this._requireAuth(req, res, seedCoreRoute.authMessage)) return
          const result = await runSeedCoreAction({ node: this.node, body })
          if (!result.ok && result.kind === 'seed-error') return this._custodyErrorResponse(res, result.error)
          return this._json(res, result.payload, result.status || 200)
        }

        // Publish this relay's index-room pointer. Called by the index sidecar
        // (loopback) once its schema-sheets room is ready, so the relay can
        // advertise it in the capability doc + /catalog.json. Operator-authed.
        const indexRoomRoute = resolveIndexRoomRoute(req.method, path)
        if (indexRoomRoute && indexRoomRoute.kind === 'index-room') {
          if (!this._requireAuth(req, res, indexRoomRoute.authMessage)) return
          const result = await runIndexRoomAction({
            body,
            node: this.node,
            emit: (...args) => this.emit(...args)
          })
          return this._json(res, result.payload, result.status || 200)
        }

        if (seedPublishRoute && seedPublishRoute.kind === 'registry-publish') {
          if (!this._requireAuth(req, res, seedPublishRoute.authMessage)) return
          const result = await runSeedPublishRouteAction({
            route: seedPublishRoute,
            body,
            node: this.node,
            disabled: this._custodyApiDisabled()
          })
          if (!result.ok && result.kind === 'seed-error') return this._custodyErrorResponse(res, result.error)
          return this._json(res, result.payload, result.status || 200)
        }

        const operatorCustodyRoute = resolveOperatorCustodyRoute(req.method, path)
        if (operatorCustodyRoute) {
          if (!this._requireAuth(req, res, operatorCustodyRoute.authMessage)) return
          const result = await runOperatorCustodyRouteAction({
            route: operatorCustodyRoute,
            body,
            node: this.node,
            disabled: this._custodyApiDisabled()
          })
          return this._json(res, result.payload, result.status || 200)
        }

        // ─── /api/manage/catalog/* — operator catalog controls ───────────
        // Replaces the older /registry/{auto-accept,approve,reject} endpoints
        // with a clearer surface aligned to the per-relay local-catalog model.

        const catalogRoute = resolveCatalogManagementRoute(req.method, path)
        if (catalogRoute) {
          if (!this._requireAuth(req, res, catalogRoute.authMessage)) return
          const result = await runCatalogManagementRouteAction({
            route: catalogRoute,
            body,
            config: this.node.config,
            node: this.node,
            persistConfig: () => this._persistConfig(),
            emit: (...args) => this.emit(...args)
          })
          if (!result.ok && result.kind === 'config-persist') return this._persistFailureResponse(res, result)
          return this._json(res, result.payload, result.status || 200)
        }

        // ─── /api/manage/federation/* — explicit cross-relay federation ──

        const federationRoute = resolveFederationManagementRoute(req.method, path)
        if (federationRoute) {
          if (!this._requireAuth(req, res, federationRoute.authMessage)) return
          const result = await runFederationManagementRouteAction({
            route: federationRoute,
            body,
            federation: this.node.federation,
            emit: (...args) => this.emit(...args),
            disabled: this._federationApiDisabled()
          })
          return this._json(res, result.payload, result.status || 200)
        }

        // ─── /api/manage/delegation/* — device-attestation revocation ────

        const delegationRoute = resolveDelegationManagementRoute(req.method, path)
        if (delegationRoute && delegationRoute.kind === 'revoke') {
          if (!this._requireAuth(req, res, delegationRoute.authMessage)) return
          const result = runDelegationRevokeAction({ body, node: this.node })
          return this._json(res, result.payload, result.status || 200)
        }

        const unseedRoute = resolveUnseedRoute(req.method, path)
        if (unseedRoute && unseedRoute.kind === 'operator-unseed') {
          if (!this._requireAuth(req, res, unseedRoute.authMessage)) return
          const result = await runOperatorUnseedAction({ body, node: this.node })
          return this._json(res, result.payload, result.status || 200)
        }

        if (unseedRoute && unseedRoute.kind === 'publisher-unseed') {
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
        if (seedPublishRoute && seedPublishRoute.kind === 'publisher-seed') {
          const result = await runSeedPublishRouteAction({
            route: seedPublishRoute,
            body,
            node: this.node,
            disabled: this._custodyApiDisabled()
          })
          if (!result.ok && result.kind === 'seed-error') return this._custodyErrorResponse(res, result.error)
          return this._json(res, result.payload, result.status || 200)
        }

        // ─── Publisher-signed custody pipeline (no operator API key) ─
        // Each entry is itself Ed25519-signed by the publisher (the
        // signature lives on body.signature). The relay's
        // _verifiedCustodyEntry validates the embedded signature before
        // append, so the publisher's signing key IS the authorization.
        // We pass `null` as the keypair so the registry refuses to
        // fall back to relay-side signing — body MUST be pre-signed.
        const publisherCustodyRoute = resolvePublisherCustodyRoute(req.method, path)
        if (publisherCustodyRoute) {
          const result = await runPublisherCustodyRouteAction({
            route: publisherCustodyRoute,
            body,
            node: this.node,
            disabled: this._custodyApiDisabled()
          })
          if (!result.ok && result.kind === 'custody-error') return this._custodyErrorResponse(res, result.error)
          return this._json(res, result.payload, result.status || 200)
        }

        // ─── Live Management API (requires API key or localhost) ─────

        if (isManagementApiRoute(path)) {
          if (!this._requireAuth(req, res, MANAGEMENT_AUTH_ERROR)) return
        }

        const aiModelManagementRoute = resolveAIModelManagementRoute(req.method, path)
        if (aiModelManagementRoute) {
          const service = resolveAIServiceProvider(this.node)
          if (!service.ok) return this._json(res, { error: service.error }, service.status)
          const result = await runAIModelManagementRouteAction({
            route: aiModelManagementRoute,
            provider: service.provider,
            body,
            node: this.node,
            emit: (...args) => this.emit(...args)
          })
          return this._json(res, result.payload, result.status || 200)
        }

        const configUpdateRoute = resolveConfigUpdateRoute(req.method, path)
        if (configUpdateRoute && configUpdateRoute.kind === 'config-update') {
          const result = await runConfigUpdateAction({
            body,
            config: this.node.config,
            persistConfig: () => this._persistConfig(),
            safeConfigPayload: () => this._getSafeConfig()
          })
          if (!result.ok && result.kind === 'config-persist') return this._persistFailureResponse(res, result)
          // Live-apply a storage designation: persisting maxStorageBytes alone
          // does not re-cap the running seeder. The live application blocks
          // new adoption when over cap but deliberately does not enable
          // eviction or delete already-held data.
          if (result.ok && Array.isArray(result.payload?.applied) && result.payload.applied.includes('maxStorageBytes') &&
              typeof this.node.applyStorageDesignation === 'function') {
            try { await this.node.applyStorageDesignation(this.node.config.maxStorageBytes) } catch (_) {}
          }
          return this._json(res, result.payload, result.status || 200)
        }

        const serviceConfigUpdateRoute = resolveServiceConfigUpdateRoute(req.method, path)
        if (serviceConfigUpdateRoute && serviceConfigUpdateRoute.kind === 'service-config-update') {
          const result = await runServiceConfigUpdateAction({
            body,
            config: this.node.config,
            registry: this.node.serviceRegistry,
            persistConfig: () => this._persistConfig(),
            serviceConfigPayload: () => serviceConfigPayload(this.node.config, this.node.serviceRegistry)
          })
          if (!result.ok && result.kind === 'config-persist') return this._persistFailureResponse(res, result)
          return this._json(res, result.payload, result.status || 200)
        }

        const serviceManagementRoute = resolveServiceManagementRoute(req.method, path)
        if (serviceManagementRoute && serviceManagementRoute.kind === 'service-management') {
          const result = await runServiceManagementAction({
            body,
            registry: this.node.serviceRegistry,
            config: this.node.config,
            node: this.node,
            store: this.node.store,
            persistConfig: () => this._persistConfig(),
            serviceConfigPayload: () => serviceConfigPayload(this.node.config, this.node.serviceRegistry)
          })
          if (!result.ok && result.kind === 'config-persist') return this._persistFailureResponse(res, result)
          return this._json(res, result.payload, result.status || 200)
        }

        const modeTransportRoute = resolveModeTransportManagementRoute(req.method, path)
        if (modeTransportRoute) {
          const result = await runModeTransportManagementRouteAction({
            route: modeTransportRoute,
            body,
            node: this.node,
            config: this.node.config,
            persistConfig: () => this._persistConfig(),
            emit: (...args) => this.emit(...args)
          })
          if (!result.ok && result.kind === 'config-persist') return this._persistFailureResponse(res, result)
          return this._json(res, result.payload, result.status || 200)
        }

        const devicePairingRoute = resolveDevicePairingManagementRoute(req.method, path)
        if (devicePairingRoute) {
          const result = await runDevicePairingManagementRouteAction({
            route: devicePairingRoute,
            body,
            node: this.node,
            emit: (...args) => this.emit(...args)
          })
          return this._json(res, result.payload, result.status || 200)
        }

        const lifecycleRoute = resolveLifecycleManagementRoute(req.method, path)
        if (lifecycleRoute) {
          const result = runLifecycleAction({
            action: lifecycleRoute.action,
            node: this.node,
            emit: (...args) => this.emit(...args)
          })
          return this._json(res, result.payload, result.status || 200)
        }
      }

      // GET — Management info endpoints (require auth)
      if (req.method === 'GET') {
        if (isManagementApiRoute(path) && !this._requireAuth(req, res, MANAGEMENT_AUTH_ERROR)) return

        if (notifyRoute && notifyRoute.management) {
          const result = await runNotifyRouteAction({
            route: notifyRoute,
            providerResult: resolveNotifyServiceProvider(this.node),
            query: notifyQueryParams(url)
          })
          return this._json(res, result.payload, result.status || 200, result.headers || null)
        }

        const managementSnapshotRoute = resolveManagementSnapshotRoute(req.method, path)
        if (managementSnapshotRoute) {
          const result = await buildManagementSnapshotRoutePayload({
            route: managementSnapshotRoute,
            node: this.node,
            aiModelProvider: managementSnapshotRoute.kind === 'ai-models' ? resolveAIServiceProvider(this.node) : null,
            emit: (...args) => this.emit(...args)
          })
          return this._json(res, result.payload, result.status || 200)
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

  _relayKernelProfileActive () {
    return this.node && (
      this.node.mode === 'relaykernel' ||
      this.node.mode === 'public-t1-gateway' ||
      (this.node.config && (this.node.config.productProfile === 'relaykernel' ||
        this.node.config.productProfile === 'public-t1-gateway'))
    )
  }

  _custodyApiDisabled () {
    return this._relayKernelProfileActive() ||
      !!(this.node && this.node.config && this.node.config.custody && this.node.config.custody.enabled === false)
  }

  _federationApiDisabled () {
    return this._relayKernelProfileActive()
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
    const result = await buildIndexProxyRouteResponse({
      base: this.node.indexSidecarUrl,
      url
    })
    if (result.event) this.emit(result.event.name, result.event.detail)
    if (result.kind === 'json') return this._json(res, result.payload, result.status || 200, result.headers || null)
    res.writeHead(result.status || 200, result.headers || { 'Content-Type': 'application/json' })
    return res.end(result.kind === 'buffer' ? result.body : result.text)
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

  _getUsageTelemetryPayload () {
    const stats = typeof this.node.getStats === 'function' ? this.node.getStats() : {}
    return usageTelemetryPayload(this.node._bandwidthReceipt, stats)
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
        message: persistErrorMessage(err),
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
            message: persistErrorMessage(err),
            error: err
          })
        }
      }
      this._persistFailureResponse(res, { kind: 'config-persist' })
      return false
    }
  }

  _persistFailureResponse (res, result) {
    const out = result && result.kind === 'wizard-persist'
      ? wizardPersistFailureResult({ error: result.error, emit: (...args) => this.emit(...args) })
      : configPersistFailureResult()
    return this._json(res, out.payload, out.status)
  }

  async stop () {
    if (this._retrievabilityProofProvider) {
      try { await this._retrievabilityProofProvider.stop() } catch (_) {}
    }

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
