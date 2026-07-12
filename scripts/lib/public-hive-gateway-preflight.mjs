import http from 'http'
import https from 'https'
import { createHash } from 'crypto'
import { isIP } from 'net'
import {
  assertHiveAppGatewayIsolation
} from '../../packages/core/core/relay-node/gateway-server.js'
import {
  encodeHiveAppKey,
  normalizeHiveAppHostSuffix,
  resolveHiveAppHost
} from '../../packages/core/gateway/hive-host.js'
import {
  PUBLIC_HIVE_GATEWAY_ADMISSION_CAPABILITY,
  normalizeHiveAppPublicKeys,
  normalizeHiveAppPublicVersions
} from '../../packages/core/gateway/public-app-admission.js'
import {
  PUBLIC_HIVE_GATEWAY_PROBE_CHECKS,
  PUBLIC_HIVE_GATEWAY_PROBE_SCHEMA
} from './public-hive-gateway-evidence.mjs'
import {
  PUBLIC_HIVE_GATEWAY_FINITE_CONFIG_FIELDS,
  PUBLIC_HIVE_GATEWAY_FINITE_POLICY
} from './public-hive-gateway-policy.mjs'

export {
  inspectPublicHiveGatewayQuarantineNginx
} from './public-hive-gateway-quarantine-authority.mjs'

const MAX_PROXY_TEMPLATE_BYTES = 256 * 1024
const MAX_NGINX_INSPECTION_BYTES = 8 * 1024 * 1024
const MAX_PROBE_BODY_BYTES = 64 * 1024 * 1024
const NGINX_UPSTREAM_DIRECTIVES = new Set([
  'proxy_pass',
  'fastcgi_pass',
  'uwsgi_pass',
  'scgi_pass',
  'grpc_pass'
])
const NGINX_DEFAULT_DIRECTIVES = new Set([
  'listen',
  'server_name',
  'ssl_certificate',
  'ssl_certificate_key',
  'ssl_protocols',
  'ssl_session_tickets',
  'gzip',
  'gunzip',
  'access_log',
  'error_log',
  'return'
])
const NGINX_APP_SERVER_DIRECTIVES = new Set([
  'listen',
  'server_name',
  'ssl_certificate',
  'ssl_certificate_key',
  'ssl_protocols',
  'ssl_session_tickets',
  'access_log',
  'error_log',
  'server_tokens',
  'gzip',
  'gunzip',
  'proxy_cache',
  'proxy_hide_header',
  'client_max_body_size',
  'limit_req',
  'limit_conn',
  'limit_req_status',
  'limit_conn_status',
  'add_header'
])
const NGINX_APP_LOCATION_DIRECTIVES = new Set([
  'proxy_pass',
  'proxy_http_version',
  'proxy_set_header',
  'proxy_pass_request_body',
  'proxy_connect_timeout',
  'proxy_send_timeout',
  'proxy_read_timeout',
  'proxy_next_upstream',
  'proxy_buffering',
  'proxy_request_buffering'
])
const NGINX_REVIEWED_MAIN_DIRECTIVES = new Set([
  'daemon',
  'env',
  'error_log',
  'lock_file',
  'master_process',
  'pcre_jit',
  'pid',
  'thread_pool',
  'timer_resolution',
  'user',
  'worker_cpu_affinity',
  'worker_priority',
  'worker_processes',
  'worker_rlimit_core',
  'worker_rlimit_nofile',
  'working_directory'
])
const NGINX_REVIEWED_HTTP_PARENT_DIRECTIVES = new Set([
  'access_log',
  'client_body_timeout',
  'client_header_timeout',
  'default_type',
  'error_log',
  'include',
  'keepalive_requests',
  'keepalive_timeout',
  'large_client_header_buffers',
  'limit_req_zone',
  'limit_conn_zone',
  'lingering_close',
  'lingering_time',
  'lingering_timeout',
  'log_format',
  'open_file_cache',
  'open_file_cache_errors',
  'open_file_cache_min_uses',
  'open_file_cache_valid',
  'read_ahead',
  'reset_timedout_connection',
  'send_timeout',
  'sendfile',
  'server_names_hash_bucket_size',
  'server_names_hash_max_size',
  'ssl_prefer_server_ciphers',
  'ssl_protocols',
  'tcp_nodelay',
  'tcp_nopush',
  'types_hash_bucket_size',
  'types_hash_max_size'
])
const NGINX_REVIEWED_EVENTS_DIRECTIVES = new Set([
  'accept_mutex',
  'accept_mutex_delay',
  'debug_connection',
  'multi_accept',
  'use',
  'worker_connections'
])

export function normalizePublicHiveGatewayConnectAddress (value) {
  if (typeof value !== 'string' || value.length < 2 || value.length > 64 || value !== value.trim() || isIP(value) === 0) return null
  return value.toLowerCase()
}

export function inspectPublicHiveGatewayConfig (config, opts = {}) {
  const mode = opts.mode || 'canary'
  const errors = []
  const warnings = []
  if (mode !== 'canary' && mode !== 'fleet') errors.push('mode must be canary or fleet')
  if (!config || typeof config !== 'object' || Array.isArray(config)) {
    return { ok: false, errors: ['config must be a JSON object'], warnings, normalized: null }
  }

  try {
    assertHiveAppGatewayIsolation({
      hiveAppHostSuffix: config.hiveAppHostSuffix,
      hiveAppPublicKeys: config.hiveAppPublicKeys,
      hiveAppPublicVersions: config.hiveAppPublicVersions,
      gatewayPort: config.gatewayPort,
      gatewayHost: config.gatewayHost,
      gatewayCompatibilityHosts: config.gatewayCompatibilityHosts,
      gatewayTrustedProxyAddresses: config.gatewayTrustedProxyAddresses,
      gatewayTrustProxy: config.gatewayTrustProxy,
      gatewayRequireForwardedSNI: config.gatewayRequireForwardedSNI,
      gatewayMaxResponseBytes: config.gatewayMaxResponseBytes,
      gatewayMaxTransformBytes: config.gatewayMaxTransformBytes,
      gatewayEgressBytesPerWindow: config.gatewayEgressBytesPerWindow,
      gatewayEgressWindowMs: config.gatewayEgressWindowMs,
      gatewayMaxResponseLifetimeMs: config.gatewayMaxResponseLifetimeMs,
      apiPort: config.apiPort,
      apiHost: config.apiHost,
      enableAPI: config.enableAPI,
      enableSeeding: config.enableSeeding,
      enableRelay: config.enableRelay,
      enableServices: config.enableServices,
      plugins: config.plugins,
      signedDirectory: config.signedDirectory,
      federation: config.federation,
      lease: config.lease,
      payment: config.payment,
      subsidy: config.subsidy,
      shardStore: config.shardStore,
      custody: config.custody,
      mode: config.mode,
      productProfile: config.productProfile,
      // Static inspection reports compiled substrate readiness separately
      // below. Only RelayNode construction/startup may open the runtime gate.
      enforceCompiledAdmission: false
    })
  } catch (err) {
    errors.push(err.message)
  }

  const suffix = normalizeHiveAppHostSuffix(config.hiveAppHostSuffix)
  const keys = normalizeHiveAppPublicKeys(config.hiveAppPublicKeys)
  const versions = normalizeHiveAppPublicVersions(config.hiveAppPublicVersions ?? {})
  if (!keys || keys.size === 0) {
    errors.push('hiveAppPublicKeys must approve exactly one manifest-bound Phase-1 public app')
  } else if (keys.size !== 1) {
    // The release manifest currently binds one public app expectation per
    // relay. Do not let a PSL assertion turn unmanifested sibling apps into an
    // implicit admission set: Phase 1 remains exactly one app in both canary
    // and fleet postures until the manifest/evidence schemas bind every app.
    errors.push('Phase 1 must expose exactly one manifest-bound trusted app; multi-app admission is deferred')
  }
  if (!versions) {
    errors.push('hiveAppPublicVersions must map public app keys to non-negative safe integer versions')
  } else {
    const onlyKey = keys?.size === 1 ? [...keys][0] : null
    const hasExactPin = onlyKey !== null && versions.size === 1 && versions.has(onlyKey)
    if (!hasExactPin) {
      const message = 'Phase 1 requires exactly one immutable hiveAppPublicVersions pin matching its one manifest-bound app key'
      if (mode === 'fleet') errors.push(message)
      else warnings.push(message)
    }
  }
  if (!isLoopbackHost(config.apiHost)) errors.push('apiHost must bind loopback for a public gateway deployment')
  if (!isLoopbackHost(config.gatewayHost)) errors.push('gatewayHost must bind loopback behind the TLS edge')
  if (config.gatewayTrustProxy !== true) errors.push('gatewayTrustProxy must be true behind the strict TLS edge')
  if (config.gatewayRequireForwardedSNI !== true) errors.push('gatewayRequireForwardedSNI must be true for SNI/Host binding')
  if (config.custody?.enabled !== false) {
    errors.push('custody.enabled must be false on the dedicated public availability gateway until the frozen substrate role predicate proves safe mixed-role segregation')
  }

  const trusted = config.gatewayTrustedProxyAddresses
  if (!Array.isArray(trusted) || trusted.length === 0 || trusted.some(address => !isLoopbackIp(address))) {
    errors.push('gatewayTrustedProxyAddresses must contain only loopback proxy IPs')
  }
  const compatibility = config.gatewayCompatibilityHosts
  if (!Array.isArray(compatibility) || compatibility.length === 0 || compatibility.some(host => !isLoopbackHost(host))) {
    errors.push('gatewayCompatibilityHosts must contain only loopback health/probe Hosts')
  }
  if (!Number.isSafeInteger(config.gatewayMaxInFlight) || config.gatewayMaxInFlight < 1 || config.gatewayMaxInFlight > 4096) {
    errors.push('gatewayMaxInFlight must be an integer from 1 to 4096')
  }
  if (!Number.isSafeInteger(config.gatewayMaxInFlightPerApp) || config.gatewayMaxInFlightPerApp < 1 ||
      config.gatewayMaxInFlightPerApp > config.gatewayMaxInFlight) {
    errors.push('gatewayMaxInFlightPerApp must be positive and no greater than gatewayMaxInFlight')
  }
  for (const [field, expected] of Object.entries(PUBLIC_HIVE_GATEWAY_FINITE_CONFIG_FIELDS)) {
    if (config[field] !== expected || (opts.explicitConfig && !Object.hasOwn(opts.explicitConfig, field))) {
      errors.push(`${field} must be explicitly pinned to the finite production value ${expected}`)
    }
  }
  if (opts.apiKeyPresent !== true) errors.push('a non-empty HIVERELAY_API_KEY is required even with a loopback management API')

  const readiness = inspectPublicHiveGatewayAdmissionReadiness(PUBLIC_HIVE_GATEWAY_ADMISSION_CAPABILITY, mode)
  errors.push(...readiness.errors)
  warnings.push(...readiness.warnings)
  if (opts.publicSuffixReady !== true) {
    warnings.push('app suffix is not evidenced as a Public Suffix; Phase 1 remains restricted to its one manifest-bound app')
  }
  warnings.push('Phase 1 disables shared proxy caching; versioned immutable URLs and purge semantics are deferred')

  return {
    ok: errors.length === 0,
    errors,
    warnings,
    normalized: suffix && keys && versions
      ? {
          suffix,
          appKeys: [...keys],
          appVersions: Object.fromEntries(versions),
          apiPort: config.apiPort,
          gatewayPort: config.gatewayPort,
          finiteProductionPolicy: { ...PUBLIC_HIVE_GATEWAY_FINITE_POLICY },
          admissionProfile: PUBLIC_HIVE_GATEWAY_ADMISSION_CAPABILITY.profile
        }
      : null
  }
}

export function inspectPublicHiveGatewayAdmissionReadiness (capability, mode = 'canary') {
  const errors = []
  const warnings = []
  const profile = typeof capability?.profile === 'string' && capability.profile.length > 0
    ? capability.profile
    : 'unknown-profile'
  const authority = typeof capability?.authority === 'string' && capability.authority.length > 0
    ? capability.authority
    : 'unknown-authority'
  const valid = Object.isFrozen(capability) &&
    capability?.kind === 'public-hive-gateway-admission-capability' &&
    capability?.version === 1 &&
    typeof capability?.profile === 'string' && /^[a-z0-9]+(?:-[a-z0-9]+)+$/.test(capability.profile) &&
    typeof capability?.authority === 'string' && /^[a-z0-9]+(?:-[a-z0-9]+)+$/.test(capability.authority) &&
    typeof capability?.fleetReady === 'boolean'

  // Profile names are descriptive release metadata, never readiness signals.
  // Only the compiled admission capability can open the production posture.
  if (!valid || capability.fleetReady !== true) {
    const message = `blind-substrate admission is not fleet-ready (${profile}; authority=${authority})`
    if (mode === 'fleet') errors.push(message)
    else warnings.push(message)
  }
  return { ok: errors.length === 0, errors, warnings }
}

export function renderPublicHiveGatewayNginx (template, opts) {
  if (typeof template !== 'string' || Buffer.byteLength(template) > MAX_PROXY_TEMPLATE_BYTES) {
    throw new Error('nginx template must be a bounded string')
  }
  const suffix = normalizeHiveAppHostSuffix(opts?.suffix)
  if (!suffix) throw new Error('invalid Hive app host suffix')
  if (!Number.isSafeInteger(opts.gatewayPort) || opts.gatewayPort < 1 || opts.gatewayPort > 65535) {
    throw new Error('invalid gateway port')
  }
  const certificate = safeAbsolutePath(opts.certificate, 'certificate')
  const certificateKey = safeAbsolutePath(opts.certificateKey, 'certificate key')
  const suffixRegex = suffix.replace(/\./g, '\\.')
  const rendered = template
    .replaceAll('__HIVE_APP_HOST_SUFFIX__', suffix)
    .replaceAll('__HIVE_APP_HOST_SUFFIX_REGEX__', suffixRegex)
    .replaceAll('__HIVE_GATEWAY_PORT__', String(opts.gatewayPort))
    .replaceAll('__HIVE_TLS_CERTIFICATE__', certificate)
    .replaceAll('__HIVE_TLS_CERTIFICATE_KEY__', certificateKey)
  if (/__[A-Z0-9_]+__/.test(rendered)) throw new Error('nginx template contains unresolved placeholders')
  return rendered
}

export function inspectPublicHiveGatewayNginx (text, opts) {
  const errors = []
  if (typeof text !== 'string' || Buffer.byteLength(text) > MAX_NGINX_INSPECTION_BYTES) {
    return { ok: false, errors: ['nginx config must be a bounded string'] }
  }
  // Evidence must describe directives nginx can parse, not reassuring words in
  // comments. Preserve quoted # characters (for example in a safe path/value)
  // while removing comment text before every structural check below.
  const effective = stripNginxComments(text)
  const suffix = normalizeHiveAppHostSuffix(opts?.suffix)
  if (!suffix) errors.push('invalid expected suffix')
  if (!Number.isSafeInteger(opts?.gatewayPort)) errors.push('invalid expected gateway port')
  const parsed = parseNginxStatements(effective)
  if (!parsed.ok) errors.push('nginx configuration structure could not be inspected safely')
  if (findNginxBlocks(parsed.nodes, 'stream').length > 0) {
    errors.push('Phase 1 public gateway forbids nginx stream context and stream includes')
  }

  const serverRecords = findNginxBlocksWithContext(parsed.nodes, 'server')
  const serverBlocks = serverRecords.map(record => record.block)
  const httpServerBlocks = serverRecords.filter(isHttpServerContext).map(record => record.block)
  const foreignTlsServers = serverRecords.filter(record =>
    !isHttpServerContext(record) && directDirectives(record.block, 'listen').some(isPort443Listen))
  if (foreignTlsServers.length > 0) {
    errors.push('TLS port 443 server blocks must be in HTTP context; stream or nested listeners are forbidden')
  }
  if (serverBlocks.some(block => directDirectives(block, 'listen').some(directive => directive.args.includes('quic')))) {
    errors.push('Phase 1 public gateway must not configure an HTTP/3 QUIC listener')
  }
  if (allDirectives({ children: parsed.nodes }, 'add_header').some(directive =>
    String(directive.args[0] || '').toLowerCase() === 'alt-svc' &&
    directive.args.slice(1).join(' ').toLowerCase().includes('h3'))) {
    errors.push('Phase 1 public gateway must not advertise HTTP/3 through Alt-Svc')
  }
  inspectReviewedNginxDirectivePosture(parsed.nodes, errors)
  const defaultBlocks = httpServerBlocks.filter(block => directDirectives(block, 'listen').some(isDefaultTls443Listen))
  const safeDefaultBlocks = defaultBlocks.filter(isSafeDefaultServer)
  if (defaultBlocks.length !== 1 || safeDefaultBlocks.length !== 1) {
    errors.push('public TLS listener must have exactly one default 421 reject vhost and no competing default')
  }

  let appBlock = null
  if (suffix) {
    const escaped = suffix.replace(/\./g, '\\.')
    const expectedServerName = `"~^(?<hive_app_key>[ybndrfg8ejkmcpqxot1uwisza345h769]{52})\\.${escaped}$"`
    const appBlocks = httpServerBlocks.filter(block => {
      const names = directDirectives(block, 'server_name')
      return names.length === 1 && sameArgs(names[0].args, [expectedServerName])
    })
    if (appBlocks.length !== 1) {
      errors.push('nginx must contain exactly one active quoted app-key server block scoped to the configured suffix')
    } else {
      appBlock = appBlocks[0]
    }

    for (const block of httpServerBlocks) {
      if (block === appBlock) continue
      if (!directDirectives(block, 'listen').some(isPort443Listen)) continue
      const names = directDirectives(block, 'server_name').flatMap(directive => directive.args)
      if (names.some(name => serverNameCanMatchHiveApp(name, suffix))) {
        errors.push('a sibling TLS vhost can shadow the reviewed app-host server_name')
      }
    }
  }

  for (const block of httpServerBlocks) {
    if (block === appBlock || safeDefaultBlocks.includes(block)) continue
    const listens = directDirectives(block, 'listen')
    if (!listens.some(isPort443Listen)) continue
    if (!hasExactPublicTlsListeners(listens, false)) {
      errors.push('sibling TLS vhosts must use only the shared wildcard 443 ssl listen tuples')
    }
    const names = directDirectives(block, 'server_name').flatMap(directive => directive.args)
    if (names.length === 0 || names.some(name => !isExplicitDisjointServerName(name, suffix))) {
      errors.push('sibling TLS vhosts require explicit server_name values disjoint from the app suffix')
    }
  }

  // Every app-edge property must be a parsed directive in the one selected
  // app server. Directive-shaped words in comments, quoted values, or sibling
  // vhosts are deliberately not evidence.
  const appListens = appBlock ? directDirectives(appBlock, 'listen') : []
  if (!hasExactPublicTlsListeners(appListens, false)) errors.push('app proxy must actively listen on TLS port 443')
  if (!hasSingleDirective(appBlock, 'ssl_certificate') || !hasSingleDirective(appBlock, 'ssl_certificate_key')) {
    errors.push('app proxy must terminate TLS with one explicit certificate and key')
  }
  requireDirective(appBlock, 'ssl_protocols', ['TLSv1.2', 'TLSv1.3'], 'app proxy must permit only TLS 1.2 and TLS 1.3', errors)
  requireDirective(appBlock, 'ssl_session_tickets', ['off'], 'app proxy must disable TLS session tickets', errors)
  requireDirective(appBlock, 'access_log', ['off'], 'app proxy must disable durable request access logging', errors)
  requireDirective(appBlock, 'error_log', ['stderr', 'crit'], 'app proxy must constrain error logging to critical stderr events', errors)
  requireDirective(appBlock, 'server_tokens', ['off'], 'app proxy must suppress nginx version tokens', errors)
  requireDirective(appBlock, 'proxy_set_header', ['Accept-Encoding', '""'], 'proxy must require identity transfer encoding upstream', errors, false)
  requireDirective(appBlock, 'proxy_set_header', ['Host', '$host'], 'proxy must preserve canonical Host', errors, false)
  requireDirective(appBlock, 'proxy_set_header', ['X-Forwarded-For', '$remote_addr'], 'proxy must overwrite X-Forwarded-For', errors, false)
  requireDirective(appBlock, 'proxy_set_header', ['X-Forwarded-Host', '""'], 'proxy must strip X-Forwarded-Host', errors, false)
  requireDirective(appBlock, 'proxy_set_header', ['Forwarded', '""'], 'proxy must strip Forwarded', errors, false)
  requireDirective(appBlock, 'proxy_set_header', ['X-Hive-Forwarded-SNI', '$ssl_server_name'], 'proxy must attest the TLS SNI', errors, false)
  if (!hasExactProxyHeaderPolicy(appBlock)) errors.push('proxy header policy must not contain duplicate or unreviewed overrides')
  const forwardingScope = appBlock || { children: parsed.nodes }
  if (allDirectives(forwardingScope, 'proxy_set_header').some(directive => directive.args.includes('$proxy_add_x_forwarded_for'))) {
    errors.push('proxy must not append attacker-supplied X-Forwarded-For')
  }
  if (!hasSniHostReject(appBlock)) errors.push('proxy must reject SNI/Host mismatch')
  requireDirective(appBlock, 'proxy_cache', ['off'], 'Phase 1 proxy cache must be disabled', errors)
  requireDirective(appBlock, 'gzip', ['off'], 'proxy must not transform exact response bytes with gzip', errors)
  requireDirective(appBlock, 'gunzip', ['off'], 'proxy must not transform upstream response bytes with gunzip', errors)
  requireDirective(appBlock, 'proxy_hide_header', ['Set-Cookie'], 'proxy must suppress gateway Set-Cookie', errors)
  requireDirective(appBlock, 'client_max_body_size', ['1k'], 'app proxy must bound rejected request bodies', errors)
  requireDirective(appBlock, 'limit_req', ['zone=hive_app_rate', 'burst=40', 'nodelay'], 'app proxy must apply the reviewed request-rate zone', errors)
  requireDirective(appBlock, 'limit_conn', ['hive_app_conn', '16'], 'app proxy must apply the reviewed connection-rate zone', errors)
  requireDirective(appBlock, 'limit_req_status', ['429'], 'request-rate throttling must return 429', errors)
  requireDirective(appBlock, 'limit_conn_status', ['429'], 'connection throttling must return 429', errors)
  if (!hasReadOnlyRootLocation(appBlock)) errors.push('app proxy must allow only GET and implicit HEAD')
  requireDirective(appBlock, 'proxy_pass_request_body', ['off'], 'read-only app proxy must discard request bodies', errors)
  requireDirective(appBlock, 'proxy_set_header', ['Content-Length', '""'], 'read-only app proxy must clear request Content-Length', errors, false)
  requireDirective(appBlock, 'proxy_http_version', ['1.1'], 'app proxy must use the reviewed upstream HTTP version', errors)
  requireDirective(appBlock, 'proxy_next_upstream', ['off'], 'app proxy must disable upstream failover', errors)
  requireDirective(appBlock, 'proxy_buffering', ['off'], 'app proxy must disable response buffering', errors)
  requireDirective(appBlock, 'proxy_request_buffering', ['off'], 'app proxy must disable request buffering', errors)
  requireDirective(appBlock, 'add_header', ['Strict-Transport-Security', '"max-age=31536000"', 'always'], 'app proxy must emit HSTS', errors)
  if (Number.isSafeInteger(opts?.gatewayPort)) {
    requireDirective(appBlock, 'proxy_pass', [`http://127.0.0.1:${opts.gatewayPort}`], 'proxy_pass must target the loopback gateway port', errors)
  }
  const upstreams = appBlock
    ? allDirectives(appBlock).filter(directive => NGINX_UPSTREAM_DIRECTIVES.has(directive.name))
    : []
  if (upstreams.length !== 1 || upstreams[0].name !== 'proxy_pass') {
    errors.push('app proxy must contain exactly one upstream')
  }
  if (!hasReviewedAppShape(appBlock)) errors.push('app proxy must not contain directives or nested routes outside the reviewed Phase 1 policy')
  requireGlobalZone(parsed.nodes, 'limit_req_zone', '$binary_remote_addr', 'zone=hive_app_rate:', 'request-rate zone must key the direct client address', errors)
  requireGlobalZone(parsed.nodes, 'limit_conn_zone', '$binary_remote_addr', 'zone=hive_app_conn:', 'connection zone must key the direct client address', errors)
  return { ok: errors.length === 0, errors }
}

export function inspectActivePublicHiveGatewayNginx (text, opts) {
  const result = inspectPublicHiveGatewayNginx(text, opts)
  const errors = [...result.errors]
  const installed = opts?.installedConfig
  const installedPath = opts?.installedPath
  if (typeof installed !== 'string' || Buffer.byteLength(installed) > MAX_PROXY_TEMPLATE_BYTES ||
      typeof installedPath !== 'string' || !installedPath.startsWith('/') || /[\r\n\0]/.test(installedPath)) {
    errors.push('active nginx attestation requires a bounded installed config and absolute path')
    return { ok: false, errors }
  }
  if (/^# configuration file [^\r\n]+:\r?$/m.test(installed)) {
    errors.push('installed gateway configuration contains an ambiguous nginx dump marker')
    return { ok: false, errors }
  }

  const marker = `# configuration file ${installedPath}:\n`
  const markerOffsets = findLineOffsets(text, marker)
  if (markerOffsets.length !== 1) {
    errors.push('active nginx -T output must identify the installed gateway configuration exactly once')
    return { ok: false, errors }
  }
  const contentStart = markerOffsets[0] + marker.length
  if (!text.startsWith(installed, contentStart)) {
    errors.push('active nginx -T output does not contain the exact installed gateway configuration at its parser marker')
    return { ok: false, errors }
  }
  const remainder = text.slice(contentStart + installed.length)
  const nextMarker = '# configuration file '
  // nginx inserts one dump-separator newline after each file, including the
  // final file. It is framing, not an installed config byte.
  const exactBoundary = remainder.length === 0 || remainder === '\n' ||
    remainder.startsWith(`\n${nextMarker}`) ||
    (installed.endsWith('\n') && remainder.startsWith(nextMarker))
  if (!exactBoundary) {
    errors.push('active nginx -T output extends the installed gateway configuration before the next parser marker')
  }
  return { ok: errors.length === 0, errors }
}

export function stripNginxComments (text) {
  let output = ''
  let quote = null
  let escaped = false
  for (let i = 0; i < text.length; i++) {
    const character = text[i]
    if (escaped) {
      output += character
      escaped = false
      continue
    }
    if (character === '\\') {
      output += character
      escaped = true
      continue
    }
    if (quote) {
      output += character
      if (character === quote) quote = null
      continue
    }
    if (character === '"' || character === "'") {
      quote = character
      output += character
      continue
    }
    if (character === '#') {
      while (i + 1 < text.length && text[i + 1] !== '\n') i++
      continue
    }
    output += character
  }
  return output
}

function parseNginxStatements (text) {
  const nodes = []
  const stack = [nodes]
  let tokens = []
  let token = ''
  let quote = null
  let ok = true

  const pushToken = () => {
    if (token.length > 0) tokens.push(token)
    token = ''
  }
  for (let i = 0; i < text.length; i++) {
    const character = text[i]
    if (quote) {
      token += character
      if (character === '\\' && i + 1 < text.length) token += text[++i]
      else if (character === quote) quote = null
      continue
    }
    if (character === '"' || character === "'") {
      quote = character
      token += character
      continue
    }
    if (character === '\\') {
      token += character
      if (i + 1 < text.length) token += text[++i]
      else ok = false
      continue
    }
    if (/\s/.test(character)) {
      pushToken()
      continue
    }
    if (character !== ';' && character !== '{' && character !== '}') {
      token += character
      continue
    }

    pushToken()
    if (character === ';') {
      if (tokens.length === 0) ok = false
      else stack[stack.length - 1].push({ kind: 'directive', name: tokens[0], args: tokens.slice(1) })
      tokens = []
      continue
    }
    if (character === '{') {
      if (tokens.length === 0) {
        ok = false
      } else {
        const block = { kind: 'block', name: tokens[0], args: tokens.slice(1), children: [] }
        stack[stack.length - 1].push(block)
        stack.push(block.children)
      }
      tokens = []
      continue
    }
    if (tokens.length > 0 || stack.length === 1) ok = false
    else stack.pop()
    tokens = []
  }
  pushToken()
  if (quote || tokens.length > 0 || stack.length !== 1) ok = false
  return { ok, nodes }
}

function findNginxBlocks (nodes, name) {
  const matches = []
  for (const node of nodes) {
    if (node.kind !== 'block') continue
    if (node.name === name) matches.push(node)
    matches.push(...findNginxBlocks(node.children, name))
  }
  return matches
}

function findNginxBlocksWithContext (nodes, name, ancestors = []) {
  const matches = []
  for (const node of nodes) {
    if (node.kind !== 'block') continue
    if (node.name === name) matches.push({ block: node, ancestors })
    matches.push(...findNginxBlocksWithContext(node.children, name, [...ancestors, node]))
  }
  return matches
}

function isHttpServerContext (record) {
  // Included conf.d files are dumped by nginx -T without their lexical `http`
  // wrapper, so top-level server blocks are treated as HTTP include content.
  // An explicit parent must, however, be the HTTP context. This keeps a
  // `stream { server { listen 443; } }` block from satisfying or shadowing the
  // reviewed HTTPS topology.
  if (record.ancestors.length === 0) return true
  return record.ancestors.at(-1).name === 'http'
}

function directDirectives (block, name = null) {
  if (!block) return []
  return block.children.filter(node => node.kind === 'directive' && (name === null || node.name === name))
}

function allDirectives (block, name = null) {
  if (!block) return []
  const matches = []
  for (const node of block.children) {
    if (node.kind === 'directive' && (name === null || node.name === name)) matches.push(node)
    if (node.kind === 'block') matches.push(...allDirectives(node, name))
  }
  return matches
}

function inspectReviewedNginxDirectivePosture (nodes, errors) {
  const rejected = []
  const isReviewedTypesBlock = node => node.kind === 'block' &&
    node.name === 'types' &&
    node.children.every(child => child.kind === 'directive')
  const inspectHttpChildren = children => {
    for (const node of children) {
      if (node.kind === 'directive') {
        const reviewedParentCompression =
          (node.name === 'gzip' && (sameArgs(node.args, ['on']) || sameArgs(node.args, ['off']))) ||
          (node.name === 'gunzip' && sameArgs(node.args, ['off']))
        if (!NGINX_REVIEWED_HTTP_PARENT_DIRECTIVES.has(node.name) && !reviewedParentCompression) {
          rejected.push(node.name)
        }
        continue
      }
      if (node.kind === 'block' && node.name !== 'server' && !isReviewedTypesBlock(node)) {
        rejected.push(`${node.name} {}`)
      }
    }
  }

  for (const node of nodes) {
    if (node.kind === 'directive') {
      const reviewedTopLevel = NGINX_REVIEWED_MAIN_DIRECTIVES.has(node.name) ||
        NGINX_REVIEWED_HTTP_PARENT_DIRECTIVES.has(node.name) ||
        (node.name === 'gzip' && (sameArgs(node.args, ['on']) || sameArgs(node.args, ['off']))) ||
        (node.name === 'gunzip' && sameArgs(node.args, ['off']))
      if (!reviewedTopLevel) rejected.push(node.name)
      continue
    }
    if (node.name === 'events') {
      for (const child of node.children) {
        if (child.kind !== 'directive' || !NGINX_REVIEWED_EVENTS_DIRECTIVES.has(child.name)) {
          rejected.push(child.kind === 'block' ? `${child.name} {}` : child.name)
        }
      }
    } else if (node.name === 'http') {
      inspectHttpChildren(node.children)
    } else if (node.name !== 'server' && !isReviewedTypesBlock(node)) {
      rejected.push(`${node.name} {}`)
    }
  }

  if (rejected.length > 0) {
    const names = [...new Set(rejected)].sort().slice(0, 8).join(', ')
    errors.push(`Phase 1 public gateway rejects unreviewed inherited HTTP/module directives or blocks: ${names}`)
  }
}

function sameArgs (actual, expected) {
  return actual.length === expected.length && actual.every((value, index) => value === expected[index])
}

function isPort443Listen (directive) {
  const endpoint = directive.args[0] || ''
  return endpoint === '443' || /:443$/.test(endpoint)
}

function isDefaultTls443Listen (directive) {
  // `ssl` is a socket option. A separate server can claim default_server on a
  // socket whose sibling listen enables TLS without repeating the ssl token.
  return isPort443Listen(directive) && directive.args.includes('default_server')
}

function serverNameCanMatchHiveApp (rawName, suffix) {
  let name = String(rawName || '').trim()
  if ((name.startsWith('"') && name.endsWith('"')) || (name.startsWith("'") && name.endsWith("'"))) {
    name = name.slice(1, -1)
  }
  name = name.toLowerCase().replace(/\.$/, '')
  if (!name || name === '_') return false
  // Regex precedence and PCRE semantics are too broad to prove disjoint from
  // the 52-character key space with a string heuristic. Any sibling regex on
  // the shared TLS socket is therefore rejected fail-closed.
  if (name.startsWith('~')) return true
  const suffixName = suffix.toLowerCase()
  if (name.startsWith('*.')) {
    const base = name.slice(2)
    return suffixName === base || suffixName.endsWith(`.${base}`)
  }
  if (name.startsWith('.')) {
    const base = name.slice(1)
    return suffixName === base || suffixName.endsWith(`.${base}`)
  }
  if (name.includes('*')) return true
  if (!name.endsWith(`.${suffixName}`)) return false
  const label = name.slice(0, -(suffixName.length + 1))
  return /^[ybndrfg8ejkmcpqxot1uwisza345h769]{52}$/.test(label)
}

function isExplicitDisjointServerName (rawName, suffix) {
  let name = String(rawName || '').trim()
  if ((name.startsWith('"') && name.endsWith('"')) || (name.startsWith("'") && name.endsWith("'"))) {
    name = name.slice(1, -1)
  }
  name = name.toLowerCase().replace(/\.$/, '')
  if (!name || name === '_' || name.startsWith('~') || name.includes('*')) return false
  if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/.test(name)) return false
  return !serverNameCanMatchHiveApp(name, suffix)
}

function hasExactPublicTlsListeners (listens, defaultServer) {
  const option = defaultServer ? ['ssl', 'default_server'] : ['ssl']
  const expected = [
    ['443', ...option],
    ['[::]:443', ...option]
  ]
  return listens.length === expected.length && expected.every(args =>
    listens.some(directive => sameArgs(directive.args, args)))
}

function isSafeDefaultServer (block) {
  const directives = directDirectives(block)
  const names = directDirectives(block, 'server_name')
  const returns = directDirectives(block, 'return')
  const hasNestedBlock = block.children.some(node => node.kind === 'block')
  const upstreams = allDirectives(block).filter(directive => NGINX_UPSTREAM_DIRECTIVES.has(directive.name))
  return hasExactPublicTlsListeners(directDirectives(block, 'listen'), true) &&
    names.length === 1 && sameArgs(names[0].args, ['_']) &&
    returns.length === 1 && sameArgs(returns[0].args, ['421']) &&
    hasSingleDirective(block, 'ssl_certificate') &&
    hasSingleDirective(block, 'ssl_certificate_key') &&
    hasSingleDirective(block, 'ssl_protocols', ['TLSv1.2', 'TLSv1.3']) &&
    hasSingleDirective(block, 'ssl_session_tickets', ['off']) &&
    hasSingleDirective(block, 'gzip', ['off']) &&
    hasSingleDirective(block, 'gunzip', ['off']) &&
    hasSingleDirective(block, 'access_log', ['off']) &&
    hasSingleDirective(block, 'error_log', ['stderr', 'crit']) &&
    directives.every(directive => NGINX_DEFAULT_DIRECTIVES.has(directive.name)) &&
    !hasNestedBlock && upstreams.length === 0
}

function hasSingleDirective (block, name, args = null) {
  const directives = directDirectives(block, name)
  return directives.length === 1 && directives[0].args.length === (args?.length || 1) &&
    (args === null || sameArgs(directives[0].args, args))
}

function requireDirective (block, name, args, message, errors, exclusive = true) {
  const directives = allDirectives(block, name)
  const matches = directives.filter(directive => sameArgs(directive.args, args))
  if (matches.length !== 1 || (exclusive && directives.length !== 1)) errors.push(message)
}

function hasExactProxyHeaderPolicy (block) {
  const expected = [
    ['Connection', '""'],
    ['Accept-Encoding', '""'],
    ['Host', '$host'],
    ['Forwarded', '""'],
    ['X-Forwarded-Host', '""'],
    ['X-Forwarded-For', '$remote_addr'],
    ['X-Real-IP', '$remote_addr'],
    ['X-Forwarded-Proto', 'https'],
    ['X-Hive-Forwarded-SNI', '$ssl_server_name'],
    ['Content-Length', '""']
  ]
  const headers = allDirectives(block, 'proxy_set_header')
  return headers.length === expected.length && expected.every(args =>
    headers.filter(directive => sameArgs(directive.args, args)).length === 1)
}

function hasSniHostReject (block) {
  if (!block) return false
  const matches = block.children.filter(node => node.kind === 'block' && node.name === 'if' &&
    node.args.join(' ') === '($ssl_server_name != $host)')
  const returns = matches.length === 1 ? directDirectives(matches[0], 'return') : []
  return returns.length === 1 && sameArgs(returns[0].args, ['421'])
}

function hasReadOnlyRootLocation (block) {
  if (!block) return false
  const locations = findNginxBlocks(block.children, 'location')
  if (locations.length !== 1 || !sameArgs(locations[0].args, ['/'])) return false
  const limits = findNginxBlocks(locations[0].children, 'limit_except')
  if (limits.length !== 1 || !sameArgs(limits[0].args, ['GET'])) return false
  const denies = directDirectives(limits[0], 'deny')
  return denies.length === 1 && sameArgs(denies[0].args, ['all'])
}

function hasReviewedAppShape (block) {
  if (!block) return false
  const directBlocks = block.children.filter(node => node.kind === 'block')
  if (!directDirectives(block).every(directive => NGINX_APP_SERVER_DIRECTIVES.has(directive.name))) return false
  if (!directBlocks.every(node => node.name === 'if' || node.name === 'location')) return false

  const conditions = directBlocks.filter(node => node.name === 'if')
  const locations = directBlocks.filter(node => node.name === 'location')
  if (conditions.length !== 1 || locations.length !== 1) return false
  if (!directDirectives(conditions[0]).every(directive => directive.name === 'return') ||
      conditions[0].children.some(node => node.kind === 'block')) return false

  const location = locations[0]
  if (!directDirectives(location).every(directive => NGINX_APP_LOCATION_DIRECTIVES.has(directive.name))) return false
  const limitBlocks = location.children.filter(node => node.kind === 'block')
  if (limitBlocks.length !== 1 || limitBlocks[0].name !== 'limit_except') return false
  return directDirectives(limitBlocks[0]).every(directive => directive.name === 'deny') &&
    !limitBlocks[0].children.some(node => node.kind === 'block')
}

function requireGlobalZone (nodes, name, key, zonePrefix, message, errors) {
  const root = { children: nodes }
  const found = allDirectives(root, name).some(directive =>
    directive.args[0] === key && directive.args.some(value => value.startsWith(zonePrefix)))
  if (!found) errors.push(message)
}

function findLineOffsets (text, line) {
  const offsets = []
  let offset = 0
  while (offset < text.length) {
    const found = text.indexOf(line, offset)
    if (found < 0) break
    if (found === 0 || text[found - 1] === '\n') offsets.push(found)
    offset = found + line.length
  }
  return offsets
}

export async function probePublicHiveGateway (opts) {
  const appKey = String(opts?.appKey || '').toLowerCase()
  if (!/^[0-9a-f]{64}$/.test(appKey)) throw new Error('probe appKey must be 64 hex characters')
  const origin = new URL(opts.origin)
  if (origin.protocol !== 'https:' || origin.username || origin.password || origin.pathname !== '/' || origin.search || origin.hash) {
    throw new Error('probe origin must be a credential-free HTTPS origin')
  }
  const resolved = resolveHiveAppHost(origin.hostname, opts.suffix)
  if (resolved.kind !== 'app' || resolved.appKey !== appKey) throw new Error('probe origin does not encode the expected app key')
  const connectAddress = opts.connectAddress == null
    ? null
    : normalizePublicHiveGatewayConnectAddress(opts.connectAddress)
  if (opts.connectAddress != null && !connectAddress) throw new Error('probe connectAddress must be an explicit IP address')
  const expectedDriveVersion = opts.expectedDriveVersion == null
    ? null
    : opts.expectedDriveVersion
  if (expectedDriveVersion != null && (!Number.isSafeInteger(expectedDriveVersion) || expectedDriveVersion < 0)) {
    throw new Error('probe expectedDriveVersion must be a non-negative safe integer')
  }
  const requestOpts = {
    ca: opts.ca,
    lookup: connectAddress ? createPinnedLookup(connectAddress) : opts.lookup,
    timeoutMs: opts.timeoutMs || 5000,
    maxBytes: opts.maxBytes || MAX_PROBE_BODY_BYTES
  }
  const path = opts.path || '/index.html'

  const browserEncoding = { 'Accept-Encoding': 'gzip, br, zstd' }
  const metadata = await requestUrl(new URL('/.well-known/hiverelay-app.json', origin), 'GET', browserEncoding, requestOpts)
  const metadataBody = parseJson(metadata.raw, 'gateway metadata')
  assertResponse(metadata.statusCode === 200, 'gateway metadata must return 200')
  assertResponse(metadataBody.appKey === appKey, 'gateway metadata app key mismatch')
  assertResponse(metadataBody.gatewayHost === origin.hostname, 'gateway metadata Host mismatch')
  assertAppHeaders(metadata.headers, appKey, 'generated')

  const exact = await requestUrl(new URL(path, origin), 'GET', browserEncoding, requestOpts)
  assertResponse(exact.statusCode === 200, 'exact app probe must return 200')
  assertAppHeaders(exact.headers, appKey, 'exact', path)
  assertResponse(exact.raw.byteLength > 0, 'exact app probe must return a non-empty fixture')
  assertResponse(exact.tlsProtocol === 'TLSv1.2' || exact.tlsProtocol === 'TLSv1.3', 'gateway must negotiate TLS 1.2 or newer')
  assertResponse(/^(?:[0-9a-f]{2}:){31}[0-9a-f]{2}$/i.test(exact.peerFingerprint256 || ''), 'gateway peer certificate fingerprint unavailable')
  const driveVersion = exact.headers['x-hive-drive-version'] || null
  if (expectedDriveVersion != null) {
    assertResponse(driveVersion === String(expectedDriveVersion), 'exact app response drive version does not match the configured immutable pin')
  }
  const sha256 = createHash('sha256').update(exact.raw).digest('hex')
  if (opts.expectedSha256 && sha256 !== String(opts.expectedSha256).toLowerCase()) {
    throw new Error('exact app response SHA-256 mismatch')
  }

  const range = await requestUrl(new URL(path, origin), 'GET', {
    ...browserEncoding,
    Range: 'bytes=0-0'
  }, requestOpts)
  assertResponse(range.statusCode === 206 && range.raw.byteLength === 1, 'single-byte Range probe failed')
  assertResponse(range.raw[0] === exact.raw[0], 'Range probe returned different source bytes')
  assertResponse(range.headers['content-range'] === `bytes 0-0/${exact.raw.byteLength}`, 'Range Content-Range mismatch')
  assertAppHeaders(range.headers, appKey, 'exact', path)
  assertResponse(range.headers['x-hive-drive-version'] === driveVersion, 'Range probe drive version changed')

  const head = await requestUrl(new URL(path, origin), 'HEAD', browserEncoding, requestOpts)
  assertResponse(head.statusCode === 200 && head.raw.byteLength === 0, 'HEAD probe failed')
  assertResponse(head.headers['content-length'] === String(exact.raw.byteLength), 'HEAD content length mismatch')
  assertAppHeaders(head.headers, appKey, 'exact', path)
  assertResponse(head.headers['x-hive-drive-version'] === driveVersion, 'HEAD probe drive version changed')

  const management = await requestUrl(new URL('/api/manage/config', origin), 'GET', browserEncoding, requestOpts)
  assertResponse(management.statusCode === 403 || management.statusCode === 404, 'app Host reached a management-looking route')
  assertResponse(!management.raw.toString('utf8').includes('apiKey'), 'management response leaked through app Host')
  assertResponse(management.headers['alt-svc'] === undefined, 'app edge must not advertise an unprobed HTTP/3 route')
  assertResponse(management.headers['content-encoding'] === undefined, 'non-probed app route must not be content encoded')

  const forwarded = await requestUrl(new URL(path, origin), 'GET', {
    ...browserEncoding,
    'X-Forwarded-Host': `${'y'.repeat(52)}.${resolved.host.slice(resolved.label.length + 1)}`,
    'X-Forwarded-For': '198.51.100.99'
  }, requestOpts)
  assertResponse(forwarded.statusCode === 200, 'forwarded headers changed app availability')
  assertResponse(forwarded.raw.equals(exact.raw), 'forwarded headers changed exact app bytes')
  assertAppHeaders(forwarded.headers, appKey, 'exact', path)
  assertResponse(forwarded.headers['x-hive-drive-version'] === driveVersion,
    'forwarded headers changed the immutable drive version')

  const unavailableAppKey = appKey === '0'.repeat(64) ? 'f'.repeat(64) : '0'.repeat(64)
  const unavailableOrigin = new URL(origin)
  unavailableOrigin.hostname = `${encodeHiveAppKey(Buffer.from(unavailableAppKey, 'hex'))}.${resolved.host.slice(resolved.label.length + 1)}`
  const unavailable = await requestUrl(new URL('/', unavailableOrigin), 'GET', browserEncoding, requestOpts)
  const unavailableBody = parseJson(unavailable.raw, 'unavailable app response')
  assertResponse(unavailable.statusCode === 403, 'unapproved canonical app Host must fail closed')
  assertResponse(unavailableBody.error === 'App unavailable through public Hive gateway', 'unavailable app response is not generic')
  assertAppOriginHeaders(unavailable.headers, unavailableAppKey)

  // Keep the destination URL/lookup pinned to the approved origin while
  // varying only TLS SNI and HTTP Host. The unrelated-SNI request disables
  // certificate verification solely because a correct default vhost cannot
  // present a certificate for an intentionally unrelated name; no positive
  // content or certificate evidence is taken from that request.
  const unrelatedHost = 'public-hive-default-reject.invalid'
  const defaultSni = await requestUrl(new URL('/', origin), 'GET', {
    Host: unrelatedHost
  }, {
    ...requestOpts,
    servername: unrelatedHost,
    rejectUnauthorized: false
  })
  assertResponse(defaultSni.statusCode === 421, 'public TLS default vhost must reject unrelated SNI with 421')

  const sniHostMismatch = await requestUrl(new URL('/', origin), 'GET', {
    Host: unavailableOrigin.host
  }, {
    ...requestOpts,
    servername: origin.hostname
  })
  assertResponse(sniHostMismatch.statusCode === 421, 'public TLS edge must reject SNI/Host mismatch with 421')

  return {
    schema: PUBLIC_HIVE_GATEWAY_PROBE_SCHEMA,
    observedAt: new Date().toISOString(),
    origin: origin.origin,
    connectAddress,
    appKey,
    path,
    sha256,
    bytes: exact.raw.byteLength,
    driveVersion,
    tlsProtocol: exact.tlsProtocol,
    peerFingerprint256: exact.peerFingerprint256,
    peerValidTo: exact.peerValidTo,
    metadataSigned: metadataBody.signed === true,
    checks: Object.fromEntries(PUBLIC_HIVE_GATEWAY_PROBE_CHECKS.map(name => [name, true]))
  }
}

function requestUrl (url, method, headers, opts) {
  return new Promise((resolve, reject) => {
    const client = url.protocol === 'https:' ? https : http
    const req = client.request(url, {
      method,
      headers,
      ca: opts.ca,
      lookup: opts.lookup,
      servername: opts.servername,
      rejectUnauthorized: opts.rejectUnauthorized,
      timeout: opts.timeoutMs,
      agent: false
    }, res => {
      const encrypted = res.socket.encrypted === true
      const certificate = encrypted ? res.socket.getPeerCertificate() : null
      const tlsProtocol = encrypted ? res.socket.getProtocol() : null
      const chunks = []
      let bytes = 0
      res.on('data', chunk => {
        bytes += chunk.byteLength
        if (bytes > opts.maxBytes) {
          req.destroy(new Error('gateway probe response exceeded byte limit'))
          return
        }
        chunks.push(chunk)
      })
      res.on('end', () => resolve({
        statusCode: res.statusCode,
        headers: res.headers,
        raw: Buffer.concat(chunks),
        tlsProtocol,
        peerFingerprint256: certificate?.fingerprint256 || null,
        peerValidTo: certificate?.valid_to || null
      }))
    })
    req.on('timeout', () => req.destroy(new Error('gateway probe timed out')))
    req.on('error', reject)
    req.end()
  })
}

function createPinnedLookup (address) {
  const family = isIP(address)
  return (_hostname, options, callback) => {
    if (options?.all === true) callback(null, [{ address, family }])
    else callback(null, address, family)
  }
}

function assertAppHeaders (headers, appKey, mode, filePath = null) {
  assertAppOriginHeaders(headers, appKey)
  assertResponse(headers['x-hive-byte-mode'] === mode, `X-Hive-Byte-Mode must be ${mode}`)
  if (mode === 'exact') assertCanonicalIdentity(headers.link, appKey, filePath)
}

function assertCanonicalIdentity (header, appKey, filePath) {
  const canonical = new URL(`hive://${appKey}/`)
  canonical.pathname = new URL(filePath, 'https://gateway.invalid').pathname
  const relations = parseLinkRelations(header)
  assertResponse(relations.some(link => link.target === canonical.href && link.relations.includes('canonical')),
    'exact app response must advertise its canonical hive:// identity')
  assertResponse(relations.some(link => link.target === '/.well-known/hiverelay-app.json' && link.relations.includes('describedby')),
    'exact app response must advertise the gateway metadata relation')
}

function parseLinkRelations (header) {
  const value = Array.isArray(header) ? header.join(',') : String(header || '')
  if (value.length > 8192 || /[\r\n]/.test(value)) return []
  return value.split(',').map(part => {
    const match = part.trim().match(/^<([^<>]+)>\s*;\s*rel=(?:"([^"]+)"|([^\s;,]+))$/i)
    if (!match) return null
    return {
      target: match[1],
      relations: String(match[2] || match[3]).toLowerCase().split(/\s+/)
    }
  }).filter(Boolean)
}

function assertAppOriginHeaders (headers, appKey) {
  assertResponse(headers['x-hive-app-key'] === appKey, 'X-Hive-App-Key mismatch')
  assertResponse(String(headers.vary || '').split(',').map(v => v.trim().toLowerCase()).includes('host'), 'Vary must include Host')
  assertResponse(headers['cache-control'] === 'no-store, max-age=0', 'Phase 1 app response must be no-store')
  assertResponse(headers['set-cookie'] === undefined, 'gateway response must not set cookies')
  assertResponse(headers['alt-svc'] === undefined, 'Phase 1 app response must not advertise HTTP/3')
  assertResponse(headers['content-encoding'] === undefined, 'Phase 1 app response must not be content encoded')
}

function assertResponse (condition, message) {
  if (!condition) throw new Error(message)
}

function parseJson (raw, label) {
  try { return JSON.parse(raw.toString('utf8')) } catch { throw new Error(`${label} is not valid JSON`) }
}

function isLoopbackHost (value) {
  if (typeof value !== 'string') return false
  const host = value.trim().toLowerCase().replace(/^\[|\]$/g, '')
  if (host === 'localhost' || host === '::1') return true
  return isIP(host) === 4 && host.startsWith('127.')
}

function isLoopbackIp (value) {
  if (typeof value !== 'string') return false
  let address = value.trim().toLowerCase()
  if (address.startsWith('::ffff:')) address = address.slice(7)
  return address === '::1' || (isIP(address) === 4 && address.startsWith('127.'))
}

function safeAbsolutePath (value, label) {
  if (typeof value !== 'string' || value.length > 4096 || !/^\/[A-Za-z0-9._/-]+$/.test(value)) {
    throw new Error(`${label} must be a safe absolute path`)
  }
  return value
}
