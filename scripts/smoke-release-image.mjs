#!/usr/bin/env node
import { spawn } from 'node:child_process'
import { createServer } from 'node:net'
import fs from 'node:fs'
import path from 'node:path'
import { WebSocket } from 'ws'

const args = process.argv.slice(2)
const MIN_SMOKE_TIMEOUT_MS = 1000
const MAX_SMOKE_TIMEOUT_MS = 30 * 60 * 1000
const MAX_EVIDENCE_JSON_BYTES = 2 * 1024 * 1024
const EXPECTED_POKER_AI_PLUGINS = Object.freeze(['poker', 'vrf', 'arbitration', 'zk', 'ai'])
const REQUIRED_IMAGE_PLATFORMS = Object.freeze(['linux/amd64', 'linux/arm64'])
const DIGEST_PINNED_IMAGE_REF_PATTERN = /^(ghcr\.io\/[a-z0-9_.-]+\/[a-z0-9._/-]+):(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)@(sha256:[a-f0-9]{64})$/

const FORBIDDEN_PUBLIC_VALUE_PATTERNS = [
  [/-----BEGIN [A-Z ]*(?:PRIVATE|SECRET) KEY-----/, 'private key block'],
  [/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b/, 'GitHub token'],
  [/\bgithub_pat_[A-Za-z0-9_]{20,}\b/, 'GitHub token'],
  [/\bAuthorization\s*:\s*/i, 'authorization header'],
  [/\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b/i, 'bearer token'],
  [/\bAPP_SEED=[^\s'"]+/i, 'APP_SEED'],
  [/\bHIVERELAY_API_KEY=[^\s'"]+/i, 'API key'],
  [/\bsk-[A-Za-z0-9_-]{20,}\b/, 'API key']
]

const FORBIDDEN_PUBLIC_SMOKE_KEYS = new Set([
  'authorization',
  'bearer',
  'containerid',
  'containername',
  'healthbody',
  'hostport',
  'rawhealth',
  'secret',
  'stderr',
  'stdout',
  'token'
])

if (args.includes('--help') || args.includes('-h')) {
  console.log(`Usage: node scripts/smoke-release-image.mjs <image-ref> [--timeout-ms <ms>] [--evidence <path>]

Boots the release container, waits for /health, verifies the appliance
dashboard/setup pages, and checks authenticated wallet + service-management
writes through the dashboard token.
`)
  process.exit(0)
}

const imageRef = args[0]
const timeoutMs = parseTimeoutMs(readFlag('--timeout-ms') || process.env.HIVERELAY_SMOKE_TIMEOUT_MS || '120000')
const evidenceFile = readFlag('--evidence') || process.env.HIVERELAY_RELEASE_IMAGE_SMOKE_EVIDENCE || ''
const imageManifestEvidenceFile = process.env.HIVERELAY_RELEASE_IMAGE_MANIFEST_EVIDENCE || 'release-image-manifest-evidence.json'

if (!imageRef || imageRef.startsWith('--')) fatal('image-ref is required')
if (!/^[A-Za-z0-9._/:@+-]+$/.test(imageRef)) fatal('image-ref contains unsupported characters')
if (evidenceFile && !isDigestPinnedImageRef(imageRef)) {
  fatal('release image smoke evidence requires a GHCR semver tag plus sha256 digest image ref')
}
if (evidenceFile) requireImageManifestEvidence(imageManifestEvidenceFile, imageRef)

const containerName = `hiverelay-smoke-${process.pid}-${Date.now()}`
const hostPort = await reservePort()
const checks = []
let cleaned = false
let failed = false

process.on('SIGINT', () => cleanup().finally(() => process.exit(130)))
process.on('SIGTERM', () => cleanup().finally(() => process.exit(143)))

try {
  await run('docker', [
    'run',
    '-d',
    '--rm',
    '--name', containerName,
    '-e', 'APP_SEED=release-smoke-seed-00000000000000000000000000000000',
    '-e', 'HIVERELAY_API_KEY=release-smoke-api-key-00000000000000000000000000000000',
    '-e', 'HIVERELAY_API_HOST=0.0.0.0',
    '-e', 'HIVERELAY_API_PORT=9100',
    '-e', 'HIVERELAY_UI_SIMPLE=true',
    '-e', 'HIVERELAY_UI_EXPOSE_TOKEN=true',
    '-e', 'HIVERELAY_ACCEPT_MODE=review',
    '-e', 'HIVERELAY_LOG_LEVEL=warn',
    '-p', `127.0.0.1:${hostPort}:9100`,
    imageRef
  ])

  const baseUrl = `http://127.0.0.1:${hostPort}`
  const health = await waitForHealth(baseUrl, timeoutMs)
  if (health.running !== true) throw new Error('/health did not report running:true')
  recordCheck('health', { version: health.version || '' })

  const dashboard = await fetchText(`${baseUrl}/dashboard`)
  assertIncludes(dashboard, 'id="svcBody"', 'dashboard service manager')
  assertIncludes(dashboard, 'Payout wallet', 'dashboard wallet controls')
  assertIncludes(dashboard, 'hiverelay-ui-token', 'dashboard auth token meta')
  const dashboardUi = assertDashboardUiHardening(dashboard)
  recordCheck('dashboard', { serviceManager: true, walletControls: true, tokenMeta: true, ...dashboardUi })

  const setup = await fetchText(`${baseUrl}/wizard?edit=1`)
  assertIncludes(setup, 'Setup', 'setup wizard')
  const setupUi = assertSetupWizardUiHardening(setup)
  recordCheck('setupWizard', { editMode: true, ...setupUi })

  const token = dashboard.match(/<meta name="hiverelay-ui-token" content="([^"]+)"/)?.[1]
  if (!token) throw new Error('dashboard did not expose a management token')
  recordCheck('dashboardToken', { exposedViaMeta: true })

  const dashboardWebSocket = await assertDashboardWebSocket(baseUrl, token)
  recordCheck('dashboardWebSocket', dashboardWebSocket)

  const usageTelemetry = await assertUsageTelemetry(baseUrl, token)
  recordCheck('usageTelemetry', usageTelemetry)
  const acceptMode = await assertAcceptModeDefault(baseUrl)
  recordCheck('acceptModeDefault', { mode: acceptMode })

  const services = await fetchJson(`${baseUrl}/api/manage/services/available`, {
    Authorization: `Bearer ${token}`
  })
  if (!Array.isArray(services.available) || !services.available.includes('poker') || !services.available.includes('vrf')) {
    throw new Error('service catalog is missing built-in services')
  }
  if (!services.bundles || !Array.isArray(services.bundles.poker)) {
    throw new Error('service catalog is missing the poker provider bundle')
  }
  assertPluginList(services.bundles.poker, EXPECTED_POKER_AI_PLUGINS.slice(0, 4), 'service catalog poker bundle is stale')
  recordCheck('serviceCatalog', { builtIns: ['poker', 'vrf'], bundles: ['poker'] })

  await setWallet(baseUrl, token, 'release-smoke@example.com')
  recordCheck('walletWrite', { destinationSaved: true })
  const plugins = await setServices(baseUrl, token)
  recordCheck('servicesSave', { plugins, restartRequired: true })

  writeSmokeEvidence()
  console.log(`release image smoke passed: ${imageRef}`)
} catch (err) {
  failed = true
  await printLogs()
  console.error(redactSensitiveOutput(err.message || String(err)))
} finally {
  await cleanup()
  if (failed) process.exitCode = 1
}

function readFlag (name) {
  const i = args.indexOf(name)
  if (i === -1) return null
  return args[i + 1] || null
}

function parseTimeoutMs (value) {
  const text = String(value || '').trim()
  if (!/^\d+$/.test(text)) {
    fatal(`--timeout-ms must be an integer between ${MIN_SMOKE_TIMEOUT_MS} and ${MAX_SMOKE_TIMEOUT_MS}`)
  }
  const parsed = Number(text)
  if (!Number.isSafeInteger(parsed) || parsed < MIN_SMOKE_TIMEOUT_MS || parsed > MAX_SMOKE_TIMEOUT_MS) {
    fatal(`--timeout-ms must be an integer between ${MIN_SMOKE_TIMEOUT_MS} and ${MAX_SMOKE_TIMEOUT_MS}`)
  }
  return parsed
}

function isDigestPinnedImageRef (value) {
  return Boolean(parseDigestPinnedImageRef(value))
}

function parseDigestPinnedImageRef (value) {
  const match = DIGEST_PINNED_IMAGE_REF_PATTERN.exec(value)
  if (!match) return null
  return {
    imageName: match[1],
    imageTag: match[2],
    imageDigest: match[3]
  }
}

function assertIncludes (text, needle, label) {
  if (!text.includes(needle)) throw new Error(`${label} missing ${needle}`)
}

function assertDashboardUiHardening (html) {
  assertIncludes(html, 'var API_ERROR_MAX = 180;', 'dashboard bounded API error max')
  assertIncludes(html, ".replace(/[\\x00-\\x1f\\x7f]+/g, ' ')", 'dashboard API error control-char normalization')
  assertIncludes(html, "msg = msg.slice(0, API_ERROR_MAX - 3) + '...';", 'dashboard API error length cap')
  assertIncludes(html, 'var walletBusy = false;', 'dashboard wallet busy-state storage')
  assertIncludes(html, 'function setWalletBusy(busy)', 'dashboard wallet busy-state guard')
  assertIncludes(html, 'if (walletBusy) return;', 'dashboard wallet duplicate-write guard')
  assertIncludes(html, "if ($('walletSave').disabled) return;", 'dashboard wallet enter duplicate guard')
  assertIncludes(html, 'function handleWalletDialogCancel(event)', 'dashboard wallet pending-cancel guard')
  assertIncludes(html, "$('walletDialog').addEventListener('cancel', handleWalletDialogCancel);", 'dashboard wallet dialog cancel guard listener')
  assertIncludes(html, 'function renderPayout(dest)', 'dashboard dynamic payout renderer')
  assertIncludes(html, "chip.type = 'button';", 'dashboard payout copy non-submit button')
  assertIncludes(html, "edit.type = 'button';", 'dashboard payout edit non-submit button')
  assertIncludes(html, 'pay.appendChild(edit);', 'dashboard payout controls use DOM append')
  assertIncludes(html, 'function setSvcConfigBusy(busy)', 'dashboard service save busy-state guard')
  assertIncludes(html, 'var svcRestartPending = false;', 'dashboard service restart pending state')
  assertIncludes(html, 'function svcVisualState(name, configured, active)', 'dashboard service live-vs-saved state labels')
  assertIncludes(html, 'function svcActionMessage(selected)', 'dashboard service inline action guidance')
  assertIncludes(html, 'function renderSvcPlan(selected)', 'dashboard service inline change plan')
  assertIncludes(html, "return 'Unsaved: ' + svcPlanSentence(delta) + '. Save selection before restarting.';", 'dashboard service unsaved change guidance')
  assertIncludes(html, "return 'Saved change pending: ' + svcPlanSentence(delta) + '. Restart Blindspark to apply.';", 'dashboard service saved change guidance')
  assertIncludes(html, "appendSvcPlanLine(lines, 'Start', delta.starts, 'start')", 'dashboard service start-plan chips')
  assertIncludes(html, "appendSvcPlanLine(lines, 'Stop', delta.stops, 'stop')", 'dashboard service stop-plan chips')
  assertIncludes(html, "appendServiceSummary(summary, 'Selected', metricCount(configured.length)", 'dashboard service summary counts')
  assertIncludes(html, "appendEl(content, 'span', 'svc-state ' + visualState.className, visualState.label)", 'dashboard service state pills')
  assertIncludes(html, "meterBox.className = 'svc-meter-box';", 'dashboard service meter layout class')
  assertIncludes(html, 'function setSvcModelBusy(busy)', 'dashboard AI model busy-state guard')
  assertIncludes(html, 'if (svcModelBusy) return;', 'dashboard AI model duplicate-write guard')
  assertIncludes(html, 'function syncSvcModelDraft()', 'dashboard AI model draft preservation guard')
  assertIncludes(html, "modelId.addEventListener('input', syncSvcModelDraft);", 'dashboard AI model draft input listener')
  assertIncludes(html, "msg.setAttribute('aria-live', 'polite');", 'dashboard AI model inline status')
  assertIncludes(html, "fetchWithTimeout('/seed'", 'dashboard seed write app-proxy fetch')
  assertIncludes(html, "fetchWithTimeout('/api/lease/config'", 'dashboard lease write app-proxy fetch')
  assertNotIncludes(html, "fetch('/seed'", 'dashboard raw seed fetch')
  assertNotIncludes(html, "fetch('/api/lease/config'", 'dashboard raw lease fetch')
  assertIncludes(html, 'var leaseRefreshBusy = false;', 'dashboard lease polling busy state')
  assertIncludes(html, 'function fetchLease(force)', 'dashboard force-aware lease polling')
  assertIncludes(html, 'if (!canPoll(force, leaseRefreshBusy)) return Promise.resolve(null);', 'dashboard bounded lease polling guard')
  assertIncludes(html, 'setInterval(function(){ fetchLease(false); }, 30000);', 'dashboard bounded lease polling interval')
  assertNotIncludes(html, 'setInterval(function(){ fetchLease(); }, 30000);', 'dashboard unbounded lease polling interval')
  assertNotIncludes(html, ' style=', 'dashboard inline styles')
  assertNotIncludes(html, 'meterBox.style.marginTop', 'dashboard runtime meter inline style')
  assertNotIncludes(html, '.style.cssText', 'dashboard runtime style injection')
  assertNotIncludes(html, '.innerHTML =', 'dashboard runtime HTML string injection')
  assertNotIncludes(html, 'pay.innerHTML', 'dashboard payout runtime HTML string injection')
  assertNotIncludes(html, 'onerror=', 'dashboard inline error handlers')
  return {
    walletBusyState: true,
    dynamicPayoutControls: true,
    serviceActionState: true,
    serviceInlinePlanState: true,
    aiModelAddState: true,
    appProxyWrites: true,
    leasePollingBounded: true,
    staticMarkupSafe: true
  }
}

function assertSetupWizardUiHardening (html) {
  assertIncludes(html, 'const WIZARD_ERROR_MAX = 180', 'setup wizard bounded API error max')
  assertIncludes(html, 'function wizardErrorText', 'setup wizard API error normalizer')
  assertIncludes(html, ".replace(/[\\x00-\\x1f\\x7f]+/g, ' ')", 'setup wizard API error control-char normalization')
  assertIncludes(html, "msg = msg.slice(0, WIZARD_ERROR_MAX - 3) + '...'", 'setup wizard API error length cap')
  assertIncludes(html, 'id="wizard-status" role="status" aria-live="polite"', 'setup wizard status region')
  assertIncludes(html, 'let wizardActionBusy = false', 'setup wizard action lock state')
  assertIncludes(html, 'if (wizardActionBusy) return', 'setup wizard duplicate action guard')
  assertIncludes(html, 'setWizardActionBusy(true, action)', 'setup wizard busy action start')
  assertIncludes(html, '.finally(() => { setWizardActionBusy(false, action) })', 'setup wizard busy action cleanup')
  assertIncludes(html, 'href="dashboard" data-wizard-action="dashboard"', 'setup wizard app-relative dashboard link')
  assertIncludes(html, 'document.querySelectorAll(\'[data-wizard-action="dashboard"][href]\').forEach(el => {', 'setup wizard dashboard link rewrite')
  assertIncludes(html, "el.setAttribute('href', appPath('/dashboard'))", 'setup wizard app-proxy dashboard link')
  assertNotIncludes(html, 'href="/dashboard"', 'setup wizard root dashboard link')
  assertNotIncludes(html, ' style=', 'setup wizard inline styles')
  return {
    statusRegion: true,
    actionLock: true,
    dashboardLinkAppPath: true,
    staticMarkupSafe: true
  }
}

function assertNotIncludes (text, needle, label) {
  if (text.includes(needle)) throw new Error(`${label} unexpectedly included ${needle}`)
}

async function waitForHealth (baseUrl, timeout) {
  const deadline = Date.now() + timeout
  let lastError = null
  while (Date.now() < deadline) {
    try {
      const health = await fetchJson(`${baseUrl}/health`)
      if (health && health.running === true) return health
      lastError = new Error('health response did not report running:true')
    } catch (err) {
      lastError = err
    }
    await delay(1500)
  }
  throw lastError || new Error('timed out waiting for /health')
}

async function fetchText (url, headers = {}) {
  const res = await fetch(url, { headers })
  if (!res.ok) throw new Error(`${url} returned HTTP ${res.status}`)
  return res.text()
}

async function fetchJson (url, headers = {}, opts = {}) {
  const res = await fetch(url, {
    ...opts,
    headers: { Accept: 'application/json', ...headers, ...(opts.headers || {}) }
  })
  if (!res.ok) throw new Error(`${url} returned HTTP ${res.status}`)
  return res.json()
}

async function setWallet (baseUrl, token, destination) {
  const out = await fetchJson(`${baseUrl}/api/subsidy/destination`, {
    Authorization: `Bearer ${token}`,
    'Content-Type': 'application/json'
  }, {
    method: 'POST',
    body: JSON.stringify({ destination })
  })
  const value = out?.payoutDestination?.value || ''
  if (value !== destination) throw new Error('wallet destination did not save through release image API')
}

async function setServices (baseUrl, token) {
  const out = await fetchJson(`${baseUrl}/api/manage/services/config`, {
    Authorization: `Bearer ${token}`,
    'Content-Type': 'application/json'
  }, {
    method: 'POST',
    body: JSON.stringify({ enabled: true, plugins: ['poker', 'ai'] })
  })
  assertPluginList(out?.config?.plugins, EXPECTED_POKER_AI_PLUGINS, 'service selection did not save through release image API')
  if (out?.restartRequired !== true) throw new Error('service config save did not report restartRequired:true')
  return out.config.plugins
}

async function assertUsageTelemetry (baseUrl, token) {
  const auth = { Authorization: `Bearer ${token}` }
  const usage = await fetchJson(`${baseUrl}/api/usage`, auth)
  if (!usage || typeof usage !== 'object') throw new Error('usage telemetry API did not return an object')
  if (typeof usage.enabled !== 'boolean') throw new Error('usage telemetry enabled flag is missing')
  if (!usage.verified || typeof usage.verified !== 'object') {
    throw new Error('usage telemetry verified counters are missing')
  }
  const count = assertNonNegativeNumber(usage.verified.count, 'usage telemetry verified.count')
  const bytes = assertNonNegativeNumber(usage.verified.bytes, 'usage telemetry verified.bytes')
  const bandwidthBytes = assertNonNegativeNumber(
    usage.verified.totals && usage.verified.totals.bandwidthBytes,
    'usage telemetry verified.totals.bandwidthBytes'
  )

  const poker = await fetchJson(`${baseUrl}/api/poker/usage`, auth)
  if (!poker || typeof poker !== 'object') throw new Error('poker usage telemetry API did not return an object')
  if (typeof poker.enabled !== 'boolean') throw new Error('poker usage telemetry enabled flag is missing')
  const tables = assertNonNegativeNumber(poker.tables, 'poker usage telemetry tables')
  const appends = assertNonNegativeNumber(poker.appends, 'poker usage telemetry appends')
  const seats = assertNonNegativeNumber(poker.seats, 'poker usage telemetry seats')

  return {
    bandwidth: {
      enabled: usage.enabled,
      count,
      bytes,
      bandwidthBytes
    },
    poker: {
      enabled: poker.enabled,
      tables,
      appends,
      seats
    }
  }
}

async function assertAcceptModeDefault (baseUrl) {
  const catalog = await fetchJson(`${baseUrl}/catalog.json`)
  if (catalog?.acceptMode !== 'review') {
    throw new Error(`release image did not honor HIVERELAY_ACCEPT_MODE=review: got ${JSON.stringify(catalog?.acceptMode)}`)
  }
  return catalog.acceptMode
}

async function assertDashboardWebSocket (baseUrl, token) {
  const wsUrl = httpToWsUrl(baseUrl) + '/ws'
  await assertWsUrlCredentialsRejected(wsUrl, token, baseUrl)

  const ws = new WebSocket(wsUrl, {
    headers: { Origin: baseUrl }
  })
  try {
    await waitForWsOpen(ws)
    ws.send(JSON.stringify({ type: 'auth', token }))
    const msg = await waitForWsJson(ws)
    if (msg?.type !== 'update' || !msg.overview) {
      throw new Error('dashboard WebSocket did not send an authenticated overview update')
    }
  } finally {
    try { ws.close() } catch {}
  }

  return {
    queryTokenRejected: true,
    inBandAuth: true,
    updateReceived: true
  }
}

async function assertWsUrlCredentialsRejected (wsUrl, token, origin) {
  const ws = new WebSocket(`${wsUrl}?token=${encodeURIComponent(token)}`, {
    headers: { Origin: origin }
  })
  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('dashboard WebSocket did not reject URL credentials')), 5000)
      ws.once('open', () => {
        clearTimeout(timer)
        reject(new Error('dashboard WebSocket accepted URL credentials'))
      })
      ws.once('unexpected-response', (_req, res) => {
        clearTimeout(timer)
        if (isHttpClientErrorStatus(res.statusCode)) resolve()
        else reject(new Error(`dashboard WebSocket URL credential rejection returned HTTP ${res.statusCode}`))
      })
      ws.once('error', (err) => {
        clearTimeout(timer)
        const status = parseUnexpectedResponseStatus(err)
        if (isHttpClientErrorStatus(status)) resolve()
        else reject(new Error('dashboard WebSocket URL credential rejection failed'))
      })
    })
  } finally {
    try { ws.close() } catch {}
  }
}

function parseUnexpectedResponseStatus (err) {
  const match = String(err?.message || '').match(/Unexpected server response:\s*(\d+)/)
  return match ? Number(match[1]) : null
}

function isHttpClientErrorStatus (status) {
  return Number.isInteger(status) && status >= 400 && status < 500
}

function waitForWsOpen (ws) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('dashboard WebSocket did not open')), 5000)
    ws.once('open', () => {
      clearTimeout(timer)
      resolve()
    })
    ws.once('error', (err) => {
      clearTimeout(timer)
      reject(new Error(`dashboard WebSocket open failed: ${err?.message || 'unknown error'}`))
    })
  })
}

function waitForWsJson (ws) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('dashboard WebSocket did not send an authenticated update')), 5000)
    ws.once('message', (data) => {
      clearTimeout(timer)
      try {
        resolve(JSON.parse(data.toString()))
      } catch {
        reject(new Error('dashboard WebSocket sent malformed JSON'))
      }
    })
    ws.once('close', () => {
      clearTimeout(timer)
      reject(new Error('dashboard WebSocket closed before authenticated update'))
    })
  })
}

function httpToWsUrl (baseUrl) {
  const url = new URL(baseUrl)
  url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:'
  return url.toString().replace(/\/$/, '')
}

function assertNonNegativeNumber (value, label) {
  const number = Number(value)
  if (!Number.isFinite(number) || number < 0) throw new Error(`${label} must be a non-negative number`)
  return number
}

function assertPluginList (actual, expected, label) {
  if (!Array.isArray(actual) || actual.length !== expected.length || actual.some((name, i) => name !== expected[i])) {
    throw new Error(`${label}: got ${JSON.stringify(actual)}`)
  }
}

function requireImageManifestEvidence (relativePath, smokeImageRef) {
  if (!relativePath || path.isAbsolute(relativePath) || path.normalize(relativePath) !== relativePath || relativePath.startsWith('..')) {
    fatal(`release image manifest evidence path must be a plain relative path; got ${JSON.stringify(relativePath)}`)
  }
  const file = path.resolve(process.cwd(), relativePath)
  let stat
  try {
    stat = fs.lstatSync(file)
  } catch (err) {
    if (err && err.code === 'ENOENT') fatal(`release image manifest evidence file is required before writing smoke evidence: ${relativePath}`)
    throw err
  }
  if (stat.isSymbolicLink()) fatal(`release image manifest evidence file must not be a symlink: ${relativePath}`)
  if (!stat.isFile()) fatal(`release image manifest evidence file must be a regular file: ${relativePath}`)
  if (stat.size > MAX_EVIDENCE_JSON_BYTES) {
    fatal(`release image manifest evidence file must be ${MAX_EVIDENCE_JSON_BYTES} bytes or smaller: ${relativePath} is ${stat.size} bytes`)
  }
  const body = readImageManifestEvidence(file, relativePath)
  const image = parseDigestPinnedImageRef(smokeImageRef)
  if (!image) fatal('release image manifest evidence requires a digest-pinned smoke image ref')
  if (body.schemaVersion !== 1) fatal('release image manifest evidence schemaVersion must be 1')
  if (body.kind !== 'release-image-manifest') fatal('release image manifest evidence kind must be release-image-manifest')
  if (body.status !== 'verified') fatal('release image manifest evidence status must be verified')
  if (body.image?.ref !== smokeImageRef) fatal('release image manifest image ref must match smoke image ref')
  if (body.image?.name !== image.imageName) fatal('release image manifest image name must match smoke image name')
  if (body.image?.tag !== image.imageTag) fatal('release image manifest image tag must match smoke image tag')
  if (body.image?.digest !== image.imageDigest) fatal('release image manifest image digest must match smoke image digest')
  assertManifestPlatforms(body)
}

function readImageManifestEvidence (file, relativePath) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'))
  } catch (err) {
    fatal(`release image manifest evidence must be valid JSON: ${relativePath}: ${err.message}`)
  }
}

function assertManifestPlatforms (body) {
  if (!Array.isArray(body.requiredPlatforms) ||
    body.requiredPlatforms.length !== REQUIRED_IMAGE_PLATFORMS.length ||
    body.requiredPlatforms.some((platform, index) => platform !== REQUIRED_IMAGE_PLATFORMS[index])) {
    fatal(`release image manifest required platforms must be ${JSON.stringify(REQUIRED_IMAGE_PLATFORMS)}`)
  }
  if (!Array.isArray(body.platforms)) fatal('release image manifest evidence platforms must be an array')
  const platforms = new Set(body.platforms.map((platform) => `${platform?.os}/${platform?.architecture}`))
  for (const platform of REQUIRED_IMAGE_PLATFORMS) {
    if (!platforms.has(platform)) fatal(`release image manifest evidence is missing required platform ${platform}`)
  }
}

function reservePort () {
  return new Promise((resolve, reject) => {
    const server = createServer()
    server.on('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      server.close((err) => {
        if (err) reject(err)
        else resolve(address.port)
      })
    })
  })
}

function run (cmd, argv, opts = {}) {
  return new Promise((resolve, reject) => {
    const capture = opts.capture !== false
    const child = spawn(cmd, argv, { stdio: capture ? ['ignore', 'pipe', 'pipe'] : 'inherit' })
    let stdout = ''
    let stderr = ''
    if (child.stdout) child.stdout.on('data', chunk => { stdout += chunk })
    if (child.stderr) child.stderr.on('data', chunk => { stderr += chunk })
    child.on('error', reject)
    child.on('exit', (code, signal) => {
      if (code === 0) resolve({ stdout, stderr })
      else reject(new Error(`${formatCommand(cmd, argv)} failed (${signal || code})${stderr ? `: ${redactSensitiveOutput(stderr)}` : ''}`))
    })
  })
}

function formatCommand (cmd, argv) {
  return redactSensitiveOutput([cmd, ...argv].join(' '))
}

function redactSensitiveOutput (value) {
  let text = String(value || '')
  for (const [pattern, name] of FORBIDDEN_PUBLIC_VALUE_PATTERNS) {
    const flags = pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g'
    text = text.replace(new RegExp(pattern.source, flags), `[redacted ${name}]`)
  }
  return text
}

function writeRedactedOutput (stream, value) {
  const text = redactSensitiveOutput(value)
  if (!text) return
  stream.write(text.endsWith('\n') ? text : text + '\n')
}

function recordCheck (name, details = {}) {
  checks.push({ name, status: 'passed', ...details })
}

function writeSmokeEvidence () {
  if (!evidenceFile) return
  const file = path.resolve(evidenceFile)
  const image = parseDigestPinnedImageRef(imageRef)
  if (!image) fatal('release image smoke evidence requires a GHCR semver tag plus sha256 digest image ref')
  const body = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    kind: 'release-image-smoke',
    imageRef,
    ...image,
    checks
  }
  assertPublicSafeSmoke(body, 'release image smoke')
  fs.mkdirSync(path.dirname(file), { recursive: true })
  const tmp = `${file}.tmp-${process.pid}`
  fs.writeFileSync(tmp, JSON.stringify(body, null, 2) + '\n')
  fs.renameSync(tmp, file)
}

function assertPublicSafeSmoke (value, label) {
  visit(value, '$')

  function visit (node, at) {
    if (node == null) return
    if (typeof node === 'string') {
      assertPublicSafeString(node, label, at)
      return
    }
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i++) visit(node[i], `${at}[${i}]`)
      return
    }
    if (typeof node === 'object') {
      for (const [key, child] of Object.entries(node)) {
        if (FORBIDDEN_PUBLIC_SMOKE_KEYS.has(key.toLowerCase())) {
          fatal(`${label} evidence must not expose ${key} at ${at}.${key}`)
        }
        visit(child, `${at}.${key}`)
      }
    }
  }
}

function assertPublicSafeString (value, label, at) {
  if (hasControlChars(value)) fatal(`${label} evidence must not contain control characters at ${at}`)
  for (const [pattern, name] of FORBIDDEN_PUBLIC_VALUE_PATTERNS) {
    if (pattern.test(value)) fatal(`${label} evidence must not expose ${name} at ${at}`)
  }
  if (!/^https?:\/\//i.test(value)) return
  try {
    const url = new URL(value)
    if (url.username || url.password) fatal(`${label} evidence must not expose URL credentials at ${at}`)
  } catch (_) {}
}

function hasControlChars (value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if (code < 32 || code === 127) return true
  }
  return false
}

async function printLogs () {
  try {
    const logs = await run('docker', ['logs', '--tail', '160', containerName], { capture: true })
    writeRedactedOutput(process.stdout, logs.stdout)
    writeRedactedOutput(process.stderr, logs.stderr)
  } catch (_) {}
}

async function cleanup () {
  if (cleaned) return
  cleaned = true
  try {
    await run('docker', ['rm', '-f', containerName], { capture: true })
  } catch (_) {}
}

function delay (ms) {
  return new Promise(resolve => setTimeout(resolve, ms))
}

function fatal (message) {
  console.error(redactSensitiveOutput(message))
  process.exit(1)
}
