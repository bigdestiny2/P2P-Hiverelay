#!/usr/bin/env node
import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import fs from 'node:fs/promises'
import { createReadStream } from 'node:fs'
import { createServer } from 'node:http'
import os from 'node:os'
import path from 'node:path'
import process from 'node:process'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'
import b4a from 'b4a'
import {
  BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT_PROFILES,
  decodeBlindClientPublicBrowserArtifactManifestV1,
  encodeBlindClientPublicBrowserChromiumEvidenceV1,
  hashBlindClientPublicBrowserArtifactManifestV1,
  verifyBlindClientPublicBrowserArtifactV1
} from '../browser-artifact.js'

const execute = promisify(execFile)
const argv = process.argv.slice(2)
const hostMode = argv.length === 0
const ciFunctionalOnly = argv.length === 1 && argv[0] === '--ci-functional-only'
if (!hostMode && !ciFunctionalOnly) {
  throw new Error('usage: test-blind-client-public-browser-artifact-chromium.mjs [--ci-functional-only]')
}

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const root = path.resolve(packageRoot, '../..')
const generator = path.join(packageRoot, 'scripts/generate-blind-client-public-browser-artifacts.mjs')
const hostNode = '/opt/homebrew/Cellar/node@22/22.22.0/bin/node'
const hostNodeHash = '59776c1735b2c28a28b0ae00b58bd9cbe524572e0caf62e043d5e44a62d98cce'
const hostChromium = '/Users/localllm/Library/Caches/ms-playwright/chromium_headless_shell-1234/chrome-headless-shell-mac-arm64/chrome-headless-shell'
const hostChromiumVersion = 'Google Chrome for Testing 151.0.7922.34'
const hostChromiumHash = '7687bff7cb2db075f250e6d5848bbc8838cac3802ac3952a899c574f8eccab45'
const contentSecurityPolicy = "default-src 'self'; base-uri 'none'; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: hyper: pear:; connect-src 'self' hyper: pear: https://relay-syd.p2phiverelay.xyz https://relay-dal.p2phiverelay.xyz; frame-ancestors 'none'; form-action 'none'"
const tempPrefix = hostMode
  ? 'hiverelay-blind-client-public-browser-chromium-'
  : 'hr-bc-'
const profiles = Object.freeze({
  full: BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT_PROFILES.full,
  limited: BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT_PROFILES.limited
})

function absolute (relative) {
  return path.resolve(root, ...relative.split('/'))
}

async function sha256File (file) {
  const hash = createHash('sha256')
  await new Promise((resolve, reject) => {
    const stream = createReadStream(file)
    stream.on('data', chunk => hash.update(chunk))
    stream.once('error', reject)
    stream.once('end', resolve)
  })
  return hash.digest('hex')
}

async function requireRealDirectoryAncestry (expected, field) {
  if (!path.isAbsolute(expected)) throw new Error(`${field} must be absolute`)
  const parsed = path.parse(expected)
  let current = parsed.root
  for (const segment of expected.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, segment)
    const stat = await fs.lstat(current)
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      throw new Error(`${field} ancestry must contain only real directories: ${current}`)
    }
  }
  if (await fs.realpath(expected) !== expected) throw new Error(`${field} realpath changed: ${expected}`)
}

async function assertHostEnvironment () {
  const expected = {
    TMPDIR: path.join(root, '.t/seq29-browser-artifact-gates/tmp'),
    npm_config_cache: path.join(root, '.t/seq29-browser-artifact-gates/npm-cache'),
    npm_config_devdir: '/Users/localllm/Library/Caches/node-gyp'
  }
  for (const [name, value] of Object.entries(expected)) {
    if (process.env[name] !== value) throw new Error(`${name} must be the exact scoped host gate path ${value}`)
    await requireRealDirectoryAncestry(value, name)
  }
  if (process.execPath !== hostNode || process.version !== 'v22.22.0' ||
      process.versions.modules !== '127' || process.versions.napi !== '10' ||
      process.platform !== 'darwin' || process.arch !== 'arm64' ||
      await sha256File(process.execPath) !== hostNodeHash) {
    throw new Error('host Chromium gate requires the exact pinned Node runtime')
  }
}

async function assertCiEnvironment () {
  if (process.env.CI !== 'true') throw new Error('CI functional mode requires CI=true')
  if (!process.env.RUNNER_TEMP) throw new Error('CI functional mode requires RUNNER_TEMP')
  await requireRealDirectoryAncestry(process.env.RUNNER_TEMP, 'RUNNER_TEMP')
}

async function executable (candidate) {
  if (!candidate) return null
  try {
    await fs.access(candidate, fs.constants.X_OK)
    return candidate
  } catch {
    return null
  }
}

async function ciChromium () {
  const candidates = [
    process.env.HIVERELAY_CHROMIUM,
    process.env.CHROMIUM_PATH,
    process.env.CHROME_PATH,
    '/usr/bin/google-chrome',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser'
  ]
  for (const candidate of candidates) {
    const found = await executable(candidate)
    if (found) return found
  }
  const cache = process.env.PLAYWRIGHT_BROWSERS_PATH ||
    path.join(os.homedir(), '.cache/ms-playwright')
  let names = []
  try { names = await fs.readdir(cache) } catch {}
  for (const name of names.sort().reverse()) {
    for (const relative of [
      'chrome-headless-shell-linux64/chrome-headless-shell',
      'chrome-linux/chrome',
      'chrome-linux64/chrome'
    ]) {
      const found = await executable(path.join(cache, name, relative))
      if (found) return found
    }
  }
  throw new Error('CI functional mode requires an available real Chromium executable')
}

async function generatorReport () {
  const result = await execute(process.execPath, [generator, '--check'], {
    cwd: root,
    env: process.env,
    encoding: 'utf8',
    timeout: 120_000,
    killSignal: 'SIGKILL',
    maxBuffer: 4 * 1024 * 1024
  })
  const reports = result.stdout.split(/\r?\n/).filter(Boolean).map(line => {
    try { return JSON.parse(line) } catch { return null }
  }).filter(value => value && value.schema === 'HiveRelayBlindClientPublicBrowserArtifactGenerationV1')
  if (reports.length !== 1 || reports[0].mode !== 'check' ||
      !/^[0-9a-f]{64}$/.test(reports[0].normalizedGraphSetHash)) {
    throw new Error('host Chromium gate did not receive one canonical generator report')
  }
  return reports[0]
}

function page () {
  return '<!doctype html>\n<meta charset="utf-8">\n' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">\n' +
    '<link rel="icon" href="data:,">\n' +
    '<title>HiveRelay public browser artifact gate</title>\n' +
    '<body data-status="running">running</body>\n' +
    '<script type="module" src="/bootstrap.mjs"></script>\n'
}

function bootstrapModule () {
  return `const body = document.body
const observed = { securitypolicyviolation: [], error: [], unhandledrejection: [] }
addEventListener('securitypolicyviolation', event => observed.securitypolicyviolation.push(event.violatedDirective || 'unknown'))
addEventListener('error', event => observed.error.push(event.message || 'unknown'))
addEventListener('unhandledrejection', event => observed.unhandledrejection.push(String(event.reason || 'unknown')))
try {
  const gate = await import('/gate.mjs')
  const result = await gate.run()
  await new Promise(resolve => setTimeout(resolve, 0))
  if (observed.securitypolicyviolation.length || observed.error.length || observed.unhandledrejection.length) {
    throw new Error('browser event inventory is not empty: ' + JSON.stringify(observed))
  }
  body.dataset.status = 'pass'
  body.textContent = JSON.stringify({ ok: true, result, observed })
} catch (error) {
  body.dataset.status = 'fail'
  body.textContent = JSON.stringify({ ok: false, message: error && error.message ? error.message : String(error), observed })
}
`
}

function commonGateSource (identity, functionalSource) {
  return `const exactExports = ${JSON.stringify([...identity.exactSortedExports].sort())}
const forbiddenExports = ${JSON.stringify([
    'createInboxReplica',
    'createWatchInboxRequest',
    'createRenewInboxRequest',
    'createCloseInboxRequest',
    'destroyInboxWriteCapability'
  ])}
function equalBytes (left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index])
}
async function common(client) {
  const actual = Object.keys(client).sort()
  if (JSON.stringify(actual) !== JSON.stringify(exactExports)) throw new Error('runtime export inventory changed')
  for (const name of forbiddenExports) if (name in client) throw new Error('forbidden lifecycle export ' + name)
  const runtime = client.createBrowserCryptoRuntime(globalThis.crypto)
  const key = new Uint8Array(32).fill(0x11)
  const nonce = new Uint8Array(12).fill(0x22)
  const aad = new TextEncoder().encode('HIVERELAY_PUBLIC_BROWSER_AAD_V1')
  const plaintext = new TextEncoder().encode('HIVERELAY_PUBLIC_BROWSER_PLAINTEXT_V1')
  const sealed = await runtime.aes256GcmEncrypt({ key, nonce, aad, plaintext })
  const opened = await runtime.aes256GcmDecrypt({ key, nonce, aad, sealed })
  if (!equalBytes(opened, plaintext)) throw new Error('WebCrypto AES-256-GCM round trip failed')
  return { runtime, exportCount: actual.length }
}
export async function run() {
  const client = await import('/${path.posix.basename(identity.artifactPath)}')
  const shared = await common(client)
  ${functionalSource}
}
`
}

function gateModule (id, identity) {
  if (id === 'full') {
    return commonGateSource(identity, `let receiver = null
  const originalFetch = globalThis.fetch
  try {
    globalThis.fetch = function () { receiver = this; return Promise.resolve(new Response()) }
    const direct = new client.BlindDirectHttpClient({ runtime: {} })
    await direct.fetch('https://example.invalid')
    if (receiver !== globalThis) throw new Error('global fetch fallback is not bound')
    globalThis.fetch = undefined
    let missingFetchRejected = false
    try { new client.BlindDirectHttpClient({ runtime: {} }) } catch { missingFetchRejected = true }
    if (!missingFetchRejected) throw new Error('missing global fetch did not fail closed')
  } finally {
    globalThis.fetch = originalFetch
  }
  const readCap = {
    relayPublicKey: new Uint8Array(32).fill(0x31),
    physicalTopic: new Uint8Array(32).fill(0x32),
    frameClassBits: 1,
    appendAuthMode: 0,
    appendPublicKey: null
  }
  const admission = {
    profileId: 1,
    schemeId: 1,
    parameterHash: new Uint8Array(32).fill(0x33),
    token: new Uint8Array([0x34])
  }
  const append = await client.createAppendInboxRequest({
    runtime: shared.runtime,
    readCap,
    frameClass: 1,
    frame: new Uint8Array(4096).fill(0x41),
    clientNonce: new Uint8Array(32).fill(0x42),
    admission
  })
  if (!append.requestBytes.length || append.request.frame.length !== 4096 || append.request.appendSignature !== null) {
    throw new Error('INBOX APPEND functional semantics changed')
  }
  const nullCursor = await client.createReadInboxRequest({
    runtime: shared.runtime,
    readCap,
    cursor: null,
    limit: 1,
    clientNonce: new Uint8Array(32).fill(0x43)
  })
  const presentCursor = await client.createReadInboxRequest({
    runtime: shared.runtime,
    readCap,
    cursor: new Uint8Array([0x44]),
    limit: 1,
    clientNonce: new Uint8Array(32).fill(0x45)
  })
  if (nullCursor.request.cursor.length !== 0 || presentCursor.request.cursor.length !== 1 ||
      nullCursor.wire.expectedResultBodyBytes < 4096 ||
      presentCursor.wire.expectedResultBodyBytes !== nullCursor.wire.expectedResultBodyBytes) {
    throw new Error('compressed INBOX READ functional semantics changed')
  }
  return { profileId: 'full', exportCount: shared.exportCount, appendBytes: append.requestBytes.length,
    readBytes: nullCursor.requestBytes.length, aes256Gcm: true, boundGlobalFetch: true }
`)
  }
  return commonGateSource(identity, `let fetchCalls = 0
  const control = client.createBlindCellGetControl({
    runtime: {},
    fetch: async () => { fetchCalls++; throw new Error('unexpected transport') },
    nowEpoch: () => 1,
    monotonicMillis: () => 1,
    supportedProtocolProfiles: [{ profileId: 1, profileHash: new Uint8Array(32).fill(1) }],
    supportedTransportProfiles: [{ transportProfileId: 1, transportProfileHash: new Uint8Array(32).fill(2) }]
  })
  const methods = Object.getOwnPropertyNames(Object.getPrototypeOf(control)).sort()
  if (JSON.stringify(methods) !== JSON.stringify(['constructor', 'qualifyCellGetCandidate', 'readCell'])) {
    throw new Error('limited control methods changed')
  }
  let selectionRejected = false
  try { await control.qualifyCellGetCandidate({}, { familyId: 1 }) } catch { selectionRejected = true }
  if (!selectionRejected) throw new Error('limited control accepted caller-selected operation')
  let foreignRejected = false
  try { await control.readCell({ endpoint: Object.freeze({}) }) } catch { foreignRejected = true }
  if (!foreignRejected || fetchCalls !== 0) throw new Error('limited control did not fail closed before transport')
  return { profileId: 'limited', exportCount: shared.exportCount, aes256Gcm: true,
    cellGetOnly: true, transportCalls: fetchCalls }
`)
}

async function listen (id, identity, artifactBytes) {
  const requests = []
  const routes = new Map([
    ['/', { contentType: 'text/html; charset=utf-8', bytes: b4a.from(page()) }],
    ['/bootstrap.mjs', { contentType: 'text/javascript; charset=utf-8', bytes: b4a.from(bootstrapModule()) }],
    ['/gate.mjs', { contentType: 'text/javascript; charset=utf-8', bytes: b4a.from(gateModule(id, identity)) }],
    [`/${path.posix.basename(identity.artifactPath)}`, { contentType: 'text/javascript; charset=utf-8', bytes: artifactBytes }]
  ])
  const server = createServer((request, response) => {
    requests.push(request.url)
    response.setHeader('Cache-Control', 'no-store')
    response.setHeader('Content-Security-Policy', contentSecurityPolicy)
    response.setHeader('X-Content-Type-Options', 'nosniff')
    const route = routes.get(request.url)
    if (!route) {
      response.statusCode = 404
      response.end()
      return
    }
    response.statusCode = 200
    response.setHeader('Content-Type', route.contentType)
    response.setHeader('Content-Length', String(route.bytes.byteLength))
    response.end(route.bytes)
  })
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  return { server, requests }
}

async function runProfile (
  id,
  identity,
  chromium,
  version,
  tempRoot,
  generatorProfile,
  generatorSourceClosureHash
) {
  const [artifactBytes, manifestBytes] = await Promise.all([
    fs.readFile(absolute(identity.artifactPath)),
    fs.readFile(absolute(identity.manifestPath))
  ])
  const verified = verifyBlindClientPublicBrowserArtifactV1({
    profile: id,
    manifestBytes,
    artifactBytes,
    expectedManifestHash: generatorProfile == null
      ? hashBlindClientPublicBrowserArtifactManifestV1(manifestBytes)
      : generatorProfile.manifestHash,
    expectedSourceClosureHash: generatorProfile == null
      ? decodeBlindClientPublicBrowserArtifactManifestV1(manifestBytes).sourceClosureHash
      : generatorSourceClosureHash,
    ...(generatorProfile == null ? {} : { expectedTupleHash: generatorProfile.tupleHash })
  })
  const profileDirectory = path.join(tempRoot, id)
  await fs.mkdir(profileDirectory, { mode: 0o700 })
  const browserEnvironment = ciFunctionalOnly
    ? {
        ...process.env,
        HOME: tempRoot,
        XDG_CACHE_HOME: path.join(tempRoot, 'xdg-cache'),
        XDG_CONFIG_HOME: path.join(tempRoot, 'xdg-config'),
        TMPDIR: path.join(tempRoot, 'tmp')
      }
    : process.env
  if (ciFunctionalOnly) {
    await Promise.all([
      fs.mkdir(browserEnvironment.XDG_CACHE_HOME, { recursive: true, mode: 0o700 }),
      fs.mkdir(browserEnvironment.XDG_CONFIG_HOME, { recursive: true, mode: 0o700 }),
      fs.mkdir(browserEnvironment.TMPDIR, { recursive: true, mode: 0o700 })
    ])
  }
  const { server, requests } = await listen(id, identity, artifactBytes)
  const address = server.address()
  try {
    const headlessFlag = path.basename(chromium).includes('headless-shell') ? '--headless' : '--headless=new'
    const result = await execute(chromium, [
      headlessFlag,
      '--disable-background-networking',
      '--disable-breakpad',
      '--disable-component-update',
      '--disable-crash-reporter',
      '--disable-default-apps',
      '--disable-extensions',
      '--disable-sync',
      '--metrics-recording-only',
      '--no-first-run',
      `--user-data-dir=${profileDirectory}`,
      '--virtual-time-budget=15000',
      '--dump-dom',
      `http://127.0.0.1:${address.port}/`
    ], {
      cwd: root,
      env: browserEnvironment,
      encoding: 'utf8',
      timeout: 45_000,
      killSignal: 'SIGKILL',
      maxBuffer: 8 * 1024 * 1024
    })
    if (!result.stdout.includes('data-status="pass"') ||
        (!result.stdout.includes('&quot;ok&quot;:true') && !result.stdout.includes('"ok":true'))) {
      throw new Error(`real Chromium did not pass ${id}: ${result.stdout}\n${result.stderr}`)
    }
    if (requests.length !== identity.chromiumRequestInventory.length ||
        requests.some((value, index) => value !== identity.chromiumRequestInventory[index])) {
      throw new Error(`${id} Chromium request inventory changed: ${JSON.stringify(requests)}`)
    }
    return {
      verified,
      version,
      requestInventory: Object.freeze([...requests]),
      securityPolicyViolationCount: 0,
      errorCount: 0,
      unhandledRejectionCount: 0
    }
  } finally {
    await new Promise(resolve => server.close(resolve))
  }
}

async function matchingTempChildren (parent) {
  return (await fs.readdir(parent)).filter(name => name.startsWith(tempPrefix)).sort()
}

async function removeOwnedDirectory (parent, directory, identity) {
  const stat = await fs.lstat(directory)
  if (!stat.isDirectory() || stat.isSymbolicLink() || `${stat.dev}:${stat.ino}` !== identity ||
      path.dirname(await fs.realpath(directory)) !== await fs.realpath(parent)) {
    throw new Error('Chromium temporary custody changed before cleanup')
  }
  await fs.rm(directory, { recursive: true, force: false })
}

if (hostMode) await assertHostEnvironment()
else await assertCiEnvironment()

const chromium = hostMode ? hostChromium : await ciChromium()
if (!await executable(chromium)) throw new Error(`Chromium executable is unavailable: ${chromium}`)
if (hostMode && await sha256File(chromium) !== hostChromiumHash) {
  throw new Error('pinned Chromium executable hash changed')
}
const version = (await execute(chromium, ['--version'], {
  encoding: 'utf8',
  timeout: 10_000,
  killSignal: 'SIGKILL',
  maxBuffer: 1024 * 1024
})).stdout.trim()
if (hostMode && version !== hostChromiumVersion) throw new Error(`pinned Chromium version changed: ${version}`)

const generatorResult = hostMode ? await generatorReport() : null
const tempParent = hostMode ? process.env.TMPDIR : process.env.RUNNER_TEMP
if ((await matchingTempChildren(tempParent)).length !== 0) {
  throw new Error('Chromium gate temporary prefix has pre-existing residue')
}
const tempRoot = await fs.mkdtemp(path.join(tempParent, tempPrefix))
const tempStat = await fs.lstat(tempRoot)
const tempIdentity = `${tempStat.dev}:${tempStat.ino}`
const results = {}
try {
  for (const [id, identity] of Object.entries(profiles)) {
    results[id] = await runProfile(
      id,
      identity,
      chromium,
      version,
      tempRoot,
      generatorResult == null ? null : generatorResult.profiles[id],
      generatorResult == null ? null : generatorResult.sourceClosureHash)
  }
} finally {
  await removeOwnedDirectory(tempParent, tempRoot, tempIdentity)
}
if ((await matchingTempChildren(tempParent)).length !== 0) {
  throw new Error('Chromium gate left matching temporary residue')
}

const report = {
  schema: 'HiveRelayBlindClientPublicBrowserArtifactChromiumGateV1',
  mode: hostMode ? 'pinned-host-evidence' : 'ci-functional-only',
  chromium: version,
  releaseReady: false,
  standaloneAuthority: false,
  authority: hostMode
    ? 'external-postcommit-final-sequence-required'
    : 'non-authoritative-ci-signal-only',
  profiles: {}
}
for (const [id, identity] of Object.entries(profiles)) {
  const result = results[id]
  if (hostMode) {
    const evidence = {
      schema: 'HiveRelayBlindClientPublicBrowserArtifactChromiumEvidenceV1',
      version: 1,
      evidenceClass: 'real-chromium',
      profile: identity.profile,
      artifactPath: identity.artifactPath,
      artifactLength: result.verified.artifactLength,
      artifactHash: result.verified.artifactHash,
      manifestHash: result.verified.manifestHash,
      tupleHash: result.verified.tupleHash,
      sourceClosureHash: result.verified.sourceClosureHash,
      chromium: hostChromiumVersion,
      chromiumExecutablePath: hostChromium,
      chromiumExecutableHash: hostChromiumHash,
      contentSecurityPolicySourceCommit: '6a8c1743d7e7ed504ccb0482f248e77d77fddca3',
      contentSecurityPolicySourcePath: 'deploy/render-security-headers.json',
      contentSecurityPolicySourceFileHash: 'e672153d1c396e617491fce64ed5472635314e20c45864e959b48e5f1b52b312',
      contentSecurityPolicy,
      contentSecurityPolicyHash: 'b3c81c106609f04764e531e72842dffcaf061d33263a5c24c447a9a06cd0ed6b',
      requestInventory: identity.chromiumRequestInventory,
      securityPolicyViolationCount: result.securityPolicyViolationCount,
      errorCount: result.errorCount,
      unhandledRejectionCount: result.unhandledRejectionCount,
      candidateIdentityBinding: 'external-postcommit-final-sequence',
      standaloneAuthority: false,
      checks: identity.chromiumChecks,
      passed: true
    }
    await fs.writeFile(absolute(identity.chromiumEvidencePath),
      encodeBlindClientPublicBrowserChromiumEvidenceV1(evidence), { mode: 0o644 })
  }
  report.profiles[id] = {
    profile: identity.profile,
    artifactPath: identity.artifactPath,
    artifactHash: result.verified.artifactHash,
    manifestHash: result.verified.manifestHash,
    requestInventory: result.requestInventory,
    securityPolicyViolationCount: result.securityPolicyViolationCount,
    errorCount: result.errorCount,
    unhandledRejectionCount: result.unhandledRejectionCount,
    evidenceWritten: hostMode,
    ok: true
  }
}
report.tempDirectChildrenCreated = 1
report.matchingResidue = 0
process.stdout.write(`${JSON.stringify(report)}\n`)
