#!/usr/bin/env node
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import process from 'node:process'
import { execFile, spawn } from 'node:child_process'
import { createServer } from 'node:http'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'
import b4a from 'b4a'
import { decodeCanonical } from '../packages/blind-protocol/codec.js'
import { blindForwardHttpsOriginForwardTurnRequestV1 } from '../packages/blind-protocol/wire-v3.js'
import {
  decodeBlindClientBrowserArtifactManifestV3,
  verifyBlindClientBrowserArtifactV3
} from '../packages/blind-client/browser-artifact-v3.js'

const execute = promisify(execFile)
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const artifactRoot = path.join(root, 'packages/blind-client/browser-artifacts')
const vectorRoot = path.join(root, 'packages/blind-protocol/vectors-v3/wire/positive')

async function browserFixture (wireV3AbiHash) {
  const names = [
    'open-origin.bin',
    'open-source-pre-forward-error.bin',
    'open-target-result.bin',
    'data-origin-max.bin',
    'data-target-ack.bin',
    'data-target-close.bin',
    'close-origin.bin',
    'close-target-ack.bin'
  ]
  const vectors = Object.fromEntries(await Promise.all(names.map(async name => [
    name,
    b4a.toString(await fs.readFile(path.join(vectorRoot, name)), 'base64')
  ])))
  const originBytes = b4a.from(vectors['open-origin.bin'], 'base64')
  const origin = decodeCanonical(blindForwardHttpsOriginForwardTurnRequestV1, originBytes, { copyBytes: true })
  const capability = origin.parentCapability
  const endpoint = {
    version: 3,
    releaseProfileId: 2,
    routeKind: 7,
    wireV3AbiHash,
    verifiedEndpointHandleHash: 'a1'.repeat(32),
    sourceRelayPublicKey: b4a.toString(capability.sourceRelayPublicKey, 'hex'),
    sourceDescriptorSequence: capability.sourceDescriptorSequence.toString(),
    sourceDescriptorHash: b4a.toString(capability.sourceDescriptorHash, 'hex'),
    targetCatalogEntryId: b4a.toString(capability.targetCatalogEntryId, 'hex'),
    targetRelayPublicKey: b4a.toString(capability.targetRelayPublicKey, 'hex'),
    targetDescriptorSequence: capability.targetDescriptorSequence.toString(),
    targetDescriptorHash: b4a.toString(capability.targetDescriptorHash, 'hex'),
    signedDescriptorHash: 'a2'.repeat(32),
    signedHealthHash: 'a3'.repeat(32),
    descriptorFresh: true,
    signedHealthFresh: true,
    credentialFreeHttps: true,
    cookies: false,
    authorization: false,
    referrer: false,
    redirect: false,
    exactRequestBytes: 65_536,
    exactResultBytes: 65_536,
    continuityBackend: 'INDEXEDDB_PERSISTENT'
  }
  return { vectors, endpoint }
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

async function playwrightCandidates () {
  const cache = process.env.PLAYWRIGHT_BROWSERS_PATH || path.join(os.homedir(), 'Library/Caches/ms-playwright')
  let names
  try {
    names = await fs.readdir(cache)
  } catch {
    return []
  }
  const newestFirst = values => values.sort((left, right) => right.localeCompare(left, 'en', { numeric: true }))
  const versions = [
    ...newestFirst(names.filter(name => /^chromium_headless_shell-[0-9]+$/.test(name))),
    ...newestFirst(names.filter(name => /^chromium-[0-9]+$/.test(name)))
  ]
  const output = []
  for (const name of versions) {
    const base = path.join(cache, name)
    output.push(
      path.join(base, 'chrome-headless-shell-mac-arm64/chrome-headless-shell'),
      path.join(base, 'chrome-headless-shell-mac-x64/chrome-headless-shell'),
      path.join(base, 'chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing'),
      path.join(base, 'chrome-mac-x64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing'),
      path.join(base, 'chrome-linux/chrome'),
      path.join(base, 'chrome-linux64/chrome'),
      path.join(base, 'chrome-headless-shell-linux64/chrome-headless-shell')
    )
  }
  return output
}

async function findChromium () {
  const candidates = [
    process.env.HIVERELAY_CHROMIUM,
    process.env.CHROMIUM_PATH,
    '/Applications/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/usr/bin/google-chrome',
    ...await playwrightCandidates()
  ]
  for (const candidate of candidates) {
    const found = await executable(candidate)
    if (found) return found
  }
  throw new Error('real Chromium is required; set HIVERELAY_CHROMIUM to its executable')
}

function page (fixture) {
  return `<!doctype html>
<meta charset="utf-8">
<title>HiveRelay WIRE v3 IndexedDB crash gate</title>
<body data-status="running">running</body>
<script type="module">
const body = document.body
const fixture = ${JSON.stringify(fixture)}
const equal = (left, right) => left.length === right.length && left.every((value, index) => value === right[index])
const deepEqual = (left, right) => {
  if (left === right) return true
  if (left instanceof Uint8Array || right instanceof Uint8Array) {
    return left instanceof Uint8Array && right instanceof Uint8Array && equal(left, right)
  }
  if (!left || !right || typeof left !== 'object' || typeof right !== 'object') return false
  const leftKeys = Object.keys(left).sort()
  const rightKeys = Object.keys(right).sort()
  return leftKeys.length === rightKeys.length && leftKeys.every((key, index) => key === rightKeys[index] && deepEqual(left[key], right[key]))
}
const base64 = value => Uint8Array.from(atob(value), character => character.charCodeAt(0))
const hex = value => Uint8Array.from(value.match(/../g), pair => Number.parseInt(pair, 16))
const vectors = Object.fromEntries(Object.entries(fixture.vectors).map(([name, value]) => [name, base64(value)]))
const byteFields = [
  'wireV3AbiHash', 'verifiedEndpointHandleHash', 'sourceRelayPublicKey', 'sourceDescriptorHash',
  'targetCatalogEntryId', 'targetRelayPublicKey', 'targetDescriptorHash', 'signedDescriptorHash', 'signedHealthHash'
]
const endpoint = { ...fixture.endpoint }
for (const field of byteFields) endpoint[field] = hex(endpoint[field])
endpoint.sourceDescriptorSequence = BigInt(endpoint.sourceDescriptorSequence)
endpoint.targetDescriptorSequence = BigInt(endpoint.targetDescriptorSequence)
const input = (sessionKey, requestBytes) => ({ sessionKey, verifiedEndpoint: endpoint, requestBytes })
const request = value => new Promise((resolve, reject) => {
  value.onsuccess = () => resolve(value.result)
  value.onerror = () => reject(value.error || new Error('raw IndexedDB request failed'))
})
const transaction = value => new Promise((resolve, reject) => {
  value.oncomplete = () => resolve()
  value.onabort = () => reject(value.error || new Error('raw IndexedDB transaction aborted'))
  value.onerror = () => reject(value.error || new Error('raw IndexedDB transaction failed'))
})
const rawPut = async (database, key, value) => {
  const tx = database.transaction('forwardHttpsSessionsV3', 'readwrite')
  const done = transaction(tx)
  tx.objectStore('forwardHttpsSessionsV3').put(value, key)
  await done
}
const rawGet = async (database, key) => {
  const tx = database.transaction('forwardHttpsSessionsV3', 'readonly')
  const done = transaction(tx)
  const value = await request(tx.objectStore('forwardHttpsSessionsV3').get(key))
  await done
  return value
}
const rejects = async (operation, pattern) => {
  try {
    await operation()
  } catch (error) {
    if (!pattern || pattern.test(error && error.message ? error.message : String(error))) return error
    throw new Error('unexpected rejection: ' + (error && error.message ? error.message : String(error)))
  }
  throw new Error('operation unexpectedly succeeded')
}
try {
  body.textContent = 'stage:import'
  const client = await import('/blind-client-control-v3.mjs')
  if (client.BLIND_CLIENT_CONTROL_V3_AUTHORITY.runtimeReady !== false ||
      client.BLIND_CLIENT_CONTROL_V3_AUTHORITY.forwardReadinessOperationBits !== 0 ||
      client.BLIND_CLIENT_CONTROL_V3_AUTHORITY.authorizesRelease !== false) {
    throw new Error('browser v3 artifact is not fail-closed')
  }
  if (client.commitVerifiedForwardHttpsResultV3.length !== 3 ||
      typeof client.prepareForwardHttpsOriginPersistenceV3 !== 'function' ||
      typeof client.assertForwardHttpsPersistedSessionRecordV3 !== 'function') {
    throw new Error('browser v3 exact result and pure state APIs are incomplete')
  }
  const databaseName = 'hiverelay-v3-chromium-' + Date.now()
  body.textContent = 'stage:open'
  let database = await client.openForwardHttpsIndexedDbV3(databaseName)
  const openOrigin = vectors['open-origin.bin']
  const openSource = vectors['open-source-pre-forward-error.bin']
  const openTarget = vectors['open-target-result.bin']

  body.textContent = 'stage:verified-wrapper-source'
  let observedAwaiting = false
  const source = await client.fetchPersistedForwardHttpsOriginV3(database, input('session-main', openOrigin), async exact => {
    const persisted = await client.loadForwardHttpsSessionV3(database, 'session-main')
    observedAwaiting = persisted.outstandingState === 2 && equal(persisted.outstandingOriginRequest, exact)
    return openSource
  })
  if (!observedAwaiting || !Object.isFrozen(source) || source.verified !== true || source.advanced !== false || source.resultRole !== 2) {
    throw new Error('verified wrapper did not expose AWAITING source non-advance')
  }
  let retained = await client.loadForwardHttpsSessionV3(database, 'session-main')
  if (retained.outstandingState !== 2 || retained.nextSequence !== '0' || !equal(retained.outstandingOriginRequest, openOrigin)) {
    throw new Error('source result advanced or cleared the exact request')
  }

  body.textContent = 'stage:invalid-results'
  await rejects(() => client.commitVerifiedForwardHttpsResultV3(database, 'session-main', new Uint8Array(65536)))
  await rejects(() => client.commitVerifiedForwardHttpsResultV3(database, 'session-main', vectors['data-target-ack.bin']))
  retained = await client.loadForwardHttpsSessionV3(database, 'session-main')
  if (retained.outstandingState !== 2 || retained.nextSequence !== '0') throw new Error('invalid ID77 mutated durable state')

  body.textContent = 'stage:verified-wrapper-target'
  let exactRetry = false
  const target = await client.retryPersistedForwardHttpsOriginV3(database, 'session-main', async exact => {
    const persisted = await client.loadForwardHttpsSessionV3(database, 'session-main')
    exactRetry = persisted.outstandingState === 2 && equal(exact, openOrigin) && equal(persisted.outstandingOriginRequest, openOrigin)
    return openTarget
  })
  if (!exactRetry || target.verified !== true || target.advanced !== true || target.normalClose || target.targetFin) {
    throw new Error('exact retry did not verify and atomically advance TARGET_RESULT')
  }
  let committed = await client.loadForwardHttpsSessionV3(database, 'session-main')
  if (committed.outstandingState !== 0 || committed.nextSequence !== '1' || !equal(committed.lastDefinitiveTargetResult, openTarget)) {
    throw new Error('definitive target result did not commit complete history')
  }

  body.textContent = 'stage:later-history-target-fin'
  const priorResult = new Uint8Array(committed.lastDefinitiveTargetResult)
  let laterAwaiting = false
  const fin = await client.fetchPersistedForwardHttpsOriginV3(database, input('session-main', vectors['data-origin-max.bin']), async exact => {
    const persisted = await client.loadForwardHttpsSessionV3(database, 'session-main')
    laterAwaiting = persisted.outstandingState === 2 && equal(persisted.lastDefinitiveTargetResult, priorResult) && equal(exact, vectors['data-origin-max.bin'])
    return vectors['data-target-close.bin']
  })
  committed = await client.loadForwardHttpsSessionV3(database, 'session-main')
  if (!laterAwaiting || !fin.targetFin || fin.normalClose || committed.targetFin !== true || committed.terminal !== 0 || committed.nextSequence !== '2') {
    throw new Error('target response CLOSE was confused with normal close or lost history')
  }

  body.textContent = 'stage:recovery-low-level'
  await client.persistForwardHttpsOriginBeforeFetchV3(database, input('session-recovery', openOrigin))
  const recovered = await client.commitVerifiedForwardHttpsResultV3(database, 'session-recovery', openTarget)
  if (!recovered.advanced || recovered.nextSequence !== '1') throw new Error('low-level exact result recovery did not commit state 1')
  await rejects(() => client.commitVerifiedForwardHttpsResultV3(database, 'session-recovery', openTarget), /outstanding/)
  const recoveredRecord = await client.loadForwardHttpsSessionV3(database, 'session-recovery')

  body.textContent = 'stage:normal-close'
  await client.persistForwardHttpsOriginBeforeFetchV3(database, input('session-close', openOrigin))
  await client.commitVerifiedForwardHttpsResultV3(database, 'session-close', openTarget)
  const closed = await client.fetchPersistedForwardHttpsOriginV3(database, input('session-close', vectors['close-origin.bin']), async exact => {
    const persisted = await client.loadForwardHttpsSessionV3(database, 'session-close')
    if (persisted.outstandingState !== 2 || !equal(exact, vectors['close-origin.bin'])) throw new Error('CLOSE transport did not observe AWAITING')
    return vectors['close-target-ack.bin']
  })
  const closedRecord = await client.loadForwardHttpsSessionV3(database, 'session-close')
  if (!closed.normalClose || closed.targetFin || closedRecord.terminal !== 1 || closedRecord.terminalKind !== 'NORMAL_CLOSE') {
    throw new Error('definitive CLOSE request did not normal-close exactly')
  }
  await rejects(() => client.retryPersistedForwardHttpsOriginV3(database, 'session-close', async () => openTarget), /terminal/)

  body.textContent = 'stage:transport-loss-restart'
  let capturedResult = null
  await rejects(() => client.fetchPersistedForwardHttpsOriginV3(database, input('session-crash', openOrigin), async exact => {
    const persisted = await client.loadForwardHttpsSessionV3(database, 'session-crash')
    if (persisted.outstandingState !== 2 || !equal(exact, openOrigin)) throw new Error('transport-loss request was not AWAITING')
    capturedResult = new Uint8Array(openTarget)
    throw new Error('simulated transport loss after exact ID77 capture')
  }), /transport loss/)
  database.close()
  database = await client.openForwardHttpsIndexedDbV3(databaseName)
  let crashRetryBytes = null
  const crashRecovered = await client.retryPersistedForwardHttpsOriginV3(database, 'session-crash', async exact => {
    crashRetryBytes = new Uint8Array(exact)
    return capturedResult
  })
  if (!equal(crashRetryBytes, openOrigin) || !crashRecovered.advanced) throw new Error('restart did not exact-retry and verify captured ID77')

  body.textContent = 'stage:conflict-terminal-evidence'
  await client.persistForwardHttpsOriginBeforeFetchV3(database, input('session-conflict', openOrigin))
  await rejects(() => client.persistForwardHttpsOriginBeforeFetchV3(database, input('session-conflict', vectors['close-origin.bin'])), /terminalized/)
  const conflict = await client.loadForwardHttpsSessionV3(database, 'session-conflict')
  if (conflict.terminalKind !== 'CORRECTNESS' || conflict.outstandingState !== 0 || conflict.outstandingOriginRequest.length !== 0 ||
      !equal(conflict.terminalEvidence.originRequest, openOrigin)) {
    throw new Error('outstanding conflict did not retain closed original evidence')
  }

  body.textContent = 'stage:malformed-and-store-key-recovery'
  await client.persistForwardHttpsOriginBeforeFetchV3(database, input('raw-source', openOrigin))
  const rawSource = await rawGet(database, 'raw-source')
  let forbiddenTransportCalls = 0
  const malformedCorpus = [
    ['noncanonical-u64', record => { record.nextSequence = '01' }],
    ['negative-u64', record => { record.nextSequence = '-1' }],
    ['overflow-u64', record => { record.nextSequence = '18446744073709551616' }],
    ['outstanding-enum', record => { record.outstandingState = 9 }],
    ['terminal-enum', record => { record.terminalKind = 'CALLER_ASSERTED' }],
    ['terminal-outstanding', record => { record.terminal = 1; record.terminalKind = 'NORMAL_CLOSE' }],
    ['chain-zero-rule', record => { record.previousTargetResultHash = new Uint8Array(32).fill(0xd1) }],
    ['request-commitment', record => { record.outstandingOriginRequestCommitment[0] ^= 1 }],
    ['request-canonicality', record => { record.outstandingOriginRequest[0] ^= 1 }],
    ['request-session-metadata', record => { record.stableSessionId[0] ^= 1 }],
    ['endpoint-wire-abi', record => { record.verifiedEndpoint.wireV3AbiHash[0] ^= 1 }],
    ['sequence-zero-target-fin', record => { record.targetFin = true }]
  ]
  for (const [name, mutate] of malformedCorpus) {
    const key = 'raw-malformed-' + name
    const malformed = structuredClone(rawSource)
    malformed.sessionKey = key
    mutate(malformed)
    await rawPut(database, key, malformed)
    const before = await rawGet(database, key)
    await rejects(() => client.retryPersistedForwardHttpsOriginV3(database, key, async () => {
      forbiddenTransportCalls++
      return openTarget
    }))
    const after = await rawGet(database, key)
    if (!deepEqual(before, after)) throw new Error('malformed recovery mutated raw state: ' + name)
  }
  if (forbiddenTransportCalls !== 0) {
    throw new Error('malformed recovery corpus reached transport')
  }

  const advancedWrongChain = structuredClone(recoveredRecord)
  advancedWrongChain.sessionKey = 'raw-advanced-wrong-chain'
  advancedWrongChain.previousTargetResultHash[0] ^= 1
  await rawPut(database, 'raw-advanced-wrong-chain', advancedWrongChain)
  const advancedWrongChainBefore = await rawGet(database, 'raw-advanced-wrong-chain')
  await rejects(() => client.retryPersistedForwardHttpsOriginV3(database, 'raw-advanced-wrong-chain', async () => {
    forbiddenTransportCalls++
    return openTarget
  }), /target-result chain/)
  const advancedWrongChainAfter = await rawGet(database, 'raw-advanced-wrong-chain')
  if (forbiddenTransportCalls !== 0 || !deepEqual(advancedWrongChainBefore, advancedWrongChainAfter)) {
    throw new Error('isolated advanced wrong-chain recovery mutated or reached transport')
  }

  const moved = structuredClone(rawSource)
  await rawPut(database, 'raw-moved', moved)
  await rejects(() => client.retryPersistedForwardHttpsOriginV3(database, 'raw-moved', async () => {
    forbiddenTransportCalls++
    return openTarget
  }), /object-store key/)
  const movedAfter = await rawGet(database, 'raw-moved')
  if (forbiddenTransportCalls !== 0 || movedAfter.sessionKey !== 'raw-source' || movedAfter.outstandingState !== 1) {
    throw new Error('moved record reached transport or mutated')
  }

  const badEndpoint = structuredClone(rawSource)
  badEndpoint.sessionKey = 'raw-bad-endpoint'
  badEndpoint.verifiedEndpoint.targetRelayPublicKey = new Uint8Array(32).fill(0xee)
  await rawPut(database, 'raw-bad-endpoint', badEndpoint)
  await rejects(() => client.retryPersistedForwardHttpsOriginV3(database, 'raw-bad-endpoint', async () => {
    forbiddenTransportCalls++
    return openTarget
  }), /verified endpoint|verifiedEndpoint/)
  if (forbiddenTransportCalls !== 0) throw new Error('bad full ID9 authority reached transport')

  body.textContent = 'stage:advanced-recovery-forgery'
  const forgedClose = structuredClone(recoveredRecord)
  forgedClose.sessionKey = 'raw-forged-close'
  forgedClose.terminal = 1
  forgedClose.terminalKind = 'NORMAL_CLOSE'
  await rawPut(database, 'raw-forged-close', forgedClose)
  await rejects(() => client.loadForwardHttpsSessionV3(database, 'raw-forged-close'), /iff|normal-close/)
  const forgedPrefix = structuredClone(recoveredRecord)
  forgedPrefix.sessionKey = 'raw-forged-prefix'
  forgedPrefix.capabilityPrefixHash = new Uint8Array(32).fill(0xef)
  await rawPut(database, 'raw-forged-prefix', forgedPrefix)
  await rejects(() => client.loadForwardHttpsSessionV3(database, 'raw-forged-prefix'), /prefix|chain/)

  await rejects(() => client.commitVerifiedForwardHttpsResultV3(database, {
    sessionKey: 'raw-source', provenanceVerified: true, resultRole: 1, resultBytes: openTarget
  }), /sessionKey/)

  body.textContent = 'stage:cleanup'
  database.close()
  await new Promise((resolve, reject) => {
    const request = indexedDB.deleteDatabase(databaseName)
    request.onsuccess = () => resolve()
    request.onerror = () => reject(request.error)
  })
  body.dataset.status = 'pass'
  body.textContent = JSON.stringify({
    ok: true,
    awaitingBeforeTransport: true,
    exactRetry: true,
    transportLossRecovery: true,
    atomicAdvance: true,
    sourceNoAdvance: true,
    targetFinNotNormalClose: true,
    closedTerminalEvidence: true,
    malformedZeroTransport: true,
    storeKeyBound: true,
    fullId9RecoveryAuthority: true
  })
  await fetch('/result?status=pass')
} catch (error) {
  body.dataset.status = 'fail'
  body.textContent = JSON.stringify({ ok: false, message: error && error.message ? error.message : String(error) })
  await fetch('/result?status=fail&message=' + encodeURIComponent(error && error.message ? error.message : String(error)))
}
</script>`
}

async function listen (artifacts, html) {
  let settle
  const completion = new Promise(resolve => { settle = resolve })
  const server = createServer((request, response) => {
    response.setHeader('Cache-Control', 'no-store')
    response.setHeader('X-Content-Type-Options', 'nosniff')
    if (artifacts.has(request.url)) {
      const bytes = artifacts.get(request.url)
      response.statusCode = 200
      response.setHeader('Content-Type', 'text/javascript; charset=utf-8')
      response.setHeader('Content-Length', String(bytes.byteLength))
      response.end(bytes)
      return
    }
    if (request.url === '/') {
      const bytes = b4a.from(html)
      response.statusCode = 200
      response.setHeader('Content-Type', 'text/html; charset=utf-8')
      response.setHeader('Content-Length', String(bytes.byteLength))
      response.end(bytes)
      return
    }
    if (request.url.startsWith('/result?')) {
      const result = new URL(request.url, 'http://127.0.0.1')
      response.statusCode = 204
      response.end()
      settle({ status: result.searchParams.get('status'), message: result.searchParams.get('message') })
      return
    }
    response.statusCode = 404
    response.end()
  })
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  return { server, completion }
}

const [v1, v2, v3, manifestBytes, closureBytes, chromium] = await Promise.all([
  fs.readFile(path.join(artifactRoot, 'blind-client-control-v1.mjs')),
  fs.readFile(path.join(artifactRoot, 'blind-client-control-v2.mjs')),
  fs.readFile(path.join(artifactRoot, 'blind-client-control-v3.mjs')),
  fs.readFile(path.join(artifactRoot, 'blind-client-control-v3.manifest.cenc')),
  fs.readFile(path.join(artifactRoot, 'blind-client-control-v3.source-closure.json')),
  findChromium()
])
verifyBlindClientBrowserArtifactV3(v3, manifestBytes, closureBytes)
const manifest = decodeBlindClientBrowserArtifactManifestV3(manifestBytes)
const fixture = await browserFixture(b4a.toString(manifest.wireV3AbiHash, 'hex'))
const listening = await listen(new Map([
  ['/blind-client-control-v1.mjs', v1],
  ['/blind-client-control-v2.mjs', v2],
  ['/blind-client-control-v3.mjs', v3]
]), page(fixture))
const { server, completion } = listening
const address = server.address()
const profile = await fs.mkdtemp(path.join(os.tmpdir(), 'hiverelay-v3-browser-gate-'))
try {
  const version = (await execute(chromium, ['--version'], {
    encoding: 'utf8', timeout: 10_000, killSignal: 'SIGKILL', maxBuffer: 1024 * 1024
  })).stdout.trim()
  const headlessFlag = path.basename(chromium).includes('headless-shell') ? '--headless' : '--headless=new'
  const child = spawn(chromium, [
    headlessFlag,
    '--disable-background-networking',
    '--disable-component-update',
    '--disable-default-apps',
    '--disable-extensions',
    '--disable-sync',
    '--metrics-recording-only',
    '--no-first-run',
    `--user-data-dir=${profile}`,
    `http://127.0.0.1:${address.port}/`
  ], { stdio: ['ignore', 'ignore', 'pipe'] })
  let stderr = ''
  child.stderr.setEncoding('utf8')
  child.stderr.on('data', chunk => { stderr += chunk })
  const earlyExit = new Promise(resolve => child.once('exit', (code, signal) => resolve({ status: 'exit', message: `code=${code} signal=${signal}` })))
  let timeoutId
  const timeout = new Promise(resolve => {
    timeoutId = setTimeout(() => resolve({ status: 'timeout', message: 'browser gate timed out' }), 60_000)
  })
  const result = await Promise.race([completion, earlyExit, timeout])
  clearTimeout(timeoutId)
  if (!child.killed) child.kill('SIGKILL')
  if (child.exitCode == null && child.signalCode == null) await earlyExit
  if (result.status !== 'pass') {
    throw new Error(`real Chromium did not pass browser v3 IndexedDB gate: ${JSON.stringify(result)}\n${stderr}`)
  }
  process.stdout.write(`${JSON.stringify({
    schema: 'HiveRelayBlindClientBrowserArtifactChromiumGateV3',
    chromium: version,
    manifestBytes: manifestBytes.byteLength,
    wireV3AbiHash: b4a.toString(manifest.wireV3AbiHash, 'hex'),
    checks: [
      'AWAITING_BEFORE_TRANSPORT',
      'VERIFIED_WRAPPER_OUTCOME',
      'RESTART_EXACT_RETRY',
      'TRANSPORT_LOSS_REOPEN_RETRY',
      'RECOVERY_ONLY_STATE1_COMMIT',
      'ATOMIC_TARGET_ADVANCE',
      'SOURCE_RESULT_NO_ADVANCE',
      'TARGET_FIN_NOT_NORMAL_CLOSE',
      'NORMAL_CLOSE_REQUEST_ONLY',
      'CONFLICT_TERMINAL_EVIDENCE',
      'MALFORMED_ZERO_TRANSPORT',
      'INDEXEDDB_STORE_KEY_BOUND',
      'FULL_ID9_RECOVERY_AUTHORITY'
    ],
    ok: true
  })}\n`)
} finally {
  await new Promise(resolve => server.close(resolve))
  await fs.rm(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 })
}
