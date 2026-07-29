#!/usr/bin/env node
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import process from 'node:process'
import { execFile } from 'node:child_process'
import { createServer } from 'node:http'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'
import b4a from 'b4a'
import {
  hashAbi,
  hashClientCompositionFormat,
  hashClientCompositionVectorSet,
  hashSpec,
  hashVectorSet
} from '@hiverelay/blind-protocol/hashes'
import {
  BLIND_CLIENT_BROWSER_ARTIFACT_STATUS,
  BLIND_CLIENT_CELL_GET_BROWSER_ARTIFACT_STATUS,
  hashBlindClientBrowserArtifactManifest,
  verifyBlindClientBrowserArtifactV1
} from '@hiverelay/blind-client/browser-artifact'

const execute = promisify(execFile)
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const cellGetOnly = process.argv.includes('--cell-get-only')
const unknownArguments = process.argv.slice(2).filter(argument => argument !== '--cell-get-only')
if (unknownArguments.length > 0) {
  throw new Error(`unknown Chromium gate argument: ${unknownArguments.join(', ')}`)
}
const artifactStatus = cellGetOnly
  ? BLIND_CLIENT_CELL_GET_BROWSER_ARTIFACT_STATUS
  : BLIND_CLIENT_BROWSER_ARTIFACT_STATUS
const artifactFile = path.join(
  root, 'packages/blind-client', artifactStatus.artifactPath)
const manifestFile = path.join(
  root, 'packages/blind-client', artifactStatus.manifestPath)
const evidenceFile = path.join(
  root, 'packages/blind-client', artifactStatus.chromiumEvidencePath)
const broadEvidenceChecks = Object.freeze([
  'STANDALONE_ESM_IMPORT',
  'REQUIRED_CONTROL_EXPORTS',
  'CLOSED_EXTERNAL_PROFILE_DECODER',
  'WEBCRYPTO_AES_256_GCM_ROUNDTRIP',
  'SIGNED_CAPABILITY_CELL_COMPOSITION',
  'PLAINTEXT_SENTINEL_ABSENT_FROM_REQUEST'
])
const cellGetEvidenceChecks = Object.freeze([
  'STANDALONE_ESM_IMPORT',
  'EXACT_CELL_GET_ONLY_EXPORTS',
  'WEBCRYPTO_AES_256_GCM_ROUNDTRIP',
  'FIXED_CELL_GET_OPERATION_BOUNDARY',
  'FORWARD_CANDIDATE_CODE_ABSENT'
])
const evidenceChecks = cellGetOnly ? cellGetEvidenceChecks : broadEvidenceChecks
const cellGetOnlyExports = Object.freeze([
  'createBlindCellGetControl',
  'createBrowserCryptoRuntime'
])

async function writeAtomic (file, bytes) {
  const temporary = `${file}.${process.pid}.tmp`
  try {
    await fs.writeFile(temporary, bytes, { mode: 0o644 })
    await fs.rename(temporary, file)
  } finally {
    await fs.rm(temporary, { force: true })
  }
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
  const cache = process.env.PLAYWRIGHT_BROWSERS_PATH ||
    path.join(os.homedir(), 'Library/Caches/ms-playwright')
  let names
  try { names = await fs.readdir(cache) } catch { return [] }
  const newestFirst = values => values.sort((left, right) =>
    right.localeCompare(left, 'en', { numeric: true }))
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

async function exactTuple () {
  const [spec, abi, vectors, composition, compositionVectors] = await Promise.all([
    fs.readFile(path.join(root, 'docs/protocol/HIVERELAY-BLIND-WIRE-V1.md')),
    fs.readFile(path.join(root, 'packages/blind-protocol/hiverelay-blind-abi-v1.cenc')),
    fs.readFile(path.join(root, 'packages/blind-protocol/vector-manifest-v1.cenc')),
    fs.readFile(path.join(root,
      'packages/blind-protocol/hiverelay-blind-client-composition-format-v1.cenc')),
    fs.readFile(path.join(root,
      'packages/blind-protocol/hiverelay-blind-client-composition-vector-manifest-v1.cenc'))
  ])
  return Object.freeze({
    specHash: hashSpec(spec),
    abiHash: hashAbi(abi),
    vectorSetHash: hashVectorSet(vectors),
    clientCompositionFormatHash: hashClientCompositionFormat(composition),
    clientCompositionVectorSetHash: hashClientCompositionVectorSet(compositionVectors)
  })
}

function broadPage (manifestHash) {
  return `<!doctype html>
<meta charset="utf-8">
<title>HiveRelay blind client real-browser gate</title>
<body data-status="running">running</body>
<script type="module">
const body = document.body
const fail = message => {
  body.dataset.status = 'fail'
  body.textContent = JSON.stringify({ ok: false, message })
}
try {
  const client = await import('/blind-client-control-v1.mjs')
  const required = [
    'BlindDescriptorBootstrapHttpClient',
    'BlindDirectHttpClient',
    'DescriptorTrustStore',
    'createBrowserCryptoRuntime',
    'createCellReplica',
    'decodeBlindExternalProfileValueV1',
    'verifyOperationResult'
  ]
  for (const name of required) {
    if (typeof client[name] !== 'function') throw new Error('missing export ' + name)
  }
  const readCap = new Uint8Array(131)
  readCap[0] = 1
  readCap.fill(0x41, 1, 33)
  readCap.fill(0x42, 33, 65)
  readCap.fill(0x43, 65, 97)
  readCap[97] = 1
  readCap[98] = 1
  readCap.fill(0x44, 99)
  const decodedReadCap = client.decodeBlindExternalProfileValueV1('ReadCellCapV1', readCap)
  if (decodedReadCap.sizeClass !== 1 || decodedReadCap.relayPublicKey[0] !== 0x41) {
    throw new Error('closed external-profile decoder failed its canonical browser vector')
  }
  let unknownRejected = false
  try {
    client.decodeBlindExternalProfileValueV1('WriteCellCapV1', readCap)
  } catch (error) {
    unknownRejected = error && error.code === 'BAD_ENCODING'
  }
  if (!unknownRejected) throw new Error('closed external-profile decoder accepted an unknown type')
  const runtime = client.createBrowserCryptoRuntime(globalThis.crypto)
  const key = new Uint8Array(32).fill(0x21)
  const nonce = new Uint8Array(12).fill(0x22)
  const aad = new TextEncoder().encode('hiverelay-browser-artifact-gate-v1')
  const plaintext = new TextEncoder().encode('browser-webcrypto-roundtrip')
  const sealed = await runtime.aes256GcmEncrypt({ key, nonce, aad, plaintext })
  const opened = await runtime.aes256GcmDecrypt({ key, nonce, aad, sealed })
  if (opened.length !== plaintext.length ||
      !opened.every((value, index) => value === plaintext[index])) {
    throw new Error('browser AES-GCM round trip failed')
  }
  const sentinel = new TextEncoder().encode('BROWSER_CLIENT_PRIVATE_SENTINEL_4bd7700e')
  const created = await client.createCellReplica({
    runtime,
    relayPublicKey: new Uint8Array(32).fill(0x31),
    allocationEpoch: 300,
    sizeClass: 1,
    leaseClass: 1,
    structuredContent: sentinel,
    admission: {
      profileId: 1,
      schemeId: 1,
      parameterHash: new Uint8Array(32).fill(0x32),
      token: new Uint8Array([0x33])
    }
  })
  if (created.requestBytes.length === 0 || created.request.createSignature.length !== 64 ||
      created.request.cellBlob.length !== 4096) {
    throw new Error('browser client-composition execution failed')
  }
  const requestHex = [...created.requestBytes]
    .map(value => value.toString(16).padStart(2, '0')).join('')
  const sentinelHex = [...sentinel]
    .map(value => value.toString(16).padStart(2, '0')).join('')
  if (requestHex.includes(sentinelHex)) throw new Error('private sentinel leaked into relay bytes')
  body.dataset.status = 'pass'
  body.textContent = JSON.stringify({
    ok: true,
    manifestHash: '${manifestHash}',
    exportCount: required.length,
    requestBytes: created.requestBytes.length,
    cellBytes: created.request.cellBlob.length
  })
} catch (error) {
  fail(error && error.message ? error.message : String(error))
}
</script>`
}

function cellGetPage (manifestHash) {
  const artifactName = path.posix.basename(artifactStatus.artifactPath)
  return `<!doctype html>
<meta charset="utf-8">
<title>HiveRelay blind Cell-GET client real-browser gate</title>
<body data-status="running">running</body>
<script type="module">
const body = document.body
const fail = message => {
  body.dataset.status = 'fail'
  body.textContent = JSON.stringify({ ok: false, message })
}
try {
  const client = await import('/${artifactName}')
  const expectedExports = ${JSON.stringify(cellGetOnlyExports)}
  const actualExports = Object.keys(client).sort()
  if (actualExports.length !== expectedExports.length ||
      actualExports.some((value, index) => value !== expectedExports[index])) {
    throw new Error('Cell-GET-only export set changed: ' + actualExports.join(','))
  }
  for (const name of expectedExports) {
    if (typeof client[name] !== 'function') throw new Error('invalid export ' + name)
  }
  const runtime = client.createBrowserCryptoRuntime(globalThis.crypto)
  const key = new Uint8Array(32).fill(0x21)
  const nonce = new Uint8Array(12).fill(0x22)
  const aad = new TextEncoder().encode('hiverelay-cell-get-browser-gate-v1')
  const plaintext = new TextEncoder().encode('browser-webcrypto-roundtrip')
  const sealed = await runtime.aes256GcmEncrypt({ key, nonce, aad, plaintext })
  const opened = await runtime.aes256GcmDecrypt({ key, nonce, aad, sealed })
  if (opened.length !== plaintext.length ||
      !opened.every((value, index) => value === plaintext[index])) {
    throw new Error('browser AES-GCM round trip failed')
  }
  const control = client.createBlindCellGetControl({
    runtime,
    nowEpoch: () => 300,
    supportedProtocolProfiles: [{
      protocolId: 1,
      major: 1,
      minimumMinor: 0,
      profileHash: new Uint8Array(32).fill(0x0a)
    }],
    supportedTransportProfiles: [{
      transportId: 1,
      transportSupportBit: 1,
      transportProfileHash: new Uint8Array(32).fill(0x0b)
    }],
    fetch: async () => { throw new Error('operation-selection rejection dialed the network') }
  })
  if (!Object.isFrozen(control) || Object.keys(control).length !== 0) {
    throw new Error('Cell-GET control leaked mutable transport state')
  }
  for (const attempt of [
    () => control.fetchDescriptorHead({ canonicalUrl: new Uint8Array([1]), familyId: 2 }),
    () => control.qualifyCellGetCandidate({}, { operationId: 1 }),
    () => control.readCell({ operationId: 1 })
  ]) {
    let rejected = false
    try { await attempt() } catch (error) {
      rejected = error && error.code === 'BAD_CLIENT_INPUT' &&
        error.message.includes('cannot select')
    }
    if (!rejected) throw new Error('Cell-GET boundary accepted caller-selected operation metadata')
  }
  body.dataset.status = 'pass'
  body.textContent = JSON.stringify({
    ok: true,
    manifestHash: '${manifestHash}',
    exportCount: actualExports.length,
    fixedOperationBoundary: true
  })
} catch (error) {
  fail(error && error.message ? error.message : String(error))
}
</script>`
}

async function listen (artifactBytes, html) {
  const server = createServer((request, response) => {
    response.setHeader('Cache-Control', 'no-store')
    response.setHeader('X-Content-Type-Options', 'nosniff')
    if (request.url === `/${path.posix.basename(artifactStatus.artifactPath)}`) {
      response.statusCode = 200
      response.setHeader('Content-Type', 'text/javascript; charset=utf-8')
      response.setHeader('Content-Length', String(artifactBytes.byteLength))
      response.end(artifactBytes)
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
    response.statusCode = 404
    response.end()
  })
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  return server
}

const [artifactBytes, manifestBytes, tuple, chromium] = await Promise.all([
  fs.readFile(artifactFile),
  fs.readFile(manifestFile),
  exactTuple(),
  findChromium()
])
const manifestHash = hashBlindClientBrowserArtifactManifest(manifestBytes)
const verified = verifyBlindClientBrowserArtifactV1({
  artifactBytes,
  manifestBytes,
  expectedManifestHash: manifestHash,
  expectedTuple: tuple
})
if (cellGetOnly) {
  const artifactText = b4a.toString(verified.artifactBytes, 'utf8')
  for (const token of [
    'BlindForwardRouteHopV1', 'BlindForwardRouteScopeV1',
    'acceptedRouteScopeHash', 'parentRouteScopeHash',
    'createCellReplica', 'createPutCellRequest', 'PutCellV1',
    'VerifiedOperationResult'
  ]) {
    if (artifactText.includes(token)) {
      throw new Error(`Cell-GET-only artifact contains forbidden candidate token: ${token}`)
    }
  }
}
const manifestHashHex = b4a.toString(manifestHash, 'hex')
const server = await listen(verified.artifactBytes,
  cellGetOnly ? cellGetPage(manifestHashHex) : broadPage(manifestHashHex))
const address = server.address()
const profile = await fs.mkdtemp(path.join(os.tmpdir(), 'hiverelay-browser-gate-'))
try {
  const version = (await execute(chromium, ['--version'], {
    encoding: 'utf8', timeout: 10_000, killSignal: 'SIGKILL', maxBuffer: 1024 * 1024
  })).stdout.trim()
  const headlessFlag = path.basename(chromium).includes('headless-shell')
    ? '--headless'
    : '--headless=new'
  const { stdout, stderr } = await execute(chromium, [
    headlessFlag,
    '--disable-background-networking',
    '--disable-component-update',
    '--disable-default-apps',
    '--disable-extensions',
    '--disable-sync',
    '--metrics-recording-only',
    '--no-first-run',
    `--user-data-dir=${profile}`,
    '--virtual-time-budget=10000',
    '--dump-dom',
    `http://127.0.0.1:${address.port}/`
  ], {
    encoding: 'utf8', timeout: 30_000, killSignal: 'SIGKILL', maxBuffer: 4 * 1024 * 1024
  })
  if (!stdout.includes('data-status="pass"') ||
      (!stdout.includes(`"manifestHash":"${manifestHashHex}"`) &&
       !stdout.includes(`&quot;manifestHash&quot;:&quot;${manifestHashHex}&quot;`))) {
    throw new Error(`real Chromium did not pass the checked artifact gate: ${stdout}\n${stderr}`)
  }
  const evidence = {
    schema: 'HiveRelayBlindClientBrowserArtifactChromiumEvidenceV1',
    version: 1,
    evidenceClass: 'real-chromium',
    artifactPath: artifactStatus.artifactPath,
    artifactLength: verified.artifactBytes.byteLength,
    artifactHash: b4a.toString(verified.manifest.artifactHash, 'hex'),
    manifestHash: manifestHashHex,
    sourceClosureHash: b4a.toString(verified.manifest.sourceClosureHash, 'hex'),
    chromium: version,
    checks: evidenceChecks,
    passed: true
  }
  await writeAtomic(evidenceFile, b4a.from(JSON.stringify(evidence, null, 2) + '\n'))
  process.stdout.write(`${JSON.stringify({
    schema: 'HiveRelayBlindClientBrowserArtifactChromiumGateV1',
    chromium: version,
    manifestHash: manifestHashHex,
    artifactBytes: verified.artifactBytes.byteLength,
    clientCompositionFormatHash: b4a.toString(tuple.clientCompositionFormatHash, 'hex'),
    clientCompositionVectorSetHash: b4a.toString(tuple.clientCompositionVectorSetHash, 'hex'),
    evidencePath: path.relative(root, evidenceFile).replaceAll(path.sep, '/'),
    ok: true
  })}\n`)
} finally {
  await new Promise(resolve => server.close(resolve))
  await fs.rm(profile, { recursive: true, force: true })
}
