#!/usr/bin/env node
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import process from 'node:process'
import { spawnSync } from 'node:child_process'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import { gzipSync } from 'node:zlib'
import b4a from 'b4a'
import { build } from 'esbuild'
import {
  blake2b256,
  hashAbi,
  hashClientCompositionFormat,
  hashClientCompositionVectorSet,
  hashSpec,
  hashVectorSet
} from '@hiverelay/blind-protocol/hashes'
import {
  BLIND_CLIENT_BROWSER_ARTIFACT_STATUS,
  BLIND_CLIENT_CELL_GET_BROWSER_ARTIFACT_STATUS,
  encodeBlindClientBrowserArtifactManifestV1,
  hashBlindClientBrowserArtifact,
  hashBlindClientBrowserArtifactManifest,
  hashBlindClientBrowserSourceClosure,
  verifyBlindClientBrowserArtifactReleaseEvidenceV1,
  verifyBlindClientBrowserArtifactV1
} from '@hiverelay/blind-client/browser-artifact'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const require = createRequire(import.meta.url)
const esbuildVersion = require('esbuild/package.json').version
const check = process.argv.includes('--check')
const requireReleaseEvidence = process.argv.includes('--require-release-evidence')
const cellGetOnly = process.argv.includes('--cell-get-only')
const allowedArguments = new Set(['--check', '--require-release-evidence', '--cell-get-only'])
const unknownArguments = process.argv.slice(2).filter(argument => !allowedArguments.has(argument))
if (unknownArguments.length > 0) {
  throw new Error(`unknown browser artifact generator argument: ${unknownArguments.join(', ')}`)
}
const artifactStatus = cellGetOnly
  ? BLIND_CLIENT_CELL_GET_BROWSER_ARTIFACT_STATUS
  : BLIND_CLIENT_BROWSER_ARTIFACT_STATUS
const artifactRelative = path.posix.join(
  'packages/blind-client', artifactStatus.artifactPath)
const manifestRelative = path.posix.join(
  'packages/blind-client', artifactStatus.manifestPath)
const cellGetOnlyExports = Object.freeze([
  'createBlindCellGetControl',
  'createBrowserCryptoRuntime'
])
const entrySource = cellGetOnly
  ? [
      'export {',
      ...cellGetOnlyExports.map(name => `  ${name},`),
      "} from './packages/blind-client/cell-get-control.js'",
      ''
    ].join('\n')
  : [
      "export * from './packages/blind-client/control.js'",
      "export { createBrowserCryptoRuntime } from './packages/blind-client/runtime/browser.js'",
      ''
    ].join('\n')
const browserTarget = 'es2020'
const buildProfile = cellGetOnly
  ? 'esbuild;bundle=true;platform=browser;format=esm;target=es2020;minify=true;sourcemap=false;charset=utf8;legalComments=none;surface=cell-get-only-v1'
  : 'esbuild;bundle=true;platform=browser;format=esm;target=es2020;minify=true;sourcemap=false;charset=utf8;legalComments=none'
const virtualEntryPath = cellGetOnly
  ? 'blind-client-cell-get-browser-entry.mjs'
  : 'blind-client-control-browser-entry.mjs'
const allowedDisabledInput = '(disabled):crypto'
const generatorRelative = 'scripts/generate-blind-client-browser-artifacts.mjs'
const fixedAuthorityPaths = Object.freeze([
  'package.json',
  'package-lock.json',
  generatorRelative,
  'scripts/generate-blind-protocol-draft.mjs',
  'scripts/verify-blind-published-wire-v1.mjs',
  'scripts/lib/blind-published-wire-v1.mjs',
  'scripts/generate-blind-client-composition-authority.mjs',
  'docs/protocol/HIVERELAY-BLIND-WIRE-V1.md',
  'docs/protocol/BLIND-APP-AGNOSTIC-HIVERELAY-MASTER-SPEC.md',
  'docs/protocol/HIVERELAY-BLIND-CLIENT-COMPOSITION-V1.md',
  'packages/blind-client/browser-artifact.js',
  'packages/blind-client/crypto.js',
  'packages/blind-protocol/codec.js',
  'packages/blind-protocol/crypto.js',
  'packages/blind-protocol/errors.js',
  'packages/blind-protocol/hashes.js',
  'packages/blind-protocol/master-schema-inventory.js',
  'packages/blind-protocol/package.json',
  'packages/blind-protocol/registry.js',
  'packages/blind-protocol/schema-meta.js',
  'packages/blind-protocol/schema-catalog-runtime-authority.js',
  'packages/blind-protocol/wire-runtime-authority.js',
  'packages/blind-protocol/hiverelay-blind-wire-authority-v1.json',
  'packages/blind-protocol/hiverelay-blind-abi-v1.cenc',
  'packages/blind-protocol/vector-manifest-v1.cenc',
  'packages/blind-protocol/hiverelay-blind-client-composition-authority-v1.json',
  'packages/blind-protocol/hiverelay-blind-client-composition-format-v1.cenc',
  'packages/blind-protocol/hiverelay-blind-client-composition-schema-catalog-v1.cenc',
  'packages/blind-protocol/hiverelay-blind-client-composition-vector-manifest-v1.cenc',
  'node_modules/esbuild/package.json'
])
const forbiddenArtifactTokens = Object.freeze([
  'INTERNAL_STORE',
  'CLIENT_EXAMPLE',
  'BlindStoreManifestV1',
  'BlindBackupManifestV1',
  'Peerit',
  'OutboxLog',
  'BlindShard',
  'EXECUTABLE_SCHEMA_CODECS'
])
const cellGetOnlyForbiddenArtifactTokens = Object.freeze([
  'BlindForwardRouteHopV1',
  'BlindForwardRouteScopeV1',
  'acceptedRouteScopeHash',
  'parentRouteScopeHash',
  'createCellReplica',
  'createPutCellRequest',
  'PutCellV1',
  'VerifiedOperationResult'
])
const cellGetOnlyForbiddenGraphInputs = Object.freeze([
  'packages/blind-client/control.js',
  'packages/blind-client/requests.js',
  'packages/blind-client/results.js',
  'packages/blind-client/attempt.js',
  'packages/blind-client/forward.js'
])

function u16 (value) {
  return b4a.from([(value >>> 8) & 0xff, value & 0xff])
}

function u32 (value) {
  return b4a.from([
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff
  ])
}

function u64 (value) {
  value = BigInt(value)
  const output = b4a.alloc(8)
  for (let index = 7; index >= 0; index--) {
    output[index] = Number(value & 0xffn)
    value >>= 8n
  }
  return output
}

function normalizeGraphPath (rawPath) {
  const normalized = rawPath.replaceAll('\\', '/')
  if (normalized.length === 0 || normalized.includes('\0') ||
      normalized.startsWith('/') || /^[A-Za-z]:\//.test(normalized) ||
      normalized === '..' || normalized.startsWith('../') || normalized.includes('/../')) {
    throw new Error(`browser artifact graph path is not root-relative: ${rawPath}`)
  }
  return normalized
}

function absoluteFromRelative (relative) {
  return path.resolve(root, ...relative.split('/'))
}

async function maybeAddFile (entries, relative) {
  if (entries.has(relative)) return
  let content
  try {
    content = await fs.readFile(absoluteFromRelative(relative))
  } catch (error) {
    if (error && error.code === 'ENOENT') return
    throw error
  }
  entries.set(relative, b4a.from(content))
}

async function sourceSnapshot (metafile) {
  const graphInputs = new Set()
  const entries = new Map()
  for (const rawPath of Object.keys(metafile.inputs)) {
    const normalized = normalizeGraphPath(rawPath)
    graphInputs.add(normalized)
    if (normalized === virtualEntryPath) {
      entries.set(normalized, b4a.from(entrySource))
      continue
    }
    if (normalized.startsWith('(disabled):')) {
      if (normalized !== allowedDisabledInput) {
        throw new Error(`browser artifact contains an unapproved disabled input: ${normalized}`)
      }
      entries.set(normalized, b4a.from(`esbuild-disabled-module-v1:${normalized}`, 'utf8'))
      continue
    }
    await maybeAddFile(entries, normalized)
    if (!entries.has(normalized)) {
      throw new Error(`browser artifact source input disappeared: ${normalized}`)
    }
    let directory = path.posix.dirname(normalized)
    while (directory !== '.') {
      await maybeAddFile(entries, path.posix.join(directory, 'package.json'))
      const parent = path.posix.dirname(directory)
      if (parent === directory) break
      directory = parent
    }
  }
  for (const relative of fixedAuthorityPaths) {
    await maybeAddFile(entries, relative)
    if (!entries.has(relative)) {
      throw new Error(`browser artifact build authority is missing: ${relative}`)
    }
  }
  return Object.freeze({ entries, graphInputs })
}

function sourceClosureBytes (snapshot) {
  const entries = [...snapshot.entries].map(([entryPath, content]) => ({
    path: entryPath,
    content
  }))
  entries.sort((left, right) => b4a.compare(b4a.from(left.path), b4a.from(right.path)))
  const chunks = [u32(entries.length)]
  for (const entry of entries) {
    const pathBytes = b4a.from(entry.path)
    if (pathBytes.byteLength < 1 || pathBytes.byteLength > 0xffff) {
      throw new Error(`browser artifact source path is outside u16: ${entry.path}`)
    }
    chunks.push(u16(pathBytes.byteLength), pathBytes, u64(entry.content.byteLength), blake2b256(entry.content))
  }
  return b4a.concat(chunks)
}

function loaderFor (absolute) {
  switch (path.extname(absolute)) {
    case '.js':
    case '.mjs':
    case '.cjs': return 'js'
    case '.json': return 'json'
    default: throw new Error(`browser artifact source has no frozen loader: ${absolute}`)
  }
}

function frozenSourcePlugin (snapshot) {
  return {
    name: 'hiverelay-frozen-browser-source-closure',
    setup (builder) {
      builder.onLoad({ filter: /.*/, namespace: 'file' }, args => {
        const relative = normalizeGraphPath(path.relative(root, args.path))
        if (!snapshot.graphInputs.has(relative)) {
          throw new Error(`browser artifact build requested an unsnapshotted input: ${relative}`)
        }
        const contents = snapshot.entries.get(relative)
        if (contents == null) {
          throw new Error(`browser artifact snapshot is missing graph input: ${relative}`)
        }
        return {
          contents,
          loader: loaderFor(args.path),
          resolveDir: path.dirname(args.path)
        }
      })
    }
  }
}

function assertSameGraph (metafile, snapshot) {
  const actual = [...Object.keys(metafile.inputs)].map(normalizeGraphPath).sort()
  const expected = [...snapshot.graphInputs].sort()
  if (actual.length !== expected.length || actual.some((value, index) => value !== expected[index])) {
    throw new Error('frozen browser artifact build changed its resolved source graph')
  }
}

function assertClosedBrowserGraph (metafile) {
  const inputs = Object.keys(metafile.inputs).map(normalizeGraphPath)
  const forbidden = inputs.filter(input =>
    /(^|\/)node_modules\/(?:sodium-native|bare-crypto)(?:\/|$)/.test(input) ||
    input.includes('node:') || input.endsWith('.node') ||
    input.endsWith('packages/blind-protocol/index.js') ||
    input.endsWith('packages/blind-protocol/registry.js') ||
    input.endsWith('packages/blind-protocol/extended-schema-metadata.js') ||
    input.endsWith('packages/blind-protocol/evidence-schemas.js') ||
    input.endsWith('packages/blind-protocol/durability-schemas.js') ||
    input.endsWith('packages/blind-protocol/client-internal-schemas.js') ||
    input.endsWith('packages/blind-protocol/client-composition-authority.js') ||
    input.endsWith('packages/blind-protocol/client-composition-runtime-vectors.js') ||
    input.endsWith('packages/blind-protocol/schema-codecs.js') ||
    input.endsWith('packages/blind-protocol/master-schema-inventory.js') ||
    input.endsWith('packages/blind-protocol/schema-meta.js') ||
    input.endsWith('packages/blind-protocol/abi-registry.js'))
  if (forbidden.length > 0) {
    throw new Error(`browser artifact contains forbidden native/server inputs: ${forbidden.join(', ')}`)
  }
  if (cellGetOnly) {
    const forbiddenCellGetInputs = inputs.filter(input =>
      cellGetOnlyForbiddenGraphInputs.some(relative => input.endsWith(relative)))
    if (forbiddenCellGetInputs.length > 0) {
      throw new Error(`Cell-GET-only browser artifact contains a broad client input: ${forbiddenCellGetInputs.join(', ')}`)
    }
  }
  const unusedSodiumInputs = inputs.filter(input =>
    input.endsWith('node_modules/sodium-javascript/index.js') ||
    /node_modules\/sodium-javascript\/crypto_(?:aead|auth|box|hash_sha256|kdf|kx|onetimeauth|secretbox|secretstream|shorthash|stream(?:_chacha20)?)\.js$/.test(input) ||
    /node_modules\/(?:chacha20-universal|sha256-universal|sha256-wasm|siphash24|xsalsa20)\//.test(input))
  if (unusedSodiumInputs.length > 0) {
    throw new Error(`browser artifact contains unused sodium inputs: ${unusedSodiumInputs.join(', ')}`)
  }
  const disabled = inputs.filter(input => input.startsWith('(disabled):'))
  if (disabled.length !== 1 || disabled[0] !== allowedDisabledInput) {
    throw new Error(`browser artifact disabled inputs changed: ${disabled.join(', ')}`)
  }
  const disabledImporters = []
  const externalRuntimeImports = []
  for (const [rawInput, metadata] of Object.entries(metafile.inputs)) {
    const input = normalizeGraphPath(rawInput)
    for (const imported of metadata.imports || []) {
      if (imported.path.startsWith('(disabled):')) {
        disabledImporters.push({ input, ...imported })
      }
      if (imported.external) externalRuntimeImports.push({ input, ...imported })
    }
  }
  if (disabledImporters.length !== 1 ||
      disabledImporters[0].input !== 'node_modules/sodium-javascript/randombytes.js' ||
      disabledImporters[0].path !== allowedDisabledInput ||
      disabledImporters[0].kind !== 'require-call' || disabledImporters[0].original !== 'crypto') {
    throw new Error('browser artifact disabled-module edge is not the exact audited sodium browser fallback')
  }
  if (externalRuntimeImports.length !== 1 ||
      externalRuntimeImports[0].input !== 'node_modules/sodium-javascript/randombytes.js' ||
      externalRuntimeImports[0].path !== '<runtime>' ||
      externalRuntimeImports[0].kind !== 'import-statement') {
    throw new Error('browser artifact contains an unaudited external or dynamic runtime import')
  }
  const outputImports = Object.values(metafile.outputs)
    .flatMap(output => output.imports || [])
  if (outputImports.length !== 0) {
    throw new Error(`browser artifact output is not standalone: ${JSON.stringify(outputImports)}`)
  }
}

function assertExactCellGetOnlyExports (metafile) {
  if (!cellGetOnly) return
  const outputs = Object.values(metafile.outputs)
  if (outputs.length !== 1) {
    throw new Error('Cell-GET-only browser artifact did not produce exactly one output')
  }
  const actual = [...(outputs[0].exports || [])].sort()
  const expected = [...cellGetOnlyExports].sort()
  if (actual.length !== expected.length ||
      actual.some((value, index) => value !== expected[index])) {
    throw new Error(`Cell-GET-only browser artifact exports changed: ${actual.join(', ')}`)
  }
}

async function buildOnce (output, snapshot = null) {
  const result = await build({
    absWorkingDir: root,
    stdin: {
      contents: entrySource,
      resolveDir: root,
      sourcefile: virtualEntryPath,
      loader: 'js'
    },
    bundle: true,
    platform: 'browser',
    format: 'esm',
    target: browserTarget,
    minify: true,
    sourcemap: false,
    charset: 'utf8',
    legalComments: 'none',
    metafile: true,
    outfile: output,
    logLevel: 'silent',
    plugins: snapshot == null ? [] : [frozenSourcePlugin(snapshot)]
  })
  assertClosedBrowserGraph(result.metafile)
  assertExactCellGetOnlyExports(result.metafile)
  if (snapshot != null) assertSameGraph(result.metafile, snapshot)
  const artifactBytes = await fs.readFile(output)
  const artifactText = b4a.toString(artifactBytes, 'utf8')
  const prohibitedTokens = cellGetOnly
    ? [...forbiddenArtifactTokens, ...cellGetOnlyForbiddenArtifactTokens]
    : forbiddenArtifactTokens
  const leakedTokens = prohibitedTokens.filter(token =>
    artifactText.toLowerCase().includes(token.toLowerCase()))
  if (leakedTokens.length > 0) {
    throw new Error(`browser artifact contains forbidden application/internal vocabulary: ${leakedTokens.join(', ')}`)
  }
  const artifactGzipBytes = gzipSync(artifactBytes).byteLength
  if (artifactBytes.byteLength < 1 ||
      artifactBytes.byteLength > artifactStatus.maxArtifactBytes) {
    throw new Error(`browser artifact exceeds its raw limit: ${artifactBytes.byteLength}`)
  }
  if (artifactGzipBytes > artifactStatus.maxArtifactGzipBytes) {
    throw new Error(`browser artifact exceeds its gzip limit: ${artifactGzipBytes}`)
  }
  return { artifactBytes, artifactGzipBytes, metafile: result.metafile }
}

function assertProtocolTupleCurrent () {
  const protocolGenerator = path.join(root, cellGetOnly
    ? 'scripts/verify-blind-published-wire-v1.mjs'
    : 'scripts/generate-blind-protocol-draft.mjs')
  const protocolArguments = cellGetOnly
    ? ['--check']
    : ['--wire-only', '--forbid-non-wire-fixtures', '--check']
  const verified = spawnSync(process.execPath, [
    protocolGenerator,
    ...protocolArguments
  ], {
    cwd: root,
    encoding: 'utf8',
    maxBuffer: 4 * 1024 * 1024
  })
  if (verified.status !== 0) {
    const detail = (verified.stderr || verified.stdout ||
      `protocol generator terminated with ${verified.signal || verified.status}`).trim()
    const authority = cellGetOnly ? 'published WIRE v1' : 'tuple'
    throw new Error(`browser artifact ${authority} authority is stale: ${detail}`)
  }
  const clientCompositionGenerator = path.join(
    root, 'scripts/generate-blind-client-composition-authority.mjs')
  const clientCompositionVerified = spawnSync(
    process.execPath,
    [clientCompositionGenerator, '--check'],
    { cwd: root, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 }
  )
  if (clientCompositionVerified.status !== 0) {
    const detail = (clientCompositionVerified.stderr || clientCompositionVerified.stdout ||
      `client-composition generator terminated with ${clientCompositionVerified.signal || clientCompositionVerified.status}`).trim()
    throw new Error(`browser artifact client-composition authority is stale: ${detail}`)
  }
}

async function currentTuple () {
  const [spec, abi, vectors, clientCompositionFormat, clientCompositionVectors] = await Promise.all([
    fs.readFile(path.join(root, 'docs/protocol/HIVERELAY-BLIND-WIRE-V1.md')),
    fs.readFile(path.join(root, 'packages/blind-protocol/hiverelay-blind-abi-v1.cenc')),
    fs.readFile(path.join(root, 'packages/blind-protocol/vector-manifest-v1.cenc')),
    fs.readFile(path.join(root, 'packages/blind-protocol/hiverelay-blind-client-composition-format-v1.cenc')),
    fs.readFile(path.join(root, 'packages/blind-protocol/hiverelay-blind-client-composition-vector-manifest-v1.cenc'))
  ])
  return Object.freeze({
    specHash: hashSpec(spec),
    abiHash: hashAbi(abi),
    vectorSetHash: hashVectorSet(vectors),
    clientCompositionFormatHash: hashClientCompositionFormat(clientCompositionFormat),
    clientCompositionVectorSetHash: hashClientCompositionVectorSet(clientCompositionVectors)
  })
}

async function compareOrWrite (relative, expected) {
  const absolute = path.join(root, relative)
  if (check) {
    let actual
    try { actual = await fs.readFile(absolute) } catch { throw new Error(`missing generated browser artifact: ${relative}`) }
    if (!b4a.equals(actual, expected)) throw new Error(`generated browser artifact drift: ${relative}`)
    return
  }
  await fs.mkdir(path.dirname(absolute), { recursive: true })
  const temporary = path.join(
    path.dirname(absolute), `.${path.basename(absolute)}.${process.pid}.tmp`)
  try {
    await fs.writeFile(temporary, expected, { mode: 0o644 })
    await fs.rename(temporary, absolute)
  } finally {
    await fs.rm(temporary, { force: true })
  }
}

async function releaseEvidenceStatus (artifactBytes, manifestBytes, tuple) {
  try {
    const [chromiumEvidenceBytes, crossHostEvidenceBytes] = await Promise.all([
      fs.readFile(path.join(root, 'packages/blind-client',
        artifactStatus.chromiumEvidencePath)),
      fs.readFile(path.join(root, 'packages/blind-client',
        artifactStatus.crossHostEvidencePath))
    ])
    return verifyBlindClientBrowserArtifactReleaseEvidenceV1({
      artifactBytes,
      manifestBytes,
      expectedManifestHash: hashBlindClientBrowserArtifactManifest(manifestBytes),
      expectedTuple: tuple,
      chromiumEvidenceBytes,
      crossHostEvidenceBytes
    })
  } catch {
    return artifactStatus
  }
}

assertProtocolTupleCurrent()
const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'hiverelay-blind-client-artifact-'))
try {
  const discovery = await buildOnce(path.join(directory, 'discovery.mjs'))
  const snapshot = await sourceSnapshot(discovery.metafile)
  const first = await buildOnce(path.join(directory, 'first.mjs'), snapshot)
  const second = await buildOnce(path.join(directory, 'second.mjs'), snapshot)
  if (!b4a.equals(discovery.artifactBytes, first.artifactBytes)) {
    throw new Error('browser artifact source changed while its frozen closure was captured')
  }
  if (!b4a.equals(first.artifactBytes, second.artifactBytes)) {
    throw new Error('two frozen browser artifact builds are not byte-identical')
  }
  const closure = sourceClosureBytes(snapshot)
  const tuple = await currentTuple()
  const manifestBytes = encodeBlindClientBrowserArtifactManifestV1({
    version: 1,
    draft: false,
    ...tuple,
    toolchain: `esbuild@${esbuildVersion}`,
    buildProfile,
    sourceClosureHash: hashBlindClientBrowserSourceClosure(closure),
    artifactPath: artifactStatus.artifactPath,
    artifactLength: BigInt(first.artifactBytes.byteLength),
    artifactHash: hashBlindClientBrowserArtifact(first.artifactBytes)
  })
  verifyBlindClientBrowserArtifactV1({
    manifestBytes,
    artifactBytes: first.artifactBytes,
    expectedTuple: tuple,
    expectedManifestHash: hashBlindClientBrowserArtifactManifest(manifestBytes)
  })
  await compareOrWrite(artifactRelative, first.artifactBytes)
  await compareOrWrite(manifestRelative, manifestBytes)
  const evidenceStatus = await releaseEvidenceStatus(first.artifactBytes, manifestBytes, tuple)
  if (requireReleaseEvidence && !evidenceStatus.releaseReady) {
    throw new Error(`browser artifact release evidence is incomplete: ${evidenceStatus.releaseBlockers.join(', ')}`)
  }
  process.stdout.write(`${JSON.stringify({
    schema: 'HiveRelayBlindClientBrowserArtifactGenerationV1',
    artifactProfile: cellGetOnly ? 'cell-get-only-v1' : 'control-v1',
    draft: false,
    releaseReady: evidenceStatus.releaseReady,
    releaseBlockers: evidenceStatus.releaseBlockers,
    crossHostByteEqualityProven:
      evidenceStatus.crossHostByteEqualityProven,
    realBrowserImportProven: evidenceStatus.realBrowserImportProven,
    artifactPath: artifactRelative,
    artifactBytes: first.artifactBytes.byteLength,
    artifactGzipBytes: first.artifactGzipBytes,
    manifestPath: manifestRelative,
    manifestHash: b4a.toString(hashBlindClientBrowserArtifactManifest(manifestBytes), 'hex'),
    sourceInputCount: Object.keys(first.metafile.inputs).length,
    sourceClosureEntryCount: snapshot.entries.size,
    toolchain: `esbuild@${esbuildVersion}`,
    specHash: b4a.toString(tuple.specHash, 'hex'),
    abiHash: b4a.toString(tuple.abiHash, 'hex'),
    vectorSetHash: b4a.toString(tuple.vectorSetHash, 'hex'),
    clientCompositionFormatHash: b4a.toString(tuple.clientCompositionFormatHash, 'hex'),
    clientCompositionVectorSetHash: b4a.toString(tuple.clientCompositionVectorSetHash, 'hex')
  })}\n`)
} finally {
  await fs.rm(directory, { recursive: true, force: true })
}
