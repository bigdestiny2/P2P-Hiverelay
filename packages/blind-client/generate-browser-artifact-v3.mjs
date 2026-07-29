#!/usr/bin/env node
import fs from 'node:fs/promises'
import path from 'node:path'
import process from 'node:process'
import { createHash } from 'node:crypto'
import { createRequire } from 'node:module'
import b4a from 'b4a'
import { build } from 'esbuild'
import { hashAbi, hashClientCompositionFormat } from '@hiverelay/blind-protocol/hashes'
import {
  hashBlindClientBrowserArtifactManifestV2,
  hashBlindClientBrowserArtifactV2
} from './browser-artifact-v2.js'
import {
  encodeBlindClientBrowserArtifactManifestV3,
  hashBlindClientBrowserArtifactManifestV3,
  hashBlindClientBrowserArtifactV3,
  hashBlindClientBrowserSourceClosureV3
} from './browser-artifact-v3.js'
import { BLIND_CLIENT_CONTROL_V3_AUTHORITY } from './browser-forward-state-v3.js'

const check = process.argv.includes('--check')
const packageRoot = path.dirname(new URL(import.meta.url).pathname)
const repoRoot = path.resolve(packageRoot, '../..')
const protocolRoot = path.resolve(packageRoot, '../blind-protocol')
const artifactRoot = path.join(packageRoot, 'browser-artifacts')
const require = createRequire(import.meta.url)
const esbuildVersion = require('esbuild/package.json').version
const virtualEntryPath = 'packages/blind-client/browser-artifacts/blind-client-control-v3.entry.mjs'
const externalV2 = './blind-client-control-v2.mjs'
const entrySource = `export * from '${externalV2}'\nexport * from '../browser-forward-state-v3.js'\n`
const buildProfile = Object.freeze({
  bundle: true,
  platform: 'browser',
  format: 'esm',
  target: 'es2020',
  minify: true,
  sourcemap: false,
  charset: 'utf8',
  legalComments: 'none'
})
const buildProfileText = 'bundle=true;platform=browser;format=esm;target=es2020;minify=true;sourcemap=false;charset=utf8;legalComments=none'
const hex = value => b4a.toString(value, 'hex')
const json = value => b4a.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8')
const sha256 = value => createHash('sha256').update(value).digest('hex')

if (esbuildVersion !== '0.28.1') throw new Error(`browser v3 artifact requires esbuild@0.28.1, found ${esbuildVersion}`)

const compatibilityFloor = Object.freeze({
  'browser-artifact.js': '92f4daa973af957f295ce96c11e9684ad9a2313247832934b952819d2710204e',
  'browser-artifact-v2.js': 'f5d91cd97c2623906c9db9aef3151a47ba83b9382854bea69210dab7b3decb28',
  'generate-browser-artifact-v2.mjs': '74d1d15ba41e17add53d666fd1e50f1ab84b665d29b690817bbc9bb1a4ce3a81',
  'browser-artifacts/blind-client-control-v1.mjs': '10425bb00fb8045e63ce2869b5e6bf88af39dc0723963203a6b021e0fd28090a',
  'browser-artifacts/blind-client-control-v1.manifest.cenc': '76a7ea97db644971203c2f94c476614a95b0320980a58504b927f04b152aadf1',
  'browser-artifacts/blind-client-control-v1.chromium-evidence.json': '1382b24b21cae661392a199b0470a22768b85f62215db6fb943ed17b66859c2e',
  'browser-artifacts/blind-client-control-v1.cross-host-evidence.json': '3cfd3c12a7664899a0901eff7b613f85da6fd039b930f74ade5bc820d215dcd2',
  'browser-artifacts/blind-client-control-v2.mjs': 'dfb4276ae74a42d487ad1ef77783309a93ba8985591799ea298c01f8f47442aa',
  'browser-artifacts/blind-client-control-v2.manifest.cenc': 'eb37a674bb92e218088f9f6e9a820866e1eca9f540feeeee825923e311b81731',
  'browser-artifacts/blind-client-control-v2.authority.json': 'eef9468bc97b04fb53692ca7096997ce71e5e56f85a451d1aacdcde12215b43c',
  'browser-artifacts/blind-client-control-v2.source-closure.json': 'b6dac623480fd1e36ffe39bed8fab6e16df4139488e2039abe6bd71e2f03cf6f',
  'package.json': '39ca1e16d47b42c529683a4ae13e437292c67f55ce67e404c9894a2444dbb3a8'
})

const fixedAuthorityPaths = Object.freeze([
  'package.json',
  'package-lock.json',
  'docs/protocol/HIVERELAY-BLIND-WIRE-V3.md',
  'docs/protocol/HIVERELAY-BLIND-CLIENT-COMPOSITION-V3.md',
  'packages/blind-client/package.json',
  'packages/blind-client/browser-artifact-v3.js',
  'packages/blind-client/browser-forward-state-v3.js',
  'packages/blind-client/generate-browser-artifact-v3.mjs',
  'packages/blind-client/browser-artifacts/blind-client-control-v2.mjs',
  'packages/blind-client/browser-artifacts/blind-client-control-v2.manifest.cenc',
  'packages/blind-client/browser-artifacts/blind-client-control-v2.authority.json',
  'packages/blind-client/browser-artifacts/blind-client-control-v2.source-closure.json',
  'packages/blind-protocol/package.json',
  'packages/blind-protocol/generate-wire-v3.mjs',
  'packages/blind-protocol/wire-v3.js',
  'packages/blind-protocol/hiverelay-blind-abi-v3.cenc',
  'packages/blind-protocol/hiverelay-blind-wire-authority-v3.json',
  'packages/blind-protocol/generate-client-composition-v3.mjs',
  'packages/blind-protocol/client-composition-v3.js',
  'packages/blind-protocol/hiverelay-blind-client-composition-format-v3.cenc',
  'packages/blind-protocol/hiverelay-blind-client-composition-authority-v3.json',
  'node_modules/esbuild/package.json'
])

async function assertCompatibilityFloor () {
  for (const [relative, expected] of Object.entries(compatibilityFloor)) {
    const actual = sha256(await fs.readFile(path.join(packageRoot, relative)))
    if (actual !== expected) throw new Error(`frozen browser v1/v2 artifact changed: ${relative} ${actual}`)
  }
}

function normalizeGraphPath (rawPath) {
  const value = rawPath.replaceAll('\\', '/')
  if (!value || value.includes('\0') || value.startsWith('/') || /^[A-Za-z]:\//.test(value) ||
      value === '..' || value.startsWith('../') || value.includes('/../')) {
    throw new Error(`browser v3 graph path is not normalized root-relative authority: ${rawPath}`)
  }
  return value
}

function loaderFor (absolute) {
  const extension = path.extname(absolute)
  if (extension === '.js' || extension === '.mjs' || extension === '.cjs') return 'js'
  if (extension === '.json') return 'json'
  throw new Error(`browser v3 graph input has no frozen loader: ${absolute}`)
}

function normalizedInputGraph (metafile) {
  return Object.entries(metafile.inputs).map(([rawPath, metadata]) => ({
    path: normalizeGraphPath(rawPath),
    bytes: metadata.bytes,
    format: metadata.format || null,
    imports: (metadata.imports || []).map(value => ({
      path: normalizeGraphPath(value.path),
      kind: value.kind,
      original: value.original || null,
      external: value.external === true
    })).sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)))
  })).sort((left, right) => left.path.localeCompare(right.path))
}

function assertClosedGraph (metafile) {
  const inputs = Object.keys(metafile.inputs).map(normalizeGraphPath)
  const forbidden = inputs.filter(value =>
    /(^|\/)node_modules\/(?:sodium-native|bare-crypto)(?:\/|$)/.test(value) ||
    value.endsWith('.node') || value.includes('packages/blind-protocol/index.js') ||
    value.includes('packages/blind-protocol/client-internal-schemas.js') ||
    value.includes('packages/blind-protocol/durability-schemas.js'))
  if (forbidden.length > 0) throw new Error(`browser v3 graph contains native/server authority: ${forbidden.join(', ')}`)
  const disabled = inputs.filter(value => value.startsWith('(disabled):'))
  if (disabled.length !== 1 || disabled[0] !== '(disabled):crypto') {
    throw new Error(`browser v3 disabled graph changed: ${disabled.join(', ')}`)
  }
  const externalEdges = []
  for (const [rawInput, metadata] of Object.entries(metafile.inputs)) {
    const input = normalizeGraphPath(rawInput)
    for (const imported of metadata.imports || []) {
      if (imported.external) externalEdges.push({ input, ...imported })
    }
  }
  const runtimeInputs = externalEdges.filter(value => value.path === '<runtime>').map(value => value.input).sort()
  const expectedRuntimeInputs = [
    'node_modules/sodium-javascript/randombytes.js',
    'packages/blind-protocol/wire-v2.js',
    'packages/blind-protocol/wire-v3.js'
  ]
  const externalModuleEdges = externalEdges.filter(value => value.path !== '<runtime>')
  const expectedV2 = externalModuleEdges.find(value =>
    value.input === virtualEntryPath && value.path === externalV2 && value.kind === 'import-statement')
  if (JSON.stringify(runtimeInputs) !== JSON.stringify(expectedRuntimeInputs) ||
      externalModuleEdges.length !== 1 || !expectedV2) {
    throw new Error(`browser v3 input graph has unaudited external edges: ${JSON.stringify(externalEdges)}`)
  }
  const outputImports = Object.values(metafile.outputs).flatMap(value => value.imports || [])
  if (outputImports.length !== 1 || outputImports[0].path !== externalV2 ||
      outputImports[0].kind !== 'import-statement' || outputImports[0].external !== true) {
    throw new Error(`browser v3 output external is not the exact frozen v2 artifact: ${JSON.stringify(outputImports)}`)
  }
}

async function buildOnce (snapshot = null) {
  const plugins = []
  if (snapshot) {
    plugins.push({
      name: 'hiverelay-browser-v3-frozen-source',
      setup (builder) {
        builder.onLoad({ filter: /.*/, namespace: 'file' }, args => {
          const relative = normalizeGraphPath(path.relative(repoRoot, args.path))
          if (!snapshot.graphInputs.has(relative)) throw new Error(`browser v3 build requested unexpected input: ${relative}`)
          const entry = snapshot.entries.get(relative)
          if (!entry) throw new Error(`browser v3 frozen input disappeared: ${relative}`)
          return { contents: entry.content, loader: loaderFor(args.path), resolveDir: path.dirname(args.path) }
        })
      }
    })
  }
  const result = await build({
    absWorkingDir: repoRoot,
    stdin: {
      contents: entrySource,
      resolveDir: artifactRoot,
      sourcefile: 'blind-client-control-v3.entry.mjs',
      loader: 'js'
    },
    ...buildProfile,
    metafile: true,
    write: false,
    outfile: 'packages/blind-client/browser-artifacts/blind-client-control-v3.mjs',
    external: [externalV2],
    logLevel: 'silent',
    plugins
  })
  assertClosedGraph(result.metafile)
  if (snapshot) {
    const actual = normalizedInputGraph(result.metafile)
    if (JSON.stringify(actual) !== JSON.stringify(snapshot.inputGraph)) {
      throw new Error('browser v3 frozen metafile input graph changed')
    }
  }
  if (result.outputFiles.length !== 1) throw new Error('browser v3 build did not produce one exact ESM artifact')
  return Object.freeze({ artifactBytes: b4a.from(result.outputFiles[0].contents), metafile: result.metafile })
}

async function addFile (entries, relative, role, required = true) {
  relative = normalizeGraphPath(relative)
  let content
  try {
    content = b4a.from(await fs.readFile(path.join(repoRoot, ...relative.split('/'))))
  } catch (error) {
    if (!required && error && error.code === 'ENOENT') return false
    throw new Error(`browser v3 source authority is missing ${relative}: ${error.message}`)
  }
  const current = entries.get(relative)
  if (current) {
    if (!b4a.equals(current.content, content)) throw new Error(`browser v3 authority changed while snapshotting ${relative}`)
    current.roles.add(role)
  } else {
    entries.set(relative, { content, roles: new Set([role]) })
  }
  return true
}

async function sourceSnapshot (metafile) {
  const inputGraph = normalizedInputGraph(metafile)
  const graphInputs = new Set(inputGraph.map(value => value.path))
  const entries = new Map()
  for (const input of inputGraph) {
    if (input.path === virtualEntryPath) {
      entries.set(input.path, { content: b4a.from(entrySource), roles: new Set(['METAFILE_INPUT', 'VIRTUAL_ENTRY']) })
      continue
    }
    if (input.path === '(disabled):crypto') {
      entries.set(input.path, {
        content: b4a.from('esbuild@0.28.1-disabled-browser-module:(disabled):crypto'),
        roles: new Set(['METAFILE_INPUT', 'DISABLED_BROWSER_MODULE'])
      })
      continue
    }
    await addFile(entries, input.path, 'METAFILE_INPUT')
    let directory = path.posix.dirname(input.path)
    while (directory !== '.') {
      await addFile(entries, path.posix.join(directory, 'package.json'), 'RESOLUTION_METADATA', false)
      const parent = path.posix.dirname(directory)
      if (parent === directory) break
      directory = parent
    }
  }
  for (const relative of fixedAuthorityPaths) await addFile(entries, relative, 'FIXED_AUTHORITY')
  return Object.freeze({ entries, graphInputs, inputGraph })
}

function sourceClosureBytes (snapshot) {
  const entries = [...snapshot.entries].map(([entryPath, value]) => ({
    path: entryPath,
    bytes: value.content.byteLength,
    sha256: sha256(value.content),
    roles: [...value.roles].sort()
  })).sort((left, right) => left.path.localeCompare(right.path))
  return json({
    schema: 'HiveRelayBlindClientBrowserSourceClosureV3',
    toolchain: `esbuild@${esbuildVersion}`,
    buildProfile,
    buildProfileText,
    externalArtifacts: [externalV2],
    metafileInputs: snapshot.inputGraph,
    entries
  })
}

async function writeOrCheck (file, content) {
  content = b4a.from(content)
  if (check) {
    let current
    try { current = await fs.readFile(file) } catch { throw new Error(`missing generated browser v3 artifact: ${path.relative(repoRoot, file)}`) }
    if (!b4a.equals(current, content)) throw new Error(`stale generated browser v3 artifact: ${path.relative(repoRoot, file)}`)
    return
  }
  await fs.mkdir(path.dirname(file), { recursive: true })
  await fs.writeFile(file, content)
}

await assertCompatibilityFloor()

const [v2ArtifactBytes, v2ManifestBytes, wireV3AbiBytes, compositionV3FormatBytes] = await Promise.all([
  fs.readFile(path.join(artifactRoot, 'blind-client-control-v2.mjs')),
  fs.readFile(path.join(artifactRoot, 'blind-client-control-v2.manifest.cenc')),
  fs.readFile(path.join(protocolRoot, 'hiverelay-blind-abi-v3.cenc')),
  fs.readFile(path.join(protocolRoot, 'hiverelay-blind-client-composition-format-v3.cenc'))
])
if (hex(hashBlindClientBrowserArtifactV2(v2ArtifactBytes)) !== '217ac636ded5bc6358a7a33b31aab7361b65feb117cf38dce68f6041bf773122') {
  throw new Error('frozen browser v2 artifact hash mismatch')
}
const wireV3AbiHash = hashAbi(wireV3AbiBytes)
const compositionV3FormatHash = hashClientCompositionFormat(compositionV3FormatBytes)
if (hex(wireV3AbiHash) !== BLIND_CLIENT_CONTROL_V3_AUTHORITY.wireV3AbiHash ||
    hex(compositionV3FormatHash) !== BLIND_CLIENT_CONTROL_V3_AUTHORITY.clientCompositionV3FormatHash) {
  throw new Error('browser v3 source authority does not match the frozen WIRE/composition tuple')
}

const discovery = await buildOnce()
const snapshot = await sourceSnapshot(discovery.metafile)
const first = await buildOnce(snapshot)
const second = await buildOnce(snapshot)
if (!b4a.equals(discovery.artifactBytes, first.artifactBytes) || !b4a.equals(first.artifactBytes, second.artifactBytes)) {
  throw new Error('browser v3 esbuild output is not deterministic over its frozen source closure')
}

const artifactBytes = first.artifactBytes
const sourceClosure = sourceClosureBytes(snapshot)
const manifestValue = {
  version: 3,
  baseBrowserV2ArtifactHash: hashBlindClientBrowserArtifactV2(v2ArtifactBytes),
  baseBrowserV2ManifestHash: hashBlindClientBrowserArtifactManifestV2(v2ManifestBytes),
  wireV3AbiHash,
  clientCompositionV3FormatHash: compositionV3FormatHash,
  artifactHash: hashBlindClientBrowserArtifactV3(artifactBytes),
  sourceClosureHash: hashBlindClientBrowserSourceClosureV3(sourceClosure),
  exactRequestBytes: 65_536,
  exactResultBytes: 65_536,
  forwardReadinessOperationBits: 0
}
const manifestBytes = encodeBlindClientBrowserArtifactManifestV3(manifestValue)
const authority = {
  profile: 'blind-client-browser-artifact-v3',
  authorityVersion: 3,
  artifactPath: 'browser-artifacts/blind-client-control-v3.mjs',
  manifestPath: 'browser-artifacts/blind-client-control-v3.manifest.cenc',
  baseBrowserV2ArtifactHash: hex(manifestValue.baseBrowserV2ArtifactHash),
  baseBrowserV2ManifestHash: hex(manifestValue.baseBrowserV2ManifestHash),
  wireV3AbiHash: hex(wireV3AbiHash),
  clientCompositionV3FormatHash: hex(compositionV3FormatHash),
  artifactHash: hex(manifestValue.artifactHash),
  manifestHash: hex(hashBlindClientBrowserArtifactManifestV3(manifestBytes)),
  sourceClosureHash: hex(manifestValue.sourceClosureHash),
  sourceClosureSchema: 'HiveRelayBlindClientBrowserSourceClosureV3',
  sourceClosureEntries: snapshot.entries.size,
  metafileInputCount: snapshot.inputGraph.length,
  toolchain: `esbuild@${esbuildVersion}`,
  buildProfile: buildProfileText,
  externalArtifacts: [externalV2],
  exactRequestBytes: 65_536,
  exactResultBytes: 65_536,
  credentialMode: 'omit',
  cacheMode: 'no-store',
  redirectMode: 'error',
  referrerPolicy: 'no-referrer',
  continuityBackend: 'INDEXEDDB_PERSISTENT',
  forwardDescriptorOperationBits: 0,
  forwardAdvertisedOperationBits: 0,
  forwardReadinessOperationBits: 0,
  runtimeReady: false,
  realBrowserEvidenceAccepted: false,
  authorizesRelease: false,
  compatibilityFloor
}

const outputs = [
  [path.join(artifactRoot, 'blind-client-control-v3.mjs'), artifactBytes],
  [path.join(artifactRoot, 'blind-client-control-v3.manifest.cenc'), manifestBytes],
  [path.join(artifactRoot, 'blind-client-control-v3.authority.json'), json(authority)],
  [path.join(artifactRoot, 'blind-client-control-v3.source-closure.json'), sourceClosure]
]
for (const [file, content] of outputs) await writeOrCheck(file, content)

console.log(check ? 'browser v3 artifact verified' : 'browser v3 artifact generated')
