#!/usr/bin/env node
import fs from 'node:fs/promises'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'
import b4a from 'b4a'
import { build } from 'esbuild'
import {
  BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT_PROFILES,
  decodeBlindClientPublicBrowserArtifactManifestV1,
  hashBlindClientPublicBrowserArtifactManifestV1,
  verifyBlindClientPublicBrowserArtifactV1
} from '../browser-artifact.js'

if (process.argv.length !== 2) {
  throw new Error('test-blind-client-public-browser-bundle.mjs accepts no arguments')
}

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const root = path.resolve(packageRoot, '../..')
const expectedEnvironment = Object.freeze({
  TMPDIR: path.join(root, '.t/seq29-browser-artifact-gates/tmp'),
  npm_config_cache: path.join(root, '.t/seq29-browser-artifact-gates/npm-cache'),
  npm_config_devdir: '/Users/localllm/Library/Caches/node-gyp'
})
const profiles = Object.freeze({
  full: BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT_PROFILES.full,
  limited: BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT_PROFILES.limited
})
const forbiddenExports = Object.freeze([
  'createInboxReplica',
  'createWatchInboxRequest',
  'createRenewInboxRequest',
  'createCloseInboxRequest',
  'destroyInboxWriteCapability'
])

function normalizePath (raw) {
  const value = raw.replaceAll('\\', '/')
  if (!value || value.startsWith('/') || /^[A-Za-z]:\//.test(value) ||
      value === '..' || value.startsWith('../') || value.includes('/../')) {
    throw new Error(`bundle graph path is not repository-relative: ${raw}`)
  }
  return value
}

function exactArray (actual, expected, message) {
  if (actual.length !== expected.length || actual.some((value, index) => value !== expected[index])) {
    throw new Error(message)
  }
}

async function assertGateEnvironment () {
  for (const [name, expected] of Object.entries(expectedEnvironment)) {
    if (process.env[name] !== expected) throw new Error(`${name} must be the exact scoped gate path ${expected}`)
    const stat = await fs.lstat(expected)
    if (!stat.isDirectory() || stat.isSymbolicLink() || await fs.realpath(expected) !== expected) {
      throw new Error(`${name} must resolve to a real scoped gate directory`)
    }
  }
}

function assertMetafile (id, identity, metafile) {
  const inputs = Object.keys(metafile.inputs).map(normalizePath)
  const outputs = Object.values(metafile.outputs)
  if (outputs.length !== 1 || (outputs[0].imports || []).length !== 0) {
    throw new Error(`${id} committed bundle is not one standalone ESM module`)
  }
  exactArray(outputs[0].exports || [], identity.exactSortedExports,
    `${id} committed bundle exports changed`)
  const forbidden = inputs.filter(input =>
    input !== identity.artifactPath ||
    input.endsWith('.node') || input.includes('node:') ||
    /(^|\/)node_modules\/(?:sodium-native|bare-crypto|sha512-wasm|blake2b-wasm)(?:\/|$)/.test(input) ||
    input.startsWith('packages/blind-client/browser-artifacts/'))
  if (forbidden.length !== 0) {
    throw new Error(`${id} committed bundle test reached forbidden inputs: ${forbidden.join(', ')}`)
  }
  const edges = Object.values(metafile.inputs).flatMap(value => value.imports || [])
  if (edges.some(value => value.external || value.kind === 'dynamic-import')) {
    throw new Error(`${id} committed bundle has external or dynamic runtime edges`)
  }
}

async function importCommittedArtifact (id, identity, artifactBytes) {
  const result = await build({
    absWorkingDir: root,
    entryPoints: [identity.artifactPath],
    bundle: true,
    platform: 'browser',
    format: 'esm',
    target: 'es2020',
    treeShaking: true,
    minify: false,
    sourcemap: false,
    legalComments: 'none',
    metafile: true,
    write: false,
    outfile: `packages/blind-client-public-browser/browser-artifacts/${id}.test.mjs`,
    logLevel: 'silent'
  })
  if (result.outputFiles.length !== 1) throw new Error(`${id} committed artifact did not parse as standalone ESM`)
  assertMetafile(id, identity, result.metafile)
  const encoded = b4a.toString(artifactBytes, 'base64')
  return import(`data:text/javascript;base64,${encoded}`)
}

async function aesRoundTrip (module) {
  const runtime = module.createBrowserCryptoRuntime(globalThis.crypto)
  const key = b4a.alloc(32, 0x11)
  const nonce = b4a.alloc(12, 0x22)
  const aad = b4a.from('HIVERELAY_PUBLIC_BROWSER_AAD_V1')
  const plaintext = b4a.from('HIVERELAY_PUBLIC_BROWSER_PLAINTEXT_V1')
  const sealed = await runtime.aes256GcmEncrypt({ key, nonce, aad, plaintext })
  const opened = await runtime.aes256GcmDecrypt({ key, nonce, aad, sealed })
  if (!b4a.equals(opened, plaintext)) throw new Error('WebCrypto AES-256-GCM round trip failed')
}

async function assertBoundFetch (module) {
  const original = globalThis.fetch
  let receiver = null
  try {
    globalThis.fetch = function () {
      receiver = this
      return Promise.resolve(Object.freeze({}))
    }
    const direct = new module.BlindDirectHttpClient({ runtime: {} })
    await direct.fetch('https://example.invalid')
    if (receiver !== globalThis) throw new Error('full artifact did not bind the global fetch receiver')
    const explicit = async () => Object.freeze({})
    if (new module.BlindDescriptorBootstrapHttpClient({ runtime: {}, fetch: explicit }).fetch !== explicit) {
      throw new Error('full artifact did not preserve explicit fetch identity')
    }
    globalThis.fetch = undefined
    let failed = false
    try { Reflect.construct(module.BlindDirectHttpClient, [{ runtime: {} }]) } catch { failed = true }
    if (!failed) throw new Error('full artifact did not fail closed without fetch')
  } finally {
    globalThis.fetch = original
  }
}

async function assertLimitedControl (module) {
  const control = module.createBlindCellGetControl({
    runtime: {},
    fetch: async () => { throw new Error('unexpected transport') },
    nowEpoch: () => 1,
    monotonicMillis: () => 1,
    supportedProtocolProfiles: [{ profileId: 1, profileHash: b4a.alloc(32, 1) }],
    supportedTransportProfiles: [{ transportProfileId: 1, transportProfileHash: b4a.alloc(32, 2) }]
  })
  const methods = Object.getOwnPropertyNames(Object.getPrototypeOf(control)).sort()
  exactArray(methods, ['constructor', 'qualifyCellGetCandidate', 'readCell'],
    'limited artifact control methods changed')
  let selectionRejected = false
  try { await control.qualifyCellGetCandidate({}, { familyId: 1 }) } catch { selectionRejected = true }
  if (!selectionRejected) throw new Error('limited artifact accepted caller-selected operation')
  let foreignRejected = false
  try { await control.readCell({ endpoint: Object.freeze({}) }) } catch { foreignRejected = true }
  if (!foreignRejected) throw new Error('limited artifact accepted a foreign endpoint')
}

const report = {
  schema: 'HiveRelayBlindClientPublicBrowserBundleTestV1',
  profiles: {}
}
await assertGateEnvironment()
for (const [id, identity] of Object.entries(profiles)) {
  const [artifactBytes, manifestBytes] = await Promise.all([
    fs.readFile(path.join(root, identity.artifactPath)),
    fs.readFile(path.join(root, identity.manifestPath))
  ])
  const manifest = decodeBlindClientPublicBrowserArtifactManifestV1(manifestBytes)
  const verified = verifyBlindClientPublicBrowserArtifactV1({
    profile: id,
    manifestBytes,
    artifactBytes,
    expectedManifestHash: hashBlindClientPublicBrowserArtifactManifestV1(manifestBytes),
    expectedSourceClosureHash: manifest.sourceClosureHash,
    expectedTupleHash: manifest.tupleHash
  })
  const text = b4a.toString(artifactBytes)
  const forbiddenTokens = [
    ...forbiddenExports,
    'WebAssembly',
    'eval(',
    'new Function(',
    'import(',
    'sha512-wasm',
    'blake2b-wasm'
  ].filter(token => text.includes(token))
  if (forbiddenTokens.length !== 0) {
    throw new Error(`${id} committed artifact contains forbidden tokens: ${forbiddenTokens.join(', ')}`)
  }
  const module = await importCommittedArtifact(id, identity, artifactBytes)
  exactArray(Object.keys(module).sort(), [...identity.exactSortedExports].sort(),
    `${id} runtime exports changed`)
  for (const name of forbiddenExports) {
    if (name in module) throw new Error(`${id} exposes forbidden lifecycle export ${name}`)
  }
  await aesRoundTrip(module)
  if (id === 'full') await assertBoundFetch(module)
  else await assertLimitedControl(module)
  report.profiles[id] = {
    artifactPath: verified.artifactPath,
    artifactLength: verified.artifactLength,
    artifactHash: verified.artifactHash,
    manifestHash: verified.manifestHash,
    sourceClosureHash: verified.sourceClosureHash,
    exactExportCount: identity.exactSortedExports.length,
    nativeInputs: 0,
    externalRuntimeImports: 0,
    dynamicRuntimeImports: 0,
    ok: true
  }
}
process.stdout.write(`${JSON.stringify(report)}\n`)
