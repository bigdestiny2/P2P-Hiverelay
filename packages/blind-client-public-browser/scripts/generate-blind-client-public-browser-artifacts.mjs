#!/usr/bin/env node
import fs from 'node:fs/promises'
import path from 'node:path'
import process from 'node:process'
import { createHash } from 'node:crypto'
import { spawn } from 'node:child_process'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import b4a from 'b4a'
import { build } from 'esbuild'
import {
  BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT_AUTHORITY,
  BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT_PROFILES,
  createBlindClientPublicBrowserArtifactManifestV1,
  createBlindClientPublicBrowserArtifactTupleV1,
  decodeBlindClientPublicBrowserArtifactManifestV1,
  encodeBlindClientPublicBrowserArtifactManifestV1,
  hashBlindClientPublicBrowserArtifactManifestV1,
  hashBlindClientPublicBrowserNormalizedGraphSetV1,
  hashBlindClientPublicBrowserNormalizedGraphV1,
  hashBlindClientPublicBrowserSourceClosure,
  verifyBlindClientPublicBrowserArtifactReleaseEvidenceV1,
  verifyBlindClientPublicBrowserArtifactV1
} from '../browser-artifact.js'

const argv = process.argv.slice(2)
const generate = argv.length === 0
const check = argv.length === 1 && argv[0] === '--check'
const requireReleaseEvidence = argv.length === 2 &&
  argv[0] === '--check' && argv[1] === '--require-release-evidence'
const ciStructuralOnly = argv.length === 3 && argv[0] === '--check' &&
  argv[1] === '--ci-structural-only' && argv[2] === '--require-release-evidence'
const checkMode = check || requireReleaseEvidence || ciStructuralOnly
if (!generate && !check && !requireReleaseEvidence && !ciStructuralOnly) {
  throw new Error('usage: generate-blind-client-public-browser-artifacts.mjs [--check [--require-release-evidence] | --check --ci-structural-only --require-release-evidence]')
}

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const root = path.resolve(packageRoot, '../..')
const require = createRequire(import.meta.url)
const esbuildVersion = require('esbuild/package.json').version
if (esbuildVersion !== BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT_AUTHORITY.toolchain.esbuild) {
  throw new Error(`public browser artifact requires esbuild ${BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT_AUTHORITY.toolchain.esbuild}`)
}

const BUILD_PROFILE = Object.freeze({
  bundle: true,
  platform: 'browser',
  format: 'esm',
  target: 'es2020',
  minify: true,
  sourcemap: false,
  charset: 'utf8',
  legalComments: 'none',
  treeShaking: true
})
const CSP_ALIASES = Object.freeze({
  'sha512-wasm': 'packages/blind-client-public-browser/scripts/lib/sha512-wasm-csp-disabled.cjs',
  'blake2b-wasm': 'packages/blind-client-public-browser/scripts/lib/blake2b-wasm-csp-disabled.cjs'
})
const EXPECTED_GATE_ENVIRONMENT = Object.freeze({
  TMPDIR: path.join(root, '.t/seq29-browser-artifact-gates/tmp'),
  npm_config_cache: path.join(root, '.t/seq29-browser-artifact-gates/npm-cache'),
  npm_config_devdir: '/Users/localllm/Library/Caches/node-gyp'
})
const PROFILE_CONFIG = Object.freeze({
  full: Object.freeze({
    identity: BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT_PROFILES.full,
    entryRelative: 'packages/blind-client-public-browser/src/browser-control.js',
    entrySource: "export * from './src/browser-control.js'\n",
    virtualEntry: 'packages/blind-client-public-browser/blind-client-public-full-v1.entry.mjs'
  }),
  limited: Object.freeze({
    identity: BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT_PROFILES.limited,
    entryRelative: 'packages/blind-client-public-browser/src/cell-get-control.js',
    entrySource: "export * from './src/cell-get-control.js'\n",
    virtualEntry: 'packages/blind-client-public-browser/blind-client-public-limited-v1.entry.mjs'
  })
})
const FIXED_AUTHORITY_PATHS = Object.freeze([
  'package.json',
  'package-lock.json',
  'patches/hypercore-storage+3.2.0.patch',
  'packages/blind-client-public-browser/package.json',
  'packages/blind-client-public-browser/browser-artifact.js',
  'packages/blind-client-public-browser/scripts/generate-blind-client-public-browser-artifacts.mjs',
  'packages/blind-client-public-browser/scripts/lib/sha512-wasm-csp-disabled.cjs',
  'packages/blind-client-public-browser/scripts/lib/blake2b-wasm-csp-disabled.cjs',
  'packages/blind-client-public-browser/src/browser-control.js',
  'packages/blind-client-public-browser/src/cell-get-control.js',
  'packages/blind-client-public-browser/src/cell-get-requests.js',
  'packages/blind-client-public-browser/src/cell-get-results.js',
  'docs/protocol/HIVERELAY-BLIND-WIRE-V1.md',
  'docs/protocol/HIVERELAY-BLIND-CLIENT-COMPOSITION-V1.md',
  'scripts/generate-blind-protocol-draft.mjs',
  'scripts/generate-blind-client-composition-authority.mjs',
  'packages/blind-protocol/hiverelay-blind-wire-authority-v1.json',
  'packages/blind-protocol/hiverelay-blind-abi-v1.cenc',
  'packages/blind-protocol/vector-manifest-v1.cenc',
  'packages/blind-protocol/hiverelay-blind-client-composition-authority-v1.json',
  'packages/blind-protocol/hiverelay-blind-client-composition-format-v1.cenc',
  'packages/blind-protocol/hiverelay-blind-client-composition-schema-catalog-v1.cenc',
  'packages/blind-protocol/hiverelay-blind-client-composition-vector-manifest-v1.cenc',
  'node_modules/esbuild/package.json'
])
const LEGACY_FROZEN_SHA256 = Object.freeze({
  'package.json': 'db55467150b6e9f656de5ed5738b943afc8b4e9cf373297caa52e9c4f900b686',
  'package-lock.json': 'df3f3592f32eac9d090ff4f5759f5985bdaec560471bcb9874652eb373129576',
  'patches/hypercore-storage+3.2.0.patch': 'fbcd793cfb4fd3334b04bfd9163a728064eef2500361cb83ef84e95d13b46b53',
  'packages/blind-client/package.json': 'bda10754b89b255d178ddb4f0190f877a209ad143bebcce10876be80aefbfb29',
  'packages/blind-client/browser-artifact.js': '92f4daa973af957f295ce96c11e9684ad9a2313247832934b952819d2710204e',
  'packages/blind-client/browser-artifact-v2.js': 'f5d91cd97c2623906c9db9aef3151a47ba83b9382854bea69210dab7b3decb28',
  'packages/blind-client/browser-artifact-v3.js': '64095fb3cd90d499f6ec8849cb05767128f17b0f9a131df5d8304edb249b9075',
  'packages/blind-client/bootstrap-http.js': 'd642f83aeb43538d8a899d6020895436724fafc5334edbcbe2e4fb0a20581945',
  'packages/blind-client/direct-http.js': '0a7e7fac812687b81545717f2ba2b5ccfa28df89b8af64bef0d1779fa962105b',
  'packages/blind-client/describe.js': 'ca8022c5a7dd967a8191b3fabf93e5bcd24badfd96e7f4ef13948ba28ffdf2c4',
  'packages/blind-client/control.js': '484ff47bf0b2a335481e264fac030ec9500e5c8ead659feae28a59eb63c8c7fc',
  'packages/blind-client/generate-browser-artifact-v2.mjs': '74d1d15ba41e17add53d666fd1e50f1ab84b665d29b690817bbc9bb1a4ce3a81',
  'packages/blind-client/generate-browser-artifact-v3.mjs': '1461b18840e9cc8c77a046013bafc40666da9172300cff8c5b250ad3a5018684',
  'scripts/generate-blind-client-browser-artifacts.mjs': '9c1d4a616ea263f55ba5256143735ef6514b5cea6fb32b8148a5a29edd8184ba',
  'scripts/test-blind-client-browser-bundle.mjs': '84070b9249851efd0bcb1e99e613d5401f7c475aa4cfa2f9620fb4f731e127f3',
  'scripts/test-blind-client-browser-artifact-chromium.mjs': '33e8a13531ced49aeb674eb1d1c17e7809c0e175641dd0cc56b4a81138800119',
  'scripts/test-blind-client-browser-artifact-cross-host.mjs': '3525e70d31eb928afcc8f28ff994b562272a5cbb522038dc82a11a73eac02fa8',
  'test/unit/blind-protocol-v1-compatibility-floor.test.js': '375fb8937d27d9a10a1683bb7fd3b4c72d17ff112b512f43fee11df00bb41ae3',
  'packages/blind-client/browser-artifacts/blind-client-control-v1.mjs': '10425bb00fb8045e63ce2869b5e6bf88af39dc0723963203a6b021e0fd28090a',
  'packages/blind-client/browser-artifacts/blind-client-control-v1.manifest.cenc': '343a301acf50e5d0d4449e44a11b30c52a1692855c3ad3c03c6c9acc9103c509',
  'packages/blind-client/browser-artifacts/blind-client-control-v1.chromium-evidence.json': '5dc23bb9de210ec3292c74407fcb815b43b88535d656f62df16036473547e5cf',
  'packages/blind-client/browser-artifacts/blind-client-control-v1.cross-host-evidence.json': '72d7bdac68d2680436f54165dc956f48673d0c4320b3ae3325dbb29021cecaee',
  'packages/blind-client/browser-artifacts/blind-client-control-v2.mjs': 'dfb4276ae74a42d487ad1ef77783309a93ba8985591799ea298c01f8f47442aa',
  'packages/blind-client/browser-artifacts/blind-client-control-v2.manifest.cenc': 'eb37a674bb92e218088f9f6e9a820866e1eca9f540feeeee825923e311b81731',
  'packages/blind-client/browser-artifacts/blind-client-control-v2.authority.json': 'eef9468bc97b04fb53692ca7096997ce71e5e56f85a451d1aacdcde12215b43c',
  'packages/blind-client/browser-artifacts/blind-client-control-v2.source-closure.json': 'b6dac623480fd1e36ffe39bed8fab6e16df4139488e2039abe6bd71e2f03cf6f',
  'packages/blind-client/browser-artifacts/blind-client-control-v3.mjs': '874afd4a1927d4df2f0b439c1ecb72679de7eadde91ab256a330d85378e98744',
  'packages/blind-client/browser-artifacts/blind-client-control-v3.manifest.cenc': '819358a1638cf13e5ce149b52ddae922159c595558081135b1e74737ddcca3c4',
  'packages/blind-client/browser-artifacts/blind-client-control-v3.authority.json': '3943a61c1b8fd7d75b339620d17320954729f1516b100a8ff858a265731cb928',
  'packages/blind-client/browser-artifacts/blind-client-control-v3.source-closure.json': 'f9f49e6a58f8861cde0aff1c5b2d75938cde0c9d8a002ed1764c9f9659280563'
})
const LEGACY_CHECKS = Object.freeze([
  Object.freeze({
    script: 'scripts/generate-blind-client-browser-artifacts.mjs',
    args: ['--check'],
    message: 'generated browser artifact drift: packages/blind-client/browser-artifacts/blind-client-control-v1.mjs',
    scratch: true
  }),
  Object.freeze({
    script: 'packages/blind-client/generate-browser-artifact-v2.mjs',
    args: ['--check'],
    message: 'frozen browser v1 artifact changed: blind-client-control-v1.manifest.cenc 343a301acf50e5d0d4449e44a11b30c52a1692855c3ad3c03c6c9acc9103c509',
    scratch: false
  }),
  Object.freeze({
    script: 'packages/blind-client/generate-browser-artifact-v3.mjs',
    args: ['--check'],
    message: 'frozen browser v1/v2 artifact changed: browser-artifacts/blind-client-control-v1.manifest.cenc 343a301acf50e5d0d4449e44a11b30c52a1692855c3ad3c03c6c9acc9103c509',
    scratch: false
  })
])
const LEGACY_SCRATCH_PREFIX = 'hiverelay-blind-client-artifact-'
const LEGACY_SCRATCH_FILES = new Set(['discovery.mjs', 'first.mjs', 'second.mjs'])
const BROWSER_RANDOMBYTES_PATH = 'node_modules/sodium-javascript/randombytes.js'
const NODE_RANDOMBYTES_FALLBACK = `
  if (require != null) {
    // Node.js. Bust Browserify
    crypto = require('cry' + 'pto')
    if (crypto && crypto.randomBytes) return nodeBytes
  }
`
const FORBIDDEN_EXPORTS = Object.freeze([
  'createInboxReplica',
  'createWatchInboxRequest',
  'createRenewInboxRequest',
  'createCloseInboxRequest',
  'destroyInboxWriteCapability'
])
const SUCCESSOR_PATHS = Object.freeze([
  '.eslintignore',
  '.github/workflows/test.yml',
  'packages/blind-client-public-browser/package.json',
  'packages/blind-client-public-browser/browser-artifact.js',
  'packages/blind-client-public-browser/src/browser-control.js',
  'packages/blind-client-public-browser/src/cell-get-control.js',
  'packages/blind-client-public-browser/src/cell-get-requests.js',
  'packages/blind-client-public-browser/src/cell-get-results.js',
  'packages/blind-client-public-browser/test/browser-artifact.test.js',
  'packages/blind-client-public-browser/test/browser-artifact-inbox.test.js',
  'packages/blind-client-public-browser/test/cell-get-browser-artifact.test.js',
  'packages/blind-client-public-browser/test/cell-get-control.test.js',
  'packages/blind-client-public-browser/test/http-control.test.js',
  ...Object.values(PROFILE_CONFIG).flatMap(value => [
    value.identity.artifactPath,
    value.identity.manifestPath,
    value.identity.chromiumEvidencePath,
    value.identity.crossHostEvidencePath
  ]),
  'packages/blind-client-public-browser/scripts/generate-blind-client-public-browser-artifacts.mjs',
  'packages/blind-client-public-browser/scripts/test-blind-client-public-browser-bundle.mjs',
  'packages/blind-client-public-browser/scripts/test-blind-client-public-browser-artifact-chromium.mjs',
  'packages/blind-client-public-browser/scripts/test-blind-client-public-browser-artifact-cross-host.mjs',
  'packages/blind-client-public-browser/scripts/lib/sha512-wasm-csp-disabled.cjs',
  'packages/blind-client-public-browser/scripts/lib/blake2b-wasm-csp-disabled.cjs',
  'test/unit/blind-client-public-browser-artifact.test.js'
])

function sha256 (bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function canonicalJson (value) {
  return b4a.from(`${JSON.stringify(value, null, 2)}\n`)
}

function codePointCompare (left, right) {
  const leftPoints = Array.from(left, value => value.codePointAt(0))
  const rightPoints = Array.from(right, value => value.codePointAt(0))
  const length = Math.min(leftPoints.length, rightPoints.length)
  for (let index = 0; index < length; index++) {
    if (leftPoints[index] !== rightPoints[index]) return leftPoints[index] - rightPoints[index]
  }
  return leftPoints.length - rightPoints.length
}

function normalizePath (raw, field = 'graph path') {
  const value = raw.replaceAll('\\', '/')
  const segments = value.split('/')
  if (!value || value.includes('\0') || value.startsWith('/') || /^[A-Za-z]:\//.test(value) ||
      segments.some(segment => segment === '' || segment === '.' || segment === '..')) {
    throw new Error(`${field} is not repository-relative: ${raw}`)
  }
  return value
}

function absolute (relative) {
  return path.resolve(root, ...normalizePath(relative).split('/'))
}

function sortedObjectEntries (value) {
  return Object.entries(value).sort(([left], [right]) => codePointCompare(left, right))
}

async function requireRealDirectory (expected, field) {
  let stat
  try { stat = await fs.lstat(expected) } catch (error) {
    throw new Error(`${field} is missing: ${expected}`, { cause: error })
  }
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`${field} must be a real directory: ${expected}`)
  }
  if (await fs.realpath(expected) !== expected) {
    throw new Error(`${field} realpath changed: ${expected}`)
  }
}

async function assertGateEnvironment () {
  for (const [name, expected] of Object.entries(EXPECTED_GATE_ENVIRONMENT)) {
    if (process.env[name] !== expected) {
      throw new Error(`${name} must be the exact scoped gate path ${expected}`)
    }
  }
  await requireRealDirectory(root, 'source root')
  await requireRealDirectory(path.join(root, '.t'), 'gate parent')
  await requireRealDirectory(path.join(root, '.t/seq29-browser-artifact-gates'), 'gate root')
  await requireRealDirectory(EXPECTED_GATE_ENVIRONMENT.TMPDIR, 'TMPDIR')
  await requireRealDirectory(EXPECTED_GATE_ENVIRONMENT.npm_config_cache, 'npm_config_cache')
  await requireRealDirectory(EXPECTED_GATE_ENVIRONMENT.npm_config_devdir, 'npm_config_devdir')
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

async function assertCiStructuralEnvironment () {
  if (process.env.CI !== 'true') throw new Error('CI structural mode requires CI=true')
  if (!process.env.RUNNER_TEMP) throw new Error('CI structural mode requires RUNNER_TEMP')
  await requireRealDirectoryAncestry(process.env.RUNNER_TEMP, 'RUNNER_TEMP')
}

async function repositoryInventory () {
  const inventory = []
  async function visit (relative) {
    if (relative === '.git' || relative.startsWith('.git/')) return
    const target = relative === '.' ? root : absolute(relative)
    const stat = await fs.lstat(target)
    const mode = stat.mode & 0o7777
    if (stat.isSymbolicLink()) {
      inventory.push({ path: relative, type: 'symlink', mode, target: await fs.readlink(target) })
      return
    }
    if (stat.isFile()) {
      const content = await fs.readFile(target)
      inventory.push({ path: relative, type: 'file', mode, bytes: content.byteLength, sha256: sha256(content) })
      return
    }
    if (stat.isDirectory()) {
      inventory.push({ path: relative, type: 'directory', mode })
      const children = (await fs.readdir(target)).sort(codePointCompare)
      for (const child of children) await visit(relative === '.' ? child : path.posix.join(relative, child))
      return
    }
    inventory.push({ path: relative, type: 'other', mode, device: stat.rdev })
  }
  await visit('.')
  return canonicalJson(inventory)
}

async function assertRepositoryInventoryUnchanged (before) {
  const after = await repositoryInventory()
  if (!b4a.equals(before, after)) {
    throw new Error('CI structural mode changed the complete repository inventory')
  }
}

function normalizedMetafile (metafile) {
  const inputs = sortedObjectEntries(metafile.inputs).map(([rawPath, metadata]) => ({
    path: normalizePath(rawPath),
    bytes: metadata.bytes,
    format: metadata.format || 'none',
    imports: (metadata.imports || []).map(value => ({
      path: value.path.startsWith('<') || value.path.startsWith('(')
        ? value.path
        : normalizePath(value.path, 'graph import'),
      kind: value.kind,
      external: value.external === true,
      original: value.original ?? null
    })).sort((left, right) => codePointCompare(JSON.stringify(left), JSON.stringify(right)))
  }))
  const outputs = sortedObjectEntries(metafile.outputs).map(([rawPath, metadata]) => ({
    path: normalizePath(rawPath, 'output path'),
    entryPoint: metadata.entryPoint == null ? null : normalizePath(metadata.entryPoint),
    exports: [...(metadata.exports || [])].sort(codePointCompare),
    imports: (metadata.imports || []).map(value => ({
      path: value.path.startsWith('<') || value.path.startsWith('(')
        ? value.path
        : normalizePath(value.path, 'output import'),
      kind: value.kind,
      external: value.external === true
    })).sort((left, right) => codePointCompare(JSON.stringify(left), JSON.stringify(right))),
    inputs: sortedObjectEntries(metadata.inputs || {}).map(([input, value]) => ({
      path: normalizePath(input),
      bytesInOutput: value.bytesInOutput
    })),
    bytes: metadata.bytes
  }))
  return Object.freeze({ inputs, outputs })
}

function exactArray (actual, expected, message) {
  if (actual.length !== expected.length || actual.some((value, index) => value !== expected[index])) {
    throw new Error(message)
  }
}

function assertClosedGraph (profile, metafile, artifactBytes) {
  const normalized = normalizedMetafile(metafile)
  if (normalized.outputs.length !== 1 || normalized.outputs[0].imports.length !== 0) {
    throw new Error(`${profile.identity.id} output is not one standalone ESM module`)
  }
  exactArray(normalized.outputs[0].exports, profile.identity.exactSortedExports,
    `${profile.identity.id} metafile exports changed`)
  const inputs = normalized.inputs.map(value => value.path)
  const forbidden = inputs.filter(input =>
    input.startsWith('packages/blind-client/browser-artifacts/') ||
    input.startsWith('packages/blind-client-public-browser/browser-artifacts/') ||
    input.endsWith('.node') || input.includes('node:') ||
    /(^|\/)node_modules\/(?:sodium-native|bare-crypto)(?:\/|$)/.test(input) ||
    /(^|\/)(?:server|daemon|fleet)(?:\/|$)/i.test(input) ||
    /(^|\/)node_modules\/(?:sha512-wasm|blake2b-wasm)(?:\/|$)/.test(input))
  if (profile.identity.id === 'limited') {
    forbidden.push(...inputs.filter(input => [
      'packages/blind-client/control.js',
      'packages/blind-client/requests.js',
      'packages/blind-client/results.js',
      'packages/blind-client/inbox.js',
      'packages/blind-client/core.js',
      'packages/blind-client/forward.js'
    ].includes(input)))
  }
  if (forbidden.length !== 0) {
    throw new Error(`${profile.identity.id} graph contains forbidden inputs: ${[...new Set(forbidden)].join(', ')}`)
  }
  const graphEdges = normalized.inputs.flatMap(input => input.imports.map(edge => ({ input: input.path, ...edge })))
  const external = graphEdges.filter(edge => edge.external)
  const dynamic = graphEdges.filter(edge => edge.kind === 'dynamic-import')
  const disabled = inputs.filter(input => input.startsWith('(disabled):'))
  if (external.length || dynamic.length || disabled.length) {
    throw new Error(`${profile.identity.id} graph has external, dynamic, or disabled edges`)
  }
  const text = b4a.toString(artifactBytes)
  const tokens = [
    ...FORBIDDEN_EXPORTS,
    'WebAssembly',
    'eval(',
    'new Function(',
    'import(',
    'sha512-wasm',
    'blake2b-wasm'
  ].filter(token => text.includes(token))
  if (tokens.length) throw new Error(`${profile.identity.id} artifact contains forbidden tokens: ${tokens.join(', ')}`)
  if (artifactBytes.byteLength < 1 ||
      artifactBytes.byteLength > BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT_AUTHORITY.maximumArtifactBytes) {
    throw new Error(`${profile.identity.id} artifact is outside its byte limit`)
  }
  return normalized
}

function loaderFor (file) {
  switch (path.extname(file)) {
    case '.js':
    case '.mjs':
    case '.cjs': return 'js'
    case '.json': return 'json'
    default: throw new Error(`public browser artifact has no frozen loader for ${file}`)
  }
}

function frozenSourcePlugin (snapshot) {
  return {
    name: 'hiverelay-public-browser-frozen-source',
    setup (builder) {
      builder.onLoad({ filter: /.*/, namespace: 'file' }, args => {
        const relative = normalizePath(path.relative(root, args.path))
        const contents = snapshot.entries.get(relative)
        if (contents == null || !snapshot.graphInputs.has(relative)) {
          throw new Error(`public browser artifact requested unsnapshotted input: ${relative}`)
        }
        return { contents, loader: loaderFor(args.path), resolveDir: path.dirname(args.path) }
      })
    }
  }
}

function closedBrowserRandomBytesPlugin (snapshot) {
  return {
    name: 'hiverelay-public-browser-closed-randombytes',
    setup (builder) {
      builder.onLoad({ filter: /node_modules\/sodium-javascript\/randombytes\.js$/, namespace: 'file' }, async args => {
        const relative = normalizePath(path.relative(root, args.path))
        if (relative !== BROWSER_RANDOMBYTES_PATH) {
          throw new Error(`public browser randombytes transform reached ${relative}`)
        }
        const source = snapshot == null
          ? await fs.readFile(args.path, 'utf8')
          : b4a.toString(snapshot.entries.get(relative))
        if (source.split(NODE_RANDOMBYTES_FALLBACK).length !== 2) {
          throw new Error('public browser randombytes Node fallback source changed')
        }
        return {
          contents: source.replace(NODE_RANDOMBYTES_FALLBACK, '\n'),
          loader: 'js',
          resolveDir: path.dirname(args.path)
        }
      })
    }
  }
}

async function buildOnce (profile, snapshot = null) {
  const alias = Object.fromEntries(Object.entries(CSP_ALIASES).map(([name, relative]) => [name, absolute(relative)]))
  const result = await build({
    absWorkingDir: root,
    stdin: {
      contents: profile.entrySource,
      resolveDir: packageRoot,
      sourcefile: path.basename(profile.virtualEntry),
      loader: 'js'
    },
    ...BUILD_PROFILE,
    alias,
    metafile: true,
    write: false,
    outfile: profile.identity.artifactPath,
    logLevel: 'silent',
    plugins: [
      closedBrowserRandomBytesPlugin(snapshot),
      ...(snapshot == null ? [] : [frozenSourcePlugin(snapshot)])
    ]
  })
  if (result.outputFiles.length !== 1) throw new Error(`${profile.identity.id} build did not produce one output`)
  const artifactBytes = b4a.from(result.outputFiles[0].contents)
  const graph = assertClosedGraph(profile, result.metafile, artifactBytes)
  return Object.freeze({ artifactBytes, graph, metafile: result.metafile })
}

async function addSnapshotFile (entries, relative) {
  relative = normalizePath(relative)
  if (relative.startsWith('packages/blind-client/browser-artifacts/') ||
      relative.startsWith('packages/blind-client-public-browser/browser-artifacts/')) {
    throw new Error(`generated artifact is forbidden from source closure: ${relative}`)
  }
  const content = b4a.from(await fs.readFile(absolute(relative)))
  const prior = entries.get(relative)
  if (prior != null && !b4a.equals(prior, content)) {
    throw new Error(`source changed while snapshotting ${relative}`)
  }
  entries.set(relative, content)
}

async function sourceSnapshot (discoveries) {
  const entries = new Map()
  const graphInputs = new Set()
  for (const [profileId, discovery] of Object.entries(discoveries)) {
    const profile = PROFILE_CONFIG[profileId]
    for (const input of discovery.graph.inputs) {
      graphInputs.add(input.path)
      if (input.path === profile.virtualEntry) {
        entries.set(input.path, b4a.from(profile.entrySource))
        continue
      }
      await addSnapshotFile(entries, input.path)
      let directory = path.posix.dirname(input.path)
      while (directory !== '.') {
        const packageJson = path.posix.join(directory, 'package.json')
        try { await addSnapshotFile(entries, packageJson) } catch (error) {
          if (!error || error.code !== 'ENOENT') throw error
        }
        const parent = path.posix.dirname(directory)
        if (parent === directory) break
        directory = parent
      }
    }
  }
  for (const relative of FIXED_AUTHORITY_PATHS) await addSnapshotFile(entries, relative)
  return Object.freeze({ entries, graphInputs })
}

function sourceClosureBytes (snapshot, discoveries) {
  const preClosureTupleParameters = {
    schema: 'HiveRelayBlindClientPublicBrowserPreClosureTupleParametersV1',
    tupleSchema: BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT_AUTHORITY.tupleSchema,
    tupleHashDomain: BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT_AUTHORITY.tupleHashDomain,
    sourceClosureHashDomain: BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT_AUTHORITY.sourceClosureHashDomain,
    acceptedSourceCommit: BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT_AUTHORITY.acceptedSourceCommit,
    acceptedSourceTree: BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT_AUTHORITY.acceptedSourceTree,
    profiles: Object.values(PROFILE_CONFIG).map(value => ({
      profile: value.identity.profile,
      artifactHashDomain: value.identity.artifactHashDomain,
      manifestHashDomain: value.identity.manifestHashDomain,
      artifactPath: value.identity.artifactPath,
      exactSortedExports: value.identity.exactSortedExports
    })),
    toolchain: BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT_AUTHORITY.toolchain,
    buildProfile: BUILD_PROFILE,
    cspAliases: CSP_ALIASES
  }
  const entries = [...snapshot.entries].map(([entryPath, content]) => ({
    path: entryPath,
    bytes: content.byteLength,
    sha256: sha256(content)
  })).sort((left, right) => codePointCompare(left.path, right.path))
  return canonicalJson({
    schema: 'HiveRelayBlindClientPublicBrowserSourceClosureV1',
    preClosureTupleParameters,
    normalizedMetafiles: Object.fromEntries(Object.entries(discoveries).map(([id, value]) => [id, value.graph])),
    entries
  })
}

async function assertFrozenLegacyHashes () {
  for (const [relative, expected] of Object.entries(LEGACY_FROZEN_SHA256)) {
    const actual = sha256(await fs.readFile(absolute(relative)))
    if (actual !== expected) throw new Error(`frozen legacy byte changed: ${relative} ${actual}`)
  }
}

async function inventoryPath (relative) {
  const target = absolute(relative)
  let stat
  try { stat = await fs.lstat(target) } catch (error) {
    if (error && error.code === 'ENOENT') return { path: relative, type: 'absent' }
    throw error
  }
  if (stat.isSymbolicLink()) return { path: relative, type: 'symlink', target: await fs.readlink(target) }
  if (stat.isFile()) {
    const content = await fs.readFile(target)
    return { path: relative, type: 'file', bytes: content.byteLength, sha256: sha256(content) }
  }
  if (stat.isDirectory()) return { path: relative, type: 'directory' }
  return { path: relative, type: 'other', mode: stat.mode }
}

async function recursiveInventoryPaths (relative) {
  const output = [relative]
  let children
  try { children = await fs.readdir(absolute(relative), { withFileTypes: true }) } catch (error) {
    if (error && error.code === 'ENOENT') return output
    throw error
  }
  for (const child of children.sort((left, right) => codePointCompare(left.name, right.name))) {
    const childRelative = path.posix.join(relative, child.name)
    output.push(childRelative)
    if (child.isDirectory() && !child.isSymbolicLink()) {
      output.push(...(await recursiveInventoryPaths(childRelative)).slice(1))
    }
  }
  return output
}

async function protectedInventory () {
  const recursive = await recursiveInventoryPaths('packages/blind-client-public-browser')
  const temporary = await recursiveInventoryPaths('.t/seq29-browser-artifact-gates/tmp')
  const paths = [...new Set([
    ...Object.keys(LEGACY_FROZEN_SHA256),
    ...SUCCESSOR_PATHS,
    ...recursive,
    ...temporary
  ])].sort()
  return canonicalJson(await Promise.all(paths.map(inventoryPath)))
}

async function scratchInventory (tmpRoot) {
  return (await fs.readdir(tmpRoot)).filter(name => name.startsWith(LEGACY_SCRATCH_PREFIX)).sort()
}

async function inspectScratch (tmpRoot, state) {
  const matching = await scratchInventory(tmpRoot)
  if (matching.length > 1) throw new Error(`frozen v1 check created multiple scratch roots: ${matching.join(', ')}`)
  if (matching.length === 0) {
    state.activeRoot = null
    state.activeIdentity = null
    return
  }
  const scratch = path.join(tmpRoot, matching[0])
  let stat
  try { stat = await fs.lstat(scratch) } catch (error) {
    if (error && error.code === 'ENOENT') return
    throw error
  }
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('frozen v1 scratch is not a real directory')
  const real = await fs.realpath(scratch)
  if (path.dirname(real) !== await fs.realpath(tmpRoot)) throw new Error('frozen v1 scratch escaped inherited TMPDIR')
  const identity = `${stat.dev}:${stat.ino}`
  if (state.activeRoot == null) {
    state.activeRoot = matching[0]
    state.activeIdentity = identity
    state.rootAppearances++
    state.observedRoots.add(matching[0])
  } else if (state.activeRoot !== matching[0]) {
    throw new Error('frozen v1 check replaced its scratch root during execution')
  } else if (state.activeIdentity !== identity) {
    state.activeIdentity = identity
    state.rootAppearances++
  }
  let children
  try { children = await fs.readdir(scratch, { withFileTypes: true }) } catch (error) {
    if (error && error.code === 'ENOENT') return
    throw error
  }
  for (const child of children) {
    if (!child.isFile() || child.isSymbolicLink() || !LEGACY_SCRATCH_FILES.has(child.name)) {
      throw new Error(`frozen v1 scratch contains a forbidden entry: ${child.name}`)
    }
    state.observedFiles.add(child.name)
  }
  const names = children.map(child => child.name).sort()
  if (names.length === LEGACY_SCRATCH_FILES.size &&
      names.every(name => LEGACY_SCRATCH_FILES.has(name))) state.exactInventoryObserved = true
}

async function runLegacyNegative (negative) {
  const tmpRoot = process.env.TMPDIR
  if (!tmpRoot || !path.isAbsolute(tmpRoot)) throw new Error('legacy checks require an inherited absolute TMPDIR')
  if ((await scratchInventory(tmpRoot)).length !== 0) throw new Error('legacy v1 scratch inventory is not empty before check')
  const observed = {
    activeRoot: null,
    activeIdentity: null,
    rootAppearances: 0,
    observedRoots: new Set(),
    observedFiles: new Set(),
    exactInventoryObserved: false
  }
  const child = spawn(process.execPath, [absolute(negative.script), ...negative.args], {
    cwd: root,
    env: process.env,
    stdio: ['ignore', 'pipe', 'pipe']
  })
  const stdout = []
  const stderr = []
  child.stdout.on('data', value => stdout.push(b4a.from(value)))
  child.stderr.on('data', value => stderr.push(b4a.from(value)))
  let childClosed = false
  let monitoringError = null
  const monitor = (async () => {
    for (;;) {
      await inspectScratch(tmpRoot, observed)
      if (childClosed) break
      await new Promise(resolve => setImmediate(resolve))
    }
  })().catch(error => { monitoringError = error })
  const outcome = await new Promise(resolve => {
    child.once('error', error => resolve({ error, code: null, signal: null }))
    child.once('close', (code, signal) => resolve({ code, signal }))
  })
  childClosed = true
  await monitor
  if (monitoringError) throw monitoringError
  if (outcome.error) throw outcome.error
  const residue = await scratchInventory(tmpRoot)
  if (residue.length !== 0) throw new Error(`legacy check left scratch residue: ${residue.join(', ')}`)
  if (negative.scratch && (observed.rootAppearances !== 1 || observed.observedRoots.size !== 1)) {
    throw new Error('frozen v1 check did not use one exact scratch child')
  }
  if (negative.scratch) {
    exactArray([...observed.observedFiles].sort(), [...LEGACY_SCRATCH_FILES].sort(),
      'frozen v1 check did not materialize the exact three-file scratch inventory')
    if (!observed.exactInventoryObserved) {
      throw new Error('frozen v1 check never exposed the exact complete three-file scratch inventory')
    }
  }
  if (!negative.scratch && (observed.rootAppearances !== 0 ||
      observed.observedRoots.size !== 0 || observed.observedFiles.size !== 0)) {
    throw new Error(`${negative.script} wrote forbidden scratch state`)
  }
  const output = `${b4a.toString(b4a.concat(stdout))}\n${b4a.toString(b4a.concat(stderr))}`
  const exactErrorLines = output.split(/\r?\n/).filter(line => line === `Error: ${negative.message}`)
  if (outcome.code !== 1 || outcome.signal != null || exactErrorLines.length !== 1) {
    throw new Error(`legacy negative check changed: ${negative.script}`)
  }
}

async function assertLegacyNegativeBaseline () {
  await assertFrozenLegacyHashes()
  for (const negative of LEGACY_CHECKS) {
    const before = await protectedInventory()
    await runLegacyNegative(negative)
    const after = await protectedInventory()
    if (!b4a.equals(before, after)) {
      throw new Error(`legacy negative check mutated protected inventory: ${negative.script}`)
    }
    await assertFrozenLegacyHashes()
  }
}

async function compareOrWrite (relative, expected) {
  const destination = absolute(relative)
  if (checkMode) {
    let actual
    try { actual = await fs.readFile(destination) } catch (error) {
      if (error && error.code === 'ENOENT') throw new Error(`missing generated public browser artifact: ${relative}`)
      throw error
    }
    if (!b4a.equals(actual, expected)) throw new Error(`generated public browser artifact drift: ${relative}`)
    return
  }
  await fs.mkdir(path.dirname(destination), { recursive: true })
  await fs.writeFile(destination, expected, { mode: 0o644 })
}

async function assertSnapshotCurrent (snapshot) {
  for (const [relative, expected] of snapshot.entries) {
    if (relative.endsWith('.entry.mjs')) continue
    const actual = await fs.readFile(absolute(relative))
    if (!b4a.equals(actual, expected)) {
      throw new Error(`source closure changed after snapshot: ${relative}`)
    }
  }
}

async function releaseEvidenceStatus (
  profile,
  artifactBytes,
  manifestBytes,
  sourceClosureHash,
  normalizedGraphHash,
  normalizedGraphSetHash
) {
  const files = [profile.identity.chromiumEvidencePath, profile.identity.crossHostEvidencePath]
  let evidence
  try { evidence = await Promise.all(files.map(relative => fs.readFile(absolute(relative)))) } catch (error) {
    if (error && error.code === 'ENOENT') {
      return Object.freeze({
        evidenceValid: false,
        structuralEvidenceReady: false,
        releaseReady: false,
        reason: 'missing-release-evidence'
      })
    }
    throw error
  }
  try {
    const verified = verifyBlindClientPublicBrowserArtifactReleaseEvidenceV1({
      profile: profile.identity.profile,
      manifestBytes,
      artifactBytes,
      expectedManifestHash: hashBlindClientPublicBrowserArtifactManifestV1(manifestBytes),
      expectedSourceClosureHash: sourceClosureHash,
      expectedNormalizedGraphHash: normalizedGraphHash,
      expectedNormalizedGraphSetHash: normalizedGraphSetHash,
      chromiumEvidenceBytes: evidence[0],
      crossHostEvidenceBytes: evidence[1]
    })
    if (verified.evidenceValid !== true || verified.structuralEvidenceReady !== true ||
        verified.releaseReady !== false || verified.standaloneAuthority !== false ||
        verified.candidateIdentityBinding !== 'external-postcommit-final-sequence' ||
        verified.authority !== 'external-postcommit-final-sequence-required') {
      throw new Error('release evidence changed its external-only structural authority')
    }
    return Object.freeze({
      evidenceValid: true,
      structuralEvidenceReady: true,
      releaseReady: false,
      reason: null
    })
  } catch (error) {
    if (requireReleaseEvidence || ciStructuralOnly) throw error
    return Object.freeze({
      evidenceValid: false,
      structuralEvidenceReady: false,
      releaseReady: false,
      reason: error.code || 'invalid-release-evidence'
    })
  }
}

let ciInventoryBefore = null
if (ciStructuralOnly) {
  await assertCiStructuralEnvironment()
  ciInventoryBefore = await repositoryInventory()
} else {
  await assertGateEnvironment()
}

let report
try {
  await assertFrozenLegacyHashes()
  if (!generate && !ciStructuralOnly) await assertLegacyNegativeBaseline()

  const discoveries = {}
  for (const [id, profile] of Object.entries(PROFILE_CONFIG)) discoveries[id] = await buildOnce(profile)
  const snapshot = await sourceSnapshot(discoveries)
  const first = {}
  const second = {}
  for (const [id, profile] of Object.entries(PROFILE_CONFIG)) {
    first[id] = await buildOnce(profile, snapshot)
    second[id] = await buildOnce(profile, snapshot)
    if (!b4a.equals(discoveries[id].artifactBytes, first[id].artifactBytes)) {
      throw new Error(`${id} source changed while its closure was captured`)
    }
    if (JSON.stringify(discoveries[id].graph) !== JSON.stringify(first[id].graph) ||
        !b4a.equals(first[id].artifactBytes, second[id].artifactBytes) ||
        JSON.stringify(first[id].graph) !== JSON.stringify(second[id].graph)) {
      throw new Error(`${id} dual build or normalized metafile is not deterministic`)
    }
  }
  const normalizedGraphHashes = Object.freeze({
    full: hashBlindClientPublicBrowserNormalizedGraphV1({
      profileId: 'full',
      normalizedGraph: first.full.graph
    }),
    limited: hashBlindClientPublicBrowserNormalizedGraphV1({
      profileId: 'limited',
      normalizedGraph: first.limited.graph
    })
  })
  const normalizedGraphSetHash = hashBlindClientPublicBrowserNormalizedGraphSetV1(
    normalizedGraphHashes)
  const closureBytes = sourceClosureBytes(snapshot, discoveries)
  const sourceClosureHash = hashBlindClientPublicBrowserSourceClosure(closureBytes)
  await assertSnapshotCurrent(snapshot)
  report = {
    schema: 'HiveRelayBlindClientPublicBrowserArtifactGenerationV1',
    mode: generate
      ? 'generate'
      : ciStructuralOnly
        ? 'ci-structural-only'
        : 'check',
    sourceClosureHash,
    sourceClosureEntries: snapshot.entries.size,
    normalizedGraphSetHash,
    toolchain: `esbuild@${esbuildVersion}`,
    releaseReady: false,
    standaloneAuthority: false,
    authority: ciStructuralOnly
      ? 'non-authoritative-ci-signal-only'
      : 'external-postcommit-final-sequence-required',
    profiles: {}
  }
  for (const [id, profile] of Object.entries(PROFILE_CONFIG)) {
    const tuple = createBlindClientPublicBrowserArtifactTupleV1({ profile: id, sourceClosureHash })
    const manifestBytes = encodeBlindClientPublicBrowserArtifactManifestV1(
      createBlindClientPublicBrowserArtifactManifestV1({ tuple, artifactBytes: first[id].artifactBytes }))
    const manifest = decodeBlindClientPublicBrowserArtifactManifestV1(manifestBytes)
    const verified = verifyBlindClientPublicBrowserArtifactV1({
      profile: id,
      manifestBytes,
      artifactBytes: first[id].artifactBytes,
      expectedManifestHash: hashBlindClientPublicBrowserArtifactManifestV1(manifestBytes),
      expectedSourceClosureHash: sourceClosureHash,
      expectedTupleHash: manifest.tupleHash
    })
    await compareOrWrite(profile.identity.artifactPath, first[id].artifactBytes)
    await compareOrWrite(profile.identity.manifestPath, manifestBytes)
    const evidence = await releaseEvidenceStatus(
      profile,
      first[id].artifactBytes,
      manifestBytes,
      sourceClosureHash,
      normalizedGraphHashes[id],
      normalizedGraphSetHash)
    if ((requireReleaseEvidence || ciStructuralOnly) && !evidence.structuralEvidenceReady) {
      throw new Error(`${id} public browser release evidence is incomplete: ${evidence.reason}`)
    }
    const nativeAddonReachable = first[id].graph.inputs.some(input =>
      input.path.endsWith('.node') || input.path.includes('/blind-peercred/'))
    if (nativeAddonReachable) throw new Error(`${id} normalized graph reaches the native addon`)
    report.profiles[id] = {
      profile: verified.profile,
      artifactPath: verified.artifactPath,
      artifactLength: verified.artifactLength,
      artifactHash: verified.artifactHash,
      manifestPath: profile.identity.manifestPath,
      manifestHash: verified.manifestHash,
      tupleHash: verified.tupleHash,
      exactExportCount: profile.identity.exactSortedExports.length,
      metafileInputCount: first[id].graph.inputs.length,
      normalizedGraphHash: normalizedGraphHashes[id],
      nativeAddonReachable,
      nativeAddonUnreachable: !nativeAddonReachable,
      evidenceValid: evidence.evidenceValid,
      structuralEvidenceReady: evidence.structuralEvidenceReady,
      releaseReady: false,
      standaloneAuthority: false,
      authority: ciStructuralOnly
        ? 'non-authoritative-ci-signal-only'
        : 'external-postcommit-final-sequence-required'
    }
  }
  if (ciStructuralOnly) {
    report.ci = {
      repositoryInventorySha256: sha256(ciInventoryBefore),
      deterministicOutputComparisons: 4,
      structuralEvidenceInputs: 4,
      legacyNegativeChildrenExecuted: false,
      repositoryWrites: 0,
      runnerTempWrites: 0
    }
  }
  await assertFrozenLegacyHashes()
} finally {
  if (ciStructuralOnly) await assertRepositoryInventoryUnchanged(ciInventoryBefore)
}
process.stdout.write(`${JSON.stringify(report)}\n`)
