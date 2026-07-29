#!/usr/bin/env node
import fs from 'node:fs/promises'
import path from 'node:path'
import process from 'node:process'
import { execFile } from 'node:child_process'
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
  hashBlindClientBrowserArtifactManifest,
  verifyBlindClientBrowserArtifactV1
} from '@hiverelay/blind-client/browser-artifact'

const execute = promisify(execFile)
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const image = process.env.HIVERELAY_CROSS_HOST_NODE_IMAGE || 'node:22-bookworm-slim'
const artifactFile = path.join(
  root, 'packages/blind-client', BLIND_CLIENT_BROWSER_ARTIFACT_STATUS.artifactPath)
const manifestFile = path.join(
  root, 'packages/blind-client', BLIND_CLIENT_BROWSER_ARTIFACT_STATUS.manifestPath)
const evidenceFile = path.join(
  root, 'packages/blind-client', BLIND_CLIENT_BROWSER_ARTIFACT_STATUS.crossHostEvidencePath)
const evidenceChecks = Object.freeze([
  'CLEAN_LINUX_DEPENDENCY_INSTALL',
  'FROZEN_GENERATOR_CHECK',
  'ARTIFACT_BYTE_EQUALITY',
  'MANIFEST_BYTE_EQUALITY'
])

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

async function writeAtomic (file, bytes) {
  const temporary = `${file}.${process.pid}.tmp`
  try {
    await fs.writeFile(temporary, bytes, { mode: 0o644 })
    await fs.rename(temporary, file)
  } finally {
    await fs.rm(temporary, { force: true })
  }
}

async function inspectImage () {
  let output
  try {
    output = (await execute('docker', [
      'image', 'inspect', image, '--format', '{{.Id}} {{.Os}} {{.Architecture}}'
    ], { encoding: 'utf8', timeout: 30_000, maxBuffer: 1024 * 1024 })).stdout.trim()
  } catch (error) {
    if (process.env.HIVERELAY_CROSS_HOST_ALLOW_PULL !== '1') {
      throw new Error(`Linux evidence image is unavailable; pull ${image} or set HIVERELAY_CROSS_HOST_ALLOW_PULL=1`,
        { cause: error })
    }
    await execute('docker', ['pull', image], {
      encoding: 'utf8', timeout: 10 * 60_000, maxBuffer: 8 * 1024 * 1024
    })
    output = (await execute('docker', [
      'image', 'inspect', image, '--format', '{{.Id}} {{.Os}} {{.Architecture}}'
    ], { encoding: 'utf8', timeout: 30_000, maxBuffer: 1024 * 1024 })).stdout.trim()
  }
  const [id, platform, architecture] = output.split(' ')
  if (!/^sha256:[0-9a-f]{64}$/.test(id) || platform !== 'linux' || !architecture) {
    throw new Error(`cross-host image inspection was not exact Linux metadata: ${output}`)
  }
  return Object.freeze({ id, platform, architecture })
}

const [artifactBytes, manifestBytes, tuple, imageMetadata] = await Promise.all([
  fs.readFile(artifactFile),
  fs.readFile(manifestFile),
  exactTuple(),
  inspectImage()
])
const manifestHash = hashBlindClientBrowserArtifactManifest(manifestBytes)
const verified = verifyBlindClientBrowserArtifactV1({
  artifactBytes,
  manifestBytes,
  expectedManifestHash: manifestHash,
  expectedTuple: tuple
})

const containerScript = `set -eu
mkdir -p /work
cd /source
tar --exclude='./node_modules' --exclude='./.git' --exclude='./.env' --exclude='./.env.*' -cf - . | tar -xf - -C /work
cd /work
npm ci --ignore-scripts --no-audit --no-fund
node scripts/generate-blind-client-browser-artifacts.mjs --check
node -e "process.stdout.write('HIVERELAY_CROSS_HOST_ENV=' + JSON.stringify({node:process.version,platform:process.platform,architecture:process.arch}) + '\\n')"`
const run = await execute('docker', [
  'run', '--rm', '--read-only',
  '--tmpfs', '/tmp:rw,exec,nosuid,size=1024m',
  '--tmpfs', '/root/.npm:rw,exec,nosuid,size=1024m',
  '--tmpfs', '/work:rw,exec,nosuid,size=2048m',
  '--mount', `type=bind,source=${root},target=/source,readonly`,
  '--workdir', '/work',
  '--cap-drop', 'ALL',
  '--security-opt', 'no-new-privileges',
  image, 'sh', '-lc', containerScript
], {
  encoding: 'utf8', timeout: 10 * 60_000, killSignal: 'SIGKILL', maxBuffer: 16 * 1024 * 1024
})
const report = run.stdout.split('\n').map(line => line.trim()).filter(Boolean)
  .map(line => {
    try { return JSON.parse(line) } catch { return null }
  }).find(value => value && value.schema === 'HiveRelayBlindClientBrowserArtifactGenerationV1')
const environmentLine = run.stdout.split('\n').find(line => line.startsWith('HIVERELAY_CROSS_HOST_ENV='))
if (!report || !environmentLine) {
  throw new Error(`clean Linux rebuild did not emit exact evidence markers:\n${run.stdout}\n${run.stderr}`)
}
const environment = JSON.parse(environmentLine.slice('HIVERELAY_CROSS_HOST_ENV='.length))
if (environment.platform !== 'linux' || environment.architecture !== imageMetadata.architecture ||
    report.artifactBytes !== verified.artifactBytes.byteLength || report.manifestHash !==
    b4a.toString(manifestHash, 'hex')) {
  throw new Error('clean Linux rebuild evidence does not bind the checked host artifact and manifest')
}

const evidence = {
  schema: 'HiveRelayBlindClientBrowserArtifactCrossHostEvidenceV1',
  version: 1,
  evidenceClass: 'clean-linux-container',
  artifactPath: BLIND_CLIENT_BROWSER_ARTIFACT_STATUS.artifactPath,
  artifactLength: verified.artifactBytes.byteLength,
  artifactHash: b4a.toString(verified.manifest.artifactHash, 'hex'),
  manifestHash: b4a.toString(manifestHash, 'hex'),
  sourceClosureHash: b4a.toString(verified.manifest.sourceClosureHash, 'hex'),
  platform: environment.platform,
  architecture: environment.architecture,
  containerImageId: imageMetadata.id,
  node: environment.node,
  toolchain: verified.manifest.toolchain,
  checks: evidenceChecks,
  passed: true
}
await writeAtomic(evidenceFile, b4a.from(JSON.stringify(evidence, null, 2) + '\n'))
process.stdout.write(`${JSON.stringify({
  schema: 'HiveRelayBlindClientBrowserArtifactCrossHostGateV1',
  image,
  imageId: imageMetadata.id,
  node: environment.node,
  architecture: environment.architecture,
  manifestHash: evidence.manifestHash,
  artifactHash: evidence.artifactHash,
  evidencePath: path.relative(root, evidenceFile).replaceAll(path.sep, '/'),
  ok: true
})}\n`)
