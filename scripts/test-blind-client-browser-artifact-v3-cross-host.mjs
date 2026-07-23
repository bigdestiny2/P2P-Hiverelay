#!/usr/bin/env node
import fs from 'node:fs/promises'
import path from 'node:path'
import process from 'node:process'
import { createHash } from 'node:crypto'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'

const execute = promisify(execFile)
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const image = process.env.HIVERELAY_CROSS_HOST_NODE_IMAGE || 'node:22-bookworm-slim'
const files = Object.freeze([
  'packages/blind-client/browser-artifacts/blind-client-control-v3.mjs',
  'packages/blind-client/browser-artifacts/blind-client-control-v3.manifest.cenc',
  'packages/blind-client/browser-artifacts/blind-client-control-v3.authority.json',
  'packages/blind-client/browser-artifacts/blind-client-control-v3.source-closure.json'
])

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex')

async function hashesAt (directory) {
  return Object.fromEntries(await Promise.all(files.map(async file => [
    file,
    sha256(await fs.readFile(path.join(directory, file)))
  ])))
}

const imageOutput = (await execute('docker', [
  'image', 'inspect', image, '--format', '{{.Id}} {{.Os}} {{.Architecture}}'
], { encoding: 'utf8', timeout: 30_000, maxBuffer: 1024 * 1024 })).stdout.trim()
const [imageId, imagePlatform, imageArchitecture] = imageOutput.split(' ')
if (!/^sha256:[0-9a-f]{64}$/.test(imageId) || imagePlatform !== 'linux' || !imageArchitecture) {
  throw new Error(`cross-host image inspection was not exact Linux metadata: ${imageOutput}`)
}

const localHashes = await hashesAt(root)
const containerScript = `set -eu
mkdir -p /work
cd /source
tar --exclude='./node_modules' --exclude='./.git' --exclude='./.env' --exclude='./.env.*' -cf - . | tar -xf - -C /work
cd /work
npm ci --ignore-scripts --no-audit --no-fund
node packages/blind-protocol/generate-wire-v3.mjs --check
node packages/blind-ipc/generate-private-ipc-v4.mjs --check
node packages/blind-protocol/generate-client-composition-v3.mjs --check
node packages/blind-client/generate-browser-artifact-v3.mjs --check
node -e "const fs=require('node:fs');const c=require('node:crypto');const files=JSON.parse(process.env.HIVERELAY_V3_FILES);const hashes=Object.fromEntries(files.map(file=>[file,c.createHash('sha256').update(fs.readFileSync(file)).digest('hex')]));process.stdout.write('HIVERELAY_V3_CROSS_HOST='+JSON.stringify({node:process.version,platform:process.platform,architecture:process.arch,hashes})+'\\n')"`
const run = await execute('docker', [
  'run', '--rm', '--read-only',
  '--tmpfs', '/tmp:rw,exec,nosuid,size=1024m',
  '--tmpfs', '/root/.npm:rw,exec,nosuid,size=1024m',
  '--tmpfs', '/work:rw,exec,nosuid,size=2048m',
  '--mount', `type=bind,source=${root},target=/source,readonly`,
  '--workdir', '/work',
  '--cap-drop', 'ALL',
  '--security-opt', 'no-new-privileges',
  '--env', `HIVERELAY_V3_FILES=${JSON.stringify(files)}`,
  image, 'sh', '-lc', containerScript
], {
  encoding: 'utf8',
  timeout: 10 * 60_000,
  killSignal: 'SIGKILL',
  maxBuffer: 16 * 1024 * 1024
})
const marker = run.stdout.split('\n').find(line => line.startsWith('HIVERELAY_V3_CROSS_HOST='))
if (!marker) throw new Error(`clean Linux rebuild did not emit its exact marker:\n${run.stdout}\n${run.stderr}`)
const report = JSON.parse(marker.slice('HIVERELAY_V3_CROSS_HOST='.length))
if (report.platform !== 'linux' || report.architecture !== imageArchitecture ||
    JSON.stringify(report.hashes) !== JSON.stringify(localHashes)) {
  throw new Error('clean Linux rebuild does not byte-match the checked host v3 artifact closure')
}

process.stdout.write(`${JSON.stringify({
  schema: 'HiveRelayBlindClientBrowserArtifactCrossHostGateV3',
  image,
  imageId,
  node: report.node,
  architecture: report.architecture,
  checkedFiles: files.length,
  hashes: report.hashes,
  readiness: 0,
  runtimeReady: false,
  authorizesRelease: false,
  ok: true
})}\n`)
