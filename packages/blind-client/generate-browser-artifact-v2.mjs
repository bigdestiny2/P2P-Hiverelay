import fs from 'node:fs/promises'
import path from 'node:path'
import process from 'node:process'
import { createHash } from 'node:crypto'
import b4a from 'b4a'
import { hashAbi, hashClientCompositionFormat } from '@hiverelay/blind-protocol/hashes'
import {
  hashBlindClientBrowserArtifact,
  hashBlindClientBrowserArtifactManifest
} from './browser-artifact.js'
import {
  encodeBlindClientBrowserArtifactManifestV2,
  hashBlindClientBrowserArtifactManifestV2,
  hashBlindClientBrowserArtifactV2,
  hashBlindClientBrowserSourceClosureV2
} from './browser-artifact-v2.js'

const check = process.argv.includes('--check')
const packageRoot = path.dirname(new URL(import.meta.url).pathname)
const repoRoot = path.resolve(packageRoot, '../..')
const protocolRoot = path.resolve(packageRoot, '../blind-protocol')
const artifactRoot = path.join(packageRoot, 'browser-artifacts')
const hex = value => b4a.toString(value, 'hex')
const json = value => b4a.from(`${JSON.stringify(value, null, 2)}\n`)

const compatibilityFloor = Object.freeze({
  'blind-client-control-v1.mjs': '10425bb00fb8045e63ce2869b5e6bf88af39dc0723963203a6b021e0fd28090a',
  'blind-client-control-v1.manifest.cenc': '76a7ea97db644971203c2f94c476614a95b0320980a58504b927f04b152aadf1',
  'blind-client-control-v1.chromium-evidence.json': '1382b24b21cae661392a199b0470a22768b85f62215db6fb943ed17b66859c2e',
  'blind-client-control-v1.cross-host-evidence.json': '3cfd3c12a7664899a0901eff7b613f85da6fd039b930f74ade5bc820d215dcd2'
})

function sha256 (bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

async function assertCompatibilityFloor () {
  for (const [relative, expected] of Object.entries(compatibilityFloor)) {
    const actual = sha256(await fs.readFile(path.join(artifactRoot, relative)))
    if (actual !== expected) throw new Error(`frozen browser v1 artifact changed: ${relative} ${actual}`)
  }
}

async function writeOrCheck (file, bytes) {
  if (!b4a.isBuffer(bytes)) bytes = b4a.from(bytes)
  if (check) {
    let current
    try {
      current = await fs.readFile(file)
    } catch {
      throw new Error(`missing generated browser v2 artifact: ${path.relative(repoRoot, file)}`)
    }
    if (!b4a.equals(current, bytes)) throw new Error(`stale generated browser v2 artifact: ${path.relative(repoRoot, file)}`)
    return
  }
  await fs.mkdir(path.dirname(file), { recursive: true })
  await fs.writeFile(file, bytes)
}

function artifactSource (wireV2AbiHash, compositionV2FormatHash) {
  const authority = {
    profile: 'blind-client-control-v2',
    wireV2AbiHash,
    clientCompositionV2FormatHash: compositionV2FormatHash,
    releaseProfileId: 2,
    routeKind: 7,
    exactRequestBytes: 65_536,
    exactResultBytes: 65_536,
    forwardDescriptorOperationBits: 0,
    forwardAdvertisedOperationBits: 0,
    forwardReadinessOperationBits: 0,
    runtimeReady: false
  }
  return '/* eslint-disable */\nexport * from \'./blind-client-control-v1.mjs\'\n' +
    `export const BLIND_CLIENT_CONTROL_V2_AUTHORITY = Object.freeze(${JSON.stringify(authority, null, 2)})\n` +
    'function bytes (value, length, field) {\n' +
    '  if (!(value instanceof ArrayBuffer) && !ArrayBuffer.isView(value)) throw new TypeError(field + \' must be ArrayBuffer-backed bytes\')\n' +
    '  const output = value instanceof ArrayBuffer ? new Uint8Array(value) : new Uint8Array(value.buffer, value.byteOffset, value.byteLength)\n' +
    '  if (output.byteLength !== length) throw new RangeError(field + \' must be exactly \' + length + \' bytes\')\n' +
    '  return new Uint8Array(output)\n' +
    '}\n' +
    'export function assertForwardHttpsBrowserCellV2 (value) {\n' +
    '  if (!value || typeof value !== \'object\') throw new TypeError(\'browser cell must be an object\')\n' +
    '  for (const field of [\'url\', \'host\', \'hostname\', \'ip\', \'ipAddress\', \'dialAddress\', \'credentials\']) {\n' +
    '    if (field in value) throw new TypeError(\'browser cell \' + field + \' is forbidden\')\n' +
    '  }\n' +
    '  if (value.releaseProfileId !== 2 || value.routeKind !== 7 || value.credentialsMode !== \'omit\' ||\n' +
    '      value.cacheMode !== \'no-store\' || value.redirectMode !== \'error\' || value.referrerPolicy !== \'no-referrer\') {\n' +
    '    throw new TypeError(\'browser cell privacy policy is invalid\')\n' +
    '  }\n' +
    '  return Object.freeze({ body: bytes(value.body, 65536, \'body\'), releaseProfileId: 2, routeKind: 7 })\n' +
    '}\n'
}

function closureBytes (entries) {
  return json(entries.map(([entryPath, content]) => ({
    path: entryPath,
    bytes: content.byteLength,
    sha256: sha256(content)
  })).sort((left, right) => left.path.localeCompare(right.path)))
}

await assertCompatibilityFloor()

const v1ArtifactBytes = await fs.readFile(path.join(artifactRoot, 'blind-client-control-v1.mjs'))
const v1ManifestBytes = await fs.readFile(path.join(artifactRoot, 'blind-client-control-v1.manifest.cenc'))
const wireV2AbiBytes = await fs.readFile(path.join(protocolRoot, 'hiverelay-blind-abi-v2.cenc'))
const compositionV2FormatBytes = await fs.readFile(path.join(protocolRoot, 'hiverelay-blind-client-composition-format-v2.cenc'))
const wireV2AbiHash = hashAbi(wireV2AbiBytes)
const compositionV2FormatHash = hashClientCompositionFormat(compositionV2FormatBytes)
const artifactBytes = b4a.from(artifactSource(hex(wireV2AbiHash), hex(compositionV2FormatHash)))

const sourcePaths = [
  'packages/blind-client/browser-artifact-v2.js',
  'packages/blind-client/generate-browser-artifact-v2.mjs',
  'packages/blind-client/browser-artifacts/blind-client-control-v1.mjs',
  'packages/blind-client/browser-artifacts/blind-client-control-v1.manifest.cenc',
  'packages/blind-protocol/hiverelay-blind-abi-v2.cenc',
  'packages/blind-protocol/hiverelay-blind-wire-authority-v2.json',
  'packages/blind-protocol/hiverelay-blind-client-composition-format-v2.cenc',
  'packages/blind-protocol/hiverelay-blind-client-composition-authority-v2.json'
]
const sourceEntries = []
for (const relative of sourcePaths) sourceEntries.push([relative, await fs.readFile(path.join(repoRoot, relative))])
const sourceClosure = closureBytes(sourceEntries)
const manifestValue = {
  version: 2,
  baseBrowserV1ArtifactHash: hashBlindClientBrowserArtifact(v1ArtifactBytes),
  baseBrowserV1ManifestHash: hashBlindClientBrowserArtifactManifest(v1ManifestBytes),
  wireV2AbiHash,
  clientCompositionV2FormatHash: compositionV2FormatHash,
  artifactHash: hashBlindClientBrowserArtifactV2(artifactBytes),
  sourceClosureHash: hashBlindClientBrowserSourceClosureV2(sourceClosure),
  exactRequestBytes: 65_536,
  exactResultBytes: 65_536,
  forwardReadinessOperationBits: 0
}
const manifestBytes = encodeBlindClientBrowserArtifactManifestV2(manifestValue)
const authority = {
  profile: 'blind-client-browser-artifact-v2',
  authorityVersion: 2,
  artifactPath: 'browser-artifacts/blind-client-control-v2.mjs',
  manifestPath: 'browser-artifacts/blind-client-control-v2.manifest.cenc',
  baseBrowserV1ArtifactHash: hex(manifestValue.baseBrowserV1ArtifactHash),
  baseBrowserV1ManifestHash: hex(manifestValue.baseBrowserV1ManifestHash),
  wireV2AbiHash: hex(wireV2AbiHash),
  clientCompositionV2FormatHash: hex(compositionV2FormatHash),
  artifactHash: hex(manifestValue.artifactHash),
  manifestHash: hex(hashBlindClientBrowserArtifactManifestV2(manifestBytes)),
  sourceClosureHash: hex(manifestValue.sourceClosureHash),
  exactRequestBytes: 65_536,
  exactResultBytes: 65_536,
  credentialMode: 'omit',
  cacheMode: 'no-store',
  redirectMode: 'error',
  referrerPolicy: 'no-referrer',
  forwardDescriptorOperationBits: 0,
  forwardAdvertisedOperationBits: 0,
  forwardReadinessOperationBits: 0,
  runtimeReady: false,
  realBrowserEvidenceAccepted: false,
  compatibilityFloor
}

const outputs = [
  [path.join(artifactRoot, 'blind-client-control-v2.mjs'), artifactBytes],
  [path.join(artifactRoot, 'blind-client-control-v2.manifest.cenc'), manifestBytes],
  [path.join(artifactRoot, 'blind-client-control-v2.authority.json'), json(authority)],
  [path.join(artifactRoot, 'blind-client-control-v2.source-closure.json'), sourceClosure]
]
for (const [file, bytes] of outputs) await writeOrCheck(file, bytes)

console.log(check ? 'browser v2 artifact verified' : 'browser v2 artifact generated')
