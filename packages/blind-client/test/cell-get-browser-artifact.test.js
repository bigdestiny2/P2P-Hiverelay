import test from 'brittle'
import fs from 'node:fs'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { gzipSync } from 'node:zlib'
import b4a from 'b4a'
import {
  hashAbi,
  hashClientCompositionFormat,
  hashClientCompositionVectorSet,
  hashSpec,
  hashVectorSet
} from '@hiverelay/blind-protocol'
import {
  BLIND_CLIENT_CELL_GET_BROWSER_ARTIFACT_STATUS,
  hashBlindClientBrowserArtifactManifest,
  verifyBlindClientBrowserArtifactReleaseEvidenceV1,
  verifyBlindClientBrowserArtifactV1
} from '../browser-artifact.js'

const artifactUrl = new URL(
  '../browser-artifacts/blind-client-cell-get-v1.mjs', import.meta.url)
const manifestUrl = new URL(
  '../browser-artifacts/blind-client-cell-get-v1.manifest.cenc', import.meta.url)
const chromiumEvidenceUrl = new URL(
  '../browser-artifacts/blind-client-cell-get-v1.chromium-evidence.json', import.meta.url)
const crossHostEvidenceUrl = new URL(
  '../browser-artifacts/blind-client-cell-get-v1.cross-host-evidence.json', import.meta.url)
const generatorUrl = new URL(
  '../../../scripts/generate-blind-client-browser-artifacts.mjs', import.meta.url)
const packageUrl = new URL('../package.json', import.meta.url)
const rootPackageUrl = new URL('../../../package.json', import.meta.url)
const artifactBytes = fs.readFileSync(artifactUrl)
const manifestBytes = fs.readFileSync(manifestUrl)
const expectedManifestHash = hashBlindClientBrowserArtifactManifest(manifestBytes)
const expectedTuple = Object.freeze({
  specHash: hashSpec(fs.readFileSync(new URL(
    '../../../docs/protocol/HIVERELAY-BLIND-WIRE-V1.md', import.meta.url))),
  abiHash: hashAbi(fs.readFileSync(new URL(
    '../../blind-protocol/hiverelay-blind-abi-v1.cenc', import.meta.url))),
  vectorSetHash: hashVectorSet(fs.readFileSync(new URL(
    '../../blind-protocol/vector-manifest-v1.cenc', import.meta.url))),
  clientCompositionFormatHash: hashClientCompositionFormat(fs.readFileSync(new URL(
    '../../blind-protocol/hiverelay-blind-client-composition-format-v1.cenc', import.meta.url))),
  clientCompositionVectorSetHash: hashClientCompositionVectorSet(fs.readFileSync(new URL(
    '../../blind-protocol/hiverelay-blind-client-composition-vector-manifest-v1.cenc', import.meta.url)))
})
const exactExports = Object.freeze([
  'createBlindCellGetControl',
  'createBrowserCryptoRuntime'
])

test('checked Cell-GET browser artifact is exact, narrow, and release-qualified', async t => {
  const verified = verifyBlindClientBrowserArtifactV1({
    artifactBytes,
    manifestBytes,
    expectedManifestHash,
    expectedTuple
  })
  t.is(verified.manifest.artifactPath,
    BLIND_CLIENT_CELL_GET_BROWSER_ARTIFACT_STATUS.artifactPath)
  t.ok(artifactBytes.byteLength <=
    BLIND_CLIENT_CELL_GET_BROWSER_ARTIFACT_STATUS.maxArtifactBytes)
  t.ok(gzipSync(artifactBytes).byteLength <=
    BLIND_CLIENT_CELL_GET_BROWSER_ARTIFACT_STATUS.maxArtifactGzipBytes)

  const browser = await import(`${artifactUrl.href}?test=${Date.now()}`)
  t.alike(Object.keys(browser), exactExports)
  for (const name of exactExports) {
    t.is(typeof browser[name], 'function', name)
  }
  const artifactText = b4a.toString(artifactBytes, 'utf8')
  for (const token of [
    'BlindForwardRouteHopV1', 'BlindForwardRouteScopeV1',
    'acceptedRouteScopeHash', 'parentRouteScopeHash',
    'createCellReplica', 'createPutCellRequest', 'PutCellV1',
    'VerifiedOperationResult'
  ]) t.absent(artifactText.includes(token), `${token} is absent`)

  let fetches = 0
  const control = browser.createBlindCellGetControl({
    runtime: {
      randomBytes: length => b4a.alloc(length, 0x51),
      aes256GcmEncrypt: async () => b4a.alloc(16),
      aes256GcmDecrypt: async () => b4a.alloc(1)
    },
    nowEpoch: () => 7,
    supportedProtocolProfiles: [{
      protocolId: 1,
      major: 1,
      minimumMinor: 0,
      profileHash: b4a.alloc(32, 0x0a)
    }],
    supportedTransportProfiles: [{
      transportId: 1,
      transportSupportBit: 1,
      transportProfileHash: b4a.alloc(32, 0x0b)
    }],
    fetch: async () => {
      fetches++
      throw new Error('must not dial')
    }
  })
  await t.exception(control.qualifyCellGetCandidate({}, { operationId: 1 }), /cannot select/)
  await t.exception(control.readCell({ familyId: 2 }), /cannot select/)
  t.is(fetches, 0, 'non-GET selection is impossible before transport')

  const status = verifyBlindClientBrowserArtifactReleaseEvidenceV1({
    artifactBytes,
    manifestBytes,
    expectedManifestHash,
    expectedTuple,
    chromiumEvidenceBytes: fs.readFileSync(chromiumEvidenceUrl),
    crossHostEvidenceBytes: fs.readFileSync(crossHostEvidenceUrl)
  })
  t.is(status.releaseReady, true)
  t.is(status.realBrowserImportProven, true)
  t.is(status.crossHostByteEqualityProven, true)
  t.alike(status.releaseBlockers, [])
})

test('Cell-GET artifact generator and package boundary are exact', t => {
  const generated = spawnSync(process.execPath, [
    fileURLToPath(generatorUrl),
    '--cell-get-only',
    '--check',
    '--require-release-evidence'
  ], { encoding: 'utf8' })
  t.is(generated.status, 0, generated.stderr)
  const report = JSON.parse(generated.stdout)
  t.is(report.artifactProfile, 'cell-get-only-v1')
  t.is(report.releaseReady, true)
  t.is(report.manifestHash, b4a.toString(expectedManifestHash, 'hex'))

  const packageJson = JSON.parse(fs.readFileSync(packageUrl, 'utf8'))
  for (const relative of [
    'blind-client-cell-get-v1.mjs',
    'blind-client-cell-get-v1.manifest.cenc',
    'blind-client-cell-get-v1.chromium-evidence.json',
    'blind-client-cell-get-v1.cross-host-evidence.json'
  ]) {
    const subpath = `./browser-artifacts/${relative}`
    t.is(packageJson.exports[subpath], subpath)
    const resolved = fileURLToPath(import.meta.resolve(`@hiverelay/blind-client/${subpath.slice(2)}`))
    t.is(path.basename(resolved), relative)
  }
  t.is(packageJson.exports['./cell-get-control'], './cell-get-control.js')

  const rootPackage = JSON.parse(fs.readFileSync(rootPackageUrl, 'utf8'))
  t.is(rootPackage.scripts['generate:blind-client:cell-get-browser-artifact'],
    'node scripts/generate-blind-client-browser-artifacts.mjs --cell-get-only')
  t.is(rootPackage.scripts['verify:blind-client:cell-get-browser-artifact:release'],
    'node scripts/generate-blind-client-browser-artifacts.mjs --cell-get-only --check --require-release-evidence')
})
