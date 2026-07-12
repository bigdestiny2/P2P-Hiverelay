import test from 'brittle'
import fs from 'node:fs'
import os from 'node:os'
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
  BLIND_CLIENT_BROWSER_ARTIFACT_STATUS,
  decodeBlindClientBrowserArtifactManifestV1,
  encodeBlindClientBrowserArtifactManifestV1,
  hashBlindClientBrowserArtifactManifest,
  verifyBlindClientBrowserArtifactReleaseEvidenceV1,
  verifyBlindClientBrowserArtifactV1
} from '../browser-artifact.js'

const artifactUrl = new URL('../browser-artifacts/blind-client-control-v1.mjs', import.meta.url)
const manifestUrl = new URL('../browser-artifacts/blind-client-control-v1.manifest.cenc', import.meta.url)
const chromiumEvidenceUrl = new URL(
  '../browser-artifacts/blind-client-control-v1.chromium-evidence.json', import.meta.url)
const crossHostEvidenceUrl = new URL(
  '../browser-artifacts/blind-client-control-v1.cross-host-evidence.json', import.meta.url)
const artifactBytes = fs.readFileSync(artifactUrl)
const manifestBytes = fs.readFileSync(manifestUrl)
const packageUrl = new URL('../package.json', import.meta.url)
const rootPackageUrl = new URL('../../../package.json', import.meta.url)
const eslintIgnoreUrl = new URL('../../../.eslintignore', import.meta.url)
const generatorUrl = new URL('../../../scripts/generate-blind-client-browser-artifacts.mjs', import.meta.url)
const expectedManifestHash = hashBlindClientBrowserArtifactManifest(manifestBytes)
const expectedTuple = Object.freeze({
  specHash: hashSpec(fs.readFileSync(new URL('../../../docs/protocol/HIVERELAY-BLIND-WIRE-V1.md', import.meta.url))),
  abiHash: hashAbi(fs.readFileSync(new URL('../../blind-protocol/hiverelay-blind-abi-v1.cenc', import.meta.url))),
  vectorSetHash: hashVectorSet(fs.readFileSync(new URL('../../blind-protocol/vector-manifest-v1.cenc', import.meta.url))),
  clientCompositionFormatHash: hashClientCompositionFormat(fs.readFileSync(
    new URL('../../blind-protocol/hiverelay-blind-client-composition-format-v1.cenc', import.meta.url))),
  clientCompositionVectorSetHash: hashClientCompositionVectorSet(fs.readFileSync(
    new URL('../../blind-protocol/hiverelay-blind-client-composition-vector-manifest-v1.cenc', import.meta.url)))
})

function changed (value, offset) {
  const output = b4a.from(value)
  output[offset] ^= 1
  return output
}

function throwsCode (t, operation, code) {
  try {
    operation()
    t.fail(`expected ${code}`)
  } catch (error) {
    t.is(error.code, code)
  }
}

function decodedManifest () {
  return decodeBlindClientBrowserArtifactManifestV1(manifestBytes)
}

function manifestInput (overrides = {}) {
  const value = decodedManifest()
  return {
    ...value,
    specHash: b4a.from(value.specHash),
    abiHash: b4a.from(value.abiHash),
    vectorSetHash: b4a.from(value.vectorSetHash),
    clientCompositionFormatHash: b4a.from(value.clientCompositionFormatHash),
    clientCompositionVectorSetHash: b4a.from(value.clientCompositionVectorSetHash),
    sourceClosureHash: b4a.from(value.sourceClosureHash),
    artifactHash: b4a.from(value.artifactHash),
    ...overrides
  }
}

test('checked browser control artifact is deterministic, tuple-bound, and importable', async t => {
  const verified = verifyBlindClientBrowserArtifactV1({
    artifactBytes,
    manifestBytes,
    expectedManifestHash,
    expectedTuple
  })
  t.is(verified.manifest.draft, false)
  t.is(verified.manifest.artifactLength, BigInt(artifactBytes.byteLength))
  t.is(verified.manifest.artifactPath, BLIND_CLIENT_BROWSER_ARTIFACT_STATUS.artifactPath)
  t.ok(b4a.equals(encodeBlindClientBrowserArtifactManifestV1(verified.manifest), manifestBytes))
  t.ok(artifactBytes.byteLength <= BLIND_CLIENT_BROWSER_ARTIFACT_STATUS.maxArtifactBytes)
  t.ok(gzipSync(artifactBytes).byteLength <= BLIND_CLIENT_BROWSER_ARTIFACT_STATUS.maxArtifactGzipBytes)
  const exposedManifest = verified.manifest
  const exposedArtifact = verified.artifactBytes
  exposedManifest.specHash[0] ^= 1
  exposedManifest.clientCompositionFormatHash[0] ^= 1
  exposedArtifact[0] ^= 1
  t.ok(b4a.equals(verified.manifest.specHash, expectedTuple.specHash), 'verified manifest has no mutable alias')
  t.ok(b4a.equals(verified.manifest.clientCompositionFormatHash,
    expectedTuple.clientCompositionFormatHash), 'verified client-composition tuple has no mutable alias')
  t.ok(b4a.equals(verified.artifactBytes, artifactBytes), 'verified artifact has no mutable alias')
  const artifactText = b4a.toString(artifactBytes)
  t.absent(artifactText.includes(fileURLToPath(new URL('../../../', import.meta.url))), 'workspace path is absent')
  t.absent(artifactText.includes('blind-client-control-browser-entry.mjs'), 'virtual build path is absent')
  for (const forbidden of [
    'INTERNAL_STORE', 'CLIENT_EXAMPLE', 'BlindStoreManifestV1', 'BlindBackupManifestV1',
    'Peerit', 'OutboxLog', 'BlindShard', 'EXECUTABLE_SCHEMA_CODECS'
  ]) {
    t.absent(artifactText.toLowerCase().includes(forbidden.toLowerCase()),
      `${forbidden} is absent from the standalone browser artifact`)
  }
  const browser = await import(`${artifactUrl.href}?test=${Date.now()}`)
  for (const name of [
    'BlindDescriptorBootstrapHttpClient',
    'BlindDirectHttpClient',
    'BlindRelayQualifier',
    'DescriptorTrustStore',
    'createBrowserCryptoRuntime',
    'createCellReplica',
    'decodeBlindExternalProfileValueV1',
    'trustedAdmissionProfile',
    'trustedDescriptorValidity',
    'verifiedAdmissionParametersValidity',
    'verifiedEndpointContext',
    'verifiedHealthValidity',
    'verifyAdmissionParametersBytes',
    'verifyOperationResult'
  ]) t.is(typeof browser[name], 'function', name)
  t.alike(Object.keys(browser).filter(name => name.includes('ExternalProfile')),
    ['decodeBlindExternalProfileValueV1'], 'the external-profile schema selector is one closed API')
  for (const hidden of [
    'decodeCanonical', 'encodeCanonical', 'readCellCapV1', 'blindReceiptV1',
    'EXECUTABLE_SCHEMA_CODECS'
  ]) t.is(browser[hidden], undefined, `${hidden} is not exported`)

  const readCap = b4a.concat([
    b4a.from([1]),
    b4a.alloc(32, 0x41),
    b4a.alloc(32, 0x42),
    b4a.alloc(32, 0x43),
    b4a.from([1, 1]),
    b4a.alloc(32, 0x44)
  ])
  const decoded = browser.decodeBlindExternalProfileValueV1('ReadCellCapV1', readCap)
  t.is(decoded.sizeClass, 1)
  t.ok(Object.isFrozen(decoded))
  const relayPublicKey = b4a.from(decoded.relayPublicKey)
  readCap.fill(0)
  t.ok(b4a.equals(decoded.relayPublicKey, relayPublicKey), 'browser decoder snapshots caller bytes')
  throwsCode(t, () => browser.decodeBlindExternalProfileValueV1(
    'WriteCellCapV1', b4a.alloc(131)), 'BAD_ENCODING')
})

test('artifact, manifest, tuple, and expected-manifest substitution fail closed', t => {
  for (const offset of [0, Math.floor(artifactBytes.byteLength / 2), artifactBytes.byteLength - 1]) {
    throwsCode(t, () => verifyBlindClientBrowserArtifactV1({
      artifactBytes: changed(artifactBytes, offset),
      manifestBytes,
      expectedManifestHash,
      expectedTuple
    }), 'BLIND_CLIENT_BROWSER_ARTIFACT_DRIFT')
  }
  for (let offset = 0; offset < manifestBytes.byteLength; offset++) {
    throwsCode(t, () => verifyBlindClientBrowserArtifactV1({
      artifactBytes,
      manifestBytes: changed(manifestBytes, offset),
      expectedManifestHash,
      expectedTuple
    }), 'BLIND_CLIENT_BROWSER_MANIFEST_DRIFT')
  }
  throwsCode(t, () => verifyBlindClientBrowserArtifactV1({
    artifactBytes,
    manifestBytes,
    expectedManifestHash: changed(expectedManifestHash, 0),
    expectedTuple
  }), 'BLIND_CLIENT_BROWSER_MANIFEST_DRIFT')
  throwsCode(t, () => verifyBlindClientBrowserArtifactV1({
    artifactBytes,
    manifestBytes,
    expectedManifestHash,
    expectedTuple: { ...expectedTuple, abiHash: changed(expectedTuple.abiHash, 0) }
  }), 'BLIND_CLIENT_BROWSER_TUPLE_MISMATCH')
  throwsCode(t, () => verifyBlindClientBrowserArtifactV1({
    artifactBytes,
    manifestBytes,
    expectedManifestHash,
    expectedTuple: {
      ...expectedTuple,
      clientCompositionFormatHash: changed(expectedTuple.clientCompositionFormatHash, 0)
    }
  }), 'BLIND_CLIENT_BROWSER_TUPLE_MISMATCH')
})

test('browser artifact manifest and verification inputs are exact and canonical', t => {
  for (let length = 0; length < manifestBytes.byteLength; length++) {
    throwsCode(t, () => decodeBlindClientBrowserArtifactManifestV1(
      manifestBytes.subarray(0, length)), 'BAD_BLIND_CLIENT_BROWSER_ARTIFACT')
  }
  throwsCode(t, () => decodeBlindClientBrowserArtifactManifestV1(
    b4a.concat([manifestBytes, b4a.from([0])])), 'BAD_BLIND_CLIENT_BROWSER_ARTIFACT')
  const magic = b4a.from('HIVERELAY-BLIND-CLIENT-BROWSER-V1', 'ascii')
  for (const offset of [0, magic.byteLength, magic.byteLength + 1]) {
    throwsCode(t, () => decodeBlindClientBrowserArtifactManifestV1(
      changed(manifestBytes, offset)), 'BAD_BLIND_CLIENT_BROWSER_ARTIFACT')
  }
  const toolchainOffset = manifestBytes.indexOf(b4a.from(decodedManifest().toolchain))
  const invalidUtf8 = b4a.from(manifestBytes)
  invalidUtf8[toolchainOffset] = 0xff
  throwsCode(t, () => decodeBlindClientBrowserArtifactManifestV1(
    invalidUtf8), 'BAD_BLIND_CLIENT_BROWSER_ARTIFACT')
  const zeroLength = b4a.from(manifestBytes)
  zeroLength.fill(0, zeroLength.byteLength - 40, zeroLength.byteLength - 32)
  throwsCode(t, () => decodeBlindClientBrowserArtifactManifestV1(
    zeroLength), 'BAD_BLIND_CLIENT_BROWSER_ARTIFACT')

  for (const artifactLength of ['1', 1.5, NaN, {}, 0n, 327681n]) {
    throwsCode(t, () => encodeBlindClientBrowserArtifactManifestV1(
      manifestInput({ artifactLength })), 'BAD_BLIND_CLIENT_BROWSER_ARTIFACT')
  }
  throwsCode(t, () => encodeBlindClientBrowserArtifactManifestV1(manifestInput({
    artifactPath: 'browser-artifacts/other.mjs'
  })), 'BAD_BLIND_CLIENT_BROWSER_ARTIFACT')
  const inherited = manifestInput()
  Object.setPrototypeOf(inherited, { injected: true })
  throwsCode(t, () => encodeBlindClientBrowserArtifactManifestV1(
    inherited), 'BAD_BLIND_CLIENT_BROWSER_ARTIFACT')
  const symbol = manifestInput()
  symbol[Symbol('hidden')] = true
  throwsCode(t, () => encodeBlindClientBrowserArtifactManifestV1(
    symbol), 'BAD_BLIND_CLIENT_BROWSER_ARTIFACT')
  const accessor = manifestInput()
  Object.defineProperty(accessor, 'toolchain', {
    enumerable: true,
    get () { return decodedManifest().toolchain }
  })
  throwsCode(t, () => encodeBlindClientBrowserArtifactManifestV1(
    accessor), 'BAD_BLIND_CLIENT_BROWSER_ARTIFACT')
  t.ok(b4a.equals(encodeBlindClientBrowserArtifactManifestV1(manifestInput({
    artifactLength: artifactBytes.byteLength
  })), manifestBytes), 'safe integer length canonicalizes to the exact u64 wire form')

  throwsCode(t, () => verifyBlindClientBrowserArtifactV1({
    artifactBytes,
    manifestBytes,
    expectedManifestHash,
    expectedTuple,
    extra: true
  }), 'BAD_BLIND_CLIENT_BROWSER_ARTIFACT')
  throwsCode(t, () => verifyBlindClientBrowserArtifactV1({
    artifactBytes,
    manifestBytes,
    expectedManifestHash,
    expectedTuple: { ...expectedTuple, extra: true }
  }), 'BAD_BLIND_CLIENT_BROWSER_ARTIFACT')
})

test('browser artifact stays package-addressable while candidate authority blocks regeneration', t => {
  const generated = spawnSync(process.execPath, [fileURLToPath(generatorUrl), '--check'], {
    cwd: os.tmpdir(),
    encoding: 'utf8'
  })
  t.is(generated.status, 1)
  t.ok(generated.stderr.includes('browser artifact tuple authority is stale'))
  t.ok(generated.stderr.includes('BlindForwardRouteScopeV1'))
  const resolvedArtifact = fileURLToPath(import.meta.resolve(
    '@hiverelay/blind-client/browser-artifacts/blind-client-control-v1.mjs'))
  const resolvedManifest = fileURLToPath(import.meta.resolve(
    '@hiverelay/blind-client/browser-artifacts/blind-client-control-v1.manifest.cenc'))
  const resolvedChromiumEvidence = fileURLToPath(import.meta.resolve(
    '@hiverelay/blind-client/browser-artifacts/blind-client-control-v1.chromium-evidence.json'))
  const resolvedCrossHostEvidence = fileURLToPath(import.meta.resolve(
    '@hiverelay/blind-client/browser-artifacts/blind-client-control-v1.cross-host-evidence.json'))
  t.is(fs.realpathSync(resolvedArtifact), fs.realpathSync(fileURLToPath(artifactUrl)))
  t.is(fs.realpathSync(resolvedManifest), fs.realpathSync(fileURLToPath(manifestUrl)))
  t.is(fs.realpathSync(resolvedChromiumEvidence), fs.realpathSync(fileURLToPath(chromiumEvidenceUrl)))
  t.is(fs.realpathSync(resolvedCrossHostEvidence), fs.realpathSync(fileURLToPath(crossHostEvidenceUrl)))
  const packageJson = JSON.parse(fs.readFileSync(packageUrl, 'utf8'))
  t.is(packageJson.exports['./browser-artifacts/blind-client-control-v1.mjs'],
    './browser-artifacts/blind-client-control-v1.mjs')
  t.is(packageJson.exports['./browser-artifacts/blind-client-control-v1.manifest.cenc'],
    './browser-artifacts/blind-client-control-v1.manifest.cenc')
  t.is(packageJson.exports['./browser-artifacts/blind-client-control-v1.chromium-evidence.json'],
    './browser-artifacts/blind-client-control-v1.chromium-evidence.json')
  t.is(packageJson.exports['./browser-artifacts/blind-client-control-v1.cross-host-evidence.json'],
    './browser-artifacts/blind-client-control-v1.cross-host-evidence.json')
  t.ok(packageJson.files.includes('browser-artifacts/'))
  t.is(path.basename(resolvedArtifact), 'blind-client-control-v1.mjs')
})

test('ordinary style lint excludes only the generated bundle and retains dedicated byte verification', t => {
  const ignored = fs.readFileSync(eslintIgnoreUrl, 'utf8').split(/\r?\n/).filter(Boolean)
  t.alike(ignored, ['packages/blind-client/browser-artifacts/blind-client-control-v1.mjs'])
  const rootPackage = JSON.parse(fs.readFileSync(rootPackageUrl, 'utf8'))
  t.is(rootPackage.scripts['generate:blind-client:browser-artifact'],
    'node scripts/generate-blind-client-browser-artifacts.mjs')
  t.is(rootPackage.scripts['verify:blind-client:browser-artifact'],
    'node scripts/generate-blind-client-browser-artifacts.mjs --check')
})

test('browser production closure has no broad registry edge', t => {
  const clientRoot = fileURLToPath(new URL('..', import.meta.url))
  const protocolRoot = fileURLToPath(new URL('../../blind-protocol', import.meta.url))
  const sources = [
    ...fs.readdirSync(clientRoot).filter(name => name.endsWith('.js'))
      .map(name => path.join(clientRoot, name)),
    ...[
      'client-composition-external-codecs.js', 'codec.js', 'dispatch.js', 'errors.js',
      'external-profile-decoder.js', 'hashes.js', 'outer-envelope.js',
      'result-binding.js', 'schema-catalog-runtime-authority.js', 'schemas.js',
      'wire-runtime-authority.js'
    ].map(name => path.join(protocolRoot, name))
  ]
  for (const source of sources) {
    const text = fs.readFileSync(source, 'utf8')
    t.absent(text.includes("blind-protocol/registry'"), `${path.basename(source)} avoids package registry`)
    t.absent(text.includes("from './registry.js'"), `${path.basename(source)} avoids local registry`)
  }
})

test('browser artifact static status is fail closed until exact external evidence is verified', t => {
  t.is(BLIND_CLIENT_BROWSER_ARTIFACT_STATUS.tupleBound, true)
  t.is(BLIND_CLIENT_BROWSER_ARTIFACT_STATUS.sourceClosureBound, true)
  t.is(BLIND_CLIENT_BROWSER_ARTIFACT_STATUS.deterministicGeneratorReady, true)
  t.is(BLIND_CLIENT_BROWSER_ARTIFACT_STATUS.sameHostByteEqualityProven, true)
  t.is(BLIND_CLIENT_BROWSER_ARTIFACT_STATUS.crossHostByteEqualityProven, false)
  t.is(BLIND_CLIENT_BROWSER_ARTIFACT_STATUS.realBrowserImportProven, false)
  t.is(BLIND_CLIENT_BROWSER_ARTIFACT_STATUS.packageSubpathsExported, true)
  t.is(BLIND_CLIENT_BROWSER_ARTIFACT_STATUS.maxArtifactBytes, 320 * 1024)
  t.is(BLIND_CLIENT_BROWSER_ARTIFACT_STATUS.maxArtifactGzipBytes, 90 * 1024)
  t.is(BLIND_CLIENT_BROWSER_ARTIFACT_STATUS.finalTupleBound, true)
  t.is(BLIND_CLIENT_BROWSER_ARTIFACT_STATUS.clientCompositionTupleBound, true)
  t.is(BLIND_CLIENT_BROWSER_ARTIFACT_STATUS.releaseReady, false)
  t.alike(BLIND_CLIENT_BROWSER_ARTIFACT_STATUS.releaseBlockers, [
    'REAL_CHROMIUM_HASH_BOUND_EVIDENCE_NOT_VERIFIED',
    'CROSS_HOST_HASH_BOUND_EVIDENCE_NOT_VERIFIED'
  ])
})

test('checked Chromium and clean-Linux records release the exact artifact only', t => {
  const chromiumEvidenceBytes = fs.readFileSync(chromiumEvidenceUrl)
  const crossHostEvidenceBytes = fs.readFileSync(crossHostEvidenceUrl)
  const status = verifyBlindClientBrowserArtifactReleaseEvidenceV1({
    artifactBytes,
    manifestBytes,
    expectedManifestHash,
    expectedTuple,
    chromiumEvidenceBytes,
    crossHostEvidenceBytes
  })
  t.is(status.releaseReady, true)
  t.is(status.realBrowserImportProven, true)
  t.is(status.crossHostByteEqualityProven, true)
  t.alike(status.releaseBlockers, [])
  t.is(status.artifactHash, b4a.toString(decodedManifest().artifactHash, 'hex'))
  t.is(status.manifestHash, b4a.toString(expectedManifestHash, 'hex'))

  for (const [field, value] of [
    ['chromiumEvidenceBytes', chromiumEvidenceBytes],
    ['crossHostEvidenceBytes', crossHostEvidenceBytes]
  ]) {
    const changedValue = JSON.parse(b4a.toString(value, 'utf8'))
    changedValue.artifactHash = `${changedValue.artifactHash[0] === '0' ? '1' : '0'}${changedValue.artifactHash.slice(1)}`
    const changedEvidence = b4a.from(`${JSON.stringify(changedValue, null, 2)}\n`, 'utf8')
    throwsCode(t, () => verifyBlindClientBrowserArtifactReleaseEvidenceV1({
      artifactBytes,
      manifestBytes,
      expectedManifestHash,
      expectedTuple,
      chromiumEvidenceBytes,
      crossHostEvidenceBytes,
      [field]: changedEvidence
    }), 'BLIND_CLIENT_BROWSER_RELEASE_EVIDENCE_MISMATCH')
  }
  throwsCode(t, () => verifyBlindClientBrowserArtifactReleaseEvidenceV1({
    artifactBytes: changed(artifactBytes, 0),
    manifestBytes,
    expectedManifestHash,
    expectedTuple,
    chromiumEvidenceBytes,
    crossHostEvidenceBytes
  }), 'BLIND_CLIENT_BROWSER_ARTIFACT_DRIFT')
})
