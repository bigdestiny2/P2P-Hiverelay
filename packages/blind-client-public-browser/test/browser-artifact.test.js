import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'brittle'
import * as full from '../src/browser-control.js'
import {
  BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT_PROFILES,
  BLIND_CLIENT_PUBLIC_BROWSER_TOOLCHAIN,
  createBlindClientPublicBrowserArtifactManifestV1,
  createBlindClientPublicBrowserNormalizedGraphDigestPreimageV1,
  createBlindClientPublicBrowserNormalizedGraphSetDigestPreimageV1,
  createBlindClientPublicBrowserArtifactTupleV1,
  encodeBlindClientPublicBrowserArtifactManifestV1,
  encodeBlindClientPublicBrowserChromiumEvidenceV1,
  encodeBlindClientPublicBrowserCrossHostEvidenceV1,
  encodeBlindClientPublicBrowserNormalizedGraphDigestPreimageV1,
  encodeBlindClientPublicBrowserNormalizedGraphSetDigestPreimageV1,
  hashBlindClientPublicBrowserArtifactManifestV1,
  hashBlindClientPublicBrowserArtifactTupleV1,
  hashBlindClientPublicBrowserNormalizedGraphSetV1,
  hashBlindClientPublicBrowserNormalizedGraphV1,
  verifyBlindClientPublicBrowserArtifactReleaseEvidenceV1,
  verifyBlindClientPublicBrowserArtifactV1
} from '../browser-artifact.js'

const here = path.dirname(fileURLToPath(import.meta.url))

const FULL_EXPORTS = Object.freeze([
  'BlindDescriptorBootstrapHttpClient',
  'BlindDirectHttpClient',
  'BlindRelayQualifier',
  'CLIENT_SELECTION_LIMITS',
  'DescriptorTrustStore',
  'DurabilityTracker',
  'DurableAttempt',
  'EncryptedIntentStore',
  'HEALTH_QUALIFICATION_LIMITS',
  'INTENT_STATE',
  'MemoryDescriptorTrustBackend',
  'MemoryIntentBackend',
  'RESULT_VERIFIER_STATUS',
  'RelayCandidatePool',
  'TrustedDescriptor',
  'VerifiedAdmissionParameters',
  'VerifiedDescriptor',
  'VerifiedEndpoint',
  'VerifiedHealth',
  'VerifiedOperationResult',
  'createAdmissionParametersRequest',
  'createAesGcmIntentSealer',
  'createAppendInboxRequest',
  'createBrowserCryptoRuntime',
  'createCellReplica',
  'createClientIntent',
  'createDescribeGetRequest',
  'createGetCellRequest',
  'createHealthChallenge',
  'createReadInboxRequest',
  'decodeBlindExternalProfileValueV1',
  'decodeClientIntent',
  'encodeClientIntent',
  'journalSignedIntent',
  'openVerifiedCellGetResult',
  'qualifyDescribeControlEndpoint',
  'qualifyRelay',
  'trustedAdmissionProfile',
  'trustedDescriptorValidity',
  'verifiedAdmissionParametersValidity',
  'verifiedEndpointContext',
  'verifiedHealthValidity',
  'verifyAdmissionParametersBytes',
  'verifyDescriptorBytes',
  'verifyHealthResultBytes',
  'verifyOperationResult'
])

test('public browser control source has the exact closed 46-export surface', t => {
  t.alike(Object.keys(full).sort(), [...FULL_EXPORTS].sort())
  t.is(new Set(FULL_EXPORTS).size, 46)

  const source = fs.readFileSync(path.join(here, '../src/browser-control.js'), 'utf8')
  t.absent(source.includes('export *'))
  t.absent(source.includes('createInboxReplica'))
  t.absent(source.includes('createWatchInboxRequest'))
  t.absent(source.includes('createRenewInboxRequest'))
  t.absent(source.includes('createCloseInboxRequest'))
  t.absent(source.includes('destroyInboxWriteCapability'))
})

test('Ubuntu CI uses distinct structural and functional non-authoritative modes', t => {
  const workflow = fs.readFileSync(path.resolve(here, '../../../.github/workflows/test.yml'), 'utf8')
  const chromiumRunner = fs.readFileSync(path.join(
    here, '../scripts/test-blind-client-public-browser-artifact-chromium.mjs'), 'utf8')
  const focused = './node_modules/.bin/brittle-node --timeout 120000 test/unit/blind-client-public-browser-artifact.test.js'
  const frozen = './node_modules/.bin/brittle-node --timeout 120000 test/unit/blind-protocol-v1-compatibility-floor.test.js'
  const structural = 'node packages/blind-client-public-browser/scripts/generate-blind-client-public-browser-artifacts.mjs --check --ci-structural-only --require-release-evidence'
  const functional = 'node packages/blind-client-public-browser/scripts/test-blind-client-public-browser-artifact-chromium.mjs --ci-functional-only'
  t.ok(workflow.indexOf(focused) < workflow.indexOf(frozen))
  t.ok(workflow.indexOf(frozen) < workflow.indexOf(structural))
  t.ok(workflow.indexOf(structural) < workflow.indexOf(functional))
  t.is(workflow.split(structural).length - 1, 1)
  t.is(workflow.split(functional).length - 1, 1)
  t.absent(workflow.includes('.t/seq29-browser-artifact-gates'))
  t.absent(workflow.includes('npm_config_devdir'))
  const tempPrefixes = chromiumRunner.match(
    /const tempPrefix = hostMode\s*\? '([^']+)'\s*: '([^']+)'/)
  t.ok(tempPrefixes, 'Chromium runner keeps mode-specific temporary custody prefixes')
  t.is(tempPrefixes[1], 'hiverelay-blind-client-public-browser-chromium-')
  t.ok(tempPrefixes[2].length <= 8, 'CI Chromium prefix is bounded for Linux SingletonSocket')
  t.ok(chromiumRunner.includes(
    'const tempParent = hostMode ? process.env.TMPDIR : process.env.RUNNER_TEMP'))
})

test('generator preserves executable browser requires and rejects forbidden runtime reachability', t => {
  const generator = fs.readFileSync(path.join(
    here, '../scripts/generate-blind-client-public-browser-artifacts.mjs'), 'utf8')
  t.absent(generator.includes('define: Object.freeze({ require:'))
  for (const required of [
    'input.endsWith(\'.node\')',
    'input.includes(\'node:\')',
    'sodium-native|bare-crypto',
    'edge.kind === \'dynamic-import\'',
    "'WebAssembly'",
    "'sha512-wasm'",
    "'blake2b-wasm'"
  ]) t.ok(generator.includes(required), required)
})

function artifactFixture (profile = 'full') {
  const identity = BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT_PROFILES[profile]
  const sourceClosureHash = '11'.repeat(32)
  const artifactBytes = Buffer.from('export const deterministic = true\n')
  const tuple = createBlindClientPublicBrowserArtifactTupleV1({ profile, sourceClosureHash })
  const manifest = createBlindClientPublicBrowserArtifactManifestV1({ tuple, artifactBytes })
  const manifestBytes = encodeBlindClientPublicBrowserArtifactManifestV1(manifest)
  return {
    profile,
    identity,
    sourceClosureHash,
    artifactBytes,
    tuple,
    tupleHash: hashBlindClientPublicBrowserArtifactTupleV1(tuple),
    manifest,
    manifestBytes,
    manifestHash: hashBlindClientPublicBrowserArtifactManifestV1(manifestBytes)
  }
}

function chromiumEvidence (fixture) {
  return {
    schema: 'HiveRelayBlindClientPublicBrowserArtifactChromiumEvidenceV1',
    version: 1,
    evidenceClass: 'real-chromium',
    profile: fixture.identity.profile,
    artifactPath: fixture.identity.artifactPath,
    artifactLength: fixture.artifactBytes.byteLength,
    artifactHash: fixture.manifest.artifactHash,
    manifestHash: fixture.manifestHash,
    tupleHash: fixture.tupleHash,
    sourceClosureHash: fixture.sourceClosureHash,
    chromium: 'Google Chrome for Testing 151.0.7922.34',
    chromiumExecutablePath: '/Users/localllm/Library/Caches/ms-playwright/chromium_headless_shell-1234/chrome-headless-shell-mac-arm64/chrome-headless-shell',
    chromiumExecutableHash: '7687bff7cb2db075f250e6d5848bbc8838cac3802ac3952a899c574f8eccab45',
    contentSecurityPolicySourceCommit: '6a8c1743d7e7ed504ccb0482f248e77d77fddca3',
    contentSecurityPolicySourcePath: 'deploy/render-security-headers.json',
    contentSecurityPolicySourceFileHash: 'e672153d1c396e617491fce64ed5472635314e20c45864e959b48e5f1b52b312',
    contentSecurityPolicy: "default-src 'self'; base-uri 'none'; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: hyper: pear:; connect-src 'self' hyper: pear: https://relay-syd.p2phiverelay.xyz https://relay-dal.p2phiverelay.xyz; frame-ancestors 'none'; form-action 'none'",
    contentSecurityPolicyHash: 'b3c81c106609f04764e531e72842dffcaf061d33263a5c24c447a9a06cd0ed6b',
    requestInventory: fixture.identity.chromiumRequestInventory,
    securityPolicyViolationCount: 0,
    errorCount: 0,
    unhandledRejectionCount: 0,
    candidateIdentityBinding: 'external-postcommit-final-sequence',
    standaloneAuthority: false,
    checks: fixture.identity.chromiumChecks,
    passed: true
  }
}

function crossHostEvidence (fixture) {
  return {
    schema: 'HiveRelayBlindClientPublicBrowserArtifactCrossHostEvidenceV1',
    version: 1,
    evidenceClass: 'clean-linux-container',
    profile: fixture.identity.profile,
    artifactPath: fixture.identity.artifactPath,
    artifactLength: fixture.artifactBytes.byteLength,
    artifactHash: fixture.manifest.artifactHash,
    manifestHash: fixture.manifestHash,
    tupleHash: fixture.tupleHash,
    sourceClosureHash: fixture.sourceClosureHash,
    acceptedSourceCommit: '1a114f64c97547cab6a18102c2ef4bff930e53ed',
    acceptedSourceTree: '5a341ba17a3d91a750cac94ba51116fe3552a6aa',
    candidateIdentityBinding: 'external-postcommit-final-sequence',
    standaloneAuthority: false,
    sourceArchiveIdentity: 'same-committed-relative-bytes',
    hostNodeExecutable: '/opt/homebrew/Cellar/node@22/22.22.0/bin/node',
    hostNodeExecutableHash: '59776c1735b2c28a28b0ae00b58bd9cbe524572e0caf62e043d5e44a62d98cce',
    hostNode: 'v22.22.0',
    hostModulesAbi: '127',
    hostNapi: '10',
    hostPlatform: 'darwin',
    hostArchitecture: 'arm64',
    headerCachePath: '/Users/localllm/Library/Caches/node-gyp/22.22.0',
    headerCacheFileCount: 2726,
    headerCacheSymlinkCount: 0,
    headerCacheDigest: 'dcd517fb9670e6192712badf0bdf1a9dfc4c8ff88887d06e4d4f4eb42e574990',
    headerCachePostflightDigest: 'dcd517fb9670e6192712badf0bdf1a9dfc4c8ff88887d06e4d4f4eb42e574990',
    headerCacheInstallVersion: '11',
    headerCacheInstallVersionHash: '25d4f2a86deb5e2574bb3210b67bb24fcc4afb19f93a7b65a057daa874a9d18e',
    headerCacheNodeHeaderPath: '/Users/localllm/Library/Caches/node-gyp/22.22.0/include/node/node.h',
    headerCacheNodeHeaderBytes: 69621,
    headerCacheNodeHeaderHash: '4da8d691b256d4bef9c0e89114645f08787dc4892eae76240d28efdf4fa55019',
    nativeAddonPath: 'packages/blind-peercred/build/Release/blind_peercred.node',
    nativeAddonPackage: '@hiverelay/blind-peercred',
    nativeAddonVersion: '1.0.0-rc.1',
    nativeAddonArchitecture: 'Mach-O 64-bit bundle arm64',
    nativeAddonHash: '22'.repeat(32),
    sourceArchiveNativeAddonEqual: true,
    containerImageId: 'sha256:813a7480f28fdadac1f7f5c824bcdad435b5bc1322a5968bbbdef8d058f9dff4',
    containerPlatform: 'linux/arm64',
    containerArchitecture: 'arm64',
    containerNode: 'v22.23.1',
    containerModulesAbi: '127',
    containerNapi: '10',
    containerRootReadOnly: true,
    containerCapabilitiesDropped: true,
    containerNoNewPrivileges: true,
    installNetworkPhase: 'networked-exact-lock-npm-ci-ignore-scripts',
    generationNetworkPhase: 'none',
    patchApplied: 'hypercore-storage@3.2.0',
    patchHash: 'fbcd793cfb4fd3334b04bfd9163a728064eef2500361cb83ef84e95d13b46b53',
    containerNativeRebuild: 'omitted-unreachable',
    fullNativeAddonReachable: false,
    limitedNativeAddonReachable: false,
    normalizedGraphHash: '33'.repeat(32),
    normalizedGraphSetHash: '44'.repeat(32),
    artifactManifestByteEquality: true,
    committedEvidenceInputsUntouched: true,
    committedEvidenceInputsProof: 'external-f2-pre-post-sha256',
    toolchain: BLIND_CLIENT_PUBLIC_BROWSER_TOOLCHAIN,
    checks: fixture.identity.crossHostChecks,
    passed: true
  }
}

test('canonical verifier binds profile, tuple, artifact and complete release evidence', t => {
  const fixture = artifactFixture()
  const verified = verifyBlindClientPublicBrowserArtifactV1({
    profile: fixture.profile,
    manifestBytes: fixture.manifestBytes,
    artifactBytes: fixture.artifactBytes,
    expectedManifestHash: fixture.manifestHash,
    expectedSourceClosureHash: fixture.sourceClosureHash,
    expectedTupleHash: fixture.tupleHash
  })
  t.is(verified.artifactHash, fixture.manifest.artifactHash)

  const release = verifyBlindClientPublicBrowserArtifactReleaseEvidenceV1({
    profile: fixture.profile,
    manifestBytes: fixture.manifestBytes,
    artifactBytes: fixture.artifactBytes,
    expectedManifestHash: fixture.manifestHash,
    expectedSourceClosureHash: fixture.sourceClosureHash,
    expectedNormalizedGraphHash: '33'.repeat(32),
    expectedNormalizedGraphSetHash: '44'.repeat(32),
    expectedTupleHash: fixture.tupleHash,
    chromiumEvidenceBytes: encodeBlindClientPublicBrowserChromiumEvidenceV1(
      chromiumEvidence(fixture)),
    crossHostEvidenceBytes: encodeBlindClientPublicBrowserCrossHostEvidenceV1(
      crossHostEvidence(fixture))
  })
  t.is(release.evidenceValid, true)
  t.is(release.releaseReady, false)
  t.is(release.crossHost.candidateIdentityBinding, 'external-postcommit-final-sequence')
  t.is(release.crossHost.normalizedGraphHash, '33'.repeat(32))
  t.is(release.crossHost.normalizedGraphSetHash, '44'.repeat(32))
})

function normalizedGraphFixture () {
  return {
    inputs: [{
      path: 'packages/example/input.js',
      bytes: 7,
      format: 'esm',
      imports: [{
        path: 'packages/example/runtime.js',
        kind: 'import-statement',
        external: false,
        original: null
      }]
    }],
    outputs: [{
      path: 'packages/example/output.mjs',
      entryPoint: 'packages/example/input.js',
      exports: ['example'],
      imports: [],
      inputs: [{
        path: 'packages/example/input.js',
        bytesInOutput: 7
      }],
      bytes: 11
    }]
  }
}

test('normalized graph digests use exact SHA-256 NUL domains and canonical bytes', t => {
  const graph = normalizedGraphFixture()
  const fullPreimage = createBlindClientPublicBrowserNormalizedGraphDigestPreimageV1({
    profileId: 'full',
    normalizedGraph: graph
  })
  const fullBytes = encodeBlindClientPublicBrowserNormalizedGraphDigestPreimageV1(fullPreimage)
  t.is(fullBytes.toString(), JSON.stringify({
    schema: 'HiveRelayBlindClientPublicBrowserNormalizedGraphDigestV1',
    profileId: 'full',
    normalizedGraph: graph
  }, null, 2) + '\n')
  const full = hashBlindClientPublicBrowserNormalizedGraphV1({
    profileId: 'full',
    normalizedGraph: graph
  })
  const limited = hashBlindClientPublicBrowserNormalizedGraphV1({
    profileId: 'limited',
    normalizedGraph: graph
  })
  t.is(full, '8217f6dc1898f5f37518fdf119d10eb5bdb52f2151330046423bf86b5eefdd04')
  t.is(limited, '9ea57348efc8f66b788e4eae2fc665b2c5b6330976d3e4b7de5193c07167a7b2')
  t.unlike(full, limited)

  const setPreimage = createBlindClientPublicBrowserNormalizedGraphSetDigestPreimageV1({
    full,
    limited
  })
  const setBytes = encodeBlindClientPublicBrowserNormalizedGraphSetDigestPreimageV1(setPreimage)
  t.is(setBytes.toString(), JSON.stringify({
    schema: 'HiveRelayBlindClientPublicBrowserNormalizedGraphSetDigestV1',
    profileOrder: ['full', 'limited'],
    profiles: { full, limited }
  }, null, 2) + '\n')
  t.is(hashBlindClientPublicBrowserNormalizedGraphSetV1({ full, limited }),
    '95bdaf70841ec22feb54796a5dd5f7a39777942ddaecfbc23dc5e5b39b50db67')
})

test('normalized graph digests reject mutation, swap, field/order drift and substitution', t => {
  const graph = normalizedGraphFixture()
  const full = hashBlindClientPublicBrowserNormalizedGraphV1({ profileId: 'full', normalizedGraph: graph })
  const limited = hashBlindClientPublicBrowserNormalizedGraphV1({ profileId: 'limited', normalizedGraph: graph })
  const set = hashBlindClientPublicBrowserNormalizedGraphSetV1({ full, limited })
  const mutated = structuredClone(graph)
  mutated.outputs[0].bytes++
  t.unlike(hashBlindClientPublicBrowserNormalizedGraphV1({
    profileId: 'full',
    normalizedGraph: mutated
  }), full)
  t.exception(() => hashBlindClientPublicBrowserNormalizedGraphV1({
    normalizedGraph: graph,
    profileId: 'full'
  }), /canonical order/)
  t.exception(() => hashBlindClientPublicBrowserNormalizedGraphV1({
    profileId: 'full',
    normalizedGraph: { outputs: graph.outputs, inputs: graph.inputs }
  }), /canonical order/)
  t.exception(() => hashBlindClientPublicBrowserNormalizedGraphV1({
    profileId: 'full',
    normalizedGraph: { ...graph, unknown: true }
  }), /missing or unexpected/)
  t.exception(() => hashBlindClientPublicBrowserNormalizedGraphV1({
    profileId: 'full',
    normalizedGraph: { inputs: graph.inputs }
  }), /missing or unexpected/)
  t.exception(() => encodeBlindClientPublicBrowserNormalizedGraphSetDigestPreimageV1({
    schema: 'HiveRelayBlindClientPublicBrowserNormalizedGraphSetDigestV1',
    profileOrder: ['limited', 'full'],
    profiles: { full, limited }
  }), /ordered inventory/)
  t.exception(() => encodeBlindClientPublicBrowserNormalizedGraphSetDigestPreimageV1({
    schema: 'HiveRelayBlindClientPublicBrowserNormalizedGraphSetDigestV1',
    profileOrder: ['full', 'limited'],
    profiles: { limited, full }
  }), /canonical order/)

  const fixture = artifactFixture()
  const evidence = crossHostEvidence(fixture)
  const input = {
    profile: fixture.profile,
    manifestBytes: fixture.manifestBytes,
    artifactBytes: fixture.artifactBytes,
    expectedManifestHash: fixture.manifestHash,
    expectedSourceClosureHash: fixture.sourceClosureHash,
    expectedNormalizedGraphHash: evidence.normalizedGraphHash,
    expectedNormalizedGraphSetHash: evidence.normalizedGraphSetHash,
    chromiumEvidenceBytes: encodeBlindClientPublicBrowserChromiumEvidenceV1(chromiumEvidence(fixture)),
    crossHostEvidenceBytes: encodeBlindClientPublicBrowserCrossHostEvidenceV1(evidence)
  }
  t.exception(() => verifyBlindClientPublicBrowserArtifactReleaseEvidenceV1({
    ...input,
    expectedNormalizedGraphHash: limited
  }), /profile graph digest/)
  t.exception(() => verifyBlindClientPublicBrowserArtifactReleaseEvidenceV1({
    ...input,
    expectedNormalizedGraphSetHash: set
  }), /ordered graph set digest/)
  t.exception(() => verifyBlindClientPublicBrowserArtifactReleaseEvidenceV1({
    ...input,
    expectedNormalizedGraphHash: fixture.sourceClosureHash
  }), /profile graph digest/)
  const omitted = crossHostEvidence(fixture)
  delete omitted.normalizedGraphSetHash
  t.exception(() => encodeBlindClientPublicBrowserCrossHostEvidenceV1(omitted), /missing or unexpected/)
})

test('verifier rejects swaps, false authority and candidate self-reference fields', t => {
  const fixture = artifactFixture()
  t.exception(() => verifyBlindClientPublicBrowserArtifactV1({
    profile: 'limited',
    manifestBytes: fixture.manifestBytes,
    artifactBytes: fixture.artifactBytes,
    expectedManifestHash: fixture.manifestHash,
    expectedSourceClosureHash: fixture.sourceClosureHash
  }), /wrong profile/)

  t.exception(() => encodeBlindClientPublicBrowserChromiumEvidenceV1({
    ...chromiumEvidence(fixture),
    standaloneAuthority: true
  }), /authority identity/)
  t.exception(() => encodeBlindClientPublicBrowserCrossHostEvidenceV1({
    ...crossHostEvidence(fixture),
    candidateCommit: '44'.repeat(20)
  }), /missing or unexpected/)
})
