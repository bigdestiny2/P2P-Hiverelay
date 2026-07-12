import test from 'brittle'
import { encodeHiveAppKey } from '../../packages/core/gateway/hive-host.js'
import {
  assertOperatorContractMatchesCohort,
  cohortEntryForRelay,
  cohortEntriesForChannel,
  normalizePublicHiveGatewayOperatorContract,
  normalizePublicHiveGatewayReleaseManifest,
  operatorContractPathForRelay,
  sha256PublicHiveGatewayOperatorContract
} from '../../scripts/lib/public-hive-gateway-release-manifest.mjs'
import { PUBLIC_HIVE_GATEWAY_FINITE_POLICY } from '../../scripts/lib/public-hive-gateway-policy.mjs'

const APP_KEY = 'aa'.repeat(32)
const SUFFIX = 'hive-canary.operator.example'
const LABEL = encodeHiveAppKey(Buffer.from(APP_KEY, 'hex'))
const FINGERPRINT = Array(32).fill('AA').join(':')

test('public gateway release manifest binds a signed release to an exact cohort identity', (t) => {
  const manifest = normalizePublicHiveGatewayReleaseManifest(fixture(), { releaseTarget: 'v1.2.3' })

  t.is(manifest.releaseTarget, 'v1.2.3')
  t.is(manifest.admissionProfile, 'blind-substrate-public-v1')
  t.is(manifest.observationWindowMs, 24 * 60 * 60 * 1000)
  t.is(manifest.cohort.length, 1)
  t.alike(cohortEntryForRelay(manifest, 'canary-1'), {
    relay: 'canary-1',
    channel: 'canary',
    suffix: SUFFIX,
    origin: `https://${LABEL}.${SUFFIX}`,
    connectAddress: '127.0.0.1',
    appKey: APP_KEY,
    path: '/index.html',
    contentSha256: 'bb'.repeat(32),
    driveVersion: '7',
    peerFingerprint256: FINGERPRINT,
    nginxConfigSha256: 'cc'.repeat(32)
  })
  t.alike(cohortEntriesForChannel(manifest, 'canary').map(entry => entry.relay), ['canary-1'])
  t.alike(cohortEntriesForChannel(manifest, 'stable'), [])
})

test('public gateway release manifest fails closed on transitional, stale, and ambiguous policy', (t) => {
  const disabled = fixture()
  disabled.enabled = false
  t.exception(() => normalizePublicHiveGatewayReleaseManifest(disabled), /explicitly enabled/)

  const transitional = fixture()
  transitional.admissionProfile = 'transitional-operator-allowlist-v1'
  t.exception(() => normalizePublicHiveGatewayReleaseManifest(transitional), /frozen admissionProfile/)

  const shortWindow = fixture()
  shortWindow.observationWindowMs = 60 * 60 * 1000
  t.exception(() => normalizePublicHiveGatewayReleaseManifest(shortWindow), /between 24 hours and 7 days/)

  const mismatchedOrigin = fixture()
  mismatchedOrigin.cohort[0].origin = 'https://example.com/'
  t.exception(() => normalizePublicHiveGatewayReleaseManifest(mismatchedOrigin), /exact appKey and suffix/)

  const duplicated = fixture()
  duplicated.cohort.push({ ...duplicated.cohort[0] })
  t.exception(() => normalizePublicHiveGatewayReleaseManifest(duplicated), /repeats relay/)

  const unknown = fixture()
  unknown.cohort[0].unexpected = true
  t.exception(() => normalizePublicHiveGatewayReleaseManifest(unknown), /unsupported fields/)

  const unsafeVersion = fixture()
  unsafeVersion.cohort[0].driveVersion = String(Number.MAX_SAFE_INTEGER + 1)
  t.exception(() => normalizePublicHiveGatewayReleaseManifest(unsafeVersion), /safe integer string/)

  t.exception(() => normalizePublicHiveGatewayReleaseManifest(fixture(), { releaseTarget: 'v1.2.4' }), /must target v1.2.4/)
  t.exception(() => cohortEntryForRelay(normalizePublicHiveGatewayReleaseManifest(fixture()), 'other'), /does not uniquely approve/)
})

test('public gateway release manifest binds public-t1 cohort to one canonical operator contract digest', (t) => {
  const contract = operatorFixture()
  const digest = sha256PublicHiveGatewayOperatorContract(contract)
  const source = fixture()
  source.cohort[0].deploymentProfile = 'public-t1-gateway'
  source.cohort[0].operatorContractSha256 = digest
  const manifest = normalizePublicHiveGatewayReleaseManifest(source, { requirePublicT1: true })
  const entry = cohortEntryForRelay(manifest, 'canary-1')
  const matched = assertOperatorContractMatchesCohort(contract, manifest, entry)

  t.is(entry.deploymentProfile, 'public-t1-gateway')
  t.is(entry.operatorContractSha256, digest)
  t.is(matched.digest, digest)
  t.is(matched.contract.certificateSpkiSha256, 'dd'.repeat(32))
  t.is(operatorContractPathForRelay('canary-1'), 'fleet/public-hive-gateway-operators/canary-1.json')

  const reordered = operatorFixture()
  reordered.expectedAddresses.reverse()
  t.is(sha256PublicHiveGatewayOperatorContract(reordered), digest, 'canonical digest ignores source key/address order')

  const missingDigest = fixture()
  missingDigest.cohort[0].deploymentProfile = 'public-t1-gateway'
  t.exception(() => normalizePublicHiveGatewayReleaseManifest(missingDigest), /operatorContractSha256 is required/)

  const profileTypo = fixture()
  profileTypo.cohort[0].deploymentProfile = 'public-tl-gateway'
  profileTypo.cohort[0].operatorContractSha256 = digest
  t.exception(() => normalizePublicHiveGatewayReleaseManifest(profileTypo), /must be exactly public-t1-gateway/)

  const drifted = operatorFixture()
  drifted.certificateSpkiSha256 = 'ee'.repeat(32)
  t.exception(() => assertOperatorContractMatchesCohort(drifted, manifest, entry), /digest does not match/)

  const normalized = normalizePublicHiveGatewayOperatorContract(contract, { releaseTarget: 'v1.2.3' })
  t.is(normalized.release.expectedPath, '/index.html')
  t.exception(() => normalizePublicHiveGatewayOperatorContract({ ...contract, unknown: true }), /unsupported fields/)
})

test('public gateway release manifest keeps historical parsing but rejects legacy cohorts for new publication', (t) => {
  const historical = normalizePublicHiveGatewayReleaseManifest(fixture())
  t.is(historical.cohort[0].deploymentProfile, undefined, 'historical legacy manifests remain readable')
  t.exception(() => normalizePublicHiveGatewayReleaseManifest(fixture(), { requirePublicT1: true }),
    /must use public-t1-gateway with a canonical operator contract digest/)
})

function fixture () {
  return {
    schema: 'hiverelay-public-gateway-release-v1',
    enabled: true,
    releaseTarget: 'v1.2.3',
    admissionProfile: 'blind-substrate-public-v1',
    observationWindowMs: 24 * 60 * 60 * 1000,
    maxProbeGapMs: 20 * 60 * 1000,
    cohort: [{
      relay: 'canary-1',
      channel: 'canary',
      suffix: SUFFIX,
      origin: `https://${LABEL}.${SUFFIX}/`,
      connectAddress: '127.0.0.1',
      appKey: APP_KEY,
      path: '/index.html',
      contentSha256: 'bb'.repeat(32),
      driveVersion: '7',
      peerFingerprint256: FINGERPRINT,
      nginxConfigSha256: 'cc'.repeat(32)
    }]
  }
}

function operatorFixture () {
  return {
    schema: 'hiverelay-public-gateway-operator-contract-v1',
    deploymentProfile: 'public-t1-gateway',
    relay: 'canary-1',
    channel: 'canary',
    operatorId: 'operator-a',
    registrableDomain: 'operator.example',
    apiHostname: 'relay-api.operator.example',
    suffix: SUFFIX,
    appKey: APP_KEY,
    addressFamilyPolicy: 'dual-stack',
    expectedAddresses: ['2606:4700:4700::1111', '8.8.8.8'],
    expectedConnectAddress: '127.0.0.1',
    certificateFingerprint256: FINGERPRINT,
    certificateSpkiSha256: 'dd'.repeat(32),
    publicSuffixReady: false,
    finiteProductionPolicy: { ...PUBLIC_HIVE_GATEWAY_FINITE_POLICY },
    release: {
      target: 'v1.2.3',
      expectedPath: '/index.html',
      expectedContentSha256: 'bb'.repeat(32),
      expectedDriveVersion: '7',
      expectedNginxSha256: 'cc'.repeat(32)
    }
  }
}
