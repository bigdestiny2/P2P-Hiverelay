import test from 'brittle'
import { createHash } from 'node:crypto'
import {
  encodeHiveAppKey
} from '../../packages/core/gateway/hive-host.js'
import {
  PUBLIC_HIVE_GATEWAY_DNS_SNAPSHOT_SCHEMA,
  PUBLIC_HIVE_GATEWAY_FINITE_POLICY,
  PUBLIC_HIVE_GATEWAY_OPS_CONTRACT_SCHEMA,
  PUBLIC_HIVE_GATEWAY_OPS_EVIDENCE_SCHEMA,
  PUBLIC_HIVE_GATEWAY_TLS_SNAPSHOT_SCHEMA,
  collectPublicHiveGatewayDnsSnapshot,
  inspectPublicHiveGatewayBaseEvidence,
  inspectPublicHiveGatewayDnsSnapshot,
  inspectPublicHiveGatewayOpsConfig,
  inspectPublicHiveGatewaySocketSnapshot,
  inspectPublicHiveGatewayTlsSnapshot,
  normalizePublicHiveGatewayOpsContract,
  verifyPublicHiveGatewayOpsEvidence,
  verifyPublicHiveGatewayOperatorSet
} from '../../scripts/lib/public-hive-gateway-ops.mjs'
import {
  PUBLIC_HIVE_GATEWAY_EVIDENCE_SCHEMA,
  PUBLIC_HIVE_GATEWAY_PROBE_CHECKS,
  PUBLIC_HIVE_GATEWAY_PROBE_SCHEMA
} from '../../scripts/lib/public-hive-gateway-evidence.mjs'
import {
  sha256PublicHiveGatewayOperatorContract
} from '../../scripts/lib/public-hive-gateway-release-manifest.mjs'

const NOW = Date.parse('2026-07-12T00:00:00.000Z')
const APP_KEY = 'a'.repeat(64)
const APP_LABEL = encodeHiveAppKey(Buffer.from(APP_KEY, 'hex'))
const FINGERPRINT = Array(32).fill('AA').join(':')
const SPKI = 'b'.repeat(64)
const NGINX_SHA = 'c'.repeat(64)
const CONTENT_SHA = 'd'.repeat(64)
const RELEASE_SHA = 'e'.repeat(40)
const IPV4 = '8.8.8.8'
const IPV6 = '2606:4700:4700::1111'

function contractFixture (overrides = {}) {
  return {
    schema: PUBLIC_HIVE_GATEWAY_OPS_CONTRACT_SCHEMA,
    deploymentProfile: 'public-t1-gateway',
    relay: 'utah',
    channel: 'canary',
    operatorId: 'operator-a',
    registrableDomain: 'operator.example',
    apiHostname: 'relay-api.operator.example',
    suffix: 'hive-canary.operator.example',
    appKey: APP_KEY,
    addressFamilyPolicy: 'dual-stack',
    expectedAddresses: [IPV4, IPV6],
    expectedConnectAddress: '127.0.0.1',
    certificateFingerprint256: FINGERPRINT,
    certificateSpkiSha256: SPKI,
    publicSuffixReady: false,
    physicalEnforcementRequired: true,
    finiteProductionPolicy: { ...PUBLIC_HIVE_GATEWAY_FINITE_POLICY },
    release: {
      target: 'v1.2.3',
      expectedPath: '/index.html',
      expectedContentSha256: CONTENT_SHA,
      expectedDriveVersion: '7',
      expectedNginxSha256: NGINX_SHA
    },
    ...overrides
  }
}

function configFixture (overrides = {}) {
  return {
    productProfile: 'relay-core',
    requirePhysicalEnforcement: true,
    apiHost: '127.0.0.1',
    apiPort: 9100,
    gatewayHost: '127.0.0.1',
    gatewayPort: 9200,
    gatewayTrustProxy: true,
    gatewayRequireForwardedSNI: true,
    gatewayMaxResponseBytes: 67108864,
    gatewayMaxTransformBytes: 4194304,
    gatewayEgressBytesPerWindow: 268435456,
    gatewayEgressWindowMs: 60000,
    gatewayMaxResponseLifetimeMs: 900000,
    custody: { enabled: false },
    hiveAppHostSuffix: 'hive-canary.operator.example',
    hiveAppPublicKeys: [APP_KEY],
    hiveAppPublicVersions: { [APP_KEY]: 7 },
    ...overrides
  }
}

function dnsSnapshotFixture (contract) {
  const witnessKey = contract.appKey === '0'.repeat(64) ? 'f'.repeat(64) : '0'.repeat(64)
  const answer = {
    a: [{ address: IPV4, ttl: 300 }],
    aaaa: [{ address: IPV6, ttl: 300 }],
    cname: []
  }
  return {
    schema: PUBLIC_HIVE_GATEWAY_DNS_SNAPSHOT_SCHEMA,
    observedAt: new Date(NOW).toISOString(),
    hostname: contract.appHostname,
    witnessHostname: `${encodeHiveAppKey(Buffer.from(witnessKey, 'hex'))}.${contract.suffix}`,
    app: structuredClone(answer),
    witness: structuredClone(answer),
    routing: {
      app: { https: [], svcb: [] },
      witness: { https: [], svcb: [] }
    }
  }
}

function perAddressProbe (contract, address) {
  return {
    schema: PUBLIC_HIVE_GATEWAY_PROBE_SCHEMA,
    observedAt: new Date(NOW).toISOString(),
    origin: contract.origin,
    connectAddress: address,
    appKey: contract.appKey,
    path: contract.release.expectedPath,
    sha256: contract.release.expectedContentSha256,
    bytes: 128,
    driveVersion: contract.release.expectedDriveVersion,
    tlsProtocol: 'TLSv1.3',
    peerFingerprint256: contract.certificateFingerprint256,
    peerValidTo: '2026-09-01T00:00:00.000Z',
    metadataSigned: false,
    checks: Object.fromEntries(PUBLIC_HIVE_GATEWAY_PROBE_CHECKS.map(name => [name, true]))
  }
}

function tlsSnapshotFixture (contract, overrides = {}) {
  return {
    schema: PUBLIC_HIVE_GATEWAY_TLS_SNAPSHOT_SCHEMA,
    observedAt: new Date(NOW).toISOString(),
    hostname: contract.appHostname,
    port: 443,
    endpoints: contract.expectedAddresses.map(address => ({
      address,
      authorized: true,
      protocol: 'TLSv1.3',
      fingerprint256: FINGERPRINT,
      spkiSha256: SPKI,
      validTo: '2026-09-01T00:00:00.000Z',
      probe: perAddressProbe(contract, address)
    })),
    ...overrides
  }
}

function baseEvidenceFixture (contract, overrides = {}) {
  return {
    schema: PUBLIC_HIVE_GATEWAY_EVIDENCE_SCHEMA,
    status: 'pass',
    checkedAt: new Date(NOW).toISOString(),
    mode: 'canary',
    admissionProfile: 'transitional-operator-allowlist-v1',
    release: { target: contract.release.target, sha: RELEASE_SHA },
    config: {
      suffix: contract.suffix,
      appKeyCount: 1,
      apiHost: '127.0.0.1',
      apiPort: 9100,
      gatewayHost: '127.0.0.1',
      gatewayPort: 9200,
      connectAddress: contract.expectedConnectAddress,
      publicSuffixReady: false,
      custodyEnabled: false,
      physicalEnforcementRequired: true,
      finiteProductionPolicy: { ...PUBLIC_HIVE_GATEWAY_FINITE_POLICY }
    },
    static: { ok: true, errors: [], warnings: ['transitional rehearsal'] },
    nginx: { ok: true, errors: [], source: 'active', sha256: NGINX_SHA },
    probe: {
      schema: PUBLIC_HIVE_GATEWAY_PROBE_SCHEMA,
      observedAt: new Date(NOW).toISOString(),
      origin: contract.origin,
      connectAddress: contract.expectedConnectAddress,
      appKey: APP_KEY,
      path: '/index.html',
      sha256: CONTENT_SHA,
      bytes: 42,
      driveVersion: '7',
      tlsProtocol: 'TLSv1.3',
      peerFingerprint256: FINGERPRINT,
      peerValidTo: '2026-09-01T00:00:00.000Z',
      metadataSigned: false,
      checks: Object.fromEntries(PUBLIC_HIVE_GATEWAY_PROBE_CHECKS.map(name => [name, true]))
    },
    probeError: null,
    ...overrides
  }
}

test('public gateway ops - exact public-t1 operator contract normalizes canonical bindings', (t) => {
  const contract = normalizePublicHiveGatewayOpsContract(contractFixture())
  t.is(contract.deploymentProfile, 'public-t1-gateway')
  t.is(contract.appHostname, `${APP_LABEL}.hive-canary.operator.example`)
  t.is(contract.origin, `https://${APP_LABEL}.hive-canary.operator.example`)
  t.alike(contract.expectedAddresses, [IPV4, IPV6])
  t.is(contract.expectedConnectAddress, '127.0.0.1')
})

test('public gateway ops - contract rejects role drift, unsafe DNS, and implicit address policy', (t) => {
  t.exception(() => normalizePublicHiveGatewayOpsContract(contractFixture({
    deploymentProfile: 't2-custody'
  })), /public-t1-gateway/)
  t.exception(() => normalizePublicHiveGatewayOpsContract(contractFixture({
    expectedAddresses: ['127.0.0.1', IPV6]
  })), /globally routable/)
  t.exception(() => normalizePublicHiveGatewayOpsContract(contractFixture({
    expectedAddresses: [IPV4],
    addressFamilyPolicy: 'dual-stack'
  })), /dual-stack/)
  t.exception(() => normalizePublicHiveGatewayOpsContract(contractFixture({
    expectedConnectAddress: '169.254.169.254'
  })), /loopback or a reviewed public address/)
  t.exception(() => normalizePublicHiveGatewayOpsContract(contractFixture({
    apiHostname: 'api.hive-canary.operator.example'
  })), /separate exact child outside the app suffix/)
  t.exception(() => normalizePublicHiveGatewayOpsContract(contractFixture({
    expectedAddresses: [IPV4, '1.1.1.1', IPV6]
  })), /1 or 2 addresses/)
})

test('public gateway ops - DNS snapshot proves exact wildcard A/AAAA set and bounded TTL', (t) => {
  const contract = normalizePublicHiveGatewayOpsContract(contractFixture())
  const result = inspectPublicHiveGatewayDnsSnapshot(dnsSnapshotFixture(contract), contract, { now: NOW })
  t.ok(result.ok)
  t.alike(result.errors, [])
  t.alike(result.result.ipv4, [IPV4])
  t.alike(result.result.ipv6, [IPV6])
  t.alike(result.result.ttlRangeSeconds, { min: 300, max: 300 })

  const rebound = dnsSnapshotFixture(contract)
  rebound.app.a[0].address = '1.1.1.1'
  const reboundResult = inspectPublicHiveGatewayDnsSnapshot(rebound, contract, { now: NOW })
  t.absent(reboundResult.ok)
  t.ok(reboundResult.errors.some(value => value.includes('exactly equal')))

  const cname = dnsSnapshotFixture(contract)
  cname.app.cname = ['edge.vendor.example']
  const cnameResult = inspectPublicHiveGatewayDnsSnapshot(cname, contract, { now: NOW })
  t.absent(cnameResult.ok)
  t.ok(cnameResult.errors.some(value => value.includes('without CNAME')))

  for (const label of ['app', 'witness']) {
    for (const routingKind of ['https', 'svcb']) {
      const routed = dnsSnapshotFixture(contract)
      routed.routing[label][routingKind] = [{ priority: 1, name: '.' }]
      const routedResult = inspectPublicHiveGatewayDnsSnapshot(routed, contract, { now: NOW })
      t.absent(routedResult.ok)
      t.ok(routedResult.errors.some(value => value.includes(`${label} DNS must have empty HTTPS and SVCB`)))
    }
  }

  const stale = dnsSnapshotFixture(contract)
  stale.observedAt = new Date(NOW - 16 * 60 * 1000).toISOString()
  t.exception(() => inspectPublicHiveGatewayDnsSnapshot(stale, contract, { now: NOW }), /15 minutes/)
})

test('public gateway ops - live DNS collection binds routing RRsets for app and witness', async (t) => {
  const contract = normalizePublicHiveGatewayOpsContract(contractFixture())
  const routingCalls = []
  const resolver = {
    resolve4: async () => [{ address: IPV4, ttl: 300 }],
    resolve6: async () => [{ address: IPV6, ttl: 300 }],
    resolveCname: async () => []
  }
  const snapshot = await collectPublicHiveGatewayDnsSnapshot(contract, {
    resolver,
    now: NOW,
    resolveRoutingRecords: async (hostname, rrtype) => {
      routingCalls.push([hostname, rrtype])
      return []
    }
  })
  t.ok(inspectPublicHiveGatewayDnsSnapshot(snapshot, contract, { now: NOW }).ok)
  t.alike(routingCalls, [
    [contract.appHostname, 'HTTPS'],
    [contract.appHostname, 'SVCB'],
    [snapshot.witnessHostname, 'HTTPS'],
    [snapshot.witnessHostname, 'SVCB']
  ])
})

test('public gateway ops - TLS snapshot binds every DNS address to one reviewed leaf and SPKI', (t) => {
  const contract = normalizePublicHiveGatewayOpsContract(contractFixture())
  const identity = { fingerprint256: FINGERPRINT, spkiSha256: SPKI }
  const result = inspectPublicHiveGatewayTlsSnapshot(tlsSnapshotFixture(contract), contract, identity, { now: NOW })
  t.ok(result.ok)
  t.is(result.result.endpoints.length, 2)

  const substituted = tlsSnapshotFixture(contract)
  substituted.endpoints[1].spkiSha256 = 'f'.repeat(64)
  const substitutedResult = inspectPublicHiveGatewayTlsSnapshot(substituted, contract, identity, { now: NOW })
  t.absent(substitutedResult.ok)
  t.ok(substitutedResult.errors.some(value => value.includes('certificate SPKI')))

  const missingIpv6 = tlsSnapshotFixture(contract)
  missingIpv6.endpoints.pop()
  const missingResult = inspectPublicHiveGatewayTlsSnapshot(missingIpv6, contract, identity, { now: NOW })
  t.absent(missingResult.ok)
  t.ok(missingResult.errors.some(value => value.includes('every reviewed public address')))

  const wrongAddress = tlsSnapshotFixture(contract)
  wrongAddress.endpoints[1].probe.connectAddress = IPV4
  t.absent(inspectPublicHiveGatewayTlsSnapshot(wrongAddress, contract, identity, { now: NOW }).ok)

  const protocolDrift = tlsSnapshotFixture(contract)
  protocolDrift.endpoints[1].probe.tlsProtocol = 'TLSv1.2'
  const protocolResult = inspectPublicHiveGatewayTlsSnapshot(protocolDrift, contract, identity, { now: NOW })
  t.absent(protocolResult.ok)
  t.ok(protocolResult.errors.some(value => value.includes('TLS protocol binding')))

  const metadataDrift = tlsSnapshotFixture(contract)
  metadataDrift.endpoints[1].probe.metadataSigned = true
  t.absent(inspectPublicHiveGatewayTlsSnapshot(metadataDrift, contract, identity, { now: NOW }).ok)

  const validityDrift = tlsSnapshotFixture(contract)
  validityDrift.endpoints[1].probe.peerValidTo = '2026-10-01T00:00:00.000Z'
  t.absent(inspectPublicHiveGatewayTlsSnapshot(validityDrift, contract, identity, { now: NOW }).ok)
})

test('public gateway ops - actual listener snapshot keeps upstreams numeric-loopback only', (t) => {
  const config = configFixture()
  const snapshot = [
    'LISTEN 0 511 0.0.0.0:443 0.0.0.0:*',
    'LISTEN 0 511 [::]:443 [::]:*',
    'LISTEN 0 511 127.0.0.1:9100 0.0.0.0:*',
    'LISTEN 0 511 127.0.0.1:9200 0.0.0.0:*'
  ].join('\n')
  const result = inspectPublicHiveGatewaySocketSnapshot(snapshot, config)
  t.ok(result.ok)
  t.alike(result.result.api, ['127.0.0.1:9100'])
  t.alike(result.result.gateway, ['127.0.0.1:9200'])

  const exposed = inspectPublicHiveGatewaySocketSnapshot(snapshot.replace('127.0.0.1:9200', '0.0.0.0:9200'), config)
  t.absent(exposed.ok)
  t.ok(exposed.errors.some(value => value.includes('exactly one socket bound')))

  const missingDefault = inspectPublicHiveGatewaySocketSnapshot(snapshot.replace('LISTEN 0 511 [::]:443 [::]:*\n', ''), config)
  t.absent(missingDefault.ok)
  t.ok(missingDefault.errors.some(value => value.includes('IPv4 and IPv6 listeners')))

  const quic = inspectPublicHiveGatewaySocketSnapshot(`${snapshot}\nudp UNCONN 0 0 0.0.0.0:443 0.0.0.0:*`, config)
  t.absent(quic.ok)
  t.ok(quic.errors.some(value => value.includes('UDP/QUIC')))
})

test('public gateway ops - rehearsal config is narrow while fleet requires compiled profile', (t) => {
  const contract = normalizePublicHiveGatewayOpsContract(contractFixture())
  const rehearsal = inspectPublicHiveGatewayOpsConfig(configFixture(), contract, 'rehearsal')
  t.ok(rehearsal.ok)

  const pendingFleet = inspectPublicHiveGatewayOpsConfig(configFixture(), contract, 'fleet')
  t.absent(pendingFleet.ok)
  t.ok(pendingFleet.errors.some(value => value.includes('compiled public-t1-gateway')))

  const fleet = inspectPublicHiveGatewayOpsConfig(configFixture({ productProfile: 'public-t1-gateway' }), contract, 'fleet')
  t.ok(fleet.ok)

  const missingPhysicalRequirement = configFixture({ productProfile: 'public-t1-gateway' })
  delete missingPhysicalRequirement.requirePhysicalEnforcement
  const missingPhysicalResult = inspectPublicHiveGatewayOpsConfig(missingPhysicalRequirement, contract, 'fleet')
  t.absent(missingPhysicalResult.ok)
  t.ok(missingPhysicalResult.errors.some(value => value.includes('physical enforcement')))

  const disabledPhysicalResult = inspectPublicHiveGatewayOpsConfig(configFixture({
    productProfile: 'public-t1-gateway',
    requirePhysicalEnforcement: false
  }), contract, 'fleet')
  t.absent(disabledPhysicalResult.ok)
  t.ok(disabledPhysicalResult.errors.some(value => value.includes('physical enforcement')))

  const custody = inspectPublicHiveGatewayOpsConfig(configFixture({ custody: { enabled: true } }), contract, 'rehearsal')
  t.absent(custody.ok)
  t.ok(custody.errors.some(value => value.includes('disable T2 custody')))

  const unknownSibling = inspectPublicHiveGatewayOpsConfig(configFixture({
    hiveAppPublicKeys: [APP_KEY, 'f'.repeat(64)]
  }), contract, 'rehearsal')
  t.absent(unknownSibling.ok)
  t.ok(unknownSibling.errors.some(value => value.includes('exactly the one contract-bound')))
})

test('public gateway ops - rehearsal binds active nginx, SNI checks, bytes, version, and certificate', (t) => {
  const contract = normalizePublicHiveGatewayOpsContract(contractFixture())
  const config = configFixture()
  const evidence = baseEvidenceFixture(contract)
  const result = inspectPublicHiveGatewayBaseEvidence(evidence, config, contract, 'rehearsal', { now: NOW, releaseSha: RELEASE_SHA })
  t.ok(result.ok)
  t.is(result.result.nginxSha256, NGINX_SHA)
  t.is(result.result.contentSha256, CONTENT_SHA)

  const failedSni = baseEvidenceFixture(contract)
  failedSni.probe.checks.sniHostBinding = false
  const failedSniResult = inspectPublicHiveGatewayBaseEvidence(failedSni, config, contract, 'rehearsal', { now: NOW, releaseSha: RELEASE_SHA })
  t.absent(failedSniResult.ok)
  t.ok(failedSniResult.errors.some(value => value.includes('sniHostBinding')))

  const installedOnly = baseEvidenceFixture(contract)
  installedOnly.nginx.source = 'installed'
  const installedOnlyResult = inspectPublicHiveGatewayBaseEvidence(installedOnly, config, contract, 'rehearsal', { now: NOW, releaseSha: RELEASE_SHA })
  t.absent(installedOnlyResult.ok)
  t.ok(installedOnlyResult.errors.some(value => value.includes('active nginx source')))
})

test('public gateway ops - fleet verifier derives the signed contract and rejects readiness drift', (t) => {
  const contract = normalizePublicHiveGatewayOpsContract(contractFixture())
  const contractSha256 = sha256PublicHiveGatewayOperatorContract(contract)
  const manifest = fleetManifestFixture(contract, contractSha256)
  const manifestBytes = Buffer.from(JSON.stringify(manifest) + '\n')
  const manifestSha256 = createHash('sha256').update(manifestBytes).digest('hex')
  const evidence = fleetOpsEvidenceFixture(contract, contractSha256, manifestSha256)
  const verified = verifyPublicHiveGatewayOpsEvidence(evidence, {
    contract,
    manifest,
    releaseSha: RELEASE_SHA,
    relay: contract.relay,
    expectedContractSha256: contractSha256,
    releaseManifestSha256: manifestSha256,
    now: NOW
  })
  t.is(verified.status, 'verified')
  t.is(verified.operatorContractSha256, contractSha256)
  t.alike(verified.expectedAddresses, [IPV4, IPV6])
  t.ok(verified.claimBoundary.includes('no blind G2/G3'))

  const stale = structuredClone(evidence)
  stale.checkedAt = new Date(NOW - 16 * 60 * 1000).toISOString()
  t.exception(() => verifyFleetEvidence(stale, contract, manifest, contractSha256, manifestSha256), /15 minutes/)

  const fixtureDns = structuredClone(evidence)
  fixtureDns.dns.source = 'fixture'
  t.exception(() => verifyFleetEvidence(fixtureDns, contract, manifest, contractSha256, manifestSha256), /DNS source/)

  const unsignedPolicy = structuredClone(evidence)
  unsignedPolicy.finiteProductionPolicy.signedReleaseBound = false
  t.exception(() => verifyFleetEvidence(unsignedPolicy, contract, manifest, contractSha256, manifestSha256), /signed release binding/)

  const driftedDigest = structuredClone(evidence)
  driftedDigest.sourceDigests.operatorContractSha256 = 'f'.repeat(64)
  t.exception(() => verifyFleetEvidence(driftedDigest, contract, manifest, contractSha256, manifestSha256), /operator contract SHA-256/)

  const driftedSpki = structuredClone(evidence)
  driftedSpki.tls.observed.endpoints[0].spkiSha256 = 'f'.repeat(64)
  t.exception(() => verifyFleetEvidence(driftedSpki, contract, manifest, contractSha256, manifestSha256), /endpoint SPKI/)

  const driftedAddress = structuredClone(evidence)
  driftedAddress.dns.observed.ipv4 = ['1.1.1.1']
  t.exception(() => verifyFleetEvidence(driftedAddress, contract, manifest, contractSha256, manifestSha256), /observed DNS addresses/)

  const witnessRoute = structuredClone(evidence)
  witnessRoute.dns.observed.routing.witness.https.push({ priority: 1, name: '.' })
  t.exception(() => verifyFleetEvidence(witnessRoute, contract, manifest, contractSha256, manifestSha256),
    /witness DNS HTTPS and SVCB RRsets must be empty/)

  const falseBlindClaim = structuredClone(evidence)
  falseBlindClaim.claims.provesBlindG2 = true
  t.exception(() => verifyFleetEvidence(falseBlindClaim, contract, manifest, contractSha256, manifestSha256), /provesBlindG2/)

  const oldReadinessSchema = structuredClone(evidence)
  oldReadinessSchema.schema = 'hiverelay-public-gateway-operator-readiness-v2'
  t.exception(() => verifyFleetEvidence(oldReadinessSchema, contract, manifest, contractSha256, manifestSha256), /schema/)
  const missingPhysicalRequirement = structuredClone(evidence)
  delete missingPhysicalRequirement.physicalEnforcementRequired
  t.exception(() => verifyFleetEvidence(missingPhysicalRequirement, contract, manifest, contractSha256, manifestSha256), /physicalEnforcementRequired/)
  const disabledPhysicalRequirement = structuredClone(evidence)
  disabledPhysicalRequirement.physicalEnforcementRequired = false
  t.exception(() => verifyFleetEvidence(disabledPhysicalRequirement, contract, manifest, contractSha256, manifestSha256), /physical enforcement requirement/)
  const gatewayRequirementDrift = structuredClone(evidence)
  gatewayRequirementDrift.gateway.physicalEnforcementRequired = false
  t.exception(() => verifyFleetEvidence(gatewayRequirementDrift, contract, manifest, contractSha256, manifestSha256), /gateway physicalEnforcementRequired|gateway physical enforcement requirement/)

  const exposedSocket = structuredClone(evidence)
  exposedSocket.sockets.observed.gateway = ['0.0.0.0:9200']
  t.exception(() => verifyFleetEvidence(exposedSocket, contract, manifest, contractSha256, manifestSha256), /numeric-loopback only/)

  const unknownNested = structuredClone(evidence)
  unknownNested.operator.unreviewed = true
  t.exception(() => verifyFleetEvidence(unknownNested, contract, manifest, contractSha256, manifestSha256), /unknown field unreviewed/)
})

test('public gateway ops - operator-set verifier requires distinct domains, keys, and edge networks', (t) => {
  const first = operatorEvidenceFixture()
  const second = operatorEvidenceFixture({
    operator: {
      ...first.operator,
      relay: 'singapore',
      operatorId: 'operator-b',
      registrableDomain: 'independent.example',
      apiHostname: 'relay-api.independent.example',
      suffix: 'hive.independent.example'
    },
    certificate: {
      ...first.certificate,
      fingerprint256: Array(32).fill('BB').join(':'),
      spkiSha256: 'f'.repeat(64)
    },
    dns: {
      ...first.dns,
      expectedAddresses: ['1.1.1.1', '2606:4700:4700::1001']
    }
  })
  const verified = verifyPublicHiveGatewayOperatorSet([first, second], { mode: 'rehearsal' })
  t.is(verified.operatorCount, 2)
  t.ok(verified.claimBoundary.includes('rehearsal-only'))

  const sharedKey = structuredClone(second)
  sharedKey.certificate.spkiSha256 = first.certificate.spkiSha256
  t.exception(() => verifyPublicHiveGatewayOperatorSet([first, sharedKey], { mode: 'rehearsal' }), /SPKIs must not contain duplicates/)

  const sharedAddress = structuredClone(second)
  sharedAddress.dns.expectedAddresses[0] = IPV4
  t.exception(() => verifyPublicHiveGatewayOperatorSet([first, sharedAddress], { mode: 'rehearsal' }), /address sets must be disjoint/)

  const fleetFirst = structuredClone(first)
  const fleetSecond = structuredClone(second)
  const reducedFleet = structuredClone(first)
  reducedFleet.mode = 'fleet'
  reducedFleet.checkedAt = new Date(NOW).toISOString()
  reducedFleet.finiteProductionPolicy.signedReleaseBound = true
  t.exception(() => verifyPublicHiveGatewayOperatorSet([reducedFleet, fleetSecond], {
    mode: 'fleet',
    now: NOW
  }), /fleet errors must be empty/)
  for (const [index, evidence] of [fleetFirst, fleetSecond].entries()) {
    evidence.mode = 'fleet'
    evidence.checkedAt = new Date(NOW).toISOString()
    evidence.finiteProductionPolicy.signedReleaseBound = true
    evidence.errors = []
    evidence.dns.source = 'live'
    evidence.tls = { source: 'live' }
    evidence.sockets = { source: 'live' }
    evidence.checks.contract = true
    Object.assign(evidence.claims, {
      provesCurrentDnsAnswers: true,
      provesCurrentWebPkiTls: true,
      provesCurrentLoopbackSockets: true,
      forbidsT2Exposure: true,
      forbidsUnknownExposure: true,
      provesFiniteProductionPolicyBehavior: false,
      provesOperatorControl: false
    })
    evidence.sourceDigests = {
      operatorContractSha256: String(index + 1).repeat(64),
      releaseManifestSha256: 'a'.repeat(64)
    }
  }
  const fleet = verifyPublicHiveGatewayOperatorSet([fleetFirst, fleetSecond], { mode: 'fleet', now: NOW })
  t.ok(fleet.claimBoundary.includes('no organizational-control'))
  t.is(fleet.operators[0].checkedAt, new Date(NOW).toISOString())

  fleetSecond.checkedAt = new Date(NOW - 16 * 60 * 1000).toISOString()
  t.exception(() => verifyPublicHiveGatewayOperatorSet([fleetFirst, fleetSecond], {
    mode: 'fleet',
    now: NOW
  }), /15 minutes/)
})

function operatorEvidenceFixture (overrides = {}) {
  return {
    schema: PUBLIC_HIVE_GATEWAY_OPS_EVIDENCE_SCHEMA,
    status: 'pass',
    mode: 'rehearsal',
    deploymentProfile: 'public-t1-gateway',
    physicalEnforcementRequired: true,
    operator: {
      relay: 'utah',
      operatorId: 'operator-a',
      registrableDomain: 'operator.example',
      apiHostname: 'relay-api.operator.example',
      suffix: 'hive-canary.operator.example',
      publicSuffixReady: false
    },
    gateway: {
      appKey: APP_KEY,
      contentSha256: CONTENT_SHA,
      driveVersion: '7',
      physicalEnforcementRequired: true,
      releaseTarget: 'v1.2.3',
      releaseSha: RELEASE_SHA
    },
    certificate: { fingerprint256: FINGERPRINT, spkiSha256: SPKI },
    dns: { expectedAddresses: [IPV4, IPV6] },
    finiteProductionPolicy: {
      ...PUBLIC_HIVE_GATEWAY_FINITE_POLICY,
      configured: {
        maxResponseBytes: 67108864,
        maxTransformBytes: 4194304,
        egressBytesPerClientAppWindow: 268435456,
        egressWindowMs: 60000,
        maxResponseLifetimeMs: 900000
      },
      contractBound: true,
      signedReleaseBound: false
    },
    checks: { config: true, certificate: true, dns: true, tls: true, sockets: true, gateway: true },
    claims: {
      attestsFiniteProductionPolicyValues: true,
      attestsPhysicalEnforcementRequirement: true,
      provesActivePhysicalEnforcement: false,
      provesBlindG2: false,
      provesBlindG3: false
    },
    ...overrides
  }
}

function fleetManifestFixture (contract, contractSha256) {
  return {
    schema: 'hiverelay-public-gateway-release-v1',
    enabled: true,
    releaseTarget: contract.release.target,
    admissionProfile: 'blind-substrate-public-v1',
    observationWindowMs: 24 * 60 * 60 * 1000,
    maxProbeGapMs: 20 * 60 * 1000,
    cohort: [{
      relay: contract.relay,
      channel: contract.channel,
      suffix: contract.suffix,
      origin: contract.origin,
      connectAddress: contract.expectedConnectAddress,
      appKey: contract.appKey,
      path: contract.release.expectedPath,
      contentSha256: contract.release.expectedContentSha256,
      driveVersion: contract.release.expectedDriveVersion,
      peerFingerprint256: contract.certificateFingerprint256,
      nginxConfigSha256: contract.release.expectedNginxSha256,
      deploymentProfile: 'public-t1-gateway',
      operatorContractSha256: contractSha256
    }]
  }
}

function fleetOpsEvidenceFixture (contract, contractSha256, manifestSha256) {
  return {
    schema: PUBLIC_HIVE_GATEWAY_OPS_EVIDENCE_SCHEMA,
    status: 'pass',
    checkedAt: new Date(NOW).toISOString(),
    mode: 'fleet',
    deploymentProfile: 'public-t1-gateway',
    physicalEnforcementRequired: true,
    operator: {
      relay: contract.relay,
      operatorId: contract.operatorId,
      registrableDomain: contract.registrableDomain,
      apiHostname: contract.apiHostname,
      suffix: contract.suffix,
      publicSuffixReady: contract.publicSuffixReady
    },
    gateway: {
      schema: 'hiverelay-public-gateway-evidence-verification-v2',
      status: 'verified',
      mode: 'fleet',
      admissionProfile: 'blind-substrate-public-v1',
      publicSuffixReady: contract.publicSuffixReady,
      finiteProductionPolicy: { ...PUBLIC_HIVE_GATEWAY_FINITE_POLICY },
      releaseTarget: contract.release.target,
      releaseSha: RELEASE_SHA,
      checkedAt: new Date(NOW).toISOString(),
      probeObservedAt: new Date(NOW).toISOString(),
      origin: contract.origin,
      connectAddress: contract.expectedConnectAddress,
      appKey: contract.appKey,
      path: contract.release.expectedPath,
      contentSha256: contract.release.expectedContentSha256,
      driveVersion: contract.release.expectedDriveVersion,
      physicalEnforcementRequired: true,
      tlsProtocol: 'TLSv1.3',
      peerFingerprint256: contract.certificateFingerprint256,
      nginxSha256: contract.release.expectedNginxSha256,
      checks: Object.fromEntries(PUBLIC_HIVE_GATEWAY_PROBE_CHECKS.map(name => [name, true]))
    },
    finiteProductionPolicy: {
      ...PUBLIC_HIVE_GATEWAY_FINITE_POLICY,
      configured: {
        maxResponseBytes: PUBLIC_HIVE_GATEWAY_FINITE_POLICY.maxResponseBytes,
        maxTransformBytes: PUBLIC_HIVE_GATEWAY_FINITE_POLICY.maxTransformBytes,
        egressBytesPerClientAppWindow: PUBLIC_HIVE_GATEWAY_FINITE_POLICY.egressBytesPerClientAppWindow,
        egressWindowMs: PUBLIC_HIVE_GATEWAY_FINITE_POLICY.egressWindowMs,
        maxResponseLifetimeMs: PUBLIC_HIVE_GATEWAY_FINITE_POLICY.maxResponseLifetimeMs
      },
      contractBound: true,
      signedReleaseBound: true
    },
    certificate: {
      fingerprint256: contract.certificateFingerprint256,
      spkiSha256: contract.certificateSpkiSha256,
      validFrom: '2026-07-01T00:00:00.000Z',
      validTo: '2026-09-01T00:00:00.000Z',
      dnsNames: [`*.${contract.suffix}`],
      chainLength: 2,
      keyType: 'rsa'
    },
    dns: {
      source: 'live',
      expectedAddresses: [...contract.expectedAddresses],
      addressFamilyPolicy: contract.addressFamilyPolicy,
      observed: {
        observedAt: new Date(NOW).toISOString(),
        hostname: contract.appHostname,
        witnessHostname: `${encodeHiveAppKey(Buffer.alloc(32))}.${contract.suffix}`,
        ipv4: [IPV4],
        ipv6: [IPV6],
        routing: {
          app: { https: [], svcb: [] },
          witness: { https: [], svcb: [] }
        },
        ttlRangeSeconds: { min: 300, max: 300 }
      }
    },
    tls: {
      source: 'live',
      observed: {
        observedAt: new Date(NOW).toISOString(),
        hostname: contract.appHostname,
        port: 443,
        endpoints: contract.expectedAddresses.map(address => ({
          address,
          protocol: 'TLSv1.3',
          fingerprint256: contract.certificateFingerprint256,
          spkiSha256: contract.certificateSpkiSha256,
          validTo: '2026-09-01T00:00:00.000Z',
          probe: perAddressProbe(contract, address)
        }))
      }
    },
    sockets: {
      source: 'live',
      observed: {
        api: ['127.0.0.1:9100'],
        gateway: ['127.0.0.1:9200'],
        tls: ['0.0.0.0:443', '[::]:443'],
        udp443: []
      }
    },
    sourceDigests: {
      contractFileSha256: '1'.repeat(64),
      operatorContractSha256: contractSha256,
      configSha256: '2'.repeat(64),
      gatewayEvidenceSha256: '3'.repeat(64),
      releaseManifestSha256: manifestSha256
    },
    checks: {
      contract: true,
      config: true,
      certificate: true,
      dns: true,
      tls: true,
      sockets: true,
      gateway: true
    },
    claims: {
      provesCurrentDnsAnswers: true,
      provesCurrentWebPkiTls: true,
      provesCurrentLoopbackSockets: true,
      forbidsT2Exposure: true,
      forbidsUnknownExposure: true,
      attestsFiniteProductionPolicyValues: true,
      attestsPhysicalEnforcementRequirement: true,
      provesActivePhysicalEnforcement: false,
      provesBlindG2: false,
      provesBlindG3: false,
      provesFiniteProductionPolicyBehavior: false,
      provesOperatorControl: false
    },
    externalGates: ['independent timestamp and operator-control proof'],
    errors: []
  }
}

function verifyFleetEvidence (evidence, contract, manifest, contractSha256, manifestSha256) {
  return verifyPublicHiveGatewayOpsEvidence(evidence, {
    contract,
    manifest,
    releaseSha: RELEASE_SHA,
    relay: contract.relay,
    expectedContractSha256: contractSha256,
    releaseManifestSha256: manifestSha256,
    now: NOW
  })
}
