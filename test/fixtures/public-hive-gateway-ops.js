import { createHash } from 'node:crypto'
import { encodeHiveAppKey } from '../../packages/core/gateway/hive-host.js'
import { PUBLIC_HIVE_GATEWAY_PROBE_CHECKS } from '../../scripts/lib/public-hive-gateway-evidence.mjs'
import {
  PUBLIC_HIVE_GATEWAY_FINITE_POLICY,
  PUBLIC_HIVE_GATEWAY_OPS_EVIDENCE_SCHEMA
} from '../../scripts/lib/public-hive-gateway-ops.mjs'
import {
  operatorContractPathForRelay,
  sha256PublicHiveGatewayOperatorContract
} from '../../scripts/lib/public-hive-gateway-release-manifest.mjs'

export function createPublicT1OpsFixture (opts = {}) {
  const now = Number.isFinite(opts.now) ? opts.now : Date.now()
  const checkedAt = new Date(now).toISOString()
  const validTo = new Date(now + 30 * 24 * 60 * 60 * 1000).toISOString()
  const releaseSha = opts.releaseSha || 'b'.repeat(40)
  const relay = opts.relay || 'canary-1'
  const appKey = opts.appKey || 'a'.repeat(64)
  const suffix = opts.suffix || 'hive.operator.example'
  const appHostname = `${encodeHiveAppKey(Buffer.from(appKey, 'hex'))}.${suffix}`
  const origin = `https://${appHostname}`
  const fingerprint256 = opts.fingerprint256 || Array(32).fill('AA').join(':')
  const spkiSha256 = opts.spkiSha256 || 'b'.repeat(64)
  const contentSha256 = opts.contentSha256 || 'c'.repeat(64)
  const nginxSha256 = opts.nginxSha256 || 'd'.repeat(64)
  const expectedAddresses = opts.expectedAddresses || ['8.8.8.8', '2606:4700:4700::1111']
  const contract = {
    schema: 'hiverelay-public-gateway-operator-contract-v2',
    deploymentProfile: 'public-t1-gateway',
    relay,
    channel: opts.channel || 'canary',
    operatorId: opts.operatorId || 'operator-a',
    registrableDomain: opts.registrableDomain || 'operator.example',
    apiHostname: opts.apiHostname || 'relay-api.operator.example',
    suffix,
    appKey,
    addressFamilyPolicy: 'dual-stack',
    expectedAddresses,
    expectedConnectAddress: '127.0.0.1',
    certificateFingerprint256: fingerprint256,
    certificateSpkiSha256: spkiSha256,
    publicSuffixReady: false,
    physicalEnforcementRequired: true,
    finiteProductionPolicy: { ...PUBLIC_HIVE_GATEWAY_FINITE_POLICY },
    release: {
      target: opts.releaseTarget || 'v1.2.3',
      expectedPath: '/index.html',
      expectedContentSha256: contentSha256,
      expectedDriveVersion: '7',
      expectedNginxSha256: nginxSha256
    }
  }
  const operatorContractSha256 = sha256PublicHiveGatewayOperatorContract(contract)
  const manifest = {
    schema: 'hiverelay-public-gateway-release-v1',
    enabled: true,
    releaseTarget: contract.release.target,
    admissionProfile: 'blind-substrate-public-v1',
    observationWindowMs: 24 * 60 * 60 * 1000,
    maxProbeGapMs: 20 * 60 * 1000,
    cohort: [{
      relay,
      channel: contract.channel,
      suffix,
      origin,
      connectAddress: contract.expectedConnectAddress,
      appKey,
      path: contract.release.expectedPath,
      contentSha256,
      driveVersion: contract.release.expectedDriveVersion,
      peerFingerprint256: fingerprint256,
      nginxConfigSha256: nginxSha256,
      deploymentProfile: 'public-t1-gateway',
      operatorContractSha256
    }]
  }
  const contractBytes = Buffer.from(JSON.stringify(contract) + '\n')
  const manifestBytes = Buffer.from(JSON.stringify(manifest) + '\n')
  const releaseManifestSha256 = sha256(manifestBytes)
  const evidence = {
    schema: PUBLIC_HIVE_GATEWAY_OPS_EVIDENCE_SCHEMA,
    status: 'pass',
    checkedAt,
    mode: 'fleet',
    deploymentProfile: 'public-t1-gateway',
    physicalEnforcementRequired: true,
    operator: {
      relay,
      operatorId: contract.operatorId,
      registrableDomain: contract.registrableDomain,
      apiHostname: contract.apiHostname,
      suffix,
      publicSuffixReady: false
    },
    gateway: {
      schema: 'hiverelay-public-gateway-evidence-verification-v2',
      status: 'verified',
      mode: 'fleet',
      admissionProfile: manifest.admissionProfile,
      publicSuffixReady: false,
      finiteProductionPolicy: { ...PUBLIC_HIVE_GATEWAY_FINITE_POLICY },
      releaseTarget: contract.release.target,
      releaseSha,
      checkedAt,
      probeObservedAt: checkedAt,
      origin,
      connectAddress: contract.expectedConnectAddress,
      appKey,
      path: contract.release.expectedPath,
      contentSha256,
      driveVersion: contract.release.expectedDriveVersion,
      physicalEnforcementRequired: true,
      tlsProtocol: 'TLSv1.3',
      peerFingerprint256: fingerprint256,
      nginxSha256,
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
      fingerprint256,
      spkiSha256,
      validFrom: new Date(now - 24 * 60 * 60 * 1000).toISOString(),
      validTo,
      dnsNames: [`*.${suffix}`],
      chainLength: 2,
      keyType: 'rsa'
    },
    dns: {
      source: 'live',
      expectedAddresses,
      addressFamilyPolicy: contract.addressFamilyPolicy,
      observed: {
        observedAt: checkedAt,
        hostname: appHostname,
        witnessHostname: `${encodeHiveAppKey(Buffer.alloc(32))}.${suffix}`,
        ipv4: expectedAddresses.filter(address => !address.includes(':')),
        ipv6: expectedAddresses.filter(address => address.includes(':')),
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
        observedAt: checkedAt,
        hostname: appHostname,
        port: 443,
        endpoints: expectedAddresses.map(address => ({
          address,
          protocol: 'TLSv1.3',
          fingerprint256,
          spkiSha256,
          validTo,
          probe: {
            schema: 'hiverelay-public-gateway-probe-v1',
            observedAt: checkedAt,
            origin,
            connectAddress: address,
            appKey,
            path: contract.release.expectedPath,
            sha256: contentSha256,
            bytes: 128,
            driveVersion: contract.release.expectedDriveVersion,
            tlsProtocol: 'TLSv1.3',
            peerFingerprint256: fingerprint256,
            peerValidTo: validTo,
            metadataSigned: false,
            checks: Object.fromEntries(PUBLIC_HIVE_GATEWAY_PROBE_CHECKS.map(name => [name, true]))
          }
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
      contractFileSha256: sha256(contractBytes),
      operatorContractSha256,
      configSha256: '1'.repeat(64),
      gatewayEvidenceSha256: '2'.repeat(64),
      releaseManifestSha256
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
    externalGates: ['independent timestamp and organizational-control proof'],
    errors: []
  }
  const evidenceBytes = Buffer.from(JSON.stringify(evidence) + '\n')
  return {
    contract,
    contractBytes,
    evidence,
    evidenceBytes,
    manifest,
    manifestBytes,
    operatorContractSha256,
    releaseManifestSha256,
    contractPath: operatorContractPathForRelay(relay),
    binding: { relay, path: operatorContractPathForRelay(relay), sha256: operatorContractSha256 }
  }
}

function sha256 (value) {
  return createHash('sha256').update(value).digest('hex')
}
