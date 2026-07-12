import test from 'brittle'
import { execFile, spawnSync } from 'node:child_process'
import { createHash, X509Certificate } from 'node:crypto'
import { chmod, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import {
  encodeHiveAppKey
} from '../../packages/core/gateway/hive-host.js'
import {
  PUBLIC_HIVE_GATEWAY_DNS_SNAPSHOT_SCHEMA,
  PUBLIC_HIVE_GATEWAY_FINITE_POLICY,
  PUBLIC_HIVE_GATEWAY_OPS_CONTRACT_SCHEMA,
  PUBLIC_HIVE_GATEWAY_TLS_SNAPSHOT_SCHEMA,
  inspectPublicHiveGatewayCertificate,
  normalizePublicHiveGatewayOpsContract
} from '../../scripts/lib/public-hive-gateway-ops.mjs'
import {
  PUBLIC_HIVE_GATEWAY_EVIDENCE_SCHEMA,
  PUBLIC_HIVE_GATEWAY_PROBE_CHECKS,
  PUBLIC_HIVE_GATEWAY_PROBE_SCHEMA
} from '../../scripts/lib/public-hive-gateway-evidence.mjs'

const execFileAsync = promisify(execFile)
const APP_KEY = 'a'.repeat(64)
const CONTENT_SHA = 'c'.repeat(64)
const NGINX_SHA = 'd'.repeat(64)
const RELEASE_SHA = 'e'.repeat(40)
const IPV4 = '8.8.8.8'
const IPV6 = '2606:4700:4700::1111'
const SUFFIX = 'hive-canary.operator.example'

test('public gateway ops certificate - wildcard SAN, key, chain, lifetime, and identity are exact', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'hiverelay-ops-cert-'))
  t.teardown(() => rm(root, { recursive: true, force: true }))
  const fixture = await createCertificateChain(root, SUFFIX)
  const contract = normalizePublicHiveGatewayOpsContract(contractFixture(fixture))
  const now = Date.now()
  const valid = inspectPublicHiveGatewayCertificate(fixture.fullchain, fixture.privateKey, contract, { now })
  t.ok(valid.ok, valid.errors.join('\n'))
  t.is(valid.identity.fingerprint256, fixture.fingerprint256)
  t.is(valid.identity.spkiSha256, fixture.spkiSha256)
  t.alike(valid.identity.dnsNames, [`*.${SUFFIX}`])
  t.is(valid.identity.chainLength, 2)

  const wrongKey = inspectPublicHiveGatewayCertificate(fixture.fullchain, fixture.caPrivateKey, contract, { now })
  t.absent(wrongKey.ok)
  t.ok(wrongKey.errors.some(value => value.includes('do not match')))

  const noChain = inspectPublicHiveGatewayCertificate(fixture.leafCertificate, fixture.privateKey, contract, { now })
  t.absent(noChain.ok)
  t.ok(noChain.errors.some(value => value.includes('fullchain')))

  const nearExpiry = inspectPublicHiveGatewayCertificate(fixture.fullchain, fixture.privateKey, contract, {
    now: Date.parse(fixture.validTo) - 6 * 24 * 60 * 60 * 1000
  })
  t.absent(nearExpiry.ok)
  t.ok(nearExpiry.errors.some(value => value.includes('at least 7 days')))

  const wrongSuffix = normalizePublicHiveGatewayOpsContract(contractFixture(fixture, {
    suffix: 'hive.other.example',
    registrableDomain: 'other.example',
    apiHostname: 'relay-api.other.example'
  }))
  const wrongSan = inspectPublicHiveGatewayCertificate(fixture.fullchain, fixture.privateKey, wrongSuffix, { now })
  t.absent(wrongSan.ok)
  t.ok(wrongSan.errors.some(value => value.includes('exactly the DNS SAN')))
})

test('public gateway ops CLI - certbot symlinks and offline DNS/TLS/socket fixtures produce bounded rehearsal evidence', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'hiverelay-ops-cli-'))
  t.teardown(() => rm(root, { recursive: true, force: true }))
  const certificateRoot = join(root, 'letsencrypt')
  const archive = join(certificateRoot, 'archive', 'hiverelay-public-apps')
  const live = join(certificateRoot, 'live', 'hiverelay-public-apps')
  await mkdir(archive, { recursive: true })
  await mkdir(live, { recursive: true })
  const fixture = await createCertificateChain(root, SUFFIX)
  const archiveCertificate = join(archive, 'fullchain1.pem')
  const archiveKey = join(archive, 'privkey1.pem')
  await writeFile(archiveCertificate, fixture.fullchain)
  await writeFile(archiveKey, fixture.privateKey, { mode: 0o600 })
  await symlink('../../archive/hiverelay-public-apps/fullchain1.pem', join(live, 'fullchain.pem'))
  await symlink('../../archive/hiverelay-public-apps/privkey1.pem', join(live, 'privkey.pem'))

  const now = Date.now()
  const contract = normalizePublicHiveGatewayOpsContract(contractFixture(fixture))
  const appHostname = contract.appHostname
  const witnessHostname = `${encodeHiveAppKey(Buffer.alloc(32))}.${SUFFIX}`
  const config = {
    productProfile: 'relay-core',
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
    hiveAppHostSuffix: SUFFIX,
    hiveAppPublicKeys: [APP_KEY],
    hiveAppPublicVersions: { [APP_KEY]: 7 }
  }
  const gatewayEvidence = baseEvidenceFixture(contract, now, fixture.validTo)
  const answer = {
    a: [{ address: IPV4, ttl: 300 }],
    aaaa: [{ address: IPV6, ttl: 300 }],
    cname: []
  }
  const dns = {
    schema: PUBLIC_HIVE_GATEWAY_DNS_SNAPSHOT_SCHEMA,
    observedAt: new Date(now).toISOString(),
    hostname: appHostname,
    witnessHostname,
    app: structuredClone(answer),
    witness: structuredClone(answer),
    routing: {
      app: { https: [], svcb: [] },
      witness: { https: [], svcb: [] }
    }
  }
  const tls = {
    schema: PUBLIC_HIVE_GATEWAY_TLS_SNAPSHOT_SCHEMA,
    observedAt: new Date(now).toISOString(),
    hostname: appHostname,
    port: 443,
    endpoints: [IPV4, IPV6].map(address => ({
      address,
      authorized: true,
      protocol: 'TLSv1.3',
      fingerprint256: fixture.fingerprint256,
      spkiSha256: fixture.spkiSha256,
      validTo: fixture.validTo,
      probe: { ...gatewayEvidence.probe, connectAddress: address }
    }))
  }
  const sockets = [
    'LISTEN 0 511 0.0.0.0:443 0.0.0.0:*',
    'LISTEN 0 511 [::]:443 [::]:*',
    'LISTEN 0 511 127.0.0.1:9100 0.0.0.0:*',
    'LISTEN 0 511 127.0.0.1:9200 0.0.0.0:*',
    ''
  ].join('\n')

  const contractPath = join(root, 'operator-contract.json')
  const configPath = join(root, 'config.json')
  const gatewayEvidencePath = join(root, 'gateway-evidence.json')
  const dnsPath = join(root, 'dns.json')
  const tlsPath = join(root, 'tls.json')
  const socketsPath = join(root, 'sockets.txt')
  const outputPath = join(root, 'ops-evidence.json')
  await Promise.all([
    writeFile(contractPath, JSON.stringify(contractFixture(fixture))),
    writeFile(configPath, JSON.stringify(config)),
    writeFile(gatewayEvidencePath, JSON.stringify(gatewayEvidence)),
    writeFile(dnsPath, JSON.stringify(dns)),
    writeFile(tlsPath, JSON.stringify(tls)),
    writeFile(socketsPath, sockets)
  ])

  const result = runOps([
    '--mode', 'rehearsal',
    '--contract', contractPath,
    '--config', configPath,
    '--gateway-evidence', gatewayEvidencePath,
    '--release-sha', RELEASE_SHA,
    '--certificate', join(live, 'fullchain.pem'),
    '--certificate-key', join(live, 'privkey.pem'),
    '--certificate-root', certificateRoot,
    '--dns-snapshot', dnsPath,
    '--tls-snapshot', tlsPath,
    '--socket-snapshot', socketsPath,
    '--evidence', outputPath
  ])
  t.is(result.status, 0, result.stderr)
  const evidence = JSON.parse(result.stdout)
  t.is(evidence.status, 'pass')
  t.alike(evidence.errors, [])
  t.is(evidence.certificate.fingerprint256, fixture.fingerprint256)
  t.is(evidence.certificate.spkiSha256, fixture.spkiSha256)
  t.alike(evidence.checks, {
    contract: true,
    config: true,
    certificate: true,
    dns: true,
    tls: true,
    sockets: true,
    gateway: true
  })
  t.absent(evidence.claims.provesCurrentDnsAnswers, 'fixture does not become live DNS proof')
  t.absent(evidence.claims.provesBlindG2)
  t.absent(evidence.claims.provesBlindG3)
  t.ok(evidence.claims.attestsFiniteProductionPolicyValues)
  t.absent(evidence.claims.provesFiniteProductionPolicyBehavior)
  t.is(evidence.finiteProductionPolicy.maxResponseBytes, 67108864)
  t.is(evidence.finiteProductionPolicy.egressWindowMs, 60000)
  t.absent(evidence.finiteProductionPolicy.signedReleaseBound)
  t.alike(JSON.parse(await readFile(outputPath, 'utf8')), evidence)

  await chmod(archiveKey, 0o644)
  const permissiveKey = runOps([
    '--mode', 'rehearsal',
    '--contract', contractPath,
    '--config', configPath,
    '--gateway-evidence', gatewayEvidencePath,
    '--release-sha', RELEASE_SHA,
    '--certificate', join(live, 'fullchain.pem'),
    '--certificate-key', join(live, 'privkey.pem'),
    '--certificate-root', certificateRoot,
    '--dns-snapshot', dnsPath,
    '--tls-snapshot', tlsPath,
    '--socket-snapshot', socketsPath
  ])
  t.not(permissiveKey.status, 0)
  t.ok(permissiveKey.stderr.includes('must not be group/world accessible'))
})

test('public gateway ops verifier CLI - readiness evidence cannot be supplied through a symlink', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'hiverelay-ops-verifier-'))
  t.teardown(() => rm(root, { recursive: true, force: true }))
  const target = join(root, 'target.json')
  const evidence = join(root, 'evidence.json')
  const contract = join(root, 'contract.json')
  const manifest = join(root, 'manifest.json')
  await writeFile(target, '{}\n')
  await symlink(target, evidence)
  await writeFile(contract, '{}\n')
  await writeFile(manifest, '{}\n')
  const result = spawnSync(process.execPath, [
    'scripts/verify-public-hive-gateway-ops-evidence.mjs',
    '--evidence', evidence,
    '--contract', contract,
    '--release-manifest', manifest,
    '--release-sha', RELEASE_SHA,
    '--relay', 'utah',
    '--expected-contract-sha256', 'f'.repeat(64)
  ], {
    encoding: 'utf8',
    maxBuffer: 1024 * 1024,
    timeout: 30_000
  })
  t.not(result.status, 0)
  t.ok(result.stderr.includes('operator readiness evidence must be a readable non-symlink file'))
})

async function createCertificateChain (directory, suffix) {
  const rootConfig = join(directory, `root-${Date.now()}.cnf`)
  const leafConfig = join(directory, `leaf-${Date.now()}.cnf`)
  const caKeyPath = join(directory, `root-${Date.now()}.key`)
  const caCertPath = join(directory, `root-${Date.now()}.crt`)
  const keyPath = join(directory, `leaf-${Date.now()}.key`)
  const requestPath = join(directory, `leaf-${Date.now()}.csr`)
  const certificatePath = join(directory, `leaf-${Date.now()}.crt`)
  await writeFile(rootConfig, [
    '[req]',
    'prompt = no',
    'distinguished_name = dn',
    'x509_extensions = extensions',
    '[dn]',
    'CN = HiveRelay operator test root',
    '[extensions]',
    'basicConstraints = critical,CA:TRUE,pathlen:1',
    'keyUsage = critical,keyCertSign,cRLSign',
    'subjectKeyIdentifier = hash',
    ''
  ].join('\n'))
  await writeFile(leafConfig, [
    '[req]',
    'prompt = no',
    'distinguished_name = dn',
    'req_extensions = extensions',
    '[dn]',
    `CN = *.${suffix}`,
    '[extensions]',
    'basicConstraints = critical,CA:FALSE',
    'keyUsage = critical,digitalSignature,keyEncipherment',
    'extendedKeyUsage = serverAuth',
    `subjectAltName = DNS:*.${suffix}`,
    ''
  ].join('\n'))
  await execFileAsync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '30',
    '-config', rootConfig, '-keyout', caKeyPath, '-out', caCertPath
  ])
  await execFileAsync('openssl', [
    'req', '-new', '-newkey', 'rsa:2048', '-nodes',
    '-config', leafConfig, '-keyout', keyPath, '-out', requestPath
  ])
  await execFileAsync('openssl', [
    'x509', '-req', '-in', requestPath,
    '-CA', caCertPath, '-CAkey', caKeyPath, '-CAcreateserial',
    '-days', '30', '-extfile', leafConfig, '-extensions', 'extensions',
    '-out', certificatePath
  ])
  const leafCertificate = await readFile(certificatePath, 'utf8')
  const caCertificate = await readFile(caCertPath, 'utf8')
  const privateKey = await readFile(keyPath, 'utf8')
  const caPrivateKey = await readFile(caKeyPath, 'utf8')
  const leaf = new X509Certificate(leafCertificate)
  return {
    fullchain: leafCertificate + caCertificate,
    leafCertificate,
    privateKey,
    caPrivateKey,
    fingerprint256: leaf.fingerprint256.toUpperCase(),
    spkiSha256: createHash('sha256').update(leaf.publicKey.export({ type: 'spki', format: 'der' })).digest('hex'),
    validTo: new Date(leaf.validToDate?.getTime?.() ?? Date.parse(leaf.validTo)).toISOString()
  }
}

function contractFixture (certificate, overrides = {}) {
  return {
    schema: PUBLIC_HIVE_GATEWAY_OPS_CONTRACT_SCHEMA,
    deploymentProfile: 'public-t1-gateway',
    relay: 'utah',
    channel: 'canary',
    operatorId: 'operator-a',
    registrableDomain: 'operator.example',
    apiHostname: 'relay-api.operator.example',
    suffix: SUFFIX,
    appKey: APP_KEY,
    addressFamilyPolicy: 'dual-stack',
    expectedAddresses: [IPV4, IPV6],
    expectedConnectAddress: '127.0.0.1',
    certificateFingerprint256: certificate.fingerprint256,
    certificateSpkiSha256: certificate.spkiSha256,
    publicSuffixReady: false,
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

function baseEvidenceFixture (contract, now, validTo) {
  return {
    schema: PUBLIC_HIVE_GATEWAY_EVIDENCE_SCHEMA,
    status: 'pass',
    checkedAt: new Date(now).toISOString(),
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
      finiteProductionPolicy: { ...PUBLIC_HIVE_GATEWAY_FINITE_POLICY }
    },
    static: { ok: true, errors: [], warnings: ['transitional rehearsal'] },
    nginx: { ok: true, errors: [], source: 'active', sha256: NGINX_SHA },
    probe: {
      schema: PUBLIC_HIVE_GATEWAY_PROBE_SCHEMA,
      observedAt: new Date(now).toISOString(),
      origin: contract.origin,
      connectAddress: contract.expectedConnectAddress,
      appKey: APP_KEY,
      path: '/index.html',
      sha256: CONTENT_SHA,
      bytes: 42,
      driveVersion: '7',
      tlsProtocol: 'TLSv1.3',
      peerFingerprint256: contract.certificateFingerprint256,
      peerValidTo: validTo,
      metadataSigned: false,
      checks: Object.fromEntries(PUBLIC_HIVE_GATEWAY_PROBE_CHECKS.map(name => [name, true]))
    },
    probeError: null
  }
}

function runOps (args) {
  return spawnSync(process.execPath, ['scripts/preflight-public-hive-gateway-ops.mjs', ...args], {
    encoding: 'utf8',
    maxBuffer: 4 * 1024 * 1024,
    timeout: 30_000
  })
}
