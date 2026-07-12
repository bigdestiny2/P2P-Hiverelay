import { createHash, createPrivateKey, X509Certificate } from 'node:crypto'
import { Resolver } from 'node:dns/promises'
import { isIP } from 'node:net'
import tls from 'node:tls'
import { Address4, Address6 } from 'ip-address'
import {
  encodeHiveAppKey,
  normalizeHiveAppHostSuffix
} from '../../packages/core/gateway/hive-host.js'
import {
  PUBLIC_HIVE_GATEWAY_EVIDENCE_SCHEMA,
  PUBLIC_HIVE_GATEWAY_PROBE_CHECKS,
  PUBLIC_HIVE_GATEWAY_PROBE_SCHEMA,
  verifyPublicHiveGatewayEvidence
} from './public-hive-gateway-evidence.mjs'
import { probePublicHiveGateway } from './public-hive-gateway-preflight.mjs'
import {
  PUBLIC_HIVE_GATEWAY_DEPLOYMENT_PROFILE,
  PUBLIC_HIVE_GATEWAY_FINITE_CONFIG_FIELDS,
  PUBLIC_HIVE_GATEWAY_FINITE_POLICY
} from './public-hive-gateway-policy.mjs'
import {
  resolvePublicHiveGatewayRoutingRecords
} from './public-hive-gateway-quarantine-authority.mjs'
import {
  PUBLIC_HIVE_GATEWAY_OPERATOR_CONTRACT_SCHEMA,
  assertOperatorContractMatchesCohort,
  canonicalPublicHiveGatewayOperatorContract,
  cohortEntryForRelay,
  normalizePublicHiveGatewayOperatorContract,
  normalizePublicHiveGatewayReleaseManifest,
  sha256PublicHiveGatewayOperatorContract
} from './public-hive-gateway-release-manifest.mjs'

export {
  PUBLIC_HIVE_GATEWAY_DEPLOYMENT_PROFILE,
  PUBLIC_HIVE_GATEWAY_FINITE_POLICY
} from './public-hive-gateway-policy.mjs'

export const PUBLIC_HIVE_GATEWAY_OPS_CONTRACT_SCHEMA = PUBLIC_HIVE_GATEWAY_OPERATOR_CONTRACT_SCHEMA
export const PUBLIC_HIVE_GATEWAY_OPS_EVIDENCE_SCHEMA = 'hiverelay-public-gateway-operator-readiness-v2'
export const PUBLIC_HIVE_GATEWAY_DNS_SNAPSHOT_SCHEMA = 'hiverelay-public-gateway-dns-snapshot-v2'
export const PUBLIC_HIVE_GATEWAY_TLS_SNAPSHOT_SCHEMA = 'hiverelay-public-gateway-tls-snapshot-v1'
export const PUBLIC_HIVE_GATEWAY_OPERATOR_SET_SCHEMA = 'hiverelay-public-gateway-operator-set-v1'

export function canonicalPublicHiveGatewayOpsContract (value) {
  return canonicalPublicHiveGatewayOperatorContract(normalizePublicHiveGatewayOpsContract(value))
}

export function sha256PublicHiveGatewayOpsContract (value) {
  return sha256PublicHiveGatewayOperatorContract(normalizePublicHiveGatewayOpsContract(value))
}

const SHA256_PATTERN = /^[a-f0-9]{64}$/
const FINGERPRINT256_PATTERN = /^(?:[A-F0-9]{2}:){31}[A-F0-9]{2}$/
const RELEASE_TAG_PATTERN = /^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/
const RELEASE_SHA_PATTERN = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/
const DRIVE_VERSION_PATTERN = /^(?:0|[1-9][0-9]{0,19})$/
const OPERATOR_ID_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/
const CERTIFICATE_PEM_PATTERN = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g
const PRIVATE_KEY_PEM_PATTERN = /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC )?PRIVATE KEY-----/g
const MIN_CERTIFICATE_REMAINING_MS = 7 * 24 * 60 * 60 * 1000
const MAX_CERTIFICATE_LIFETIME_MS = 398 * 24 * 60 * 60 * 1000
const MAX_SNAPSHOT_AGE_MS = 15 * 60 * 1000
const MAX_FUTURE_SKEW_MS = 5 * 60 * 1000
const MIN_DNS_TTL_SECONDS = 30
const MAX_DNS_TTL_SECONDS = 900

export function normalizePublicHiveGatewayOpsContract (value) {
  const normalized = normalizePublicHiveGatewayOperatorContract(value)
  for (const [index, address] of normalized.expectedAddresses.entries()) {
    requirePublicAddress(address, `operator expectedAddresses[${index}]`)
  }
  return normalized
}

export function inspectPublicHiveGatewayCertificate (fullchainPem, privateKeyPem, contract, opts = {}) {
  const errors = []
  const nowMs = normalizeNow(opts.now)
  let certificates = []
  let privateKey = null

  try {
    certificates = parseCertificateChain(fullchainPem)
  } catch (err) {
    errors.push(err.message)
  }
  try {
    privateKey = parsePrivateKey(privateKeyPem)
  } catch (err) {
    errors.push(err.message)
  }
  if (certificates.length === 0) return { ok: false, errors, identity: null }

  const leaf = certificates[0]
  const validFromMs = leaf.validFromDate?.getTime?.() ?? Date.parse(leaf.validFrom)
  const validToMs = leaf.validToDate?.getTime?.() ?? Date.parse(leaf.validTo)
  if (!Number.isFinite(validFromMs) || validFromMs > nowMs + MAX_FUTURE_SKEW_MS) {
    errors.push('operator leaf certificate is not valid yet')
  }
  if (!Number.isFinite(validToMs) || validToMs - nowMs < MIN_CERTIFICATE_REMAINING_MS) {
    errors.push('operator leaf certificate must remain valid for at least 7 days')
  }
  if (Number.isFinite(validFromMs) && Number.isFinite(validToMs) && validToMs - validFromMs > MAX_CERTIFICATE_LIFETIME_MS) {
    errors.push('operator leaf certificate lifetime exceeds the reviewed 398-day Web PKI ceiling')
  }
  if (leaf.ca === true) errors.push('operator leaf certificate must not be a CA certificate')

  const expectedWildcard = `*.${contract.suffix}`
  const dnsNames = parseDnsSubjectAltNames(leaf.subjectAltName)
  if (dnsNames === null) {
    errors.push('operator leaf certificate SAN extension must contain only parseable DNS names')
  } else if (dnsNames.length !== 1 || dnsNames[0] !== expectedWildcard) {
    errors.push(`operator leaf certificate must contain exactly the DNS SAN ${expectedWildcard}`)
  }
  const checkedHost = leaf.checkHost(contract.appHostname, {
    subject: 'never',
    wildcards: true,
    partialWildcards: false,
    multiLabelWildcards: false,
    singleLabelSubdomains: false
  })
  if (checkedHost !== expectedWildcard) errors.push('operator leaf certificate does not exactly cover the key-derived app hostname')
  if (leaf.checkHost(contract.apiHostname, { subject: 'never' })) {
    errors.push('operator wildcard certificate must not cover the management/API hostname')
  }

  if (privateKey) {
    try {
      if (!leaf.checkPrivateKey(privateKey)) errors.push('operator certificate and private key do not match')
    } catch {
      errors.push('operator certificate and private key match could not be verified')
    }
    inspectKeyStrength(privateKey, errors)
  }

  const fingerprints = new Set()
  for (let index = 0; index < certificates.length; index++) {
    const certificate = certificates[index]
    if (fingerprints.has(certificate.fingerprint256)) errors.push('operator certificate chain contains a duplicate certificate')
    fingerprints.add(certificate.fingerprint256)
    const chainValidFrom = certificate.validFromDate?.getTime?.() ?? Date.parse(certificate.validFrom)
    const chainValidTo = certificate.validToDate?.getTime?.() ?? Date.parse(certificate.validTo)
    if (!Number.isFinite(chainValidFrom) || !Number.isFinite(chainValidTo) ||
        chainValidFrom > nowMs + MAX_FUTURE_SKEW_MS || chainValidTo - nowMs < MIN_CERTIFICATE_REMAINING_MS) {
      errors.push(`operator certificate chain member ${index} is outside the required validity window`)
    }
    if (index === certificates.length - 1) continue
    const issuer = certificates[index + 1]
    if (issuer.ca !== true || !certificate.checkIssued(issuer) || !certificate.verify(issuer.publicKey)) {
      errors.push(`operator certificate chain link ${index} is not issued by the following CA certificate`)
    }
  }
  if (certificates.length < 2) errors.push('operator fullchain must include the issuing intermediate or trust anchor after the leaf')

  const fingerprint256 = leaf.fingerprint256.toUpperCase()
  const spkiSha256 = createHash('sha256')
    .update(leaf.publicKey.export({ type: 'spki', format: 'der' }))
    .digest('hex')
  if (fingerprint256 !== contract.certificateFingerprint256) {
    errors.push('operator leaf certificate fingerprint does not match the reviewed contract')
  }
  if (spkiSha256 !== contract.certificateSpkiSha256) {
    errors.push('operator leaf certificate SPKI does not match the reviewed contract')
  }

  return {
    ok: errors.length === 0,
    errors,
    identity: {
      fingerprint256,
      spkiSha256,
      validFrom: Number.isFinite(validFromMs) ? new Date(validFromMs).toISOString() : null,
      validTo: Number.isFinite(validToMs) ? new Date(validToMs).toISOString() : null,
      dnsNames: dnsNames || [],
      chainLength: certificates.length,
      keyType: leaf.publicKey.asymmetricKeyType || null
    }
  }
}

export function inspectPublicHiveGatewayDnsSnapshot (snapshot, contract, opts = {}) {
  const errors = []
  requireObject(snapshot, 'operator DNS snapshot')
  requireOnlyKeys('operator DNS snapshot', snapshot, [
    'schema', 'observedAt', 'hostname', 'witnessHostname', 'app', 'witness', 'routing'
  ])
  requireEqual(snapshot.schema, PUBLIC_HIVE_GATEWAY_DNS_SNAPSHOT_SCHEMA, 'operator DNS snapshot schema')
  const observedAtMs = requireFreshTimestamp(snapshot.observedAt, 'operator DNS snapshot observedAt', opts.now)
  requireEqual(snapshot.hostname, contract.appHostname, 'operator DNS snapshot hostname')
  const expectedWitness = witnessHostnameFor(contract)
  requireEqual(snapshot.witnessHostname, expectedWitness, 'operator DNS wildcard witness hostname')

  const app = normalizeDnsAnswer(snapshot.app, 'operator app DNS answer', errors)
  const witness = normalizeDnsAnswer(snapshot.witness, 'operator wildcard witness DNS answer', errors)
  const expectedIpv4 = contract.expectedAddresses.filter(address => isIP(address) === 4)
  const expectedIpv6 = contract.expectedAddresses.filter(address => isIP(address) === 6)
  compareAddressSets(app.ipv4, expectedIpv4, 'operator app A records', errors)
  compareAddressSets(app.ipv6, expectedIpv6, 'operator app AAAA records', errors)
  compareAddressSets(witness.ipv4, expectedIpv4, 'operator wildcard witness A records', errors)
  compareAddressSets(witness.ipv6, expectedIpv6, 'operator wildcard witness AAAA records', errors)
  if (app.cnames.length > 0 || witness.cnames.length > 0) {
    errors.push('operator app DNS must use direct A/AAAA records without CNAME indirection')
  }
  for (const label of ['app', 'witness']) {
    const routing = snapshot.routing?.[label]
    if (!routing || typeof routing !== 'object' || Array.isArray(routing) ||
        Object.keys(routing).sort().join(',') !== 'https,svcb' ||
        !Array.isArray(routing.https) || !Array.isArray(routing.svcb) ||
        routing.https.length !== 0 || routing.svcb.length !== 0) {
      errors.push(`operator Phase 1 ${label} DNS must have empty HTTPS and SVCB RRsets`)
    }
  }
  if (!snapshot.routing || typeof snapshot.routing !== 'object' || Array.isArray(snapshot.routing) ||
      Object.keys(snapshot.routing).sort().join(',') !== 'app,witness') {
    errors.push('operator Phase 1 DNS routing evidence must bind exactly the app and wildcard witness')
  }

  return {
    ok: errors.length === 0,
    errors,
    result: {
      observedAt: new Date(observedAtMs).toISOString(),
      hostname: contract.appHostname,
      witnessHostname: expectedWitness,
      ipv4: app.ipv4,
      ipv6: app.ipv6,
      routing: {
        app: { https: [], svcb: [] },
        witness: { https: [], svcb: [] }
      },
      ttlRangeSeconds: ttlRange([...app.ttls, ...witness.ttls])
    }
  }
}

export async function collectPublicHiveGatewayDnsSnapshot (contract, opts = {}) {
  const resolver = opts.resolver || new Resolver()
  const resolveRouting = opts.resolveRoutingRecords || ((hostname, rrtype) =>
    resolvePublicHiveGatewayRoutingRecords(hostname, rrtype, {
      resolver,
      servers: opts.servers,
      timeoutMs: opts.timeoutMs
    }))
  const witnessHostname = witnessHostnameFor(contract)
  return {
    schema: PUBLIC_HIVE_GATEWAY_DNS_SNAPSHOT_SCHEMA,
    observedAt: new Date(normalizeNow(opts.now)).toISOString(),
    hostname: contract.appHostname,
    witnessHostname,
    app: await resolveDnsAnswer(resolver, contract.appHostname),
    witness: await resolveDnsAnswer(resolver, witnessHostname),
    routing: {
      app: {
        https: await resolveRouting(contract.appHostname, 'HTTPS'),
        svcb: await resolveRouting(contract.appHostname, 'SVCB')
      },
      witness: {
        https: await resolveRouting(witnessHostname, 'HTTPS'),
        svcb: await resolveRouting(witnessHostname, 'SVCB')
      }
    }
  }
}

export function inspectPublicHiveGatewayTlsSnapshot (snapshot, contract, certificateIdentity, opts = {}) {
  const errors = []
  requireObject(snapshot, 'operator TLS snapshot')
  requireOnlyKeys('operator TLS snapshot', snapshot, ['schema', 'observedAt', 'hostname', 'port', 'endpoints'])
  requireEqual(snapshot.schema, PUBLIC_HIVE_GATEWAY_TLS_SNAPSHOT_SCHEMA, 'operator TLS snapshot schema')
  const observedAtMs = requireFreshTimestamp(snapshot.observedAt, 'operator TLS snapshot observedAt', opts.now)
  requireEqual(snapshot.hostname, contract.appHostname, 'operator TLS snapshot hostname')
  requireEqual(snapshot.port, 443, 'operator TLS snapshot port')
  if (!Array.isArray(snapshot.endpoints) || snapshot.endpoints.length !== contract.expectedAddresses.length) {
    errors.push('operator TLS snapshot must contain exactly one result for every reviewed public address')
  }

  const endpoints = []
  for (const [index, endpoint] of (Array.isArray(snapshot.endpoints) ? snapshot.endpoints : []).entries()) {
    try {
      requireObject(endpoint, `operator TLS endpoint[${index}]`)
      requireOnlyKeys(`operator TLS endpoint[${index}]`, endpoint, [
        'address', 'authorized', 'protocol', 'fingerprint256', 'spkiSha256', 'validTo', 'probe'
      ])
      const address = requirePublicAddress(endpoint.address, `operator TLS endpoint[${index}] address`)
      requireEqual(endpoint.authorized, true, `operator TLS endpoint[${index}] authorization`)
      if (endpoint.protocol !== 'TLSv1.2' && endpoint.protocol !== 'TLSv1.3') {
        throw new Error(`operator TLS endpoint[${index}] must negotiate TLS 1.2 or TLS 1.3`)
      }
      const fingerprint256 = String(endpoint.fingerprint256 || '').toUpperCase()
      const spkiSha256 = String(endpoint.spkiSha256 || '').toLowerCase()
      if (!FINGERPRINT256_PATTERN.test(fingerprint256)) throw new Error(`operator TLS endpoint[${index}] fingerprint is invalid`)
      if (!SHA256_PATTERN.test(spkiSha256)) throw new Error(`operator TLS endpoint[${index}] SPKI is invalid`)
      requireEqual(fingerprint256, certificateIdentity.fingerprint256, `operator TLS endpoint[${index}] certificate fingerprint`)
      requireEqual(spkiSha256, certificateIdentity.spkiSha256, `operator TLS endpoint[${index}] certificate SPKI`)
      const validToMs = Date.parse(endpoint.validTo)
      if (!Number.isFinite(validToMs) || validToMs - normalizeNow(opts.now) < MIN_CERTIFICATE_REMAINING_MS) {
        throw new Error(`operator TLS endpoint[${index}] certificate must remain valid for at least 7 days`)
      }
      const probe = normalizePerAddressGatewayProbe(
        endpoint.probe, contract, address, fingerprint256, endpoint.protocol, endpoint.validTo, opts.now
      )
      endpoints.push({ address, protocol: endpoint.protocol, fingerprint256, spkiSha256, validTo: new Date(validToMs).toISOString(), probe })
    } catch (err) {
      errors.push(err.message)
    }
  }
  compareAddressSets(endpoints.map(endpoint => endpoint.address), contract.expectedAddresses, 'operator TLS endpoint addresses', errors)

  return {
    ok: errors.length === 0,
    errors,
    result: {
      observedAt: new Date(observedAtMs).toISOString(),
      hostname: contract.appHostname,
      port: 443,
      endpoints: endpoints.sort((left, right) => compareAddresses(left.address, right.address))
    }
  }
}

export async function collectPublicHiveGatewayTlsSnapshot (contract, opts = {}) {
  const endpoints = []
  for (const address of contract.expectedAddresses) {
    const tls = await probeTlsEndpoint(address, contract.appHostname, opts)
    const probe = opts.baseProbe && address === contract.expectedConnectAddress
      ? structuredClone(opts.baseProbe)
      : await probePublicHiveGateway({
        origin: contract.origin,
        appKey: contract.appKey,
        suffix: contract.suffix,
        connectAddress: address,
        path: contract.release.expectedPath,
        expectedSha256: contract.release.expectedContentSha256,
        expectedDriveVersion: Number(contract.release.expectedDriveVersion),
        ca: opts.ca,
        timeoutMs: opts.timeoutMs
      })
    endpoints.push({ ...tls, probe })
  }
  return {
    schema: PUBLIC_HIVE_GATEWAY_TLS_SNAPSHOT_SCHEMA,
    observedAt: new Date(normalizeNow(opts.now)).toISOString(),
    hostname: contract.appHostname,
    port: 443,
    endpoints
  }
}

export function inspectPublicHiveGatewaySocketSnapshot (text, config) {
  const errors = []
  if (typeof text !== 'string' || Buffer.byteLength(text) > 1024 * 1024) {
    return { ok: false, errors: ['operator socket snapshot must be a bounded string'], result: null }
  }
  const apiHost = requireNumericLoopback(config.apiHost, 'operator API listener host')
  const gatewayHost = requireNumericLoopback(config.gatewayHost, 'operator gateway listener host')
  const apiPort = requirePort(config.apiPort, 'operator API listener port')
  const gatewayPort = requirePort(config.gatewayPort, 'operator gateway listener port')
  if (apiPort === gatewayPort || apiPort === 443 || gatewayPort === 443) {
    errors.push('operator API, gateway, and public TLS listeners must use distinct ports')
  }

  const parsed = []
  for (const [index, line] of text.split(/\r?\n/).entries()) {
    if (!line.trim()) continue
    try {
      parsed.push(parseSsLine(line, index))
    } catch (err) {
      errors.push(err.message)
    }
  }
  const tcpListeners = parsed.filter(listener => listener.protocol === 'tcp')
  const udp443Listeners = parsed.filter(listener => listener.protocol === 'udp' && listener.port === 443)
  const apiListeners = tcpListeners.filter(listener => listener.port === apiPort)
  const gatewayListeners = tcpListeners.filter(listener => listener.port === gatewayPort)
  const tlsListeners = tcpListeners.filter(listener => listener.port === 443)
  requireExactLoopbackListeners(apiListeners, apiHost, 'operator API listener', errors)
  requireExactLoopbackListeners(gatewayListeners, gatewayHost, 'operator gateway listener', errors)
  const hasPublicIpv4 = tlsListeners.some(listener => listener.address === '0.0.0.0')
  const hasPublicIpv6 = tlsListeners.some(listener => listener.address === '::')
  if (!hasPublicIpv4 || !hasPublicIpv6 || tlsListeners.length !== 2) {
    errors.push('operator public TLS port 443 must have exactly the reviewed wildcard IPv4 and IPv6 listeners')
  }
  if (udp443Listeners.length !== 0) errors.push('operator Phase 1 edge must not expose UDP/QUIC port 443')

  return {
    ok: errors.length === 0,
    errors,
    result: {
      api: apiListeners.map(formatListener),
      gateway: gatewayListeners.map(formatListener),
      tls: tlsListeners.map(formatListener),
      udp443: udp443Listeners.map(formatListener)
    }
  }
}

export function inspectPublicHiveGatewayOpsConfig (config, contract, mode, opts = {}) {
  const errors = []
  if (!config || typeof config !== 'object' || Array.isArray(config)) {
    return { ok: false, errors: ['operator gateway config must be an object'], result: null }
  }
  const suffix = normalizeHiveAppHostSuffix(config.hiveAppHostSuffix)
  if (suffix !== contract.suffix) errors.push('operator gateway config suffix does not match the reviewed contract')
  if (!Array.isArray(config.hiveAppPublicKeys) || config.hiveAppPublicKeys.length !== 1 ||
      String(config.hiveAppPublicKeys[0] || '').toLowerCase() !== contract.appKey) {
    errors.push('operator gateway config must admit exactly the one contract-bound public app')
  }
  const versions = config.hiveAppPublicVersions
  if (!versions || typeof versions !== 'object' || Array.isArray(versions) ||
      Object.keys(versions).length !== 1 || versions[contract.appKey] !== Number(contract.release.expectedDriveVersion)) {
    errors.push('operator gateway config must pin exactly the contract-bound immutable drive version')
  }
  try { requireNumericLoopback(config.apiHost, 'operator API listener host') } catch (err) { errors.push(err.message) }
  try { requireNumericLoopback(config.gatewayHost, 'operator gateway listener host') } catch (err) { errors.push(err.message) }
  if (config.custody?.enabled !== false) errors.push('operator public-t1-gateway config must explicitly disable T2 custody')
  if (config.gatewayTrustProxy !== true || config.gatewayRequireForwardedSNI !== true) {
    errors.push('operator gateway config must require the reviewed loopback proxy and forwarded SNI binding')
  }
  for (const [field, expected] of Object.entries(PUBLIC_HIVE_GATEWAY_FINITE_CONFIG_FIELDS)) {
    if (!Object.hasOwn(opts.explicitConfig || config, field) || config[field] !== expected) {
      errors.push(`operator gateway config must explicitly pin ${field} to ${expected}`)
    }
  }
  if (mode === 'fleet' && config.productProfile !== PUBLIC_HIVE_GATEWAY_DEPLOYMENT_PROFILE) {
    errors.push('fleet operator config must expose the exact compiled public-t1-gateway product profile')
  }
  return {
    ok: errors.length === 0,
    errors,
    result: {
      productProfile: config.productProfile || null,
      apiHost: config.apiHost,
      apiPort: config.apiPort,
      gatewayHost: config.gatewayHost,
      gatewayPort: config.gatewayPort,
      custodyEnabled: config.custody?.enabled === true,
      admittedAppCount: Array.isArray(config.hiveAppPublicKeys) ? config.hiveAppPublicKeys.length : 0,
      finiteProductionPolicy: {
        ...contract.finiteProductionPolicy,
        configured: {
          maxResponseBytes: config.gatewayMaxResponseBytes,
          maxTransformBytes: config.gatewayMaxTransformBytes,
          egressBytesPerClientAppWindow: config.gatewayEgressBytesPerWindow,
          egressWindowMs: config.gatewayEgressWindowMs,
          maxResponseLifetimeMs: config.gatewayMaxResponseLifetimeMs
        }
      }
    }
  }
}

export function inspectPublicHiveGatewayBaseEvidence (evidence, config, contract, mode, opts = {}) {
  const errors = []
  if (mode === 'fleet') {
    try {
      const verified = verifyPublicHiveGatewayEvidence(evidence, {
        releaseTarget: contract.release.target,
        releaseSha: opts.releaseSha,
        now: opts.now,
        maxAgeMs: MAX_SNAPSHOT_AGE_MS,
        requireMode: 'fleet',
        expectedOrigin: contract.origin,
        expectedConnectAddress: contract.expectedConnectAddress,
        expectedAppKey: contract.appKey,
        expectedPath: contract.release.expectedPath,
        expectedSha256: contract.release.expectedContentSha256,
        expectedDriveVersion: contract.release.expectedDriveVersion,
        expectedPeerFingerprint256: contract.certificateFingerprint256,
        expectedNginxSha256: contract.release.expectedNginxSha256
      })
      return { ok: true, errors: [], result: verified }
    } catch (err) {
      return { ok: false, errors: [err.message], result: null }
    }
  }

  try {
    requireObject(evidence, 'operator base gateway evidence')
    requireEqual(evidence.schema, PUBLIC_HIVE_GATEWAY_EVIDENCE_SCHEMA, 'operator base gateway evidence schema')
    requireEqual(evidence.status, 'pass', 'operator base gateway evidence status')
    requireFreshTimestamp(evidence.checkedAt, 'operator base gateway evidence checkedAt', opts.now)
    requireEqual(evidence.mode, 'canary', 'operator rehearsal gateway evidence mode')
    requireObject(evidence.release, 'operator base gateway evidence release')
    requireEqual(evidence.release?.target, contract.release.target, 'operator base gateway release target')
    requireEqual(String(evidence.release?.sha || '').toLowerCase(), opts.releaseSha, 'operator base gateway release SHA')
    requireObject(evidence.config, 'operator base gateway evidence config')
    requireEqual(evidence.config?.suffix, contract.suffix, 'operator base gateway suffix')
    requireEqual(evidence.config?.appKeyCount, 1, 'operator base gateway admitted app count')
    requireEqual(evidence.config?.apiHost, config.apiHost, 'operator base gateway API host')
    requireEqual(evidence.config?.apiPort, config.apiPort, 'operator base gateway API port')
    requireEqual(evidence.config?.gatewayHost, config.gatewayHost, 'operator base gateway host')
    requireEqual(evidence.config?.gatewayPort, config.gatewayPort, 'operator base gateway port')
    requireEqual(normalizeAddress(evidence.config?.connectAddress), contract.expectedConnectAddress, 'operator base gateway connect address')
    requireEqual(evidence.config?.publicSuffixReady, contract.publicSuffixReady, 'operator base gateway Public Suffix assertion')
    requireEqual(evidence.config?.custodyEnabled, false, 'operator base gateway custody status')
    requireObject(evidence.config?.finiteProductionPolicy, 'operator base gateway finite production policy')
    for (const [field, expected] of Object.entries(contract.finiteProductionPolicy)) {
      requireEqual(evidence.config.finiteProductionPolicy[field], expected, `operator base gateway finite production policy ${field}`)
    }
    requireEqual(evidence.static?.ok, true, 'operator base gateway static preflight')
    if (!Array.isArray(evidence.static?.errors) || evidence.static.errors.length !== 0) {
      throw new Error('operator base gateway static errors must be empty')
    }
    requireEqual(evidence.nginx?.ok, true, 'operator base gateway active nginx status')
    requireEqual(evidence.nginx?.source, 'active', 'operator base gateway active nginx source')
    requireEqual(String(evidence.nginx?.sha256 || '').toLowerCase(), contract.release.expectedNginxSha256, 'operator base gateway active nginx SHA-256')
    if (!Array.isArray(evidence.nginx?.errors) || evidence.nginx.errors.length !== 0) {
      throw new Error('operator base gateway active nginx errors must be empty')
    }
    requireEqual(evidence.probeError, null, 'operator base gateway probe error')
    requireObject(evidence.probe, 'operator base gateway live probe')
    requireEqual(evidence.probe?.schema, PUBLIC_HIVE_GATEWAY_PROBE_SCHEMA, 'operator base gateway live probe schema')
    requireFreshTimestamp(evidence.probe?.observedAt, 'operator base gateway live probe observedAt', opts.now)
    requireEqual(evidence.probe?.origin, contract.origin, 'operator base gateway probe origin')
    requireEqual(normalizeAddress(evidence.probe?.connectAddress), contract.expectedConnectAddress, 'operator base gateway probe connect address')
    requireEqual(evidence.probe?.appKey, contract.appKey, 'operator base gateway probe appKey')
    requireEqual(evidence.probe?.path, contract.release.expectedPath, 'operator base gateway probe path')
    requireEqual(evidence.probe?.sha256, contract.release.expectedContentSha256, 'operator base gateway content SHA-256')
    requireEqual(evidence.probe?.driveVersion, contract.release.expectedDriveVersion, 'operator base gateway drive version')
    if (evidence.probe?.tlsProtocol !== 'TLSv1.2' && evidence.probe?.tlsProtocol !== 'TLSv1.3') {
      throw new Error('operator base gateway live probe must negotiate TLS 1.2 or TLS 1.3')
    }
    requireEqual(String(evidence.probe?.peerFingerprint256 || '').toUpperCase(), contract.certificateFingerprint256, 'operator base gateway TLS fingerprint')
    const peerValidTo = Date.parse(evidence.probe?.peerValidTo)
    if (!Number.isFinite(peerValidTo) || peerValidTo - normalizeNow(opts.now) < MIN_CERTIFICATE_REMAINING_MS) {
      throw new Error('operator base gateway TLS certificate must remain valid for at least 7 days')
    }
    requireObject(evidence.probe?.checks, 'operator base gateway live checks')
    for (const check of PUBLIC_HIVE_GATEWAY_PROBE_CHECKS) {
      requireEqual(evidence.probe.checks[check], true, `operator base gateway live check ${check}`)
    }
  } catch (err) {
    errors.push(err.message)
  }
  return {
    ok: errors.length === 0,
    errors,
    result: errors.length === 0
      ? {
          mode: evidence.mode,
          admissionProfile: evidence.admissionProfile,
          releaseTarget: evidence.release.target,
          releaseSha: evidence.release.sha,
          checkedAt: evidence.checkedAt,
          probeObservedAt: evidence.probe.observedAt,
          origin: evidence.probe.origin,
          connectAddress: evidence.probe.connectAddress,
          appKey: evidence.probe.appKey,
          contentSha256: evidence.probe.sha256,
          driveVersion: evidence.probe.driveVersion,
          peerFingerprint256: String(evidence.probe.peerFingerprint256).toUpperCase(),
          nginxSha256: evidence.nginx.sha256
        }
      : null
  }
}

export function verifyPublicHiveGatewayOpsEvidence (evidence, opts = {}) {
  const contract = normalizePublicHiveGatewayOpsContract(opts.contract)
  const releaseSha = String(opts.releaseSha || '').toLowerCase()
  if (!RELEASE_SHA_PATTERN.test(releaseSha)) throw new Error('expected ops evidence release SHA is invalid')
  if (opts.relay && opts.relay !== contract.relay) throw new Error('expected ops evidence relay does not match operator contract')
  const manifest = normalizePublicHiveGatewayReleaseManifest(opts.manifest, {
    releaseTarget: contract.release.target,
    requirePublicT1: true
  })
  const cohortEntry = cohortEntryForRelay(manifest, contract.relay)
  const binding = assertOperatorContractMatchesCohort(contract, manifest, cohortEntry)
  const expectedDigest = String(opts.expectedContractSha256 || binding.digest).toLowerCase()
  if (!SHA256_PATTERN.test(expectedDigest) || expectedDigest !== binding.digest) {
    throw new Error('expected operator contract SHA-256 does not match the signed cohort')
  }

  requireObject(evidence, 'operator readiness evidence')
  requireOnlyKeys('operator readiness evidence', evidence, [
    'schema', 'status', 'checkedAt', 'mode', 'deploymentProfile', 'operator',
    'gateway', 'finiteProductionPolicy', 'certificate', 'dns', 'tls',
    'sockets', 'sourceDigests', 'checks', 'claims', 'externalGates', 'errors'
  ])
  requireEqual(evidence.schema, PUBLIC_HIVE_GATEWAY_OPS_EVIDENCE_SCHEMA, 'operator readiness evidence schema')
  requireEqual(evidence.status, 'pass', 'operator readiness evidence status')
  requireFreshTimestamp(evidence.checkedAt, 'operator readiness evidence checkedAt', opts.now)
  requireEqual(evidence.mode, 'fleet', 'operator readiness evidence mode')
  requireEqual(evidence.deploymentProfile, PUBLIC_HIVE_GATEWAY_DEPLOYMENT_PROFILE, 'operator readiness evidence profile')
  if (!Array.isArray(evidence.errors) || evidence.errors.length !== 0) throw new Error('operator readiness evidence errors must be empty')

  requireObject(evidence.operator, 'operator readiness operator')
  requireOnlyKeys('operator readiness operator', evidence.operator, [
    'relay', 'operatorId', 'registrableDomain', 'apiHostname', 'suffix', 'publicSuffixReady'
  ])
  const operatorBindings = {
    relay: contract.relay,
    operatorId: contract.operatorId,
    registrableDomain: contract.registrableDomain,
    apiHostname: contract.apiHostname,
    suffix: contract.suffix,
    publicSuffixReady: contract.publicSuffixReady
  }
  for (const [field, expected] of Object.entries(operatorBindings)) {
    requireEqual(evidence.operator[field], expected, `operator readiness operator ${field}`)
  }

  requireObject(evidence.gateway, 'operator readiness gateway')
  requireOnlyKeys('operator readiness gateway', evidence.gateway, [
    'schema', 'status', 'mode', 'admissionProfile', 'publicSuffixReady',
    'finiteProductionPolicy', 'releaseTarget', 'releaseSha', 'checkedAt',
    'probeObservedAt', 'origin', 'connectAddress', 'appKey', 'path',
    'contentSha256', 'driveVersion', 'tlsProtocol', 'peerFingerprint256',
    'nginxSha256', 'checks'
  ])
  requireEqual(evidence.gateway.schema, 'hiverelay-public-gateway-evidence-verification-v1',
    'operator readiness gateway schema')
  requireEqual(evidence.gateway.status, 'verified', 'operator readiness gateway status')
  requireEqual(evidence.gateway.admissionProfile, manifest.admissionProfile,
    'operator readiness gateway admission profile')
  requireFreshTimestamp(evidence.gateway.checkedAt, 'operator readiness gateway checkedAt', opts.now)
  requireFreshTimestamp(evidence.gateway.probeObservedAt, 'operator readiness gateway probeObservedAt', opts.now)
  if (evidence.gateway.tlsProtocol !== 'TLSv1.2' && evidence.gateway.tlsProtocol !== 'TLSv1.3') {
    throw new Error('operator readiness gateway TLS protocol must be TLS 1.2 or TLS 1.3')
  }
  requireObject(evidence.gateway.finiteProductionPolicy, 'operator readiness gateway finite production policy')
  requireOnlyKeys('operator readiness gateway finite production policy',
    evidence.gateway.finiteProductionPolicy, Object.keys(PUBLIC_HIVE_GATEWAY_FINITE_POLICY))
  for (const [field, expected] of Object.entries(PUBLIC_HIVE_GATEWAY_FINITE_POLICY)) {
    requireEqual(evidence.gateway.finiteProductionPolicy[field], expected,
      `operator readiness gateway finite production policy ${field}`)
  }
  requireObject(evidence.gateway.checks, 'operator readiness gateway checks')
  requireOnlyKeys('operator readiness gateway checks', evidence.gateway.checks,
    PUBLIC_HIVE_GATEWAY_PROBE_CHECKS)
  for (const check of PUBLIC_HIVE_GATEWAY_PROBE_CHECKS) {
    requireEqual(evidence.gateway.checks[check], true, `operator readiness gateway check ${check}`)
  }
  const gatewayBindings = {
    mode: 'fleet',
    publicSuffixReady: contract.publicSuffixReady,
    releaseTarget: contract.release.target,
    releaseSha,
    origin: contract.origin,
    connectAddress: contract.expectedConnectAddress,
    appKey: contract.appKey,
    path: contract.release.expectedPath,
    contentSha256: contract.release.expectedContentSha256,
    driveVersion: contract.release.expectedDriveVersion,
    peerFingerprint256: contract.certificateFingerprint256,
    nginxSha256: contract.release.expectedNginxSha256
  }
  for (const [field, expected] of Object.entries(gatewayBindings)) {
    requireEqual(evidence.gateway[field], expected, `operator readiness gateway ${field}`)
  }

  requireObject(evidence.finiteProductionPolicy, 'operator readiness finite production policy')
  for (const [field, expected] of Object.entries(PUBLIC_HIVE_GATEWAY_FINITE_POLICY)) {
    requireEqual(evidence.finiteProductionPolicy[field], expected, `operator readiness finite production policy ${field}`)
  }
  requireEqual(evidence.finiteProductionPolicy.contractBound, true, 'operator readiness finite policy contract binding')
  requireEqual(evidence.finiteProductionPolicy.signedReleaseBound, true, 'operator readiness finite policy signed release binding')
  requireObject(evidence.finiteProductionPolicy.configured, 'operator readiness configured finite policy')
  const configuredPolicy = {
    maxResponseBytes: PUBLIC_HIVE_GATEWAY_FINITE_POLICY.maxResponseBytes,
    maxTransformBytes: PUBLIC_HIVE_GATEWAY_FINITE_POLICY.maxTransformBytes,
    egressBytesPerClientAppWindow: PUBLIC_HIVE_GATEWAY_FINITE_POLICY.egressBytesPerClientAppWindow,
    egressWindowMs: PUBLIC_HIVE_GATEWAY_FINITE_POLICY.egressWindowMs,
    maxResponseLifetimeMs: PUBLIC_HIVE_GATEWAY_FINITE_POLICY.maxResponseLifetimeMs
  }
  requireOnlyKeys('operator readiness configured finite policy', evidence.finiteProductionPolicy.configured,
    Object.keys(configuredPolicy))
  for (const [field, expected] of Object.entries(configuredPolicy)) {
    requireEqual(evidence.finiteProductionPolicy.configured[field], expected, `operator readiness configured finite policy ${field}`)
  }

  requireObject(evidence.certificate, 'operator readiness certificate')
  requireOnlyKeys('operator readiness certificate', evidence.certificate, [
    'fingerprint256', 'spkiSha256', 'validFrom', 'validTo', 'dnsNames',
    'chainLength', 'keyType'
  ])
  requireEqual(evidence.certificate.fingerprint256, contract.certificateFingerprint256, 'operator readiness certificate fingerprint')
  requireEqual(evidence.certificate.spkiSha256, contract.certificateSpkiSha256, 'operator readiness certificate SPKI')
  if (!Array.isArray(evidence.certificate.dnsNames) || evidence.certificate.dnsNames.length !== 1 ||
      evidence.certificate.dnsNames[0] !== `*.${contract.suffix}`) {
    throw new Error('operator readiness certificate DNS SAN does not match the operator contract')
  }
  const certificateValidTo = Date.parse(evidence.certificate.validTo)
  if (!Number.isFinite(certificateValidTo) || certificateValidTo - normalizeNow(opts.now) < MIN_CERTIFICATE_REMAINING_MS) {
    throw new Error('operator readiness certificate must remain valid for at least 7 days')
  }

  requireObject(evidence.dns, 'operator readiness DNS')
  requireOnlyKeys('operator readiness DNS', evidence.dns,
    ['source', 'expectedAddresses', 'addressFamilyPolicy', 'observed'])
  requireEqual(evidence.dns.source, 'live', 'operator readiness DNS source')
  requireEqual(evidence.dns.addressFamilyPolicy, contract.addressFamilyPolicy, 'operator readiness DNS address family policy')
  requireAddressArray(evidence.dns.expectedAddresses, contract.expectedAddresses, 'operator readiness expected DNS addresses')
  requireObject(evidence.dns.observed, 'operator readiness observed DNS')
  requireOnlyKeys('operator readiness observed DNS', evidence.dns.observed, [
    'observedAt', 'hostname', 'witnessHostname', 'ipv4', 'ipv6',
    'routing', 'ttlRangeSeconds'
  ])
  requireFreshTimestamp(evidence.dns.observed.observedAt, 'operator readiness observed DNS observedAt', opts.now)
  requireEqual(evidence.dns.observed.hostname, contract.appHostname, 'operator readiness observed DNS hostname')
  requireEqual(evidence.dns.observed.witnessHostname, witnessHostnameFor(contract),
    'operator readiness observed DNS wildcard witness hostname')
  requireObject(evidence.dns.observed.ttlRangeSeconds, 'operator readiness observed DNS TTL range')
  requireOnlyKeys('operator readiness observed DNS TTL range', evidence.dns.observed.ttlRangeSeconds,
    ['min', 'max'])
  for (const field of ['min', 'max']) {
    const value = evidence.dns.observed.ttlRangeSeconds[field]
    if (!Number.isSafeInteger(value) || value < MIN_DNS_TTL_SECONDS || value > MAX_DNS_TTL_SECONDS) {
      throw new Error(`operator readiness observed DNS TTL ${field} is outside the reviewed range`)
    }
  }
  if (evidence.dns.observed.ttlRangeSeconds.min > evidence.dns.observed.ttlRangeSeconds.max) {
    throw new Error('operator readiness observed DNS TTL range is inverted')
  }
  requireAddressArray(
    [...(evidence.dns.observed.ipv4 || []), ...(evidence.dns.observed.ipv6 || [])],
    contract.expectedAddresses,
    'operator readiness observed DNS addresses'
  )
  requireObject(evidence.dns.observed.routing, 'operator readiness observed DNS routing records')
  requireOnlyKeys('operator readiness observed DNS routing records', evidence.dns.observed.routing, ['app', 'witness'])
  for (const label of ['app', 'witness']) {
    const routing = evidence.dns.observed.routing[label]
    requireObject(routing, `operator readiness observed ${label} DNS routing records`)
    requireOnlyKeys(`operator readiness observed ${label} DNS routing records`, routing, ['https', 'svcb'])
    if (!Array.isArray(routing.https) || routing.https.length !== 0 ||
        !Array.isArray(routing.svcb) || routing.svcb.length !== 0) {
      throw new Error(`operator readiness observed ${label} DNS HTTPS and SVCB RRsets must be empty`)
    }
  }

  requireObject(evidence.tls, 'operator readiness TLS')
  requireOnlyKeys('operator readiness TLS', evidence.tls, ['source', 'observed'])
  requireEqual(evidence.tls.source, 'live', 'operator readiness TLS source')
  requireObject(evidence.tls.observed, 'operator readiness observed TLS')
  requireOnlyKeys('operator readiness observed TLS', evidence.tls.observed,
    ['observedAt', 'hostname', 'port', 'endpoints'])
  requireFreshTimestamp(evidence.tls.observed.observedAt, 'operator readiness observed TLS observedAt', opts.now)
  requireEqual(evidence.tls.observed.hostname, contract.appHostname, 'operator readiness observed TLS hostname')
  requireEqual(evidence.tls.observed.port, 443, 'operator readiness observed TLS port')
  if (!Array.isArray(evidence.tls.observed.endpoints)) throw new Error('operator readiness TLS endpoints must be an array')
  requireAddressArray(evidence.tls.observed.endpoints.map(endpoint => endpoint.address), contract.expectedAddresses,
    'operator readiness TLS endpoint addresses')
  for (const endpoint of evidence.tls.observed.endpoints) {
    requireObject(endpoint, 'operator readiness TLS endpoint')
    requireOnlyKeys('operator readiness TLS endpoint', endpoint,
      ['address', 'protocol', 'fingerprint256', 'spkiSha256', 'validTo', 'probe'])
    requireEqual(endpoint.fingerprint256, contract.certificateFingerprint256, 'operator readiness TLS endpoint fingerprint')
    requireEqual(endpoint.spkiSha256, contract.certificateSpkiSha256, 'operator readiness TLS endpoint SPKI')
    if (endpoint.protocol !== 'TLSv1.2' && endpoint.protocol !== 'TLSv1.3') {
      throw new Error('operator readiness TLS endpoint protocol must be TLS 1.2 or TLS 1.3')
    }
    const endpointValidTo = Date.parse(endpoint.validTo)
    if (!Number.isFinite(endpointValidTo) || endpointValidTo - normalizeNow(opts.now) < MIN_CERTIFICATE_REMAINING_MS) {
      throw new Error('operator readiness TLS endpoint certificate must remain valid for at least 7 days')
    }
    normalizePerAddressGatewayProbe(
      endpoint.probe,
      contract,
      endpoint.address,
      contract.certificateFingerprint256,
      endpoint.protocol,
      endpoint.validTo,
      opts.now
    )
  }

  requireObject(evidence.sockets, 'operator readiness sockets')
  requireOnlyKeys('operator readiness sockets', evidence.sockets, ['source', 'observed'])
  requireEqual(evidence.sockets.source, 'live', 'operator readiness socket source')
  requireObject(evidence.sockets.observed, 'operator readiness observed sockets')
  requireOnlyKeys('operator readiness observed sockets', evidence.sockets.observed,
    ['api', 'gateway', 'tls', 'udp443'])
  if (!Array.isArray(evidence.sockets.observed.api) || evidence.sockets.observed.api.length !== 1 ||
      !Array.isArray(evidence.sockets.observed.gateway) || evidence.sockets.observed.gateway.length !== 1 ||
      !Array.isArray(evidence.sockets.observed.tls) || evidence.sockets.observed.tls.length !== 2 ||
      !Array.isArray(evidence.sockets.observed.udp443) || evidence.sockets.observed.udp443.length !== 0) {
    throw new Error('operator readiness observed sockets must contain one API, one gateway, and two TLS listeners')
  }
  const apiSocket = parseListenerSummary(evidence.sockets.observed.api[0], 'operator readiness API socket')
  const gatewaySocket = parseListenerSummary(evidence.sockets.observed.gateway[0], 'operator readiness gateway socket')
  if (!isLoopbackAddress(apiSocket.address) || !isLoopbackAddress(gatewaySocket.address)) {
    throw new Error('operator readiness API and gateway sockets must remain numeric-loopback only')
  }
  if (apiSocket.port === gatewaySocket.port || apiSocket.port === 443 || gatewaySocket.port === 443) {
    throw new Error('operator readiness API, gateway, and TLS socket ports must remain distinct')
  }
  const tlsSockets = evidence.sockets.observed.tls.map((value, index) =>
    parseListenerSummary(value, `operator readiness TLS socket[${index}]`))
  if (tlsSockets.some(socket => socket.port !== 443) ||
      !tlsSockets.some(socket => socket.address === '0.0.0.0') ||
      !tlsSockets.some(socket => socket.address === '::')) {
    throw new Error('operator readiness TLS sockets must contain the reviewed IPv4 and IPv6 wildcard listeners on port 443')
  }

  requireObject(evidence.sourceDigests, 'operator readiness source digests')
  requireOnlyKeys('operator readiness source digests', evidence.sourceDigests, [
    'contractFileSha256', 'operatorContractSha256', 'configSha256',
    'gatewayEvidenceSha256', 'releaseManifestSha256'
  ])
  for (const [name, digest] of Object.entries(evidence.sourceDigests)) {
    if (!SHA256_PATTERN.test(digest || '')) throw new Error(`operator readiness source digest ${name} is invalid`)
  }
  requireEqual(evidence.sourceDigests.operatorContractSha256, expectedDigest, 'operator readiness operator contract SHA-256')
  if (opts.contractFileSha256) {
    requireEqual(evidence.sourceDigests.contractFileSha256, opts.contractFileSha256,
      'operator readiness contract file SHA-256')
  }
  if (opts.releaseManifestSha256) {
    requireEqual(evidence.sourceDigests.releaseManifestSha256, opts.releaseManifestSha256,
      'operator readiness release manifest file SHA-256')
  }
  requireObject(evidence.checks, 'operator readiness checks')
  requireOnlyKeys('operator readiness checks', evidence.checks,
    ['contract', 'config', 'certificate', 'dns', 'tls', 'sockets', 'gateway'])
  for (const [check, passed] of Object.entries(evidence.checks)) requireEqual(passed, true, `operator readiness check ${check}`)

  requireObject(evidence.claims, 'operator readiness claims')
  const claimBindings = {
    provesCurrentDnsAnswers: true,
    provesCurrentWebPkiTls: true,
    provesCurrentLoopbackSockets: true,
    forbidsT2Exposure: true,
    forbidsUnknownExposure: true,
    attestsFiniteProductionPolicyValues: true,
    provesBlindG2: false,
    provesBlindG3: false,
    provesFiniteProductionPolicyBehavior: false,
    provesOperatorControl: false
  }
  requireOnlyKeys('operator readiness claims', evidence.claims, Object.keys(claimBindings))
  for (const [claim, expected] of Object.entries(claimBindings)) requireEqual(evidence.claims[claim], expected, `operator readiness claim ${claim}`)
  if (!Array.isArray(evidence.externalGates) || evidence.externalGates.length < 1 ||
      evidence.externalGates.some(value => typeof value !== 'string' || value.length < 1 || value.length > 256)) {
    throw new Error('operator readiness external gates must remain explicit')
  }
  assertPublicSafeOpsEvidence(evidence)

  return {
    schema: 'hiverelay-public-gateway-operator-readiness-verification-v1',
    status: 'verified',
    mode: 'fleet',
    deploymentProfile: PUBLIC_HIVE_GATEWAY_DEPLOYMENT_PROFILE,
    relay: contract.relay,
    operatorId: contract.operatorId,
    registrableDomain: contract.registrableDomain,
    suffix: contract.suffix,
    appKey: contract.appKey,
    contentSha256: contract.release.expectedContentSha256,
    driveVersion: contract.release.expectedDriveVersion,
    releaseTarget: contract.release.target,
    releaseSha,
    operatorContractSha256: expectedDigest,
    certificateFingerprint256: contract.certificateFingerprint256,
    certificateSpkiSha256: contract.certificateSpkiSha256,
    expectedAddresses: [...contract.expectedAddresses],
    checkedAt: evidence.checkedAt,
    claimBoundary: 'operator edge readiness; no blind G2/G3, independent timestamp, or organizational-control proof'
  }
}

export function verifyPublicHiveGatewayOperatorSet (evidences, opts = {}) {
  const requiredMode = opts.mode || 'fleet'
  if (requiredMode !== 'fleet' && requiredMode !== 'rehearsal') throw new Error('operator set mode must be fleet or rehearsal')
  if (!Array.isArray(evidences) || evidences.length < 2 || evidences.length > 16) {
    throw new Error('operator set requires 2 to 16 readiness artifacts')
  }
  const normalized = evidences.map((evidence, index) =>
    normalizeOpsEvidenceSummary(evidence, index, requiredMode, opts.now))
  const first = normalized[0]
  for (const entry of normalized.slice(1)) {
    requireEqual(entry.appKey, first.appKey, 'operator set appKey')
    requireEqual(entry.contentSha256, first.contentSha256, 'operator set content SHA-256')
    requireEqual(entry.driveVersion, first.driveVersion, 'operator set drive version')
    requireEqual(entry.releaseTarget, first.releaseTarget, 'operator set release target')
    requireEqual(entry.releaseSha, first.releaseSha, 'operator set release SHA')
  }
  requireUnique(normalized.map(entry => entry.relay), 'operator set relay identities')
  requireUnique(normalized.map(entry => entry.operatorId), 'operator set operator identities')
  requireUnique(normalized.map(entry => entry.registrableDomain), 'operator set asserted registrable domains')
  requireUnique(normalized.map(entry => entry.suffix), 'operator set app suffixes')
  requireUnique(normalized.map(entry => entry.fingerprint256), 'operator set certificate fingerprints')
  requireUnique(normalized.map(entry => entry.spkiSha256), 'operator set certificate SPKIs')
  if (requiredMode === 'fleet') {
    requireUnique(normalized.map(entry => entry.operatorContractSha256),
      'operator set canonical contract digests')
  }
  const seenAddresses = new Set()
  for (const entry of normalized) {
    for (const address of entry.expectedAddresses) {
      if (seenAddresses.has(address)) throw new Error('operator set public address sets must be disjoint')
      seenAddresses.add(address)
    }
  }
  return {
    schema: PUBLIC_HIVE_GATEWAY_OPERATOR_SET_SCHEMA,
    status: 'verified',
    mode: requiredMode,
    operatorCount: normalized.length,
    appKey: first.appKey,
    contentSha256: first.contentSha256,
    driveVersion: first.driveVersion,
    releaseTarget: first.releaseTarget,
    releaseSha: first.releaseSha,
    operators: normalized.map(entry => ({
      relay: entry.relay,
      operatorId: entry.operatorId,
      registrableDomain: entry.registrableDomain,
      suffix: entry.suffix,
      expectedAddresses: entry.expectedAddresses,
      fingerprint256: entry.fingerprint256,
      spkiSha256: entry.spkiSha256,
      operatorContractSha256: entry.operatorContractSha256,
      checkedAt: entry.checkedAt
    })),
    claimBoundary: requiredMode === 'fleet'
      ? 'asserted technical separation across distinct contract identities, domains, keys, and address sets; no organizational-control, independent-timestamp, or content-provenance proof'
      : 'rehearsal-only; no production independence claim'
  }
}

function parseCertificateChain (pem) {
  if (typeof pem !== 'string' || Buffer.byteLength(pem) < 1 || Buffer.byteLength(pem) > 1024 * 1024) {
    throw new Error('operator fullchain must be a bounded PEM string')
  }
  const blocks = pem.match(CERTIFICATE_PEM_PATTERN) || []
  if (blocks.length === 0 || pem.replace(CERTIFICATE_PEM_PATTERN, '').trim() !== '') {
    throw new Error('operator fullchain must contain only PEM certificate blocks')
  }
  try {
    return blocks.map(block => new X509Certificate(block))
  } catch {
    throw new Error('operator fullchain contains an invalid certificate')
  }
}

function parsePrivateKey (pem) {
  if (typeof pem !== 'string' || Buffer.byteLength(pem) < 1 || Buffer.byteLength(pem) > 128 * 1024) {
    throw new Error('operator private key must be a bounded PEM string')
  }
  const blocks = pem.match(PRIVATE_KEY_PEM_PATTERN) || []
  if (blocks.length !== 1 || pem.replace(PRIVATE_KEY_PEM_PATTERN, '').trim() !== '') {
    throw new Error('operator private key file must contain exactly one PEM private key')
  }
  try {
    return createPrivateKey(pem)
  } catch {
    throw new Error('operator private key is invalid')
  }
}

function parseDnsSubjectAltNames (value) {
  if (typeof value !== 'string' || value.length < 5 || value.length > 4096 || /["\\]/.test(value)) return null
  const entries = value.split(', ').map(entry => entry.trim())
  if (entries.length === 0 || entries.some(entry => !entry.startsWith('DNS:'))) return null
  const names = entries.map(entry => entry.slice(4).toLowerCase())
  if (names.some(name => !/^\*\.[a-z0-9.-]+$|^[a-z0-9.-]+$/.test(name))) return null
  return names
}

function inspectKeyStrength (key, errors) {
  if (key.asymmetricKeyType === 'rsa' || key.asymmetricKeyType === 'rsa-pss') {
    if ((key.asymmetricKeyDetails?.modulusLength || 0) < 2048) errors.push('operator RSA private key must be at least 2048 bits')
    return
  }
  if (key.asymmetricKeyType === 'ec') {
    const curve = key.asymmetricKeyDetails?.namedCurve
    if (!['prime256v1', 'secp384r1', 'secp521r1'].includes(curve)) {
      errors.push('operator EC private key must use a reviewed Web PKI curve')
    }
    return
  }
  errors.push('operator private key must use RSA or a reviewed EC curve')
}

function normalizeDnsAnswer (value, label, errors) {
  const result = { ipv4: [], ipv6: [], cnames: [], ttls: [] }
  try {
    requireObject(value, label)
    requireOnlyKeys(label, value, ['a', 'aaaa', 'cname'])
    result.ipv4 = normalizeDnsRecords(value.a, 4, `${label} A`, result.ttls)
    result.ipv6 = normalizeDnsRecords(value.aaaa, 6, `${label} AAAA`, result.ttls)
    if (!Array.isArray(value.cname) || value.cname.length > 8 || value.cname.some(name => requireDnsName(name, `${label} CNAME`) !== name)) {
      throw new Error(`${label} CNAME records are invalid`)
    }
    result.cnames = [...value.cname]
  } catch (err) {
    errors.push(err.message)
  }
  return result
}

function normalizeDnsRecords (records, family, label, ttlOutput) {
  if (!Array.isArray(records) || records.length > 16) throw new Error(`${label} records must be a bounded array`)
  const addresses = records.map((record, index) => {
    requireObject(record, `${label}[${index}]`)
    requireOnlyKeys(`${label}[${index}]`, record, ['address', 'ttl'])
    const address = requirePublicAddress(record.address, `${label}[${index}] address`)
    if (isIP(address) !== family) throw new Error(`${label}[${index}] has the wrong address family`)
    if (!Number.isSafeInteger(record.ttl) || record.ttl < MIN_DNS_TTL_SECONDS || record.ttl > MAX_DNS_TTL_SECONDS) {
      throw new Error(`${label}[${index}] TTL must be between ${MIN_DNS_TTL_SECONDS} and ${MAX_DNS_TTL_SECONDS} seconds`)
    }
    ttlOutput.push(record.ttl)
    return address
  })
  requireUnique(addresses, `${label} addresses`)
  return addresses.sort(compareAddresses)
}

async function resolveDnsAnswer (resolver, hostname) {
  const [a, aaaa, cname] = await Promise.all([
    resolveOptional(() => resolver.resolve4(hostname, { ttl: true })),
    resolveOptional(() => resolver.resolve6(hostname, { ttl: true })),
    resolveOptional(() => resolver.resolveCname(hostname))
  ])
  return { a, aaaa, cname }
}

async function resolveOptional (operation) {
  try {
    return await operation()
  } catch (err) {
    if (['ENODATA', 'ENOTFOUND', 'NOTFOUND'].includes(err?.code)) return []
    throw new Error(`operator DNS resolution failed: ${err?.code || err?.message || 'unknown error'}`)
  }
}

function normalizePerAddressGatewayProbe (value, contract, address, fingerprint256, endpointProtocol, endpointValidTo, now) {
  requireObject(value, `operator gateway probe for ${address}`)
  requireOnlyKeys(`operator gateway probe for ${address}`, value, [
    'schema', 'observedAt', 'origin', 'connectAddress', 'appKey', 'path',
    'sha256', 'bytes', 'driveVersion', 'tlsProtocol', 'peerFingerprint256',
    'peerValidTo', 'metadataSigned', 'checks'
  ])
  requireEqual(value.schema, PUBLIC_HIVE_GATEWAY_PROBE_SCHEMA, `operator gateway probe for ${address} schema`)
  requireEqual(value.origin, contract.origin, `operator gateway probe for ${address} origin`)
  requireEqual(value.connectAddress, address, `operator gateway probe for ${address} connect address`)
  requireEqual(value.appKey, contract.appKey, `operator gateway probe for ${address} app key`)
  requireEqual(value.path, contract.release.expectedPath, `operator gateway probe for ${address} path`)
  requireEqual(String(value.sha256 || '').toLowerCase(), contract.release.expectedContentSha256,
    `operator gateway probe for ${address} content SHA-256`)
  requireEqual(String(value.driveVersion || ''), contract.release.expectedDriveVersion,
    `operator gateway probe for ${address} drive version`)
  requireEqual(String(value.peerFingerprint256 || '').toUpperCase(), fingerprint256,
    `operator gateway probe for ${address} certificate fingerprint`)
  requireEqual(value.metadataSigned, false, `operator gateway probe for ${address} metadata provenance claim`)
  if (value.tlsProtocol !== 'TLSv1.2' && value.tlsProtocol !== 'TLSv1.3') {
    throw new Error(`operator gateway probe for ${address} TLS protocol is invalid`)
  }
  requireEqual(value.tlsProtocol, endpointProtocol, `operator gateway probe for ${address} TLS protocol binding`)
  const probeValidTo = Date.parse(value.peerValidTo)
  const tlsValidTo = Date.parse(endpointValidTo)
  if (!Number.isFinite(probeValidTo) || !Number.isFinite(tlsValidTo) || probeValidTo !== tlsValidTo ||
      probeValidTo - normalizeNow(now) < MIN_CERTIFICATE_REMAINING_MS) {
    throw new Error(`operator gateway probe for ${address} certificate validity is inconsistent`)
  }
  if (!Number.isSafeInteger(value.bytes) || value.bytes < 1 || value.bytes > PUBLIC_HIVE_GATEWAY_FINITE_POLICY.maxResponseBytes) {
    throw new Error(`operator gateway probe for ${address} byte count is invalid`)
  }
  requireFreshTimestamp(value.observedAt, `operator gateway probe for ${address} observedAt`, now)
  requireObject(value.checks, `operator gateway probe for ${address} checks`)
  requireOnlyKeys(`operator gateway probe for ${address} checks`, value.checks, PUBLIC_HIVE_GATEWAY_PROBE_CHECKS)
  for (const check of PUBLIC_HIVE_GATEWAY_PROBE_CHECKS) {
    requireEqual(value.checks?.[check], true, `operator gateway probe for ${address} ${check}`)
  }
  return {
    observedAt: value.observedAt,
    origin: value.origin,
    connectAddress: address,
    appKey: value.appKey,
    path: value.path,
    sha256: String(value.sha256).toLowerCase(),
    bytes: value.bytes,
    driveVersion: String(value.driveVersion),
    tlsProtocol: value.tlsProtocol,
    peerFingerprint256: String(value.peerFingerprint256).toUpperCase(),
    checks: Object.fromEntries(PUBLIC_HIVE_GATEWAY_PROBE_CHECKS.map(check => [check, true]))
  }
}

function probeTlsEndpoint (address, hostname, opts) {
  return new Promise((resolve, reject) => {
    const timeoutMs = opts.timeoutMs || 5000
    const socket = tls.connect({
      host: address,
      port: 443,
      servername: hostname,
      ca: opts.ca,
      rejectUnauthorized: true,
      minVersion: 'TLSv1.2',
      maxVersion: 'TLSv1.3'
    })
    const timer = setTimeout(() => socket.destroy(new Error(`operator TLS endpoint ${address} timed out`)), timeoutMs)
    timer.unref()
    socket.once('secureConnect', () => {
      try {
        if (!socket.authorized) throw new Error(socket.authorizationError || 'certificate authorization failed')
        const certificate = socket.getPeerX509Certificate()
        if (!certificate) throw new Error('peer certificate unavailable')
        const spkiSha256 = createHash('sha256')
          .update(certificate.publicKey.export({ type: 'spki', format: 'der' }))
          .digest('hex')
        const result = {
          address,
          authorized: true,
          protocol: socket.getProtocol(),
          fingerprint256: certificate.fingerprint256.toUpperCase(),
          spkiSha256,
          validTo: new Date(certificate.validToDate?.getTime?.() ?? Date.parse(certificate.validTo)).toISOString()
        }
        clearTimeout(timer)
        socket.end()
        resolve(result)
      } catch (err) {
        socket.destroy()
        reject(new Error(`operator TLS endpoint ${address} failed: ${err.message}`))
      }
    })
    socket.once('error', err => {
      clearTimeout(timer)
      reject(new Error(`operator TLS endpoint ${address} failed: ${err.message}`))
    })
  })
}

function parseSsLine (line, index) {
  const columns = line.trim().split(/\s+/)
  let protocol = 'tcp'
  if (columns[0] === 'tcp' || columns[0] === 'udp') protocol = columns.shift()
  const expectedState = protocol === 'tcp' ? 'LISTEN' : 'UNCONN'
  if (columns.length < 5 || columns[0] !== expectedState) throw new Error(`operator socket snapshot line ${index + 1} is not canonical ss listener output`)
  const local = columns[3]
  let address
  let portText
  if (local.startsWith('[')) {
    const match = local.match(/^\[([^\]]+)]:(\d+)$/)
    if (!match) throw new Error(`operator socket snapshot line ${index + 1} has an invalid IPv6 listener`)
    address = match[1].split('%')[0]
    portText = match[2]
  } else {
    const separator = local.lastIndexOf(':')
    if (separator < 1) throw new Error(`operator socket snapshot line ${index + 1} has an invalid listener`)
    address = local.slice(0, separator)
    portText = local.slice(separator + 1)
  }
  if (address === '*') address = '0.0.0.0'
  address = normalizeAddress(address)
  const port = Number(portText)
  if (!address || !Number.isSafeInteger(port) || port < 1 || port > 65535) {
    throw new Error(`operator socket snapshot line ${index + 1} has an invalid listener endpoint`)
  }
  return { address, port, protocol }
}

function requireExactLoopbackListeners (listeners, expectedHost, label, errors) {
  if (listeners.length !== 1 || listeners[0].address !== expectedHost) {
    errors.push(`${label} must have exactly one socket bound to ${expectedHost}`)
  }
}

function formatListener (listener) {
  return `${isIP(listener.address) === 6 ? `[${listener.address}]` : listener.address}:${listener.port}`
}

function parseListenerSummary (value, label) {
  if (typeof value !== 'string' || value.length < 3 || value.length > 96) {
    throw new Error(`${label} is invalid`)
  }
  let address
  let portText
  if (value.startsWith('[')) {
    const match = /^\[([^\]]+)]:(\d+)$/.exec(value)
    if (!match) throw new Error(`${label} is invalid`)
    address = match[1]
    portText = match[2]
  } else {
    const separator = value.lastIndexOf(':')
    if (separator < 1) throw new Error(`${label} is invalid`)
    address = value.slice(0, separator)
    portText = value.slice(separator + 1)
  }
  const normalizedAddress = requireCanonicalAddress(address, `${label} address`)
  const port = Number(portText)
  if (!/^[1-9][0-9]{0,4}$/.test(portText) || !Number.isSafeInteger(port) || port > 65535) {
    throw new Error(`${label} port is invalid`)
  }
  return { address: normalizedAddress, port }
}

function witnessHostnameFor (contract) {
  const witnessKey = contract.appKey === '0'.repeat(64) ? 'f'.repeat(64) : '0'.repeat(64)
  return `${encodeHiveAppKey(Buffer.from(witnessKey, 'hex'))}.${contract.suffix}`
}

function normalizeOpsEvidenceSummary (evidence, index, requiredMode, now) {
  requireObject(evidence, `operator readiness evidence[${index}]`)
  requireEqual(evidence.schema, PUBLIC_HIVE_GATEWAY_OPS_EVIDENCE_SCHEMA, `operator readiness evidence[${index}] schema`)
  requireEqual(evidence.status, 'pass', `operator readiness evidence[${index}] status`)
  requireEqual(evidence.mode, requiredMode, `operator readiness evidence[${index}] mode`)
  requireEqual(evidence.deploymentProfile, PUBLIC_HIVE_GATEWAY_DEPLOYMENT_PROFILE, `operator readiness evidence[${index}] profile`)
  const checkedAt = requiredMode === 'fleet'
    ? new Date(requireFreshTimestamp(evidence.checkedAt, `operator readiness evidence[${index}] checkedAt`, now)).toISOString()
    : (evidence.checkedAt || null)
  let operatorContractSha256 = null
  if (requiredMode === 'fleet') {
    if (!Array.isArray(evidence.errors) || evidence.errors.length !== 0) {
      throw new Error(`operator readiness evidence[${index}] fleet errors must be empty`)
    }
    for (const group of ['dns', 'tls', 'sockets']) {
      requireEqual(evidence[group]?.source, 'live',
        `operator readiness evidence[${index}] ${group} source`)
    }
    const fleetClaims = {
      provesCurrentDnsAnswers: true,
      provesCurrentWebPkiTls: true,
      provesCurrentLoopbackSockets: true,
      forbidsT2Exposure: true,
      forbidsUnknownExposure: true,
      provesBlindG2: false,
      provesBlindG3: false,
      provesFiniteProductionPolicyBehavior: false,
      provesOperatorControl: false
    }
    for (const [claim, expected] of Object.entries(fleetClaims)) {
      requireEqual(evidence.claims?.[claim], expected,
        `operator readiness evidence[${index}] fleet claim ${claim}`)
    }
    operatorContractSha256 = String(evidence.sourceDigests?.operatorContractSha256 || '').toLowerCase()
    if (!SHA256_PATTERN.test(operatorContractSha256)) {
      throw new Error(`operator readiness evidence[${index}] canonical operator contract digest is invalid`)
    }
    if (!SHA256_PATTERN.test(evidence.sourceDigests?.releaseManifestSha256 || '')) {
      throw new Error(`operator readiness evidence[${index}] signed release manifest digest is invalid`)
    }
  }
  requireEqual(evidence.claims?.provesBlindG2, false, `operator readiness evidence[${index}] blind G2 claim`)
  requireEqual(evidence.claims?.provesBlindG3, false, `operator readiness evidence[${index}] blind G3 claim`)
  if (evidence.checks?.config !== true || evidence.checks?.dns !== true || evidence.checks?.tls !== true ||
      evidence.checks?.sockets !== true || evidence.checks?.gateway !== true || evidence.checks?.certificate !== true ||
      (requiredMode === 'fleet' && evidence.checks?.contract !== true)) {
    throw new Error(`operator readiness evidence[${index}] does not contain every required passing ops check`)
  }
  requireObject(evidence.finiteProductionPolicy, `operator readiness evidence[${index}] finite production policy`)
  for (const [field, expected] of Object.entries(PUBLIC_HIVE_GATEWAY_FINITE_POLICY)) {
    requireEqual(evidence.finiteProductionPolicy[field], expected,
      `operator readiness evidence[${index}] finite production policy ${field}`)
  }
  requireEqual(evidence.finiteProductionPolicy.contractBound, true,
    `operator readiness evidence[${index}] finite production policy contract binding`)
  if (requiredMode === 'fleet') {
    requireEqual(evidence.finiteProductionPolicy.signedReleaseBound, true,
      `operator readiness evidence[${index}] finite production policy signed release binding`)
  }
  requireEqual(evidence.claims?.attestsFiniteProductionPolicyValues, true,
    `operator readiness evidence[${index}] finite production policy value attestation`)
  const expectedAddresses = evidence.dns?.expectedAddresses
  if (!Array.isArray(expectedAddresses) || expectedAddresses.length < 1) {
    throw new Error(`operator readiness evidence[${index}] has no reviewed public addresses`)
  }
  const fingerprint256 = String(evidence.certificate?.fingerprint256 || '').toUpperCase()
  const spkiSha256 = String(evidence.certificate?.spkiSha256 || '').toLowerCase()
  const appKey = String(evidence.gateway?.appKey || '').toLowerCase()
  const contentSha256 = String(evidence.gateway?.contentSha256 || '').toLowerCase()
  const driveVersion = String(evidence.gateway?.driveVersion || '')
  const releaseSha = String(evidence.gateway?.releaseSha || '').toLowerCase()
  if (!FINGERPRINT256_PATTERN.test(fingerprint256)) throw new Error(`operator readiness evidence[${index}] certificate fingerprint is invalid`)
  if (!SHA256_PATTERN.test(spkiSha256)) throw new Error(`operator readiness evidence[${index}] certificate SPKI is invalid`)
  if (!SHA256_PATTERN.test(appKey)) throw new Error(`operator readiness evidence[${index}] appKey is invalid`)
  if (!SHA256_PATTERN.test(contentSha256)) throw new Error(`operator readiness evidence[${index}] content SHA-256 is invalid`)
  if (!DRIVE_VERSION_PATTERN.test(driveVersion)) throw new Error(`operator readiness evidence[${index}] drive version is invalid`)
  if (!RELEASE_TAG_PATTERN.test(evidence.gateway?.releaseTarget || '')) throw new Error(`operator readiness evidence[${index}] release target is invalid`)
  if (!RELEASE_SHA_PATTERN.test(releaseSha)) throw new Error(`operator readiness evidence[${index}] release SHA is invalid`)
  return {
    relay: requireBoundedIdentity(evidence.operator?.relay, `operator readiness evidence[${index}] relay`),
    operatorId: requireOperatorId(evidence.operator?.operatorId),
    registrableDomain: requireDnsName(evidence.operator?.registrableDomain, `operator readiness evidence[${index}] registrableDomain`),
    suffix: requireDnsName(evidence.operator?.suffix, `operator readiness evidence[${index}] suffix`),
    expectedAddresses: expectedAddresses.map((address, addressIndex) =>
      requirePublicAddress(address, `operator readiness evidence[${index}] expectedAddresses[${addressIndex}]`)),
    fingerprint256,
    spkiSha256,
    appKey,
    contentSha256,
    driveVersion,
    releaseTarget: evidence.gateway?.releaseTarget,
    releaseSha,
    operatorContractSha256,
    checkedAt
  }
}

function requirePublicAddress (value, label) {
  const normalized = requireCanonicalAddress(value, label)
  if (isIP(normalized) === 4) {
    const address = new Address4(normalized)
    if (address.isPrivate() || address.isLoopback() || address.isLinkLocal() || address.isCGNAT() ||
        address.isUnspecified() || address.isMulticast() || address.isBroadcast() || isReservedIpv4(address)) {
      throw new Error(`${label} must be a globally routable unicast address`)
    }
  } else {
    const address = new Address6(normalized)
    if (address.isULA() || address.isLoopback() || address.isLinkLocal() || address.isDocumentation() ||
        address.isUnspecified() || address.isMulticast() || address.isMapped4() || address.is6to4() || address.isTeredo()) {
      throw new Error(`${label} must be a globally routable unicast address`)
    }
  }
  return normalized
}

function isReservedIpv4 (address) {
  const value = address.bigInt()
  const ranges = [
    ['0.0.0.0', 8],
    ['192.0.0.0', 24],
    ['192.0.2.0', 24],
    ['192.88.99.0', 24],
    ['198.18.0.0', 15],
    ['198.51.100.0', 24],
    ['203.0.113.0', 24],
    ['240.0.0.0', 4]
  ]
  return ranges.some(([base, prefix]) => {
    const start = new Address4(`${base}/${prefix}`).startAddress().bigInt()
    const end = new Address4(`${base}/${prefix}`).endAddress().bigInt()
    return value >= start && value <= end
  })
}

function requireCanonicalAddress (value, label) {
  const normalized = normalizeAddress(value)
  if (!normalized) throw new Error(`${label} must be a canonical IP address`)
  return normalized
}

function normalizeAddress (value) {
  if (typeof value !== 'string' || value !== value.trim() || value.length < 2 || value.length > 64) return null
  try {
    if (isIP(value) === 4) return new Address4(value).correctForm()
    if (isIP(value) === 6) return new Address6(value).correctForm()
  } catch {}
  return null
}

function compareAddresses (left, right) {
  const leftFamily = isIP(left)
  const rightFamily = isIP(right)
  if (leftFamily !== rightFamily) return leftFamily - rightFamily
  const leftValue = leftFamily === 4 ? new Address4(left).bigInt() : new Address6(left).bigInt()
  const rightValue = rightFamily === 4 ? new Address4(right).bigInt() : new Address6(right).bigInt()
  return leftValue < rightValue ? -1 : leftValue > rightValue ? 1 : 0
}

function isLoopbackAddress (address) {
  if (isIP(address) === 4) return new Address4(address).isLoopback()
  return isIP(address) === 6 && new Address6(address).isLoopback()
}

function requireNumericLoopback (value, label) {
  const address = requireCanonicalAddress(value, label)
  if (!isLoopbackAddress(address)) throw new Error(`${label} must be an explicit numeric loopback address`)
  return address
}

function requirePort (value, label) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 65535) throw new Error(`${label} must be a valid TCP port`)
  return value
}

function requireDnsName (value, label) {
  const normalized = normalizeHiveAppHostSuffix(value)
  if (!normalized || normalized !== value || isIP(value) !== 0) throw new Error(`${label} must be a canonical lowercase DNS name`)
  return normalized
}

function requireOperatorId (value) {
  if (typeof value !== 'string' || !OPERATOR_ID_PATTERN.test(value)) throw new Error('operatorId must be a canonical lowercase identifier')
  return value
}

function requireBoundedIdentity (value, label) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(value)) throw new Error(`${label} is invalid`)
  return value
}

function requireFreshTimestamp (value, label, nowValue) {
  const nowMs = normalizeNow(nowValue)
  const timestamp = Date.parse(value)
  if (typeof value !== 'string' || !Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
    throw new Error(`${label} must be a canonical ISO timestamp`)
  }
  if (timestamp > nowMs + MAX_FUTURE_SKEW_MS || nowMs - timestamp > MAX_SNAPSHOT_AGE_MS) {
    throw new Error(`${label} must be no more than 15 minutes old and not in the future`)
  }
  return timestamp
}

function normalizeNow (value) {
  const now = value == null ? Date.now() : value instanceof Date ? value.getTime() : Number(value)
  if (!Number.isSafeInteger(now) || now < 0) throw new Error('operator readiness time must be a valid epoch timestamp')
  return now
}

function compareAddressSets (actual, expected, label, errors) {
  const left = [...actual].sort(compareAddresses)
  const right = [...expected].sort(compareAddresses)
  if (left.length !== right.length || left.some((value, index) => value !== right[index])) {
    errors.push(`${label} must exactly equal the reviewed address set`)
  }
}

function requireAddressArray (actual, expected, label) {
  if (!Array.isArray(actual)) throw new Error(`${label} must be an array`)
  const errors = []
  const normalized = actual.map((address, index) => requirePublicAddress(address, `${label}[${index}]`))
  compareAddressSets(normalized, expected, label, errors)
  if (errors.length > 0) throw new Error(errors[0])
}

function assertPublicSafeOpsEvidence (evidence) {
  const serialized = JSON.stringify(evidence)
  const forbidden = [
    /-----BEGIN [A-Z ]*(?:PRIVATE|SECRET) KEY-----/,
    /\bHIVERELAY_API_KEY=/i,
    /\bAuthorization\s*:/i,
    /\bBearer\s+[A-Za-z0-9._~+/=-]{16,}/i,
    /\bsk-[A-Za-z0-9_-]{20,}/
  ]
  if (serialized.length > 2 * 1024 * 1024 || forbidden.some(pattern => pattern.test(serialized))) {
    throw new Error('operator readiness evidence contains unsafe or oversized public values')
  }
}

function ttlRange (values) {
  if (values.length === 0) return { min: null, max: null }
  return { min: Math.min(...values), max: Math.max(...values) }
}

function requireUnique (values, label) {
  if (new Set(values).size !== values.length) throw new Error(`${label} must not contain duplicates`)
}

function requireObject (value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`)
}

function requireOnlyKeys (label, value, allowed) {
  const set = new Set(allowed)
  for (const key of Object.keys(value)) {
    if (!set.has(key)) throw new Error(`${label} contains unknown field ${key}`)
  }
  for (const key of allowed) {
    if (!Object.hasOwn(value, key)) throw new Error(`${label} is missing field ${key}`)
  }
}

function requireEqual (actual, expected, label) {
  if (actual !== expected) throw new Error(`${label} must equal ${JSON.stringify(expected)}`)
}
