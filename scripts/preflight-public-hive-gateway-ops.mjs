#!/usr/bin/env node

import { constants } from 'node:fs'
import { lstat, open, realpath, rename, unlink } from 'node:fs/promises'
import { createHash, randomBytes } from 'node:crypto'
import { execFile } from 'node:child_process'
import { isUtf8 } from 'node:buffer'
import { dirname, isAbsolute, join, relative, resolve } from 'node:path'
import { promisify } from 'node:util'
import defaults from '../packages/core/config/default.js'
import {
  assertOperatorContractMatchesCohort,
  cohortEntryForRelay,
  normalizePublicHiveGatewayReleaseManifest
} from './lib/public-hive-gateway-release-manifest.mjs'
import {
  PUBLIC_HIVE_GATEWAY_DEPLOYMENT_PROFILE,
  PUBLIC_HIVE_GATEWAY_OPS_EVIDENCE_SCHEMA,
  collectPublicHiveGatewayDnsSnapshot,
  collectPublicHiveGatewayTlsSnapshot,
  inspectPublicHiveGatewayBaseEvidence,
  inspectPublicHiveGatewayCertificate,
  inspectPublicHiveGatewayDnsSnapshot,
  inspectPublicHiveGatewayOpsConfig,
  inspectPublicHiveGatewaySocketSnapshot,
  inspectPublicHiveGatewayTlsSnapshot,
  normalizePublicHiveGatewayOpsContract,
  sha256PublicHiveGatewayOpsContract
} from './lib/public-hive-gateway-ops.mjs'

const execFileAsync = promisify(execFile)
const args = parseArgs(process.argv.slice(2))

if (args.help) {
  console.log(`Usage:
  node scripts/preflight-public-hive-gateway-ops.mjs --mode <rehearsal|fleet> \\
    --contract <operator-contract.json> --config <config.json> \\
    --gateway-evidence <preflight-live.json> --certificate <fullchain.pem> \\
    --certificate-key <privkey.pem> --release-sha <verified-tag-commit> [sources] [options]

Required sources:
  --dns-live                         Resolve and pin live wildcard A/AAAA records
  --dns-snapshot <path>              Rehearsal-only DNS fixture instead of live DNS
  --ss-binary <absolute-path>        Capture live TCP and UDP listener state
  --socket-snapshot <path>           Rehearsal-only listener fixture
  --tls-snapshot <path>              Required with --dns-snapshot; rehearsal only

Options:
  --certificate-root <absolute-dir>  Allow certbot-style symlinks only inside this root
  --release-manifest <path>          Signed-tag cohort manifest binding (required fleet)
  --ca <path>                        Rehearsal-only private CA for live TLS endpoint checks
  --timeout-ms <1000..30000>         Per-endpoint TLS timeout (default 5000)
  --evidence <path>                  Atomically write public-safe ops evidence

Fleet mode forbids fixtures/private CAs, requires live DNS/TLS and socket
inspection, and also requires the merged runtime config to expose the exact
compiled public-t1-gateway product profile. Ops evidence never claims blind
G2/G3, storage-class, or finite-production-policy proof.`)
  process.exit(0)
}

const mode = args.mode
if (mode !== 'rehearsal' && mode !== 'fleet') throw new Error('--mode must be rehearsal or fleet')
validateSourceArgs(args, mode)
const timeoutMs = args.timeoutMs == null ? 5000 : parseBoundedInteger(args.timeoutMs, '--timeout-ms', 1000, 30000)
const contractBuffer = await readRegularFile(requiredPath(args.contract, '--contract'), 'operator readiness contract', 256 * 1024)
const contract = normalizePublicHiveGatewayOpsContract(parseJson(contractBuffer, 'operator readiness contract'))
const releaseSha = normalizeReleaseSha(args.releaseSha)
const operatorContractSha256 = sha256PublicHiveGatewayOpsContract(contract)
let releaseManifestBuffer = null
let manifestBinding = null
if (args.releaseManifest) {
  releaseManifestBuffer = await readRegularFile(
    requiredPath(args.releaseManifest, '--release-manifest'),
    'public gateway release manifest',
    2 * 1024 * 1024
  )
  const manifest = normalizePublicHiveGatewayReleaseManifest(
    parseJson(releaseManifestBuffer, 'public gateway release manifest'),
    { releaseTarget: contract.release.target, requirePublicT1: true }
  )
  const entry = cohortEntryForRelay(manifest, contract.relay)
  manifestBinding = assertOperatorContractMatchesCohort(contract, manifest, entry)
  if (manifestBinding.digest !== operatorContractSha256) throw new Error('operator contract canonical digest changed during manifest binding')
}
const configBuffer = await readRegularFile(requiredPath(args.config, '--config'), 'operator gateway config', 1024 * 1024)
const persistedConfig = parseJson(configBuffer, 'operator gateway config')
const config = { ...defaults, ...persistedConfig }
const gatewayEvidenceBuffer = await readRegularFile(requiredPath(args.gatewayEvidence, '--gateway-evidence'), 'operator base gateway evidence', 2 * 1024 * 1024)
const gatewayEvidence = parseJson(gatewayEvidenceBuffer, 'operator base gateway evidence')

const allowedCertificateRoot = args.certificateRoot ? requiredAbsolutePath(args.certificateRoot, '--certificate-root') : null
const certificateFile = await readPemPath(requiredPath(args.certificate, '--certificate'), 'operator fullchain', 1024 * 1024, {
  allowedRoot: allowedCertificateRoot,
  privateFile: false,
  requireRootOwner: mode === 'fleet'
})
const keyFile = await readPemPath(requiredPath(args.certificateKey, '--certificate-key'), 'operator private key', 128 * 1024, {
  allowedRoot: allowedCertificateRoot,
  privateFile: true,
  requireRootOwner: mode === 'fleet'
})
if (certificateFile.identity.dev === keyFile.identity.dev && certificateFile.identity.ino === keyFile.identity.ino) {
  throw new Error('operator certificate and private key must be distinct files')
}

const now = Date.now()
const configCheck = inspectPublicHiveGatewayOpsConfig(config, contract, mode, { explicitConfig: persistedConfig })
const certificateCheck = inspectPublicHiveGatewayCertificate(
  certificateFile.buffer.toString('utf8'),
  keyFile.buffer.toString('utf8'),
  contract,
  { now }
)
const gatewayCheck = inspectPublicHiveGatewayBaseEvidence(gatewayEvidence, config, contract, mode, { now, releaseSha })

let dnsSource
let dnsSnapshot
let dnsCollectionError = null
try {
  if (args.dnsLive) {
    dnsSource = 'live'
    dnsSnapshot = await collectPublicHiveGatewayDnsSnapshot(contract, { now })
  } else {
    dnsSource = 'fixture'
    dnsSnapshot = parseJson(
      await readRegularFile(requiredPath(args.dnsSnapshot, '--dns-snapshot'), 'operator DNS snapshot', 256 * 1024),
      'operator DNS snapshot'
    )
  }
} catch (err) {
  dnsCollectionError = err.message
}
const dnsCheck = dnsSnapshot
  ? captureInspection(() => inspectPublicHiveGatewayDnsSnapshot(dnsSnapshot, contract, { now }))
  : failedInspection(dnsCollectionError || 'operator DNS snapshot unavailable')

let tlsSource
let tlsSnapshot
let tlsCollectionError = null
try {
  if (args.dnsLive) {
    tlsSource = 'live'
    const ca = args.ca
      ? (await readRegularFile(requiredPath(args.ca, '--ca'), 'operator private CA', 1024 * 1024)).toString('utf8')
      : undefined
    tlsSnapshot = await collectPublicHiveGatewayTlsSnapshot(contract, {
      now,
      ca,
      timeoutMs,
      baseProbe: gatewayCheck.ok ? gatewayEvidence.probe : null
    })
  } else {
    tlsSource = 'fixture'
    tlsSnapshot = parseJson(
      await readRegularFile(requiredPath(args.tlsSnapshot, '--tls-snapshot'), 'operator TLS snapshot', 512 * 1024),
      'operator TLS snapshot'
    )
  }
} catch (err) {
  tlsCollectionError = err.message
}
const tlsCheck = tlsSnapshot && certificateCheck.identity
  ? captureInspection(() => inspectPublicHiveGatewayTlsSnapshot(tlsSnapshot, contract, certificateCheck.identity, { now }))
  : failedInspection(tlsCollectionError || 'operator TLS certificate identity unavailable')

let socketSource
let socketText
let socketCollectionError = null
try {
  if (args.ssBinary) {
    socketSource = 'live'
    socketText = await collectSocketSnapshot(args.ssBinary)
  } else {
    socketSource = 'fixture'
    socketText = (await readRegularFile(
      requiredPath(args.socketSnapshot, '--socket-snapshot'),
      'operator socket snapshot',
      1024 * 1024
    )).toString('utf8')
  }
} catch (err) {
  socketCollectionError = err.message
}
const socketCheck = socketText
  ? captureInspection(() => inspectPublicHiveGatewaySocketSnapshot(socketText, config))
  : failedInspection(socketCollectionError || 'operator socket snapshot unavailable')

const checks = {
  contract: true,
  config: configCheck.ok,
  certificate: certificateCheck.ok,
  dns: dnsCheck.ok,
  tls: tlsCheck.ok,
  sockets: socketCheck.ok,
  gateway: gatewayCheck.ok
}
const errors = [
  ...configCheck.errors,
  ...certificateCheck.errors,
  ...dnsCheck.errors,
  ...tlsCheck.errors,
  ...socketCheck.errors,
  ...gatewayCheck.errors
]
const ok = Object.values(checks).every(Boolean) && errors.length === 0
const evidence = {
  schema: PUBLIC_HIVE_GATEWAY_OPS_EVIDENCE_SCHEMA,
  status: ok ? 'pass' : 'fail',
  checkedAt: new Date(now).toISOString(),
  mode,
  deploymentProfile: PUBLIC_HIVE_GATEWAY_DEPLOYMENT_PROFILE,
  physicalEnforcementRequired: configCheck.result?.physicalEnforcementRequired === true,
  operator: {
    relay: contract.relay,
    operatorId: contract.operatorId,
    registrableDomain: contract.registrableDomain,
    apiHostname: contract.apiHostname,
    suffix: contract.suffix,
    publicSuffixReady: contract.publicSuffixReady
  },
  gateway: gatewayCheck.result || {
    releaseTarget: contract.release.target,
    releaseSha,
    origin: contract.origin,
    connectAddress: contract.expectedConnectAddress,
    appKey: contract.appKey,
    contentSha256: contract.release.expectedContentSha256,
    driveVersion: contract.release.expectedDriveVersion,
    physicalEnforcementRequired: configCheck.result?.physicalEnforcementRequired === true,
    peerFingerprint256: contract.certificateFingerprint256,
    nginxSha256: contract.release.expectedNginxSha256
  },
  finiteProductionPolicy: {
    ...contract.finiteProductionPolicy,
    configured: configCheck.result?.finiteProductionPolicy?.configured || null,
    contractBound: true,
    signedReleaseBound: mode === 'fleet' && manifestBinding?.digest === operatorContractSha256
  },
  certificate: certificateCheck.identity,
  dns: {
    source: dnsSource || null,
    expectedAddresses: contract.expectedAddresses,
    addressFamilyPolicy: contract.addressFamilyPolicy,
    observed: dnsCheck.result
  },
  tls: {
    source: tlsSource || null,
    observed: tlsCheck.result
  },
  sockets: {
    source: socketSource || null,
    observed: socketCheck.result
  },
  sourceDigests: {
    contractFileSha256: sha256(contractBuffer),
    operatorContractSha256,
    configSha256: sha256(configBuffer),
    gatewayEvidenceSha256: sha256(gatewayEvidenceBuffer),
    releaseManifestSha256: releaseManifestBuffer ? sha256(releaseManifestBuffer) : null
  },
  checks,
  claims: {
    provesCurrentDnsAnswers: dnsSource === 'live' && dnsCheck.ok,
    provesCurrentWebPkiTls: tlsSource === 'live' && tlsCheck.ok,
    provesCurrentLoopbackSockets: socketSource === 'live' && socketCheck.ok,
    forbidsT2Exposure: true,
    forbidsUnknownExposure: true,
    attestsFiniteProductionPolicyValues: configCheck.ok,
    attestsPhysicalEnforcementRequirement: configCheck.result?.physicalEnforcementRequired === true,
    provesActivePhysicalEnforcement: false,
    provesBlindG2: false,
    provesBlindG3: false,
    provesFiniteProductionPolicyBehavior: false,
    provesOperatorControl: false
  },
  externalGates: [
    ...(mode === 'fleet' && manifestBinding?.digest === operatorContractSha256
      ? []
      : ['signed release binding for the operator contract digest and finite-production-policy values']),
    'authoritative compiled public-t1-gateway substrate/profile evidence',
    'negative T2 and unknown storage-class exposure conformance',
    'finite-production-policy response/egress/lifetime conformance evidence from the exact release',
    'active exclusive OS quota provider lease and fresh settlement attestation; the config boolean proves only the fail-closed requirement',
    'blind G2 storage-classification and G3 signing-foundation evidence',
    'authenticated proof of DNS, certificate-key, and operator organizational control'
  ],
  errors
}

if (args.evidence) await writeAtomic(resolve(args.evidence), Buffer.from(JSON.stringify(evidence, null, 2) + '\n'))
console.log(JSON.stringify(evidence, null, 2))
if (!ok) process.exitCode = 1

function parseArgs (argv) {
  const out = {}
  const booleans = new Set(['help', 'dns-live'])
  const values = new Set([
    'mode',
    'contract',
    'config',
    'gateway-evidence',
    'release-sha',
    'release-manifest',
    'certificate',
    'certificate-key',
    'certificate-root',
    'dns-snapshot',
    'tls-snapshot',
    'ss-binary',
    'socket-snapshot',
    'ca',
    'timeout-ms',
    'evidence'
  ])
  const seen = new Set()
  for (let index = 0; index < argv.length; index++) {
    const raw = argv[index]
    if (raw === '-h') {
      if (seen.has('help')) throw new Error('Duplicate option: --help')
      seen.add('help')
      out.help = true
      continue
    }
    if (!raw.startsWith('--')) throw new Error(`Unexpected argument: ${raw}`)
    const rawName = raw.slice(2)
    if (!booleans.has(rawName) && !values.has(rawName)) throw new Error(`Unknown option: --${rawName}`)
    if (seen.has(rawName)) throw new Error(`Duplicate option: --${rawName}`)
    seen.add(rawName)
    const name = camel(rawName)
    if (booleans.has(rawName)) {
      out[name] = true
      continue
    }
    const value = argv[++index]
    if (!value || value.startsWith('--')) throw new Error(`Missing value for ${raw}`)
    out[name] = value
  }
  return out
}

function validateSourceArgs (values, selectedMode) {
  if (Boolean(values.dnsLive) === Boolean(values.dnsSnapshot)) {
    throw new Error('provide exactly one of --dns-live or --dns-snapshot')
  }
  if (values.dnsLive && values.tlsSnapshot) throw new Error('--tls-snapshot is valid only with --dns-snapshot')
  if (values.dnsSnapshot && !values.tlsSnapshot) throw new Error('--dns-snapshot requires --tls-snapshot')
  if (Boolean(values.ssBinary) === Boolean(values.socketSnapshot)) {
    throw new Error('provide exactly one of --ss-binary or --socket-snapshot')
  }
  if (values.ca && !values.dnsLive) throw new Error('--ca requires --dns-live')
  if (selectedMode === 'fleet' && (!values.dnsLive || !values.ssBinary || !values.releaseManifest || values.ca)) {
    throw new Error('fleet mode requires --dns-live, --ss-binary, and --release-manifest and forbids fixture/private-CA inputs')
  }
}

async function collectSocketSnapshot (binaryValue) {
  const binary = requiredAbsolutePath(binaryValue, '--ss-binary')
  let tcp
  let udp
  try {
    tcp = await execFileAsync(binary, ['-H', '-lnt'], {
      encoding: 'buffer',
      timeout: 10_000,
      maxBuffer: 1024 * 1024,
      env: { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C', LC_ALL: 'C' }
    })
    udp = await execFileAsync(binary, ['-H', '-lnu'], {
      encoding: 'buffer',
      timeout: 10_000,
      maxBuffer: 1024 * 1024,
      env: { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C', LC_ALL: 'C' }
    })
  } catch (err) {
    throw new Error(`live socket inspection failed: ${err?.killed ? 'timed out' : 'ss command failed'}`)
  }
  if (!Buffer.isBuffer(tcp.stdout) || tcp.stdout.length < 1 || !isUtf8(tcp.stdout) ||
      !Buffer.isBuffer(udp.stdout) || !isUtf8(udp.stdout)) {
    throw new Error('live socket inspection must produce bounded UTF-8 ss output')
  }
  return [
    ...tcp.stdout.toString('utf8').split(/\r?\n/).filter(Boolean).map(line => `tcp ${line}`),
    ...udp.stdout.toString('utf8').split(/\r?\n/).filter(Boolean).map(line => `udp ${line}`)
  ].join('\n')
}

async function readRegularFile (path, label, maxBytes) {
  const opened = await readOpenedFile(path, label, maxBytes)
  return opened.buffer
}

async function readPemPath (path, label, maxBytes, opts) {
  const absolute = resolve(path)
  let selected = absolute
  const initial = await lstat(absolute, { bigint: true })
  if (initial.isSymbolicLink()) {
    if (!opts.allowedRoot) throw new Error(`${label} symlink requires --certificate-root`)
    const allowedRoot = await realpath(opts.allowedRoot)
    selected = await realpath(absolute)
    if (!isWithin(allowedRoot, selected)) throw new Error(`${label} symlink must resolve inside --certificate-root`)
  } else if (!initial.isFile()) {
    throw new Error(`${label} must be a regular file or an explicitly rooted certificate symlink`)
  }
  const opened = await readOpenedFile(selected, label, maxBytes)
  if (initial.isSymbolicLink() && await realpath(absolute) !== selected) throw new Error(`${label} symlink changed while it was being read`)
  if (opened.identity.nlink !== 1n) throw new Error(`${label} must have exactly one hard link`)
  if (opts.privateFile && (opened.identity.mode & 0o077n) !== 0n) throw new Error(`${label} must not be group/world accessible`)
  if (opts.requireRootOwner && opened.identity.uid !== 0n) throw new Error(`${label} must be root-owned in fleet mode`)
  return opened
}

async function readOpenedFile (path, label, maxBytes) {
  let handle
  try {
    if (typeof constants.O_NOFOLLOW !== 'number') throw new Error('safe no-follow opens are unavailable')
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW)
    const before = await handle.stat({ bigint: true })
    if (!before.isFile() || before.size < 1n || before.size > BigInt(maxBytes)) {
      throw new Error(`${label} must be a bounded non-empty regular file`)
    }
    const buffer = Buffer.allocUnsafe(maxBytes + 1)
    let length = 0
    while (length < buffer.length) {
      const { bytesRead } = await handle.read(buffer, length, buffer.length - length, length)
      if (bytesRead === 0) break
      length += bytesRead
    }
    const after = await handle.stat({ bigint: true })
    if (length > maxBytes || BigInt(length) !== after.size || !sameSnapshot(before, after)) {
      throw new Error(`${label} changed or exceeded its size bound while being read`)
    }
    return { buffer: buffer.subarray(0, length), identity: after }
  } catch (err) {
    if (err?.message?.startsWith(label)) throw err
    throw new Error(`${label} must be a readable non-symlink regular file`)
  } finally {
    await handle?.close()
  }
}

async function writeAtomic (path, buffer) {
  const directory = dirname(path)
  let temporary = null
  let handle = null
  let renamed = false
  try {
    for (let attempt = 0; attempt < 8; attempt++) {
      temporary = join(directory, `.hiverelay-ops-${process.pid}-${randomBytes(16).toString('hex')}.tmp`)
      try {
        handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600)
        break
      } catch (err) {
        if (err.code !== 'EEXIST') throw err
      }
    }
    if (!handle) throw new Error(`unable to allocate an exclusive temporary output for ${path}`)
    await handle.writeFile(buffer)
    await handle.sync()
    await handle.close()
    handle = null
    await rename(temporary, path)
    renamed = true
  } finally {
    await handle?.close()
    if (temporary && !renamed) await unlink(temporary).catch(() => {})
  }
}

function parseJson (buffer, label) {
  if (!isUtf8(buffer)) throw new Error(`${label} must be valid UTF-8 JSON`)
  let value
  try { value = JSON.parse(buffer.toString('utf8')) } catch { throw new Error(`${label} must be valid JSON`) }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must contain a JSON object`)
  return value
}

function requiredPath (value, label) {
  if (!value) throw new Error(`${label} is required`)
  return resolve(value)
}

function requiredAbsolutePath (value, label) {
  if (typeof value !== 'string' || !isAbsolute(value) || value.length > 4096 || /[\r\n\0]/.test(value)) {
    throw new Error(`${label} must be a bounded absolute path`)
  }
  return value
}

function isWithin (root, candidate) {
  const relation = relative(root, candidate)
  return relation !== '' && relation !== '..' && !relation.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`) && !isAbsolute(relation)
}

function sameSnapshot (left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode &&
    left.nlink === right.nlink && left.size === right.size && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs
}

function parseBoundedInteger (value, label, minimum, maximum) {
  if (!/^(?:0|[1-9][0-9]*)$/.test(value || '')) throw new Error(`${label} must be an integer`)
  const parsed = Number(value)
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${label} must be between ${minimum} and ${maximum}`)
  }
  return parsed
}

function normalizeReleaseSha (value) {
  const normalized = String(value || '').toLowerCase()
  if (!/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(normalized)) {
    throw new Error('--release-sha must be the verified 40- or 64-hex tagged commit')
  }
  return normalized
}

function captureInspection (operation) {
  try { return operation() } catch (err) { return failedInspection(err.message) }
}

function failedInspection (message) {
  return { ok: false, errors: [message], result: null }
}

function sha256 (buffer) {
  return createHash('sha256').update(buffer).digest('hex')
}

function camel (value) {
  return value.replace(/-([a-z])/g, (_, char) => char.toUpperCase())
}
