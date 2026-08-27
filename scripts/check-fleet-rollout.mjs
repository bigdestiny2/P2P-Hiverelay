#!/usr/bin/env node

import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import {
  cohortEntriesForChannel,
  normalizePublicHiveGatewayReleaseManifest
} from './lib/public-hive-gateway-release-manifest.mjs'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const defaultRepoRoot = path.resolve(__dirname, '..')

const usage = `
Usage:
  node scripts/check-fleet-rollout.mjs --target vX.Y.Z [options]

Options:
  --target <tag>              Release tag expected on each relay
  --target-sha <sha>          Expected commit SHA (defaults to git rev-parse tag)
  --channel <name|both|all>   Relay channel to check (default: both)
  --relays <path>             Fleet inventory JSON (default: fleet/relays.json)
  --channels <path>           Fleet channel targets JSON (default: fleet/channels.json)
  --ssh-command <path>        Explicit SSH wrapper/executable (default: ssh)
  --ssh-key <path>            SSH key to use for every relay
  --known-hosts <path>        Pinned OpenSSH known_hosts file (required unless an
                              explicit --ssh-command wrapper owns host-key policy)
  --allowed-signers <path>    Trusted release signers (default: fleet/allowed-signers)
  --ssh-user <user>           SSH username (default: root)
  --repo <path>               Git repository containing the target tag
  --remote-repo-dir <path>    Repo path on each relay (default: $HOME/hiverelay)
  --service <name>            systemd service name (default: hiverelay)
  --api <url>                 Relay health URL base (default: http://127.0.0.1:9100)
  --timeout-ms <ms>           Total rollout wait budget (default: 1800000)
  --interval-ms <ms>          Delay between polling rounds (default: 30000)
  --ssh-timeout-ms <ms>       Per-relay SSH timeout (default: 25000)
  --gateway-evidence <path>   Absolute remote live-gateway evidence path
                              (env: HIVERELAY_FLEET_GATEWAY_EVIDENCE)
  --gateway-manifest <path>   Repo-relative manifest in the exact target commit
  --gateway-window-state <p>  Persistent local 24-hour observation state
  --evidence <path>           Write per-relay rollout evidence JSON
  --dry-run                   Resolve relays/target but do not SSH
`

const FORBIDDEN_PUBLIC_VALUE_PATTERNS = [
  [/-----BEGIN [A-Z ]*(?:PRIVATE|SECRET) KEY-----/, 'private key block'],
  [/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b/, 'GitHub token'],
  [/\bgithub_pat_[A-Za-z0-9_]{20,}\b/, 'GitHub token'],
  [/\bAuthorization\s*:\s*/i, 'authorization header'],
  [/\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b/i, 'bearer token'],
  [/\bAPP_SEED=[^\s'"]+/i, 'APP_SEED'],
  [/\bHIVERELAY_API_KEY=[^\s'"]+/i, 'API key'],
  [/\bsk-[A-Za-z0-9_-]{20,}\b/, 'API key']
]
const MAX_FLEET_METADATA_BYTES = 2 * 1024 * 1024
const FLEET_ROLLOUT_TIMEOUT_MIN_MS = 10 * 60 * 1000
const FLEET_ROLLOUT_TIMEOUT_MAX_MS = 4 * 60 * 60 * 1000
const FLEET_ROLLOUT_INTERVAL_MIN_MS = 5 * 1000
const FLEET_ROLLOUT_INTERVAL_MAX_MS = 5 * 60 * 1000
const FLEET_ROLLOUT_SSH_TIMEOUT_MIN_MS = 5 * 1000
const FLEET_ROLLOUT_SSH_TIMEOUT_MAX_MS = 2 * 60 * 1000
const MAX_GATEWAY_WINDOW_STATE_BYTES = 16 * 1024 * 1024
const SSH_KEYGEN_PROGRAM = '/usr/bin/ssh-keygen'
const GIT_PROGRAM = '/usr/bin/git'
const UNSAFE_GIT_ENV = new Set([
  'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_COMMON_DIR', 'GIT_CONFIG',
  'GIT_CONFIG_COUNT', 'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_PARAMETERS',
  'GIT_CONFIG_SYSTEM', 'GIT_DIR', 'GIT_EXEC_PATH', 'GIT_GRAFT_FILE',
  'GIT_INDEX_FILE', 'GIT_NAMESPACE', 'GIT_OBJECT_DIRECTORY', 'GIT_PREFIX',
  'GIT_QUARANTINE_PATH', 'GIT_REPLACE_REF_BASE', 'GIT_SHALLOW_FILE',
  'GIT_WORK_TREE'
])
const MAX_GATEWAY_SAMPLES_PER_RELAY = 20000
const GATEWAY_CONTROLLER_CLOCK_SKEW_MS = 5 * 60 * 1000
const GATEWAY_WINDOW_STATE_SCHEMA = 'hiverelay-public-gateway-window-state-v1'
const GATEWAY_TOKEN_SCHEMA = 'hiverelay-public-gateway-evidence-verification-v2'
const GATEWAY_CHECK_NAMES = Object.freeze([
  'metadata',
  'exactBytes',
  'range',
  'head',
  'canonicalIdentity',
  'managementIsolation',
  'forwardedHostIsolation',
  'unavailableAppIsolation',
  'defaultSniRejection',
  'sniHostBinding'
])

const args = parseArgs(process.argv.slice(2))
const target = args.target || args._[0]
if (!target || args.help) {
  console.log(usage.trim())
  process.exit(args.help ? 0 : 1)
}
if (!/^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(target)) {
  die(`Invalid --target "${target}". Expected vX.Y.Z.`)
}

const channel = args.channel || process.env.HIVERELAY_FLEET_CHANNEL || 'both'
const repoRoot = path.resolve(args.repo || defaultRepoRoot)
const relaysPath = path.resolve(args.relays || path.join(repoRoot, 'fleet', 'relays.json'))
const channelsPath = path.resolve(args.channels || path.join(repoRoot, 'fleet', 'channels.json'))
const explicitSshCommand = args.sshCommand || process.env.HIVERELAY_FLEET_SSH_COMMAND || ''
const sshCommand = validateLocalCommand(explicitSshCommand || 'ssh')
const sshKey = validateLocalPath(args.sshKey || process.env.HIVERELAY_FLEET_SSH_KEY || '', 'ssh-key')
const knownHosts = validateLocalPath(args.knownHosts || process.env.HIVERELAY_FLEET_KNOWN_HOSTS || '', 'known-hosts')
const allowedSignersPath = path.resolve(args.allowedSigners || path.join(repoRoot, 'fleet', 'allowed-signers'))
const sshUser = validateSshUser(args.sshUser || process.env.HIVERELAY_FLEET_SSH_USER || 'root')
const remoteRepoDir = validateRemotePath(args.remoteRepoDir || process.env.HIVERELAY_REMOTE_REPO_DIR || '', 'remote-repo-dir')
const service = validateServiceName(args.service || process.env.HIVERELAY_SERVICE || 'hiverelay')
const api = normalizeApiBase(args.api || process.env.HIVERELAY_API || 'http://127.0.0.1:9100')
const timeoutMs = numberArg(args.timeoutMs || process.env.HIVERELAY_FLEET_ROLLOUT_TIMEOUT_MS, 1800000, 'timeout-ms')
const intervalMs = numberArg(args.intervalMs || process.env.HIVERELAY_FLEET_ROLLOUT_INTERVAL_MS, 30000, 'interval-ms')
const sshTimeoutMs = numberArg(args.sshTimeoutMs || process.env.HIVERELAY_FLEET_SSH_TIMEOUT_MS, 25000, 'ssh-timeout-ms')
const gatewayEvidencePath = validateRemoteAbsolutePath(
  args.gatewayEvidence || process.env.HIVERELAY_FLEET_GATEWAY_EVIDENCE || '',
  'gateway-evidence'
)
const gatewayManifestPath = validateRepoRelativePath(
  args.gatewayManifest || process.env.HIVERELAY_FLEET_GATEWAY_MANIFEST || '',
  'gateway-manifest'
)
const gatewayWindowStatePath = validateLocalAbsolutePath(
  args.gatewayWindowState || process.env.HIVERELAY_FLEET_GATEWAY_WINDOW_STATE || '',
  'gateway-window-state'
)
const evidenceFile = args.evidence || process.env.HIVERELAY_FLEET_ROLLOUT_EVIDENCE || ''
const dryRun = Boolean(args.dryRun)
const targetSha = String(args.targetSha || await resolveTargetSha(target)).toLowerCase()
const targetVersion = target.slice(1)
let relays = selectRelays(readInventory(relaysPath), channel)
const channelTargets = validateChannelTargets(readChannels(channelsPath), channel, target)
const inventorySha256 = sha256File(relaysPath, 'fleet inventory')
const channelsSha256 = sha256File(channelsPath, 'fleet channel config')
const inventoryPath = pathForEvidence(relaysPath)
const channelsEvidencePath = pathForEvidence(channelsPath)
let gatewayRelease = null
let gatewayManifestSha256 = ''
let gatewayCohortByRelay = new Map()
let gatewayCohortNames = []
let gatewayWindow = null
let gatewayWindowStateSha256 = ''

if (!/^[a-f0-9]{40}$/i.test(targetSha)) die(`Invalid target SHA "${targetSha}".`)
if (!relays.length) die(`No relays matched channel "${channel}" in ${relaysPath}.`)

if (gatewayEvidencePath) {
  if (!gatewayManifestPath) die('--gateway-manifest is required with --gateway-evidence.')
  if (!knownHosts) die('--known-hosts is required with --gateway-evidence; unpinned host keys are refused.')
  if (!gatewayWindowStatePath) die('--gateway-window-state is required with --gateway-evidence.')
  if (!evidenceFile) die('--evidence is required with --gateway-evidence so the manifest-bound result is retained.')
  if (!['canary', 'stable', 'both'].includes(channel)) {
    die('Public gateway rollout requires --channel canary, stable, or both.')
  }
  readFleetMetadataFile(allowedSignersPath, 'trusted release allowed_signers')
  await verifySignedTargetTag(target)
  const taggedSha = await resolveTargetSha(target)
  if (taggedSha.toLowerCase() !== targetSha.toLowerCase()) {
    die(`Target SHA ${targetSha} does not match tagged commit ${taggedSha}.`)
  }
  const manifestBytes = await readTargetFile(targetSha, gatewayManifestPath, 'public gateway release manifest')
  gatewayManifestSha256 = crypto.createHash('sha256').update(manifestBytes).digest('hex')
  gatewayRelease = parseGatewayReleaseManifest(manifestBytes)
  const expectedEntries = channel === 'both'
    ? gatewayRelease.cohort
    : cohortEntriesForChannel(gatewayRelease, channel)
  relays = selectExactGatewayCohort(relays, expectedEntries)
  gatewayCohortByRelay = new Map(expectedEntries.map(entry => [entry.relay, entry]))
  gatewayCohortNames = expectedEntries.map(entry => entry.relay)
  const existingState = readGatewayWindowStateIfPresent()
  if (existingState) {
    gatewayWindow = summarizeGatewayWindowState(existingState)
    gatewayWindowStateSha256 = sha256GatewayState(existingState)
  }
} else if (gatewayManifestPath || gatewayWindowStatePath) {
  die('--gateway-manifest and --gateway-window-state require --gateway-evidence.')
}

if (knownHosts) assertKnownHostsFile(knownHosts)
if (!dryRun && !knownHosts && !explicitSshCommand) {
  die('--known-hosts is required for live rollout checks unless an explicit --ssh-command wrapper owns pinned host-key policy.')
}

console.log(`Fleet rollout target: ${target} (${targetSha})`)
console.log(`Checking ${relays.length} relay(s) on channel ${channel}: ${relays.map((r) => r.name).join(', ')}`)

if (dryRun) {
  writeRolloutEvidence('dry-run', relays.map((relay) => ({ relay })))
  console.log('dry-run: not opening SSH connections')
  process.exit(0)
}

const deadline = Date.now() + timeoutMs
let lastResults = []
while (Date.now() < deadline) {
  lastResults = await Promise.all(relays.map((relay) => probeRelay(relay)))
  if (gatewayEvidencePath) updateGatewayWindowState(lastResults)
  printResults(lastResults)
  if (gatewayEvidencePath && lastResults.every(resultIsRelayGreen) && !gatewayWindow?.complete) {
    writeRolloutEvidence('observing', lastResults, 'signed public gateway observation window is incomplete')
    console.error('Public gateway is green, but its signed 24-hour observation window is incomplete. Persisted this sample; rerun after the next fresh live probe.')
    process.exit(2)
  }
  if (lastResults.every(resultIsGreen)) {
    writeRolloutEvidence('verified', lastResults)
    console.log(`Fleet rollout verified: ${relays.length}/${relays.length} relay(s) on ${target}`)
    process.exit(0)
  }
  await sleep(Math.min(intervalMs, Math.max(0, deadline - Date.now())))
}

console.error(`Fleet rollout did not converge within ${timeoutMs}ms.`)
printResults(lastResults, { stderr: true })
writeRolloutEvidence('failed', lastResults, `timeout after ${timeoutMs}ms`)
process.exit(1)

function parseArgs (argv) {
  const out = { _: [] }
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--help' || arg === '-h') {
      out.help = true
      continue
    }
    if (!arg.startsWith('--')) {
      out._.push(arg)
      continue
    }
    const key = camel(arg.slice(2))
    if (key === 'dryRun') {
      out[key] = true
      continue
    }
    const value = argv[++i]
    if (!value || value.startsWith('--')) die(`Missing value for ${arg}`)
    out[key] = value
  }
  return out
}

function camel (value) {
  return value.replace(/-([a-z])/g, (_, c) => c.toUpperCase())
}

function numberArg (value, fallback, name) {
  if (value == null || value === '') return fallback
  const raw = String(value)
  if (!/^[1-9][0-9]*$/.test(raw)) die(`Invalid --${name} value. Expected a positive integer without whitespace or control characters.`)
  const n = Number(raw)
  if (!Number.isSafeInteger(n)) die(`Invalid --${name} value. Expected a safe positive integer.`)
  return n
}

function readInventory (file) {
  const json = JSON.parse(readFleetMetadataFile(file, 'fleet inventory', 'utf8'))
  if (!Array.isArray(json.relays)) die(`${file} is missing a relays array.`)
  return json.relays
}

function readChannels (file) {
  const json = JSON.parse(readFleetMetadataFile(file, 'fleet channel config', 'utf8'))
  if (!json || typeof json !== 'object' || Array.isArray(json)) die(`${file} must be a JSON object.`)
  return json
}

function validateChannelTargets (channels, requestedChannel, expectedTarget) {
  const required = requiredChannelNames(channels, requestedChannel)
  const out = {}
  for (const name of required) {
    const value = channels[name]
    if (typeof value !== 'string' || !value) die(`fleet channel ${name} is missing a release target in ${channelsPath}.`)
    const safeName = validatePublicLabel(name, 'fleet channel name', 32)
    const safeValue = validatePublicLabel(value, `fleet channel ${name} target`, 80)
    if (safeValue !== expectedTarget) {
      die(`fleet channel ${name} target is ${safeValue}; expected ${expectedTarget}. Run npm run release:prepare or update fleet/channels.json before checking rollout.`)
    }
    out[safeName] = safeValue
  }
  return out
}

function requiredChannelNames (channels, requestedChannel) {
  if (requestedChannel === 'both') return ['canary', 'stable']
  if (requestedChannel === 'all') {
    const names = Object.keys(channels)
      .filter((name) => !name.startsWith('_'))
      .sort()
    if (names.length === 0) die(`${channelsPath} does not define any fleet channels.`)
    return names
  }
  return [requestedChannel]
}

function selectRelays (allRelays, requestedChannel) {
  const allowed = new Set()
  let includeAll = false
  if (requestedChannel === 'all') {
    includeAll = true
  } else if (requestedChannel === 'both') {
    allowed.add('stable')
    allowed.add('canary')
  } else if (/^[A-Za-z0-9._-]{1,32}$/.test(requestedChannel)) {
    allowed.add(requestedChannel)
  } else {
    die(`Invalid --channel "${requestedChannel}".`)
  }
  const selected = []
  const selectedNames = new Set()
  for (const raw of allRelays) {
    const rawChannel = raw.channel || 'stable'
    if (!includeAll && !allowed.has(rawChannel)) continue
    const name = validatePublicLabel(raw.name || '(unnamed)', 'relay name', 80)
    const relayChannel = validatePublicLabel(rawChannel, 'relay channel', 32)
    const host = raw.tailnet || raw.publicIp
    if (!host) continue
    if (selectedNames.has(name)) {
      die(`Duplicate relay name "${name}" in selected fleet channel "${requestedChannel}". Relay names must be unique before rollout evidence is written.`)
    }
    selectedNames.add(name)
    selected.push({
      name,
      channel: relayChannel,
      host: validateSshHost(host, `relay host for ${name}`),
      sshKey: validateLocalPath(raw.sshKey || '', `ssh key for ${name}`)
    })
  }
  return selected
}

async function resolveTargetSha (tag) {
  const result = await runLocal('git', ['rev-parse', `${tag}^{commit}`], { cwd: repoRoot, timeoutMs: 10000 })
  if (result.code !== 0) die(`Could not resolve ${tag}^{commit}; fetch tags first.\n${result.stderr.trim()}`)
  return result.stdout.trim()
}

async function verifySignedTargetTag (tag) {
  const result = await runLocal('git', ['cat-file', '-t', `refs/tags/${tag}`], { cwd: repoRoot, timeoutMs: 10000 })
  if (result.code !== 0 || result.stdout.trim() !== 'tag') {
    die(`Public gateway target ${tag} must be an annotated release tag.`)
  }
  const tagObject = await runLocal('git', ['cat-file', '-p', `refs/tags/${tag}`], { cwd: repoRoot, timeoutMs: 10000 })
  if (tagObject.code !== 0 || !/-----BEGIN (?:SSH|PGP) SIGNATURE-----/.test(tagObject.stdout)) {
    die(`Public gateway target ${tag} must carry a release signature.`)
  }
  const verified = await runLocal('git', [
    '-c', 'gpg.format=ssh',
    '-c', `gpg.ssh.allowedSignersFile=${allowedSignersPath}`,
    '-c', `gpg.ssh.program=${SSH_KEYGEN_PROGRAM}`,
    'verify-tag', '--raw', tag
  ], { cwd: repoRoot, timeoutMs: 15000 })
  const output = `${verified.stdout}\n${verified.stderr}`
  if (verified.code !== 0 || !/GOODSIG|TRUST_(?:FULLY|ULTIMATE)|Good[^\r\n]*signature/i.test(output)) {
    die(`Public gateway target ${tag} is not signed by a trusted fleet signer.`)
  }
}

async function readTargetFile (commitSha, repoRelativePath, label) {
  const result = await runLocal('git', ['show', `${commitSha}:${repoRelativePath}`], {
    cwd: repoRoot,
    timeoutMs: 10000,
    maxOutputBytes: MAX_FLEET_METADATA_BYTES
  })
  if (result.code !== 0) die(`Could not read ${label} ${repoRelativePath} from ${commitSha}.`)
  const bytes = Buffer.from(result.stdout)
  if (bytes.byteLength > MAX_FLEET_METADATA_BYTES) die(`${label} exceeds ${MAX_FLEET_METADATA_BYTES} bytes.`)
  return bytes
}

function parseGatewayReleaseManifest (bytes) {
  let parsed
  try {
    parsed = JSON.parse(bytes.toString('utf8'))
  } catch (_) {
    die('Public gateway release manifest in the target commit is not valid JSON.')
  }
  try {
    return normalizePublicHiveGatewayReleaseManifest(parsed, {
      releaseTarget: target,
      requirePublicT1: true
    })
  } catch (err) {
    die(`Invalid public gateway release manifest: ${safeProbeError(err?.message || err)}`)
  }
}

function selectExactGatewayCohort (selectedRelays, expectedEntries) {
  if (expectedEntries.length === 0) die(`Public gateway release manifest has no ${channel} cohort.`)
  const selected = new Map(selectedRelays.map(relay => [relay.name, relay]))
  const cohortRelays = []
  for (const entry of expectedEntries) {
    const relay = selected.get(entry.relay)
    if (!relay) die(`Signed public gateway cohort relay ${entry.relay} is missing from the selected fleet inventory.`)
    if (relay.channel !== entry.channel) {
      die(`Relay ${entry.relay} channel does not match its signed public gateway cohort entry.`)
    }
    cohortRelays.push(relay)
  }
  return cohortRelays
}

function decodeAndValidateRolloutToken (encoded, relay) {
  if (typeof encoded !== 'string' || !/^[A-Za-z0-9_-]{32,8192}$/.test(encoded)) {
    throw new Error('invalid gateway rollout token encoding')
  }
  let bytes
  let token
  try {
    bytes = Buffer.from(encoded, 'base64url')
    if (bytes.toString('base64url') !== encoded) throw new Error('non-canonical base64url')
    token = JSON.parse(bytes.toString('utf8'))
  } catch (_) {
    throw new Error('invalid gateway rollout token')
  }
  assertRolloutTokenSummarySchema(token, `gateway rollout token for ${relay.name}`)
  const entry = gatewayCohortByRelay.get(relay.name)
  if (!entry) throw new Error(`relay ${relay.name} has no signed gateway cohort entry`)
  if (token.schema !== GATEWAY_TOKEN_SCHEMA || token.status !== 'verified' || token.mode !== 'fleet' ||
      token.admissionProfile !== gatewayRelease.admissionProfile || token.releaseTarget !== target ||
      String(token.releaseSha).toLowerCase() !== targetSha.toLowerCase()) {
    throw new Error('gateway rollout token release posture does not match the signed manifest')
  }
  const exact = [
    ['origin', entry.origin],
    ['connectAddress', entry.connectAddress],
    ['appKey', entry.appKey],
    ['path', entry.path],
    ['contentSha256', entry.contentSha256],
    ['driveVersion', entry.driveVersion],
    ['peerFingerprint256', entry.peerFingerprint256],
    ['nginxSha256', entry.nginxConfigSha256]
  ]
  for (const [name, expected] of exact) {
    if (token[name] !== expected) throw new Error(`gateway rollout token ${name} does not match signed manifest`)
  }
  if (token.tlsProtocol !== 'TLSv1.2' && token.tlsProtocol !== 'TLSv1.3') {
    throw new Error('gateway rollout token TLS version is invalid')
  }
  if (typeof token.publicSuffixReady !== 'boolean' || !/^[a-f0-9]{64}$/.test(token.evidenceSha256 || '')) {
    throw new Error('gateway rollout token public fields are invalid')
  }
  if (token.physicalEnforcementRequired !== true) {
    throw new Error('gateway rollout token must attest the physical enforcement requirement')
  }
  const checkedAt = requireIsoMs(token.checkedAt, 'gateway rollout token checkedAt')
  const observedAt = requireIsoMs(token.probeObservedAt, 'gateway rollout token probeObservedAt')
  if (observedAt > checkedAt) throw new Error('gateway rollout token observation is after its check')
  const controllerNow = Date.now()
  if (checkedAt > controllerNow + GATEWAY_CONTROLLER_CLOCK_SKEW_MS ||
      observedAt > controllerNow + GATEWAY_CONTROLLER_CLOCK_SKEW_MS) {
    throw new Error('gateway rollout token is too far in the controller future')
  }
  if (controllerNow - checkedAt > gatewayRelease.maxProbeGapMs ||
      controllerNow - observedAt > gatewayRelease.maxProbeGapMs) {
    throw new Error('gateway rollout token is older than the signed maximum probe gap')
  }
  assertPublicSafeValues(token, 'gateway rollout token')
  return token
}

function assertRolloutTokenSummarySchema (token, label) {
  requireOnlyKeys(label, token, [
    'schema',
    'status',
    'mode',
    'admissionProfile',
    'publicSuffixReady',
    'physicalEnforcementRequired',
    'releaseTarget',
    'releaseSha',
    'checkedAt',
    'probeObservedAt',
    'origin',
    'connectAddress',
    'appKey',
    'path',
    'contentSha256',
    'driveVersion',
    'tlsProtocol',
    'peerFingerprint256',
    'nginxSha256',
    'checks',
    'evidenceSha256'
  ])
  requireOnlyKeys(`${label} checks`, token.checks, GATEWAY_CHECK_NAMES)
  for (const name of GATEWAY_CHECK_NAMES) {
    if (token.checks[name] !== true) throw new Error(`${label} check ${name} is not true`)
  }
}

function requireIsoMs (value, label) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) {
    throw new Error(`${label} must be a canonical ISO timestamp`)
  }
  const ms = Date.parse(value)
  if (!Number.isFinite(ms) || new Date(ms).toISOString() !== value) throw new Error(`${label} is invalid`)
  return ms
}

function readGatewayWindowStateIfPresent () {
  if (!fs.existsSync(gatewayWindowStatePath)) return null
  let parsed
  try {
    parsed = JSON.parse(readFleetMetadataFile(
      gatewayWindowStatePath,
      'public gateway observation state',
      'utf8',
      MAX_GATEWAY_WINDOW_STATE_BYTES
    ))
  } catch (err) {
    if (err?.message) die(err.message)
    die('Public gateway observation state is not valid JSON.')
  }
  validateGatewayWindowState(parsed)
  return parsed
}

function createGatewayWindowState () {
  return {
    schema: GATEWAY_WINDOW_STATE_SCHEMA,
    releaseTarget: target,
    releaseSha: targetSha.toLowerCase(),
    channel,
    manifestSha256: gatewayManifestSha256,
    observationWindowMs: gatewayRelease.observationWindowMs,
    maxProbeGapMs: gatewayRelease.maxProbeGapMs,
    cohortNames: [...gatewayCohortNames],
    relays: gatewayCohortNames.map(name => ({ name, samples: [] }))
  }
}

function validateGatewayWindowState (state) {
  requireOnlyKeys('public gateway observation state', state, [
    'schema',
    'releaseTarget',
    'releaseSha',
    'channel',
    'manifestSha256',
    'observationWindowMs',
    'maxProbeGapMs',
    'cohortNames',
    'relays'
  ])
  if (state.schema !== GATEWAY_WINDOW_STATE_SCHEMA || state.releaseTarget !== target ||
      state.releaseSha !== targetSha.toLowerCase() || state.channel !== channel ||
      state.manifestSha256 !== gatewayManifestSha256 ||
      state.observationWindowMs !== gatewayRelease.observationWindowMs ||
      state.maxProbeGapMs !== gatewayRelease.maxProbeGapMs) {
    die('Public gateway observation state does not match the exact release manifest and rollout target.')
  }
  if (!sameStringArray(state.cohortNames, gatewayCohortNames)) {
    die('Public gateway observation state cohort does not match the signed manifest.')
  }
  if (!Array.isArray(state.relays) || state.relays.length !== gatewayCohortNames.length) {
    die('Public gateway observation state must contain every signed cohort relay exactly once.')
  }
  for (let i = 0; i < state.relays.length; i++) {
    const relay = state.relays[i]
    requireOnlyKeys(`public gateway observation state relay[${i}]`, relay, ['name', 'samples'])
    if (relay.name !== gatewayCohortNames[i] || !Array.isArray(relay.samples) ||
        relay.samples.length > MAX_GATEWAY_SAMPLES_PER_RELAY) {
      die('Public gateway observation state relay order or sample bounds are invalid.')
    }
    let previousObserved = -1
    let previousCollected = -1
    const digests = new Set()
    for (let j = 0; j < relay.samples.length; j++) {
      const sample = relay.samples[j]
      requireOnlyKeys(`public gateway observation state ${relay.name} sample[${j}]`, sample, [
        'observedAt',
        'collectedAt',
        'evidenceSha256'
      ])
      const observed = requireIsoMs(sample.observedAt, `public gateway observation state ${relay.name} observedAt`)
      const collected = requireIsoMs(sample.collectedAt, `public gateway observation state ${relay.name} collectedAt`)
      if (observed <= previousObserved || collected <= previousCollected) {
        die('Public gateway observation state relay and controller timestamps must be strictly increasing.')
      }
      if (observed > collected + GATEWAY_CONTROLLER_CLOCK_SKEW_MS ||
          collected - observed > gatewayRelease.maxProbeGapMs) {
        die('Public gateway observation state relay timestamp is not fresh at controller collection time.')
      }
      if (!/^[a-f0-9]{64}$/.test(sample.evidenceSha256 || '') || digests.has(sample.evidenceSha256)) {
        die('Public gateway observation state evidence digests must be valid and unique per relay.')
      }
      if (previousObserved >= 0 && (
        observed - previousObserved > gatewayRelease.maxProbeGapMs ||
        collected - previousCollected > gatewayRelease.maxProbeGapMs
      )) {
        die('Public gateway observation state contains a relay or controller gap larger than the signed manifest allows.')
      }
      previousObserved = observed
      previousCollected = collected
      digests.add(sample.evidenceSha256)
    }
  }
}

function updateGatewayWindowState (results) {
  const state = readGatewayWindowStateIfPresent() || createGatewayWindowState()
  const resultsByName = new Map(results.map(result => [result.relay.name, result]))
  const collectedAt = new Date().toISOString()
  for (const relayState of state.relays) {
    const result = resultsByName.get(relayState.name)
    if (!result?.gatewayHealthy || !result.gateway) {
      relayState.samples = []
      continue
    }
    const sample = {
      observedAt: result.gateway.probeObservedAt,
      collectedAt,
      evidenceSha256: result.gateway.evidenceSha256
    }
    const sampleMs = requireIsoMs(sample.observedAt, `gateway observation ${relayState.name}`)
    const collectedMs = requireIsoMs(sample.collectedAt, `gateway controller collection ${relayState.name}`)
    const last = relayState.samples.at(-1)
    if (last) {
      const lastMs = requireIsoMs(last.observedAt, `gateway observation ${relayState.name}`)
      const lastCollectedMs = requireIsoMs(last.collectedAt, `gateway controller collection ${relayState.name}`)
      if (sampleMs < lastMs || collectedMs <= lastCollectedMs ||
          sampleMs - lastMs > gatewayRelease.maxProbeGapMs ||
          collectedMs - lastCollectedMs > gatewayRelease.maxProbeGapMs) {
        relayState.samples = []
      } else if (sampleMs === lastMs) {
        if (last.evidenceSha256 !== sample.evidenceSha256) {
          // A new evidence file for the same live observation is not a new continuity sample.
          last.evidenceSha256 = sample.evidenceSha256
        }
        continue
      }
    }
    if (relayState.samples.some(item => item.evidenceSha256 === sample.evidenceSha256)) {
      relayState.samples = []
    }
    relayState.samples.push(sample)
    pruneGatewaySamples(relayState.samples)
  }
  validateGatewayWindowState(state)
  writeGatewayWindowState(state)
  gatewayWindow = summarizeGatewayWindowState(state)
  gatewayWindowStateSha256 = sha256GatewayState(state)
}

function pruneGatewaySamples (samples) {
  if (samples.length <= 2) return
  const latestObservedMs = requireIsoMs(samples.at(-1).observedAt, 'latest gateway observation')
  const latestCollectedMs = requireIsoMs(samples.at(-1).collectedAt, 'latest gateway controller collection')
  const observedCutoff = latestObservedMs - gatewayRelease.observationWindowMs
  const collectedCutoff = latestCollectedMs - gatewayRelease.observationWindowMs
  let keepFrom = 0
  for (let i = 0; i < samples.length - 1; i++) {
    if (requireIsoMs(samples[i].observedAt, 'gateway observation') <= observedCutoff &&
        requireIsoMs(samples[i].collectedAt, 'gateway controller collection') <= collectedCutoff) keepFrom = i
    else break
  }
  if (keepFrom > 0) samples.splice(0, keepFrom)
  if (samples.length > MAX_GATEWAY_SAMPLES_PER_RELAY) {
    die('Public gateway observation state exceeded its fail-closed sample bound.')
  }
}

function summarizeGatewayWindowState (state, nowMs = Date.now()) {
  validateGatewayWindowState(state)
  let relayWindowStartedMs = -1
  let relayWindowEndedMs = Number.MAX_SAFE_INTEGER
  let controllerWindowStartedMs = -1
  let controllerWindowEndedMs = Number.MAX_SAFE_INTEGER
  let sampleCount = 0
  let maxGapMs = 0
  let hasEnoughSamples = true
  let latestSamplesFresh = true
  for (const relay of state.relays) {
    sampleCount += relay.samples.length
    if (relay.samples.length > 0) {
      const firstObservedMs = requireIsoMs(relay.samples[0].observedAt, `${relay.name} first observation`)
      const lastObservedMs = requireIsoMs(relay.samples.at(-1).observedAt, `${relay.name} last observation`)
      const firstCollectedMs = requireIsoMs(relay.samples[0].collectedAt, `${relay.name} first controller collection`)
      const lastCollectedMs = requireIsoMs(relay.samples.at(-1).collectedAt, `${relay.name} last controller collection`)
      relayWindowStartedMs = Math.max(relayWindowStartedMs, firstObservedMs)
      relayWindowEndedMs = Math.min(relayWindowEndedMs, lastObservedMs)
      controllerWindowStartedMs = Math.max(controllerWindowStartedMs, firstCollectedMs)
      controllerWindowEndedMs = Math.min(controllerWindowEndedMs, lastCollectedMs)
      if (lastCollectedMs > nowMs + GATEWAY_CONTROLLER_CLOCK_SKEW_MS ||
          nowMs - lastCollectedMs > gatewayRelease.maxProbeGapMs ||
          lastObservedMs > nowMs + GATEWAY_CONTROLLER_CLOCK_SKEW_MS ||
          nowMs - lastObservedMs > gatewayRelease.maxProbeGapMs) {
        latestSamplesFresh = false
      }
    }
    if (relay.samples.length < 2) {
      hasEnoughSamples = false
      continue
    }
    for (let i = 1; i < relay.samples.length; i++) {
      const relayGap = requireIsoMs(relay.samples[i].observedAt, 'gateway observation') -
        requireIsoMs(relay.samples[i - 1].observedAt, 'gateway observation')
      const controllerGap = requireIsoMs(relay.samples[i].collectedAt, 'gateway controller collection') -
        requireIsoMs(relay.samples[i - 1].collectedAt, 'gateway controller collection')
      maxGapMs = Math.max(maxGapMs, relayGap, controllerGap)
    }
  }
  const hasRelayWindow = relayWindowStartedMs >= 0 && relayWindowEndedMs !== Number.MAX_SAFE_INTEGER &&
    relayWindowEndedMs >= relayWindowStartedMs
  const hasControllerWindow = controllerWindowStartedMs >= 0 && controllerWindowEndedMs !== Number.MAX_SAFE_INTEGER &&
    controllerWindowEndedMs >= controllerWindowStartedMs
  const relayDurationMs = hasRelayWindow ? relayWindowEndedMs - relayWindowStartedMs : 0
  const controllerDurationMs = hasControllerWindow ? controllerWindowEndedMs - controllerWindowStartedMs : 0
  // Report the controller-observed window. Completion additionally requires
  // the relay evidence timeline to span the same signed duration.
  const durationMs = Math.min(relayDurationMs, controllerDurationMs)
  return {
    windowStartedAt: hasControllerWindow ? new Date(controllerWindowStartedMs).toISOString() : null,
    windowEndedAt: hasControllerWindow ? new Date(controllerWindowEndedMs).toISOString() : null,
    durationMs,
    sampleCount,
    maxGapMs,
    relayCount: state.relays.length,
    complete: hasEnoughSamples && hasRelayWindow && hasControllerWindow && latestSamplesFresh &&
      relayDurationMs >= gatewayRelease.observationWindowMs &&
      controllerDurationMs >= gatewayRelease.observationWindowMs &&
      maxGapMs <= gatewayRelease.maxProbeGapMs
  }
}

function emptyGatewayWindowSummary () {
  return {
    windowStartedAt: null,
    windowEndedAt: null,
    durationMs: 0,
    sampleCount: 0,
    maxGapMs: 0,
    relayCount: gatewayCohortNames.length,
    complete: false
  }
}

function writeGatewayWindowState (state) {
  const bytes = Buffer.from(JSON.stringify(state, null, 2) + '\n')
  if (bytes.byteLength > MAX_GATEWAY_WINDOW_STATE_BYTES) {
    die('Public gateway observation state exceeds its fail-closed size bound.')
  }
  writeFileAtomicSync(gatewayWindowStatePath, bytes)
}

function sha256GatewayState (state) {
  return crypto.createHash('sha256').update(JSON.stringify(state, null, 2) + '\n').digest('hex')
}

function sameStringArray (actual, expected) {
  return Array.isArray(actual) && actual.length === expected.length &&
    actual.every((value, index) => value === expected[index])
}

async function probeRelay (relay) {
  const observedAt = new Date().toISOString()
  const key = sshKey || normalizeInventoryKey(relay.sshKey)
  const sshArgs = [
    '-o', 'BatchMode=yes',
    '-o', 'StrictHostKeyChecking=yes',
    '-o', 'UpdateHostKeys=no',
    '-o', 'ConnectTimeout=10',
    '-o', 'ServerAliveInterval=5',
    '-o', 'ServerAliveCountMax=2'
  ]
  if (knownHosts) {
    // When a pin file is provided it is the only host-key authority. Do not
    // silently accept a matching key or CA from machine-wide OpenSSH trust.
    sshArgs.push('-o', `UserKnownHostsFile=${expandHome(knownHosts)}`)
    sshArgs.push('-o', 'GlobalKnownHostsFile=/dev/null')
  }
  if (key) sshArgs.push('-i', expandHome(key))
  sshArgs.push(`${sshUser}@${relay.host}`, 'bash', '-s')

  const result = await runLocal(sshCommand, sshArgs, {
    input: remoteProbeScript(relay),
    timeoutMs: sshTimeoutMs
  })

  if (result.code !== 0) {
    return {
      relay,
      observedAt,
      ok: false,
      updated: false,
      healthy: false,
      ...(gatewayEvidencePath ? { gatewayHealthy: false, gateway: null } : {}),
      error: result.timedOut ? 'ssh timed out' : safeProbeError(result.stderr || result.stdout || `ssh exited ${result.code}`)
    }
  }

  const line = result.stdout.trim().split(/\r?\n/).pop() || ''
  const [headSha, version, running, disk, healthVersion, health, updaterState, gatewayState, gatewayToken] = line.split('\t')
  const updated = headSha === targetSha
  const packageVersionMatches = version === target
  const serviceHealthy = running === 'true'
  const updaterReady = updaterState === 'true'
  // Keep the public evidence schema compatible while strengthening its
  // `healthy` predicate: a relay is not promotable unless its signed updater
  // control plane can deliver the next channel transition too.
  const healthy = serviceHealthy && updaterReady
  const runtimeVersionMatches = healthVersion === targetVersion
  let gateway = null
  if (gatewayEvidencePath && gatewayState === 'true') {
    try {
      gateway = decodeAndValidateRolloutToken(gatewayToken, relay)
    } catch (_) {}
  }
  const gatewayHealthy = gateway !== null
  return {
    relay,
    observedAt,
    ok: true,
    updated,
    packageVersionMatches,
    healthy,
    serviceHealthy,
    updaterReady,
    runtimeVersionMatches,
    headSha,
    version,
    healthVersion,
    running,
    disk,
    health,
    ...(gatewayEvidencePath ? { gatewayHealthy, gateway } : {})
  }
}

function normalizeInventoryKey (key) {
  if (!key || key === 'default') return ''
  return key
}

function expandHome (value) {
  if (value === '~') return process.env.HOME || value
  if (value.startsWith('~/')) return path.join(process.env.HOME || '', value.slice(2))
  return value
}

function remoteProbeScript (relay) {
  const repoLine = remoteRepoDir
    ? `repo=${shellQuote(remoteRepoDir)}`
    : 'repo="$' + '{HIVERELAY_REMOTE_REPO_DIR:-$HOME/hiverelay}"'
  const serviceLine = `service=${shellQuote(service)}`
  const apiLine = `api=${shellQuote(api)}`
  const gatewayEvidenceLine = `gateway_evidence=${shellQuote(gatewayEvidencePath)}`
  const releaseTargetLine = `release_target=${shellQuote(target)}`
  const releaseShaLine = `release_sha=${shellQuote(targetSha)}`
  const expectedChannelLine = `expected_channel=${shellQuote(relay.channel)}`
  const expectedRelayNameLine = `expected_relay_name=${shellQuote(relay.name)}`
  const entry = gatewayEvidencePath ? gatewayCohortByRelay.get(relay.name) : null
  const gatewayExpectedLines = entry
    ? [
        `required_admission_profile=${shellQuote(gatewayRelease.admissionProfile)}`,
        `expected_origin=${shellQuote(entry.origin)}`,
        `expected_connect_address=${shellQuote(entry.connectAddress)}`,
        `expected_app_key=${shellQuote(entry.appKey)}`,
        `expected_path=${shellQuote(entry.path)}`,
        `expected_sha256=${shellQuote(entry.contentSha256)}`,
        `expected_drive_version=${shellQuote(entry.driveVersion)}`,
        `expected_peer_fingerprint256=${shellQuote(entry.peerFingerprint256)}`,
        `expected_nginx_sha256=${shellQuote(entry.nginxConfigSha256)}`
      ].join('\n')
    : ''
  return String.raw`set -euo pipefail
unset GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR GIT_CONFIG GIT_CONFIG_COUNT
unset GIT_CONFIG_GLOBAL GIT_CONFIG_PARAMETERS GIT_CONFIG_SYSTEM GIT_DIR GIT_EXEC_PATH
unset GIT_INDEX_FILE GIT_NAMESPACE GIT_OBJECT_DIRECTORY GIT_PREFIX GIT_QUARANTINE_PATH
unset GIT_REPLACE_REF_BASE GIT_SHALLOW_FILE GIT_WORK_TREE
export GIT_NO_REPLACE_OBJECTS=1
export GIT_GRAFT_FILE=/dev/null/hiverelay-disabled
export GIT_OPTIONAL_LOCKS=0
export GIT_CONFIG_COUNT=2
export GIT_CONFIG_KEY_0=core.hooksPath
export GIT_CONFIG_VALUE_0=/dev/null
export GIT_CONFIG_KEY_1=core.fsmonitor
export GIT_CONFIG_VALUE_1=false
git() { /usr/bin/git "$@"; }
${repoLine}
${serviceLine}
${apiLine}
${gatewayEvidenceLine}
${releaseTargetLine}
${releaseShaLine}
${expectedChannelLine}
${expectedRelayNameLine}
${gatewayExpectedLines}
env_file="\${HIVERELAY_ENV_FILE:-/etc/hiverelay/hiverelay.env}"
cd -- "$repo"
head_sha="$(git rev-parse HEAD 2>/dev/null || true)"
if [ -n "$gateway_evidence" ]; then
  # The verifier and all of its tracked imports must be the exact signed target,
  # not mutable files in a dirty checkout that merely has the right HEAD.
  index_flags="$(git -c core.fsmonitor=false ls-files -v)"
  worktree_status="$(git -c core.fsmonitor=false status --porcelain=v1 --untracked-files=all)"
  hidden_index=0
  if printf '%s\n' "$index_flags" | LC_ALL=C grep -qv '^H '; then hidden_index=1; fi
  if [ "$head_sha" != "$release_sha" ] ||
    [ -n "$worktree_status" ] || [ "$hidden_index" -ne 0 ] ||
    ! git -c core.fsmonitor=false diff --no-ext-diff --quiet "$release_sha" -- ||
    ! git -c core.fsmonitor=false diff --no-ext-diff --cached --quiet "$release_sha" --; then
    printf '%s\n' 'public gateway verifier refused: target worktree is dirty or not at the signed release' >&2
    exit 42
  fi
fi
version="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' package.json | head -n 1)"
[ -n "$version" ] && version="v$version"
updater_config=/etc/hiverelay-updater.conf
updater_launcher=/usr/local/bin/hiverelay-updater
updater_service_unit=/etc/systemd/system/hiverelay-updater.service
updater_timer_unit=/etc/systemd/system/hiverelay-updater.timer
updater_ready=false
read_updater_config_value() {
  local wanted="$1"
  /usr/bin/awk -v wanted="$wanted" '
    /^[[:space:]]*($|#)/ { next }
    {
      line = $0
      key = line
      sub(/[[:space:]]*=.*/, "", key)
      sub(/^[[:space:]]*/, "", key)
      sub(/[[:space:]]*$/, "", key)
      if (key != wanted) next
      sub(/^[^=]*=[[:space:]]*/, "", line)
      values[++count] = line
    }
    END {
      if (count != 1) exit 1
      print values[1]
    }
  ' "$updater_config"
}
strip_updater_config_quotes() {
  local value="$1"
  if [[ "$value" == \"*\" && "$value" == *\" ]]; then
    value="\${value#\"}"
    value="\${value%\"}"
  elif [[ "$value" == \'*\' && "$value" == *\' ]]; then
    value="\${value#\'}"
    value="\${value%\'}"
  fi
  printf '%s\n' "$value"
}
updater_config_equals() {
  local key="$1" expected="$2" actual
  actual="$(read_updater_config_value "$key")" || return 1
  actual="$(strip_updater_config_quotes "$actual")"
  [ "$actual" = "$expected" ]
}
installed_matches_release() {
  local source="$1" installed="$2" require_executable="\${3:-0}" expected actual
  [ -f "$installed" ] && [ ! -L "$installed" ] || return 1
  [ "$require_executable" != 1 ] || [ -x "$installed" ] || return 1
  expected="$(git rev-parse --verify "$release_sha:$source" 2>/dev/null)" || return 1
  actual="$(git hash-object --no-filters -- "$installed" 2>/dev/null)" || return 1
  [ "$actual" = "$expected" ]
}
loaded_unit_matches() {
  local unit="$1" fragment="$2" loaded dropins reload
  loaded="$(/usr/bin/systemctl show "$unit" -p FragmentPath --value 2>/dev/null)" || return 1
  dropins="$(/usr/bin/systemctl show "$unit" -p DropInPaths --value 2>/dev/null)" || return 1
  reload="$(/usr/bin/systemctl show "$unit" -p NeedDaemonReload --value 2>/dev/null)" || return 1
  [ "$loaded" = "$fragment" ] && [ -z "$dropins" ] && [ "$reload" = no ]
}
if [ -f "$updater_config" ] && [ ! -L "$updater_config" ] &&
  updater_config_equals CHANNEL "$expected_channel" &&
  updater_config_equals RELAY_NAME "$expected_relay_name" &&
  updater_config_equals REPO_DIR "$repo" &&
  installed_matches_release fleet/updater-launcher.sh "$updater_launcher" 1 &&
  installed_matches_release fleet/hiverelay-updater.service "$updater_service_unit" &&
  installed_matches_release fleet/hiverelay-updater.timer "$updater_timer_unit" &&
  loaded_unit_matches hiverelay-updater.service "$updater_service_unit" &&
  loaded_unit_matches hiverelay-updater.timer "$updater_timer_unit" &&
  /usr/bin/systemctl is-enabled --quiet hiverelay-updater.timer &&
  /usr/bin/systemctl is-active --quiet hiverelay-updater.timer &&
  /usr/bin/env -i HOME=/root PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    "$updater_launcher" --verify-only "$release_target" >/dev/null 2>&1; then
  updater_ready=true
fi
read_api_key() {
  local key
  key="$(systemctl show "$service" -p Environment 2>/dev/null | awk 'BEGIN{RS=" "} /^HIVERELAY_API_KEY=/{sub(/^HIVERELAY_API_KEY=/,""); print; exit}' || true)"
  if [ -z "$key" ] && [ -r "$env_file" ]; then
    key="$(awk -F= '/^[[:space:]]*HIVERELAY_API_KEY[[:space:]]*=/ { sub(/^[^=]*=/,""); sub(/^[[:space:]]*/,""); print; exit }' "$env_file" 2>/dev/null || true)"
  fi
  key="\${key%\"}"
  key="\${key#\"}"
  key="\${key%\'}"
  key="\${key#\'}"
  if [ -n "$key" ]; then printf '%s\n' "$key"; fi
  return 0
}
curl_with_optional_key() {
  local key="$1"
  shift
  if [ -z "$key" ]; then
    curl "$@" || return $?
    return 0
  fi
  if printf '%s' "$key" | LC_ALL=C grep -q '[[:cntrl:]]'; then
    return 2
  fi
  local header_file status
  header_file="$(mktemp)"
  chmod 600 "$header_file" 2>/dev/null || true
  printf 'Authorization: Bearer %s\n' "$key" > "$header_file"
  status=0
  curl -H "@$header_file" "$@" || status=$?
  rm -f "$header_file"
  return "$status"
}
key="$(read_api_key)"
health="$(curl_with_optional_key "$key" -fsS --max-time 10 "$api/health" 2>/dev/null || true)"
if printf '%s' "$health" | grep -q '"running":true'; then running=true; else running=false; fi
health_version="$(printf '%s' "$health" | sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
disk="$(df -h / | awk 'NR==2{print $5}')"
gateway_healthy=""
gateway_token=""
if [ -n "$gateway_evidence" ]; then
  gateway_healthy=false
  verifier="$repo/scripts/verify-public-hive-gateway-evidence.mjs"
  if [ -f "$verifier" ]; then
    gateway_token="$(node "$verifier" \
      --evidence "$gateway_evidence" \
      --release-target "$release_target" \
      --release-sha "$release_sha" \
      --require-mode fleet \
      --require-admission-profile "$required_admission_profile" \
      --expected-origin "$expected_origin" \
      --expected-connect-address "$expected_connect_address" \
      --expected-app-key "$expected_app_key" \
      --expected-path "$expected_path" \
      --expected-sha256 "$expected_sha256" \
      --expected-drive-version "$expected_drive_version" \
      --expected-peer-fingerprint256 "$expected_peer_fingerprint256" \
      --expected-nginx-sha256 "$expected_nginx_sha256" \
      --rollout-token 2>/dev/null || true)"
    if [[ "$gateway_token" =~ ^[A-Za-z0-9_-]{32,8192}$ ]]; then gateway_healthy=true; else gateway_token=""; fi
  fi
fi
printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
  "$head_sha" "$version" "$running" "$disk" "$health_version" \
  "$(printf '%s' "$health" | tr '\n\t' '  ' | cut -c1-180)" "$updater_ready" \
  "$gateway_healthy" "$gateway_token"
`
}

function validateLocalCommand (value) {
  const text = String(value || '').trim()
  if (!text) die('Invalid --ssh-command value.')
  if (hasControlChars(text)) die('Invalid --ssh-command value: control characters are not allowed.')
  return text
}

function validateLocalPath (value, label) {
  const text = String(value || '').trim()
  if (!text || text === 'default') return text
  if (hasControlChars(text)) die(`Invalid --${label} value: control characters are not allowed.`)
  if (text.length > 1024) die(`Invalid --${label} value: path is too long.`)
  return text
}

function validateLocalAbsolutePath (value, label) {
  const text = validateLocalPath(value, label)
  if (!text) return ''
  const expanded = expandHome(text)
  if (!path.isAbsolute(expanded)) die(`Invalid --${label} value: expected an absolute local path.`)
  return expanded
}

function validateRepoRelativePath (value, label) {
  const text = String(value || '').trim()
  if (!text) return ''
  if (hasControlChars(text) || text.length > 1024 || path.isAbsolute(text) || text.startsWith('-')) {
    die(`Invalid --${label} value: expected a bounded repo-relative path.`)
  }
  const normalized = path.posix.normalize(text.replaceAll('\\', '/'))
  if (normalized === '.' || normalized === '..' || normalized.startsWith('../')) {
    die(`Invalid --${label} value: path traversal is not allowed.`)
  }
  return normalized
}

function validateRemotePath (value, label) {
  const text = String(value || '').trim()
  if (!text) return ''
  if (hasControlChars(text)) die(`Invalid --${label} value: control characters are not allowed.`)
  if (text.length > 1024) die(`Invalid --${label} value: path is too long.`)
  return text
}

function validateRemoteAbsolutePath (value, label) {
  const text = validateRemotePath(value, label)
  if (text && !text.startsWith('/')) die(`Invalid --${label} value: expected an absolute path on each relay.`)
  return text
}

function assertKnownHostsFile (file) {
  const expanded = expandHome(file)
  if (!path.isAbsolute(expanded)) die('--known-hosts must resolve to an absolute local path.')
  readFleetMetadataFile(expanded, 'pinned known_hosts')
}

function validateSshUser (value) {
  const text = String(value || '').trim()
  if (!/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(text)) {
    die(`Invalid --ssh-user "${value}". Expected a local account name without SSH options.`)
  }
  return text
}

function validateServiceName (value) {
  const text = String(value || '').trim()
  if (!/^[A-Za-z0-9@_.:-]{1,128}$/.test(text) || text.startsWith('-')) {
    die(`Invalid --service "${value}". Expected a systemd service name without options.`)
  }
  return text
}

function normalizeApiBase (value) {
  const text = String(value || '').trim()
  assertPublicSafeString(text, 'fleet rollout API URL', '$.probes.api')
  let url
  try {
    url = new URL(text)
  } catch (_) {
    die(`Invalid --api "${value}". Expected an http(s) URL.`)
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    die(`Invalid --api "${value}". Expected an http(s) URL.`)
  }
  if (!url.hostname) die(`Invalid --api "${value}". Expected a hostname.`)
  if (!isLoopbackHostname(url.hostname)) {
    die(`Invalid --api "${value}". Expected a loopback URL because fleet rollout probes run on each relay over SSH.`)
  }
  if (url.search || url.hash) die(`Invalid --api "${value}". Expected a base URL without query strings or fragments.`)
  return text.replace(/\/+$/, '')
}

function isLoopbackHostname (hostname) {
  const host = String(hostname || '').toLowerCase()
  return host === 'localhost' ||
    host === '::1' ||
    host === '[::1]' ||
    host === '0:0:0:0:0:0:0:1' ||
    isLoopbackIpv4(host)
}

function isLoopbackIpv4 (host) {
  const parts = host.split('.')
  return parts.length === 4 &&
    parts[0] === '127' &&
    parts.slice(1).every((part) => /^[0-9]{1,3}$/.test(part) && Number(part) <= 255)
}

function validatePublicLabel (value, label, maxLength) {
  const text = String(value || '').trim()
  if (!text) die(`Invalid ${label}: empty values are not allowed.`)
  if (text.length > maxLength) die(`Invalid ${label}: value is too long.`)
  assertPublicSafeString(text, `fleet rollout ${label}`, '$')
  return text
}

function validateSshHost (value, label) {
  const text = String(value || '').trim()
  if (!text) die(`Invalid ${label}: empty host.`)
  if (text.length > 253) die(`Invalid ${label}: host is too long.`)
  if (
    text.startsWith('-') ||
    text.includes('@') ||
    /\s/.test(text) ||
    !/^[A-Za-z0-9._:[\]-]+$/.test(text)
  ) {
    die(`Invalid ${label}: expected a hostname, IP address, or tailnet name without SSH options.`)
  }
  assertPublicSafeString(text, 'fleet rollout relay host', '$')
  return text
}

function shellQuote (value) {
  return "'" + String(value).replace(/'/g, "'\\''") + "'"
}

function printResults (results, opts = {}) {
  const write = opts.stderr ? console.error : console.log
  write(formatRow(['relay', 'channel', 'pkg', 'live', 'head', 'target', 'health', 'disk', 'note']))
  for (const result of results) {
    const relay = result.relay
    const note = result.ok
      ? (
          resultIsGreen(result)
            ? 'ok'
            : !result.updated
                ? 'waiting-repo'
                : !result.packageVersionMatches
                    ? 'waiting-package-version'
                    : !result.runtimeVersionMatches
                        ? 'waiting-runtime-version'
                        : !result.serviceHealthy
                            ? 'waiting-health'
                            : !result.updaterReady
                                ? 'waiting-updater'
                                : !result.gatewayHealthy
                                    ? 'waiting-gateway-evidence'
                                    : 'waiting-observation-window'
        )
      : result.error
    write(formatRow([
      relay.name,
      relay.channel,
      result.version || '-',
      result.healthVersion || '-',
      shortSha(result.headSha),
      shortSha(targetSha),
      result.healthy ? 'green' : 'red',
      result.disk || '-',
      note
    ]))
  }
}

function resultIsGreen (result) {
  return resultIsRelayGreen(result) && (!gatewayEvidencePath || gatewayWindow?.complete === true)
}

function resultIsRelayGreen (result) {
  return result.updated && result.packageVersionMatches && result.healthy && result.updaterReady &&
    result.runtimeVersionMatches &&
    (!gatewayEvidencePath || result.gatewayHealthy === true)
}

function writeRolloutEvidence (status, results, error = '') {
  if (!evidenceFile) return
  assertVerifiedProbeTiming(status)
  const generatedAt = new Date().toISOString()
  const relays = results.map((result) => {
    const relay = result.relay
    const note = rolloutNote(result)
    return {
      name: relay.name,
      channel: relay.channel,
      packageVersion: result.version || '',
      healthVersion: result.healthVersion || '',
      observedAt: result.observedAt || generatedAt,
      headSha: result.headSha || '',
      targetSha,
      updated: Boolean(result.updated),
      packageVersionMatches: Boolean(result.packageVersionMatches),
      healthy: Boolean(result.healthy),
      runtimeVersionMatches: Boolean(result.runtimeVersionMatches),
      ...(gatewayEvidencePath
        ? {
            gatewayHealthy: result.gatewayHealthy === true,
            gateway: result.gateway || null
          }
        : {}),
      disk: result.disk || '',
      note,
      error: result.error || ''
    }
  })
  const evidence = {
    schemaVersion: gatewayEvidencePath ? 2 : 1,
    generatedAt,
    status,
    target: {
      tag: target,
      version: targetVersion,
      sha: targetSha,
      channel
    },
    inventory: {
      path: inventoryPath,
      sha256: inventorySha256,
      relayNames: relays.map((relay) => relay.name)
    },
    channelConfig: {
      path: channelsEvidencePath,
      sha256: channelsSha256,
      targets: channelTargets
    },
    ...(gatewayEvidencePath
      ? {
          publicGateway: {
            manifest: {
              path: gatewayManifestPath,
              sha256: gatewayManifestSha256,
              releaseTarget: gatewayRelease.releaseTarget,
              admissionProfile: gatewayRelease.admissionProfile,
              observationWindowMs: gatewayRelease.observationWindowMs,
              maxProbeGapMs: gatewayRelease.maxProbeGapMs,
              cohortNames: gatewayCohortNames
            },
            windowStateSha256: gatewayWindowStateSha256,
            window: gatewayWindow || emptyGatewayWindowSummary()
          }
        }
      : {}),
    probes: {
      timeoutMs,
      intervalMs,
      sshTimeoutMs,
      service,
      api,
      ...(gatewayEvidencePath ? { publicGatewayEvidence: true } : {})
    },
    summary: {
      total: relays.length,
      updated: relays.filter((relay) => relay.updated).length,
      packageVersionMatches: relays.filter((relay) => relay.packageVersionMatches).length,
      healthy: relays.filter((relay) => relay.healthy).length,
      runtimeVersionMatches: relays.filter((relay) => relay.runtimeVersionMatches).length,
      ...(gatewayEvidencePath
        ? { gatewayHealthy: relays.filter((relay) => relay.gatewayHealthy).length }
        : {})
    },
    relays
  }
  if (error) evidence.error = error

  assertPublicSafeValues(evidence, 'fleet rollout evidence')
  assertFleetRolloutEvidenceSchema(evidence)
  writeFileAtomicSync(path.resolve(evidenceFile), Buffer.from(JSON.stringify(evidence, null, 2) + '\n'))
}

function writeFileAtomicSync (file, bytes) {
  const absolute = path.resolve(file)
  const dir = path.dirname(absolute)
  fs.mkdirSync(dir, { recursive: true })
  const temp = path.join(dir, `.${path.basename(absolute)}.tmp-${process.pid}-${crypto.randomBytes(12).toString('hex')}`)
  let fd = null
  try {
    fd = fs.openSync(temp, 'wx', 0o600)
    fs.writeFileSync(fd, bytes)
    fs.fsyncSync(fd)
    fs.closeSync(fd)
    fd = null
    fs.renameSync(temp, absolute)
    let dirFd = null
    try {
      dirFd = fs.openSync(dir, 'r')
      fs.fsyncSync(dirFd)
    } catch (err) {
      if (!['EINVAL', 'ENOTSUP', 'EISDIR'].includes(err?.code)) throw err
    } finally {
      if (dirFd !== null) fs.closeSync(dirFd)
    }
  } finally {
    if (fd !== null) fs.closeSync(fd)
    try { fs.unlinkSync(temp) } catch (_) {}
  }
}

function assertVerifiedProbeTiming (status) {
  if (status !== 'verified') return
  requireIntegerRange('verified fleet rollout timeoutMs', timeoutMs, FLEET_ROLLOUT_TIMEOUT_MIN_MS, FLEET_ROLLOUT_TIMEOUT_MAX_MS)
  requireIntegerRange('verified fleet rollout intervalMs', intervalMs, FLEET_ROLLOUT_INTERVAL_MIN_MS, FLEET_ROLLOUT_INTERVAL_MAX_MS)
  requireIntegerRange('verified fleet rollout sshTimeoutMs', sshTimeoutMs, FLEET_ROLLOUT_SSH_TIMEOUT_MIN_MS, FLEET_ROLLOUT_SSH_TIMEOUT_MAX_MS)
}

function requireIntegerRange (label, value, min, max) {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    die(`${label} must be an integer between ${min} and ${max}`)
  }
}

function assertFleetRolloutEvidenceSchema (evidence) {
  requireOnlyKeys('fleet rollout evidence', evidence, [
    'schemaVersion',
    'generatedAt',
    'status',
    'target',
    'inventory',
    'channelConfig',
    ...(gatewayEvidencePath ? ['publicGateway'] : []),
    'probes',
    'summary',
    'relays',
    'error'
  ])
  requireOnlyKeys('fleet rollout target', evidence.target, ['tag', 'version', 'sha', 'channel'])
  requireOnlyKeys('fleet rollout inventory', evidence.inventory, ['path', 'sha256', 'relayNames'])
  requireOnlyKeys('fleet rollout channel config', evidence.channelConfig, ['path', 'sha256', 'targets'])
  requireOnlyKeys('fleet rollout channel config targets', evidence.channelConfig.targets, Object.keys(channelTargets))
  if (gatewayEvidencePath) {
    requireOnlyKeys('fleet rollout public gateway', evidence.publicGateway, ['manifest', 'windowStateSha256', 'window'])
    requireOnlyKeys('fleet rollout public gateway manifest', evidence.publicGateway.manifest, [
      'path',
      'sha256',
      'releaseTarget',
      'admissionProfile',
      'observationWindowMs',
      'maxProbeGapMs',
      'cohortNames'
    ])
    requireOnlyKeys('fleet rollout public gateway window', evidence.publicGateway.window, [
      'windowStartedAt',
      'windowEndedAt',
      'durationMs',
      'sampleCount',
      'maxGapMs',
      'relayCount',
      'complete'
    ])
  }
  requireOnlyKeys('fleet rollout probes', evidence.probes, [
    'timeoutMs',
    'intervalMs',
    'sshTimeoutMs',
    'service',
    'api',
    ...(gatewayEvidencePath ? ['publicGatewayEvidence'] : [])
  ])
  requireOnlyKeys('fleet rollout summary', evidence.summary, [
    'total',
    'updated',
    'packageVersionMatches',
    'healthy',
    'runtimeVersionMatches',
    ...(gatewayEvidencePath ? ['gatewayHealthy'] : [])
  ])
  if (Array.isArray(evidence.relays)) {
    for (const relay of evidence.relays) {
      requireOnlyKeys(`fleet rollout relay ${relay?.name || '(unnamed)'}`, relay, [
        'name',
        'channel',
        'packageVersion',
        'healthVersion',
        'observedAt',
        'headSha',
        'targetSha',
        'updated',
        'packageVersionMatches',
        'healthy',
        'runtimeVersionMatches',
        ...(gatewayEvidencePath ? ['gatewayHealthy', 'gateway'] : []),
        'disk',
        'note',
        'error'
      ])
      if (gatewayEvidencePath && relay.gateway !== null) {
        assertRolloutTokenSummarySchema(relay.gateway, `fleet rollout relay ${relay.name} gateway`)
      }
    }
  }
}

function requireOnlyKeys (label, value, allowed) {
  if (value == null || typeof value !== 'object' || Array.isArray(value)) {
    die(`${label} must be an object`)
  }
  const allowedSet = new Set(allowed)
  const extra = Object.keys(value).filter(key => !allowedSet.has(key))
  if (extra.length > 0) die(`${label} has unsupported fields: ${extra.join(', ')}`)
}

function pathForEvidence (file) {
  const rel = path.relative(repoRoot, path.resolve(file))
  if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) return path.basename(file)
  return rel
}

function sha256File (file, label) {
  return crypto.createHash('sha256').update(readFleetMetadataFile(file, label)).digest('hex')
}

function readFleetMetadataFile (file, label, encoding, maxBytes = MAX_FLEET_METADATA_BYTES) {
  const before = fs.lstatSync(file)
  if (before.isSymbolicLink()) die(`${label} file must not be a symlink: ${file}`)
  if (!before.isFile()) die(`${label} file must be a regular file: ${file}`)
  if (before.size > maxBytes) {
    die(`${label} file must be ${maxBytes} bytes or smaller: ${file} is ${before.size} bytes`)
  }
  let fd = null
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0))
    const stat = fs.fstatSync(fd)
    if (!stat.isFile() || stat.dev !== before.dev || stat.ino !== before.ino) {
      die(`${label} file changed while it was being opened: ${file}`)
    }
    if (stat.size > maxBytes) {
      die(`${label} file must be ${maxBytes} bytes or smaller: ${file} is ${stat.size} bytes`)
    }
    const value = fs.readFileSync(fd, encoding)
    const byteLength = typeof value === 'string' ? Buffer.byteLength(value) : value.byteLength
    if (byteLength > maxBytes) die(`${label} file exceeds the validation limit while reading: ${file}`)
    return value
  } finally {
    if (fd !== null) fs.closeSync(fd)
  }
}

function assertPublicSafeValues (value, label) {
  visit(value, '$')

  function visit (node, at) {
    if (node == null) return
    if (typeof node === 'string') {
      assertPublicSafeString(node, label, at)
      return
    }
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i++) visit(node[i], `${at}[${i}]`)
      return
    }
    if (typeof node === 'object') {
      for (const [key, child] of Object.entries(node)) visit(child, `${at}.${key}`)
    }
  }
}

function assertPublicSafeString (value, label, at) {
  if (hasControlChars(value)) die(`${label} must not contain control characters at ${at}`)
  for (const [pattern, name] of FORBIDDEN_PUBLIC_VALUE_PATTERNS) {
    if (pattern.test(value)) die(`${label} must not contain ${name} at ${at}`)
  }
  try {
    const url = new URL(value)
    if (url.username || url.password) die(`${label} must not expose URL credentials at ${at}`)
  } catch (_) {}
}

function hasControlChars (value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if (code <= 31 || code === 127) return true
  }
  return false
}

function rolloutNote (result) {
  if (result.ok === undefined) return 'dry-run'
  if (!result.ok) return result.error || 'probe-failed'
  if (!result.updated) return 'waiting-repo'
  if (!result.packageVersionMatches) return 'waiting-package-version'
  if (!result.runtimeVersionMatches) return 'waiting-runtime-version'
  if (!result.serviceHealthy) return 'waiting-health'
  if (!result.updaterReady) return 'waiting-updater'
  if (gatewayEvidencePath && !result.gatewayHealthy) return 'waiting-gateway-evidence'
  if (gatewayEvidencePath && !gatewayWindow?.complete) return 'waiting-observation-window'
  return 'ok'
}

function formatRow (cells) {
  const widths = [12, 9, 10, 10, 10, 10, 8, 6, 28]
  return cells.map((cell, i) => String(cell || '').slice(0, widths[i]).padEnd(widths[i])).join(' ')
}

function shortSha (sha) {
  return sha ? sha.slice(0, 8) : '-'
}

function oneLine (value) {
  return String(value).replace(/\s+/g, ' ').trim().slice(0, 180)
}

function safeProbeError (value) {
  return oneLine(redactSensitiveOutput(value))
}

function redactSensitiveOutput (value) {
  const redacted = String(value)
    .replace(/-----BEGIN [A-Z ]*(?:PRIVATE|SECRET) KEY-----[\s\S]*?-----END [A-Z ]*(?:PRIVATE|SECRET) KEY-----/g, '[redacted key block]')
    .replace(/\bAuthorization\s*:\s*[^\r\n]*/gi, '[redacted authorization header]')
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]{8,}\b/gi, '[redacted bearer token]')
    .replace(/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b/g, '[redacted GitHub token]')
    .replace(/\bgithub_pat_[A-Za-z0-9_]{20,}\b/g, '[redacted GitHub token]')
    .replace(/\bAPP_SEED=[^\s'"]+/gi, '[redacted APP_SEED]')
    .replace(/\bHIVERELAY_API_KEY=[^\s'"]+/gi, '[redacted HIVERELAY_API_KEY]')
    .replace(/\bsk-[A-Za-z0-9_-]{20,}\b/g, '[redacted API key]')
    .replace(/(\bhttps?:\/\/)([^/\s:@]+):([^@\s/]+)@/gi, '$1[redacted]@')
  return stripControlChars(redacted)
}

function stripControlChars (value) {
  let out = ''
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    out += code <= 31 || code === 127 ? ' ' : value[i]
  }
  return out
}

function hardenedGitEnv (overrides) {
  const env = { ...process.env }
  for (const name of Object.keys(env)) {
    if (UNSAFE_GIT_ENV.has(name) || /^GIT_CONFIG_(?:KEY|VALUE)_\d+$/.test(name)) delete env[name]
  }
  return { ...env, ...overrides }
}

function runLocal (cmd, args, options = {}) {
  return new Promise((resolve) => {
    const isGit = cmd === 'git'
    const childArgs = isGit ? ['--no-replace-objects', ...args] : args
    const child = spawn(isGit ? GIT_PROGRAM : cmd, childArgs, {
      cwd: options.cwd || repoRoot,
      env: isGit
        ? hardenedGitEnv({
          GIT_GRAFT_FILE: '/dev/null/hiverelay-disabled',
          GIT_NO_REPLACE_OBJECTS: '1'
        })
        : process.env,
      stdio: ['pipe', 'pipe', 'pipe']
    })
    let stdout = ''
    let stderr = ''
    let timedOut = false
    let exceededOutput = false
    const maxOutputBytes = options.maxOutputBytes || 4 * 1024 * 1024
    const timer = setTimeout(() => {
      timedOut = true
      child.kill('SIGKILL')
    }, options.timeoutMs || 30000)
    child.stdout.on('data', (chunk) => {
      if (Buffer.byteLength(stdout) + chunk.byteLength > maxOutputBytes) {
        exceededOutput = true
        child.kill('SIGKILL')
        return
      }
      stdout += chunk
    })
    child.stderr.on('data', (chunk) => {
      if (Buffer.byteLength(stderr) + chunk.byteLength > maxOutputBytes) {
        exceededOutput = true
        child.kill('SIGKILL')
        return
      }
      stderr += chunk
    })
    child.on('error', (err) => {
      clearTimeout(timer)
      resolve({ code: 127, stdout, stderr: err.message, timedOut })
    })
    child.on('close', (code) => {
      clearTimeout(timer)
      resolve({ code, stdout, stderr, timedOut, exceededOutput })
    })
    if (options.input) child.stdin.end(options.input)
    else child.stdin.end()
  })
}

function sleep (ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function die (message) {
  console.error(message)
  process.exit(1)
}
