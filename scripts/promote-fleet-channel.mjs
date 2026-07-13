#!/usr/bin/env node

import { execFile } from 'node:child_process'
import { constants as fsConstants } from 'node:fs'
import { open, rename, unlink } from 'node:fs/promises'
import { createHash, randomBytes } from 'node:crypto'
import path from 'node:path'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'
import {
  PUBLIC_HIVE_GATEWAY_RELEASE_SCHEMA,
  assertOperatorContractMatchesCohort,
  cohortEntriesForChannel,
  normalizePublicHiveGatewayReleaseManifest,
  operatorContractPathForRelay
} from './lib/public-hive-gateway-release-manifest.mjs'

const execFileAsync = promisify(execFile)
const scriptDir = path.dirname(fileURLToPath(import.meta.url))
const defaultRepoRoot = path.resolve(scriptDir, '..')
const MAX_CHANNELS_BYTES = 256 * 1024
const MAX_ALLOWED_SIGNERS_BYTES = 256 * 1024
const MAX_EVIDENCE_BYTES = 2 * 1024 * 1024
const MAX_INVENTORY_BYTES = 2 * 1024 * 1024
const MAX_GATEWAY_STATE_BYTES = 16 * 1024 * 1024
const MAX_GIT_OUTPUT_BYTES = 2 * 1024 * 1024
const RELEASE_TAG_PATTERN = /^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/
const PROMOTION_MAX_AGE_MS = 30 * 60 * 1000
const PROMOTION_MAX_FUTURE_SKEW_MS = 5 * 60 * 1000
const GATEWAY_WINDOW_STATE_SCHEMA = 'hiverelay-public-gateway-window-state-v1'
const GATEWAY_TOKEN_SCHEMA = 'hiverelay-public-gateway-evidence-verification-v2'
const CANONICAL_GATEWAY_MANIFEST_PATH = 'fleet/public-hive-gateway-release.json'
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

const usage = `
Usage:
  node scripts/promote-fleet-channel.mjs --channel <canary|stable> --target <vX.Y.Z> [options]

Options:
  --channel <canary|stable>   Update exactly one fleet channel
  --target <vX.Y.Z>           Existing trusted, signed annotated release tag
  --canary-evidence <path>    Verified canary rollout evidence (required for stable)
  --require-public-gateway    Require gateway evidence for a legacy release
                              (an enabled canonical tagged manifest forces this automatically)
  --gateway-manifest <path>   Repo-relative manifest in the verified release tag
  --gateway-window-state <p>  Resumable 24-hour observation state from rollout checks
  --relays <path>             Current full fleet inventory (gateway promotion)
  --channels <path>           Channel file (default: fleet/channels.json)
  --allowed-signers <path>    OpenSSH allowed_signers file (default: fleet/allowed-signers)
  --repo <path>               Git repository containing the release tag
  --dry-run                   Validate and report without writing any file

This tool never commits, pushes, deploys, or modifies more than the named channel.`

try {
  await main()
} catch (err) {
  console.error(`fleet promotion: ${safeError(err)}`)
  process.exitCode = 1
}

async function main () {
  const args = parseArgs(process.argv.slice(2))
  if (args.help) {
    console.log(usage.trim())
    return
  }

  const channel = args.channel
  const target = args.target
  if (channel !== 'canary' && channel !== 'stable') {
    throw new Error('--channel must be exactly canary or stable')
  }
  if (!RELEASE_TAG_PATTERN.test(target || '')) {
    throw new Error('--target must be an immutable release tag like v1.2.3')
  }
  if (channel === 'stable' && !args.canaryEvidence) {
    throw new Error('--canary-evidence is required before stable promotion')
  }
  if (args.requirePublicGateway && channel !== 'stable') {
    throw new Error('--require-public-gateway is valid only for stable promotion')
  }

  const repoRoot = path.resolve(args.repo || defaultRepoRoot)
  const channelsPath = path.resolve(args.channels || path.join(repoRoot, 'fleet', 'channels.json'))
  const allowedSignersPath = path.resolve(args.allowedSigners || path.join(repoRoot, 'fleet', 'allowed-signers'))
  const evidencePath = args.canaryEvidence ? path.resolve(args.canaryEvidence) : null
  const requestedGatewayManifestPath = args.gatewayManifest
    ? validateRepoRelativePath(args.gatewayManifest, 'gateway-manifest')
    : null
  const gatewayWindowStatePath = args.gatewayWindowState ? path.resolve(args.gatewayWindowState) : null
  const relaysPath = path.resolve(args.relays || path.join(repoRoot, 'fleet', 'relays.json'))

  const channelsFile = await readBoundedRegularFile(channelsPath, 'fleet channels', MAX_CHANNELS_BYTES)
  const channels = parseJsonObject(channelsFile.buffer, 'fleet channels')
  requireChannelTarget(channels, 'canary')
  requireChannelTarget(channels, 'stable')

  await readBoundedRegularFile(allowedSignersPath, 'allowed signers', MAX_ALLOWED_SIGNERS_BYTES)
  const release = await verifyReleaseTag(repoRoot, target, allowedSignersPath)
  const channelsSha256 = sha256(channelsFile.buffer)

  // The signed tag, not a caller-controlled flag, decides whether gateway
  // promotion gates are mandatory. A missing or explicitly disabled canonical
  // manifest preserves the legacy channel flow. Any malformed canonical
  // manifest fails closed so changing its shape cannot become an opt-out.
  const taggedGateway = await readCanonicalGatewayRelease(repoRoot, release.commitSha, target)
  const taggedGatewayEnabled = taggedGateway?.enabled === true
  const publicGatewayRequired = taggedGatewayEnabled || args.requirePublicGateway === true
  let gatewayManifestPath = null

  if (taggedGatewayEnabled) {
    if (requestedGatewayManifestPath && requestedGatewayManifestPath !== CANONICAL_GATEWAY_MANIFEST_PATH) {
      throw new Error(`enabled tagged public gateway releases must use ${CANONICAL_GATEWAY_MANIFEST_PATH}`)
    }
    gatewayManifestPath = CANONICAL_GATEWAY_MANIFEST_PATH
  } else if (args.requirePublicGateway) {
    if (!requestedGatewayManifestPath) {
      throw new Error('--gateway-manifest is required with --require-public-gateway for a legacy release')
    }
    gatewayManifestPath = requestedGatewayManifestPath
  } else if (requestedGatewayManifestPath || gatewayWindowStatePath) {
    throw new Error('--gateway-manifest and --gateway-window-state require --require-public-gateway or an enabled canonical tagged manifest')
  }

  if (publicGatewayRequired && channel === 'stable' && !gatewayWindowStatePath) {
    throw new Error('--gateway-window-state is required for an enabled public gateway stable promotion')
  }
  if (publicGatewayRequired && channel === 'canary' && gatewayWindowStatePath) {
    throw new Error('--gateway-window-state is valid only for stable public gateway promotion')
  }

  let publicGatewayExpected = null
  if (publicGatewayRequired) {
    const manifestFile = taggedGatewayEnabled
      ? taggedGateway.file
      : await readTaggedFile(repoRoot, release.commitSha, gatewayManifestPath,
        'public gateway release manifest')
    const manifest = taggedGatewayEnabled
      ? taggedGateway.manifest
      : parseReleaseManifest(manifestFile.buffer, target)
    const inventoryFile = await readBoundedRegularFile(relaysPath, 'fleet inventory', MAX_INVENTORY_BYTES)
    const inventory = parseFleetInventory(inventoryFile.buffer)
    const canaryCohort = cohortEntriesForChannel(manifest, 'canary')
    if (canaryCohort.length === 0) {
      throw new Error('enabled public gateway release manifest must contain a nonempty canary cohort')
    }
    assertFullInventoryCohort(inventory, manifest.cohort)
    const operatorContracts = []
    for (const entry of manifest.cohort) {
      if (entry.deploymentProfile !== 'public-t1-gateway') continue
      const contractPath = operatorContractPathForRelay(entry.relay)
      const contractFile = await readTaggedFile(repoRoot, release.commitSha, contractPath,
        `public-t1-gateway operator contract for ${entry.relay}`)
      const contractValue = parseJsonObject(contractFile.buffer,
        `public-t1-gateway operator contract for ${entry.relay}`)
      const binding = assertOperatorContractMatchesCohort(contractValue, manifest, entry)
      operatorContracts.push({ relay: entry.relay, path: contractPath, sha256: binding.digest })
    }
    publicGatewayExpected = {
      manifestPath: gatewayManifestPath,
      manifest,
      manifestSha256: sha256(manifestFile.buffer),
      canaryCohort,
      inventorySha256: sha256(inventoryFile.buffer),
      inventoryPath: relaysPath,
      operatorContracts
    }
    if (channel === 'stable') {
      const stateFile = await readBoundedRegularFile(gatewayWindowStatePath,
        'public gateway observation state', MAX_GATEWAY_STATE_BYTES)
      const state = parseJsonObject(stateFile.buffer, 'public gateway observation state')
      const window = inspectGatewayWindowState(state, {
        target,
        targetSha: release.commitSha,
        manifest,
        manifestSha256: sha256(manifestFile.buffer),
        cohortNames: canaryCohort.map(entry => entry.relay),
        nowMs: Date.now()
      })
      publicGatewayExpected.windowStateSha256 = sha256(stateFile.buffer)
      publicGatewayExpected.window = window
    }
  }

  let canaryEvidence = null
  if (channel === 'stable') {
    const evidenceFile = await readBoundedRegularFile(evidencePath, 'canary rollout evidence', MAX_EVIDENCE_BYTES)
    const evidence = parseJsonObject(evidenceFile.buffer, 'canary rollout evidence')
    canaryEvidence = inspectCanaryEvidence(evidence, {
      target,
      targetSha: release.commitSha,
      channelsSha256,
      path: evidencePath,
      evidenceSha256: sha256(evidenceFile.buffer),
      requirePublicGateway: publicGatewayRequired,
      publicGateway: publicGatewayExpected,
      nowMs: Date.now()
    })
  }

  const previousTarget = channels[channel]
  const wouldChange = previousTarget !== target
  const result = {
    schema: 'hiverelay-fleet-channel-promotion-v1',
    status: args.dryRun ? 'dry-run' : (wouldChange ? 'updated' : 'unchanged'),
    channel,
    previousTarget,
    target,
    tagObjectSha: release.tagObjectSha,
    targetSha: release.commitSha,
    channelsPath,
    wouldChange,
    publicGatewayRequired,
    operatorContracts: publicGatewayExpected?.operatorContracts || [],
    canaryEvidence
  }

  if (!args.dryRun && wouldChange) {
    channels[channel] = target
    const contents = Buffer.from(JSON.stringify(channels, null, 2) + '\n')
    await assertTagStillImmutable(repoRoot, target, release)
    await writeChannelsAtomic(channelsPath, contents, channelsFile)
  }

  console.log(JSON.stringify(result, null, 2))
}

function parseArgs (argv) {
  const out = {}
  const valueArgs = new Set([
    'channel',
    'target',
    'canary-evidence',
    'channels',
    'allowed-signers',
    'repo',
    'gateway-manifest',
    'gateway-window-state',
    'relays'
  ])
  const booleanArgs = new Set(['dry-run', 'require-public-gateway', 'help'])
  const seen = new Set()

  for (let i = 0; i < argv.length; i++) {
    const raw = argv[i]
    if (raw === '-h') {
      if (seen.has('help')) throw new Error('duplicate --help')
      seen.add('help')
      out.help = true
      continue
    }
    if (!raw.startsWith('--')) throw new Error(`unexpected positional argument ${JSON.stringify(raw)}`)
    const name = raw.slice(2)
    if (!valueArgs.has(name) && !booleanArgs.has(name)) throw new Error(`unknown option --${name}`)
    if (seen.has(name)) throw new Error(`duplicate option --${name}`)
    seen.add(name)
    const key = camel(name)
    if (booleanArgs.has(name)) {
      out[key] = true
      continue
    }
    const value = argv[++i]
    if (!value || value.startsWith('--')) throw new Error(`missing value for --${name}`)
    out[key] = value
  }
  return out
}

function camel (value) {
  return value.replace(/-([a-z])/g, (_, char) => char.toUpperCase())
}

async function verifyReleaseTag (repoRoot, target, allowedSignersPath) {
  const tagRef = `refs/tags/${target}`
  const type = (await git(repoRoot, ['cat-file', '-t', tagRef], `release tag ${target} does not exist`)).stdout.trim()
  if (type !== 'tag') throw new Error(`release tag ${target} must be annotated and signed; lightweight tags are refused`)

  const tagObjectSha = (await git(repoRoot, ['rev-parse', '--verify', `${tagRef}^{tag}`],
    `cannot resolve annotated tag ${target}`)).stdout.trim().toLowerCase()
  requireGitObjectId(tagObjectSha, 'tag object SHA')

  const verified = await git(repoRoot, [
    '-c', 'gpg.format=ssh',
    '-c', `gpg.ssh.allowedSignersFile=${allowedSignersPath}`,
    '-c', `gpg.ssh.program=${SSH_KEYGEN_PROGRAM}`,
    'verify-tag', '--raw', target
  ], `release tag ${target} is not signed by a trusted fleet signer`)
  const verificationOutput = `${verified.stdout}\n${verified.stderr}`
  if (!/GOODSIG|TRUST_(?:FULLY|ULTIMATE)|Good[^\r\n]*signature/i.test(verificationOutput)) {
    throw new Error(`release tag ${target} did not produce a trusted signature result`)
  }

  const commitSha = (await git(repoRoot, ['rev-parse', '--verify', `${tagRef}^{commit}`],
    `cannot resolve release commit for ${target}`)).stdout.trim().toLowerCase()
  requireGitObjectId(commitSha, 'release commit SHA')

  const packageResult = await git(repoRoot, ['show', `${commitSha}:package.json`],
    `release tag ${target} does not contain package.json`)
  if (Buffer.byteLength(packageResult.stdout) > MAX_CHANNELS_BYTES) {
    throw new Error(`package.json at ${target} exceeds the validation limit`)
  }
  const packageJson = parseJsonObject(Buffer.from(packageResult.stdout), `package.json at ${target}`)
  if (packageJson.version !== target.slice(1)) {
    throw new Error(`release tag ${target} does not match package.json version ${JSON.stringify(packageJson.version)}`)
  }

  return { tagObjectSha, commitSha }
}

async function assertTagStillImmutable (repoRoot, target, expected) {
  const tagRef = `refs/tags/${target}`
  const tagObjectSha = (await git(repoRoot, ['rev-parse', '--verify', `${tagRef}^{tag}`],
    `release tag ${target} disappeared before promotion`)).stdout.trim().toLowerCase()
  const commitSha = (await git(repoRoot, ['rev-parse', '--verify', `${tagRef}^{commit}`],
    `release tag ${target} became invalid before promotion`)).stdout.trim().toLowerCase()
  if (tagObjectSha !== expected.tagObjectSha || commitSha !== expected.commitSha) {
    throw new Error(`release tag ${target} changed during validation; refusing stale promotion`)
  }
}

async function readTaggedFile (repoRoot, commitSha, repoRelativePath, label) {
  const result = await git(repoRoot, ['show', `${commitSha}:${repoRelativePath}`],
    `${label} ${repoRelativePath} is missing from the verified release commit`)
  const buffer = Buffer.from(result.stdout)
  if (buffer.byteLength > MAX_GIT_OUTPUT_BYTES) throw new Error(`${label} exceeds the validation limit`)
  return { buffer }
}

async function readCanonicalGatewayRelease (repoRoot, commitSha, target) {
  const file = await readTaggedFileIfPresent(repoRoot, commitSha, CANONICAL_GATEWAY_MANIFEST_PATH,
    'canonical public gateway release manifest')
  if (!file) return null

  const value = parseJsonObject(file.buffer, 'canonical public gateway release manifest')
  if (value.schema !== PUBLIC_HIVE_GATEWAY_RELEASE_SCHEMA || typeof value.enabled !== 'boolean') {
    throw new Error('canonical public gateway release manifest has an invalid release-control schema')
  }
  if (value.enabled !== true) return { enabled: false, file, manifest: null }

  return {
    enabled: true,
    file,
    manifest: normalizeReleaseManifest(value, target)
  }
}

async function readTaggedFileIfPresent (repoRoot, commitSha, repoRelativePath, label) {
  try {
    const result = await execFileAsync(GIT_PROGRAM, [
      '--no-replace-objects', '-C', repoRoot, 'show', `${commitSha}:${repoRelativePath}`
    ], {
      encoding: 'utf8',
      env: hardenedGitEnv({
        GIT_GRAFT_FILE: '/dev/null/hiverelay-disabled',
        GIT_NO_REPLACE_OBJECTS: '1'
      }),
      maxBuffer: MAX_GIT_OUTPUT_BYTES,
      timeout: 15000
    })
    const buffer = Buffer.from(result.stdout)
    if (buffer.byteLength > MAX_GIT_OUTPUT_BYTES) throw new Error(`${label} exceeds the validation limit`)
    return { buffer }
  } catch (err) {
    // The commit is already verified above and the path is a fixed canonical
    // constant, so git's ordinary missing-path exit preserves legacy releases.
    // Timeouts, output bounds, and process failures remain fatal.
    const diagnostic = `${err?.stdout || ''}\n${err?.stderr || ''}`
    if (err?.code === 128 && err?.killed !== true &&
        /\bpath\s+.+\s+(?:does not exist in|exists on disk, but not in)\s+/i.test(diagnostic)) return null
    if (err?.message?.startsWith(label)) throw err
    throw new Error(`${label} could not be read from the verified release commit`)
  }
}

function validateRepoRelativePath (value, label) {
  const text = String(value || '')
  if (!text || text.length > 1024 || hasControlChars(text) || path.isAbsolute(text) || text.startsWith('-')) {
    throw new Error(`--${label} must be a bounded repo-relative path`)
  }
  const normalized = path.posix.normalize(text.replaceAll('\\', '/'))
  if (normalized === '.' || normalized === '..' || normalized.startsWith('../')) {
    throw new Error(`--${label} must not traverse outside the release commit`)
  }
  return normalized
}

function parseReleaseManifest (buffer, target) {
  const value = parseJsonObject(buffer, 'public gateway release manifest')
  return normalizeReleaseManifest(value, target)
}

function normalizeReleaseManifest (value, target) {
  try {
    return normalizePublicHiveGatewayReleaseManifest(value, {
      releaseTarget: target,
      requirePublicT1: true
    })
  } catch (err) {
    throw new Error(`public gateway release manifest is invalid: ${safeError(err)}`)
  }
}

function parseFleetInventory (buffer) {
  const inventory = parseJsonObject(buffer, 'fleet inventory')
  if (!Array.isArray(inventory.relays)) throw new Error('fleet inventory must contain a relays array')
  const relays = []
  const names = new Set()
  for (const entry of inventory.relays) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry) ||
        !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(entry.name || '') ||
        (entry.channel !== 'canary' && entry.channel !== 'stable')) {
      throw new Error('fleet inventory contains an invalid relay identity or channel')
    }
    if (names.has(entry.name)) throw new Error(`fleet inventory repeats relay ${entry.name}`)
    names.add(entry.name)
    relays.push({ name: entry.name, channel: entry.channel })
  }
  return relays
}

function assertFullInventoryCohort (inventory, cohort) {
  const inventoryIdentities = new Set(inventory.map(entry => `${entry.channel}:${entry.name}`))
  for (const entry of cohort) {
    if (!inventoryIdentities.has(`${entry.channel}:${entry.relay}`)) {
      throw new Error(`current full fleet inventory does not contain signed gateway cohort relay ${entry.relay} on ${entry.channel}`)
    }
  }
}

async function git (repoRoot, args, failureMessage) {
  try {
    return await execFileAsync(GIT_PROGRAM, ['--no-replace-objects', '-C', repoRoot, ...args], {
      encoding: 'utf8',
      env: hardenedGitEnv({
        GIT_GRAFT_FILE: '/dev/null/hiverelay-disabled',
        GIT_NO_REPLACE_OBJECTS: '1'
      }),
      maxBuffer: MAX_GIT_OUTPUT_BYTES,
      timeout: 15000
    })
  } catch {
    throw new Error(failureMessage)
  }
}

function inspectCanaryEvidence (evidence, expected) {
  requireOnlyKeys('canary evidence', evidence, [
    'schemaVersion',
    'generatedAt',
    'status',
    'target',
    'inventory',
    'channelConfig',
    'publicGateway',
    'probes',
    'summary',
    'relays',
    'error'
  ])
  if ((evidence.schemaVersion !== 1 && evidence.schemaVersion !== 2) || evidence.status !== 'verified') {
    throw new Error('canary evidence must be schemaVersion 1 or 2 with verified pass status')
  }
  requireFreshTimestamp(evidence.generatedAt, 'canary evidence generatedAt', expected.nowMs)
  if (!evidence.target || evidence.target.tag !== expected.target ||
      evidence.target.version !== expected.target.slice(1) || evidence.target.channel !== 'canary') {
    throw new Error(`canary evidence must target ${expected.target} on channel canary`)
  }
  if (String(evidence.target.sha || '').toLowerCase() !== expected.targetSha) {
    throw new Error(`canary evidence commit does not match the signed ${expected.target} tag`)
  }
  if (!evidence.channelConfig || evidence.channelConfig.sha256 !== expected.channelsSha256 ||
      evidence.channelConfig.targets?.canary !== expected.target) {
    throw new Error('canary evidence was not produced from the current channel configuration')
  }

  const relays = evidence.relays
  const summary = evidence.summary
  if (!Array.isArray(relays) || !summary || !Number.isSafeInteger(summary.total) ||
      summary.total < 1 || relays.length !== summary.total) {
    throw new Error('canary evidence must contain at least one complete relay result')
  }
  for (const field of ['updated', 'packageVersionMatches', 'healthy', 'runtimeVersionMatches']) {
    if (summary[field] !== summary.total) throw new Error(`canary evidence summary ${field} is not fully green`)
  }
  for (const relay of relays) {
    requireOnlyKeys(`canary relay ${relay?.name || '(unnamed)'}`, relay, [
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
      'gatewayHealthy',
      'gateway',
      'disk',
      'note',
      'error'
    ])
    requireFreshTimestamp(relay?.observedAt, `canary relay ${relay?.name || '(unnamed)'} observedAt`, expected.nowMs)
    if (!relay || relay.channel !== 'canary' || relay.headSha?.toLowerCase() !== expected.targetSha ||
        relay.packageVersion !== expected.target || relay.healthVersion !== expected.target.slice(1) ||
        relay.updated !== true || relay.packageVersionMatches !== true || relay.healthy !== true ||
        relay.runtimeVersionMatches !== true) {
      throw new Error('canary evidence contains a relay that did not pass the exact target')
    }
  }

  let publicGateway = null
  if (expected.requirePublicGateway) {
    const expectedGateway = expected.publicGateway
    if (!expectedGateway) throw new Error('public gateway promotion expectations are missing')
    if (evidence.schemaVersion !== 2 || evidence.probes?.publicGatewayEvidence !== true) {
      throw new Error('canary evidence does not prove the public gateway evidence gate was enabled')
    }
    if (summary.gatewayHealthy !== summary.total) {
      throw new Error('canary evidence summary gatewayHealthy is not fully green')
    }
    const cohortNames = expectedGateway.canaryCohort.map(entry => entry.relay)
    if (!evidence.inventory || evidence.inventory.sha256 !== expectedGateway.inventorySha256 ||
        !sameStringArray(evidence.inventory.relayNames, cohortNames)) {
      throw new Error('canary evidence does not bind the current full inventory digest and exact signed cohort names')
    }
    const publicEvidence = evidence.publicGateway
    requireOnlyKeys('canary public gateway evidence', publicEvidence, ['manifest', 'windowStateSha256', 'window'])
    requireOnlyKeys('canary public gateway manifest binding', publicEvidence.manifest, [
      'path',
      'sha256',
      'releaseTarget',
      'admissionProfile',
      'observationWindowMs',
      'maxProbeGapMs',
      'cohortNames'
    ])
    if (!publicEvidence || !publicEvidence.manifest ||
        publicEvidence.manifest.path !== expectedGateway.manifestPath ||
        publicEvidence.manifest.sha256 !== expectedGateway.manifestSha256 ||
        publicEvidence.manifest.releaseTarget !== expected.target ||
        publicEvidence.manifest.admissionProfile !== expectedGateway.manifest.admissionProfile ||
        publicEvidence.manifest.observationWindowMs !== expectedGateway.manifest.observationWindowMs ||
        publicEvidence.manifest.maxProbeGapMs !== expectedGateway.manifest.maxProbeGapMs ||
        !sameStringArray(publicEvidence.manifest.cohortNames, cohortNames)) {
      throw new Error('canary evidence public gateway manifest binding is stale or drifted')
    }
    if (publicEvidence.windowStateSha256 !== expectedGateway.windowStateSha256 ||
        !sameGatewayWindowSummary(publicEvidence.window, expectedGateway.window.summary) ||
        publicEvidence.window.complete !== true) {
      throw new Error('canary evidence does not prove the complete signed public gateway observation window')
    }
    if (!sameStringArray(relays.map(relay => relay.name), cohortNames)) {
      throw new Error('canary evidence relay identities do not exactly match the signed gateway cohort')
    }
    const entries = new Map(expectedGateway.canaryCohort.map(entry => [entry.relay, entry]))
    for (const relay of relays) {
      if (relay.gatewayHealthy !== true || !relay.gateway) {
        throw new Error('canary evidence contains a relay without verified public gateway evidence')
      }
      inspectGatewayToken(relay.gateway, entries.get(relay.name), expected, expectedGateway.manifest)
      const latest = expectedGateway.window.latestByRelay.get(relay.name)
      if (!latest || relay.gateway.evidenceSha256 !== latest.evidenceSha256 ||
          relay.gateway.probeObservedAt !== latest.observedAt) {
        throw new Error(`canary gateway evidence for ${relay.name} is not the latest continuous-window sample`)
      }
      requireFreshTimestamp(relay.gateway.checkedAt, `canary gateway ${relay.name} checkedAt`, expected.nowMs)
      requireFreshTimestamp(relay.gateway.probeObservedAt, `canary gateway ${relay.name} probeObservedAt`, expected.nowMs)
    }
    publicGateway = {
      status: 'verified',
      relayCount: summary.total,
      manifestSha256: expectedGateway.manifestSha256,
      inventorySha256: expectedGateway.inventorySha256,
      cohortNames,
      admissionProfile: expectedGateway.manifest.admissionProfile,
      window: expectedGateway.window.summary
    }
  }

  return {
    path: expected.path,
    sha256: expected.evidenceSha256,
    generatedAt: evidence.generatedAt,
    relayCount: summary.total,
    status: evidence.status,
    publicGateway
  }
}

function inspectGatewayWindowState (state, expected) {
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
  if (state.schema !== GATEWAY_WINDOW_STATE_SCHEMA || state.releaseTarget !== expected.target ||
      state.releaseSha !== expected.targetSha || state.channel !== 'canary' ||
      state.manifestSha256 !== expected.manifestSha256 ||
      state.observationWindowMs !== expected.manifest.observationWindowMs ||
      state.maxProbeGapMs !== expected.manifest.maxProbeGapMs ||
      !sameStringArray(state.cohortNames, expected.cohortNames)) {
    throw new Error('public gateway observation state is not bound to the verified release manifest and canary cohort')
  }
  if (!Array.isArray(state.relays) || state.relays.length !== expected.cohortNames.length) {
    throw new Error('public gateway observation state does not contain the exact signed canary cohort')
  }
  let relayWindowStartedMs = -1
  let relayWindowEndedMs = Number.MAX_SAFE_INTEGER
  let controllerWindowStartedMs = -1
  let controllerWindowEndedMs = Number.MAX_SAFE_INTEGER
  let sampleCount = 0
  let maxGapMs = 0
  const latestByRelay = new Map()
  for (let i = 0; i < state.relays.length; i++) {
    const relay = state.relays[i]
    requireOnlyKeys(`public gateway observation state relay[${i}]`, relay, ['name', 'samples'])
    if (relay.name !== expected.cohortNames[i] || !Array.isArray(relay.samples) || relay.samples.length < 2 ||
        relay.samples.length > 20000) {
      throw new Error('public gateway observation state requires multiple bounded samples for every signed relay')
    }
    let previousObservedMs = -1
    let previousCollectedMs = -1
    const digests = new Set()
    for (let j = 0; j < relay.samples.length; j++) {
      const sample = relay.samples[j]
      requireOnlyKeys(`public gateway observation state ${relay.name} sample[${j}]`, sample,
        ['observedAt', 'collectedAt', 'evidenceSha256'])
      const observedMs = parseIsoTimestamp(sample.observedAt,
        `public gateway observation state ${relay.name} sample observedAt`)
      const collectedMs = parseIsoTimestamp(sample.collectedAt,
        `public gateway observation state ${relay.name} sample collectedAt`)
      if (collectedMs > expected.nowMs + PROMOTION_MAX_FUTURE_SKEW_MS) {
        throw new Error('public gateway observation state contains a controller timestamp too far in the future')
      }
      if (observedMs > collectedMs + PROMOTION_MAX_FUTURE_SKEW_MS ||
          collectedMs - observedMs > expected.manifest.maxProbeGapMs) {
        throw new Error('public gateway observation state contains a probe timestamp that was not fresh at controller collection')
      }
      if (observedMs <= previousObservedMs || collectedMs <= previousCollectedMs ||
          !/^[a-f0-9]{64}$/.test(sample.evidenceSha256 || '') ||
          digests.has(sample.evidenceSha256)) {
        throw new Error('public gateway observation state samples must have increasing probe/controller timestamps and unique valid digests')
      }
      if (previousObservedMs >= 0) {
        const observedGap = observedMs - previousObservedMs
        const controllerGap = collectedMs - previousCollectedMs
        if (observedGap > expected.manifest.maxProbeGapMs || controllerGap > expected.manifest.maxProbeGapMs) {
          throw new Error('public gateway observation state contains an unobserved gap larger than the signed manifest allows')
        }
        maxGapMs = Math.max(maxGapMs, observedGap, controllerGap)
      }
      previousObservedMs = observedMs
      previousCollectedMs = collectedMs
      digests.add(sample.evidenceSha256)
    }
    const first = relay.samples[0]
    const last = relay.samples.at(-1)
    const firstObservedMs = parseIsoTimestamp(first.observedAt, 'gateway relay window start')
    const lastObservedMs = parseIsoTimestamp(last.observedAt, 'gateway relay window end')
    const firstCollectedMs = parseIsoTimestamp(first.collectedAt, 'gateway controller window start')
    const lastCollectedMs = parseIsoTimestamp(last.collectedAt, 'gateway controller window end')
    relayWindowStartedMs = Math.max(relayWindowStartedMs, firstObservedMs)
    relayWindowEndedMs = Math.min(relayWindowEndedMs, lastObservedMs)
    controllerWindowStartedMs = Math.max(controllerWindowStartedMs, firstCollectedMs)
    controllerWindowEndedMs = Math.min(controllerWindowEndedMs, lastCollectedMs)
    if (lastCollectedMs > expected.nowMs + PROMOTION_MAX_FUTURE_SKEW_MS ||
        expected.nowMs - lastCollectedMs > expected.manifest.maxProbeGapMs ||
        lastObservedMs > expected.nowMs + PROMOTION_MAX_FUTURE_SKEW_MS ||
        expected.nowMs - lastObservedMs > expected.manifest.maxProbeGapMs) {
      throw new Error(`public gateway observation state ${relay.name} latest relay/controller sample is not fresh`)
    }
    sampleCount += relay.samples.length
    latestByRelay.set(relay.name, last)
  }
  const hasRelayWindow = relayWindowEndedMs >= relayWindowStartedMs
  const hasControllerWindow = controllerWindowEndedMs >= controllerWindowStartedMs
  const relayDurationMs = hasRelayWindow ? relayWindowEndedMs - relayWindowStartedMs : 0
  const controllerDurationMs = hasControllerWindow ? controllerWindowEndedMs - controllerWindowStartedMs : 0
  const durationMs = Math.min(relayDurationMs, controllerDurationMs)
  const summary = {
    windowStartedAt: new Date(controllerWindowStartedMs).toISOString(),
    windowEndedAt: new Date(controllerWindowEndedMs).toISOString(),
    durationMs,
    sampleCount,
    maxGapMs,
    relayCount: state.relays.length,
    complete: hasRelayWindow && hasControllerWindow &&
      relayDurationMs >= expected.manifest.observationWindowMs &&
      controllerDurationMs >= expected.manifest.observationWindowMs &&
      maxGapMs <= expected.manifest.maxProbeGapMs
  }
  if (!summary.complete) {
    throw new Error('public gateway observation state has not completed the signed 24-hour continuity window')
  }
  return { summary, latestByRelay }
}

function inspectGatewayToken (token, entry, expected, manifest) {
  requireOnlyKeys(`canary gateway token ${entry?.relay || '(unknown)'}`, token, [
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
  if (!entry || token.schema !== GATEWAY_TOKEN_SCHEMA || token.status !== 'verified' || token.mode !== 'fleet' ||
      token.admissionProfile !== manifest.admissionProfile || token.releaseTarget !== expected.target ||
      String(token.releaseSha || '').toLowerCase() !== expected.targetSha ||
      token.physicalEnforcementRequired !== true ||
      typeof token.publicSuffixReady !== 'boolean' || !/^[a-f0-9]{64}$/.test(token.evidenceSha256 || '') ||
      (token.tlsProtocol !== 'TLSv1.2' && token.tlsProtocol !== 'TLSv1.3')) {
    throw new Error('canary gateway token does not prove the exact non-transitional fleet release posture')
  }
  const bindings = [
    ['origin', entry.origin],
    ['connectAddress', entry.connectAddress],
    ['appKey', entry.appKey],
    ['path', entry.path],
    ['contentSha256', entry.contentSha256],
    ['driveVersion', entry.driveVersion],
    ['peerFingerprint256', entry.peerFingerprint256],
    ['nginxSha256', entry.nginxConfigSha256]
  ]
  for (const [name, wanted] of bindings) {
    if (token[name] !== wanted) throw new Error(`canary gateway token ${name} drifted from the signed manifest`)
  }
  requireOnlyKeys(`canary gateway token ${entry.relay} checks`, token.checks, GATEWAY_CHECK_NAMES)
  for (const name of GATEWAY_CHECK_NAMES) {
    if (token.checks[name] !== true) throw new Error(`canary gateway token check ${name} is not green`)
  }
}

function sameGatewayWindowSummary (actual, expected) {
  if (!actual || typeof actual !== 'object' || Array.isArray(actual)) return false
  requireOnlyKeys('canary public gateway window summary', actual, [
    'windowStartedAt',
    'windowEndedAt',
    'durationMs',
    'sampleCount',
    'maxGapMs',
    'relayCount',
    'complete'
  ])
  return Object.keys(expected).every(name => actual[name] === expected[name])
}

function requireFreshTimestamp (value, label, nowMs) {
  const timestamp = parseIsoTimestamp(value, label)
  if (timestamp > nowMs + PROMOTION_MAX_FUTURE_SKEW_MS) {
    throw new Error(`${label} is more than five minutes in the future`)
  }
  if (nowMs - timestamp > PROMOTION_MAX_AGE_MS) {
    throw new Error(`${label} is older than 30 minutes`)
  }
  return timestamp
}

function parseIsoTimestamp (value, label) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) {
    throw new Error(`${label} must be a canonical ISO timestamp`)
  }
  const timestamp = Date.parse(value)
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
    throw new Error(`${label} is not a valid timestamp`)
  }
  return timestamp
}

function requireOnlyKeys (label, value, allowed) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`)
  const allowedSet = new Set(allowed)
  const unknown = Object.keys(value).filter(name => !allowedSet.has(name))
  if (unknown.length) throw new Error(`${label} has unsupported fields: ${unknown.join(', ')}`)
}

function sameStringArray (actual, expected) {
  return Array.isArray(actual) && actual.length === expected.length &&
    actual.every((value, index) => value === expected[index])
}

async function readBoundedRegularFile (file, label, maxBytes) {
  let handle
  try {
    const noFollow = fsConstants.O_NOFOLLOW || 0
    handle = await open(file, fsConstants.O_RDONLY | noFollow)
    const stat = await handle.stat()
    if (!stat.isFile() || stat.size > maxBytes) throw new Error(`${label} must be a bounded regular file`)
    const buffer = await handle.readFile()
    if (buffer.byteLength > maxBytes) throw new Error(`${label} exceeds the validation limit`)
    return { buffer, mode: stat.mode & 0o777 }
  } catch (err) {
    if (err?.message?.startsWith(label)) throw err
    throw new Error(`${label} must be a readable, non-symlink regular file`)
  } finally {
    await handle?.close().catch(() => {})
  }
}

function parseJsonObject (buffer, label) {
  let value
  try {
    value = JSON.parse(buffer.toString('utf8'))
  } catch {
    throw new Error(`${label} is not valid JSON`)
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be a JSON object`)
  return value
}

function requireChannelTarget (channels, channel) {
  if (!RELEASE_TAG_PATTERN.test(channels[channel] || '')) {
    throw new Error(`fleet channels must contain a valid ${channel} release target`)
  }
}

function requireGitObjectId (value, label) {
  if (!/^[a-f0-9]{40,64}$/.test(value)) throw new Error(`invalid ${label}`)
}

async function writeChannelsAtomic (file, contents, original) {
  const dir = path.dirname(file)
  const base = path.basename(file)
  const lockPath = path.join(dir, `.${base}.promote.lock`)
  const tempPath = path.join(dir, `.${base}.tmp-${process.pid}-${randomBytes(6).toString('hex')}`)
  let lockHandle
  let tempHandle
  let ownsLock = false

  try {
    try {
      lockHandle = await open(lockPath, 'wx', 0o600)
      ownsLock = true
    } catch (err) {
      if (err?.code === 'EEXIST') throw new Error(`another channel promotion holds ${lockPath}`)
      throw err
    }

    const current = await readBoundedRegularFile(file, 'fleet channels', MAX_CHANNELS_BYTES)
    if (!current.buffer.equals(original.buffer)) {
      throw new Error('fleet channels changed during validation; refusing stale promotion')
    }

    tempHandle = await open(tempPath, 'wx', original.mode)
    await tempHandle.writeFile(contents)
    await tempHandle.sync()
    await tempHandle.close()
    tempHandle = null

    const beforeRename = await readBoundedRegularFile(file, 'fleet channels', MAX_CHANNELS_BYTES)
    if (!beforeRename.buffer.equals(original.buffer)) {
      throw new Error('fleet channels changed before atomic replacement; refusing stale promotion')
    }
    await rename(tempPath, file)
    await syncDirectory(dir)
  } finally {
    await tempHandle?.close().catch(() => {})
    await unlink(tempPath).catch(() => {})
    await lockHandle?.close().catch(() => {})
    if (ownsLock) await unlink(lockPath).catch(() => {})
  }
}

async function syncDirectory (dir) {
  let handle
  try {
    handle = await open(dir, 'r')
    await handle.sync()
  } catch (err) {
    if (!['EINVAL', 'ENOTSUP', 'EISDIR'].includes(err?.code)) throw err
  } finally {
    await handle?.close().catch(() => {})
  }
}

function sha256 (buffer) {
  return createHash('sha256').update(buffer).digest('hex')
}

function safeError (err) {
  const value = err instanceof Error ? err.message : String(err)
  return value.replace(/[\r\n\0]/g, ' ').slice(0, 1000)
}

function hasControlChars (value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if (code <= 31 || code === 127) return true
  }
  return false
}

function hardenedGitEnv (overrides) {
  const env = { ...process.env }
  for (const name of Object.keys(env)) {
    if (UNSAFE_GIT_ENV.has(name) || /^GIT_CONFIG_(?:KEY|VALUE)_\d+$/.test(name)) delete env[name]
  }
  return { ...env, ...overrides }
}
