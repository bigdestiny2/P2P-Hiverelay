#!/usr/bin/env node

import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { constants as fsConstants } from 'node:fs'
import { lstat, mkdir, mkdtemp, open, realpath, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'
import {
  verifyPublicHiveGatewayOpsEvidence
} from './lib/public-hive-gateway-ops.mjs'

const execFileAsync = promisify(execFile)
const scriptPath = fileURLToPath(import.meta.url)
const scriptDir = path.dirname(scriptPath)
const defaultRepoRoot = path.resolve(scriptDir, '..')
const PROMOTER_RELATIVE_PATH = 'scripts/promote-fleet-channel.mjs'
const PROMOTER_LIBRARY_RELATIVE_PATH = 'scripts/lib/public-hive-gateway-release-manifest.mjs'
const PROMOTER_POLICY_RELATIVE_PATH = 'scripts/lib/public-hive-gateway-policy.mjs'
const CHANNELS_RELATIVE_PATH = 'fleet/channels.json'
const MAX_CHANNELS_BYTES = 256 * 1024
const MAX_ALLOWED_SIGNERS_BYTES = 256 * 1024
const MAX_TRUSTED_PROMOTER_BYTES = 1024 * 1024
const MAX_PROCESS_OUTPUT_BYTES = 4 * 1024 * 1024
const MAX_BOOTSTRAP_AUTHORITY_BYTES = 2 * 1024 * 1024
const GIT_PROGRAM = '/usr/bin/git'
const SSH_KEYGEN_PROGRAM = '/usr/bin/ssh-keygen'
const DISABLED_HOOKS_PATH = '/dev/null'
const RELEASE_TAG_PATTERN = /^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/
const REF_COMPONENT_PATTERN = /^(?!\.)(?!.*(?:\.\.|\/\.|\.lock(?:\/|$)))[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$/
const REMOTE_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/
const GOOD_SIGNATURE_PATTERN = /GOODSIG|TRUST_(?:FULLY|ULTIMATE)|Good[^\r\n]*signature/i
const PUBLIC_GATEWAY_PREDECESSOR_AUTHORITY = Object.freeze([
  Object.freeze({ path: 'fleet/updater.sh', mode: '100755' }),
  Object.freeze({ path: 'fleet/quarantine-public-gateway.sh', mode: '100755' }),
  Object.freeze({ path: 'scripts/verify-public-hive-gateway-quarantine.mjs', mode: '100644' }),
  Object.freeze({ path: 'scripts/lib/public-hive-gateway-quarantine-authority.mjs', mode: '100644' }),
  Object.freeze({ path: 'scripts/lib/public-hive-gateway-release-manifest.mjs', mode: '100644' }),
  Object.freeze({ path: 'scripts/lib/public-hive-gateway-policy.mjs', mode: '100644' })
])
const UNSAFE_GIT_ENV = new Set([
  'GIT_ALTERNATE_OBJECT_DIRECTORIES',
  'GIT_COMMON_DIR',
  'GIT_CONFIG',
  'GIT_CONFIG_COUNT',
  'GIT_CONFIG_GLOBAL',
  'GIT_CONFIG_PARAMETERS',
  'GIT_CONFIG_SYSTEM',
  'GIT_DIR',
  'GIT_EXEC_PATH',
  'GIT_GRAFT_FILE',
  'GIT_INDEX_FILE',
  'GIT_NAMESPACE',
  'GIT_OBJECT_DIRECTORY',
  'GIT_PREFIX',
  'GIT_PROXY_COMMAND',
  'GIT_QUARANTINE_PATH',
  'GIT_REPLACE_REF_BASE',
  'GIT_SHALLOW_FILE',
  'GIT_SSH',
  'GIT_SSH_COMMAND',
  'GIT_SSL_CAINFO',
  'GIT_SSL_CAPATH',
  'GIT_SSL_NO_VERIFY',
  'GIT_WORK_TREE'
])

const usage = `
Usage:
  node scripts/publish-fleet-channel.mjs --channel <canary|stable> --target <vX.Y.Z> [options]

Publisher options:
  --publish                  Create, verify, and atomically publish the signed channel commit
  --remote <name>            Git remote (default: origin)
  --branch <name>            Published control branch (default: main)
  --repo <absolute-path>     Clean control checkout (default: repository root)

Promotion evidence options:
  --canary-evidence <path>   Verified canary rollout evidence (stable)
  --gateway-window-state <p> Completed signed observation state (gateway stable)
  --relays <path>            Current full fleet inventory
  --allowed-signers <path>   Trusted OpenSSH allowed_signers file
  --gateway-manifest <path>  Legacy gateway manifest override only
  --gateway-ops-evidence-dir <absolute-dir>
                              Fresh per-relay <relay>.json ops artifacts (public-t1)
  --require-public-gateway   Require gateway evidence for a legacy release
  --help                     Show this help

Without --publish this command performs validation without changing the control
worktree, refs, or remotes. A private temporary trust snapshot is removed on
exit. Enabled
canonical gateway manifests force their own canary/stable evidence gates. This
command uses exact compare-and-swap leases, never an unguarded force push, and
never advances stable automatically.`

if (path.resolve(process.argv[1] || '') === scriptPath) {
  try {
    await main()
  } catch (err) {
    console.error(`fleet channel publisher: ${safeError(err)}`)
    process.exitCode = 1
  }
}

async function main () {
  const options = parseArgs(process.argv.slice(2))
  if (options.help) {
    console.log(usage.trim())
    return
  }
  const result = await publishFleetChannel(options)
  console.log(JSON.stringify(result, null, 2))
}

export async function publishFleetChannel (input, injected = {}) {
  const options = normalizeOptions(input)
  const repoRoot = options.repo
  const sourceAllowedSignersPath = options.allowedSigners || path.join(repoRoot, 'fleet', 'allowed-signers')
  const pinTrust = injected.pinAllowedSigners || pinAllowedSigners
  const pinnedTrust = await pinTrust(sourceAllowedSignersPath)
  if (!pinnedTrust || !path.isAbsolute(pinnedTrust.path || '') || typeof pinnedTrust.cleanup !== 'function') {
    throw new Error('could not create an isolated allowed_signers snapshot')
  }
  try {
    return await publishWithPinnedTrust(options, injected, pinnedTrust.path)
  } finally {
    await pinnedTrust.cleanup()
  }
}

async function publishWithPinnedTrust (options, injected, allowedSignersPath) {
  const repoRoot = options.repo
  const channelsPath = path.join(repoRoot, CHANNELS_RELATIVE_PATH)
  const git = injected.git || ((args, failure) => runGit(repoRoot, args, failure))
  const injectedPromote = injected.promote
  const deriveChannels = injected.deriveChannels || deriveExpectedChannels

  const topLevel = (await git(['rev-parse', '--show-toplevel'], 'not a Git worktree')).stdout.trim()
  if (path.resolve(topLevel) !== repoRoot && !(await pathsReferToSameLocation(topLevel, repoRoot))) {
    throw new Error(`--repo must be the exact Git worktree root (${topLevel || 'unknown'})`)
  }
  const branch = (await git(['symbolic-ref', '--quiet', '--short', 'HEAD'],
    'publisher requires an attached branch')).stdout.trim()
  if (branch !== options.branch) {
    throw new Error(`publisher requires branch ${options.branch}; current branch is ${branch || 'detached'}`)
  }
  await assertCleanControlWorktree(git)

  const startingHead = normalizeObjectId((await git(['rev-parse', '--verify', 'HEAD'],
    'cannot resolve local HEAD')).stdout, 'local HEAD')
  const promote = injectedPromote ||
    (args => runPromoterFromCommit(args, startingHead, git))
  await assertNoGitUrlRewrites(git)
  const remoteEndpoint = await resolveRemoteEndpoint(git, options.remote)
  const remoteHead = await readRemoteHead(git, remoteEndpoint, options.remote, options.branch)
  if (remoteHead !== startingHead) {
    throw new Error(`local ${options.branch} is not the current ${options.remote}/${options.branch}; refusing stale publication`)
  }

  const promoterArgs = buildPromoterArgs(options, repoRoot, channelsPath, allowedSignersPath)
  const dryRun = validatePromotionResult(await promote([...promoterArgs, '--dry-run']), options, channelsPath, true)
  await assertRecoveryExpectedCurrent(options, dryRun, git)
  await assertRemoteReleaseTag(git, remoteEndpoint, options.remote, options.target, dryRun)
  const predecessorAuthority = await validateEnabledGatewayPredecessor(
    dryRun, git, allowedSignersPath, remoteEndpoint, options.remote)
  const operatorContracts = await validateOperatorReadiness(options, dryRun, git)
  const baseResult = {
    schema: 'hiverelay-fleet-channel-publication-v1',
    status: options.publish ? 'validated' : 'dry-run',
    channel: options.channel,
    target: options.target,
    branch: options.branch,
    remote: options.remote,
    startingHead,
    publicGatewayRequired: dryRun.publicGatewayRequired,
    predecessorAuthority,
    operatorContracts,
    wouldChange: dryRun.wouldChange
  }
  if (!options.publish) return baseResult

  const expectedChannels = dryRun.wouldChange
    ? await deriveChannels(channelsPath, options.channel, options.target, dryRun.previousTarget, git)
    : null

  // Recheck immediately before the only local mutation. The promoter then
  // atomically updates the one control-plane file it already validated.
  await assertCleanControlWorktree(git)
  const preMutationHead = normalizeObjectId((await git(['rev-parse', '--verify', 'HEAD'],
    'cannot re-resolve local HEAD')).stdout, 'local HEAD')
  if (preMutationHead !== startingHead ||
      await readRemoteHead(git, remoteEndpoint, options.remote, options.branch) !== startingHead) {
    throw new Error('local or remote control branch changed after validation')
  }
  await assertRemoteReleaseTag(git, remoteEndpoint, options.remote, options.target, dryRun)
  const revalidatedPredecessorAuthority = await validateEnabledGatewayPredecessor(
    dryRun, git, allowedSignersPath, remoteEndpoint, options.remote)
  if (JSON.stringify(revalidatedPredecessorAuthority) !== JSON.stringify(predecessorAuthority)) {
    throw new Error('public gateway predecessor authority changed after publication validation')
  }
  const revalidatedOperatorContracts = await validateOperatorReadiness(options, dryRun, git)
  if (JSON.stringify(revalidatedOperatorContracts) !== JSON.stringify(operatorContracts)) {
    throw new Error('operator readiness evidence changed after publication validation')
  }
  await assertRecoveryExpectedCurrent(options, dryRun, git)

  const applied = validatePromotionResult(await promote(promoterArgs), options, channelsPath, false)
  if (applied.wouldChange !== dryRun.wouldChange ||
      applied.previousTarget !== dryRun.previousTarget ||
      applied.targetSha !== dryRun.targetSha || applied.tagObjectSha !== dryRun.tagObjectSha ||
      JSON.stringify(applied.operatorContracts) !== JSON.stringify(dryRun.operatorContracts)) {
    throw new Error('promotion result changed between validation and application')
  }
  await assertRecoveryExpectedCurrent(options, applied, git)
  if (!applied.wouldChange) {
    await assertCleanControlWorktree(git)
    return { ...baseResult, status: 'unchanged', publishedHead: startingHead }
  }

  await assertOnlyChannelsWorktreeChange(git)
  await git(['diff', '--check', '--', CHANNELS_RELATIVE_PATH],
    'channel update failed git diff safety checks')
  if (await readRemoteHead(git, remoteEndpoint, options.remote, options.branch) !== startingHead) {
    throw new Error('remote control branch changed after channel validation; leaving the local channel edit for inspection')
  }

  await git(['add', '--', CHANNELS_RELATIVE_PATH], 'could not stage the channel update')
  await assertOnlyChannelsStaged(git)
  await assertIndexEntry(git, expectedChannels.blobOid)
  await git(
    [
      '-c', `core.hooksPath=${DISABLED_HOOKS_PATH}`,
      '-c', 'gpg.format=ssh',
      'commit', '-S', '-m', `fleet: promote ${options.channel} to ${options.target}`
    ],
    'could not create the required signed channel commit'
  )

  const publishedHead = normalizeObjectId((await git(['rev-parse', '--verify', 'HEAD'],
    'cannot resolve publication commit')).stdout, 'publication commit')
  const parent = normalizeObjectId((await git(['rev-parse', '--verify', 'HEAD^'],
    'publication commit has no parent')).stdout, 'publication parent')
  if (publishedHead === startingHead || parent !== startingHead) {
    throw new Error('publication commit is not a single child of the validated control head')
  }
  await assertCommitEntry(git, expectedChannels.blobOid)
  await assertPublicationCommit(git)
  await assertCleanControlWorktree(git)

  const signature = await git([
    '-c', 'gpg.format=ssh',
    '-c', `gpg.ssh.allowedSignersFile=${allowedSignersPath}`,
    '-c', `gpg.ssh.program=${SSH_KEYGEN_PROGRAM}`,
    'verify-commit', '--raw', publishedHead
  ], 'publication commit is not signed by a trusted fleet signer')
  if (!GOOD_SIGNATURE_PATTERN.test(`${signature.stdout}\n${signature.stderr}`)) {
    throw new Error('publication commit verification did not report a trusted signature')
  }

  if (await readRemoteHead(git, remoteEndpoint, options.remote, options.branch) !== startingHead) {
    throw new Error('remote control branch raced the signed commit; refusing to push')
  }
  await assertNoGitUrlRewrites(git)
  await assertRemoteReleaseTag(git, remoteEndpoint, options.remote, options.target, dryRun)
  const releaseTagRef = `refs/tags/${options.target}`
  await git(
    [
      '-c', `core.hooksPath=${DISABLED_HOOKS_PATH}`,
      'push', '--atomic', '--porcelain', '--no-follow-tags',
      `--force-with-lease=refs/heads/${options.branch}:${startingHead}`,
      `--force-with-lease=${releaseTagRef}:${dryRun.tagObjectSha}`,
      '--', remoteEndpoint,
      `${dryRun.tagObjectSha}:${releaseTagRef}`,
      `${publishedHead}:refs/heads/${options.branch}`
    ],
    'atomic compare-and-swap publication was rejected; the signed local commit was preserved'
  )
  const confirmedRemoteHead = await readRemoteHead(git, remoteEndpoint, options.remote, options.branch)
  if (confirmedRemoteHead !== publishedHead) {
    throw new Error('remote did not resolve to the signed publication commit after push')
  }
  await assertRemoteReleaseTag(git, remoteEndpoint, options.remote, options.target, dryRun)

  return {
    ...baseResult,
    status: 'published',
    publishedHead,
    remoteHead: confirmedRemoteHead
  }
}

async function assertRecoveryExpectedCurrent (options, promotion, git) {
  if (!options.expectedCurrentTarget) return
  if (promotion.previousTarget !== options.expectedCurrentTarget) {
    throw new Error('starting fleet channel does not match the recovery expected-current target')
  }
  const previousSha = normalizeObjectId((await git([
    'rev-parse', '--verify', `refs/tags/${promotion.previousTarget}^{commit}`
  ], 'cannot resolve recovery expected-current tag')).stdout, 'recovery expected-current SHA')
  if (previousSha !== options.expectedCurrentTargetSha) {
    throw new Error('starting fleet channel target SHA does not match the recovery receipt')
  }
}

function normalizeOptions (input) {
  const options = input || {}
  if (options.channel !== 'canary' && options.channel !== 'stable') {
    throw new Error('--channel must be exactly canary or stable')
  }
  if (!RELEASE_TAG_PATTERN.test(options.target || '')) {
    throw new Error('--target must be an immutable release tag like v1.2.3')
  }
  const repo = path.resolve(options.repo || defaultRepoRoot)
  if (!path.isAbsolute(repo) || hasControlChars(repo)) throw new Error('--repo must be a safe absolute path')
  const remote = options.remote || 'origin'
  if (!REMOTE_NAME_PATTERN.test(remote)) throw new Error('--remote must be a bounded Git remote name')
  const branch = options.branch || 'main'
  if (!isSafeBranch(branch)) throw new Error('--branch must be a bounded safe Git branch name')
  if (options.expectedCurrentTarget != null || options.expectedCurrentTargetSha != null) {
    if (!RELEASE_TAG_PATTERN.test(options.expectedCurrentTarget || '') ||
        !isObjectId(options.expectedCurrentTargetSha || '')) {
      throw new Error('recovery expected-current target and SHA must be an exact release binding')
    }
  }
  if (options.channel === 'stable' && !options.canaryEvidence) {
    throw new Error('--canary-evidence is required before stable publication')
  }
  for (const name of ['canaryEvidence', 'gatewayWindowState', 'relays', 'allowedSigners', 'gatewayOpsEvidenceDir']) {
    if (options[name] != null && (!path.isAbsolute(options[name]) || hasControlChars(options[name]))) {
      throw new Error(`--${kebab(name)} must be an absolute safe path`)
    }
  }
  return { ...options, repo, remote, branch, publish: options.publish === true }
}

function buildPromoterArgs (options, repoRoot, channelsPath, allowedSignersPath) {
  const args = [
    '--channel', options.channel,
    '--target', options.target,
    '--repo', repoRoot,
    '--channels', channelsPath,
    '--allowed-signers', allowedSignersPath
  ]
  for (const [name, value] of [
    ['canary-evidence', options.canaryEvidence],
    ['gateway-window-state', options.gatewayWindowState],
    ['relays', options.relays],
    ['gateway-manifest', options.gatewayManifest]
  ]) {
    if (value) args.push(`--${name}`, value)
  }
  if (options.requirePublicGateway) args.push('--require-public-gateway')
  return args
}

function validatePromotionResult (result, options, channelsPath, dryRun) {
  if (!result || typeof result !== 'object' || Array.isArray(result) ||
      result.schema !== 'hiverelay-fleet-channel-promotion-v1' ||
      result.channel !== options.channel || result.target !== options.target ||
      path.resolve(result.channelsPath || '') !== channelsPath ||
      typeof result.wouldChange !== 'boolean' || typeof result.publicGatewayRequired !== 'boolean' ||
      !Array.isArray(result.operatorContracts) ||
      !RELEASE_TAG_PATTERN.test(result.previousTarget || '') ||
      !isObjectId(result.targetSha) || !isObjectId(result.tagObjectSha)) {
    throw new Error('promoter returned an invalid or drifted publication contract')
  }
  const wantedStatus = dryRun ? 'dry-run' : (result.wouldChange ? 'updated' : 'unchanged')
  if (result.status !== wantedStatus) throw new Error(`promoter returned unexpected status ${result.status || '(missing)'}`)
  for (const contract of result.operatorContracts) {
    if (!contract || typeof contract !== 'object' || Array.isArray(contract) ||
        !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(contract.relay || '') ||
        contract.path !== `fleet/public-hive-gateway-operators/${contract.relay}.json` ||
        !/^[a-f0-9]{64}$/.test(contract.sha256 || '')) {
      throw new Error('promoter returned an invalid public-t1 operator contract binding')
    }
  }
  return result
}

async function validateOperatorReadiness (options, promotion, git) {
  const expected = promotion.operatorContracts
  if (expected.length === 0) {
    if (options.gatewayOpsEvidenceDir) throw new Error('--gateway-ops-evidence-dir is valid only for a public-t1-gateway release')
    return []
  }
  if (!options.gatewayOpsEvidenceDir) {
    throw new Error('--gateway-ops-evidence-dir is required for a public-t1-gateway channel publication')
  }
  let evidenceDirectoryStat
  try {
    evidenceDirectoryStat = await lstat(options.gatewayOpsEvidenceDir)
  } catch {
    throw new Error('--gateway-ops-evidence-dir must be an existing non-symlink directory')
  }
  if (!evidenceDirectoryStat.isDirectory() || evidenceDirectoryStat.isSymbolicLink()) {
    throw new Error('--gateway-ops-evidence-dir must be an existing non-symlink directory')
  }
  const manifestBytes = await readTrustedHeadFile(promotion.targetSha, 'fleet/public-hive-gateway-release.json', git)
  const manifest = parseJsonObject(manifestBytes, 'trusted public gateway release manifest')
  const manifestSha256 = createHash('sha256').update(manifestBytes).digest('hex')
  const verified = []
  for (const binding of expected) {
    const contractBytes = await readTrustedHeadFile(promotion.targetSha, binding.path, git)
    const contract = parseJsonObject(contractBytes, `trusted operator contract ${binding.relay}`)
    const evidencePath = path.join(options.gatewayOpsEvidenceDir, `${binding.relay}.json`)
    const evidenceBytes = await readBoundedSingleLinkFile(evidencePath,
      `operator readiness evidence for ${binding.relay}`, 2 * 1024 * 1024)
    const evidence = parseJsonObject(evidenceBytes, `operator readiness evidence for ${binding.relay}`)
    const result = verifyPublicHiveGatewayOpsEvidence(evidence, {
      contract,
      manifest,
      releaseSha: promotion.targetSha,
      relay: binding.relay,
      expectedContractSha256: binding.sha256,
      contractFileSha256: createHash('sha256').update(contractBytes).digest('hex'),
      releaseManifestSha256: manifestSha256
    })
    if (result.operatorContractSha256 !== binding.sha256) {
      throw new Error(`passing ops evidence did not derive the signed operator contract digest for ${binding.relay}`)
    }
    verified.push({
      relay: binding.relay,
      operatorId: result.operatorId,
      registrableDomain: result.registrableDomain,
      suffix: result.suffix,
      operatorContractSha256: result.operatorContractSha256,
      certificateSpkiSha256: result.certificateSpkiSha256,
      expectedAddresses: result.expectedAddresses,
      checkedAt: result.checkedAt,
      evidenceSha256: createHash('sha256').update(evidenceBytes).digest('hex')
    })
  }
  return verified
}

async function validateEnabledGatewayPredecessor (promotion, git, allowedSignersPath, remoteEndpoint, remote) {
  if (promotion.operatorContracts.length === 0) return null
  const predecessor = promotion.previousTarget
  if (!RELEASE_TAG_PATTERN.test(predecessor || '')) {
    throw new Error('enabled public gateway publication has an invalid predecessor release tag')
  }
  const tagRef = `refs/tags/${predecessor}`
  const tagType = (await git(['cat-file', '-t', tagRef],
    `public gateway predecessor ${predecessor} is missing`)).stdout.trim()
  if (tagType !== 'tag') {
    throw new Error(`public gateway predecessor ${predecessor} must be an annotated signed tag`)
  }
  const signature = await git([
    '-c', 'gpg.format=ssh',
    '-c', `gpg.ssh.allowedSignersFile=${allowedSignersPath}`,
    '-c', `gpg.ssh.program=${SSH_KEYGEN_PROGRAM}`,
    'verify-tag', '--raw', predecessor
  ], `public gateway predecessor ${predecessor} is not signed by a trusted fleet signer`)
  if (!GOOD_SIGNATURE_PATTERN.test(`${signature.stdout}\n${signature.stderr}`)) {
    throw new Error(`public gateway predecessor ${predecessor} did not report a trusted signature`)
  }
  const tagObjectSha = normalizeObjectId((await git([
    'rev-parse', '--verify', `${tagRef}^{tag}`
  ], 'cannot resolve public gateway predecessor tag object')).stdout, 'public gateway predecessor tag object')
  const commitSha = normalizeObjectId((await git([
    'rev-parse', '--verify', `${tagRef}^{commit}`
  ], 'cannot resolve public gateway predecessor commit')).stdout, 'public gateway predecessor commit')
  await assertRemoteTagIdentity(git, remoteEndpoint, remote, predecessor, tagObjectSha, commitSha)

  const files = []
  for (const requirement of PUBLIC_GATEWAY_PREDECESSOR_AUTHORITY) {
    const target = await readTrustedAuthorityEntry(promotion.targetSha, requirement, git)
    const previous = await readTrustedAuthorityEntry(commitSha, requirement, git)
    if (target.oid !== previous.oid) {
      throw new Error(`enabled public gateway target requires predecessor ${predecessor} to contain blob-identical ${requirement.path}`)
    }
    files.push({ path: requirement.path, mode: requirement.mode, oid: target.oid })
  }
  return { target: predecessor, tagObjectSha, commitSha, files }
}

async function readTrustedAuthorityEntry (commit, requirement, git) {
  const entry = await git(['ls-tree', '-z', commit, '--', requirement.path],
    `cannot inspect public gateway bootstrap authority ${requirement.path}`)
  const match = /^(100644|100755) blob ([a-f0-9]{40}|[a-f0-9]{64})\t([^\0]+)\0$/.exec(entry.stdout)
  if (!match || match[1] !== requirement.mode || match[3] !== requirement.path) {
    throw new Error(`public gateway bootstrap authority ${requirement.path} must be one tracked ${requirement.mode} regular blob`)
  }
  const blob = await git(['cat-file', 'blob', match[2]],
    `cannot read public gateway bootstrap authority ${requirement.path}`)
  const bytes = Buffer.from(blob.stdout)
  if (bytes.byteLength < 1 || bytes.byteLength > MAX_BOOTSTRAP_AUTHORITY_BYTES || bytes.includes(0)) {
    throw new Error(`public gateway bootstrap authority ${requirement.path} has invalid bounded source bytes`)
  }
  return { oid: match[2], bytes: bytes.byteLength }
}

async function assertRemoteTagIdentity (git, endpoint, remote, target, tagObjectSha, commitSha) {
  const tagRef = `refs/tags/${target}`
  const peeledRef = `${tagRef}^{}`
  const result = await git(['ls-remote', '--exit-code', '--', endpoint, tagRef, peeledRef],
    `cannot resolve public gateway predecessor ${target} on remote ${remote}`)
  const refs = new Map()
  for (const line of result.stdout.trim().split(/\r?\n/).filter(Boolean)) {
    const match = /^([a-f0-9]{40}|[a-f0-9]{64})\t(.+)$/.exec(line)
    if (!match || refs.has(match[2])) throw new Error(`remote public gateway predecessor ${target} returned invalid refs`)
    refs.set(match[2], match[1])
  }
  if (refs.size !== 2 || refs.get(tagRef) !== tagObjectSha || refs.get(peeledRef) !== commitSha) {
    throw new Error(`remote public gateway predecessor ${target} does not match its trusted local tag`)
  }
}

async function assertCleanControlWorktree (git) {
  const status = await git(['status', '--porcelain=v1', '-z', '--untracked-files=all'],
    'cannot inspect control worktree status')
  if (status.stdout.length !== 0) {
    throw new Error('publisher requires a completely clean control worktree, including untracked files')
  }
  const tracked = splitNul((await git(['ls-files', '-v', '-z'],
    'cannot inspect tracked index flags')).stdout)
  if (tracked.some(entry => !entry.startsWith('H '))) {
    throw new Error('publisher forbids assume-unchanged, skip-worktree, and nonstandard tracked index flags')
  }
}

async function assertOnlyChannelsWorktreeChange (git) {
  const unstaged = splitNul((await git(['diff', '--name-only', '-z'],
    'cannot inspect channel worktree diff')).stdout)
  const staged = splitNul((await git(['diff', '--cached', '--name-only', '-z'],
    'cannot inspect staged files')).stdout)
  const untracked = splitNul((await git(['ls-files', '--others', '--exclude-standard', '-z'],
    'cannot inspect untracked files')).stdout)
  if (unstaged.length !== 1 || unstaged[0] !== CHANNELS_RELATIVE_PATH || staged.length !== 0 || untracked.length !== 0) {
    throw new Error(`promoter changed files outside ${CHANNELS_RELATIVE_PATH}; refusing publication`)
  }
}

async function assertOnlyChannelsStaged (git) {
  const staged = splitNul((await git(['diff', '--cached', '--name-only', '-z'],
    'cannot inspect staged channel update')).stdout)
  const unstaged = splitNul((await git(['diff', '--name-only', '-z'],
    'cannot inspect residual worktree changes')).stdout)
  const untracked = splitNul((await git(['ls-files', '--others', '--exclude-standard', '-z'],
    'cannot inspect residual untracked files')).stdout)
  if (staged.length !== 1 || staged[0] !== CHANNELS_RELATIVE_PATH || unstaged.length !== 0 || untracked.length !== 0) {
    throw new Error(`signed publication must stage only ${CHANNELS_RELATIVE_PATH}`)
  }
}

async function assertPublicationCommit (git) {
  const names = splitNul((await git([
    'diff-tree', '--no-commit-id', '--name-only', '-r', '-z', 'HEAD'
  ], 'cannot inspect publication commit')).stdout)
  if (names.length !== 1 || names[0] !== CHANNELS_RELATIVE_PATH) {
    throw new Error(`publication commit contains files outside ${CHANNELS_RELATIVE_PATH}`)
  }
}

async function assertIndexEntry (git, expectedBlobOid) {
  const result = await git(['ls-files', '--stage', '-z', '--', CHANNELS_RELATIVE_PATH],
    'cannot inspect the staged channel entry')
  const expected = `100644 ${expectedBlobOid} 0\t${CHANNELS_RELATIVE_PATH}\0`
  if (result.stdout !== expected) {
    throw new Error('staged channel mode or bytes changed after validation')
  }
}

async function assertCommitEntry (git, expectedBlobOid) {
  const result = await git(['ls-tree', '-z', 'HEAD', '--', CHANNELS_RELATIVE_PATH],
    'cannot inspect the signed channel entry')
  const expected = `100644 blob ${expectedBlobOid}\t${CHANNELS_RELATIVE_PATH}\0`
  if (result.stdout !== expected) {
    throw new Error('signed publication commit contains an unvalidated channel mode or blob')
  }
}

async function resolveRemoteEndpoint (git, remote) {
  const fetchUrls = nonemptyLines((await git(['remote', 'get-url', '--all', remote],
    `Git remote ${remote} has no fetch URL`)).stdout)
  const pushUrls = nonemptyLines((await git(['remote', 'get-url', '--push', '--all', remote],
    `Git remote ${remote} has no push URL`)).stdout)
  if (fetchUrls.length !== 1 || pushUrls.length !== 1 || fetchUrls[0] !== pushUrls[0]) {
    throw new Error(`Git remote ${remote} must have exactly one identical fetch and push endpoint`)
  }
  if (!isSafeGitEndpoint(fetchUrls[0])) {
    throw new Error(`Git remote ${remote} endpoint must be one safe HTTPS, SSH, or absolute local URL`)
  }
  return fetchUrls[0]
}

async function assertNoGitUrlRewrites (git) {
  const result = await git(['config', '--null', '--list'], 'cannot inspect effective Git URL configuration')
  for (const field of splitNul(result.stdout)) {
    const separator = field.indexOf('\n')
    const key = (separator < 0 ? field : field.slice(0, separator)).toLowerCase()
    if (/^url\..*\.(?:insteadof|pushinsteadof)$/.test(key)) {
      throw new Error('Git URL rewrite configuration is forbidden for fleet channel publication')
    }
  }
}

async function readRemoteHead (git, endpoint, remote, branch) {
  const result = await git(['ls-remote', '--exit-code', '--', endpoint, `refs/heads/${branch}`],
    `cannot resolve ${remote}/${branch}`)
  const lines = result.stdout.trim().split(/\r?\n/).filter(Boolean)
  if (lines.length !== 1) throw new Error(`remote ${remote}/${branch} did not resolve exactly once`)
  const match = /^([a-f0-9]{40}|[a-f0-9]{64})\trefs\/heads\/(.+)$/.exec(lines[0])
  if (!match || match[2] !== branch) throw new Error(`remote ${remote}/${branch} returned an invalid ref`)
  return match[1]
}

async function assertRemoteReleaseTag (git, endpoint, remote, target, expected) {
  const tagRef = `refs/tags/${target}`
  const peeledRef = `${tagRef}^{}`
  const result = await git(['ls-remote', '--exit-code', '--', endpoint, tagRef, peeledRef],
    `cannot resolve immutable release tag ${target} on remote ${remote}`)
  const refs = new Map()
  for (const line of result.stdout.trim().split(/\r?\n/).filter(Boolean)) {
    const match = /^([a-f0-9]{40}|[a-f0-9]{64})\t(.+)$/.exec(line)
    if (!match || refs.has(match[2])) throw new Error(`remote release tag ${target} returned invalid refs`)
    refs.set(match[2], match[1])
  }
  if (refs.size !== 2 || refs.get(tagRef) !== expected.tagObjectSha ||
      refs.get(peeledRef) !== expected.targetSha) {
    throw new Error(`remote release tag ${target} does not match the locally verified signed tag object and commit`)
  }
}

async function deriveExpectedChannels (file, channel, target, previousTarget, git) {
  const buffer = await readBoundedSingleLinkFile(file, 'fleet channels', MAX_CHANNELS_BYTES)
  let channels
  try {
    channels = JSON.parse(buffer.toString('utf8'))
  } catch {
    throw new Error('promoted fleet channels are not valid JSON')
  }
  if (!channels || typeof channels !== 'object' || Array.isArray(channels) ||
      channels[channel] !== previousTarget) {
    throw new Error(`starting fleet channels do not bind ${channel} to the promoter's previous target`)
  }
  const objectFormat = (await git(['rev-parse', '--show-object-format'],
    'cannot resolve Git object format')).stdout.trim()
  if (objectFormat !== 'sha1' && objectFormat !== 'sha256') {
    throw new Error('repository uses an unsupported Git object format')
  }
  const startingBlobOid = gitBlobOid(buffer, objectFormat)
  const startingEntry = await git(['ls-tree', '-z', 'HEAD', '--', CHANNELS_RELATIVE_PATH],
    'cannot inspect the starting channel entry')
  if (startingEntry.stdout !== `100644 blob ${startingBlobOid}\t${CHANNELS_RELATIVE_PATH}\0`) {
    throw new Error('starting channel file mode or bytes do not match the validated HEAD')
  }
  channels[channel] = target
  const expected = Buffer.from(JSON.stringify(channels, null, 2) + '\n')
  const blobOid = gitBlobOid(expected, objectFormat)
  return { blobOid }
}

function gitBlobOid (buffer, objectFormat) {
  const header = Buffer.from(`blob ${buffer.byteLength}\0`)
  return createHash(objectFormat).update(header).update(buffer).digest('hex')
}

function parseJsonObject (buffer, label) {
  let value
  try { value = JSON.parse(buffer.toString('utf8')) } catch { throw new Error(`${label} is not valid JSON`) }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must contain a JSON object`)
  return value
}

async function pinAllowedSigners (source) {
  const buffer = await readBoundedSingleLinkFile(source, 'allowed signers', MAX_ALLOWED_SIGNERS_BYTES)
  const directory = await mkdtemp(path.join(tmpdir(), 'hiverelay-publisher-trust-'))
  const file = path.join(directory, 'allowed_signers')
  try {
    await writeFile(file, buffer, { flag: 'wx', mode: 0o600 })
  } catch (err) {
    await rm(directory, { recursive: true, force: true }).catch(() => {})
    throw err
  }
  return {
    path: file,
    cleanup: () => rm(directory, { recursive: true, force: true })
  }
}

async function readBoundedSingleLinkFile (file, label, maxBytes) {
  let handle
  try {
    if (typeof fsConstants.O_NOFOLLOW !== 'number') throw new Error('platform lacks O_NOFOLLOW')
    handle = await open(file, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW)
    const before = await handle.stat({ bigint: true })
    if (!before.isFile() || before.nlink !== 1n || before.size < 1n || before.size > BigInt(maxBytes)) {
      throw new Error(`${label} must be a bounded single-link regular file`)
    }
    const buffer = Buffer.allocUnsafe(maxBytes + 1)
    let length = 0
    while (length < buffer.length) {
      const { bytesRead } = await handle.read(buffer, length, buffer.length - length, length)
      if (bytesRead === 0) break
      length += bytesRead
    }
    if (length > maxBytes) throw new Error(`${label} exceeds its read bound`)
    const after = await handle.stat({ bigint: true })
    if (!sameFileSnapshot(before, after) || BigInt(length) !== after.size) {
      throw new Error(`${label} changed while being read`)
    }
    return buffer.subarray(0, length)
  } catch (err) {
    if (err?.message?.startsWith(label) || err?.message === 'platform lacks O_NOFOLLOW') throw err
    throw new Error(`${label} must be a readable non-symlink file`)
  } finally {
    await handle?.close().catch(() => {})
  }
}

function sameFileSnapshot (left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode &&
    left.nlink === right.nlink && left.size === right.size && left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
}

async function runGit (repoRoot, args, failure) {
  try {
    return await execFileAsync(GIT_PROGRAM, [
      '--no-replace-objects',
      '-C', repoRoot,
      '-c', `core.hooksPath=${DISABLED_HOOKS_PATH}`,
      '-c', 'core.fsmonitor=false',
      '-c', 'http.sslVerify=true',
      '-c', 'protocol.ext.allow=never',
      ...args
    ], {
      encoding: 'utf8',
      env: hardenedGitEnv({
        GIT_GRAFT_FILE: '/dev/null/hiverelay-disabled',
        GIT_NO_REPLACE_OBJECTS: '1',
        GIT_OPTIONAL_LOCKS: '0'
      }),
      maxBuffer: MAX_PROCESS_OUTPUT_BYTES,
      timeout: 30_000
    })
  } catch {
    throw new Error(failure)
  }
}

async function runPromoterFromCommit (args, commit, git) {
  const snapshot = await pinPromoterCode(commit, git)
  try {
    return await runPromoter(args, snapshot.path)
  } finally {
    await snapshot.cleanup()
  }
}

async function pinPromoterCode (commit, git) {
  const files = await Promise.all([
    readTrustedHeadFile(commit, PROMOTER_RELATIVE_PATH, git),
    readTrustedHeadFile(commit, PROMOTER_LIBRARY_RELATIVE_PATH, git),
    readTrustedHeadFile(commit, PROMOTER_POLICY_RELATIVE_PATH, git)
  ])
  const directory = await mkdtemp(path.join(tmpdir(), 'hiverelay-publisher-code-'))
  const scriptsDirectory = path.join(directory, 'scripts')
  const libraryDirectory = path.join(scriptsDirectory, 'lib')
  const promoter = path.join(directory, PROMOTER_RELATIVE_PATH)
  try {
    await mkdir(libraryDirectory, { recursive: true, mode: 0o700 })
    await writeFile(promoter, files[0], { flag: 'wx', mode: 0o400 })
    await writeFile(path.join(directory, PROMOTER_LIBRARY_RELATIVE_PATH), files[1], { flag: 'wx', mode: 0o400 })
    await writeFile(path.join(directory, PROMOTER_POLICY_RELATIVE_PATH), files[2], { flag: 'wx', mode: 0o400 })
  } catch (err) {
    await rm(directory, { recursive: true, force: true }).catch(() => {})
    throw err
  }
  return {
    path: promoter,
    cleanup: () => rm(directory, { recursive: true, force: true })
  }
}

async function readTrustedHeadFile (commit, repoRelativePath, git) {
  const entry = await git(['ls-tree', '-z', commit, '--', repoRelativePath],
    `cannot inspect trusted ${repoRelativePath}`)
  const match = /^(100644) blob ([a-f0-9]{40}|[a-f0-9]{64})\t([^\0]+)\0$/.exec(entry.stdout)
  if (!match || match[3] !== repoRelativePath) {
    throw new Error(`trusted ${repoRelativePath} must be one non-executable regular blob`)
  }
  const blob = await git(['cat-file', 'blob', match[2]], `cannot read trusted ${repoRelativePath}`)
  const buffer = Buffer.from(blob.stdout)
  if (buffer.byteLength < 1 || buffer.byteLength > MAX_TRUSTED_PROMOTER_BYTES || buffer.includes(0)) {
    throw new Error(`trusted ${repoRelativePath} has invalid bounded source bytes`)
  }
  return buffer
}

async function runPromoter (args, trustedPromoterPath) {
  try {
    const result = await execFileAsync(process.execPath, [trustedPromoterPath, ...args], {
      encoding: 'utf8',
      env: hardenedGitEnv({
        GIT_GRAFT_FILE: '/dev/null/hiverelay-disabled',
        GIT_NO_REPLACE_OBJECTS: '1',
        GIT_OPTIONAL_LOCKS: '0'
      }),
      maxBuffer: MAX_PROCESS_OUTPUT_BYTES,
      timeout: 60_000
    })
    return JSON.parse(result.stdout)
  } catch (err) {
    const diagnostic = safeError(err?.stderr || err)
    throw new Error(`channel promoter rejected publication: ${diagnostic}`)
  }
}

function parseArgs (argv) {
  const out = {}
  const valueArgs = new Set([
    'channel',
    'target',
    'repo',
    'remote',
    'branch',
    'canary-evidence',
    'gateway-window-state',
    'relays',
    'allowed-signers',
    'gateway-manifest',
    'gateway-ops-evidence-dir'
  ])
  const booleanArgs = new Set(['publish', 'require-public-gateway', 'help'])
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

function splitNul (value) {
  if (!value) return []
  const fields = value.split('\0')
  if (fields.at(-1) === '') fields.pop()
  return fields
}

function nonemptyLines (value) {
  const lines = String(value).split(/\r?\n/)
  if (lines.at(-1) === '') lines.pop()
  return lines.filter(line => line.length > 0)
}

function normalizeObjectId (value, label) {
  const normalized = String(value || '').trim().toLowerCase()
  if (!isObjectId(normalized)) throw new Error(`invalid ${label}`)
  return normalized
}

function isObjectId (value) {
  return typeof value === 'string' && /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(value)
}

function isSafeBranch (value) {
  return typeof value === 'string' && REF_COMPONENT_PATTERN.test(value) &&
    !value.endsWith('.') && !value.endsWith('/') && !value.includes('@{') && !value.includes('//')
}

function isSafeGitEndpoint (value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 4096 ||
      value.startsWith('-') || hasControlChars(value) || /\s/.test(value)) return false
  if (path.isAbsolute(value)) return true
  if (/^(?:[A-Za-z0-9._-]+@)?[A-Za-z0-9.-]+:[A-Za-z0-9._~/-]+$/.test(value)) return true
  try {
    const parsed = new URL(value)
    if (!['https:', 'ssh:', 'file:'].includes(parsed.protocol) || parsed.password || parsed.search || parsed.hash) return false
    if (parsed.protocol === 'https:' && parsed.username) return false
    if (parsed.protocol === 'file:' && parsed.hostname && parsed.hostname !== 'localhost') return false
    return parsed.protocol !== 'file:' || path.isAbsolute(decodeURIComponent(parsed.pathname))
  } catch {
    return false
  }
}

function hasControlChars (value) {
  for (const character of String(value)) {
    const code = character.charCodeAt(0)
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

async function pathsReferToSameLocation (left, right) {
  try {
    return await realpath(left) === await realpath(right)
  } catch {
    return false
  }
}

function camel (value) {
  return value.replace(/-([a-z])/g, (_, character) => character.toUpperCase())
}

function kebab (value) {
  return value.replace(/[A-Z]/g, character => `-${character.toLowerCase()}`)
}

function safeError (err) {
  return String(err?.message || err || 'unknown error').replace(/[\r\n\0]/g, ' ').slice(0, 1000)
}
