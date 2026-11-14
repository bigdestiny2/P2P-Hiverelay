#!/usr/bin/env node
import fs from 'node:fs'
import crypto from 'node:crypto'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { isDeepStrictEqual } from 'node:util'
import { RELEASE_PROMOTION_EVIDENCE, assertArtifactSurfaceState, promotionAssetNames } from '../lib/release-evidence-contract.mjs'
import { verifyQualification, validateFleetProof, assertFreshQualification } from './qualification.mjs'
import { prepareDistribution, publishDistribution, verifyOriginalDeviceTree, RELEASE_REPOSITORY } from './distribution.mjs'
import { verifyNpmBytes, verifyImageBytes, githubRelease, promoteLabels } from './live.mjs'
import { run, readJson, digest, writeJson, parseArgs, exactKeys } from './io.mjs'

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const receiptKind = 'hiverelay-stable-promotion-v1'
const fleetReceiptName = 'stable-promotion-fleet-evidence.json'

export function stablePromotion ({ bundleDir, allowedSigners, mode, env = process.env, execute = run }) {
  if (!['promote', 'verify'].includes(mode)) throw new Error('--mode must be promote or verify')
  const release = readJson(path.join(bundleDir, 'release-evidence.json'))
  assertArtifactSurfaceState(release)
  if (release.release.prerelease || release.release.candidate) throw new Error('Stable promotion requires a GA artifact with unchanged prerelease=false identity')
  const manifest = readJson(path.join(bundleDir, 'release-image-manifest-evidence.json'))
  const receiptFile = path.join(bundleDir, RELEASE_PROMOTION_EVIDENCE)
  if (mode === 'promote' && fs.existsSync(receiptFile)) return stablePromotion({ bundleDir, allowedSigners, mode: 'verify', env, execute })
  const historical = mode === 'verify' ? readJson(receiptFile) : null
  if (historical && (!Number.isFinite(Date.parse(historical.completedAt)) || Date.parse(historical.completedAt) > Date.now() + 300000)) throw new Error('Promotion completion timestamp is invalid')
  const qualified = verifyQualification({ bundleDir, release, allowedSigners, env, now: historical ? Date.parse(historical.completedAt) : Date.now() })
  const q = qualified.qualification
  const script = (name, argv, options = {}) => execute(process.execPath, [path.join(repoRoot, 'scripts', name), ...argv], { env, ...options })
  const immutableNames = ['release-evidence.json', 'release-image-manifest-evidence.json', 'release-image-smoke-evidence.json', 'umbrel-package-smoke-evidence.json', 'release-closure-evidence.json', 'blindspark.s9pk', 'blindspark-startos-0.4.s9pk', 'startos-0.4-release-evidence.json']
  const immutable = Object.fromEntries(immutableNames.map(name => [name, digest(path.join(bundleDir, name))]))
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'hiverelay-stable-promotion-'))
  try {
    const sourceSha = execute('git', ['rev-parse', 'HEAD'], { cwd: repoRoot, env }).trim()
    if (sourceSha !== release.release.tagSha || execute('git', ['status', '--porcelain', '--untracked-files=no'], { cwd: repoRoot, env }).trim()) throw new Error('Promotion must execute clean exact accepted artifact source')
    const sourceInventory = execute('git', ['show', `${sourceSha}:fleet/relays.json`], { cwd: repoRoot, env })
    if (crypto.createHash('sha256').update(sourceInventory).digest('hex') !== qualified.sourceInventoryHash) throw new Error('Reviewed intended inventory does not derive from exact release source')
    // Execute the existing semantic and authenticated live closure verifiers.
    // A child nonzero exit is never converted to a skipped qualification.
    script('verify-release-evidence.mjs', ['--bundle-dir', bundleDir], { timeout: 120000 })
    script('verify-release-handoff-evidence.mjs', ['--bundle-dir', bundleDir], { timeout: 120000 })
    const closure = () => script('verify-release-closure-evidence.mjs', ['--bundle-dir', bundleDir, '--live-github', '--expected-prerelease', 'false'], { timeout: 300000 })
    closure()
    script('verify-umbrel-runtime-review-evidence.mjs', ['--evidence', qualified.files.umbrelRuntimeReview, '--release', release.release.version, '--official-pr-url', q.distribution.officialPr.reviewUrl])
    verifyNpmBytes(release, { env, execute })
    const children = verifyImageBytes(release, manifest, repoRoot, { env, execute })
    const releaseId = githubRelease(release, { env, execute })
    const fleetFile = path.join(temp, 'fleet-rollout-evidence.json')
    const fleetArgs = ['--target', release.release.version, '--target-sha', release.release.tagSha, '--channel', 'both', '--relays', qualified.files.inventory, '--channels', qualified.files.channels, '--known-hosts', requiredEnv(env, 'HIVERELAY_FLEET_KNOWN_HOSTS_FILE'), '--ssh-key', requiredEnv(env, 'HIVERELAY_FLEET_SSH_KEY_FILE'), '--timeout-ms', '600000', '--interval-ms', '5000', '--evidence', fleetFile]
    if (release.release.publicGateway?.enabled) {
      fleetArgs.push('--gateway-evidence', requiredEnv(env, 'HIVERELAY_FLEET_GATEWAY_EVIDENCE'), '--gateway-manifest', requiredEnv(env, 'HIVERELAY_FLEET_GATEWAY_MANIFEST'), '--gateway-window-state', requiredEnv(env, 'HIVERELAY_FLEET_GATEWAY_WINDOW_STATE'), '--allowed-signers', allowedSigners)
    }
    const liveFleet = () => {
      // Always invoke the actual SSH producer. Submitted fleet JSON alone is
      // historical evidence and cannot authorize a current promotion.
      script('check-fleet-rollout.mjs', fleetArgs, { timeout: 660000, env: { ...env, HIVERELAY_FLEET_SSH_COMMAND: '', HIVERELAY_FLEET_DRY_RUN: '' } })
      const value = readJson(fleetFile)
      validateFleetProof(value, { release, inventoryHash: q.proofs.inventory.sha256, channelsHash: q.proofs.channels.sha256, names: qualified.intendedNames })
      if (release.release.publicGateway?.enabled && (value.schemaVersion !== 2 || value.publicGateway?.window?.complete !== true || value.summary?.gatewayHealthy !== qualified.intendedNames.length)) throw new Error('Enabled gateway lacks the exact completed live observation proof')
      return digest(fleetFile)
    }
    liveFleet()
    let receipt
    if (mode === 'promote') {
      script('check-release-distribution-env.mjs', ['--stage', 'stable-v1', '--channel', 'both', '--prerelease', 'false'])
      const workflow = workflowIdentity(env, release)
      const prepared = prepareDistribution({ qualification: q, bundleDir, release, workDir: temp, env, execute })
      assertFreshQualification(q)
      // Non-atomic by design. Failed or interrupted publication emits no success
      // receipt. Retry rechecks every authority and every remote surface.
      const distribution = publishDistribution({ prepared, qualification: q, bundleDir, release, workDir: temp, env, execute })
      assertFreshQualification(q)
      const labels = promoteLabels(release, manifest, repoRoot, { env, execute })
      closure()
      const fleetSha256 = liveFleet()
      fs.copyFileSync(fleetFile, path.join(bundleDir, fleetReceiptName), fs.constants.COPYFILE_EXCL)
      assertFreshQualification(q)
      receipt = { schemaVersion: 1, kind: receiptKind, status: 'verified', completedAt: new Date().toISOString(), artifact: q.artifact, immutable, qualification: { sha256: digest(path.join(bundleDir, 'release-qualification.json')), signatureSha256: digest(path.join(bundleDir, 'release-qualification.json.sig')), trustSha256: qualified.trustHash, reviewer: qualified.identity }, workflow, imageChildren: children, fleetEvidence: { path: fleetReceiptName, sha256: fleetSha256 }, distribution, labels }
      assertImmutable(bundleDir, immutable)
      writeJson(receiptFile, receipt)
    } else {
      receipt = historical
      exactKeys(receipt, ['schemaVersion', 'kind', 'status', 'completedAt', 'artifact', 'immutable', 'qualification', 'workflow', 'imageChildren', 'fleetEvidence', 'distribution', 'labels'], 'promotion receipt')
      if (receipt.schemaVersion !== 1 || receipt.kind !== receiptKind || receipt.status !== 'verified' || !isDeepStrictEqual(receipt.artifact, q.artifact) || !isDeepStrictEqual(receipt.immutable, immutable) || !isDeepStrictEqual(receipt.imageChildren, children) || receipt.labels?.githubReleaseId !== releaseId || receipt.qualification?.sha256 !== digest(path.join(bundleDir, 'release-qualification.json')) || receipt.qualification?.signatureSha256 !== digest(path.join(bundleDir, 'release-qualification.json.sig')) || receipt.qualification?.trustSha256 !== qualified.trustHash || receipt.qualification?.reviewer !== qualified.identity) throw new Error('Promotion receipt is unlinked or changed')
      exactKeys(receipt.fleetEvidence, ['path', 'sha256'], 'promotion fleet evidence')
      if (receipt.fleetEvidence.path !== fleetReceiptName || digest(path.join(bundleDir, fleetReceiptName)) !== receipt.fleetEvidence.sha256) throw new Error('Retained promotion fleet evidence changed')
      validateFleetProof(readJson(path.join(bundleDir, fleetReceiptName)), { release, inventoryHash: q.proofs.inventory.sha256, channelsHash: q.proofs.channels.sha256, names: qualified.intendedNames, now: Date.parse(receipt.completedAt) })
      verifyPublishedReceipt({ receipt, receiptFile, release, q, env, execute, temp: fs.mkdtempSync(path.join(temp, 'receipt-readback-')) })
      verifyDistributionReadback(receipt, q, { env, execute, temp })
      verifyNpmBytes(release, { latest: true, env, execute })
      verifyImageBytes(release, manifest, repoRoot, { latest: true, env, execute })
      if (githubRelease(release, { latest: true, env, execute }) !== releaseId) throw new Error('Stable GitHub pointer changed')
      closure()
      liveFleet()
      verifyPublishedReceipt({ receipt, receiptFile, release, q, env, execute, temp: fs.mkdtempSync(path.join(temp, 'receipt-terminal-')) })
      assertImmutable(bundleDir, immutable)
    }
    return receipt
  } finally {
    fs.rmSync(temp, { recursive: true, force: true })
  }
}

function assertImmutable (bundleDir, hashes) {
  for (const [name, sha] of Object.entries(hashes)) if (digest(path.join(bundleDir, name)) !== sha) throw new Error('Artifact closure changed during stable promotion')
}

function requiredEnv (env, key) {
  if (!env[key]) throw new Error(`Protected promotion input ${key} is required`)
  return env[key]
}

function workflowIdentity (env, release) {
  if (env.GITHUB_ACTIONS !== 'true' || env.GITHUB_REPOSITORY !== RELEASE_REPOSITORY || env.GITHUB_EVENT_NAME !== 'workflow_dispatch' || env.GITHUB_REF !== `refs/tags/${release.release.version}` || env.GITHUB_SHA !== release.release.tagSha || env.GITHUB_WORKFLOW_REF !== `${RELEASE_REPOSITORY}/.github/workflows/release-stable-promotion.yml@refs/tags/${release.release.version}` || !/^[1-9][0-9]*$/.test(env.GITHUB_RUN_ID || '') || !/^[1-9][0-9]*$/.test(env.GITHUB_RUN_ATTEMPT || '')) throw new Error('Promotion requires the exact protected tag-dispatched workflow authority')
  return { repository: RELEASE_REPOSITORY, path: '.github/workflows/release-stable-promotion.yml', runId: env.GITHUB_RUN_ID, runAttempt: env.GITHUB_RUN_ATTEMPT, headSha: env.GITHUB_SHA }
}

function verifyPublishedReceipt ({ receipt, receiptFile, release, q, env, execute, temp }) {
  const w = receipt.workflow
  if (w.repository !== RELEASE_REPOSITORY || w.path !== '.github/workflows/release-stable-promotion.yml' || w.headSha !== release.release.tagSha || !/^[1-9][0-9]*$/.test(w.runId) || !/^[1-9][0-9]*$/.test(w.runAttempt)) throw new Error('Promotion workflow authority is invalid')
  const live = JSON.parse(execute('gh', ['api', `repos/${RELEASE_REPOSITORY}/actions/runs/${w.runId}/attempts/${w.runAttempt}`], { env }))
  if (![live.run_started_at, live.updated_at].every(t => Number.isFinite(Date.parse(t)))) throw new Error('Live workflow timestamps are invalid')
  if (String(live.id) !== w.runId || String(live.run_attempt) !== w.runAttempt || ![w.path, `${w.path}@${release.release.version}`, `${w.path}@refs/tags/${release.release.version}`].includes(live.path) || live.head_sha !== w.headSha || live.head_branch !== release.release.version || live.event !== 'workflow_dispatch' || live.status !== 'completed' || live.conclusion !== 'success' || Date.parse(live.run_started_at) < Date.parse(q.issuedAt) || Date.parse(live.run_started_at) > Date.parse(receipt.completedAt) || Date.parse(live.updated_at) < Date.parse(receipt.completedAt)) throw new Error('Live promotion run does not authorize the receipt timestamp/source/attempt')
  const artifactName = `stable-promotion-${release.release.version}-${w.runId}-${w.runAttempt}`
  const inventory = JSON.parse(execute('gh', ['api', `repos/${RELEASE_REPOSITORY}/actions/runs/${w.runId}/artifacts?name=${artifactName}`], { env }))
  const artifacts = inventory.artifacts?.filter(a => a.name === artifactName)
  if (inventory.total_count !== 1 || artifacts?.length !== 1) throw new Error('Promotion lacks exactly one immutable run artifact')
  const artifact = artifacts[0]
  if (!Number.isSafeInteger(artifact.id) || artifact.id < 1 || artifact.expired !== false || !/^sha256:[a-f0-9]{64}$/.test(artifact.digest || '') || artifact.workflow_run?.head_sha !== w.headSha) throw new Error('Promotion immutable artifact authority is invalid')
  const archive = path.join(temp, 'promotion.zip')
  const bytes = execute('gh', ['api', `repos/${RELEASE_REPOSITORY}/actions/artifacts/${artifact.id}/zip`], { env, encoding: null })
  fs.writeFileSync(archive, bytes)
  if (`sha256:${digest(archive)}` !== artifact.digest || fs.statSync(archive).size !== artifact.size_in_bytes) throw new Error('Promotion immutable artifact download changed')
  if (!isDeepStrictEqual(execute('unzip', ['-Z1', archive], { env }).trim().split(/\r?\n/).sort(), [RELEASE_PROMOTION_EVIDENCE, fleetReceiptName].sort())) throw new Error('Promotion artifact contains unexpected entries')
  const artifactDir = path.join(temp, 'immutable-promotion')
  fs.mkdirSync(artifactDir)
  execute('unzip', ['-q', archive, '-d', artifactDir], { env })
  if (digest(path.join(artifactDir, RELEASE_PROMOTION_EVIDENCE)) !== digest(receiptFile)) throw new Error('Promotion receipt differs from immutable workflow artifact')
  if (digest(path.join(artifactDir, fleetReceiptName)) !== receipt.fleetEvidence.sha256) throw new Error('Promotion fleet receipt differs from immutable workflow artifact')
  const downloaded = path.join(temp, RELEASE_PROMOTION_EVIDENCE)
  for (const [local, published] of Object.entries(promotionAssetNames(w))) execute('gh', ['release', 'download', release.release.version, '--repo', RELEASE_REPOSITORY, '--pattern', published, '--output', path.join(temp, local)], { env })
  if (digest(path.join(temp, fleetReceiptName)) !== receipt.fleetEvidence.sha256) throw new Error('Current published fleet receipt differs from accepted bytes')
  if (digest(downloaded) !== digest(receiptFile)) throw new Error('Current published promotion receipt differs from supplied bytes')
}

function verifyDistributionReadback (receipt, q, { env, execute, temp }) {
  const expected = q.distribution.repositories
  if (!isDeepStrictEqual(receipt.distribution.repositories.map(r => r.repository).sort(), expected.map(r => r.repository).sort())) throw new Error('Promotion receipt omits a distribution target')
  for (const row of receipt.distribution.repositories) {
    const plan = expected.find(p => p.repository === row.repository)
    if (row.role !== plan.role || row.branch !== plan.branch || row.treeSha !== plan.treeSha || !/^[a-f0-9]{40}$/.test(row.commit)) throw new Error('Promotion distribution result differs from signed review')
    const remote = execute('git', ['ls-remote', '--exit-code', `https://github.com/${row.repository}.git`, `refs/heads/${row.branch}`], { env }).trim().split(/\s/)[0]
    const commit = JSON.parse(execute('gh', ['api', `repos/${row.repository}/git/commits/${row.commit}`], { env }))
    if (remote !== row.commit || commit.tree?.sha !== row.treeSha) throw new Error('Current distributed repository differs from reviewed tree')
  }
  const plan = q.distribution
  verifyOriginalDeviceTree({ plan, release: { image: q.artifact.image }, env, execute })
  if (!isDeepStrictEqual(receipt.distribution.startosRegistry, plan.startosRegistry)) throw new Error('Registry receipt differs from signed target')
  if (!/^https:\/\/github\.com\/getumbrel\/umbrel-apps\/pull\/[1-9][0-9]*$/.test(receipt.distribution.officialPr.url) || !isDeepStrictEqual({ ...receipt.distribution.officialPr, url: plan.officialPr.url, commit: undefined }, { ...plan.officialPr, commit: undefined })) throw new Error('Official promotion receipt differs from original review binding')
  const official = receipt.distribution.repositories.find(r => r.role === 'umbrel-official')
  const pr = JSON.parse(execute('gh', ['pr', 'view', receipt.distribution.officialPr.url, '--json', 'state,isDraft,baseRefName,headRepositoryOwner,headRefName,headRefOid'], { env }))
  if (pr.state !== 'OPEN' || pr.isDraft !== true || pr.baseRefName !== plan.officialPr.base || pr.headRepositoryOwner?.login !== plan.officialPr.headOwner || pr.headRefName !== plan.officialPr.headRef || pr.headRefOid !== official.commit) throw new Error('Official draft readback changed')
  const file = path.join(temp, 'registry-current.s9pk')
  execute('curl', ['--fail', '--silent', '--show-error', '--proto', '=https', '--max-time', '60', '--output', file, plan.startosRegistry.packageUrl], { env })
  if (digest(file) !== plan.startosRegistry.packageSha256) throw new Error('Current StartOS registry bytes differ')
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = parseArgs(process.argv.slice(2), ['--bundle-dir', '--allowed-signers', '--mode'])
    if (!args['--bundle-dir']) throw new Error('--bundle-dir is required')
    stablePromotion({ bundleDir: path.resolve(args['--bundle-dir']), allowedSigners: args['--allowed-signers'] || process.env.HIVERELAY_PROMOTION_ALLOWED_SIGNERS_FILE, mode: args['--mode'] })
    console.log('Exact existing-byte stable promotion verified')
  } catch (error) {
    console.error(error.message)
    process.exitCode = 1
  }
}
