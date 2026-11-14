import fs from 'node:fs'
import path from 'node:path'
import { isDeepStrictEqual } from 'node:util'
import { run, readJson, digest, exactKeys } from './io.mjs'

export const QUALIFICATION_NAMESPACE = 'hiverelay-stable-qualification-v1'
export const MAX_QUALIFICATION_AGE_MS = 30 * 60 * 1000
const CONSUMERS = ['pearbrowser-desktop', 'pearbrowser', 'peerit']
const CONSUMER_CHECKS = ['clean-install', 'seed', 'gateway', 'restart', 'browser-compatibility', 'migration', 'rollback']
const REHEARSALS = ['restore', 'device-rebind', 'rollback', 'offline-author-fresh-reader', 'capacity-replica-floor']

export function boundFile (bundleDir, ref) {
  exactKeys(ref, ['path', 'sha256'], 'evidence reference')
  if (!/^[a-f0-9]{64}$/.test(ref.sha256) || typeof ref.path !== 'string' || path.isAbsolute(ref.path)) throw new Error('Invalid evidence reference')
  const root = fs.realpathSync(bundleDir)
  const file = path.resolve(root, ref.path)
  if (!file.startsWith(root + path.sep) || fs.realpathSync(file) !== file) throw new Error('Evidence reference escapes its immutable bundle or follows a symlink')
  const stat = fs.lstatSync(file)
  if (!stat.isFile() || stat.size < 1 || stat.size > 16 * 1024 * 1024 || digest(file) !== ref.sha256) throw new Error('Evidence reference is absent, oversized or changed')
  return file
}

export function assertFreshQualification (value, now = Date.now()) {
  const issued = Date.parse(value.issuedAt)
  const expires = Date.parse(value.expiresAt)
  if (!Number.isFinite(issued) || !Number.isFinite(expires) || issued > now + 300000 ||
      issued < now - MAX_QUALIFICATION_AGE_MS || expires <= now || expires <= issued || expires - issued > MAX_QUALIFICATION_AGE_MS) {
    throw new Error('Independent qualification is expired, stale or future dated')
  }
}

export function verifyQualification ({ bundleDir, release, allowedSigners, env = process.env, now = Date.now() }) {
  const file = path.join(bundleDir, 'release-qualification.json')
  const signature = path.join(bundleDir, 'release-qualification.json.sig')
  const trustHash = env.HIVERELAY_PROMOTION_ALLOWED_SIGNERS_SHA256
  const identity = env.HIVERELAY_PROMOTION_SIGNER_IDENTITY
  if (!/^[a-f0-9]{64}$/.test(trustHash || '') || !/^[A-Za-z0-9@._-]{1,128}$/.test(identity || '') || !allowedSigners) {
    throw new Error('Independent protected-environment qualification signer authority is unavailable')
  }
  const trustStat = fs.lstatSync(allowedSigners)
  if (!trustStat.isFile() || trustStat.isSymbolicLink() || trustStat.size > 65536 || digest(allowedSigners) !== trustHash) throw new Error('Qualification trust pin mismatch')
  const q = readJson(file)
  const signatureStat = fs.lstatSync(signature)
  if (!signatureStat.isFile() || signatureStat.isSymbolicLink() || signatureStat.size > 65536) throw new Error('Invalid detached qualification signature')
  run('/usr/bin/ssh-keygen', ['-Y', 'verify', '-f', allowedSigners, '-I', identity, '-n', QUALIFICATION_NAMESPACE, '-s', signature], { input: fs.readFileSync(file) })
  exactKeys(q, ['schemaVersion', 'kind', 'issuedAt', 'expiresAt', 'producer', 'reviewer', 'artifact', 'proofs', 'distribution'], 'qualification')
  if (q.schemaVersion !== 1 || q.kind !== QUALIFICATION_NAMESPACE || q.reviewer !== identity || !q.producer || q.producer === q.reviewer) throw new Error('Qualification lacks an independent authorized reviewer')
  assertFreshQualification(q, now)
  const artifact = {
    version: release.release.version,
    tagSha: release.release.tagSha,
    releaseEvidenceSha256: digest(path.join(bundleDir, 'release-evidence.json')),
    closureSha256: digest(path.join(bundleDir, 'release-closure-evidence.json')),
    imageManifestSha256: digest(path.join(bundleDir, 'release-image-manifest-evidence.json')),
    image: release.image,
    packages: release.release.stage.packages
  }
  if (!isDeepStrictEqual(q.artifact, artifact)) throw new Error('Qualification does not bind the exact accepted artifact closure and package/image identities')
  exactKeys(q.proofs, ['consumers', 'canary', 'fleet', 'inventory', 'inventoryPlan', 'channels', 'rehearsals', 'umbrelRuntimeReview'], 'qualification proofs')
  const files = Object.fromEntries(Object.entries(q.proofs).map(([name, ref]) => [name, boundFile(bundleDir, ref)]))
  const consumers = readJson(files.consumers)
  if (consumers.kind !== 'hiverelay-reference-consumer-proof-v1' || !isDeepStrictEqual(consumers.artifact, artifact) ||
      !Array.isArray(consumers.consumers) || !isDeepStrictEqual(consumers.consumers.map(row => row.name).sort(), [...CONSUMERS].sort())) {
    throw new Error('Reference-consumer evidence omits required consumers or exact artifact identities')
  }
  for (const consumer of consumers.consumers) {
    if (!/^[a-f0-9]{40}$/.test(consumer.sourceCommit || '') || !['changed-source', 'reviewed-no-change'].includes(consumer.sourceDisposition) ||
        !consumer.runtime || !consumer.platform || consumer.execution !== 'actual-consumer') throw new Error('Consumer source or execution provenance is absent')
    boundFile(bundleDir, consumer.sourceReceipt)
    validateChecks(consumer.checks, CONSUMER_CHECKS, bundleDir, q)
  }
  const inventory = readJson(files.inventory)
  const intended = inventory.relays || inventory
  if (!Array.isArray(intended) || intended.length < 1 || intended.length > 1000 ||
      intended.some(row => !row.name || !(row.tailnet || row.publicIp) || !['canary', 'stable'].includes(row.channel)) ||
      new Set(intended.map(row => row.name)).size !== intended.length) throw new Error('Signed intended inventory must enumerate every addressed canary/stable relay without omissions or holds')
  const inventoryPlan = readJson(files.inventoryPlan)
  exactKeys(inventoryPlan, ['schemaVersion', 'kind', 'sourceTagSha', 'sourceInventory', 'excluded'], 'intended inventory plan')
  if (inventoryPlan.schemaVersion !== 1 || inventoryPlan.kind !== 'hiverelay-intended-fleet-v1' || inventoryPlan.sourceTagSha !== release.release.tagSha || !Array.isArray(inventoryPlan.excluded)) throw new Error('Intended inventory lacks its source-bound reviewed disposition plan')
  const sourceInventoryFile = boundFile(bundleDir, inventoryPlan.sourceInventory)
  const sourceValue = readJson(sourceInventoryFile)
  const sourceRows = sourceValue.relays || sourceValue
  if (!Array.isArray(sourceRows) || !sourceRows.length || sourceRows.length > 1000 || new Set(sourceRows.map(r => r.name)).size !== sourceRows.length) throw new Error('Source fleet inventory is invalid')
  const includedNames = intended.map(r => r.name)
  const disposedNames = inventoryPlan.excluded.map(r => r.name)
  if (!isDeepStrictEqual([...includedNames, ...disposedNames].sort(), sourceRows.map(r => r.name).sort())) throw new Error('Intended fleet omits source relays without explicit reviewed disposition')
  for (const excluded of inventoryPlan.excluded) {
    exactKeys(excluded, ['name', 'disposition', 'reason', 'receipt'], 'fleet disposition')
    if (!['hold-not-intended', 'retired'].includes(excluded.disposition) || typeof excluded.reason !== 'string' || !excluded.reason.trim()) throw new Error('Excluded relay lacks an explicit disposition')
    boundFile(bundleDir, excluded.receipt)
  }
  for (const relay of intended) {
    const source = sourceRows.find(r => r.name === relay.name)
    if ((source.tailnet || source.publicIp) !== (relay.tailnet || relay.publicIp)) throw new Error('Intended relay address differs from its source inventory')
  }
  const fleet = readJson(files.fleet)
  validateFleetProof(fleet, {
    release,
    inventoryHash: q.proofs.inventory.sha256,
    channelsHash: q.proofs.channels.sha256,
    names: intended.map(row => row.name),
    now,
    requireFresh: true
  })
  const channels = readJson(files.channels)
  if (channels.canary !== release.release.version || channels.stable !== release.release.version) throw new Error('Qualified canary and stable channels must both name the exact release')
  const canary = readJson(files.canary)
  if (!intended.some(row => row.channel === 'canary')) throw new Error('Canary cohort is empty')
  const canaryChannelsFile = boundFile(bundleDir, canary.channels)
  if (readJson(canaryChannelsFile).canary !== release.release.version) throw new Error('Canary channel snapshot targets another release')
  const started = Date.parse(canary.startedAt)
  const completed = Date.parse(canary.completedAt)
  const interval = canary.maximumSampleGapMillis
  if (canary.kind !== 'hiverelay-canary-observation-v1' || !isDeepStrictEqual(canary.artifact, artifact) ||
      !Number.isSafeInteger(canary.requiredObservationMillis) || canary.requiredObservationMillis < 86400000 ||
      !Number.isSafeInteger(interval) || interval < 5000 || interval > 300000 || !Number.isFinite(started) || !Number.isFinite(completed) ||
      completed - started < canary.requiredObservationMillis || completed > Date.parse(q.issuedAt) ||
      completed < now - MAX_QUALIFICATION_AGE_MS || !Array.isArray(canary.samples) || canary.samples.length < 2 || canary.samples.length > 20000) {
    throw new Error('Canary proof lacks a complete fresh observation window')
  }
  let previous = started
  for (const ref of canary.samples) {
    const sample = readJson(boundFile(bundleDir, ref))
    validateFleetProof(sample, {
      release,
      inventoryHash: q.proofs.inventory.sha256,
      channelsHash: canary.channels.sha256,
      names: intended.filter(row => row.channel === 'canary').map(row => row.name),
      now,
      requireFresh: false
    })
    const at = Date.parse(sample.generatedAt)
    if (sample.relays.some(r => Date.parse(r.observedAt) < at - interval)) throw new Error('Canary sample reuses an observation older than its sample interval')
    if (at < previous || at - previous > interval || at > completed) throw new Error('Canary samples have a gap, regression or exceed the observation window')
    previous = at
  }
  if (completed - previous > interval) throw new Error('Canary observation final sample is incomplete')
  const rehearsals = readJson(files.rehearsals)
  if (rehearsals.kind !== 'hiverelay-release-rehearsal-proof-v1' || !isDeepStrictEqual(rehearsals.artifact, artifact)) throw new Error('Rehearsal evidence is unlinked')
  validateChecks(rehearsals.checks, REHEARSALS, bundleDir, q)
  return { qualification: q, files, sourceInventoryHash: inventoryPlan.sourceInventory.sha256, intendedNames: intended.map(row => row.name).sort(), trustHash, identity }
}

function validateChecks (checks, required, bundleDir, q) {
  if (!Array.isArray(checks) || !isDeepStrictEqual(checks.map(c => c.name).sort(), [...required].sort())) throw new Error('Qualification proof checks are incomplete or duplicated')
  for (const check of checks) {
    if (check.status !== 'passed' || check.exitCode !== 0 || check.execution !== 'actual' || !check.command ||
        !Number.isFinite(Date.parse(check.completedAt)) || Date.parse(check.completedAt) > Date.parse(q.issuedAt)) throw new Error('Qualification proof does not contain successful actual command evidence')
    boundFile(bundleDir, check.rawOutput)
  }
}

export function validateFleetProof (fleet, { release, inventoryHash, channelsHash, names, now = Date.now(), requireFresh = true }) {
  if (![1, 2].includes(fleet.schemaVersion) || fleet.status !== 'verified' || fleet.error ||
      fleet.target?.tag !== release.release.version || fleet.target?.version !== release.release.semver || fleet.target?.sha !== release.release.tagSha ||
      fleet.inventory?.sha256 !== inventoryHash || fleet.channelConfig?.sha256 !== channelsHash ||
      !Array.isArray(fleet.relays) || !isDeepStrictEqual(fleet.relays.map(r => r.name).sort(), [...names].sort()) ||
      !isDeepStrictEqual([...fleet.inventory.relayNames].sort(), [...names].sort())) throw new Error('Fleet proof is not the exact complete intended release/inventory')
  if (!names.length) throw new Error('Fleet proof cohort is empty')
  for (const [key, min, max] of [['timeoutMs', 600000, 14400000], ['intervalMs', 5000, 300000], ['sshTimeoutMs', 5000, 120000]]) {
    if (!Number.isSafeInteger(fleet.probes?.[key]) || fleet.probes[key] < min || fleet.probes[key] > max) throw new Error('Fleet probe timing differs from the existing verified producer contract')
  }
  const generated = Date.parse(fleet.generatedAt)
  if (!Number.isFinite(generated) || generated > now + 300000 || (requireFresh && generated < now - MAX_QUALIFICATION_AGE_MS)) throw new Error('Fleet proof is stale or future dated')
  for (const field of ['total', 'updated', 'packageVersionMatches', 'healthy', 'runtimeVersionMatches']) {
    if (fleet.summary?.[field] !== names.length) throw new Error('Fleet summary omits intended relays')
  }
  for (const relay of fleet.relays) {
    if (relay.packageVersion !== release.release.version || relay.healthVersion !== release.release.semver ||
        relay.headSha !== release.release.tagSha || relay.targetSha !== release.release.tagSha ||
        relay.updated !== true || relay.packageVersionMatches !== true || relay.healthy !== true || relay.runtimeVersionMatches !== true || relay.error || relay.note !== 'ok' ||
        !Number.isFinite(Date.parse(relay.observedAt)) || Date.parse(relay.observedAt) > generated ||
        Date.parse(relay.observedAt) < generated - MAX_QUALIFICATION_AGE_MS ||
        (requireFresh && Date.parse(relay.observedAt) < now - MAX_QUALIFICATION_AGE_MS)) throw new Error('Fleet relay observation differs from exact qualified source')
  }
}
