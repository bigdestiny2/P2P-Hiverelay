import test from 'brittle'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { encodeHiveAppKey } from '../../packages/core/gateway/hive-host.js'
import { createPublicT1OpsFixture } from '../fixtures/public-hive-gateway-ops.js'

const tool = path.resolve('scripts/promote-fleet-channel.mjs')
const source = readFileSync(tool, 'utf8')
const canRunFunctional = have('git') && have('ssh-keygen')

test('fleet promotion tool exposes no push or deploy mutation path', (t) => {
  t.ok(source.includes("channel !== 'canary' && channel !== 'stable'"))
  t.ok(source.includes('writeChannelsAtomic(channelsPath'))
  t.absent(source.includes("'push'"))
  t.absent(source.includes("'commit'"))
  t.absent(source.includes('systemctl'))
})

test('fleet promotion dry-run validates a signed tag without filesystem side effects', { skip: !canRunFunctional }, (t) => {
  const fixture = createFixture(t)
  const before = readFileSync(fixture.channelsPath)
  const result = promote(fixture, 'canary', fixture.target, ['--dry-run'])

  t.is(result.status, 0, result.stderr)
  const report = JSON.parse(result.stdout)
  t.is(report.status, 'dry-run')
  t.is(report.channel, 'canary')
  t.is(report.target, fixture.target)
  t.is(report.targetSha, fixture.targetSha)
  t.is(report.wouldChange, true)
  t.ok(readFileSync(fixture.channelsPath).equals(before), 'dry-run does not rewrite channels.json')
  t.absent(readdirSync(path.dirname(fixture.channelsPath)).some(name => /\.(?:lock|tmp-)/.test(name)),
    'dry-run creates no lock or temporary file')
})

test('canary promotion atomically updates only canary and preserves unrelated data', { skip: !canRunFunctional }, (t) => {
  const fixture = createFixture(t)
  const beforeHead = git(fixture.repo, ['rev-parse', 'HEAD']).stdout.trim()
  chmodSync(fixture.channelsPath, 0o640)

  const result = promote(fixture, 'canary', fixture.target)
  t.is(result.status, 0, result.stderr)
  const report = JSON.parse(result.stdout)
  const channels = readJson(fixture.channelsPath)

  t.is(report.status, 'updated')
  t.is(channels.canary, fixture.target)
  t.is(channels.stable, 'v1.0.0', 'stable is never changed implicitly')
  t.alike(channels.routing, { wave: ['one', 'two'], hold: true })
  t.is(channels._doc, 'fixture control plane')
  t.is(statSync(fixture.channelsPath).mode & 0o777, 0o640, 'atomic replacement preserves file mode')
  t.is(git(fixture.repo, ['rev-parse', 'HEAD']).stdout.trim(), beforeHead, 'tool does not create a commit')
  t.absent(readdirSync(path.dirname(fixture.channelsPath)).some(name => /\.(?:lock|tmp-)/.test(name)),
    'successful promotion cleans atomic-write artifacts')
})

test('enabled tagged gateway manifest automatically gates canary promotion and current inventory mapping', { skip: !canRunFunctional }, (t) => {
  const fixture = createFixture(t, {}, { gatewayEnabled: true, publicT1: true })
  const result = promote(fixture, 'canary', fixture.target)
  t.is(result.status, 0, result.stderr)
  t.is(JSON.parse(result.stdout).publicGatewayRequired, true,
    'the signed manifest forces the gate without an operator flag')

  const drifted = createFixture(t, {}, { gatewayEnabled: true, publicT1: true })
  const before = readFileSync(drifted.channelsPath)
  const inventory = readJson(drifted.relaysPath)
  inventory.relays[0].channel = 'stable'
  writeFileSync(drifted.relaysPath, JSON.stringify(inventory, null, 2) + '\n')
  const rejected = promote(drifted, 'canary', drifted.target)
  t.not(rejected.status, 0)
  t.ok(rejected.stderr.includes('current full fleet inventory does not contain signed gateway cohort relay'))
  t.ok(readFileSync(drifted.channelsPath).equals(before), 'inventory drift cannot move canary')
})

test('public-t1 gateway promotion derives the canonical tagged operator-contract binding', { skip: !canRunFunctional }, (t) => {
  const fixture = createFixture(t, {}, { gatewayEnabled: true, publicT1: true })
  const result = promote(fixture, 'canary', fixture.target, ['--dry-run'])
  t.is(result.status, 0, result.stderr)
  t.alike(JSON.parse(result.stdout).operatorContracts, [fixture.operatorBinding])

  const missing = createFixture(t, {}, {
    gatewayEnabled: true,
    publicT1: true,
    omitOperatorContract: true
  })
  const missingResult = promote(missing, 'canary', missing.target, ['--dry-run'])
  t.not(missingResult.status, 0)
  t.ok(missingResult.stderr.includes('operator contract for canary-1') &&
    missingResult.stderr.includes('missing from the verified release commit'))

  const drifted = createFixture(t, {}, {
    gatewayEnabled: true,
    publicT1: true,
    driftOperatorContract: true
  })
  const driftedResult = promote(drifted, 'canary', drifted.target, ['--dry-run'])
  t.not(driftedResult.status, 0)
  t.ok(driftedResult.stderr.includes('digest does not match'))

  const legacy = createFixture(t, {}, { gatewayEnabled: true })
  const legacyResult = promote(legacy, 'canary', legacy.target, ['--dry-run'])
  t.not(legacyResult.status, 0)
  t.ok(legacyResult.stderr.includes('must use public-t1-gateway with a canonical operator contract digest'))
})

test('missing or explicitly disabled tagged gateway manifests preserve legacy canary promotion', { skip: !canRunFunctional }, (t) => {
  for (const options of [{}, { omitGatewayManifest: true }]) {
    const fixture = createFixture(t, {}, options)
    const result = promote(fixture, 'canary', fixture.target, ['--dry-run'])
    t.is(result.status, 0, result.stderr)
    t.is(JSON.parse(result.stdout).publicGatewayRequired, false)
  }
})

test('invalid enabled tagged gateway manifest cannot opt out of canary validation', { skip: !canRunFunctional }, (t) => {
  const fixture = createFixture(t, {}, { gatewayEnabled: true, publicT1: true, gatewayCohortChannel: 'stable' })
  const before = readFileSync(fixture.channelsPath)
  const result = promote(fixture, 'canary', fixture.target)
  t.not(result.status, 0)
  t.ok(result.stderr.includes('must include at least one canary relay'))
  t.ok(readFileSync(fixture.channelsPath).equals(before))
})

test('stable promotion fails closed without exact verified canary evidence', { skip: !canRunFunctional }, (t) => {
  const fixture = createFixture(t, { canary: 'v1.2.3' })
  const before = readFileSync(fixture.channelsPath)

  const missing = promote(fixture, 'stable', fixture.target)
  t.not(missing.status, 0)
  t.ok(missing.stderr.includes('--canary-evidence is required'))
  t.ok(readFileSync(fixture.channelsPath).equals(before))

  const evidencePath = path.join(fixture.work, 'canary-evidence.json')
  const failed = rolloutEvidence(fixture, { status: 'failed' })
  writeFileSync(evidencePath, JSON.stringify(failed))
  const failedResult = promote(fixture, 'stable', fixture.target, ['--canary-evidence', evidencePath])
  t.not(failedResult.status, 0)
  t.ok(failedResult.stderr.includes('verified pass status'))
  t.ok(readFileSync(fixture.channelsPath).equals(before))

  const wrongTarget = rolloutEvidence(fixture, {
    target: { tag: 'v1.2.4', version: '1.2.4', sha: fixture.targetSha, channel: 'canary' }
  })
  writeFileSync(evidencePath, JSON.stringify(wrongTarget))
  const wrongResult = promote(fixture, 'stable', fixture.target, ['--canary-evidence', evidencePath])
  t.not(wrongResult.status, 0)
  t.ok(wrongResult.stderr.includes(`must target ${fixture.target}`))
  t.ok(readFileSync(fixture.channelsPath).equals(before), 'wrong-version evidence cannot mutate stable')
})

test('stable promotion accepts current all-green canary evidence for the same signed commit', { skip: !canRunFunctional }, (t) => {
  const fixture = createFixture(t, { canary: 'v1.2.3' })
  const evidencePath = path.join(fixture.work, 'canary-evidence.json')
  writeFileSync(evidencePath, JSON.stringify(rolloutEvidence(fixture), null, 2) + '\n')

  const result = promote(fixture, 'stable', fixture.target, ['--canary-evidence', evidencePath])
  t.is(result.status, 0, result.stderr)
  const report = JSON.parse(result.stdout)
  const channels = readJson(fixture.channelsPath)

  t.is(report.status, 'updated')
  t.is(report.canaryEvidence.status, 'verified')
  t.is(report.canaryEvidence.relayCount, 1)
  t.is(channels.stable, fixture.target)
  t.is(channels.canary, fixture.target)
  t.alike(channels.routing, { wave: ['one', 'two'], hold: true })
})

test('enabled tagged gateway manifest automatically requires all-green stable evidence', { skip: !canRunFunctional }, (t) => {
  const fixture = createFixture(t, { canary: 'v1.2.3' }, { gatewayEnabled: true, publicT1: true })
  const evidencePath = path.join(fixture.work, 'canary-evidence.json')
  const statePath = path.join(fixture.work, 'gateway-window-state.json')
  const requiredArgs = [
    '--canary-evidence', evidencePath,
    '--gateway-window-state', statePath,
    '--relays', fixture.relaysPath
  ]

  writeFileSync(evidencePath, JSON.stringify(rolloutEvidence(fixture)))
  const missingState = promote(fixture, 'stable', fixture.target, ['--canary-evidence', evidencePath])
  t.not(missingState.status, 0)
  t.ok(missingState.stderr.includes('--gateway-window-state is required'))

  gatewayRolloutEvidence(fixture, statePath)
  writeFileSync(evidencePath, JSON.stringify(rolloutEvidence(fixture)))
  const legacy = promote(fixture, 'stable', fixture.target, requiredArgs)
  t.not(legacy.status, 0)
  t.ok(legacy.stderr.includes('gateway evidence gate was enabled'))

  const red = gatewayRolloutEvidence(fixture, statePath)
  red.summary.gatewayHealthy = 0
  red.relays[0].gatewayHealthy = false
  writeFileSync(evidencePath, JSON.stringify(red))
  const redResult = promote(fixture, 'stable', fixture.target, requiredArgs)
  t.not(redResult.status, 0)
  t.ok(redResult.stderr.includes('gatewayHealthy is not fully green'))

  writeFileSync(evidencePath, JSON.stringify(gatewayRolloutEvidence(fixture, statePath)))
  const green = promote(fixture, 'stable', fixture.target, requiredArgs)
  t.is(green.status, 0, green.stderr)
  const report = JSON.parse(green.stdout)
  t.is(report.publicGatewayRequired, true)
  t.is(report.canaryEvidence.publicGateway.status, 'verified')
  t.is(report.canaryEvidence.publicGateway.relayCount, 1)
  t.is(report.canaryEvidence.publicGateway.manifestSha256, fixture.gatewayManifestSha256)
  t.is(report.canaryEvidence.publicGateway.window.complete, true)
  t.is(readJson(fixture.channelsPath).stable, fixture.target)
})

test('stable promotion rejects stale channel snapshots and red relay evidence', { skip: !canRunFunctional }, (t) => {
  const fixture = createFixture(t, { canary: 'v1.2.3' })
  const evidencePath = path.join(fixture.work, 'canary-evidence.json')
  const before = readFileSync(fixture.channelsPath)

  writeFileSync(evidencePath, JSON.stringify(rolloutEvidence(fixture, {
    channelConfig: { sha256: '0'.repeat(64), targets: { canary: fixture.target } }
  })))
  const stale = promote(fixture, 'stable', fixture.target, ['--canary-evidence', evidencePath])
  t.not(stale.status, 0)
  t.ok(stale.stderr.includes('current channel configuration'))

  const red = rolloutEvidence(fixture)
  red.summary.healthy = 0
  red.relays[0].healthy = false
  writeFileSync(evidencePath, JSON.stringify(red))
  const redResult = promote(fixture, 'stable', fixture.target, ['--canary-evidence', evidencePath])
  t.not(redResult.status, 0)
  t.ok(redResult.stderr.includes('summary healthy is not fully green'))
  t.ok(readFileSync(fixture.channelsPath).equals(before))
})

test('stable promotion requires fresh generatedAt and relay observedAt timestamps', { skip: !canRunFunctional }, (t) => {
  const fixture = createFixture(t, { canary: 'v1.2.3' })
  const evidencePath = path.join(fixture.work, 'canary-evidence.json')
  const args = ['--canary-evidence', evidencePath]
  const before = readFileSync(fixture.channelsPath)

  const staleGenerated = rolloutEvidence(fixture)
  staleGenerated.generatedAt = new Date(Date.now() - 31 * 60 * 1000).toISOString()
  writeFileSync(evidencePath, JSON.stringify(staleGenerated))
  const staleGeneratedResult = promote(fixture, 'stable', fixture.target, args)
  t.not(staleGeneratedResult.status, 0)
  t.ok(staleGeneratedResult.stderr.includes('generatedAt is older than 30 minutes'))

  const staleRelay = rolloutEvidence(fixture)
  staleRelay.relays[0].observedAt = new Date(Date.now() - 31 * 60 * 1000).toISOString()
  writeFileSync(evidencePath, JSON.stringify(staleRelay))
  const staleRelayResult = promote(fixture, 'stable', fixture.target, args)
  t.not(staleRelayResult.status, 0)
  t.ok(staleRelayResult.stderr.includes('observedAt is older than 30 minutes'))

  const future = rolloutEvidence(fixture)
  future.generatedAt = new Date(Date.now() + 6 * 60 * 1000).toISOString()
  writeFileSync(evidencePath, JSON.stringify(future))
  const futureResult = promote(fixture, 'stable', fixture.target, args)
  t.not(futureResult.status, 0)
  t.ok(futureResult.stderr.includes('more than five minutes in the future'))
  t.ok(readFileSync(fixture.channelsPath).equals(before), 'freshness failures never mutate stable')
})

test('public gateway stable promotion rejects manifest, identity, and continuity drift', { skip: !canRunFunctional }, (t) => {
  const fixture = createFixture(t, { canary: 'v1.2.3' }, { gatewayEnabled: true, publicT1: true })
  const evidencePath = path.join(fixture.work, 'canary-evidence.json')
  const statePath = path.join(fixture.work, 'gateway-window-state.json')
  const args = [
    '--canary-evidence', evidencePath,
    '--gateway-window-state', statePath,
    '--relays', fixture.relaysPath
  ]

  const manifestDrift = gatewayRolloutEvidence(fixture, statePath)
  manifestDrift.publicGateway.manifest.sha256 = '0'.repeat(64)
  writeFileSync(evidencePath, JSON.stringify(manifestDrift))
  const manifestResult = promote(fixture, 'stable', fixture.target, args)
  t.not(manifestResult.status, 0)
  t.ok(manifestResult.stderr.includes('manifest binding is stale or drifted'))

  const identityDrift = gatewayRolloutEvidence(fixture, statePath)
  identityDrift.relays[0].gateway.origin = 'https://drift.example'
  writeFileSync(evidencePath, JSON.stringify(identityDrift))
  const identityResult = promote(fixture, 'stable', fixture.target, args)
  t.not(identityResult.status, 0)
  t.ok(identityResult.stderr.includes('origin drifted from the signed manifest'))

  const incomplete = gatewayRolloutEvidence(fixture, statePath)
  const state = readJson(statePath)
  state.relays[0].samples = [state.relays[0].samples.at(-1)]
  writeFileSync(statePath, JSON.stringify(state, null, 2) + '\n')
  incomplete.publicGateway.windowStateSha256 = sha256(readFileSync(statePath))
  writeFileSync(evidencePath, JSON.stringify(incomplete))
  const incompleteResult = promote(fixture, 'stable', fixture.target, args)
  t.not(incompleteResult.status, 0)
  t.ok(incompleteResult.stderr.includes('requires multiple bounded samples'))
})

test('public gateway stable promotion requires controller-collected continuity', { skip: !canRunFunctional }, (t) => {
  const fixture = createFixture(t, { canary: 'v1.2.3' }, { gatewayEnabled: true, publicT1: true })
  const evidencePath = path.join(fixture.work, 'canary-evidence.json')
  const statePath = path.join(fixture.work, 'gateway-window-state.json')
  const args = [
    '--canary-evidence', evidencePath,
    '--gateway-window-state', statePath,
    '--relays', fixture.relaysPath
  ]

  const missingCollected = gatewayRolloutEvidence(fixture, statePath)
  const missingState = readJson(statePath)
  delete missingState.relays[0].samples[0].collectedAt
  writeFileSync(statePath, JSON.stringify(missingState, null, 2) + '\n')
  missingCollected.publicGateway.windowStateSha256 = sha256(readFileSync(statePath))
  writeFileSync(evidencePath, JSON.stringify(missingCollected))
  const missing = promote(fixture, 'stable', fixture.target, args)
  t.not(missing.status, 0)
  t.ok(missing.stderr.includes('sample collectedAt must be a canonical ISO timestamp'))

  const compressed = gatewayRolloutEvidence(fixture, statePath)
  const compressedState = readJson(statePath)
  const compressedStart = Date.now() - 10 * 60 * 1000
  const compressedStep = Math.floor((10 * 60 * 1000) / (compressedState.relays[0].samples.length - 1))
  compressedState.relays[0].samples.forEach((sample, index) => {
    const timestamp = new Date(compressedStart + index * compressedStep).toISOString()
    sample.observedAt = timestamp
    sample.collectedAt = timestamp
  })
  writeFileSync(statePath, JSON.stringify(compressedState, null, 2) + '\n')
  compressed.publicGateway.windowStateSha256 = sha256(readFileSync(statePath))
  writeFileSync(evidencePath, JSON.stringify(compressed))
  const shortControllerWindow = promote(fixture, 'stable', fixture.target, args)
  t.not(shortControllerWindow.status, 0)
  t.ok(shortControllerWindow.stderr.includes('has not completed the signed 24-hour continuity window'))

  const stale = gatewayRolloutEvidence(fixture, statePath)
  const staleState = readJson(statePath)
  for (const sample of staleState.relays[0].samples) {
    sample.observedAt = new Date(Date.parse(sample.observedAt) - 31 * 60 * 1000).toISOString()
    sample.collectedAt = new Date(Date.parse(sample.collectedAt) - 31 * 60 * 1000).toISOString()
  }
  writeFileSync(statePath, JSON.stringify(staleState, null, 2) + '\n')
  stale.publicGateway.windowStateSha256 = sha256(readFileSync(statePath))
  writeFileSync(evidencePath, JSON.stringify(stale))
  const staleController = promote(fixture, 'stable', fixture.target, args)
  t.not(staleController.status, 0)
  t.ok(staleController.stderr.includes('latest relay/controller sample is not fresh'))
})

test('fleet promotion refuses unsigned tags and signed version mismatches', { skip: !canRunFunctional }, (t) => {
  const fixture = createFixture(t)
  const before = readFileSync(fixture.channelsPath)

  git(fixture.repo, ['tag', 'v2.0.0'])
  const unsigned = promote(fixture, 'canary', 'v2.0.0')
  t.not(unsigned.status, 0)
  t.ok(unsigned.stderr.includes('must be annotated and signed'))

  const attackerKey = path.join(fixture.work, 'attacker')
  command('ssh-keygen', ['-t', 'ed25519', '-f', attackerKey, '-N', '', '-q', '-C', 'attacker@example'])
  git(fixture.repo, ['tag', '-d', fixture.target])
  git(fixture.repo, ['-c', `user.signingkey=${attackerKey}.pub`, 'tag', '-s', '-m', 'forged', fixture.target])
  const untrusted = promote(fixture, 'canary', fixture.target)
  t.not(untrusted.status, 0)
  t.ok(untrusted.stderr.includes('not signed by a trusted fleet signer'))

  writeFileSync(path.join(fixture.repo, 'package.json'), JSON.stringify({ version: '9.9.8' }))
  git(fixture.repo, ['add', 'package.json'])
  git(fixture.repo, ['commit', '-qm', 'mismatched package version'])
  git(fixture.repo, ['-c', `user.signingkey=${fixture.signingKey}.pub`, 'tag', '-s', '-m', 'mismatch', 'v9.9.9'])
  const mismatch = promote(fixture, 'canary', 'v9.9.9')
  t.not(mismatch.status, 0)
  t.ok(mismatch.stderr.includes('does not match package.json version'))
  t.ok(readFileSync(fixture.channelsPath).equals(before))
})

test('fleet promotion respects an existing atomic promotion lock', { skip: !canRunFunctional }, (t) => {
  const fixture = createFixture(t)
  const before = readFileSync(fixture.channelsPath)
  const lockPath = path.join(path.dirname(fixture.channelsPath), `.${path.basename(fixture.channelsPath)}.promote.lock`)
  writeFileSync(lockPath, 'other promoter\n')

  const result = promote(fixture, 'canary', fixture.target)
  t.not(result.status, 0)
  t.ok(result.stderr.includes('another channel promotion holds'))
  t.ok(readFileSync(fixture.channelsPath).equals(before))
  t.is(readFileSync(lockPath, 'utf8'), 'other promoter\n', 'failed contender does not remove another process lock')
})

function createFixture (t, channelOverrides = {}, options = {}) {
  const work = mkdtempSync(path.join(tmpdir(), 'hiverelay-promote-'))
  t.teardown(() => rmSync(work, { recursive: true, force: true }))
  const repo = path.join(work, 'repo')
  const fleetDir = path.join(repo, 'fleet')
  const channelsPath = path.join(fleetDir, 'channels.json')
  const allowedSigners = path.join(fleetDir, 'allowed-signers')
  const relaysPath = path.join(fleetDir, 'relays.json')
  const gatewayManifestPath = 'fleet/public-hive-gateway-release.json'
  const signingKey = path.join(work, 'trusted')
  const target = 'v1.2.3'
  const appKey = 'aa'.repeat(32)
  const suffix = 'hive-canary.operator.example'
  const origin = `https://${encodeHiveAppKey(Buffer.from(appKey, 'hex'))}.${suffix}`
  const baseGatewayEntry = {
    relay: 'canary-1',
    channel: options.gatewayCohortChannel || 'canary',
    suffix,
    origin,
    connectAddress: '127.0.0.1',
    appKey,
    path: '/index.html',
    contentSha256: 'b'.repeat(64),
    driveVersion: '7',
    peerFingerprint256: Array(32).fill('AA').join(':'),
    nginxConfigSha256: 'c'.repeat(64)
  }
  const publicT1 = options.publicT1
    ? createPublicT1OpsFixture({
      relay: baseGatewayEntry.relay,
      channel: baseGatewayEntry.channel,
      appKey,
      suffix,
      contentSha256: baseGatewayEntry.contentSha256,
      nginxSha256: baseGatewayEntry.nginxConfigSha256,
      fingerprint256: baseGatewayEntry.peerFingerprint256,
      releaseTarget: target
    })
    : null
  const gatewayEntry = publicT1 ? publicT1.manifest.cohort[0] : baseGatewayEntry
  const gatewayManifest = options.gatewayEnabled === true
    ? {
        schema: 'hiverelay-public-gateway-release-v1',
        enabled: true,
        releaseTarget: target,
        admissionProfile: 'blind-substrate-public-v1',
        observationWindowMs: 24 * 60 * 60 * 1000,
        maxProbeGapMs: 20 * 60 * 1000,
        cohort: [gatewayEntry]
      }
    : {
        schema: 'hiverelay-public-gateway-release-v1',
        enabled: false
      }

  mkdirSync(fleetDir, { recursive: true })
  command('ssh-keygen', ['-t', 'ed25519', '-f', signingKey, '-N', '', '-q', '-C', 'release@hiverelay'])
  writeFileSync(allowedSigners, `release@hiverelay ${readFileSync(signingKey + '.pub', 'utf8').trim()}\n`)
  writeFileSync(path.join(repo, 'package.json'), JSON.stringify({ name: 'fixture', version: target.slice(1) }, null, 2) + '\n')
  const relaysBytes = Buffer.from(JSON.stringify({
    relays: [{ name: 'canary-1', channel: 'canary', publicIp: '127.0.0.1' }]
  }, null, 2) + '\n')
  const gatewayManifestBytes = Buffer.from(JSON.stringify(gatewayManifest, null, 2) + '\n')
  writeFileSync(relaysPath, relaysBytes)
  if (!options.omitGatewayManifest) writeFileSync(path.join(repo, gatewayManifestPath), gatewayManifestBytes)
  if (publicT1 && !options.omitOperatorContract) {
    const operatorPath = path.join(repo, publicT1.contractPath)
    mkdirSync(path.dirname(operatorPath), { recursive: true })
    const operatorContract = options.driftOperatorContract
      ? { ...publicT1.contract, certificateSpkiSha256: 'f'.repeat(64) }
      : publicT1.contract
    writeFileSync(operatorPath, JSON.stringify(operatorContract, null, 2) + '\n')
  }
  writeFileSync(channelsPath, JSON.stringify({
    _doc: 'fixture control plane',
    stable: 'v1.0.0',
    canary: 'v1.0.0',
    routing: { wave: ['one', 'two'], hold: true },
    ...channelOverrides
  }, null, 2) + '\n')

  command('git', ['init', '-q', repo])
  git(repo, ['config', 'user.name', 'tester'])
  git(repo, ['config', 'user.email', 'release@hiverelay'])
  git(repo, ['config', 'gpg.format', 'ssh'])
  const releaseFiles = ['package.json', 'fleet/channels.json', 'fleet/allowed-signers', 'fleet/relays.json']
  if (!options.omitGatewayManifest) releaseFiles.push(gatewayManifestPath)
  if (publicT1 && !options.omitOperatorContract) releaseFiles.push(publicT1.contractPath)
  git(repo, ['add', ...releaseFiles])
  git(repo, ['commit', '-qm', 'fixture release'])
  git(repo, ['-c', `user.signingkey=${signingKey}.pub`, 'tag', '-s', '-m', 'release', target])

  return {
    work,
    repo,
    channelsPath,
    allowedSigners,
    signingKey,
    target,
    targetSha: git(repo, ['rev-parse', `${target}^{commit}`]).stdout.trim(),
    relaysPath,
    relaysSha256: sha256(relaysBytes),
    gatewayManifestPath,
    gatewayManifest,
    gatewayManifestSha256: sha256(gatewayManifestBytes),
    gatewayEntry,
    operatorBinding: publicT1?.binding || null
  }
}

function promote (fixture, channel, target, extra = []) {
  return spawnSync(process.execPath, [
    tool,
    '--repo', fixture.repo,
    '--channels', fixture.channelsPath,
    '--allowed-signers', fixture.allowedSigners,
    '--channel', channel,
    '--target', target,
    ...extra
  ], {
    encoding: 'utf8',
    timeout: 20000
  })
}

function rolloutEvidence (fixture, overrides = {}) {
  const now = new Date().toISOString()
  const evidence = {
    schemaVersion: 1,
    generatedAt: now,
    status: 'verified',
    target: {
      tag: fixture.target,
      version: fixture.target.slice(1),
      sha: fixture.targetSha,
      channel: 'canary'
    },
    channelConfig: {
      sha256: sha256(readFileSync(fixture.channelsPath)),
      targets: { canary: fixture.target }
    },
    summary: {
      total: 1,
      updated: 1,
      packageVersionMatches: 1,
      healthy: 1,
      runtimeVersionMatches: 1
    },
    relays: [{
      name: 'canary-1',
      channel: 'canary',
      packageVersion: fixture.target,
      healthVersion: fixture.target.slice(1),
      observedAt: now,
      headSha: fixture.targetSha,
      updated: true,
      packageVersionMatches: true,
      healthy: true,
      runtimeVersionMatches: true
    }]
  }
  return { ...evidence, ...overrides }
}

function gatewayRolloutEvidence (fixture, statePath) {
  const evidence = rolloutEvidence(fixture)
  const checkedAt = evidence.generatedAt
  const endMs = Date.parse(checkedAt)
  const samples = []
  for (let offset = 24 * 60; offset >= 0; offset -= 20) {
    const timestamp = new Date(endMs - offset * 60 * 1000).toISOString()
    samples.push({
      observedAt: timestamp,
      collectedAt: timestamp,
      evidenceSha256: offset === 0
        ? 'd'.repeat(64)
        : createHash('sha256').update(`promotion-window-${offset}`).digest('hex')
    })
  }
  const state = {
    schema: 'hiverelay-public-gateway-window-state-v1',
    releaseTarget: fixture.target,
    releaseSha: fixture.targetSha,
    channel: 'canary',
    manifestSha256: fixture.gatewayManifestSha256,
    observationWindowMs: fixture.gatewayManifest.observationWindowMs,
    maxProbeGapMs: fixture.gatewayManifest.maxProbeGapMs,
    cohortNames: ['canary-1'],
    relays: [{ name: 'canary-1', samples }]
  }
  const stateBytes = Buffer.from(JSON.stringify(state, null, 2) + '\n')
  writeFileSync(statePath, stateBytes)
  const window = {
    windowStartedAt: samples[0].observedAt,
    windowEndedAt: samples.at(-1).observedAt,
    durationMs: 24 * 60 * 60 * 1000,
    sampleCount: samples.length,
    maxGapMs: 20 * 60 * 1000,
    relayCount: 1,
    complete: true
  }
  evidence.schemaVersion = 2
  evidence.probes = { publicGatewayEvidence: true }
  evidence.summary.gatewayHealthy = evidence.summary.total
  evidence.inventory = {
    sha256: fixture.relaysSha256,
    relayNames: ['canary-1']
  }
  evidence.publicGateway = {
    manifest: {
      path: fixture.gatewayManifestPath,
      sha256: fixture.gatewayManifestSha256,
      releaseTarget: fixture.target,
      admissionProfile: fixture.gatewayManifest.admissionProfile,
      observationWindowMs: fixture.gatewayManifest.observationWindowMs,
      maxProbeGapMs: fixture.gatewayManifest.maxProbeGapMs,
      cohortNames: ['canary-1']
    },
    windowStateSha256: sha256(stateBytes),
    window
  }
  for (const relay of evidence.relays) {
    relay.gatewayHealthy = true
    relay.gateway = {
      schema: 'hiverelay-public-gateway-evidence-verification-v2',
      status: 'verified',
      mode: 'fleet',
      admissionProfile: fixture.gatewayManifest.admissionProfile,
      publicSuffixReady: false,
      physicalEnforcementRequired: true,
      releaseTarget: fixture.target,
      releaseSha: fixture.targetSha,
      checkedAt,
      probeObservedAt: samples.at(-1).observedAt,
      origin: fixture.gatewayEntry.origin,
      connectAddress: fixture.gatewayEntry.connectAddress,
      appKey: fixture.gatewayEntry.appKey,
      path: fixture.gatewayEntry.path,
      contentSha256: fixture.gatewayEntry.contentSha256,
      driveVersion: fixture.gatewayEntry.driveVersion,
      tlsProtocol: 'TLSv1.3',
      peerFingerprint256: fixture.gatewayEntry.peerFingerprint256,
      nginxSha256: fixture.gatewayEntry.nginxConfigSha256,
      checks: {
        metadata: true,
        exactBytes: true,
        range: true,
        head: true,
        canonicalIdentity: true,
        managementIsolation: true,
        forwardedHostIsolation: true,
        unavailableAppIsolation: true,
        defaultSniRejection: true,
        sniHostBinding: true
      },
      evidenceSha256: samples.at(-1).evidenceSha256
    }
  }
  return evidence
}

function readJson (file) {
  return JSON.parse(readFileSync(file, 'utf8'))
}

function sha256 (value) {
  return createHash('sha256').update(value).digest('hex')
}

function git (repo, args) {
  return command('git', ['-C', repo, ...args])
}

function command (name, args) {
  const result = spawnSync(name, args, { encoding: 'utf8', timeout: 20000 })
  if (result.status !== 0) throw new Error(`${name} ${args.join(' ')} failed: ${result.stderr || result.stdout}`)
  return result
}

function have (name) {
  return spawnSync('sh', ['-c', `command -v ${name}`], { stdio: 'ignore' }).status === 0
}
