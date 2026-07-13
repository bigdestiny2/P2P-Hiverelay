import test from 'brittle'
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { runPublicHiveGatewayDeploy } from '../../scripts/public-hive-gateway-deploy.mjs'

const TARGET = 'v1.2.3'
const PREVIOUS = 'v1.2.2'
const RECOVERY = 'v1.2.4'
const TARGET_SHA = 'a'.repeat(40)
const PREVIOUS_SHA = 'b'.repeat(40)
const RECOVERY_SHA = 'd'.repeat(40)
const PUBLISHED_SHA = 'c'.repeat(40)
const WINDOW_MS = 24 * 60 * 60 * 1000

test('public gateway deploy - canary is validation-only unless exact tag/SHA authorization is explicit', async (t) => {
  const f = await fixture(t)
  const input = canaryInput(f)

  const validation = await runPublicHiveGatewayDeploy(input, f.injected)
  t.is(validation.status, 'validated')
  t.is(validation.authorizationRequired, `publish-canary:${TARGET}:${TARGET_SHA}`)
  t.is(f.calls.length, 1)
  t.absent(f.calls[0].publish)
  t.is((await f.channels()).canary, PREVIOUS)

  await t.exception(async () => runPublicHiveGatewayDeploy({
    ...input,
    publish: true,
    authorize: `publish-canary:${TARGET}:${PREVIOUS_SHA}`,
    receipt: f.canaryReceipt
  }, f.injected), /--authorize must exactly equal/)
  t.is(f.calls.length, 2, 'bad authorization never reaches the mutating publisher')
  t.is((await f.channels()).canary, PREVIOUS)

  const published = await runPublicHiveGatewayDeploy({
    ...input,
    publish: true,
    authorize: validation.authorizationRequired,
    receipt: f.canaryReceipt
  }, f.injected)
  t.is(published.status, 'published')
  t.is((await f.channels()).canary, TARGET)
  const receipt = await privateJson(f.canaryReceipt)
  t.is(receipt.status, 'published')
  t.is(receipt.targetSha, TARGET_SHA)
  t.is(receipt.previousTarget, PREVIOUS)
  t.is(receipt.previousTargetSha, PREVIOUS_SHA)
})

test('public gateway deploy - legacy target is rejected before any publication mutation', async (t) => {
  const f = await fixture(t, { gatewayRequired: false })
  await t.exception(async () => runPublicHiveGatewayDeploy({
    ...canaryInput(f),
    publish: true,
    authorize: `publish-canary:${TARGET}:${TARGET_SHA}`,
    receipt: f.canaryReceipt
  }, f.injected), /enabled canonical public gateway release/)
  t.is(f.calls.length, 1)
  t.absent(f.calls[0].publish)
  t.is((await f.channels()).canary, PREVIOUS)
  await t.exception(() => readFile(f.canaryReceipt), /ENOENT/)
})

test('public gateway deploy - enabled publication requires public-t1 operator bindings', async (t) => {
  const f = await fixture(t, { operatorContracts: [] })
  await t.exception(async () => runPublicHiveGatewayDeploy(canaryInput(f), f.injected),
    /requires public-t1 operator contracts for every enabled gateway cohort relay/)
  t.is((await f.channels()).canary, PREVIOUS)
})

test('public gateway deploy - fresh observer session binds canary and stable stays separately authorized', async (t) => {
  const f = await fixture(t)
  await publishCanary(f)
  const start = Date.parse('2026-07-01T00:00:00.000Z')
  const times = [start, start + WINDOW_MS]
  let observerArgs
  const observe = await runPublicHiveGatewayDeploy(observeInput(f), {
    ...f.injected,
    now: () => times.shift(),
    runObserver: async (args) => {
      observerArgs = args
      await writeFile(f.windowState, JSON.stringify(windowState()) + '\n')
      await writeFile(f.rolloutEvidence, JSON.stringify(rolloutEvidence()) + '\n')
      return { code: 0 }
    }
  })

  t.is(observe.status, 'complete')
  t.is(observe.stableRemainsExplicit, true)
  t.is(observe.continuityAuthority, 'controller-retained-manifest-bound')
  t.is(observe.independentWitnessProof, false)
  t.ok(observerArgs.includes('--gateway-window-state'))
  t.ok(observerArgs.includes('--known-hosts'))
  const session = await privateJson(f.session)
  t.is(session.status, 'complete')
  t.is(session.elapsedMs, WINDOW_MS)

  const stableValidation = await runPublicHiveGatewayDeploy(stableInput(f), f.injected)
  t.is(stableValidation.status, 'validated')
  t.is(stableValidation.authorizationRequired, `publish-stable:${TARGET}:${TARGET_SHA}`)
  t.is((await f.channels()).stable, PREVIOUS, 'observation and validation cannot move stable')

  const stable = await runPublicHiveGatewayDeploy({
    ...stableInput(f),
    publish: true,
    authorize: stableValidation.authorizationRequired,
    receipt: f.stableReceipt
  }, f.injected)
  t.is(stable.status, 'published')
  t.is((await f.channels()).stable, TARGET)
  t.is((await privateJson(f.stableReceipt)).status, 'published')
})

test('public gateway deploy - refreshed ops evidence preserves signed operator invariants across canary and stable', async (t) => {
  const initial = operatorContractPublication()
  const f = await fixture(t, { operatorContracts: [initial] })
  await publishCanary(f)
  const canaryReceipt = await privateJson(f.canaryReceipt)
  t.is(canaryReceipt.gatewayOpsEvidenceDir, f.gatewayOpsEvidenceDir)
  t.is(canaryReceipt.operatorContracts[0].operatorContractSha256, initial.operatorContractSha256)
  t.absent('checkedAt' in canaryReceipt.operatorContracts[0], 'rotating artifact time is not receipt-bound')
  t.absent('evidenceSha256' in canaryReceipt.operatorContracts[0], 'rotating artifact bytes are not receipt-bound')

  await completeObservation(f)
  const refreshed = {
    ...initial,
    checkedAt: '2026-07-13T00:00:00.000Z',
    evidenceSha256: '9'.repeat(64)
  }
  f.setOperatorContracts([refreshed])
  const validation = await runPublicHiveGatewayDeploy(stableInput(f), f.injected)
  t.is(validation.status, 'validated')
  t.alike(validation.operatorContracts, canaryReceipt.operatorContracts)

  f.setOperatorContracts([{ ...refreshed, operatorId: 'operator-b' }])
  await t.exception(async () => runPublicHiveGatewayDeploy(stableInput(f), f.injected),
    /changed the signed operator-contract bindings/)

  const swappedDirectory = path.join(f.root, 'swapped-ops')
  await mkdir(swappedDirectory)
  await t.exception(async () => runPublicHiveGatewayDeploy({
    ...stableInput(f),
    gatewayOpsEvidenceDir: swappedDirectory
  }, f.injected), /evidence directory changed after canary/)
})

test('public gateway deploy - preseeded state and early observer success fail closed', async (t) => {
  const seeded = await fixture(t)
  await publishCanary(seeded)
  await writeFile(seeded.windowState, '{}\n')
  await t.exception(async () => runPublicHiveGatewayDeploy(observeInput(seeded), {
    ...seeded.injected,
    runObserver: async () => ({ code: 0 })
  }), /gateway-window-state must not already exist/)
  await t.exception(() => readFile(seeded.session), /ENOENT/)

  const early = await fixture(t)
  await publishCanary(early)
  const start = Date.parse('2026-07-01T00:00:00.000Z')
  const times = [start, start + 60_000, start + 60_000]
  await t.exception(async () => runPublicHiveGatewayDeploy(observeInput(early), {
    ...early.injected,
    now: () => times.shift(),
    runObserver: async () => {
      await writeFile(early.windowState, JSON.stringify(windowState()) + '\n')
      await writeFile(early.rolloutEvidence, JSON.stringify(rolloutEvidence()) + '\n')
      return { code: 0 }
    }
  }), /returned success before this controller session spanned/)
  t.is((await privateJson(early.session)).status, 'failed')
  await t.exception(async () => runPublicHiveGatewayDeploy({
    ...observeInput(early),
    resume: true
  }, early.injected), /only an observing session can be resumed/)
})

test('public gateway deploy - evidence drift blocks stable and reverse canary abort is retired', async (t) => {
  const drift = await fixture(t)
  await publishCanary(drift)
  await completeObservation(drift)
  await writeFile(drift.rolloutEvidence, JSON.stringify({ ...rolloutEvidence(), note: 'drift' }) + '\n')
  await t.exception(async () => runPublicHiveGatewayDeploy(stableInput(drift), drift.injected),
    /observation evidence changed/)
  t.is((await drift.channels()).stable, PREVIOUS)

  const trustDrift = await fixture(t)
  await publishCanary(trustDrift)
  await writeFile(trustDrift.allowedSigners, 'changed trust root\n')
  await t.exception(async () => runPublicHiveGatewayDeploy(observeInput(trustDrift), trustDrift.injected),
    /allowed signers bytes changed/)

  const hostDrift = await fixture(t)
  await publishCanary(hostDrift)
  await completeObservation(hostDrift)
  await writeFile(hostDrift.knownHosts, 'changed host key authority\n')
  await t.exception(async () => runPublicHiveGatewayDeploy(stableInput(hostDrift), hostDrift.injected),
    /knownHostsSha256 changed/)

  const retired = await fixture(t)
  await publishCanary(retired)
  const callsBefore = retired.calls.length
  await t.exception(async () => runPublicHiveGatewayDeploy(abortInput(retired), retired.injected),
    /abort-canary is retired.*recover-canary/)
  t.is(retired.calls.length, callsBefore, 'retired reverse transition never reaches the publisher')
  t.is((await retired.channels()).canary, TARGET)
})

test('public gateway deploy - recovery moves canary only to a signed descendant with receipt-bound CAS', async (t) => {
  const f = await fixture(t)
  await publishCanary(f)

  const validation = await runPublicHiveGatewayDeploy(recoveryInput(f), f.injected)
  t.is(validation.status, 'validated')
  t.is(validation.failedTarget, TARGET)
  t.is(validation.failedTargetSha, TARGET_SHA)
  t.is(validation.target, RECOVERY)
  t.is(validation.targetSha, RECOVERY_SHA)
  t.ok(validation.authorizationRequired.startsWith(
    `recover-canary:${TARGET}:${TARGET_SHA}->${RECOVERY}:${RECOVERY_SHA}:`))
  t.is(validation.recoveryBindingSha256.length, 64)
  t.is(f.calls.at(-1).expectedCurrentTarget, TARGET)
  t.is(f.calls.at(-1).expectedCurrentTargetSha, TARGET_SHA)
  t.is((await f.channels()).canary, TARGET)

  const result = await runPublicHiveGatewayDeploy({
    ...recoveryInput(f),
    publish: true,
    authorize: validation.authorizationRequired,
    receipt: f.recoveryReceipt
  }, f.injected)
  t.is(result.status, 'published')
  t.is((await f.channels()).canary, RECOVERY)
  const receipt = await privateJson(f.recoveryReceipt)
  t.is(receipt.action, 'recover-canary')
  t.is(receipt.failedTarget, TARGET)
  t.is(receipt.failedTargetSha, TARGET_SHA)
  t.is(receipt.recoveryBindingSha256, validation.recoveryBindingSha256)
  t.alike(receipt.operatorContracts, validation.operatorContracts)
})

test('public gateway deploy - recovery rejects replay, non-descendants, drift, and unchanged mutation', async (t) => {
  const same = await fixture(t)
  await publishCanary(same)
  await t.exception(async () => runPublicHiveGatewayDeploy({
    ...recoveryInput(same),
    target: TARGET,
    targetSha: TARGET_SHA
  }, same.injected), /new forward tag and commit/)

  const nonDescendant = await fixture(t)
  await publishCanary(nonDescendant)
  await t.exception(async () => runPublicHiveGatewayDeploy(recoveryInput(nonDescendant), {
    ...nonDescendant.injected,
    isAncestor: async () => false
  }), /must descend from the failed canary target/)

  const channelDrift = await fixture(t)
  await publishCanary(channelDrift)
  await channelDrift.setChannels({ canary: PREVIOUS, stable: PREVIOUS })
  await t.exception(async () => runPublicHiveGatewayDeploy(recoveryInput(channelDrift), channelDrift.injected),
    /canary channel no longer points/)

  const stableDrift = await fixture(t)
  await publishCanary(stableDrift)
  await stableDrift.setChannels({ canary: TARGET, stable: TARGET })
  await t.exception(async () => runPublicHiveGatewayDeploy(recoveryInput(stableDrift), stableDrift.injected),
    /already published to stable/)

  const contractDrift = await fixture(t)
  await publishCanary(contractDrift)
  const validation = await runPublicHiveGatewayDeploy(recoveryInput(contractDrift), contractDrift.injected)
  contractDrift.mutateContractsOnPublish()
  await t.exception(async () => runPublicHiveGatewayDeploy({
    ...recoveryInput(contractDrift),
    publish: true,
    authorize: validation.authorizationRequired,
    receipt: contractDrift.recoveryReceipt
  }, contractDrift.injected), /changed the signed operator-contract bindings/)
  t.is((await privateJson(contractDrift.recoveryReceipt)).status, 'failed')

  const unchanged = await fixture(t)
  await publishCanary(unchanged)
  const unchangedValidation = await runPublicHiveGatewayDeploy(recoveryInput(unchanged), unchanged.injected)
  unchanged.forceUnchangedOnPublish()
  await t.exception(async () => runPublicHiveGatewayDeploy({
    ...recoveryInput(unchanged),
    publish: true,
    authorize: unchangedValidation.authorizationRequired,
    receipt: unchanged.recoveryReceipt
  }, unchanged.injected), /cannot succeed as unchanged/)
  t.is((await privateJson(unchanged.recoveryReceipt)).status, 'failed')
})

async function fixture (t, options = {}) {
  const root = await mkdtemp(path.join(tmpdir(), 'hiverelay-deploy-'))
  t.teardown(() => rm(root, { recursive: true, force: true }))
  const repo = path.join(root, 'repo')
  const fleet = path.join(repo, 'fleet')
  const channelsPath = path.join(fleet, 'channels.json')
  const allowedSigners = path.join(root, 'allowed-signers')
  const relays = path.join(fleet, 'relays.json')
  const canaryReceipt = path.join(root, 'canary-receipt.json')
  const stableReceipt = path.join(root, 'stable-receipt.json')
  const recoveryReceipt = path.join(root, 'recovery-receipt.json')
  const session = path.join(root, 'observation-session.json')
  const windowState = path.join(root, 'window-state.json')
  const rolloutEvidencePath = path.join(root, 'rollout-evidence.json')
  const knownHosts = path.join(root, 'known-hosts')
  const initialOperatorContracts = options.operatorContracts ?? [operatorContractPublication()]
  const gatewayOpsEvidenceDir = initialOperatorContracts.length > 0 ? path.join(root, 'gateway-ops') : null
  await mkdir(fleet, { recursive: true })
  if (gatewayOpsEvidenceDir) await mkdir(gatewayOpsEvidenceDir)
  await writeFile(channelsPath, JSON.stringify({ canary: PREVIOUS, stable: PREVIOUS }, null, 2) + '\n')
  await writeFile(relays, '{"relays":[]}\n')
  await writeFile(allowedSigners, 'fixture\n')
  await writeFile(knownHosts, 'fixture\n')
  const calls = []
  let operatorContracts = structuredClone(initialOperatorContracts)
  let driftContractsOnPublish = false
  let unchangedOnPublish = false
  const publish = async (input) => {
    calls.push({ ...input })
    if (input.target === PREVIOUS && options.previousPublicT1 && !input.gatewayOpsEvidenceDir) {
      throw new Error('--gateway-ops-evidence-dir is required for a public-t1-gateway channel publication')
    }
    const channels = JSON.parse(await readFile(channelsPath, 'utf8'))
    if (input.expectedCurrentTarget) {
      if (channels[input.channel] !== input.expectedCurrentTarget || input.expectedCurrentTargetSha !== TARGET_SHA) {
        throw new Error('fixture recovery compare-and-swap rejected')
      }
    }
    const wouldChange = channels[input.channel] !== input.target
    if (input.publish && wouldChange && !unchangedOnPublish) {
      channels[input.channel] = input.target
      await writeFile(channelsPath, JSON.stringify(channels, null, 2) + '\n')
    }
    const publishedContracts = driftContractsOnPublish && input.publish
      ? [{ ...operatorContracts[0], operatorId: 'operator-drift' }]
      : operatorContracts
    const publicTarget = input.target === TARGET || input.target === RECOVERY
    return {
      schema: 'hiverelay-fleet-channel-publication-v1',
      status: input.publish ? (wouldChange && !unchangedOnPublish ? 'published' : 'unchanged') : 'dry-run',
      channel: input.channel,
      target: input.target,
      publicGatewayRequired: publicTarget ? options.gatewayRequired !== false : false,
      operatorContracts: publicTarget ? structuredClone(publishedContracts) : [],
      wouldChange,
      publishedHead: PUBLISHED_SHA,
      remoteHead: PUBLISHED_SHA
    }
  }
  const resolveTargetSha = async (_repo, target) => {
    if (target === TARGET) return TARGET_SHA
    if (target === PREVIOUS) return PREVIOUS_SHA
    if (target === RECOVERY) return RECOVERY_SHA
    throw new Error('unknown fixture tag')
  }
  return {
    root,
    repo,
    channelsPath,
    allowedSigners,
    relays,
    canaryReceipt,
    stableReceipt,
    recoveryReceipt,
    session,
    windowState,
    rolloutEvidence: rolloutEvidencePath,
    knownHosts,
    gatewayOpsEvidenceDir,
    calls,
    setOperatorContracts: value => { operatorContracts = structuredClone(value) },
    mutateContractsOnPublish: () => { driftContractsOnPublish = true },
    forceUnchangedOnPublish: () => { unchangedOnPublish = true },
    injected: {
      publish,
      resolveTargetSha,
      isAncestor: async (_repo, ancestor, descendant) => ancestor === TARGET_SHA && descendant === RECOVERY_SHA
    },
    channels: async () => JSON.parse(await readFile(channelsPath, 'utf8')),
    setChannels: async value => writeFile(channelsPath, JSON.stringify(value, null, 2) + '\n')
  }
}

function commonInput (f) {
  return {
    target: TARGET,
    targetSha: TARGET_SHA,
    repo: f.repo,
    remote: 'origin',
    branch: 'main',
    allowedSigners: f.allowedSigners,
    relays: f.relays,
    channels: f.channelsPath
  }
}

function canaryInput (f) {
  return {
    action: 'canary',
    ...commonInput(f),
    ...(f.gatewayOpsEvidenceDir ? { gatewayOpsEvidenceDir: f.gatewayOpsEvidenceDir } : {})
  }
}

function observeInput (f) {
  return {
    action: 'observe',
    ...commonInput(f),
    canaryReceipt: f.canaryReceipt,
    session: f.session,
    knownHosts: f.knownHosts,
    gatewayEvidence: '/root/gateway-evidence.json',
    gatewayWindowState: f.windowState,
    evidence: f.rolloutEvidence
  }
}

function stableInput (f) {
  return {
    action: 'stable',
    ...commonInput(f),
    canaryReceipt: f.canaryReceipt,
    session: f.session,
    ...(f.gatewayOpsEvidenceDir ? { gatewayOpsEvidenceDir: f.gatewayOpsEvidenceDir } : {})
  }
}

function abortInput (f) {
  return {
    action: 'abort-canary',
    ...commonInput(f),
    canaryReceipt: f.canaryReceipt
  }
}

function recoveryInput (f) {
  return {
    action: 'recover-canary',
    ...commonInput(f),
    target: RECOVERY,
    targetSha: RECOVERY_SHA,
    canaryReceipt: f.canaryReceipt,
    ...(f.gatewayOpsEvidenceDir ? { gatewayOpsEvidenceDir: f.gatewayOpsEvidenceDir } : {})
  }
}

async function publishCanary (f) {
  return runPublicHiveGatewayDeploy({
    ...canaryInput(f),
    publish: true,
    authorize: `publish-canary:${TARGET}:${TARGET_SHA}`,
    receipt: f.canaryReceipt
  }, f.injected)
}

async function completeObservation (f) {
  const start = Date.parse('2026-07-01T00:00:00.000Z')
  const times = [start, start + WINDOW_MS]
  return runPublicHiveGatewayDeploy(observeInput(f), {
    ...f.injected,
    now: () => times.shift(),
    runObserver: async () => {
      await writeFile(f.windowState, JSON.stringify(windowState()) + '\n')
      await writeFile(f.rolloutEvidence, JSON.stringify(rolloutEvidence()) + '\n')
      return 0
    }
  })
}

function windowState () {
  return {
    schema: 'hiverelay-public-gateway-window-state-v1',
    releaseTarget: TARGET,
    releaseSha: TARGET_SHA,
    channel: 'canary',
    observationWindowMs: WINDOW_MS
  }
}

function rolloutEvidence () {
  return {
    schemaVersion: 2,
    status: 'verified',
    target: { tag: TARGET, sha: TARGET_SHA, channel: 'canary' },
    publicGateway: { window: { complete: true } }
  }
}

function operatorContractPublication () {
  return {
    relay: 'stable-1',
    operatorId: 'operator-a',
    registrableDomain: 'operator.example',
    suffix: 'hive.operator.example',
    operatorContractSha256: 'd'.repeat(64),
    certificateSpkiSha256: 'e'.repeat(64),
    expectedAddresses: ['8.8.8.8', '2606:4700:4700::1111'],
    checkedAt: '2026-07-12T00:00:00.000Z',
    evidenceSha256: 'f'.repeat(64)
  }
}

async function privateJson (file) {
  await chmod(file, 0o600)
  return JSON.parse(await readFile(file, 'utf8'))
}
