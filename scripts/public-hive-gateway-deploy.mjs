#!/usr/bin/env node

import { execFile, spawn } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { constants as fsConstants } from 'node:fs'
import { lstat, open, rename, unlink } from 'node:fs/promises'
import { isIP } from 'node:net'
import path from 'node:path'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'
import { publishFleetChannel } from './publish-fleet-channel.mjs'

const execFileAsync = promisify(execFile)
const scriptPath = fileURLToPath(import.meta.url)
const scriptDir = path.dirname(scriptPath)
const defaultRepoRoot = path.resolve(scriptDir, '..')
const defaultObserver = path.join(scriptDir, 'observe-public-hive-gateway-rollout.mjs')
const CANONICAL_GATEWAY_MANIFEST = 'fleet/public-hive-gateway-release.json'
const RECEIPT_SCHEMA = 'hiverelay-public-gateway-deploy-transition-v1'
const OBSERVATION_SCHEMA = 'hiverelay-public-gateway-observation-session-v1'
const WINDOW_STATE_SCHEMA = 'hiverelay-public-gateway-window-state-v1'
const RELEASE_TAG_PATTERN = /^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/
const OBJECT_ID_PATTERN = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/
const MAX_RECEIPT_BYTES = 256 * 1024
const MAX_EVIDENCE_BYTES = 16 * 1024 * 1024
const MIN_OBSERVATION_WINDOW_MS = 24 * 60 * 60 * 1000
const GIT_PROGRAM = '/usr/bin/git'
const UNSAFE_GIT_ENV = new Set([
  'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_COMMON_DIR', 'GIT_CONFIG',
  'GIT_CONFIG_COUNT', 'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_PARAMETERS',
  'GIT_CONFIG_SYSTEM', 'GIT_DIR', 'GIT_EXEC_PATH', 'GIT_GRAFT_FILE',
  'GIT_INDEX_FILE', 'GIT_NAMESPACE', 'GIT_OBJECT_DIRECTORY', 'GIT_PREFIX',
  'GIT_PROXY_COMMAND', 'GIT_QUARANTINE_PATH', 'GIT_REPLACE_REF_BASE',
  'GIT_SHALLOW_FILE', 'GIT_SSH', 'GIT_SSH_COMMAND', 'GIT_SSL_CAINFO',
  'GIT_SSL_CAPATH', 'GIT_SSL_NO_VERIFY', 'GIT_WORK_TREE'
])

const usage = `
Usage:
  node scripts/public-hive-gateway-deploy.mjs canary [options]
  node scripts/public-hive-gateway-deploy.mjs observe [options]
  node scripts/public-hive-gateway-deploy.mjs stable [options]
  node scripts/public-hive-gateway-deploy.mjs recover-canary [options]

Common release options:
  --target <vX.Y.Z>           Exact signed release tag
  --target-sha <sha>          Exact tagged commit authorized by the operator
  --repo <absolute-path>      Clean control worktree (default: repository root)
  --remote <name>             Git remote (default: origin)
  --branch <name>             Control branch (default: main)
  --allowed-signers <path>    Absolute trusted OpenSSH allowed_signers path
  --relays <path>             Absolute current full fleet inventory path
  --channels <path>           Absolute channel file (observer only)
  --gateway-ops-evidence-dir <absolute-dir>
                              Fresh signed-contract ops artifacts (canary/stable)

Canary publication:
  --publish                   Publish after an internal validation-only pass
  --authorize <token>         Exact publish-canary:<tag>:<sha> token
  --receipt <path>            New private canary transition receipt (publish)

Observation:
  --canary-receipt <path>     Completed canary publication receipt
  --session <path>            Private controller observation-session record
  --known-hosts <path>        Absolute pinned fleet known_hosts file
  --gateway-evidence <path>   Absolute evidence path on each cohort relay
  --gateway-window-state <p>  Absolute new/resumed local window-state path
  --evidence <path>           Absolute new/resumed rollout-evidence path
  --gateway-manifest <path>   Tagged repo-relative manifest (canonical default)
  --resume                    Resume this wrapper's existing observing session
  --sample-interval-ms <ms>   Observer cadence
  --max-runtime-ms <ms>       Observer runtime budget
  --ssh-command <path>        Alternate checker SSH command (fixtures only)
  --ssh-key <path>            Fleet SSH key
  --ssh-user <name>           Fleet SSH user
  --remote-repo-dir <path>    Repository path on cohort relays
  --service <name>            Relay service name
  --api <url>                 Loopback management API URL
  --timeout-ms <ms>           Per-check rollout convergence budget
  --interval-ms <ms>          Per-check rollout retry cadence
  --ssh-timeout-ms <ms>       Per-relay SSH timeout

Stable publication:
  --canary-receipt <path>     Completed canary publication receipt
  --session <path>            Completed controller observation session
  --publish                   Publish after an internal validation-only pass
  --authorize <token>         Exact publish-stable:<tag>:<sha> token
  --receipt <path>            New private stable transition receipt (publish)

Forward canary recovery:
  --canary-receipt <path>     Failed canary publication receipt being recovered
  --target/--target-sha       New signed recovery tag/commit descending from it
  --publish                   Publish only after normal manifest/operator gates
  --authorize <token>         Exact receipt-bound forward recovery token
  --receipt <path>            New private recovery transition receipt (publish)

Canary and stable default to validation-only. Stable is never called by
observation. Observation continuity is controller-retained and bound to the
signed manifest; it is not independent T3/witness or external timestamp proof.`

if (path.resolve(process.argv[1] || '') === scriptPath) {
  try {
    const input = parseArgs(process.argv.slice(2))
    if (input.help) {
      console.log(usage.trim())
    } else {
      console.log(JSON.stringify(await runPublicHiveGatewayDeploy(input), null, 2))
    }
  } catch (err) {
    console.error(`public gateway deploy: ${safeError(err)}`)
    process.exitCode = 1
  }
}

export async function runPublicHiveGatewayDeploy (input, injected = {}) {
  const options = normalizeOptions(input)
  if (options.action === 'canary') return runCanary(options, injected)
  if (options.action === 'observe') return runObservation(options, injected)
  if (options.action === 'stable') return runStable(options, injected)
  if (options.action === 'abort-canary') {
    throw new Error('abort-canary is retired: create a new signed recovery tag descending from the failed canary and use recover-canary')
  }
  if (options.action === 'recover-canary') return runCanaryRecovery(options, injected)
  throw new Error('action must be exactly canary, observe, stable, recover-canary, or abort-canary (migration error only)')
}

async function runCanaryRecovery (options, injected) {
  requireReleaseInputs(options)
  rejectOptions(options, observationOnlyOptions(['resume', 'session']), 'recover-canary')
  requireCanonicalPublicationInputs(options)
  const publish = injected.publish || publishFleetChannel
  const resolveSha = injected.resolveTargetSha || resolveTargetSha
  const targetSha = await requireTargetSha(options, resolveSha)
  const failedReceiptPath = requireAbsolutePath(options.canaryReceipt, 'canary-receipt')
  const failedReceipt = await readCanaryReceipt(failedReceiptPath)
  await requireReceiptTrust(failedReceipt, options)
  if (failedReceipt.repo !== options.repo || failedReceipt.remote !== options.remote || failedReceipt.branch !== options.branch) {
    throw new Error('failed canary receipt does not bind this control repository')
  }
  const failedTarget = failedReceipt.target
  const failedTargetSha = failedReceipt.targetSha
  if (options.target === failedTarget || targetSha === failedTargetSha) {
    throw new Error('recovery must use a new forward tag and commit')
  }
  const isAncestor = injected.isAncestor || isCommitAncestor
  if (!await isAncestor(options.repo, failedTargetSha, targetSha)) {
    throw new Error('recovery target must descend from the failed canary target; revert behavior in a new commit')
  }
  const channelsPath = options.channels || path.join(options.repo, 'fleet', 'channels.json')
  const channels = await readChannels(channelsPath)
  if (requireChannelTarget(channels, 'canary') !== failedTarget) {
    throw new Error('canary channel no longer points at the failed receipt-bound release')
  }
  if (requireChannelTarget(channels, 'stable') === failedTarget) {
    throw new Error('cannot recover a canary that was already published to stable')
  }
  const failedReceiptSha256 = await sha256SafeFile(failedReceiptPath, MAX_RECEIPT_BYTES, 'failed canary receipt')
  const allowedSignersSha256 = await sha256SafeFile(options.allowedSigners, MAX_RECEIPT_BYTES, 'allowed signers')
  const publisherOptions = {
    ...publicationOptions(options, 'canary', false),
    expectedCurrentTarget: failedTarget,
    expectedCurrentTargetSha: failedTargetSha
  }
  const validation = requireGatewayPublication(await publish(publisherOptions), 'canary')
  const operatorContracts = normalizeOperatorContracts(validation.operatorContracts,
    'recovery publisher operator contracts', true)
  const gatewayOpsEvidenceDir = operatorContracts.length > 0 ? options.gatewayOpsEvidenceDir : null
  if ((operatorContracts.length > 0) !== Boolean(gatewayOpsEvidenceDir)) {
    throw new Error('recovery operator readiness did not bind its evidence directory')
  }
  const recoveryBindingSha256 = sha256(Buffer.from(JSON.stringify({
    failedReceiptSha256,
    allowedSignersSha256,
    gatewayOpsEvidenceDir,
    operatorContracts
  })))
  const authorization = `recover-canary:${failedTarget}:${failedTargetSha}->${options.target}:${targetSha}:${recoveryBindingSha256}`
  const base = transitionReport('recover-canary', options, targetSha, validation, {
    failedTarget,
    failedTargetSha,
    failedCanaryReceipt: failedReceiptPath,
    failedCanaryReceiptSha256: failedReceiptSha256,
    allowedSignersSha256,
    gatewayOpsEvidenceDir,
    operatorContracts,
    recoveryBindingSha256,
    authorizationRequired: authorization
  })
  if (!options.publish) {
    if (options.authorize) throw new Error('--authorize is valid only with --publish')
    if (options.receipt) throw new Error('--receipt is valid only with --publish')
    return base
  }
  requireAuthorization(options, authorization)
  const receiptPath = requireAbsolutePath(options.receipt, 'receipt')
  const receipt = {
    schema: RECEIPT_SCHEMA,
    action: 'recover-canary',
    status: 'publishing',
    target: options.target,
    targetSha,
    failedTarget,
    failedTargetSha,
    failedCanaryReceipt: failedReceiptPath,
    failedCanaryReceiptSha256: failedReceiptSha256,
    allowedSigners: options.allowedSigners,
    allowedSignersSha256,
    gatewayOpsEvidenceDir,
    operatorContracts,
    recoveryBindingSha256,
    repo: options.repo,
    remote: options.remote,
    branch: options.branch,
    startedAt: nowIso(injected)
  }
  await createPrivateJson(receiptPath, receipt)
  try {
    const result = requireGatewayPublication(await publish({ ...publisherOptions, publish: true }), 'canary')
    requireSameOperatorContracts(
      normalizeOperatorContracts(result.operatorContracts, 'published recovery operator contracts', true),
      operatorContracts,
      'canary recovery publication'
    )
    if (await sha256SafeFile(failedReceiptPath, MAX_RECEIPT_BYTES, 'failed canary receipt') !== failedReceiptSha256) {
      throw new Error('failed canary receipt changed during recovery publication')
    }
    if (await sha256SafeFile(options.allowedSigners, MAX_RECEIPT_BYTES, 'allowed signers') !== allowedSignersSha256) {
      throw new Error('allowed signers changed during recovery publication')
    }
    if (result.status === 'unchanged') throw new Error('recovery publication cannot succeed as unchanged')
    const completed = {
      ...receipt,
      status: result.status === 'unchanged' ? 'unchanged' : 'published',
      completedAt: nowIso(injected),
      publishedHead: requireObjectId(result.publishedHead, 'published head'),
      remoteHead: requireObjectId(result.remoteHead || result.publishedHead, 'remote head')
    }
    await replacePrivateJson(receiptPath, completed)
    return { ...base, status: completed.status, receipt: receiptPath, publication: result }
  } catch (err) {
    await replacePrivateJson(receiptPath, { ...receipt, status: 'failed', failedAt: nowIso(injected) }).catch(() => {})
    throw err
  }
}

async function runCanary (options, injected) {
  requireReleaseInputs(options)
  rejectOptions(options, observationOnlyOptions(['resume', 'session', 'canaryReceipt']), 'canary')
  requireCanonicalPublicationInputs(options)
  const resolveSha = injected.resolveTargetSha || resolveTargetSha
  const publish = injected.publish || publishFleetChannel
  const targetSha = await requireTargetSha(options, resolveSha)
  const channelsPath = options.channels || path.join(options.repo, 'fleet', 'channels.json')
  const channels = await readChannels(channelsPath)
  const previousTarget = requireChannelTarget(channels, 'canary')
  const previousTargetSha = await resolveSha(options.repo, previousTarget)
  const allowedSignersSha256 = await sha256SafeFile(options.allowedSigners, MAX_RECEIPT_BYTES, 'allowed signers')
  const publisherOptions = publicationOptions(options, 'canary', false)
  const validation = requireGatewayPublication(await publish(publisherOptions), 'canary')
  const operatorContracts = normalizeOperatorContracts(validation.operatorContracts,
    'canary publisher operator contracts', true)
  const gatewayOpsEvidenceDir = operatorContracts.length > 0 ? options.gatewayOpsEvidenceDir : null
  if ((operatorContracts.length > 0) !== Boolean(gatewayOpsEvidenceDir)) {
    throw new Error('canary operator readiness did not bind its evidence directory')
  }
  const authorization = `publish-canary:${options.target}:${targetSha}`
  const base = transitionReport('canary', options, targetSha, validation, {
    previousTarget,
    previousTargetSha,
    allowedSignersSha256,
    gatewayOpsEvidenceDir,
    operatorContracts,
    authorizationRequired: authorization
  })
  if (!options.publish) {
    if (options.authorize) throw new Error('--authorize is valid only with --publish')
    if (options.receipt) throw new Error('--receipt is valid only with --publish')
    return base
  }
  requireAuthorization(options, authorization)
  const receiptPath = requireAbsolutePath(options.receipt, 'receipt')
  const startedAt = nowIso(injected)
  const receipt = {
    schema: RECEIPT_SCHEMA,
    action: 'canary',
    status: 'publishing',
    target: options.target,
    targetSha,
    previousTarget,
    previousTargetSha,
    allowedSigners: options.allowedSigners,
    allowedSignersSha256,
    gatewayOpsEvidenceDir,
    operatorContracts,
    repo: options.repo,
    remote: options.remote,
    branch: options.branch,
    startedAt
  }
  await createPrivateJson(receiptPath, receipt)
  try {
    const result = requireGatewayPublication(await publish({ ...publisherOptions, publish: true }), 'canary')
    requireSameOperatorContracts(
      normalizeOperatorContracts(result.operatorContracts, 'published canary operator contracts', true),
      operatorContracts,
      'canary publication'
    )
    if (await sha256SafeFile(options.allowedSigners, MAX_RECEIPT_BYTES, 'allowed signers') !== allowedSignersSha256) {
      throw new Error('allowed signers changed during canary publication')
    }
    const completed = {
      ...receipt,
      status: result.status === 'unchanged' ? 'unchanged' : 'published',
      completedAt: nowIso(injected),
      publishedHead: requireObjectId(result.publishedHead, 'published head'),
      remoteHead: requireObjectId(result.remoteHead || result.publishedHead, 'remote head')
    }
    await replacePrivateJson(receiptPath, completed)
    return { ...base, status: completed.status, receipt: receiptPath, publication: result }
  } catch (err) {
    await replacePrivateJson(receiptPath, {
      ...receipt,
      status: 'failed',
      failedAt: nowIso(injected)
    }).catch(() => {})
    throw err
  }
}

async function runObservation (options, injected) {
  requireReleaseInputs(options)
  rejectOptions(options, ['publish', 'authorize', 'receipt', 'gatewayOpsEvidenceDir'], 'observe')
  requireCanonicalPublicationInputs(options)
  const resolveSha = injected.resolveTargetSha || resolveTargetSha
  const targetSha = await requireTargetSha(options, resolveSha)
  const canaryReceiptPath = requireAbsolutePath(options.canaryReceipt, 'canary-receipt')
  const canaryReceipt = await readCanaryReceipt(canaryReceiptPath)
  requireReceiptRelease(canaryReceipt, options, targetSha)
  await requireReceiptTrust(canaryReceipt, options)
  const canaryReceiptSha256 = await sha256SafeFile(canaryReceiptPath, MAX_RECEIPT_BYTES, 'canary receipt')
  const sessionPath = requireAbsolutePath(options.session, 'session')
  const statePath = requireAbsolutePath(options.gatewayWindowState, 'gateway-window-state')
  const evidencePath = requireAbsolutePath(options.evidence, 'evidence')
  requireAbsolutePath(options.knownHosts, 'known-hosts')
  requireAbsolutePath(options.gatewayEvidence, 'gateway-evidence')
  const observerArgs = buildObserverArgs(options, targetSha, statePath, evidencePath)
  const observerArgsSha256 = sha256(Buffer.from(JSON.stringify(observerArgs)))
  const knownHostsSha256 = await sha256SafeFile(options.knownHosts, MAX_RECEIPT_BYTES, 'known hosts')
  const relaysSha256 = await sha256SafeFile(options.relays, MAX_EVIDENCE_BYTES, 'fleet inventory')
  const channelsSha256 = await sha256SafeFile(options.channels, MAX_RECEIPT_BYTES, 'fleet channels')
  const sessionBase = {
    schema: OBSERVATION_SCHEMA,
    status: 'observing',
    target: options.target,
    targetSha,
    repo: options.repo,
    allowedSigners: options.allowedSigners,
    relays: options.relays,
    channels: options.channels,
    knownHosts: options.knownHosts,
    canaryReceipt: canaryReceiptPath,
    canaryReceiptSha256,
    gatewayOpsEvidenceDir: canaryReceipt.gatewayOpsEvidenceDir,
    operatorContracts: canaryReceipt.operatorContracts,
    gatewayManifest: options.gatewayManifest,
    gatewayWindowState: statePath,
    rolloutEvidence: evidencePath,
    observerArgsSha256,
    knownHostsSha256,
    relaysSha256,
    channelsSha256
  }
  let session
  if (options.resume) {
    session = await readObservationSession(sessionPath)
    if (session.status !== 'observing') throw new Error('only an observing session can be resumed')
    requireOnlyKeys('observing session', session, [
      'schema', 'status', 'target', 'targetSha', 'repo', 'allowedSigners',
      'relays', 'channels', 'knownHosts', 'canaryReceipt',
      'canaryReceiptSha256', 'gatewayOpsEvidenceDir', 'operatorContracts',
      'gatewayManifest', 'gatewayWindowState',
      'rolloutEvidence', 'observerArgsSha256', 'knownHostsSha256',
      'relaysSha256', 'channelsSha256', 'startedAt'
    ])
    for (const name of Object.keys(sessionBase)) {
      const matches = name === 'operatorContracts'
        ? JSON.stringify(session[name]) === JSON.stringify(sessionBase[name])
        : session[name] === sessionBase[name]
      if (!matches) throw new Error(`observation session ${name} does not match this invocation`)
    }
    requireIsoTimestamp(session.startedAt, 'session startedAt')
  } else {
    await requireMissing(sessionPath, 'session')
    await requireMissing(statePath, 'gateway-window-state')
    await requireMissing(evidencePath, 'evidence')
    session = { ...sessionBase, startedAt: nowIso(injected) }
    await createPrivateJson(sessionPath, session)
  }

  const runObserver = injected.runObserver || runObserverProcess
  let result
  try {
    result = await runObserver(observerArgs, { observer: defaultObserver })
  } catch (err) {
    await replacePrivateJson(sessionPath, {
      ...session,
      status: 'failed',
      failedAt: nowIso(injected),
      observerExit: 1
    }).catch(() => {})
    throw err
  }
  const exitCode = normalizeExitCode(result)
  if (exitCode !== 0) {
    await replacePrivateJson(sessionPath, {
      ...session,
      status: 'failed',
      failedAt: nowIso(injected),
      observerExit: exitCode
    })
    throw new Error(`authoritative observer stopped with exit ${exitCode}; session is failed and cannot resume`)
  }

  await requireReceiptTrust(canaryReceipt, options)
  await requireObservationInputHashes(session, options)

  const state = await readBoundedJson(statePath, MAX_EVIDENCE_BYTES, 'gateway window state')
  const evidence = await readBoundedJson(evidencePath, MAX_EVIDENCE_BYTES, 'canary rollout evidence')
  const observationWindowMs = validateCompletedObservation(state, evidence, options, targetSha)
  const completedAt = nowIso(injected)
  const elapsedMs = Date.parse(completedAt) - Date.parse(session.startedAt)
  if (!Number.isSafeInteger(elapsedMs) || elapsedMs < observationWindowMs) {
    await replacePrivateJson(sessionPath, {
      ...session,
      status: 'failed',
      failedAt: completedAt,
      observerExit: 0
    })
    throw new Error('observer returned success before this controller session spanned the manifest observation window')
  }
  const completed = {
    ...session,
    status: 'complete',
    completedAt,
    elapsedMs,
    observationWindowMs,
    windowStateSha256: await sha256SafeFile(statePath, MAX_EVIDENCE_BYTES, 'gateway window state'),
    rolloutEvidenceSha256: await sha256SafeFile(evidencePath, MAX_EVIDENCE_BYTES, 'canary rollout evidence')
  }
  await replacePrivateJson(sessionPath, completed)
  return {
    schema: RECEIPT_SCHEMA,
    action: 'observe',
    status: 'complete',
    target: options.target,
    targetSha,
    session: sessionPath,
    elapsedMs,
    observationWindowMs,
    stableRemainsExplicit: true,
    continuityAuthority: 'controller-retained-manifest-bound',
    independentWitnessProof: false
  }
}

async function runStable (options, injected) {
  requireReleaseInputs(options)
  rejectOptions(options, observationOnlyOptions(['resume']), 'stable')
  requireCanonicalPublicationInputs(options)
  const resolveSha = injected.resolveTargetSha || resolveTargetSha
  const publish = injected.publish || publishFleetChannel
  const targetSha = await requireTargetSha(options, resolveSha)
  const canaryReceiptPath = requireAbsolutePath(options.canaryReceipt, 'canary-receipt')
  const canaryReceipt = await readCanaryReceipt(canaryReceiptPath)
  requireReceiptRelease(canaryReceipt, options, targetSha)
  await requireReceiptTrust(canaryReceipt, options)
  const operatorContracts = requireReceiptOperatorReadiness(canaryReceipt, options)
  const sessionPath = requireAbsolutePath(options.session, 'session')
  const session = await readObservationSession(sessionPath)
  validateCompleteSession(session, options, targetSha, canaryReceiptPath)
  if (session.gatewayOpsEvidenceDir !== canaryReceipt.gatewayOpsEvidenceDir) {
    throw new Error('observation session changed the operator-readiness evidence directory')
  }
  requireSameOperatorContracts(
    normalizeOperatorContracts(session.operatorContracts, 'observation session operator contracts'),
    operatorContracts,
    'observation session'
  )
  await requireObservationInputHashes(session, options)
  const currentCanaryReceiptSha = await sha256SafeFile(canaryReceiptPath, MAX_RECEIPT_BYTES, 'canary receipt')
  if (currentCanaryReceiptSha !== session.canaryReceiptSha256) throw new Error('canary receipt changed after observation started')
  const stateSha = await sha256SafeFile(session.gatewayWindowState, MAX_EVIDENCE_BYTES, 'gateway window state')
  const evidenceSha = await sha256SafeFile(session.rolloutEvidence, MAX_EVIDENCE_BYTES, 'canary rollout evidence')
  if (stateSha !== session.windowStateSha256 || evidenceSha !== session.rolloutEvidenceSha256) {
    throw new Error('observation evidence changed after the controller session completed')
  }
  const state = await readBoundedJson(session.gatewayWindowState, MAX_EVIDENCE_BYTES, 'gateway window state')
  const evidence = await readBoundedJson(session.rolloutEvidence, MAX_EVIDENCE_BYTES, 'canary rollout evidence')
  if (validateCompletedObservation(state, evidence, options, targetSha) !== session.observationWindowMs) {
    throw new Error('completed observation session window drifted from its retained evidence')
  }
  const channelsPath = options.channels || path.join(options.repo, 'fleet', 'channels.json')
  const channels = await readChannels(channelsPath)
  if (requireChannelTarget(channels, 'canary') !== options.target) {
    throw new Error('canary channel no longer points at the observed release')
  }
  const previousTarget = requireChannelTarget(channels, 'stable')
  const publisherOptions = {
    ...publicationOptions(options, 'stable', false),
    canaryEvidence: session.rolloutEvidence,
    gatewayWindowState: session.gatewayWindowState
  }
  const validation = requireGatewayPublication(await publish(publisherOptions), 'stable')
  requireSameOperatorContracts(
    normalizeOperatorContracts(validation.operatorContracts, 'stable publisher operator contracts', true),
    operatorContracts,
    'stable validation'
  )
  const authorization = `publish-stable:${options.target}:${targetSha}`
  const base = transitionReport('stable', options, targetSha, validation, {
    previousTarget,
    observationSession: sessionPath,
    gatewayOpsEvidenceDir: canaryReceipt.gatewayOpsEvidenceDir,
    operatorContracts,
    authorizationRequired: authorization,
    continuityAuthority: 'controller-retained-manifest-bound',
    independentWitnessProof: false
  })
  if (!options.publish) {
    if (options.authorize) throw new Error('--authorize is valid only with --publish')
    if (options.receipt) throw new Error('--receipt is valid only with --publish')
    return base
  }
  requireAuthorization(options, authorization)
  const receiptPath = requireAbsolutePath(options.receipt, 'receipt')
  const startedAt = nowIso(injected)
  const receipt = {
    schema: RECEIPT_SCHEMA,
    action: 'stable',
    status: 'publishing',
    target: options.target,
    targetSha,
    previousTarget,
    observationSession: sessionPath,
    observationSessionSha256: await sha256SafeFile(sessionPath, MAX_RECEIPT_BYTES, 'observation session'),
    gatewayOpsEvidenceDir: canaryReceipt.gatewayOpsEvidenceDir,
    operatorContracts,
    repo: options.repo,
    remote: options.remote,
    branch: options.branch,
    startedAt
  }
  await createPrivateJson(receiptPath, receipt)
  try {
    const result = requireGatewayPublication(await publish({ ...publisherOptions, publish: true }), 'stable')
    requireSameOperatorContracts(
      normalizeOperatorContracts(result.operatorContracts, 'published stable operator contracts', true),
      operatorContracts,
      'stable publication'
    )
    await requireReceiptTrust(canaryReceipt, options)
    const completed = {
      ...receipt,
      status: result.status === 'unchanged' ? 'unchanged' : 'published',
      completedAt: nowIso(injected),
      publishedHead: requireObjectId(result.publishedHead, 'published head'),
      remoteHead: requireObjectId(result.remoteHead || result.publishedHead, 'remote head')
    }
    await replacePrivateJson(receiptPath, completed)
    return { ...base, status: completed.status, receipt: receiptPath, publication: result }
  } catch (err) {
    await replacePrivateJson(receiptPath, { ...receipt, status: 'failed', failedAt: nowIso(injected) }).catch(() => {})
    throw err
  }
}

function normalizeOptions (input) {
  const options = { ...(input || {}) }
  if (!['canary', 'observe', 'stable', 'recover-canary', 'abort-canary'].includes(options.action)) {
    throw new Error('action must be exactly canary, observe, stable, recover-canary, or abort-canary')
  }
  options.repo = requireAbsolutePath(path.resolve(options.repo || defaultRepoRoot), 'repo')
  options.remote = options.remote || 'origin'
  options.branch = options.branch || 'main'
  options.gatewayManifest = options.gatewayManifest || CANONICAL_GATEWAY_MANIFEST
  options.relays = options.relays || path.join(options.repo, 'fleet', 'relays.json')
  options.channels = options.channels || path.join(options.repo, 'fleet', 'channels.json')
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(options.remote)) throw new Error('--remote is invalid')
  if (!/^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$/.test(options.branch) || options.branch.includes('..')) {
    throw new Error('--branch is invalid')
  }
  if (!isSafeRepoRelativePath(options.gatewayManifest)) throw new Error('--gateway-manifest must be a safe repo-relative path')
  for (const name of [
    'allowedSigners', 'relays', 'channels', 'receipt', 'canaryReceipt', 'session',
    'knownHosts', 'gatewayEvidence', 'gatewayWindowState', 'evidence', 'sshKey',
    'gatewayOpsEvidenceDir'
  ]) {
    if (options[name] != null) options[name] = requireAbsolutePath(options[name], kebab(name))
  }
  options.publish = options.publish === true
  options.resume = options.resume === true
  return options
}

function requireReleaseInputs (options) {
  if (!RELEASE_TAG_PATTERN.test(options.target || '')) throw new Error('--target must be an immutable release tag like v1.2.3')
  requireObjectId(options.targetSha, 'target SHA')
  requireAbsolutePath(options.allowedSigners, 'allowed-signers')
}

async function requireTargetSha (options, resolver) {
  const expected = requireObjectId(options.targetSha, 'target SHA')
  const actual = await resolver(options.repo, options.target)
  if (actual !== expected) throw new Error(`--target-sha does not match ${options.target}^{commit}`)
  return actual
}

function publicationOptions (options, channel, publish) {
  const result = {
    repo: options.repo,
    remote: options.remote,
    branch: options.branch,
    channel,
    target: options.target,
    allowedSigners: options.allowedSigners,
    publish
  }
  if (options.relays) result.relays = options.relays
  if (options.gatewayOpsEvidenceDir) result.gatewayOpsEvidenceDir = options.gatewayOpsEvidenceDir
  return result
}

function requireGatewayPublication (result, channel) {
  requirePublicationShape(result, channel)
  if (result.publicGatewayRequired !== true) {
    throw new Error(`${channel} transition is restricted to an enabled canonical public gateway release`)
  }
  if (result.operatorContracts.length < 1) {
    throw new Error(`${channel} transition requires public-t1 operator contracts for every enabled gateway cohort relay`)
  }
  return result
}

function requirePublicationShape (result, channel, target) {
  if (!result || typeof result !== 'object' || Array.isArray(result) ||
      result.schema !== 'hiverelay-fleet-channel-publication-v1' ||
      result.channel !== channel || (target && result.target !== target) ||
      !['dry-run', 'published', 'unchanged'].includes(result.status) ||
      typeof result.publicGatewayRequired !== 'boolean' ||
      !Array.isArray(result.operatorContracts)) {
    throw new Error('publisher returned an invalid transition result')
  }
  normalizeOperatorContracts(result.operatorContracts, 'publisher operator contracts', true)
  return result
}

function normalizeOperatorContracts (value, label, publication = false) {
  if (!Array.isArray(value) || value.length > 64) throw new Error(`${label} must be a bounded array`)
  const contracts = value.map((contract, index) => {
    if (!contract || typeof contract !== 'object' || Array.isArray(contract)) {
      throw new Error(`${label}[${index}] must be an object`)
    }
    const invariantKeys = [
      'relay', 'operatorId', 'registrableDomain', 'suffix',
      'operatorContractSha256', 'certificateSpkiSha256', 'expectedAddresses'
    ]
    requireOnlyKeys(`${label}[${index}]`, contract,
      publication ? [...invariantKeys, 'checkedAt', 'evidenceSha256'] : invariantKeys)
    for (const name of ['relay', 'operatorId']) {
      if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(contract[name] || '')) {
        throw new Error(`${label}[${index}] ${name} is invalid`)
      }
    }
    for (const name of ['registrableDomain', 'suffix']) {
      if (!/^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])$/.test(contract[name] || '') ||
          !contract[name].includes('.')) {
        throw new Error(`${label}[${index}] ${name} is invalid`)
      }
    }
    for (const name of ['operatorContractSha256', 'certificateSpkiSha256']) {
      if (!/^[a-f0-9]{64}$/.test(contract[name] || '')) throw new Error(`${label}[${index}] ${name} is invalid`)
    }
    if (!Array.isArray(contract.expectedAddresses) || contract.expectedAddresses.length < 1 ||
        contract.expectedAddresses.length > 16) {
      throw new Error(`${label}[${index}] expectedAddresses is invalid`)
    }
    const expectedAddresses = contract.expectedAddresses.map(address => {
      const normalized = String(address || '').toLowerCase()
      if (normalized.length < 2 || normalized.length > 64 || hasControlChars(normalized) || isIP(normalized) === 0) {
        throw new Error(`${label}[${index}] expected address is invalid`)
      }
      return normalized
    }).sort()
    if (new Set(expectedAddresses).size !== expectedAddresses.length) {
      throw new Error(`${label}[${index}] expectedAddresses contains duplicates`)
    }
    if (publication) {
      requireIsoTimestamp(contract.checkedAt, `${label}[${index}] checkedAt`)
      if (!/^[a-f0-9]{64}$/.test(contract.evidenceSha256 || '')) {
        throw new Error(`${label}[${index}] evidenceSha256 is invalid`)
      }
    }
    return {
      relay: contract.relay,
      operatorId: contract.operatorId,
      registrableDomain: contract.registrableDomain,
      suffix: contract.suffix,
      operatorContractSha256: contract.operatorContractSha256,
      certificateSpkiSha256: contract.certificateSpkiSha256,
      expectedAddresses
    }
  }).sort((left, right) => left.relay.localeCompare(right.relay))
  if (new Set(contracts.map(contract => contract.relay)).size !== contracts.length) {
    throw new Error(`${label} contains duplicate relay bindings`)
  }
  return contracts
}

function requireSameOperatorContracts (actual, expected, label) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${label} changed the signed operator-contract bindings`)
  }
}

function transitionReport (action, options, targetSha, validation, extra) {
  return {
    schema: RECEIPT_SCHEMA,
    action,
    status: 'validated',
    target: options.target,
    targetSha,
    repo: options.repo,
    remote: options.remote,
    branch: options.branch,
    publicGatewayRequired: validation.publicGatewayRequired,
    wouldChange: validation.wouldChange,
    ...extra
  }
}

function requireAuthorization (options, expected) {
  if (options.authorize !== expected) throw new Error(`--authorize must exactly equal ${expected}`)
}

function rejectOptions (options, names, action) {
  for (const name of names) {
    if (options[name]) throw new Error(`--${kebab(name)} is not valid for ${action}`)
  }
}

function observationOnlyOptions (extra = []) {
  return [
    ...extra,
    'knownHosts', 'gatewayEvidence', 'gatewayWindowState', 'evidence',
    'sampleIntervalMs', 'maxRuntimeMs', 'sshCommand', 'sshKey', 'sshUser',
    'remoteRepoDir', 'service', 'api', 'timeoutMs', 'intervalMs', 'sshTimeoutMs'
  ]
}

function requireCanonicalPublicationInputs (options) {
  if (options.gatewayManifest !== CANONICAL_GATEWAY_MANIFEST) {
    throw new Error(`public gateway publication requires ${CANONICAL_GATEWAY_MANIFEST}`)
  }
  const canonicalChannels = path.join(options.repo, 'fleet', 'channels.json')
  if (options.channels && options.channels !== canonicalChannels) {
    throw new Error('public gateway publication requires the canonical repo fleet/channels.json')
  }
}

async function readCanaryReceipt (file) {
  const receipt = await readPrivateJson(file, MAX_RECEIPT_BYTES, 'canary receipt')
  requireOnlyKeys('canary receipt', receipt, [
    'schema', 'action', 'status', 'target', 'targetSha', 'previousTarget',
    'previousTargetSha', 'allowedSigners', 'allowedSignersSha256', 'repo',
    'gatewayOpsEvidenceDir', 'operatorContracts', 'remote', 'branch',
    'startedAt', 'completedAt', 'publishedHead', 'remoteHead'
  ])
  if (receipt.schema !== RECEIPT_SCHEMA || receipt.action !== 'canary' ||
      !['published', 'unchanged'].includes(receipt.status)) {
    throw new Error('canary receipt is not a completed canary publication')
  }
  if (!RELEASE_TAG_PATTERN.test(receipt.target) || !RELEASE_TAG_PATTERN.test(receipt.previousTarget)) {
    throw new Error('canary receipt contains invalid release tags')
  }
  requireObjectId(receipt.targetSha, 'canary receipt target SHA')
  requireObjectId(receipt.previousTargetSha, 'canary receipt previous target SHA')
  requireObjectId(receipt.publishedHead, 'canary receipt published head')
  requireObjectId(receipt.remoteHead, 'canary receipt remote head')
  requireAbsolutePath(receipt.allowedSigners, 'canary receipt allowed-signers')
  if (!/^[a-f0-9]{64}$/.test(receipt.allowedSignersSha256 || '')) {
    throw new Error('canary receipt allowed signers digest is invalid')
  }
  requireIsoTimestamp(receipt.startedAt, 'canary receipt startedAt')
  requireIsoTimestamp(receipt.completedAt, 'canary receipt completedAt')
  const operatorContracts = normalizeOperatorContracts(receipt.operatorContracts, 'canary receipt operator contracts')
  if (receipt.gatewayOpsEvidenceDir !== null) {
    receipt.gatewayOpsEvidenceDir = requireAbsolutePath(receipt.gatewayOpsEvidenceDir, 'canary receipt gateway-ops-evidence-dir')
  }
  if ((operatorContracts.length > 0) !== Boolean(receipt.gatewayOpsEvidenceDir)) {
    throw new Error('canary receipt operator contracts do not bind an evidence directory')
  }
  receipt.operatorContracts = operatorContracts
  return receipt
}

function requireReceiptRelease (receipt, options, targetSha) {
  if (receipt.target !== options.target || receipt.targetSha !== targetSha ||
      receipt.repo !== options.repo || receipt.remote !== options.remote || receipt.branch !== options.branch) {
    throw new Error('canary receipt does not bind this exact release and control repository')
  }
}

async function requireReceiptTrust (receipt, options) {
  if (receipt.allowedSigners !== options.allowedSigners) {
    throw new Error('allowed signers path changed after canary publication')
  }
  const current = await sha256SafeFile(options.allowedSigners, MAX_RECEIPT_BYTES, 'allowed signers')
  if (current !== receipt.allowedSignersSha256) {
    throw new Error('allowed signers bytes changed after canary publication')
  }
}

function requireReceiptOperatorReadiness (receipt, options) {
  const invokedDirectory = options.gatewayOpsEvidenceDir || null
  if (receipt.gatewayOpsEvidenceDir !== invokedDirectory) {
    throw new Error('operator-readiness evidence directory changed after canary publication')
  }
  return normalizeOperatorContracts(receipt.operatorContracts, 'canary receipt operator contracts')
}

async function requireObservationInputHashes (session, options) {
  if (session.allowedSigners !== options.allowedSigners || session.relays !== options.relays ||
      session.channels !== options.channels || (options.knownHosts && session.knownHosts !== options.knownHosts)) {
    throw new Error('observation trust or fleet input paths changed')
  }
  const current = {
    knownHostsSha256: await sha256SafeFile(session.knownHosts, MAX_RECEIPT_BYTES, 'known hosts'),
    relaysSha256: await sha256SafeFile(session.relays, MAX_EVIDENCE_BYTES, 'fleet inventory'),
    channelsSha256: await sha256SafeFile(session.channels, MAX_RECEIPT_BYTES, 'fleet channels')
  }
  for (const [name, digest] of Object.entries(current)) {
    if (session[name] !== digest) throw new Error(`observation input ${name} changed during the retained session`)
  }
}

async function readObservationSession (file) {
  const session = await readPrivateJson(file, MAX_RECEIPT_BYTES, 'observation session')
  if (session.schema !== OBSERVATION_SCHEMA) throw new Error('observation session schema is invalid')
  return session
}

function validateCompleteSession (session, options, targetSha, canaryReceiptPath) {
  requireOnlyKeys('completed observation session', session, [
    'schema', 'status', 'target', 'targetSha', 'repo', 'allowedSigners',
    'relays', 'channels', 'knownHosts', 'canaryReceipt',
    'canaryReceiptSha256', 'gatewayOpsEvidenceDir', 'operatorContracts',
    'gatewayManifest', 'gatewayWindowState',
    'rolloutEvidence', 'observerArgsSha256', 'knownHostsSha256',
    'relaysSha256', 'channelsSha256', 'startedAt', 'completedAt', 'elapsedMs',
    'observationWindowMs', 'windowStateSha256', 'rolloutEvidenceSha256'
  ])
  if (session.status !== 'complete') throw new Error('stable requires a completed observation session')
  if (session.target !== options.target || session.targetSha !== targetSha || session.repo !== options.repo ||
      session.canaryReceipt !== canaryReceiptPath || session.gatewayManifest !== options.gatewayManifest ||
      session.allowedSigners !== options.allowedSigners || session.relays !== options.relays ||
      session.channels !== options.channels) {
    throw new Error('completed observation session does not bind this stable transition')
  }
  requireIsoTimestamp(session.startedAt, 'session startedAt')
  requireIsoTimestamp(session.completedAt, 'session completedAt')
  if (!Number.isSafeInteger(session.observationWindowMs) || session.observationWindowMs < MIN_OBSERVATION_WINDOW_MS ||
      !Number.isSafeInteger(session.elapsedMs) || session.elapsedMs < session.observationWindowMs ||
      Date.parse(session.completedAt) - Date.parse(session.startedAt) !== session.elapsedMs) {
    throw new Error('completed observation session did not span its manifest window')
  }
  for (const name of [
    'canaryReceiptSha256', 'windowStateSha256', 'rolloutEvidenceSha256',
    'knownHostsSha256', 'relaysSha256', 'channelsSha256'
  ]) {
    if (!/^[a-f0-9]{64}$/.test(session[name] || '')) throw new Error(`session ${name} is invalid`)
  }
  if (!/^[a-f0-9]{64}$/.test(session.observerArgsSha256 || '')) throw new Error('session observerArgsSha256 is invalid')
  requireAbsolutePath(session.gatewayWindowState, 'session gateway-window-state')
  requireAbsolutePath(session.rolloutEvidence, 'session rollout-evidence')
  requireAbsolutePath(session.knownHosts, 'session known-hosts')
  requireAbsolutePath(session.relays, 'session relays')
  requireAbsolutePath(session.channels, 'session channels')
  if (session.gatewayOpsEvidenceDir !== null) {
    requireAbsolutePath(session.gatewayOpsEvidenceDir, 'session gateway-ops-evidence-dir')
  }
  const operatorContracts = normalizeOperatorContracts(session.operatorContracts, 'session operator contracts')
  if ((operatorContracts.length > 0) !== Boolean(session.gatewayOpsEvidenceDir)) {
    throw new Error('session operator contracts do not bind an evidence directory')
  }
}

function validateCompletedObservation (state, evidence, options, targetSha) {
  if (state.schema !== WINDOW_STATE_SCHEMA || state.releaseTarget !== options.target ||
      state.releaseSha !== targetSha || state.channel !== 'canary') {
    throw new Error('observer window state does not bind the exact canary release')
  }
  if (!Number.isSafeInteger(state.observationWindowMs) || state.observationWindowMs < MIN_OBSERVATION_WINDOW_MS) {
    throw new Error('observer window state weakens the minimum 24-hour window')
  }
  if (!evidence || evidence.schemaVersion !== 2 || evidence.status !== 'verified' ||
      evidence.target?.tag !== options.target || evidence.target?.sha !== targetSha ||
      evidence.target?.channel !== 'canary' || evidence.publicGateway?.window?.complete !== true) {
    throw new Error('observer did not produce completed manifest-bound canary evidence')
  }
  return state.observationWindowMs
}

function buildObserverArgs (options, targetSha, statePath, evidencePath) {
  const args = []
  for (const [name, value] of [
    ['sample-interval-ms', options.sampleIntervalMs],
    ['max-runtime-ms', options.maxRuntimeMs]
  ]) {
    if (value) args.push(`--${name}`, exactIntegerString(value, name))
  }
  args.push('--')
  const forwarded = [
    ['target', options.target],
    ['target-sha', targetSha],
    ['channel', 'canary'],
    ['repo', options.repo],
    ['relays', options.relays],
    ['channels', options.channels],
    ['known-hosts', options.knownHosts],
    ['allowed-signers', options.allowedSigners],
    ['gateway-evidence', options.gatewayEvidence],
    ['gateway-manifest', options.gatewayManifest],
    ['gateway-window-state', statePath],
    ['evidence', evidencePath],
    ['ssh-command', options.sshCommand],
    ['ssh-key', options.sshKey],
    ['ssh-user', options.sshUser],
    ['remote-repo-dir', options.remoteRepoDir],
    ['service', options.service],
    ['api', options.api],
    ['timeout-ms', options.timeoutMs],
    ['interval-ms', options.intervalMs],
    ['ssh-timeout-ms', options.sshTimeoutMs]
  ]
  for (const [name, value] of forwarded) {
    if (value != null && value !== '') args.push(`--${name}`, String(value))
  }
  return args
}

async function runObserverProcess (args, { observer }) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [observer, ...args], { stdio: 'inherit', env: process.env })
    child.once('error', reject)
    child.once('exit', (code, signal) => {
      if (signal) reject(new Error(`observer terminated by ${signal}`))
      else resolve({ code: Number.isInteger(code) ? code : 1 })
    })
  })
}

function normalizeExitCode (result) {
  if (Number.isInteger(result)) return result
  if (result && Number.isInteger(result.code)) return result.code
  throw new Error('observer runner returned an invalid exit result')
}

async function resolveTargetSha (repo, target) {
  try {
    const result = await execFileAsync(GIT_PROGRAM, [
      '-C', repo, '--no-replace-objects', 'rev-parse', '--verify', `refs/tags/${target}^{commit}`
    ], {
      encoding: 'utf8',
      env: hardenedGitEnv(),
      maxBuffer: 1024 * 1024,
      timeout: 15_000
    })
    return requireObjectId(result.stdout.trim().toLowerCase(), `${target} commit`)
  } catch (err) {
    throw new Error(`cannot resolve exact release tag ${target}: ${safeError(err?.stderr || err)}`)
  }
}

async function isCommitAncestor (repo, ancestor, descendant) {
  try {
    await execFileAsync(GIT_PROGRAM, [
      '-C', repo, '--no-replace-objects', 'merge-base', '--is-ancestor', ancestor, descendant
    ], {
      encoding: 'utf8',
      env: hardenedGitEnv(),
      maxBuffer: 1024 * 1024,
      timeout: 15_000
    })
    return true
  } catch (err) {
    if (err?.code === 1) return false
    throw new Error(`cannot prove recovery ancestry: ${safeError(err?.stderr || err)}`)
  }
}

async function readChannels (file) {
  const value = await readBoundedJson(file, MAX_RECEIPT_BYTES, 'fleet channels')
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('fleet channels must be a JSON object')
  return value
}

function requireChannelTarget (channels, channel) {
  const target = channels[channel]
  if (!RELEASE_TAG_PATTERN.test(target || '')) throw new Error(`fleet channel ${channel} does not contain a release tag`)
  return target
}

async function readPrivateJson (file, maxBytes, label) {
  const snapshot = await statSafeFile(file, maxBytes, label, true)
  return parseJsonObject(snapshot.buffer, label)
}

async function readBoundedJson (file, maxBytes, label) {
  const snapshot = await statSafeFile(file, maxBytes, label, false)
  return parseJsonObject(snapshot.buffer, label)
}

async function statSafeFile (file, maxBytes, label, privateMode) {
  let handle
  try {
    if (typeof fsConstants.O_NOFOLLOW !== 'number') throw new Error('platform lacks O_NOFOLLOW')
    handle = await open(file, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW)
    const before = await handle.stat({ bigint: true })
    if (!before.isFile() || before.nlink !== 1n || before.size < 1n || before.size > BigInt(maxBytes)) {
      throw new Error('must be a bounded single-link regular file')
    }
    if (privateMode && (before.mode & 0o077n) !== 0n) throw new Error('must not be group/world accessible')
    const buffer = Buffer.allocUnsafe(Number(before.size))
    let offset = 0
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset)
      if (bytesRead === 0) break
      offset += bytesRead
    }
    const after = await handle.stat({ bigint: true })
    if (offset !== buffer.length || !sameSnapshot(before, after)) throw new Error('changed while being read')
    return { buffer, stat: after }
  } catch (err) {
    throw new Error(`${label} cannot be read safely: ${safeError(err)}`)
  } finally {
    await handle?.close().catch(() => {})
  }
}

async function sha256SafeFile (file, maxBytes, label) {
  const { buffer } = await statSafeFile(file, maxBytes, label, false)
  return createHash('sha256').update(buffer).digest('hex')
}

async function createPrivateJson (file, value) {
  const bytes = encodeJson(value)
  let handle
  try {
    if (typeof fsConstants.O_NOFOLLOW !== 'number') throw new Error('platform lacks O_NOFOLLOW')
    handle = await open(file,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
      0o600)
    await handle.writeFile(bytes)
    await handle.sync()
  } catch (err) {
    throw new Error(`cannot create private transition record ${file}: ${safeError(err)}`)
  } finally {
    await handle?.close().catch(() => {})
  }
}

async function replacePrivateJson (file, value) {
  await readPrivateJson(file, MAX_RECEIPT_BYTES, 'existing transition record')
  const bytes = encodeJson(value)
  const temp = path.join(path.dirname(file), `.${path.basename(file)}.tmp-${process.pid}-${randomUUID()}`)
  let handle
  try {
    handle = await open(temp,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
      0o600)
    await handle.writeFile(bytes)
    await handle.sync()
    await handle.close()
    handle = null
    await rename(temp, file)
  } catch (err) {
    throw new Error(`cannot update private transition record ${file}: ${safeError(err)}`)
  } finally {
    await handle?.close().catch(() => {})
    await unlink(temp).catch(() => {})
  }
}

async function requireMissing (file, label) {
  try {
    await lstat(file)
  } catch (err) {
    if (err?.code === 'ENOENT') return
    throw new Error(`cannot inspect ${label}: ${safeError(err)}`)
  }
  throw new Error(`${label} must not already exist; use --resume only with this wrapper's observing session`)
}

function encodeJson (value) {
  const bytes = Buffer.from(JSON.stringify(value, null, 2) + '\n')
  if (bytes.length < 2 || bytes.length > MAX_RECEIPT_BYTES || bytes.includes(0)) {
    throw new Error('transition record exceeds its closed size bound')
  }
  return bytes
}

function parseJsonObject (buffer, label) {
  let value
  try {
    value = JSON.parse(buffer.toString('utf8'))
  } catch {
    throw new Error(`${label} is not valid JSON`)
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must contain a JSON object`)
  return value
}

function sha256 (value) {
  return createHash('sha256').update(value).digest('hex')
}

function requireOnlyKeys (label, value, allowed) {
  const allowedSet = new Set(allowed)
  for (const key of Object.keys(value)) {
    if (!allowedSet.has(key)) throw new Error(`${label} has unsupported field ${key}`)
  }
  for (const key of allowed) {
    if (!(key in value)) throw new Error(`${label} is missing field ${key}`)
  }
}

function sameSnapshot (left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode &&
    left.nlink === right.nlink && left.size === right.size && left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
}

function requireObjectId (value, label) {
  const normalized = String(value || '').toLowerCase()
  if (!OBJECT_ID_PATTERN.test(normalized)) throw new Error(`${label} must be an exact Git object ID`)
  return normalized
}

function requireIsoTimestamp (value, label) {
  if (typeof value !== 'string' || new Date(value).toISOString() !== value) throw new Error(`${label} must be a canonical ISO timestamp`)
  return value
}

function requireAbsolutePath (value, label) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || value.length > 4096 || hasControlChars(value)) {
    throw new Error(`--${label} must be a bounded absolute path`)
  }
  return path.resolve(value)
}

function isSafeRepoRelativePath (value) {
  return typeof value === 'string' && value.length > 0 && value.length <= 4096 &&
    !path.isAbsolute(value) && !hasControlChars(value) && !value.split('/').includes('..')
}

function exactIntegerString (value, label) {
  const text = String(value)
  if (!/^[1-9][0-9]*$/.test(text) || !Number.isSafeInteger(Number(text))) throw new Error(`--${label} must be a safe positive integer`)
  return text
}

function nowIso (injected) {
  const value = typeof injected.now === 'function' ? injected.now() : Date.now()
  return new Date(value).toISOString()
}

function hasControlChars (value) {
  for (const character of String(value)) {
    const code = character.charCodeAt(0)
    if (code <= 31 || code === 127) return true
  }
  return false
}

function hardenedGitEnv () {
  const env = { ...process.env }
  for (const name of Object.keys(env)) {
    if (UNSAFE_GIT_ENV.has(name) || /^GIT_CONFIG_(?:KEY|VALUE)_\d+$/.test(name)) delete env[name]
  }
  return {
    ...env,
    GIT_GRAFT_FILE: '/dev/null/hiverelay-disabled',
    GIT_NO_REPLACE_OBJECTS: '1',
    GIT_OPTIONAL_LOCKS: '0'
  }
}

function parseArgs (argv) {
  if (argv.length === 0) throw new Error('action is required')
  if (argv.length === 1 && (argv[0] === '--help' || argv[0] === '-h')) return { help: true }
  const action = argv[0]
  if (action.startsWith('-')) throw new Error('action must precede options')
  const out = { action }
  const booleans = new Set(['publish', 'resume', 'help'])
  const values = new Set([
    'target', 'target-sha', 'repo', 'remote', 'branch', 'allowed-signers',
    'relays', 'channels', 'receipt', 'canary-receipt', 'session', 'known-hosts',
    'gateway-evidence', 'gateway-window-state', 'evidence', 'gateway-manifest',
    'gateway-ops-evidence-dir',
    'sample-interval-ms', 'max-runtime-ms', 'ssh-command', 'ssh-key', 'ssh-user',
    'remote-repo-dir', 'service', 'api', 'timeout-ms', 'interval-ms',
    'ssh-timeout-ms', 'authorize'
  ])
  const seen = new Set()
  for (let i = 1; i < argv.length; i++) {
    const raw = argv[i]
    if (raw === '-h') {
      if (seen.has('help')) throw new Error('duplicate --help')
      seen.add('help')
      out.help = true
      continue
    }
    if (!raw.startsWith('--')) throw new Error(`unexpected positional argument ${JSON.stringify(raw)}`)
    const name = raw.slice(2)
    if (!booleans.has(name) && !values.has(name)) throw new Error(`unknown option --${name}`)
    if (seen.has(name)) throw new Error(`duplicate option --${name}`)
    seen.add(name)
    const key = camel(name)
    if (booleans.has(name)) {
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
  return value.replace(/-([a-z])/g, (_, character) => character.toUpperCase())
}

function kebab (value) {
  return value.replace(/[A-Z]/g, character => `-${character.toLowerCase()}`)
}

function safeError (err) {
  return String(err?.message || err || 'unknown error').replace(/[\r\n\0]/g, ' ').slice(0, 1000)
}
