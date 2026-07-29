#!/usr/bin/env node

import { createHash } from 'node:crypto'
import { readFile, writeFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

export const PILOT_INPUT_SCHEMA = 'hiverelay/fleet-pilot-input/v1'
export const PILOT_PLAN_SCHEMA = 'hiverelay/fleet-pilot-plan/v1'

const COMMIT = /^[a-f0-9]{40}$/
const DIGEST = /^[a-f0-9]{64}$/
const RELEASE = /^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/

export function buildFleetPilotPlan (input = {}) {
  const inventory = isObject(input.inventory) ? input.inventory : {}
  const channels = isObject(input.channels) ? input.channels : {}
  const gateway = isObject(input.gatewayRelease) ? input.gatewayRelease : {}
  const relays = Array.isArray(inventory.relays) ? inventory.relays : []
  const targetRelay = nonEmpty(input.targetRelay) ? input.targetRelay : null
  const targetMatches = relays.filter(relay => relay?.name === targetRelay)
  const target = targetMatches.length === 1 ? targetMatches[0] : null
  const canaries = relays.filter(relay => relay?.channel === 'canary')
  const stable = relays.filter(relay => relay?.channel === 'stable')
  const pilots = relays.filter(relay => relay?.channel === 'pilot')
  const blockers = []
  const addBlocker = (id, detail) => {
    if (!blockers.some(blocker => blocker.id === id)) blockers.push({ id, detail })
  }

  if (input.schema !== PILOT_INPUT_SCHEMA) {
    addBlocker('INPUT_SCHEMA_INVALID', `schema must be ${PILOT_INPUT_SCHEMA}`)
  }
  if (!targetRelay) addBlocker('TARGET_RELAY_REQUIRED', 'name exactly one pilot relay')
  else if (targetMatches.length === 0) addBlocker('TARGET_RELAY_NOT_FOUND', `${targetRelay} is not in fleet inventory`)
  else if (targetMatches.length > 1) addBlocker('TARGET_RELAY_AMBIGUOUS', `${targetRelay} appears more than once`)

  if (!COMMIT.test(input.sourceCommit || '')) {
    addBlocker('SOURCE_COMMIT_REQUIRED', 'bind the plan to one exact source commit')
  }
  if (!RELEASE.test(input.releaseId || '')) {
    addBlocker('RELEASE_ID_REQUIRED', 'bind the plan to one exact v-prefixed release identity')
  }
  if (!DIGEST.test(input.artifactSha256 || '')) {
    addBlocker('ARTIFACT_DIGEST_REQUIRED', 'bind the plan to one immutable release artifact digest')
  }
  if (gateway.schema !== 'hiverelay-public-gateway-release-v1' || gateway.enabled !== false) {
    addBlocker('HTTPS_GATEWAY_MUST_REMAIN_DISABLED', 'the first Blind Cell fleet pilot requires the public HTTPS gateway manifest to be explicitly disabled')
  }
  if (!nonEmpty(channels.canary) || !nonEmpty(channels.stable)) {
    addBlocker('BASE_CHANNELS_REQUIRED', 'stable and canary channel targets must both exist')
  }
  if (!target || (target.channel !== 'canary' && target.channel !== 'pilot')) {
    addBlocker('TARGET_NOT_PILOT_ELIGIBLE', 'the selected pilot must be assigned to canary or a dedicated pilot channel')
  }
  if (target && (!positiveNumber(target.diskGB) || !nonEmpty(target.region))) {
    addBlocker('TARGET_CAPACITY_METADATA_INCOMPLETE', 'the selected pilot needs declared disk and failure-region metadata')
  }

  const otherCanaries = canaries.filter(relay => relay.name !== targetRelay)
  const dedicatedPilotAvailable = nonEmpty(channels.pilot)
  const effectivePilotChannel = dedicatedPilotAvailable ? 'pilot' : 'canary'
  const effectivePilotRelays = dedicatedPilotAvailable ? pilots : canaries
  const currentBernOnly = targetRelay === 'bern' &&
    effectivePilotRelays.length === 1 && effectivePilotRelays[0]?.name === 'bern'
  if (!currentBernOnly) {
    addBlocker(
      'PILOT_NOT_ISOLATED',
      `publishing ${effectivePilotChannel} would target ${effectivePilotRelays.length} relays (${effectivePilotRelays.map(relay => relay.name).join(', ') || 'none'}), not Bern alone`
    )
  }

  const sameBaseTarget = channels.canary === channels.stable
  const options = [
    {
      id: 'dedicated-pilot-channel',
      recommended: true,
      status: dedicatedPilotAvailable && target?.channel === 'pilot'
        ? 'configured-awaiting-independent-evidence'
        : dedicatedPilotAvailable
          ? 'requires-node-binding-and-human-fleet-lease'
          : 'requires-reviewed-tooling-change',
      proposedChannel: 'pilot',
      targetRelays: targetRelay ? [targetRelay] : [],
      requirements: [
        'extend the signed channel publisher, rollout checker, and evidence verifier to accept exactly pilot without weakening canary/stable rules',
        `initialize pilot to the currently accepted target before binding ${targetRelay || '<target>'}`,
        `re-run install-updater.sh pilot ${targetRelay || '<target>'} under a separate explicit fleet-operation lease`,
        'prove the node-local CHANNEL and RELAY_NAME binding through the real systemd environment',
        'publish only the pilot channel after exact RC, signature, capacity, restore, rollback, and independent-review gates pass'
      ],
      authority: { authorizesToolingChange: false, authorizesNodeBinding: false, authorizesPublication: false }
    },
    {
      id: 'temporarily-rebind-other-canaries',
      recommended: false,
      status: target?.channel === 'pilot'
        ? 'not-applicable-target-uses-dedicated-pilot'
        : sameBaseTarget
          ? 'requires-human-fleet-lease'
          : 'blocked-by-channel-target-drift',
      proposedChannel: 'canary',
      targetRelays: targetRelay ? [targetRelay] : [],
      rebindToStable: otherCanaries.map(relay => relay.name).sort(),
      requirements: [
        'confirm stable and canary currently resolve to the same accepted release before rebinding',
        'update inventory in a reviewed release commit without treating it as observed node state',
        're-run install-updater.sh stable for every non-pilot canary under a separate explicit fleet-operation lease',
        'prove the node-local channel bindings and current health before any canary publication',
        `verify the effective canary cohort contains only ${targetRelay || '<target>'}`
      ],
      authority: { authorizesInventoryEdit: false, authorizesNodeRebind: false, authorizesPublication: false }
    }
  ]

  const body = {
    schema: PILOT_PLAN_SCHEMA,
    dryRun: true,
    evidenceClass: 'local-static-pilot-plan-not-observed-fleet-state',
    status: blockers.length === 0 ? 'pilot-isolated' : 'blocked',
    sourceCommit: COMMIT.test(input.sourceCommit || '') ? input.sourceCommit : null,
    releaseId: RELEASE.test(input.releaseId || '') ? input.releaseId : null,
    artifactSha256: DIGEST.test(input.artifactSha256 || '') ? input.artifactSha256 : null,
    targetRelay,
    gateway: {
      schema: gateway.schema || null,
      enabled: gateway.enabled === false ? false : gateway.enabled ?? null,
      remainsDisabled: gateway.schema === 'hiverelay-public-gateway-release-v1' && gateway.enabled === false
    },
    inventory: {
      relayCount: relays.length,
      canaryCount: canaries.length,
      stableCount: stable.length,
      pilotCount: pilots.length,
      canaryRelays: canaries.map(relay => relay.name).sort(),
      stableRelays: stable.map(relay => relay.name).sort(),
      pilotRelays: pilots.map(relay => relay.name).sort(),
      declaredNominalDiskGB: relays.reduce((sum, relay) => sum + (positiveNumber(relay?.diskGB) ? relay.diskGB : 0), 0),
      declaredDiskIsObservedCapacityEvidence: false,
      target: target
        ? { name: target.name, channel: target.channel, region: target.region || null, declaredDiskGB: positiveNumber(target.diskGB) ? target.diskGB : null }
        : null
    },
    currentControlPlane: {
      targets: { stable: channels.stable || null, canary: channels.canary || null, pilot: channels.pilot || null },
      canaryAndStableSameTarget: sameBaseTarget,
      effectivePilotChannel,
      bernOnlyPilot: currentBernOnly
    },
    options,
    blockers,
    claimBoundary: 'This report performs no signing, channel publication, SSH, service, key, root, content, HTTPS, or fleet mutation. Declared disk sizes are inventory metadata, not observed capacity. A blocker-free result is not PG-5, PG-7, deployment authority, or rollout evidence.',
    authority: {
      authorizesMutation: false,
      authorizesPublication: false,
      authorizesHttpsActivation: false,
      authorizesContentSeeding: false,
      pg5Passed: false,
      pg7Passed: false,
      requiredNextAuthority: blockers.length === 0
        ? 'independent review followed by an explicit human fleet-operation lease'
        : 'choose and implement a reviewed isolation option, then independently verify it before seeking a fleet-operation lease'
    }
  }
  return { ...body, planDigest: sha256(stableStringify(body)) }
}

export function verifyFleetPilotPlanDigest (report) {
  if (!isObject(report) || !DIGEST.test(report.planDigest || '')) return false
  const { planDigest, ...body } = report
  return planDigest === sha256(stableStringify(body))
}

function usage () {
  return [
    'Usage: node fleet/plan-pilot-cohort.mjs [options]',
    '',
    'Options:',
    '  --inventory FILE       Fleet discovery inventory (default: fleet/relays.json)',
    '  --channels FILE        Signed channel control file (default: fleet/channels.json)',
    '  --gateway FILE         Gateway release manifest (default: fleet/public-hive-gateway-release.json)',
    '  --target-relay NAME    Exactly one intended pilot relay (default: bern)',
    '  --source-commit SHA    Exact release source commit',
    '  --release-id ID        Exact v-prefixed release identity',
    '  --artifact-sha256 SHA  Immutable release artifact digest',
    '  --out FILE             Write the report locally instead of stdout',
    '  --require-isolated     Exit 2 unless the effective cohort is Bern only',
    '',
    'There is deliberately no signing, publishing, SSH, service, key, root, content, HTTPS, or mutation mode.'
  ].join('\n')
}

async function main (argv) {
  const args = parseArgs(argv)
  if (args.help) {
    process.stdout.write(`${usage()}\n`)
    return
  }
  const [inventory, channels, gatewayRelease] = await Promise.all([
    readJson(args.inventory || 'fleet/relays.json'),
    readJson(args.channels || 'fleet/channels.json'),
    readJson(args.gateway || 'fleet/public-hive-gateway-release.json')
  ])
  const report = buildFleetPilotPlan({
    schema: PILOT_INPUT_SCHEMA,
    inventory,
    channels,
    gatewayRelease,
    targetRelay: args.targetRelay || 'bern',
    sourceCommit: args.sourceCommit,
    releaseId: args.releaseId,
    artifactSha256: args.artifactSha256
  })
  const output = `${JSON.stringify(report, null, 2)}\n`
  if (args.out) await writeFile(resolve(args.out), output)
  else process.stdout.write(output)
  if (args.requireIsolated && report.status !== 'pilot-isolated') process.exitCode = 2
}

function parseArgs (argv) {
  const result = { requireIsolated: false, help: false }
  const valued = new Map([
    ['--inventory', 'inventory'],
    ['--channels', 'channels'],
    ['--gateway', 'gateway'],
    ['--target-relay', 'targetRelay'],
    ['--source-commit', 'sourceCommit'],
    ['--release-id', 'releaseId'],
    ['--artifact-sha256', 'artifactSha256'],
    ['--out', 'out']
  ])
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index]
    if (valued.has(arg)) {
      const value = argv[++index]
      if (!value || value.startsWith('--')) throw new Error(`${arg} requires a value`)
      result[valued.get(arg)] = value
    } else if (arg === '--require-isolated') result.requireIsolated = true
    else if (arg === '--help' || arg === '-h') result.help = true
    else throw new Error(`unknown argument ${arg}`)
  }
  return result
}

async function readJson (path) {
  return JSON.parse(await readFile(resolve(path), 'utf8'))
}

function positiveNumber (value) {
  return typeof value === 'number' && Number.isFinite(value) && value > 0
}

function nonEmpty (value) {
  return typeof value === 'string' && value.length > 0
}

function isObject (value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function stableStringify (value) {
  return JSON.stringify(sortValue(value))
}

function sortValue (value) {
  if (Array.isArray(value)) return value.map(sortValue)
  if (!isObject(value)) return value
  return Object.fromEntries(Object.keys(value).sort().map(key => [key, sortValue(value[key])]))
}

function sha256 (value) {
  return createHash('sha256').update(value).digest('hex')
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main(process.argv.slice(2)).catch(error => {
    process.stderr.write(`fleet pilot planner: ${error.message}\n`)
    process.exitCode = 1
  })
}
