import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'
import {
  PILOT_INPUT_SCHEMA,
  buildFleetPilotPlan,
  verifyFleetPilotPlanDigest
} from './plan-pilot-cohort.mjs'

const SOURCE = '1'.repeat(40)
const ARTIFACT = 'a'.repeat(64)

test('current fleet fails closed because canary targets three relays', async () => {
  const [inventory, channels, gatewayRelease] = await Promise.all([
    readJson('./relays.json'),
    readJson('./channels.json'),
    readJson('./public-hive-gateway-release.json')
  ])
  const report = buildFleetPilotPlan({
    schema: PILOT_INPUT_SCHEMA,
    inventory,
    channels,
    gatewayRelease,
    targetRelay: 'bern',
    sourceCommit: SOURCE,
    releaseId: 'v1.0.0-rc.1',
    artifactSha256: ARTIFACT
  })

  assert.equal(report.status, 'blocked')
  assert.equal(report.inventory.relayCount, 9)
  assert.equal(report.inventory.canaryCount, 3)
  assert.equal(report.inventory.stableCount, 6)
  assert.deepEqual(report.inventory.canaryRelays, ['bern', 'utah', 'utah-0.5gb'])
  assert.equal(report.inventory.target.declaredDiskGB, 484)
  assert.equal(report.inventory.declaredNominalDiskGB, 2138)
  assert.equal(report.gateway.remainsDisabled, true)
  assert.equal(report.currentControlPlane.bernOnlyPilot, false)
  assert.ok(report.blockers.some(blocker => blocker.id === 'PILOT_NOT_ISOLATED'))
  assert.equal(report.options[0].id, 'dedicated-pilot-channel')
  assert.equal(report.options[0].recommended, true)
  assert.equal(report.options[0].status, 'requires-reviewed-tooling-change')
  assert.deepEqual(report.options[1].rebindToStable, ['utah', 'utah-0.5gb'])
  assert.equal(report.options[1].status, 'requires-human-fleet-lease')
  assert.equal(report.authority.authorizesMutation, false)
  assert.equal(report.authority.authorizesPublication, false)
  assert.equal(report.authority.authorizesHttpsActivation, false)
  assert.equal(report.authority.authorizesContentSeeding, false)
  assert.equal(verifyFleetPilotPlanDigest(report), true)
})

test('Bern-only inventory produces an isolated local plan without mutation authority', () => {
  const inventory = fixtureInventory()
  inventory.relays.find(relay => relay.name === 'utah').channel = 'stable'
  inventory.relays.find(relay => relay.name === 'utah-0.5gb').channel = 'stable'
  const report = buildFleetPilotPlan(completeInput({ inventory }))

  assert.equal(report.status, 'pilot-isolated')
  assert.deepEqual(report.blockers, [])
  assert.deepEqual(report.inventory.canaryRelays, ['bern'])
  assert.equal(report.currentControlPlane.bernOnlyPilot, true)
  assert.equal(report.authority.pg5Passed, false)
  assert.equal(report.authority.pg7Passed, false)
  assert.equal(verifyFleetPilotPlanDigest(report), true)
})

test('dedicated pilot channel isolates Bern without disturbing canary', () => {
  const inventory = fixtureInventory()
  inventory.relays.find(relay => relay.name === 'bern').channel = 'pilot'
  const report = buildFleetPilotPlan(completeInput({
    inventory,
    channels: { stable: 'v0.24.3', canary: 'v0.24.3', pilot: 'v0.24.3' }
  }))

  assert.equal(report.status, 'pilot-isolated')
  assert.deepEqual(report.inventory.pilotRelays, ['bern'])
  assert.deepEqual(report.inventory.canaryRelays, ['utah', 'utah-0.5gb'])
  assert.equal(report.currentControlPlane.effectivePilotChannel, 'pilot')
  assert.equal(report.options[0].status, 'configured-awaiting-independent-evidence')
  assert.equal(report.options[1].status, 'not-applicable-target-uses-dedicated-pilot')
})

test('enabled HTTPS manifest blocks the Blind Cell first pilot', () => {
  const input = completeInput()
  input.gatewayRelease.enabled = true
  const report = buildFleetPilotPlan(input)

  assert.equal(report.status, 'blocked')
  assert.ok(report.blockers.some(blocker => blocker.id === 'HTTPS_GATEWAY_MUST_REMAIN_DISABLED'))
})

test('missing immutable artifact binding remains blocked', () => {
  const input = completeInput()
  delete input.artifactSha256
  const report = buildFleetPilotPlan(input)

  assert.ok(report.blockers.some(blocker => blocker.id === 'ARTIFACT_DIGEST_REQUIRED'))
})

test('pilot digest detects tampering', () => {
  const report = buildFleetPilotPlan(completeInput())
  const altered = structuredClone(report)
  altered.inventory.canaryCount++

  assert.equal(verifyFleetPilotPlanDigest(report), true)
  assert.equal(verifyFleetPilotPlanDigest(altered), false)
})

function completeInput (overrides = {}) {
  return {
    schema: PILOT_INPUT_SCHEMA,
    inventory: fixtureInventory(),
    channels: { stable: 'v0.24.3', canary: 'v0.24.3' },
    gatewayRelease: { schema: 'hiverelay-public-gateway-release-v1', enabled: false },
    targetRelay: 'bern',
    sourceCommit: SOURCE,
    releaseId: 'v1.0.0-rc.1',
    artifactSha256: ARTIFACT,
    ...overrides
  }
}

function fixtureInventory () {
  return {
    relays: [
      { name: 'utah', channel: 'canary', region: 'NA', diskGB: 350 },
      { name: 'utah-0.5gb', channel: 'canary', region: 'NA', diskGB: 20 },
      { name: 'bern', channel: 'canary', region: 'EU', diskGB: 484 },
      { name: 'sing-1', channel: 'stable', region: 'APAC', diskGB: 24 }
    ]
  }
}

async function readJson (relative) {
  return JSON.parse(await readFile(new URL(relative, import.meta.url), 'utf8'))
}
