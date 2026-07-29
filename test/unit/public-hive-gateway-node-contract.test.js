import test from 'brittle'
import { spawnSync } from 'node:child_process'
import { encodeHiveAppKey } from '../../packages/core/gateway/hive-host.js'

const tool = 'scripts/resolve-public-hive-gateway-node.mjs'
const appKey = 'a'.repeat(64)
const suffix = 'hive-canary.operator.example'
const origin = `https://${encodeHiveAppKey(Buffer.from(appKey, 'hex'))}.${suffix}/`
const normalizedOrigin = new URL(origin).origin

function manifest () {
  return {
    schema: 'hiverelay-public-gateway-release-v1',
    enabled: true,
    releaseTarget: 'v1.2.3',
    admissionProfile: 'blind-substrate-public-v1',
    observationWindowMs: 24 * 60 * 60 * 1000,
    maxProbeGapMs: 30 * 60 * 1000,
    cohort: [{
      relay: 'canary-1',
      channel: 'canary',
      suffix,
      origin,
      connectAddress: '127.0.0.1',
      appKey,
      path: '/index.html',
      contentSha256: 'b'.repeat(64),
      driveVersion: '7',
      peerFingerprint256: Array(32).fill('AA').join(':'),
      nginxConfigSha256: 'c'.repeat(64)
    }]
  }
}

function resolve (body, relay = 'canary-1', channel = 'canary', target = 'v1.2.3', extra = []) {
  return spawnSync(process.execPath, [
    tool,
    '--release-target', target,
    '--relay', relay,
    '--channel', channel,
    ...extra
  ], {
    encoding: 'utf8',
    input: JSON.stringify(body)
  })
}

test('gateway node contract emits exact normalized signed cohort bindings', (t) => {
  const result = resolve(manifest())
  t.is(result.status, 0, result.stderr)
  t.alike(result.stdout.trim().split('\t'), [
    'cohort',
    'blind-substrate-public-v1',
    normalizedOrigin,
    '127.0.0.1',
    appKey,
    '/index.html',
    'b'.repeat(64),
    '7',
    Array(32).fill('AA').join(':'),
    'c'.repeat(64),
    'legacy',
    '-'
  ])

  const t1 = manifest()
  t1.cohort[0].deploymentProfile = 'public-t1-gateway'
  t1.cohort[0].operatorContractSha256 = 'd'.repeat(64)
  const t1Result = resolve(t1)
  t.is(t1Result.status, 0, t1Result.stderr)
  t.alike(t1Result.stdout.trim().split('\t').slice(-2), ['public-t1-gateway', 'd'.repeat(64)])

  const rejectedLegacyDeployment = resolve(manifest(), 'canary-1', 'canary', 'v1.2.3', ['--require-public-t1'])
  t.not(rejectedLegacyDeployment.status, 0)
  t.ok(rejectedLegacyDeployment.stderr.includes('must use public-t1-gateway'))
  const acceptedT1Deployment = resolve(t1, 'canary-1', 'canary', 'v1.2.3', ['--require-public-t1'])
  t.is(acceptedT1Deployment.status, 0, acceptedT1Deployment.stderr)
})

test('gateway node contract distinguishes canonical disabled and noncohort releases', (t) => {
  const disabled = resolve({ schema: 'hiverelay-public-gateway-release-v1', enabled: false })
  t.is(disabled.status, 0, disabled.stderr)
  t.is(disabled.stdout.trim(), 'ordinary\tdisabled')

  const noncohort = resolve(manifest(), 'stable-1', 'stable')
  t.is(noncohort.status, 0, noncohort.stderr)
  t.is(noncohort.stdout.trim(), 'ordinary\tnoncohort')

  const otherChannel = resolve(manifest(), 'legacy-1', 'legacy')
  t.is(otherChannel.status, 0, otherChannel.stderr)
  t.is(otherChannel.stdout.trim(), 'ordinary\tnoncohort')
})

test('gateway node contract fails closed on channel, target, and disabled-control drift', (t) => {
  const wrongChannel = resolve(manifest(), 'canary-1', 'stable')
  t.not(wrongChannel.status, 0)
  t.ok(wrongChannel.stderr.includes('signed for channel canary'))

  const wrongTarget = resolve(manifest(), 'canary-1', 'canary', 'v1.2.4')
  t.not(wrongTarget.status, 0)
  t.ok(wrongTarget.stderr.includes('must target v1.2.4'))

  const ambiguousDisabled = resolve({
    schema: 'hiverelay-public-gateway-release-v1',
    enabled: false,
    cohort: []
  })
  t.not(ambiguousDisabled.status, 0)
  t.ok(ambiguousDisabled.stderr.includes('must contain exactly'))
})
