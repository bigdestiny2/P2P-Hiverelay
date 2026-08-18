import test from 'brittle'
import { readFile } from 'node:fs/promises'
import { planCapacityCeiling } from '../../packages/core/config/capacity-plan.js'

const COMPOSE_PATH = 'umbrel-app/docker-compose.yml'

function environmentValue (compose, name) {
  const match = compose.match(new RegExp(`^\\s+${name}:\\s*(?:"([^"]*)"|'([^']*)'|([^#\\s]+))\\s*$`, 'm'))
  return match ? (match[1] ?? match[2] ?? match[3]) : null
}

test('Umbrel package defaults to a bounded community edge', async (t) => {
  const compose = await readFile(COMPOSE_PATH, 'utf8')

  t.is(environmentValue(compose, 'HIVERELAY_ACCEPT_MODE'), 'review')
  t.is(environmentValue(compose, 'HIVERELAY_MAX_STORAGE'), '10GB')
  t.is(environmentValue(compose, 'HIVERELAY_CAPACITY_PROFILE'), 'edge-community')
  t.is(environmentValue(compose, 'HIVERELAY_ENABLE_SERVICES'), 'false')
  t.absent(/^\s+ports:\s*$/m.test(compose), 'does not publish host ports')
  t.absent(/^\s+network_mode:\s*host\s*$/m.test(compose), 'does not use host networking')
})

test('the shipped Umbrel defaults enforce the durable budget the docs promise', async (t) => {
  const compose = await readFile(COMPOSE_PATH, 'utf8')
  const managedCapBytes = 10 * 1_000_000_000 // HIVERELAY_MAX_STORAGE=10GB
  t.is(environmentValue(compose, 'HIVERELAY_MAX_STORAGE'), '10GB')

  // Umbrel Home ships an onboard NVMe up to 4 TB. Whatever the disk, the
  // operator cap bounds managed capacity and the profile bounds durable payload
  // inside it. umbrel-app/README.md quotes this 3.5 GB figure to owners.
  for (const diskBytes of [1e12, 2e12, 4e12]) {
    const ceiling = planCapacityCeiling({
      profileId: environmentValue(compose, 'HIVERELAY_CAPACITY_PROFILE'),
      observedUsableBytes: diskBytes,
      operatorCapBytes: managedCapBytes
    })
    t.is(ceiling.managedCapacityBytes, managedCapBytes, 'the operator cap bounds managed capacity')
    t.is(ceiling.ceilingBytes, 3_500_000_000, 'the package holds at most 3.5 GB of durable payload')
    t.ok(ceiling.ceilingBytes < managedCapBytes, 'a profile only ever narrows')
  }
})

test('Umbrel package does not enable persistent utility services', async (t) => {
  const compose = await readFile(COMPOSE_PATH, 'utf8')
  const serviceFlags = [
    'HIVERELAY_OUTBOXLOG',
    'HIVERELAY_NOTIFY',
    'HIVERELAY_SHARD_STORE',
    'HIVERELAY_STORAGE_PROOF',
    'HIVERELAY_VRF',
    'HIVERELAY_WITNESSLOG'
  ]

  for (const flag of serviceFlags) {
    t.is(environmentValue(compose, flag), 'false', `${flag} is explicitly off`)
  }
})
