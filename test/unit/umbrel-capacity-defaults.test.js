import test from 'brittle'
import { readFile } from 'node:fs/promises'

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
