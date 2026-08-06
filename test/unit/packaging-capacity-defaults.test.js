import test from 'brittle'
import { readFile } from 'node:fs/promises'

const SERVICE_FLAGS = [
  'HIVERELAY_ENABLE_SERVICES',
  'HIVERELAY_OUTBOXLOG',
  'HIVERELAY_NOTIFY',
  'HIVERELAY_SHARD_STORE',
  'HIVERELAY_STORAGE_PROOF',
  'HIVERELAY_VRF',
  'HIVERELAY_WITNESSLOG',
  'HIVERELAY_REPAIRTICKET'
]

test('packaging capacity: Docker Compose never defaults utility services on', async (t) => {
  const compose = await readFile('docker-compose.yml', 'utf8')

  t.ok(compose.includes('HIVERELAY_CAPACITY_PROFILE=$' + '{HIVERELAY_CAPACITY_PROFILE:-}'), 'operators can declare a profile without an unsafe inferred default')
  for (const flag of SERVICE_FLAGS) {
    t.absent(compose.includes(flag + '=1'), flag + ' has no default-on assignment')
  }
  t.ok(compose.includes('HIVERELAY_ENABLE_SERVICES=$' + '{HIVERELAY_ENABLE_SERVICES:-0}'), 'single-relay opt-in stays available')
})

test('packaging capacity: systemd unit is core-only by default', async (t) => {
  const unit = await readFile('hiverelay.service', 'utf8')

  t.ok(unit.includes('# Environment=HIVERELAY_CAPACITY_PROFILE=seeder-standard'), 'systemd documents explicit profile declaration')
  for (const flag of SERVICE_FLAGS) {
    t.ok(unit.includes('Environment=' + flag + '=0'), flag + ' is explicitly off')
    t.absent(unit.includes('Environment=' + flag + '=1'), flag + ' is not default-on')
  }
})
