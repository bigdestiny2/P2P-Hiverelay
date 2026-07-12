import test from 'brittle'
import { readFile } from 'node:fs/promises'

test('generic release paths cannot bypass public gateway fleet evidence gates', async (t) => {
  const prepare = await readFile('scripts/prepare-release.mjs', 'utf8')
  const release = await readFile('scripts/release.sh', 'utf8')

  t.ok(prepare.includes('public-hive-gateway-release.json'))
  t.ok(prepare.includes('cannot move fleet channel'))
  t.ok(prepare.includes('use --channel none and the evidence-gated fleet promotion tool'))
  t.ok(release.includes('--promote-canary is disabled for public gateway releases'))
  t.ok(release.includes('scripts/promote-fleet-channel.mjs'))
})
