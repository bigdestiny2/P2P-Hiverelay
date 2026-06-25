import test from 'brittle'
import { hashIdent, redactPubkeyHex, redactIp } from '../../packages/core/core/privacy.js'
import { epochDiscoveryTopic, epochDiscoveryTopics, RELAY_DISCOVERY_TOPIC } from '../../packages/core/core/constants.js'

test('privacy: hashIdent is stable, salted, truncated, non-empty-guarded', (t) => {
  const a = hashIdent('1.2.3.4')
  const b = hashIdent('1.2.3.4')
  t.is(a, b, 'stable within a process')
  t.is(a.length, 16, 'truncated to 16 hex chars')
  t.not(a, hashIdent('1.2.3.5'), 'distinct inputs differ')
  t.is(hashIdent(''), null)
  t.is(hashIdent(null), null)
  t.is(hashIdent(undefined), null)
})

test('privacy: redactPubkeyHex tags + never leaks the raw key', (t) => {
  const raw = 'ab'.repeat(32)
  const r = redactPubkeyHex(raw)
  t.ok(/^anon:[0-9a-f]{16}$/.test(r))
  t.absent(r.includes(raw))
  t.is(redactPubkeyHex('short'), null)
})

test('privacy: redactIp tags + falls back to unknown', (t) => {
  t.ok(/^ip:[0-9a-f]{16}$/.test(redactIp('9.9.9.9')))
  t.is(redactIp(null), 'unknown')
})

test('discovery: epoch topics are deterministic per bucket and roll forward', (t) => {
  const periodMs = 3_600_000
  const now = 100 * periodMs + 12345 // mid-bucket-100
  const [cur, next] = epochDiscoveryTopics(now, periodMs)
  t.alike(cur, epochDiscoveryTopic(100), 'current bucket = floor(now/period)')
  t.alike(next, epochDiscoveryTopic(101), 'next bucket = current + 1')
  t.is(cur.length, 32, '32-byte topic')
  t.absent(cur.equals(next), 'current != next')
  t.absent(cur.equals(RELAY_DISCOVERY_TOPIC), 'epoch topic != static topic')

  // A time later in the same bucket yields the same pair.
  const [cur2] = epochDiscoveryTopics(now + 1000, periodMs)
  t.alike(cur2, cur, 'same bucket -> same topic')
})
