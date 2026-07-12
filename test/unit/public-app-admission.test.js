import test from 'brittle'
import {
  MAX_HIVE_APP_PUBLIC_KEYS,
  PUBLIC_HIVE_GATEWAY_ADMISSION_CAPABILITY,
  admitPublicHiveAppEntry,
  normalizeHiveAppPublicKeys,
  normalizeHiveAppPublicVersions
} from 'p2p-hiverelay/gateway/public-app-admission.js'

const KEY = 'a'.repeat(64)
const APPROVED = { appKey: KEY, publicAppKeys: [KEY] }
const BASE = {
  type: 'app',
  blind: false,
  privacyTier: 'public',
  storageClass: 'persistent',
  availabilityClass: 'always-on'
}

test('public app admission - compiled capability keeps transitional admission out of fleet', (t) => {
  t.alike(PUBLIC_HIVE_GATEWAY_ADMISSION_CAPABILITY, {
    kind: 'public-hive-gateway-admission-capability',
    version: 1,
    profile: 'transitional-operator-allowlist-v1',
    authority: 'local-operator-allowlist',
    fleetReady: false
  })
  t.ok(Object.isFrozen(PUBLIC_HIVE_GATEWAY_ADMISSION_CAPABILITY))
  t.absent(PUBLIC_HIVE_GATEWAY_ADMISSION_CAPABILITY.fleetReady,
    'a profile label alone is never production admission proof')
})

test('public app admission - local key approval is an independent provenance gate', (t) => {
  t.alike(admitPublicHiveAppEntry(null, APPROVED), {
    allowed: false,
    reason: 'missing-entry'
  })
  t.alike(admitPublicHiveAppEntry(BASE), {
    allowed: false,
    reason: 'not-operator-approved'
  })
  t.alike(admitPublicHiveAppEntry(BASE, { appKey: KEY, publicAppKeys: [] }), {
    allowed: false,
    reason: 'not-operator-approved'
  })
  t.ok(admitPublicHiveAppEntry(BASE, APPROVED).allowed, 'approved key with explicit public metadata is admitted')
  t.ok(admitPublicHiveAppEntry(BASE, {
    appKey: KEY.toUpperCase(),
    publicAppKeys: [KEY.toUpperCase()]
  }).allowed, 'hex key case is canonicalized')
  t.ok(admitPublicHiveAppEntry(BASE, {
    appKey: KEY,
    publicAppKeys: normalizeHiveAppPublicKeys([KEY])
  }).allowed, 'GatewayServer normalized Set form is accepted')
  t.is(normalizeHiveAppPublicKeys(['not-a-key']), null, 'invalid configuration fails closed')
  t.is(normalizeHiveAppPublicKeys(Array(MAX_HIVE_APP_PUBLIC_KEYS + 1).fill(KEY)), null,
    'operator allowlist has a hard cardinality bound')
})

test('public app admission - immutable drive-version pins are strict and bounded', (t) => {
  const pins = normalizeHiveAppPublicVersions({ [KEY.toUpperCase()]: 7 })
  t.ok(pins instanceof Map)
  t.is(pins.get(KEY), 7)
  t.is(normalizeHiveAppPublicVersions({ [KEY]: '7' }), null, 'numeric strings are not runtime versions')
  t.is(normalizeHiveAppPublicVersions({ nope: 7 }), null, 'invalid app keys fail closed')
  t.is(normalizeHiveAppPublicVersions({ [KEY]: -1 }), null, 'negative versions fail closed')
  t.is(normalizeHiveAppPublicVersions([]), null, 'array-shaped mappings fail closed')
})

test('public app admission - privacy and availability metadata fail closed', (t) => {
  const cases = [
    ['missing privacy tier', { ...BASE, privacyTier: undefined }, 'not-explicitly-public'],
    ['unknown privacy tier', { ...BASE, privacyTier: 'future-tier' }, 'not-explicitly-public'],
    ['local-first', { ...BASE, privacyTier: 'local-first' }, 'not-explicitly-public'],
    ['p2p-only', { ...BASE, privacyTier: 'p2p-only' }, 'not-explicitly-public'],
    ['blind', { ...BASE, blind: true }, 'not-explicitly-transparent'],
    ['missing transparency marker', { ...BASE, blind: undefined }, 'not-explicitly-transparent'],
    ['missing storage class', { ...BASE, storageClass: undefined }, 'not-persistent-availability'],
    ['temporary storage', { ...BASE, storageClass: 'temporary' }, 'not-persistent-availability'],
    ['missing availability class', { ...BASE, availabilityClass: undefined }, 'not-public-availability-class'],
    ['atomic handoff', { ...BASE, availabilityClass: 'atomic-handoff' }, 'not-public-availability-class']
  ]

  for (const [name, entry, reason] of cases) {
    t.alike(admitPublicHiveAppEntry(entry, APPROVED), { allowed: false, reason }, name)
  }

  t.ok(admitPublicHiveAppEntry({ ...BASE, availabilityClass: 'best-effort' }, APPROVED).allowed,
    'best-effort is an explicit public availability class')
})

test('public app admission - custody and shard markers always reject', (t) => {
  const cases = [
    ['custody object', { custody: { enabled: true } }],
    ['custody intent', { custodyIntentId: 'intent-1' }],
    ['custody mode', { custodyMode: 'blind' }],
    ['custody receipt', { custodyReceipt: { receiptId: 'r1' } }],
    ['handoff id', { handoffId: 'handoff-1' }],
    ['atomic handoff', { atomicHandoff: true }],
    ['retention deadline', { retainUntil: Date.now() + 60_000 }],
    ['blind content id', { blindContentId: 'b'.repeat(64) }],
    ['encrypted marker', { encrypted: true }],
    ['encryption metadata', { encryption: { algorithm: 'secretstream' } }],
    ['ciphertext marker', { ciphertext: { blocks: 1 } }],
    ['ciphertext root', { ciphertextRoot: 'c'.repeat(64) }],
    ['commitment root', { commitmentRoot: 'e'.repeat(64) }],
    ['share scheme', { shareScheme: 'pvss-v1' }],
    ['share threshold', { shareThreshold: 2 }],
    ['share bundle key', { shareBundleKey: 'f'.repeat(64) }],
    ['share index', { shareIndex: 1 }],
    ['share commitment', { shareCommitment: '02' + '1'.repeat(64) }],
    ['share manifest', { shareManifest: [{ shareIndex: 1 }] }],
    ['share assignments', { shareAssignments: [{ relay: 'r1' }] }],
    ['shard ids', { shardIds: ['shard:' + 'd'.repeat(64)] }],
    ['shards', { shards: [{ id: 1 }] }],
    ['shard', { shard: { id: 1 } }],
    ['shard content type', { contentType: 'shard' }],
    ['custody type', { type: 'custody' }],
    ['handoff type', { type: 'handoff' }],
    ['vault type', { type: 'vault' }],
    ['contradictory type fields', { contentType: 'app', type: 'shard-set' }]
  ]

  for (const [name, marker] of cases) {
    t.alike(admitPublicHiveAppEntry({ ...BASE, ...marker }, APPROVED), {
      allowed: false,
      reason: 'custody-or-shard-entry'
    }, name)
  }
})
