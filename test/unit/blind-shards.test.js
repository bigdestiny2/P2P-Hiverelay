import test from 'brittle'
import b4a from 'b4a'
import {
  encodeShareShard, decodeShareShard, shardAddressOf,
  disperseSecret, recoverSecret, SHARE_SHARD_SCHEME
} from '../../packages/client/blind-shards.js'

// An in-memory "fleet": address -> opaque bytes. put/fetch mirror the shard
// store surface without any relay, so these tests isolate the codec + drivers.
function memoryFleet () {
  const store = new Map()
  return {
    store,
    put: async (bytes) => { const a = shardAddressOf(bytes); store.set(a, b4a.from(bytes)); return a },
    // fetch only the shards whose index passes `allow` (default all) — lets a
    // test model "only these relays answer".
    fetchWith: (allow = () => true, manifest = []) => async (address) => {
      const entry = manifest.find(m => m.shard === address)
      if (entry && !allow(entry.shareIndex)) return null
      return store.get(address) || null
    }
  }
}

test('codec: encode is deterministic and round-trips', async (t) => {
  const fleet = memoryFleet()
  const d = await disperseSecret({ count: 3, threshold: 2, put: fleet.put })
  // reconstruct one raw share object by decoding a stored blob
  const addr = d.shareManifest[0].shard
  const bytes = fleet.store.get(addr)
  const share = decodeShareShard(bytes)
  // deterministic: re-encoding the decoded share yields identical bytes + address
  const re = encodeShareShard(share)
  t.ok(b4a.equals(re, bytes), 'encode(decode(x)) === x byte-for-byte')
  t.is(shardAddressOf(re), addr, 'stable content address')
})

test('codec: rejects malformed shards', (t) => {
  t.exception(() => encodeShareShard({ index: 0, share: 'x' }), /bad share index/)
  t.exception(() => decodeShareShard(b4a.from('not json', 'utf8')), /not JSON/)
  const wrongScheme = b4a.from('{"v":1,"scheme":"nope","index":1,"share":"' + '2'.repeat(66) + '"}', 'utf8')
  t.exception(() => decodeShareShard(wrongScheme), /unsupported scheme/)
})

test('disperse -> recover round-trips the exact secret (3-of-5)', async (t) => {
  const fleet = memoryFleet()
  const d = await disperseSecret({ count: 5, threshold: 3, put: fleet.put })
  t.is(d.shareManifest.length, 5)
  t.is(new Set(d.shareManifest.map(m => m.shard)).size, 5, 'five distinct content addresses')

  const r = await recoverSecret({
    shareManifest: d.shareManifest,
    threshold: 3,
    fetch: fleet.fetchWith(() => true, d.shareManifest)
  })
  t.is(r.ok, true)
  t.is(r.key, d.key, 'reader reconstructs the dealer-private key at the edge')
  t.is(r.secretPoint, d.secretPoint)
  t.is(r.used, 3, 'stops at exactly threshold shards')
})

test('ANY k-subset reconstructs the same secret', async (t) => {
  const fleet = memoryFleet()
  const d = await disperseSecret({ count: 5, threshold: 3, put: fleet.put })
  // only relays holding shares 2, 4, 5 answer
  const subset = new Set([2, 4, 5])
  const r = await recoverSecret({
    shareManifest: d.shareManifest,
    threshold: 3,
    fetch: fleet.fetchWith((i) => subset.has(i), d.shareManifest)
  })
  t.is(r.ok, true)
  t.is(r.key, d.key, 'a different k-subset yields the identical key')
})

test('INVARIANT: fewer than k shards cannot reconstruct', async (t) => {
  const fleet = memoryFleet()
  const d = await disperseSecret({ count: 5, threshold: 3, put: fleet.put })

  // A single relay (one share) — the blind-custody promise: it cannot reconstruct.
  const one = await recoverSecret({
    shareManifest: d.shareManifest,
    threshold: 3,
    fetch: fleet.fetchWith((i) => i === 1, d.shareManifest)
  })
  t.is(one.ok, false)
  t.is(one.reason, 'INSUFFICIENT_SHARDS')
  t.is(one.collected, 1)

  // k-1 relays colluding — still not enough.
  const kMinus1 = await recoverSecret({
    shareManifest: d.shareManifest,
    threshold: 3,
    fetch: fleet.fetchWith((i) => i <= 2, d.shareManifest)
  })
  t.is(kMinus1.ok, false)
  t.is(kMinus1.collected, 2)
})

test('content-address integrity: a relay returning garbage bytes is dropped', async (t) => {
  const fleet = memoryFleet()
  const d = await disperseSecret({ count: 5, threshold: 3, put: fleet.put })

  // Relay for share 1 tampers with the bytes; share 1 is dropped but 2..5 carry.
  const tamperingFetch = async (address) => {
    const entry = d.shareManifest.find(m => m.shard === address)
    if (entry && entry.shareIndex === 1) return b4a.from('garbage-not-the-committed-bytes', 'utf8')
    return fleet.store.get(address) || null
  }
  const r = await recoverSecret({ shareManifest: d.shareManifest, threshold: 3, fetch: tamperingFetch })
  t.is(r.ok, true, 'still recovers from the honest shards')
  t.is(r.key, d.key)

  // If tampering drops the honest set below k, recovery fails cleanly.
  const mostlyTampered = async (address) => {
    const entry = d.shareManifest.find(m => m.shard === address)
    if (entry && entry.shareIndex >= 3) return b4a.from('garbage', 'utf8')
    return fleet.store.get(address) || null
  }
  const r2 = await recoverSecret({ shareManifest: d.shareManifest, threshold: 3, fetch: mostlyTampered })
  t.is(r2.ok, false)
  t.is(r2.reason, 'INSUFFICIENT_SHARDS')
})

test('INTEGRITY: a share whose point != manifest commitment is rejected', async (t) => {
  const fleet = memoryFleet()
  const d = await disperseSecret({ count: 5, threshold: 3, put: fleet.put })

  // Tamper share 1's commitment to a DIFFERENT (honest) point. The relay still
  // serves the honestly-stored, DLEQ-valid bytes at that address, but the
  // decoded point no longer equals the manifest commitment -> the share is
  // dropped (a valid DLEQ proof alone must NOT be enough to be used).
  const tampered = d.shareManifest.map((m, i) =>
    i === 0 ? { ...m, shareCommitment: d.shareManifest[1].shareCommitment } : m)
  const r = await recoverSecret({ shareManifest: tampered, threshold: 3, fetch: fleet.fetchWith(() => true, tampered) })
  t.is(r.ok, true)
  t.is(r.key, d.key, 'recovers from the honest shares; the commitment-mismatched one is dropped')

  // Enough mismatched commitments -> falls below k -> clean failure.
  const mostlyBad = d.shareManifest.map((m, i) =>
    i >= 2 ? { ...m, shareCommitment: '02' + 'f'.repeat(64) } : m)
  const r2 = await recoverSecret({ shareManifest: mostlyBad, threshold: 3, fetch: fleet.fetchWith(() => true, mostlyBad) })
  t.is(r2.ok, false)
  t.is(r2.reason, 'INSUFFICIENT_SHARDS')

  // A manifest entry with no commitment cannot be validated -> unusable.
  const noCommit = d.shareManifest.map(({ shareCommitment, ...rest }) => rest)
  const r3 = await recoverSecret({ shareManifest: noCommit, threshold: 3, fetch: fleet.fetchWith(() => true, d.shareManifest) })
  t.is(r3.ok, false, 'without commitments nothing can be trusted')
})

test('scheme + manifest shape are well-formed for custody binding', async (t) => {
  const fleet = memoryFleet()
  const d = await disperseSecret({ count: 4, threshold: 2, put: fleet.put })
  t.is(SHARE_SHARD_SCHEME, 'pvss-secp256k1-v1')
  for (const m of d.shareManifest) {
    t.ok(Number.isInteger(m.shareIndex) && m.shareIndex >= 1)
    t.ok(/^shard:[0-9a-f]{64}$/.test(m.shard), 'shard is a content address')
    t.ok(/^[0-9a-f]{66}$/.test(m.shareCommitment), 'shareCommitment is a compressed point')
  }
})
