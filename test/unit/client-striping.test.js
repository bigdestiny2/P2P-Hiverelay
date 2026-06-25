import test from 'brittle'
import b4a from 'b4a'
import { HiveRelayClient } from 'p2p-hiverelay-client'

// Build a fake HTTP gateway over a fixed byte payload that honours Range
// requests (RFC 9110), so we can exercise getStriped() without a live relay.
// Records which relay served which range so we can assert the work was spread.
function fakeGateway (payload, served) {
  return async (url, opts = {}) => {
    const range = opts.headers && opts.headers.Range
    let start = 0
    let end = payload.length - 1
    if (range) {
      const m = /bytes=(\d+)-(\d+)/.exec(range)
      start = Number(m[1]); end = Number(m[2])
    }
    const slice = payload.subarray(start, end + 1)
    served.push({ url, start, end })
    return {
      ok: true,
      status: range ? 206 : 200,
      headers: { get: (h) => (h && h.toLowerCase() === 'content-range') ? `bytes ${start}-${end}/${payload.length}` : null },
      arrayBuffer: async () => slice.buffer.slice(slice.byteOffset, slice.byteOffset + slice.byteLength)
    }
  }
}

function makeClient () {
  // Constructor is pure (no I/O); we never call start().
  return new HiveRelayClient({ autoDiscover: false })
}

const DRIVE = 'a'.repeat(64)

test('getStriped: reassembles a drive from ranges across multiple relays', async (t) => {
  const payload = b4a.alloc(1000)
  for (let i = 0; i < payload.length; i++) payload[i] = i % 256
  const served = []
  const orig = globalThis.fetch
  globalThis.fetch = fakeGateway(payload, served)
  t.teardown(() => { globalThis.fetch = orig })

  const client = makeClient()
  const quorum = [
    { url: 'http://r1', pubkey: 'r1' },
    { url: 'http://r2', pubkey: 'r2' },
    { url: 'http://r3', pubkey: 'r3' }
  ]
  const out = await client.getStriped(DRIVE, '/file.bin', { quorum, stripes: 3 })

  t.ok(out.ok, 'reassembled length matches total')
  t.is(out.bytes, 1000)
  t.is(out.striped, true)
  t.ok(b4a.equals(out.buffer, payload), 'bytes are byte-for-byte correct after concat')
  t.is(out.relaysUsed.length, 3, 'all three relays each served a stripe')
  // Beyond the 1-byte probe, every data stripe carried a Range header.
  t.ok(served.filter(s => s.end - s.start > 0).length >= 2, 'work was split into ranges')
})

test('getStriped: falls back to a single full GET when Range is unsupported', async (t) => {
  const payload = b4a.from('hello world')
  const orig = globalThis.fetch
  // Gateway that ignores Range and returns the whole body with NO content-range.
  globalThis.fetch = async () => ({
    ok: true,
    status: 200,
    headers: { get: () => null },
    arrayBuffer: async () => payload.buffer.slice(payload.byteOffset, payload.byteOffset + payload.byteLength)
  })
  t.teardown(() => { globalThis.fetch = orig })

  const client = makeClient()
  const out = await client.getStriped(DRIVE, '/x', { quorum: [{ url: 'http://r1', pubkey: 'r1' }] })
  t.is(out.striped, false, 'flagged as not striped')
  t.ok(b4a.equals(out.buffer, payload), 'still returns the correct bytes')
})

test('getStriped: validates inputs', async (t) => {
  const client = makeClient()
  await t.exception(() => client.getStriped('nothex', '/x', { quorum: [{ url: 'http://r1' }] }), /64 hex/)
  await t.exception(() => client.getStriped(DRIVE, 'no-leading-slash', { quorum: [{ url: 'http://r1' }] }), /must start with/)
})
