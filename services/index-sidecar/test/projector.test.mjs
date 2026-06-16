import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Projector } from '../lib/projector.js'

const KEY = 'a'.repeat(64)
const PUB = 'b'.repeat(64)

function fakeRelay (catalogEntries, cap) {
  return {
    async getCapability () { return cap },
    async getCatalog () { return { entries: catalogEntries, ok: true } }
  }
}

// records upserts; mimics RoomManager.upsert add/update semantics
function fakeRoom () {
  const seen = new Map()
  return {
    upserts: [],
    deletes: [],
    localLength: 0,
    async list () { return [] }, // empty room → prime() seeds nothing
    async upsert (schema, row) {
      const pk = schema + JSON.stringify(row.appKey || row.appId || row.pubkey)
      const action = seen.has(pk) ? 'update' : 'add'
      seen.set(pk, row)
      this.upserts.push({ schema, action })
      return { action, uuid: pk }
    },
    async deleteRow (schema, pk) { this.deletes.push({ schema, pk }); return true },
    async update () {}
  }
}

const cap = {
  pubkey: PUB,
  gatewayUrl: 'https://r',
  software: 'hiverelay',
  version: '0.18.0',
  features: [],
  limitation: {},
  catalog: { total: 1, anchored: 1 },
  attestedAt: 1,
  signature: { v: 1, sig: 'cc'.repeat(64) }
}
const entries = [{ appKey: KEY, key: KEY, type: 'app', name: 'App', anchored: true, sizeBytes: 10 }]

test('syncOnce projects directory + manifest + pin rows', async (t) => {
  const room = fakeRoom()
  const p = new Projector({ relayClient: fakeRelay(entries, cap), room })
  const stats = await p.syncOnce()
  assert.equal(stats.added, 3, 'relay-directory + app-manifest + pin-registry')
  const schemas = room.upserts.map(u => u.schema).sort()
  assert.deepEqual(schemas, ['app-manifest', 'pin-registry', 'relay-directory'])
})

test('debounce: a second sync with unchanged data writes nothing', async (t) => {
  const room = fakeRoom()
  const p = new Projector({ relayClient: fakeRelay(entries, cap), room })
  await p.syncOnce()
  const after1 = room.upserts.length
  const stats2 = await p.syncOnce()
  assert.equal(stats2.added, 0)
  assert.equal(stats2.updated, 0)
  assert.equal(stats2.skipped, 3, 'all unchanged rows skipped (write-amp guard)')
  assert.equal(room.upserts.length, after1, 'no new writes')
})

test('a manifest-only change triggers exactly one update', async (t) => {
  const room = fakeRoom()
  const p = new Projector({ relayClient: fakeRelay(entries, cap), room })
  await p.syncOnce()
  // author lives only in the app-manifest row (not pin-registry/relay-directory)
  p.relayClient = fakeRelay([{ ...entries[0], author: 'someone' }], cap)
  const stats = await p.syncOnce()
  assert.equal(stats.updated, 1, 'only the manifest row changed')
  assert.equal(stats.skipped, 2, 'pin + directory unchanged')
})

test('invalid rows are skipped, not written', async (t) => {
  const room = fakeRoom()
  // entry with a non-hex key → mappers drop it (not indexable) so no rows;
  // a malformed-but-indexable case is covered by schema validation in the writer
  const bad = [{ appKey: 'not-hex', name: 'x' }]
  const p = new Projector({ relayClient: fakeRelay(bad, cap), room })
  const stats = await p.syncOnce()
  // only the relay-directory row from cap should be added
  assert.equal(stats.added, 1)
  assert.deepEqual(room.upserts.map(u => u.schema), ['relay-directory'])
})
