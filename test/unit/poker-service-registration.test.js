import test from 'brittle'
import { ServiceRegistry } from 'p2p-hiverelay/core/services/registry.js'
import { PokerApp } from 'p2p-hiveservices/builtin/poker/index.js'

// Poker as a P2P service: register it, start it, and drive its capabilities the
// way the service RPC does — `handleRequest(service, method, params, context)`,
// i.e. a SINGLE params object per call. This is the convention an app client
// (HiveRelayClient.callService('poker', method, { ... })) speaks. It exercises
// both that poker is registrable/startable through the standard ServiceRegistry
// and that its read/write methods honour the params-object convention (not just
// the positional form the HTTP adapter uses).

const TABLE_KEY = 'a'.repeat(64)
const WRITER = 'b'.repeat(64)
const CTX = { role: 'anonymous', authenticated: false }

async function startedRegistry () {
  const registry = new ServiceRegistry()
  registry.register(new PokerApp())
  await registry.startAll({})
  return registry
}

test('poker registers + advertises its capabilities', async (t) => {
  const registry = await startedRegistry()
  const cat = registry.catalog()
  const poker = cat.find(s => s.name === 'poker')
  t.ok(poker, 'poker appears in the running catalog')
  for (const cap of ['createTable', 'submitEntry', 'getLog', 'getState', 'listTables']) {
    t.ok(poker.capabilities.includes(cap), `capability ${cap} advertised`)
  }
})

test('createTable + read methods work over the service RPC (params-object form)', async (t) => {
  const registry = await startedRegistry()

  const desc = await registry.handleRequest('poker', 'createTable',
    { tableKey: TABLE_KEY, writers: [WRITER], options: { sb: 1, bb: 2 } }, CTX)
  t.ok(desc && desc.tableKey, 'createTable returns a descriptor')

  // getState({ tableKey }) — broken if the method ignored the params object.
  const state = await registry.handleRequest('poker', 'getState', { tableKey: TABLE_KEY }, CTX)
  t.ok(state, 'getState resolves the table from the params object')

  // getLog({ tableKey, from, limit }) — empty log, correct shape.
  const log = await registry.handleRequest('poker', 'getLog',
    { tableKey: TABLE_KEY, from: 0, limit: 10 }, CTX)
  t.ok(log && Array.isArray(log.entries), 'getLog returns { from, to, entries }')
  t.is(log.entries.length, 0, 'fresh table has no entries')

  // listTables — no args.
  const tables = await registry.handleRequest('poker', 'listTables', {}, CTX)
  t.ok(Array.isArray(tables) || (tables && Array.isArray(tables.tables)), 'listTables returns a list')
})

test('submitEntry honours the params-object form (extracts tableKey + entry)', async (t) => {
  const registry = await startedRegistry()
  await registry.handleRequest('poker', 'createTable',
    { tableKey: TABLE_KEY, writers: [WRITER] }, CTX)

  // A shaped-but-invalid entry (writer not in the allowlist). If the params
  // object were ignored, _get() would receive an object, return null, and the
  // result would be `no-such-table`. Any OTHER rejection reason proves the
  // tableKey + entry were correctly read out of the params object.
  const entry = {
    tableKey: TABLE_KEY,
    writer: 'c'.repeat(64),
    seq: 0,
    ts: Date.now(),
    signature: '0'.repeat(128)
  }
  const res = await registry.handleRequest('poker', 'submitEntry',
    { tableKey: TABLE_KEY, entry }, CTX)
  t.ok(res, 'submitEntry returns a result')
  t.is(res.ok, false, 'invalid entry is rejected (as expected)')
  t.not(res.reason, 'no-such-table', 'tableKey was resolved from the params object')
})
