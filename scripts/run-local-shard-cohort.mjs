#!/usr/bin/env node
/**
 * Persistent LOCAL shard-store relay cohort — a live /api/v1/shard target for
 * app-side dealer development (e.g. peerit) without touching the production fleet.
 *
 * Starts N real RelayNode instances (shard-store enabled) on a shared local
 * testnet DHT, each with its HTTP API up and the production custody resolver
 * wired — the exact surface test/integration/blind-dispersal-fleet-e2e.test.js
 * proves, but kept alive as a process. Prints + writes a roster
 * ({ baseUrl, pubkey, apiKey }) that scripts/blind-dispersal-live.mjs and a
 * peerit node dealer consume directly.
 *
 *   node scripts/run-local-shard-cohort.mjs            # N=3 on 127.0.0.1
 *   HIVERELAY_COHORT_N=5 HIVERELAY_COHORT_HOST=0.0.0.0 node scripts/run-local-shard-cohort.mjs
 *
 * HONEST SCOPE: same-operator, same-machine → proves the MECHANISM + the wire
 * contract live. It is NOT the security property (independent operators, GATE 2)
 * and NOT the production fleet (still gated on the release secrets).
 */
import createTestnet from '@hyperswarm/testnet'
import b4a from 'b4a'
import { randomBytes } from 'crypto'
import { mkdir, writeFile } from 'fs/promises'
import { join } from 'path'
import { homedir } from 'os'
import { RelayNode } from 'p2p-hiverelay/core/relay-node/index.js'

const N = parseInt(process.env.HIVERELAY_COHORT_N || '3', 10)
const HOST = process.env.HIVERELAY_COHORT_HOST || '127.0.0.1'
const BASE = process.env.HIVERELAY_COHORT_DIR || join(homedir(), '.hiverelay-shard-cohort')
const ROSTER = process.env.HIVERELAY_COHORT_ROSTER || join(BASE, 'roster.json')

function benign (e) { return /Node destroyed|REQUEST_DESTROYED|Request destroyed|IO_SUSPENDED|Node was destroyed/i.test(String((e && (e.message || e.code)) || '')) }
process.on('uncaughtException', (e) => { if (!benign(e)) { console.error(e); process.exit(1) } })
process.on('unhandledRejection', (e) => { if (!benign(e)) { console.error(e); process.exit(1) } })

const nodes = []
async function shutdown () {
  console.log('\nstopping cohort…')
  for (const n of nodes) { try { await n.node.stop() } catch {} }
  try { await testnet.destroy() } catch {}
  process.exit(0)
}
process.on('SIGINT', shutdown)
process.on('SIGTERM', shutdown)

await mkdir(BASE, { recursive: true })
const testnet = await createTestnet(3)

for (let i = 0; i < N; i++) {
  const apiKey = 'cohort-' + randomBytes(6).toString('hex')
  const node = new RelayNode({
    storage: join(BASE, 'relay-' + i), // persistent → stable relay pubkey across restarts
    bootstrapNodes: testnet.bootstrap,
    enableAPI: true,
    apiPort: 0,
    apiHost: HOST,
    apiKey,
    enableSeeding: true,
    enableServices: true,
    plugins: ['shard-store'],
    enableNetworkDiscovery: false,
    enableHolesail: false,
    gatewayServeBlind: false
  })
  await node.start()
  const port = node.api.server.address().port
  nodes.push({
    node,
    apiKey,
    baseUrl: 'http://' + HOST + ':' + port,
    pubkey: b4a.toString(node.swarm.keyPair.publicKey, 'hex')
  })
  console.log(`  ✓ relay ${i}  ${'http://' + HOST + ':' + port}  ${b4a.toString(node.swarm.keyPair.publicKey, 'hex').slice(0, 16)}…`)
}

const roster = { threshold: Math.max(2, Math.ceil(N / 2)), relays: nodes.map((r) => ({ baseUrl: r.baseUrl, pubkey: r.pubkey, apiKey: r.apiKey })) }
await writeFile(ROSTER, JSON.stringify(roster, null, 2) + '\n')

console.log(`\n▶ ${N}-relay shard-store cohort LIVE — /api/v1/shard mounted on each.`)
console.log(`  roster written → ${ROSTER}`)
console.log(`  smoke it:  node scripts/blind-dispersal-live.mjs ${ROSTER}`)
console.log('  (same-operator cohort → mechanism proof, not the security property. Ctrl-C to stop.)\n')

await new Promise(() => {}) // stay alive
