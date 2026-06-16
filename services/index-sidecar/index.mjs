#!/usr/bin/env node
// HiveRelay index sidecar — Tier-2 schema-sheets index. Runs out-of-process
// (corestore-7/hc11, dependency-isolated from the relay). It projects the
// relay's public catalogue + capability doc into a signed, JMESPath-queryable
// room, serves the §2 query routes, joins the swarm so clients blind-replicate
// the room read-only, and publishes its room key back to the relay so the relay
// advertises it in the capability doc + /catalog.json.
import Corestore from 'corestore'
import Hyperswarm from 'hyperswarm'
import { mkdir, readFile, writeFile } from 'fs/promises'
import { join } from 'path'
import { loadConfig } from './config.js'
import { RelayClient } from './lib/relay-client.js'
import { RoomManager } from './lib/room.js'
import { Projector } from './lib/projector.js'
import { createServer } from './lib/server.js'

const log = (...a) => console.log('[index]', ...a)

async function readPersistedRoomKey (dir) {
  try {
    const s = (await readFile(join(dir, 'room-key'), 'utf8')).trim()
    return /^[ybndrfg8ejkmcpqxot1uwisza345h769]{52}$/.test(s) ? s : null
  } catch { return null }
}

async function main () {
  const config = loadConfig()
  await mkdir(config.storageDir, { recursive: true })
  log('storage:', config.storageDir, '| relay:', config.relayUrl, '| port:', config.port)

  const relayClient = new RelayClient({ baseUrl: config.relayUrl, apiKey: config.relayApiKey })

  // Discover the relay's pubkey (best-effort) for the membership name.
  let relayPubkey = config.relayPubkey
  try {
    const cap = await relayClient.getCapability()
    if (cap && typeof cap.pubkey === 'string') relayPubkey = cap.pubkey
  } catch { /* relay may not be up yet; projector retries */ }
  const membership = relayPubkey ? 'relay:' + relayPubkey.slice(0, 16) : 'relay:index'

  const store = new Corestore(config.storageDir)
  const roomKey = config.roomKey || await readPersistedRoomKey(config.storageDir)
  const room = new RoomManager({ store, roomKey, membership })
  const z32Key = await room.open()
  await writeFile(join(config.storageDir, 'room-key'), z32Key)
  log('room:', z32Key, roomKey ? '(reopened)' : '(created)')

  // Publish the room key to the relay (retry until it sticks — relay may boot
  // after us). Idempotent on the relay side.
  let published = false
  const publishTimer = setInterval(tryPublish, 10000)
  if (publishTimer.unref) publishTimer.unref()
  async function tryPublish () {
    if (published) return
    const r = await relayClient.publishRoom(z32Key)
    if (r.ok) {
      published = true; clearInterval(publishTimer); log('published room key to relay')
    } else if (r.status === 401) {
      log('publish unauthorized — set RELAY_API_KEY'); clearInterval(publishTimer)
    } else if (r.status >= 400 && r.status < 500) {
      // Persistent client error (bad body, missing route on an older relay) —
      // retrying won't help, so stop and surface it.
      const msg = (r.body && r.body.error) ? r.body.error : ''
      log(`publish rejected ${r.status} ${msg} — not retrying`); clearInterval(publishTimer)
    } else {
      // network (status 0) / transient 5xx — relay may still be booting; retry.
      log(`publish failed (${r.status || 'network'}), will retry`)
    }
  }
  tryPublish()

  // Swarm: announce the room so clients blind-replicate it read-only.
  let swarm = null
  if (config.enableSwarm && room.discoveryKey) {
    swarm = new Hyperswarm()
    swarm.on('connection', (socket) => { store.replicate(socket) })
    swarm.join(room.discoveryKey, { server: true, client: false })
    log('swarm announcing room discovery')
  }

  // Project + serve.
  const projector = new Projector({ relayClient, room, relayPubkey, intervalMs: config.pollIntervalMs, log })
  projector.start()

  if (config.host !== '127.0.0.1' && config.host !== '::1') {
    log('[SECURITY WARNING] query server bound to ' + config.host + ' — it is UNAUTHENTICATED and must only be reached via the relay proxy. Bind 127.0.0.1 unless you have a separate access-control layer.')
  }
  const server = createServer({ room, config, log })
  await new Promise((resolve) => server.listen(config.port, config.host, resolve))
  log('query API on http://' + config.host + ':' + config.port)

  let closing = false
  async function shutdown (sig) {
    if (closing) return
    closing = true
    log('shutting down (' + sig + ')')
    // Watchdog: a stuck swarm/room close cannot wedge SIGTERM forever.
    const kill = setTimeout(() => process.exit(1), 5000)
    if (kill.unref) kill.unref()
    clearInterval(publishTimer)
    projector.stop()
    await new Promise((resolve) => server.close(resolve))
    if (swarm) { try { await swarm.destroy() } catch (e) { log('swarm destroy error: ' + e.message) } }
    try { await room.close() } catch (e) { log('room close error: ' + e.message) }
    process.exit(0)
  }
  process.on('SIGINT', () => shutdown('SIGINT'))
  process.on('SIGTERM', () => shutdown('SIGTERM'))
}

main().catch((err) => { console.error('[index] fatal:', err); process.exit(1) })
