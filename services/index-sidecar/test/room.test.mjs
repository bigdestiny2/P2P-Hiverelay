import { test } from 'node:test'
import assert from 'node:assert/strict'
import Corestore from 'corestore'
import { rm, mkdtemp } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import { RoomManager } from '../lib/room.js'

const Z32 = /^[ybndrfg8ejkmcpqxot1uwisza345h769]{52}$/
const KEY = 'a'.repeat(64)
const tmp = () => mkdtemp(join(tmpdir(), 'idx-room-'))

test('open() creates a room and registers the 4 schemas idempotently', async () => {
  const dir = await tmp()
  const room = new RoomManager({ store: new Corestore(dir) })
  const key = await room.open()
  assert.match(key, Z32)
  assert.equal(Object.keys(room.schemaIds).length, 4)
  await room._ensureSchemas() // second call must not duplicate
  const schemas = await room.sheets.listSchemas()
  assert.equal(schemas.length, 4)
  await room.close()
  await rm(dir, { recursive: true, force: true })
})

test('upsert adds then updates the same row (no duplicate)', async () => {
  const dir = await tmp()
  const room = new RoomManager({ store: new Corestore(dir) })
  await room.open()
  const a = await room.upsert('pin-registry', { appKey: KEY, seedState: 'accepted', anchored: false, verified: false })
  assert.equal(a.action, 'add')
  const b = await room.upsert('pin-registry', { appKey: KEY, seedState: 'anchored', anchored: true, verified: true })
  assert.equal(b.action, 'update')
  assert.equal(a.uuid, b.uuid, 'same row reused on update')
  await room.update()
  const rows = await room.list('pin-registry')
  assert.equal(rows.length, 1, 'no duplicate row')
  assert.equal(rows[0].json.seedState, 'anchored')
  await room.close()
  await rm(dir, { recursive: true, force: true })
})

test('reopen hydrates the row index so re-projection updates, not duplicates', async () => {
  const dir = await tmp()
  const store1 = new Corestore(dir)
  const room1 = new RoomManager({ store: store1 })
  const key = await room1.open()
  await room1.upsert('app-manifest', { appId: KEY, name: 'A', driveKey: KEY })
  await room1.update()
  await room1.close()

  const room2 = new RoomManager({ store: new Corestore(dir), roomKey: key })
  await room2.open()
  assert.ok(room2.rowIndex['app-manifest'].has(KEY), 'index hydrated from persisted rows')
  const r = await room2.upsert('app-manifest', { appId: KEY, name: 'A renamed', driveKey: KEY })
  assert.equal(r.action, 'update', 'existing row updated after restart')
  await room2.update()
  const rows = await room2.list('app-manifest')
  assert.equal(rows.length, 1)
  await room2.close()
  await rm(dir, { recursive: true, force: true })
})
