import { test } from 'node:test'
import assert from 'node:assert/strict'
import Corestore from 'corestore'
import SchemaSheets from 'schema-sheets'
import z32 from 'z32'
import { rm, mkdtemp } from 'fs/promises'
import { tmpdir } from 'os'
import { join } from 'path'
import { RoomManager } from '../lib/room.js'

const KEY = 'a'.repeat(64)
const tmp = () => mkdtemp(join(tmpdir(), 'idx-e2e-'))

// The spike, locked in: a key-only client (no encryption key, NOT a writer)
// blind-replicates the room read-only and sees the writer's rows. This is the
// §2.3 contract — and exactly how the desktop consumes the room (it never
// joins as a writer; it opens SchemaSheets(store, roomKey) and replicates).
test('a key-only client blind-replicates the room read-only', async () => {
  const wdir = await tmp()
  const rdir = await tmp()
  const wstore = new Corestore(wdir)

  // Writer = the sidecar (RoomManager joins + registers schemas + writes).
  const writer = new RoomManager({ store: wstore })
  const roomKey = await writer.open()
  await writer.upsert('app-manifest', { appId: KEY, name: 'Replicated', driveKey: KEY })
  await writer.update()

  // Reader = a desktop client: read-only, no join, discovers the schema by name.
  const rstore = new Corestore(rdir)
  const reader = new SchemaSheets(rstore, z32.decode(roomKey), {})
  await reader.ready()

  const s1 = wstore.replicate(true)
  const s2 = rstore.replicate(false)
  s1.pipe(s2).pipe(s1)
  s1.on('error', () => {})
  s2.on('error', () => {})

  let rows = []
  for (let i = 0; i < 15; i++) {
    await reader.base.update()
    const schemas = await reader.listSchemas()
    const id = schemas.find(s => s.name === 'app-manifest')?.schemaId
    if (id) rows = await reader.list(id)
    if (rows.length > 0) break
    await new Promise(resolve => setTimeout(resolve, 300))
  }
  assert.equal(rows.length, 1, 'reader replicated the manifest row')
  assert.equal(rows[0].json.name, 'Replicated')

  await writer.close()
  await reader.close()
  await rm(wdir, { recursive: true, force: true })
  await rm(rdir, { recursive: true, force: true })
})
