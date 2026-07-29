import test from 'brittle'
import b4a from 'b4a'
import Corestore from 'corestore'
import Hyperdrive from 'hyperdrive'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { syncPublishedFiles } from '../../scripts/lib/publish-drive-sync.mjs'

async function fixture (t) {
  const dir = await mkdtemp(join(tmpdir(), 'hiverelay-publish-sync-'))
  const store = new Corestore(dir)
  const drive = new Hyperdrive(store)
  await drive.ready()
  t.teardown(async () => {
    await drive.close()
    await rm(dir, { recursive: true, force: true })
  })
  return drive
}

async function paths (drive) {
  const result = []
  for await (const entry of drive.list('/')) result.push(entry.key)
  return result.sort()
}

test('publish sync skips an identical release without growing either core', async (t) => {
  const drive = await fixture(t)
  const files = [
    { path: '/index.html', content: b4a.from('<h1>Pear</h1>') },
    { path: '/manifest.json', content: b4a.from('{"version":"1.0.0"}') }
  ]

  t.alike(await syncPublishedFiles(drive, files), {
    added: 2,
    changed: 0,
    removed: 0,
    unchanged: 0
  })
  const before = { meta: drive.core.length, blobs: drive.blobs.core.length }

  t.alike(await syncPublishedFiles(drive, files), {
    added: 0,
    changed: 0,
    removed: 0,
    unchanged: 2
  })
  t.alike(
    { meta: drive.core.length, blobs: drive.blobs.core.length },
    before,
    'a no-op release appends no metadata or blob blocks'
  )
})

test('publish sync removes stale paths and deduplicates unchanged blocks in changed files', async (t) => {
  const drive = await fixture(t)
  const block = 64 * 1024
  const first = b4a.concat([b4a.alloc(block, 0x61), b4a.alloc(block, 0x62)])
  const second = b4a.concat([b4a.alloc(block, 0x61), b4a.alloc(block, 0x63)])

  await syncPublishedFiles(drive, [
    { path: '/app.bin', content: first },
    { path: '/stale.txt', content: b4a.from('remove me') }
  ])
  const blobLength = drive.blobs.core.length

  t.alike(await syncPublishedFiles(drive, [
    { path: '/app.bin', content: second },
    { path: '/current.txt', content: b4a.from('keep me') }
  ]), {
    added: 1,
    changed: 1,
    removed: 1,
    unchanged: 0
  })

  t.alike(await paths(drive), ['/app.bin', '/current.txt'])
  t.is(await drive.get('/stale.txt'), null)
  t.ok(b4a.equals(await drive.get('/app.bin'), second), 'changed file reads back exactly')

  const changedFileGrowth = drive.blobs.core.length - blobLength - 2
  t.is(
    changedFileGrowth,
    2,
    'changed two-block file appends one changed data block and one block map'
  )
})
