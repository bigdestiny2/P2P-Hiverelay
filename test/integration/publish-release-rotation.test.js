import test from 'brittle'
import b4a from 'b4a'
import Corestore from 'corestore'
import Hyperdrive from 'hyperdrive'
import { spawn } from 'node:child_process'
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { verifyAppRelease } from '../../packages/core/core/release-lifecycle.js'

function publish (directory, storage, version) {
  return new Promise((_resolve, reject) => {
    const child = spawn(process.execPath, [
      resolve('scripts/publish-app.js'),
      directory,
      '--id', 'rotation-e2e',
      '--name', 'Rotation E2E',
      '--version', version,
      '--storage', storage,
      '--storage-budget', '128KiB',
      '--rollback-window', '3',
      '--relays', ',',
      '--no-stay',
      '--hold-seconds', '0'
    ], { cwd: resolve('.'), stdio: ['ignore', 'pipe', 'pipe'] })
    let output = ''
    child.stdout.on('data', chunk => { output += chunk })
    child.stderr.on('data', chunk => { output += chunk })
    child.once('error', reject)
    child.once('exit', code => {
      if (code === 0) _resolve(output)
      else reject(new Error(`publisher exited ${code}:\n${output}`))
    })
  })
}

test('publisher rotates at its budget and cross-writes a signed predecessor pointer', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'hiverelay-release-rotation-'))
  const app = join(root, 'app')
  const storage = join(root, 'publisher')
  await mkdir(app)
  t.teardown(() => rm(root, { recursive: true, force: true }))

  await writeFile(join(app, 'index.html'), b4a.alloc(40 * 1024, 0x61))
  const firstOutput = await publish(app, storage, '1.0.0')
  const firstMap = JSON.parse(await readFile(join(storage, 'app-drives.json'), 'utf8'))
  const firstKey = firstMap['rotation-e2e']
  t.ok(firstOutput.includes('NEW DRIVE'))

  await writeFile(join(app, 'index.html'), b4a.alloc(40 * 1024, 0x62))
  const secondOutput = await publish(app, storage, '2.0.0')
  const secondMap = JSON.parse(await readFile(join(storage, 'app-drives.json'), 'utf8'))
  const secondKey = secondMap['rotation-e2e']
  t.not(secondKey, firstKey)
  if (secondKey === firstKey) return
  t.ok(secondOutput.includes('ROTATED (signed storage-budget transition)'))

  const store = new Corestore(storage)
  const current = new Hyperdrive(store, b4a.from(secondKey, 'hex'))
  const predecessor = new Hyperdrive(store, b4a.from(firstKey, 'hex'))
  await Promise.all([current.ready(), predecessor.ready()])
  const manifest = JSON.parse(b4a.toString(await current.get('/manifest.json', { wait: false })))
  const pointer = JSON.parse(b4a.toString(await predecessor.get('/.hiverelay/rotation.json', { wait: false })))
  t.ok(verifyAppRelease(manifest.hiverelay.release).ok)
  t.is(manifest.hiverelay.release.previousDriveKey, firstKey)
  t.alike(pointer, manifest.hiverelay.release)
  await store.close()
})
