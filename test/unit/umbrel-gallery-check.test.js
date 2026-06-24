import test from 'brittle'
import { execFile } from 'node:child_process'
import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

function runCheck (argv) {
  return new Promise((resolve) => {
    execFile(process.execPath, ['scripts/check-umbrel-gallery.mjs', ...argv], {
      cwd: process.cwd(),
      timeout: 10000
    }, (err, stdout, stderr) => {
      resolve({
        status: err && typeof err.code === 'number' ? err.code : 0,
        stdout,
        stderr
      })
    })
  })
}

test('Umbrel gallery checker allows the empty first-submission gallery', async (t) => {
  const dir = await fixtureDir(t)
  const manifest = path.join(dir, 'umbrel-app.yml')
  await writeFile(manifest, 'gallery: []\n')

  const res = await runCheck(['--manifest', manifest, '--gallery-dir', path.join(dir, 'gallery')])

  t.is(res.status, 0)
  t.ok(res.stdout.includes('gallery is empty for the first official submission'))
})

test('Umbrel gallery checker validates populated 1440x900 image lists', async (t) => {
  const dir = await fixtureDir(t)
  const gallery = path.join(dir, 'gallery')
  await mkdir(gallery)
  const manifest = path.join(dir, 'umbrel-app.yml')
  await writeFile(manifest, 'gallery: [1.png, 2.jpg, 3.jpeg]\n')
  await writeFile(path.join(gallery, '1.png'), png(1440, 900))
  await writeFile(path.join(gallery, '2.jpg'), jpeg(1440, 900))
  await writeFile(path.join(gallery, '3.jpeg'), jpeg(1440, 900))

  const res = await runCheck(['--manifest', manifest, '--gallery-dir', gallery])

  t.is(res.status, 0)
  t.ok(res.stdout.includes('Umbrel gallery validates: 3 images.'))
})

test('Umbrel gallery checker rejects missing listed images', async (t) => {
  const dir = await fixtureDir(t)
  const gallery = path.join(dir, 'gallery')
  await mkdir(gallery)
  const manifest = path.join(dir, 'umbrel-app.yml')
  await writeFile(manifest, 'gallery: [1.png, 2.png, 3.png]\n')

  const res = await runCheck(['--manifest', manifest, '--gallery-dir', gallery])

  t.is(res.status, 1)
  t.ok(res.stderr.includes('Gallery image listed but missing'))
})

test('Umbrel gallery checker rejects path-like gallery names', async (t) => {
  const dir = await fixtureDir(t)
  const gallery = path.join(dir, 'gallery')
  await mkdir(gallery)
  const manifest = path.join(dir, 'umbrel-app.yml')
  await writeFile(manifest, 'gallery:\n  - ../1.png\n  - 2.png\n  - 3.png\n')

  const res = await runCheck(['--manifest', manifest, '--gallery-dir', gallery])

  t.is(res.status, 1)
  t.ok(res.stderr.includes('gallery image name must be a numbered PNG/JPEG filename'))
})

test('Umbrel gallery checker rejects wrong dimensions', async (t) => {
  const dir = await fixtureDir(t)
  const gallery = path.join(dir, 'gallery')
  await mkdir(gallery)
  const manifest = path.join(dir, 'umbrel-app.yml')
  await writeFile(manifest, 'gallery: [1.png, 2.png, 3.png]\n')
  await writeFile(path.join(gallery, '1.png'), png(1440, 900))
  await writeFile(path.join(gallery, '2.png'), png(1200, 900))
  await writeFile(path.join(gallery, '3.png'), png(1440, 900))

  const res = await runCheck(['--manifest', manifest, '--gallery-dir', gallery])

  t.is(res.status, 1)
  t.ok(res.stderr.includes('gallery image must be 1440x900 px'))
})

test('Umbrel gallery checker rejects symlinked listed images before read', async (t) => {
  const dir = await fixtureDir(t)
  const gallery = path.join(dir, 'gallery')
  await mkdir(gallery)
  const outside = path.join(dir, 'outside.png')
  const manifest = path.join(dir, 'umbrel-app.yml')
  await writeFile(manifest, 'gallery: [1.png, 2.png, 3.png]\n')
  await writeFile(outside, png(1440, 900))
  await symlink(outside, path.join(gallery, '1.png'))
  await writeFile(path.join(gallery, '2.png'), png(1440, 900))
  await writeFile(path.join(gallery, '3.png'), png(1440, 900))

  const res = await runCheck(['--manifest', manifest, '--gallery-dir', gallery])

  t.is(res.status, 1)
  t.ok(res.stderr.includes('gallery image must not be a symlink'))
})

test('Umbrel gallery checker rejects symlinked gallery directories before read', async (t) => {
  const dir = await fixtureDir(t)
  const realGallery = path.join(dir, 'real-gallery')
  const linkedGallery = path.join(dir, 'gallery')
  await mkdir(realGallery)
  const manifest = path.join(dir, 'umbrel-app.yml')
  await writeFile(manifest, 'gallery: [1.png, 2.png, 3.png]\n')
  await writeFile(path.join(realGallery, '1.png'), png(1440, 900))
  await writeFile(path.join(realGallery, '2.png'), png(1440, 900))
  await writeFile(path.join(realGallery, '3.png'), png(1440, 900))
  await symlink(realGallery, linkedGallery, 'dir')

  const res = await runCheck(['--manifest', manifest, '--gallery-dir', linkedGallery])

  t.is(res.status, 1)
  t.ok(res.stderr.includes('gallery directory must not be a symlink'))
})

test('Umbrel gallery checker rejects oversized listed images before read', async (t) => {
  const dir = await fixtureDir(t)
  const gallery = path.join(dir, 'gallery')
  await mkdir(gallery)
  const manifest = path.join(dir, 'umbrel-app.yml')
  await writeFile(manifest, 'gallery: [1.png, 2.png, 3.png]\n')
  await writeFile(path.join(gallery, '1.png'), largePngHeader(8 * 1024 * 1024 + 1))
  await writeFile(path.join(gallery, '2.png'), png(1440, 900))
  await writeFile(path.join(gallery, '3.png'), png(1440, 900))

  const res = await runCheck(['--manifest', manifest, '--gallery-dir', gallery])

  t.is(res.status, 1)
  t.ok(res.stderr.includes('gallery image must be 8388608 bytes or smaller'))
})

async function fixtureDir (t) {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-umbrel-gallery-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })
  return dir
}

function png (width, height) {
  const buf = Buffer.alloc(24)
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).copy(buf, 0)
  Buffer.from('IHDR').copy(buf, 12)
  buf.writeUInt32BE(width, 16)
  buf.writeUInt32BE(height, 20)
  return buf
}

function largePngHeader (bytes) {
  const buf = Buffer.alloc(bytes)
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]).copy(buf, 0)
  Buffer.from('IHDR').copy(buf, 12)
  buf.writeUInt32BE(1440, 16)
  buf.writeUInt32BE(900, 20)
  return buf
}

function jpeg (width, height) {
  return Buffer.from([
    0xff, 0xd8,
    0xff, 0xc0,
    0x00, 0x11,
    0x08,
    (height >> 8) & 0xff, height & 0xff,
    (width >> 8) & 0xff, width & 0xff,
    0x03,
    0x01, 0x11, 0x00,
    0x02, 0x11, 0x00,
    0x03, 0x11, 0x00,
    0xff, 0xd9
  ])
}
