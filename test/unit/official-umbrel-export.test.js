import test from 'brittle'
import { execFile } from 'node:child_process'
import { mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

function runExport (argv) {
  return new Promise((resolve) => {
    execFile(process.execPath, ['scripts/export-official-umbrel-app.mjs', ...argv], {
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

test('official Umbrel exporter rejects symlinked expected files', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-official-export-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const target = path.join(dir, 'blindspark')
  const outside = path.join(dir, 'outside.yml')
  await mkdir(target)
  await writeFile(outside, 'do-not-touch\n')
  await symlink(outside, path.join(target, 'docker-compose.yml'))

  const res = await runExport([
    '--target', target,
    '--allow-placeholder'
  ])

  t.is(res.status, 1)
  t.ok(res.stderr.includes('symlinked official Umbrel path'))
  t.is(await readFile(outside, 'utf8'), 'do-not-touch\n')
})

test('official Umbrel exporter rejects symlinked missing target parents', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-official-export-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })

  const outside = path.join(dir, 'outside-store')
  const link = path.join(dir, 'store-link')
  const target = path.join(link, 'blindspark')
  await mkdir(outside)
  await symlink(outside, link)

  const res = await runExport([
    '--target', target,
    '--allow-placeholder'
  ])

  t.is(res.status, 1)
  t.ok(res.stderr.includes('symlinked official Umbrel path'))
  t.alike(await readdir(outside), [])
})
