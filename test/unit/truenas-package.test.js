import test from 'brittle'
import { execFile } from 'node:child_process'
import { appendFile, cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

test('TrueNAS Community package remains release-aligned and security-scoped', async (t) => {
  const result = await new Promise((resolve) => {
    execFile(process.execPath, ['scripts/check-truenas-package.mjs'], {
      cwd: process.cwd(),
      env: { PATH: process.env.PATH || '' },
      timeout: 10000
    }, (err, stdout, stderr) => {
      resolve({
        status: err && typeof err.code === 'number' ? err.code : 0,
        stdout,
        stderr
      })
    })
  })

  t.is(result.status, 0, result.stderr)
  t.ok(result.stdout.includes('TrueNAS Community package validates for Blindspark.'))
})

test('TrueNAS validator rejects actual vendored source drift', async (t) => {
  const fixture = await mkdtemp(path.join(tmpdir(), 'hiverelay-truenas-integrity-'))
  t.teardown(async () => {
    await rm(fixture, { recursive: true, force: true })
  })

  await mkdir(path.join(fixture, 'scripts'), { recursive: true })
  await cp('truenas-app', path.join(fixture, 'truenas-app'), { recursive: true })
  await writeFile(path.join(fixture, 'package.json'), JSON.stringify({ version: '1.0.0-rc.1' }) + '\n')
  await writeFile(
    path.join(fixture, 'scripts', 'check-truenas-package.mjs'),
    await readFile('scripts/check-truenas-package.mjs')
  )
  await appendFile(
    path.join(fixture, 'truenas-app', 'templates', 'library', 'base_v2_3_8', 'render.py'),
    '\n# unauthorized drift\n'
  )

  const result = await runValidator(fixture)
  t.is(result.status, 1)
  t.ok(result.stderr.includes('computed vendor content SHA-256'))
  t.ok(result.stderr.includes('normalized vendor content/upstream Git tree binding'))
})

function runValidator (cwd) {
  return new Promise((resolve) => {
    execFile(process.execPath, ['scripts/check-truenas-package.mjs'], {
      cwd,
      env: { PATH: process.env.PATH || '' },
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
