import test from 'brittle'
import { execFile } from 'node:child_process'
import { mkdtemp, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

const SCRIPT = path.join(process.cwd(), 'scripts/check-official-umbrel-pr.mjs')

function runCheck (argv = []) {
  return new Promise((resolve) => {
    execFile(process.execPath, [SCRIPT, ...argv], {
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

test('official Umbrel PR check fails the current PENDING source manifest for handoff', async (t) => {
  const res = await runCheck()

  t.is(res.status, 1)
  t.ok(res.stdout.includes('submission=https://github.com/getumbrel/umbrel-apps/pull/PENDING'))
  t.ok(res.stdout.includes('Official Umbrel submission is still PENDING'))
  t.ok(res.stdout.includes('reviewer handoff'))
})

test('official Umbrel PR check allows placeholder only for pre-PR export', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-official-pr-check-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })
  const manifest = path.join(dir, 'umbrel-app.yml')
  await writeFile(manifest, manifestBody({
    submission: 'https://github.com/getumbrel/umbrel-apps/pull/PENDING',
    releaseNotes: '""'
  }))

  const res = await runCheck(['--manifest', manifest, '--allow-placeholder'])

  t.is(res.status, 0)
  t.ok(res.stdout.includes('WARN Official Umbrel submission is still PENDING'))
  t.ok(res.stdout.includes('PASS Placeholder submission is allowed for pre-PR export only.'))
})

test('official Umbrel PR check passes a real upstream PR URL', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-official-pr-check-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })
  const manifest = path.join(dir, 'umbrel-app.yml')
  await writeFile(manifest, manifestBody({
    submission: 'https://github.com/getumbrel/umbrel-apps/pull/123',
    releaseNotes: '""'
  }))

  const res = await runCheck(['--manifest', manifest, '--json'])
  const body = JSON.parse(res.stdout)

  t.is(res.status, 0)
  t.is(body.ok, true)
  t.is(body.submission, 'https://github.com/getumbrel/umbrel-apps/pull/123')
  t.is(body.version, '0.20.2')
})

test('official Umbrel PR check rejects invalid PR URLs and non-empty pending notes', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-official-pr-check-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })
  const invalidManifest = path.join(dir, 'invalid.yml')
  await writeFile(invalidManifest, manifestBody({
    submission: 'https://github.com/example/umbrel-apps/pull/123',
    releaseNotes: '""'
  }))
  const invalid = await runCheck(['--manifest', invalidManifest])
  t.is(invalid.status, 1)
  t.ok(invalid.stdout.includes('must be a getumbrel/umbrel-apps pull request URL'))

  const pendingNotesManifest = path.join(dir, 'pending-notes.yml')
  await writeFile(pendingNotesManifest, manifestBody({
    submission: 'https://github.com/getumbrel/umbrel-apps/pull/PENDING',
    releaseNotes: '>-\n  Ship notes should wait for the real official PR.'
  }))
  const pendingNotes = await runCheck(['--manifest', pendingNotesManifest, '--allow-placeholder'])
  t.is(pendingNotes.status, 1)
  t.ok(pendingNotes.stdout.includes('releaseNotes must stay empty while submission is PENDING'))
})

test('official Umbrel PR check rejects symlinked manifests', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-official-pr-check-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })
  const realManifest = path.join(dir, 'real.yml')
  const linkManifest = path.join(dir, 'link.yml')
  await writeFile(realManifest, manifestBody({
    submission: 'https://github.com/getumbrel/umbrel-apps/pull/123',
    releaseNotes: '""'
  }))
  await symlink(realManifest, linkManifest)

  const res = await runCheck(['--manifest', linkManifest])

  t.is(res.status, 1)
  t.ok(res.stdout.includes('manifest must not be a symlink'))
})

function manifestBody ({ submission, releaseNotes }) {
  return `manifestVersion: 1.1
id: blindspark
name: Blindspark
version: "0.20.2"
releaseNotes: ${releaseNotes}
submission: ${submission}
`
}
