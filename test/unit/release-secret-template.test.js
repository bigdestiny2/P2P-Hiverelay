import test from 'brittle'
import { execFile } from 'node:child_process'
import { lstat, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

function runTemplate (argv) {
  return new Promise((resolve) => {
    execFile(process.execPath, ['scripts/write-release-secrets-template.mjs', ...argv], {
      cwd: process.cwd(),
      env: {
        PATH: process.env.PATH || ''
      },
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

function runCheck (argv) {
  return new Promise((resolve) => {
    execFile(process.execPath, ['scripts/check-release-distribution-env.mjs', ...argv], {
      cwd: process.cwd(),
      env: {
        PATH: process.env.PATH || ''
      },
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

async function tempDir (t) {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-template-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })
  return dir
}

test('release secret template writer creates private placeholder candidate outside repo', async (t) => {
  const dir = await tempDir(t)
  const out = path.join(dir, 'hiverelay-release-secrets.env')
  const res = await runTemplate(['--out', out])

  t.is(res.status, 0)
  t.ok(res.stdout.includes('Wrote release value candidate template'))
  t.ok(res.stdout.includes('release:check-distribution-env'))

  const stat = await lstat(out)
  t.ok(stat.isFile())
  t.is(stat.mode & 0o777, 0o600)

  const body = await readFile(out, 'utf8')
  t.ok(body.includes('FLEET_SSH_PRIVATE_KEY<<FLEET_KEY'))
  t.ok(body.includes('UMBREL_STORE_TOKEN=REPLACE_WITH_GITHUB_TOKEN_FOR_COMMUNITY_STORE'))
  t.ok(body.includes('UMBREL_OFFICIAL_PR_TOKEN=REPLACE_WITH_GITHUB_TOKEN_FOR_OFFICIAL_UMBREL_PR'))
  t.ok(body.includes('UMBREL_OFFICIAL_FORK=REPLACE_OWNER/umbrel-apps'))
  t.ok(body.includes('STARTOS_DEVELOPER_KEY_PEM<<STARTOS_KEY'))
  t.ok(body.includes('STARTOS_REGISTRY_URL=REPLACE_WITH_PUBLIC_HTTPS_REGISTRY_URL'))
  t.absent(/gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}/.test(body))

  const check = await runCheck([
    '--env-file', out,
    '--channel', 'both',
    '--prerelease', 'false'
  ])
  t.is(check.status, 1)
  t.ok(check.stderr.includes('FLEET_SSH_PRIVATE_KEY must be a private key block'))
  t.ok(check.stderr.includes('UMBREL_STORE_TOKEN must be a GitHub token'))
  t.ok(check.stderr.includes('STARTOS_REGISTRY_URL must be a public https URL'))
})

test('release secret template writer refuses repo output paths', async (t) => {
  const out = path.join(process.cwd(), 'tmp-release-secrets.env')
  const res = await runTemplate(['--out', out])

  t.is(res.status, 1)
  t.ok(res.stderr.includes('Refusing to write release secret template inside the repository'))
})

test('release secret template writer refuses accidental overwrite unless forced', async (t) => {
  const dir = await tempDir(t)
  const out = path.join(dir, 'hiverelay-release-secrets.env')
  await writeFile(out, 'existing\n')

  const first = await runTemplate(['--out', out])
  t.is(first.status, 1)
  t.ok(first.stderr.includes('Output file already exists'))

  const second = await runTemplate(['--out', out, '--force'])
  t.is(second.status, 0)

  const body = await readFile(out, 'utf8')
  t.ok(body.includes('HiveRelay release distribution values candidate'))
  t.ok(body.includes('fork slug and registry URL are stored as GitHub Secrets for log masking'))
  t.absent(body.includes('existing'))
})

test('release secret template writer refuses symlink output even with force', async (t) => {
  const dir = await tempDir(t)
  const target = path.join(dir, 'target.env')
  const out = path.join(dir, 'linked.env')
  await writeFile(target, 'target\n')
  await symlink(target, out)

  const res = await runTemplate(['--out', out, '--force'])
  t.is(res.status, 1)
  t.ok(res.stderr.includes('Refusing to overwrite symlinked output file'))
})
