import test from 'brittle'
import { execFile } from 'node:child_process'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

function runWriter (argv, env = {}) {
  return new Promise((resolve) => {
    execFile(process.execPath, ['scripts/write-github-env.mjs', ...argv], {
      cwd: process.cwd(),
      env: {
        PATH: process.env.PATH || '',
        ...env
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

async function envFile (t) {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-github-env-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })
  return path.join(dir, 'github-env')
}

test('GitHub env writer appends one checked assignment', async (t) => {
  const out = await envFile(t)
  const res = await runWriter(['HIVERELAY_TEST_VALUE', 'safe-value', '--github-env', out])

  t.is(res.status, 0)
  t.is(await readFile(out, 'utf8'), 'HIVERELAY_TEST_VALUE=safe-value\n')
})

test('GitHub env writer rejects malformed variable names', async (t) => {
  const out = await envFile(t)
  const res = await runWriter(['bad-name', 'safe-value', '--github-env', out])

  t.is(res.status, 1)
  t.ok(res.stderr.includes('malformed GitHub environment variable name'))
})

test('GitHub env writer rejects multiline values before write', async (t) => {
  const out = await envFile(t)
  const res = await runWriter([
    'HIVERELAY_TEST_VALUE',
    'safe\nHIVERELAY_ATTACKER_VALUE=owned',
    '--github-env',
    out
  ])

  t.is(res.status, 1)
  t.ok(res.stderr.includes('multi-line or control-character value'))

  const body = await readFile(out, 'utf8').catch(() => '')
  t.is(body, '')
})
