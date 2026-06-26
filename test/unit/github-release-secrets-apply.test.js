import test from 'brittle'
import { execFile } from 'node:child_process'
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

const TEST_GITHUB_TOKEN = `ghp_${'a'.repeat(36)}`
const TEST_GITHUB_TOKEN_ALT = `gho_${'b'.repeat(36)}`
const TEST_PRIVATE_KEY = '-----BEGIN OPENSSH PRIVATE KEY-----\nfake-fleet-key\n-----END OPENSSH PRIVATE KEY-----'
const TEST_STARTOS_PRIVATE_KEY = '-----BEGIN PRIVATE KEY-----\nfake-startos-key\n-----END PRIVATE KEY-----'

function runApply (argv, env = {}) {
  return new Promise((resolve) => {
    execFile(process.execPath, ['scripts/apply-github-release-secrets.mjs', ...argv], {
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

async function candidateEnvFile (t, body) {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-apply-env-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })
  const file = path.join(dir, 'hiverelay-release-secrets.env')
  await writeFile(file, body)
  return file
}

function validCandidateEnvBody (overrides = {}) {
  const env = {
    FLEET_SSH_PRIVATE_KEY: TEST_PRIVATE_KEY,
    UMBREL_STORE_TOKEN: TEST_GITHUB_TOKEN,
    UMBREL_OFFICIAL_PR_TOKEN: TEST_GITHUB_TOKEN_ALT,
    UMBREL_OFFICIAL_FORK: 'bigdestiny2/umbrel-apps',
    STARTOS_DEVELOPER_KEY_PEM: TEST_STARTOS_PRIVATE_KEY,
    STARTOS_REGISTRY_URL: 'https://registry.start9.com',
    ...overrides
  }
  const lines = [
    'FLEET_SSH_PRIVATE_KEY<<FLEET_KEY',
    env.FLEET_SSH_PRIVATE_KEY,
    'FLEET_KEY',
    `UMBREL_STORE_TOKEN=${env.UMBREL_STORE_TOKEN}`,
    `UMBREL_OFFICIAL_PR_TOKEN=${env.UMBREL_OFFICIAL_PR_TOKEN}`,
    `UMBREL_OFFICIAL_FORK=${env.UMBREL_OFFICIAL_FORK}`,
    'STARTOS_DEVELOPER_KEY_PEM<<STARTOS_KEY',
    env.STARTOS_DEVELOPER_KEY_PEM,
    'STARTOS_KEY',
    `STARTOS_REGISTRY_URL=${env.STARTOS_REGISTRY_URL}`
  ]
  if (env.FLEET_ROLLOUT_TIMEOUT_MS) lines.push(`FLEET_ROLLOUT_TIMEOUT_MS=${env.FLEET_ROLLOUT_TIMEOUT_MS}`)
  return lines.join('\n') + '\n'
}

async function fakeGh (t) {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-apply-fake-gh-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })
  const log = path.join(dir, 'gh.jsonl')
  const file = path.join(dir, 'gh')
  await writeFile(file, `#!/usr/bin/env node
const fs = require('fs')
const args = process.argv.slice(2)
const input = fs.readFileSync(0, 'utf8')
const row = { args, input }
fs.appendFileSync(process.env.HIVERELAY_FAKE_GH_LOG, JSON.stringify(row) + '\\n')
if (process.env.HIVERELAY_FAKE_GH_FAIL) {
  process.stderr.write(process.env.HIVERELAY_FAKE_GH_FAIL)
  process.exit(1)
}
if (args[0] === 'secret' && args[1] === 'set') process.exit(0)
if (args[0] === 'variable' && args[1] === 'set') process.exit(0)
process.stderr.write('unexpected fake gh args: ' + args.join(' '))
process.exit(2)
`)
  await chmod(file, 0o755)
  return { file, log }
}

async function readGhLog (log) {
  const body = await readFile(log, 'utf8')
  return body.trim().split('\n').filter(Boolean).map(line => JSON.parse(line))
}

test('GitHub release secret apply dry-run validates candidate without printing values', async (t) => {
  const candidate = await candidateEnvFile(t, validCandidateEnvBody({
    FLEET_ROLLOUT_TIMEOUT_MS: '1800000'
  }))
  const res = await runApply([
    '--repo', 'bigdestiny2/P2P-Hiverelay',
    '--env-file', candidate,
    '--dry-run'
  ])

  t.is(res.status, 0)
  t.ok(res.stdout.includes('Release secret candidate file is valid'))
  t.ok(res.stdout.includes('Would set GitHub Secrets: FLEET_SSH_PRIVATE_KEY'))
  t.ok(res.stdout.includes('Would set GitHub Variables: FLEET_ROLLOUT_TIMEOUT_MS'))
  t.absent(res.stdout.includes(TEST_GITHUB_TOKEN))
  t.absent(res.stdout.includes(TEST_PRIVATE_KEY))
  t.absent(res.stderr.includes(TEST_GITHUB_TOKEN))
})

test('GitHub release secret apply sends validated values to gh secret set via stdin', async (t) => {
  const candidate = await candidateEnvFile(t, validCandidateEnvBody({
    FLEET_ROLLOUT_TIMEOUT_MS: '1800000'
  }))
  const gh = await fakeGh(t)
  const res = await runApply([
    '--repo', 'bigdestiny2/P2P-Hiverelay',
    '--env-file', candidate,
    '--gh', gh.file
  ], {
    HIVERELAY_FAKE_GH_LOG: gh.log
  })

  t.is(res.status, 0)
  t.ok(res.stdout.includes('Set GitHub Secret UMBREL_STORE_TOKEN'))
  t.ok(res.stdout.includes('Set GitHub Variable FLEET_ROLLOUT_TIMEOUT_MS'))
  t.absent(res.stdout.includes(TEST_GITHUB_TOKEN))
  t.absent(res.stdout.includes(TEST_PRIVATE_KEY))

  const rows = await readGhLog(gh.log)
  t.is(rows.length, 7)
  const secretRows = rows.filter(row => row.args[0] === 'secret')
  const variableRows = rows.filter(row => row.args[0] === 'variable')
  t.is(secretRows.length, 6)
  t.is(variableRows.length, 1)
  t.ok(secretRows.some(row => row.args.join(' ') === 'secret set FLEET_SSH_PRIVATE_KEY --repo bigdestiny2/P2P-Hiverelay' && row.input === TEST_PRIVATE_KEY))
  t.ok(secretRows.some(row => row.args.join(' ') === 'secret set UMBREL_STORE_TOKEN --repo bigdestiny2/P2P-Hiverelay' && row.input === TEST_GITHUB_TOKEN))
  t.ok(variableRows.some(row => row.args.join(' ') === 'variable set FLEET_ROLLOUT_TIMEOUT_MS --repo bigdestiny2/P2P-Hiverelay --body 1800000' && row.input === ''))
})

test('GitHub release secret apply rejects malformed candidate without calling gh or echoing values', async (t) => {
  const secretValue = `ghp_${'s'.repeat(36)}`
  const candidate = await candidateEnvFile(t, validCandidateEnvBody({
    UMBREL_STORE_TOKEN: ` ${secretValue}`
  }))
  const gh = await fakeGh(t)
  const res = await runApply([
    '--repo', 'bigdestiny2/P2P-Hiverelay',
    '--env-file', candidate,
    '--gh', gh.file
  ], {
    HIVERELAY_FAKE_GH_LOG: gh.log
  })

  t.is(res.status, 1)
  t.ok(res.stderr.includes('UMBREL_STORE_TOKEN must be a GitHub token'))
  t.absent(res.stdout.includes(secretValue))
  t.absent(res.stderr.includes(secretValue))

  let logMissing = false
  try {
    await readFile(gh.log, 'utf8')
  } catch (err) {
    logMissing = err && err.code === 'ENOENT'
  }
  t.ok(logMissing, 'fake gh was not called')
})

test('GitHub release secret apply rejects malformed repo names before gh calls', async (t) => {
  const candidate = await candidateEnvFile(t, validCandidateEnvBody())
  const gh = await fakeGh(t)
  const res = await runApply([
    '--repo', 'bad/repo\nHIVERELAY_ATTACKER_VALUE=owned',
    '--env-file', candidate,
    '--gh', gh.file
  ], {
    HIVERELAY_FAKE_GH_LOG: gh.log
  })

  t.is(res.status, 1)
  t.ok(res.stderr.includes('Invalid --repo'))
  t.absent(res.stderr.includes('HIVERELAY_ATTACKER_VALUE=owned'))

  let logMissing = false
  try {
    await readFile(gh.log, 'utf8')
  } catch (err) {
    logMissing = err && err.code === 'ENOENT'
  }
  t.ok(logMissing, 'fake gh was not called')
})

test('GitHub release secret apply rejects prerelease validation mode before gh calls', async (t) => {
  const candidate = await candidateEnvFile(t, validCandidateEnvBody())
  const gh = await fakeGh(t)
  const res = await runApply([
    '--repo', 'bigdestiny2/P2P-Hiverelay',
    '--env-file', candidate,
    '--gh', gh.file,
    '--prerelease', 'true'
  ], {
    HIVERELAY_FAKE_GH_LOG: gh.log
  })

  t.is(res.status, 1)
  t.ok(res.stderr.includes('only validates full-release secret values'))
  t.absent(res.stdout.includes(TEST_GITHUB_TOKEN))
  t.absent(res.stderr.includes(TEST_GITHUB_TOKEN))

  let logMissing = false
  try {
    await readFile(gh.log, 'utf8')
  } catch (err) {
    logMissing = err && err.code === 'ENOENT'
  }
  t.ok(logMissing, 'fake gh was not called')
})
