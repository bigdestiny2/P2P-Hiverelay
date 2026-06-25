import test from 'brittle'
import { execFile } from 'node:child_process'
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

const REQUIRED_SECRETS = [
  'FLEET_SSH_PRIVATE_KEY',
  'UMBREL_STORE_TOKEN',
  'UMBREL_OFFICIAL_PR_TOKEN',
  'UMBREL_OFFICIAL_FORK',
  'STARTOS_DEVELOPER_KEY_PEM',
  'STARTOS_REGISTRY_URL'
]

function runSetupCheck (argv, env = {}) {
  return new Promise((resolve) => {
    execFile(process.execPath, ['scripts/check-github-release-setup.mjs', ...argv], {
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

async function fakeGh (t) {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-fake-gh-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })
  const file = path.join(dir, 'gh')
  await writeFile(file, `#!/usr/bin/env node
const args = process.argv.slice(2)
const payload = JSON.parse(process.env.HIVERELAY_FAKE_GH || '{}')
if (payload.fail) {
  process.stderr.write(payload.failMessage || 'fake gh failure')
  process.exit(payload.failCode || 1)
}
if (payload.invalidJson) {
  process.stdout.write('{not-json')
  process.exit(0)
}
if (args[0] === 'secret' && args[1] === 'list') {
  process.stdout.write(JSON.stringify((payload.secrets || []).map(name => ({ name }))))
  process.exit(0)
}
if (args[0] === 'variable' && args[1] === 'list') {
  process.stdout.write(JSON.stringify((payload.variables || []).map(row => ({ name: row.name, value: row.value }))))
  process.exit(0)
}
process.stderr.write('unexpected fake gh args: ' + args.join(' '))
process.exit(2)
`)
  await chmod(file, 0o755)
  return file
}

function fakeEnv (payload) {
  return {
    HIVERELAY_FAKE_GH: JSON.stringify(payload)
  }
}

test('GitHub release setup check passes with all required secrets', async (t) => {
  const gh = await fakeGh(t)
  const res = await runSetupCheck([
    '--repo', 'bigdestiny2/P2P-Hiverelay',
    '--gh', gh
  ], fakeEnv({
    secrets: REQUIRED_SECRETS,
    variables: [{ name: 'FLEET_ROLLOUT_TIMEOUT_MS', value: '1800000' }]
  }))

  t.is(res.status, 0)
  t.ok(res.stdout.includes('GitHub release setup presence check passed'))
  t.ok(res.stdout.includes('Required release secret names: 6/6'))
  t.ok(res.stdout.includes('FLEET_ROLLOUT_TIMEOUT_MS'))
  t.ok(res.stdout.includes('Secret values are not readable through gh'))
  t.ok(res.stdout.includes('Release distribution preflight'))
})

test('GitHub release setup check reports missing release secrets', async (t) => {
  const gh = await fakeGh(t)
  const res = await runSetupCheck([
    '--repo', 'bigdestiny2/P2P-Hiverelay',
    '--gh', gh
  ], fakeEnv({
    secrets: ['FLEET_SSH_PRIVATE_KEY'],
    variables: []
  }))

  t.is(res.status, 1)
  t.ok(res.stderr.includes('GitHub release setup check failed'))
  t.ok(res.stderr.includes('Missing repository secret UMBREL_STORE_TOKEN'))
  t.ok(res.stderr.includes('Missing repository secret STARTOS_REGISTRY_URL'))
  t.absent(res.stderr.includes('Missing repository secret FLEET_SSH_PRIVATE_KEY'))
})

test('GitHub release setup check rejects required secrets configured as variables', async (t) => {
  const gh = await fakeGh(t)
  const res = await runSetupCheck([
    '--repo', 'bigdestiny2/P2P-Hiverelay',
    '--gh', gh
  ], fakeEnv({
    secrets: REQUIRED_SECRETS.filter(name => name !== 'UMBREL_STORE_TOKEN'),
    variables: [{ name: 'UMBREL_STORE_TOKEN', value: 'ghp_example' }]
  }))

  t.is(res.status, 1)
  t.ok(res.stderr.includes('Missing repository secret UMBREL_STORE_TOKEN'))
  t.ok(res.stderr.includes('Required secret UMBREL_STORE_TOKEN is configured as a repository variable'))
})

test('GitHub release setup check rejects invalid optional fleet timeout variable', async (t) => {
  const gh = await fakeGh(t)
  const res = await runSetupCheck([
    '--repo', 'bigdestiny2/P2P-Hiverelay',
    '--gh', gh
  ], fakeEnv({
    secrets: REQUIRED_SECRETS,
    variables: [{ name: 'FLEET_ROLLOUT_TIMEOUT_MS', value: '1800000\nHIVERELAY_ATTACKER_VALUE=owned' }]
  }))

  t.is(res.status, 1)
  t.ok(res.stderr.includes('FLEET_ROLLOUT_TIMEOUT_MS must be an integer'))
  t.absent(res.stderr.includes('HIVERELAY_ATTACKER_VALUE=owned'))
})

test('GitHub release setup check reports gh JSON failures', async (t) => {
  const gh = await fakeGh(t)
  const res = await runSetupCheck([
    '--repo', 'bigdestiny2/P2P-Hiverelay',
    '--gh', gh
  ], fakeEnv({
    invalidJson: true
  }))

  t.is(res.status, 1)
  t.ok(res.stderr.includes('returned invalid JSON'))
})

test('GitHub release setup check rejects malformed repo names before gh calls', async (t) => {
  const gh = await fakeGh(t)
  const res = await runSetupCheck([
    '--repo', 'bad/repo\nHIVERELAY_ATTACKER_VALUE=owned',
    '--gh', gh
  ], fakeEnv({
    secrets: REQUIRED_SECRETS
  }))

  t.is(res.status, 1)
  t.ok(res.stderr.includes('Invalid --repo'))
  t.absent(res.stderr.includes('HIVERELAY_ATTACKER_VALUE=owned'))
})
