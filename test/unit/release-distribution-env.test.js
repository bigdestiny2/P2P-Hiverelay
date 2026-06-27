import test from 'brittle'
import { execFile } from 'node:child_process'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

const TEST_GITHUB_TOKEN = `ghp_${'a'.repeat(36)}`
const TEST_GITHUB_TOKEN_ALT = `gho_${'b'.repeat(36)}`
const TEST_NPM_TOKEN = `npm_${'c'.repeat(36)}`
const TEST_PRIVATE_KEY = '-----BEGIN OPENSSH PRIVATE KEY-----\nfake-fleet-key\n-----END OPENSSH PRIVATE KEY-----'
const TEST_STARTOS_PRIVATE_KEY = '-----BEGIN PRIVATE KEY-----\nfake-startos-key\n-----END PRIVATE KEY-----'

function validDistributionEnv (overrides = {}) {
  return {
    FLEET_SSH_PRIVATE_KEY: TEST_PRIVATE_KEY,
    UMBREL_STORE_TOKEN: TEST_GITHUB_TOKEN,
    UMBREL_OFFICIAL_PR_TOKEN: TEST_GITHUB_TOKEN_ALT,
    UMBREL_OFFICIAL_FORK: 'bigdestiny2/umbrel-apps',
    NPM_TOKEN: TEST_NPM_TOKEN,
    STARTOS_DEVELOPER_KEY_PEM: TEST_STARTOS_PRIVATE_KEY,
    STARTOS_REGISTRY_URL: 'https://registry.start9.com',
    ...overrides
  }
}

function runCheck (argv, env = {}) {
  return new Promise((resolve) => {
    execFile(process.execPath, ['scripts/check-release-distribution-env.mjs', ...argv], {
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
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-env-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })
  return path.join(dir, 'github-env')
}

async function candidateEnvFile (t, body) {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-release-candidate-env-'))
  t.teardown(async () => {
    await rm(dir, { recursive: true, force: true })
  })
  const file = path.join(dir, 'hiverelay-release-secrets.env')
  await writeFile(file, body)
  return file
}

function validCandidateEnvBody (overrides = {}) {
  const env = validDistributionEnv(overrides)
  const lines = [
    'FLEET_SSH_PRIVATE_KEY<<FLEET_KEY',
    env.FLEET_SSH_PRIVATE_KEY,
    'FLEET_KEY',
    `UMBREL_STORE_TOKEN=${env.UMBREL_STORE_TOKEN}`,
    `UMBREL_OFFICIAL_PR_TOKEN=${env.UMBREL_OFFICIAL_PR_TOKEN}`,
    `UMBREL_OFFICIAL_FORK=${env.UMBREL_OFFICIAL_FORK}`,
    `NPM_TOKEN=${env.NPM_TOKEN}`,
    'STARTOS_DEVELOPER_KEY_PEM<<STARTOS_KEY',
    env.STARTOS_DEVELOPER_KEY_PEM,
    'STARTOS_KEY',
    `STARTOS_REGISTRY_URL=${env.STARTOS_REGISTRY_URL}`
  ]
  if (env.FLEET_ROLLOUT_TIMEOUT_MS) lines.push(`FLEET_ROLLOUT_TIMEOUT_MS=${env.FLEET_ROLLOUT_TIMEOUT_MS}`)
  if (env.HIVERELAY_RELEASE_CHANNEL) lines.push(`HIVERELAY_RELEASE_CHANNEL=${env.HIVERELAY_RELEASE_CHANNEL}`)
  if (env.HIVERELAY_RELEASE_PRERELEASE) lines.push(`HIVERELAY_RELEASE_PRERELEASE=${env.HIVERELAY_RELEASE_PRERELEASE}`)
  return lines.join('\n') + '\n'
}

test('release distribution env check skips prereleases', async (t) => {
  const out = await envFile(t)
  const res = await runCheck([
    '--prerelease', 'true',
    '--github-env', out
  ])

  t.is(res.status, 0)
  t.ok(res.stdout.includes('skipped for prerelease'))

  const body = await readFile(out, 'utf8')
  t.ok(body.includes('HIVERELAY_RELEASE_EFFECTIVE_CHANNEL=none'))
  t.ok(body.includes('HIVERELAY_RELEASE_DISTRIBUTION_PREFLIGHT_STATUS=skipped'))
})

test('release distribution env check rejects prerelease channel promotion', async (t) => {
  const out = await envFile(t)
  const res = await runCheck([
    '--channel', 'canary',
    '--prerelease', 'true',
    '--github-env', out
  ])

  t.is(res.status, 1)
  t.ok(res.stderr.includes('pre-release channel must be none'))

  const body = await readFile(out, 'utf8')
  t.ok(body.includes('HIVERELAY_RELEASE_EFFECTIVE_CHANNEL=canary'))
  t.ok(body.includes('HIVERELAY_RELEASE_DISTRIBUTION_PREFLIGHT_STATUS=failed'))
  t.ok(body.includes('HIVERELAY_RELEASE_SURFACES_STATUS=blocked'))
  t.ok(body.includes('HIVERELAY_FLEET_ROLLOUT_STATUS=blocked-prerelease-promotion'))
})

test('release distribution env check fails stable releases without every external credential', async (t) => {
  const out = await envFile(t)
  const res = await runCheck([
    '--channel', 'canary',
    '--prerelease', 'false',
    '--github-env', out
  ])

  t.is(res.status, 1)
  t.ok(res.stderr.includes('FLEET_SSH_PRIVATE_KEY'))
  t.ok(res.stderr.includes('UMBREL_STORE_TOKEN'))
  t.ok(res.stderr.includes('UMBREL_OFFICIAL_PR_TOKEN'))
  t.ok(res.stderr.includes('UMBREL_OFFICIAL_FORK'))
  t.ok(res.stderr.includes('NPM_TOKEN'))
  t.ok(res.stderr.includes('STARTOS_DEVELOPER_KEY_PEM'))
  t.ok(res.stderr.includes('STARTOS_REGISTRY_URL'))
  t.ok(res.stderr.includes('Repair path:'))
  t.ok(res.stderr.includes('npm run release:write-secret-template -- --out /private/tmp/hiverelay-release-secrets.env'))
  t.ok(res.stderr.includes('npm run release:check-distribution-env -- --env-file /private/tmp/hiverelay-release-secrets.env --channel canary --prerelease false'))
  t.ok(res.stderr.includes('npm run release:apply-github-secrets -- --repo bigdestiny2/P2P-Hiverelay --env-file /private/tmp/hiverelay-release-secrets.env'))
  t.ok(res.stderr.includes('release-distribution-preflight.yml'))

  const body = await readFile(out, 'utf8')
  t.ok(body.includes('HIVERELAY_RELEASE_DISTRIBUTION_PREFLIGHT_STATUS=failed'))
  t.ok(body.includes('HIVERELAY_RELEASE_SURFACES_STATUS=blocked'))
  t.ok(body.includes('HIVERELAY_FLEET_ROLLOUT_STATUS=missing-secret'))
  t.ok(body.includes('HIVERELAY_STARTOS_REGISTRY_STATUS=missing-secret'))
  t.ok(body.includes('HIVERELAY_NPM_PUBLISH_STATUS=missing-secret'))
  t.ok(body.includes('HIVERELAY_UMBREL_OFFICIAL_PR_STATUS=missing-secret'))
  t.ok(body.includes('HIVERELAY_UMBREL_COMMUNITY_STORE_STATUS=missing-secret'))
})

test('release distribution env check requires stable releases to promote a fleet channel', async (t) => {
  const out = await envFile(t)
  const res = await runCheck([
    '--channel', 'none',
    '--prerelease', 'false',
    '--github-env', out
  ], validDistributionEnv())

  t.is(res.status, 1)
  t.ok(res.stderr.includes('release channel must be canary, stable, or both'))

  const body = await readFile(out, 'utf8')
  t.ok(body.includes('HIVERELAY_FLEET_ROLLOUT_STATUS=missing-channel'))
})

test('release distribution env check passes stable releases with every external credential', async (t) => {
  const out = await envFile(t)
  const res = await runCheck([
    '--channel', 'both',
    '--prerelease', 'false',
    '--github-env', out
  ], validDistributionEnv())

  t.is(res.status, 0)
  t.ok(res.stdout.includes('preflight passed'))

  const body = await readFile(out, 'utf8')
  t.ok(body.includes('HIVERELAY_RELEASE_DISTRIBUTION_PREFLIGHT_STATUS=passed'))
  t.absent(body.includes('blocked'))
  t.absent(body.includes('missing-secret'))
})

test('release distribution env check validates local candidate env files before setting GitHub secrets', async (t) => {
  const out = await envFile(t)
  const candidate = await candidateEnvFile(t, validCandidateEnvBody({
    FLEET_ROLLOUT_TIMEOUT_MS: '1800000',
    HIVERELAY_RELEASE_CHANNEL: 'stable',
    HIVERELAY_RELEASE_PRERELEASE: 'false'
  }))
  const res = await runCheck([
    '--env-file', candidate,
    '--github-env', out
  ])

  t.is(res.status, 0)
  t.ok(res.stdout.includes('preflight passed'))

  const body = await readFile(out, 'utf8')
  t.ok(body.includes('HIVERELAY_RELEASE_EFFECTIVE_CHANNEL=stable'))
  t.ok(body.includes('HIVERELAY_RELEASE_DISTRIBUTION_PREFLIGHT_STATUS=passed'))
  t.absent(body.includes('missing-secret'))
  t.absent(body.includes('invalid-secret'))
})

test('release distribution env check does not satisfy env-file candidates from ambient secrets', async (t) => {
  const candidateBody = validCandidateEnvBody()
    .split('\n')
    .filter(line => !line.startsWith('STARTOS_REGISTRY_URL='))
    .join('\n')
  const candidate = await candidateEnvFile(t, candidateBody)
  const res = await runCheck([
    '--env-file', candidate,
    '--channel', 'both',
    '--prerelease', 'false'
  ], validDistributionEnv())

  t.is(res.status, 1)
  t.ok(res.stderr.includes('STARTOS_REGISTRY_URL'))
  t.absent(res.stderr.includes('registry.start9.com'))
})

test('release distribution env check rejects malformed local candidate env files without echoing values', async (t) => {
  const secretValue = `ghp_${'s'.repeat(36)}`
  const candidate = await candidateEnvFile(t, [
    `UMBREL_STORE_TOKEN=${secretValue}`,
    `UMBREL_STORE_TOKEN=${TEST_GITHUB_TOKEN}`
  ].join('\n'))
  const res = await runCheck([
    '--env-file', candidate,
    '--channel', 'both',
    '--prerelease', 'false'
  ])

  t.is(res.status, 1)
  t.ok(res.stderr.includes('Duplicate env-file variable: UMBREL_STORE_TOKEN'))
  t.absent(res.stderr.includes(secretValue))
  t.absent(res.stdout.includes(secretValue))
})

test('release distribution env check accepts sane explicit fleet rollout timeout', async (t) => {
  const out = await envFile(t)
  const res = await runCheck([
    '--channel', 'both',
    '--prerelease', 'false',
    '--github-env', out
  ], validDistributionEnv({
    FLEET_ROLLOUT_TIMEOUT_MS: '1800000'
  }))

  t.is(res.status, 0)
  t.ok(res.stdout.includes('preflight passed'))

  const body = await readFile(out, 'utf8')
  t.ok(body.includes('HIVERELAY_RELEASE_DISTRIBUTION_PREFLIGHT_STATUS=passed'))
  t.absent(body.includes('invalid-timeout'))
})

test('release distribution env check rejects unsafe fleet rollout timeout before SSH', async (t) => {
  const badTimeouts = [
    '1',
    '14400001',
    '1800000.5',
    ' 1800000',
    '1800000\nHIVERELAY_ATTACKER_VALUE=owned'
  ]

  for (const timeout of badTimeouts) {
    const out = await envFile(t)
    const res = await runCheck([
      '--channel', 'both',
      '--prerelease', 'false',
      '--github-env', out
    ], validDistributionEnv({
      FLEET_ROLLOUT_TIMEOUT_MS: timeout
    }))

    t.is(res.status, 1, `rejects timeout ${JSON.stringify(timeout)}`)
    t.ok(res.stderr.includes('FLEET_ROLLOUT_TIMEOUT_MS must be an integer between 600000 and 14400000 milliseconds'))

    const body = await readFile(out, 'utf8')
    t.ok(body.includes('HIVERELAY_RELEASE_DISTRIBUTION_PREFLIGHT_STATUS=failed'))
    t.ok(body.includes('HIVERELAY_RELEASE_SURFACES_STATUS=blocked'))
    t.ok(body.includes('HIVERELAY_FLEET_ROLLOUT_STATUS=invalid-timeout'))
    t.absent(body.includes('HIVERELAY_ATTACKER_VALUE=owned'))
  }
})

test('release distribution env check rejects placeholder GitHub tokens before checkout or gh calls', async (t) => {
  const out = await envFile(t)
  const res = await runCheck([
    '--channel', 'both',
    '--prerelease', 'false',
    '--github-env', out
  ], validDistributionEnv({
    UMBREL_STORE_TOKEN: 'present',
    UMBREL_OFFICIAL_PR_TOKEN: 'not-a-token'
  }))

  t.is(res.status, 1)
  t.ok(res.stderr.includes('UMBREL_STORE_TOKEN must be a GitHub token without whitespace or control characters'))
  t.ok(res.stderr.includes('UMBREL_OFFICIAL_PR_TOKEN must be a GitHub token without whitespace or control characters'))
  t.ok(res.stderr.includes('Repair path:'))
  t.absent(res.stderr.includes(TEST_GITHUB_TOKEN))
  t.absent(res.stderr.includes(TEST_GITHUB_TOKEN_ALT))

  const body = await readFile(out, 'utf8')
  t.ok(body.includes('HIVERELAY_RELEASE_DISTRIBUTION_PREFLIGHT_STATUS=failed'))
  t.ok(body.includes('HIVERELAY_RELEASE_SURFACES_STATUS=blocked'))
  t.ok(body.includes('HIVERELAY_UMBREL_COMMUNITY_STORE_STATUS=invalid-token'))
  t.ok(body.includes('HIVERELAY_UMBREL_OFFICIAL_PR_STATUS=invalid-token'))
})

test('release distribution env check rejects malformed npm tokens before package publish', async (t) => {
  const out = await envFile(t)
  const res = await runCheck([
    '--channel', 'both',
    '--prerelease', 'false',
    '--github-env', out
  ], validDistributionEnv({
    NPM_TOKEN: 'not a token'
  }))

  t.is(res.status, 1)
  t.ok(res.stderr.includes('NPM_TOKEN must be an npm automation token without whitespace or control characters'))

  const body = await readFile(out, 'utf8')
  t.ok(body.includes('HIVERELAY_RELEASE_DISTRIBUTION_PREFLIGHT_STATUS=failed'))
  t.ok(body.includes('HIVERELAY_RELEASE_SURFACES_STATUS=blocked'))
  t.ok(body.includes('HIVERELAY_NPM_PUBLISH_STATUS=invalid-token'))
})

test('release distribution env check rejects whitespace-padded GitHub tokens before checkout or gh calls', async (t) => {
  const out = await envFile(t)
  const res = await runCheck([
    '--channel', 'both',
    '--prerelease', 'false',
    '--github-env', out
  ], validDistributionEnv({
    UMBREL_STORE_TOKEN: `${TEST_GITHUB_TOKEN}\nHIVERELAY_ATTACKER_VALUE=owned`,
    UMBREL_OFFICIAL_PR_TOKEN: ` ${TEST_GITHUB_TOKEN_ALT}`
  }))

  t.is(res.status, 1)
  t.ok(res.stderr.includes('UMBREL_STORE_TOKEN must be a GitHub token without whitespace or control characters'))
  t.ok(res.stderr.includes('UMBREL_OFFICIAL_PR_TOKEN must be a GitHub token without whitespace or control characters'))

  const body = await readFile(out, 'utf8')
  t.ok(body.includes('HIVERELAY_RELEASE_DISTRIBUTION_PREFLIGHT_STATUS=failed'))
  t.ok(body.includes('HIVERELAY_RELEASE_SURFACES_STATUS=blocked'))
  t.ok(body.includes('HIVERELAY_UMBREL_COMMUNITY_STORE_STATUS=invalid-token'))
  t.ok(body.includes('HIVERELAY_UMBREL_OFFICIAL_PR_STATUS=invalid-token'))
  t.absent(body.includes('HIVERELAY_ATTACKER_VALUE=owned'))
})

test('release distribution env check rejects placeholder private-key secrets before SSH or StartOS publish', async (t) => {
  const out = await envFile(t)
  const res = await runCheck([
    '--channel', 'both',
    '--prerelease', 'false',
    '--github-env', out
  ], validDistributionEnv({
    FLEET_SSH_PRIVATE_KEY: 'present',
    STARTOS_DEVELOPER_KEY_PEM: '-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----'
  }))

  t.is(res.status, 1)
  t.ok(res.stderr.includes('FLEET_SSH_PRIVATE_KEY must be a private key block'))
  t.ok(res.stderr.includes('STARTOS_DEVELOPER_KEY_PEM must be a private key block'))

  const body = await readFile(out, 'utf8')
  t.ok(body.includes('HIVERELAY_RELEASE_DISTRIBUTION_PREFLIGHT_STATUS=failed'))
  t.ok(body.includes('HIVERELAY_RELEASE_SURFACES_STATUS=blocked'))
  t.ok(body.includes('HIVERELAY_FLEET_ROLLOUT_STATUS=invalid-secret'))
  t.ok(body.includes('HIVERELAY_STARTOS_REGISTRY_STATUS=invalid-secret'))
})

test('release distribution env check rejects whitespace-padded private-key secrets before SSH or StartOS publish', async (t) => {
  const out = await envFile(t)
  const res = await runCheck([
    '--channel', 'both',
    '--prerelease', 'false',
    '--github-env', out
  ], validDistributionEnv({
    FLEET_SSH_PRIVATE_KEY: `${TEST_PRIVATE_KEY}\n`,
    STARTOS_DEVELOPER_KEY_PEM: ` ${TEST_STARTOS_PRIVATE_KEY}`
  }))

  t.is(res.status, 1)
  t.ok(res.stderr.includes('FLEET_SSH_PRIVATE_KEY must be a private key block'))
  t.ok(res.stderr.includes('STARTOS_DEVELOPER_KEY_PEM must be a private key block'))

  const body = await readFile(out, 'utf8')
  t.ok(body.includes('HIVERELAY_RELEASE_DISTRIBUTION_PREFLIGHT_STATUS=failed'))
  t.ok(body.includes('HIVERELAY_RELEASE_SURFACES_STATUS=blocked'))
  t.ok(body.includes('HIVERELAY_FLEET_ROLLOUT_STATUS=invalid-secret'))
  t.ok(body.includes('HIVERELAY_STARTOS_REGISTRY_STATUS=invalid-secret'))
})

test('release distribution env check rejects non-https StartOS registry URLs before publish', async (t) => {
  const out = await envFile(t)
  const res = await runCheck([
    '--channel', 'both',
    '--prerelease', 'false',
    '--github-env', out
  ], validDistributionEnv({
    STARTOS_REGISTRY_URL: 'http://registry.example'
  }))

  t.is(res.status, 1)
  t.ok(res.stderr.includes('STARTOS_REGISTRY_URL must be a public https URL without embedded credentials'))

  const body = await readFile(out, 'utf8')
  t.ok(body.includes('HIVERELAY_RELEASE_DISTRIBUTION_PREFLIGHT_STATUS=failed'))
  t.ok(body.includes('HIVERELAY_RELEASE_SURFACES_STATUS=blocked'))
  t.ok(body.includes('HIVERELAY_STARTOS_REGISTRY_STATUS=invalid-registry-url'))
})

test('release distribution env check rejects malformed official Umbrel fork names before checkout', async (t) => {
  const out = await envFile(t)
  const res = await runCheck([
    '--channel', 'both',
    '--prerelease', 'false',
    '--github-env', out
  ], validDistributionEnv({
    UMBREL_OFFICIAL_FORK: 'not a repo'
  }))

  t.is(res.status, 1)
  t.ok(res.stderr.includes('UMBREL_OFFICIAL_FORK must be a GitHub owner/umbrel-apps fork slug'))

  const body = await readFile(out, 'utf8')
  t.ok(body.includes('HIVERELAY_RELEASE_DISTRIBUTION_PREFLIGHT_STATUS=failed'))
  t.ok(body.includes('HIVERELAY_RELEASE_SURFACES_STATUS=blocked'))
  t.ok(body.includes('HIVERELAY_UMBREL_OFFICIAL_PR_STATUS=invalid-fork'))
})

test('release distribution env check rejects renamed or option-like official Umbrel forks before checkout', async (t) => {
  const badForks = [
    'bigdestiny2/not-umbrel-apps',
    '-oProxyCommand/umbrel-apps',
    'bad_owner/umbrel-apps',
    'bad.owner/umbrel-apps',
    'getumbrel/umbrel-apps',
    'GetUmbrel/umbrel-apps'
  ]

  for (const fork of badForks) {
    const out = await envFile(t)
    const res = await runCheck([
      '--channel', 'both',
      '--prerelease', 'false',
      '--github-env', out
    ], validDistributionEnv({
      UMBREL_OFFICIAL_FORK: fork
    }))

    t.is(res.status, 1, `rejects ${fork}`)
    t.ok(res.stderr.includes('UMBREL_OFFICIAL_FORK must be a GitHub owner/umbrel-apps fork slug'))

    const body = await readFile(out, 'utf8')
    t.ok(body.includes('HIVERELAY_RELEASE_DISTRIBUTION_PREFLIGHT_STATUS=failed'))
    t.ok(body.includes('HIVERELAY_RELEASE_SURFACES_STATUS=blocked'))
    t.ok(body.includes('HIVERELAY_UMBREL_OFFICIAL_PR_STATUS=invalid-fork'))
  }
})

test('release distribution env check rejects credentialed StartOS registry URLs before publish', async (t) => {
  const out = await envFile(t)
  const res = await runCheck([
    '--channel', 'both',
    '--prerelease', 'false',
    '--github-env', out
  ], validDistributionEnv({
    STARTOS_REGISTRY_URL: 'https://user:pass@registry.example'
  }))

  t.is(res.status, 1)
  t.ok(res.stderr.includes('STARTOS_REGISTRY_URL must be a public https URL without embedded credentials'))

  const body = await readFile(out, 'utf8')
  t.ok(body.includes('HIVERELAY_RELEASE_DISTRIBUTION_PREFLIGHT_STATUS=failed'))
  t.ok(body.includes('HIVERELAY_RELEASE_SURFACES_STATUS=blocked'))
  t.ok(body.includes('HIVERELAY_STARTOS_REGISTRY_STATUS=invalid-registry-url'))
})

test('release distribution env check rejects control characters before GitHub env writes', async (t) => {
  const out = await envFile(t)
  const res = await runCheck([
    '--channel', 'both',
    '--prerelease', 'false',
    '--github-env', out
  ], validDistributionEnv({
    STARTOS_REGISTRY_URL: 'https://registry.start9.com\nmalicious.example'
  }))

  t.is(res.status, 1)
  t.ok(res.stderr.includes('STARTOS_REGISTRY_URL must be a public https URL without embedded credentials'))

  const body = await readFile(out, 'utf8')
  t.ok(body.includes('HIVERELAY_RELEASE_DISTRIBUTION_PREFLIGHT_STATUS=failed'))
  t.ok(body.includes('HIVERELAY_RELEASE_SURFACES_STATUS=blocked'))
  t.ok(body.includes('HIVERELAY_STARTOS_REGISTRY_STATUS=invalid-registry-url'))
  t.absent(body.includes('malicious.example'))
})

test('release distribution env check defaults full releases to whole-fleet promotion', async (t) => {
  const out = await envFile(t)
  const res = await runCheck([
    '--prerelease', 'false',
    '--github-env', out
  ], validDistributionEnv())

  t.is(res.status, 0)
  t.ok(res.stdout.includes('preflight passed'))

  const body = await readFile(out, 'utf8')
  t.ok(body.includes('HIVERELAY_RELEASE_EFFECTIVE_CHANNEL=both'))
  t.ok(body.includes('HIVERELAY_RELEASE_DISTRIBUTION_PREFLIGHT_STATUS=passed'))
  t.absent(body.includes('HIVERELAY_FLEET_ROLLOUT_STATUS=missing-channel'))
  t.absent(body.includes('blocked'))
})

test('release distribution env check rejects placeholder StartOS registry hosts before publish', async (t) => {
  const out = await envFile(t)
  const res = await runCheck([
    '--channel', 'both',
    '--prerelease', 'false',
    '--github-env', out
  ], validDistributionEnv({
    STARTOS_REGISTRY_URL: 'https://registry.example/startos'
  }))

  t.is(res.status, 1)
  t.ok(res.stderr.includes('reserved/local hostnames'))

  const body = await readFile(out, 'utf8')
  t.ok(body.includes('HIVERELAY_RELEASE_DISTRIBUTION_PREFLIGHT_STATUS=failed'))
  t.ok(body.includes('HIVERELAY_RELEASE_SURFACES_STATUS=blocked'))
  t.ok(body.includes('HIVERELAY_STARTOS_REGISTRY_STATUS=invalid-registry-url'))
})
