import test from 'brittle'
import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

const RESOLVER = path.join(process.cwd(), 'scripts/resolve-public-hive-gateway-release.mjs')
const MANIFEST_PATH = 'fleet/public-hive-gateway-release.json'
const APP_KEY = 'aa'.repeat(32)
const SUFFIX = 'hive-canary.operator.example'
const LABEL = z32(Buffer.from(APP_KEY, 'hex'))
const FINGERPRINT = Array(32).fill('AA').join(':')

test('tagged enabled public gateway manifests force every requested release channel to none', async (t) => {
  const repo = await gitRepo(t)
  const raw = JSON.stringify(manifest('v1.2.3'), null, 2) + '\n'
  await commitManifest(repo, raw, 'enabled gateway')
  await git(repo, ['tag', 'v1.2.3'])

  // The tag, not a later mutable worktree value, is authoritative.
  await writeFile(path.join(repo, MANIFEST_PATH), JSON.stringify({
    schema: 'hiverelay-public-gateway-release-v1',
    enabled: false
  }) + '\n')

  for (const requested of ['canary', 'stable', 'both', 'none']) {
    const result = await resolve(repo, 'v1.2.3', 'v1.2.3', requested)
    t.is(result.status, 0)
    const body = JSON.parse(result.stdout)
    t.is(body.status, 'enabled')
    t.is(body.enabled, true)
    t.is(body.requestedChannel, requested)
    t.is(body.effectiveChannel, 'none')
    t.is(body.manifestPath, MANIFEST_PATH)
    t.is(body.manifestSha256, createHash('sha256').update(raw).digest('hex'))
    t.is(body.releaseTarget, 'v1.2.3')
    t.is(body.admissionProfile, 'blind-substrate-public-v1')
    t.is(body.cohortSize, 1)
    t.ok(/^[a-f0-9]{40}$/.test(body.commitSha))
  }
})

test('missing and explicitly disabled tagged manifests retain ordinary channel behavior', async (t) => {
  const repo = await gitRepo(t)
  await writeFile(path.join(repo, 'README.md'), 'ordinary release\n')
  await git(repo, ['add', 'README.md'])
  await git(repo, ['commit', '-m', 'ordinary release'])
  await git(repo, ['tag', 'v1.2.2'])

  const missing = await resolve(repo, 'v1.2.2', 'v1.2.2', 'both')
  t.is(missing.status, 0)
  t.alike(pickResolution(JSON.parse(missing.stdout)), {
    status: 'missing',
    enabled: false,
    requestedChannel: 'both',
    effectiveChannel: 'both',
    manifestSha256: ''
  })

  const disabledRaw = JSON.stringify({
    schema: 'hiverelay-public-gateway-release-v1',
    enabled: false
  }, null, 2) + '\n'
  await commitManifest(repo, disabledRaw, 'disabled gateway')
  await git(repo, ['tag', 'v1.2.3'])
  const disabled = await resolve(repo, 'v1.2.3', 'v1.2.3', 'stable')
  t.is(disabled.status, 0)
  t.alike(pickResolution(JSON.parse(disabled.stdout)), {
    status: 'disabled',
    enabled: false,
    requestedChannel: 'stable',
    effectiveChannel: 'stable',
    manifestSha256: createHash('sha256').update(disabledRaw).digest('hex')
  })
})

test('tagged public gateway resolver fails closed on hostile or mismatched enabled manifests', async (t) => {
  const repo = await gitRepo(t)
  const cases = [
    ['v2.0.0', '{not json\n', 'valid JSON'],
    ['v2.0.1', JSON.stringify(manifest('v9.9.9')) + '\n', 'must target v2.0.1'],
    ['v2.0.2', JSON.stringify({ ...manifest('v2.0.2'), admissionProfile: 'transitional-allowlist' }) + '\n', 'frozen admissionProfile'],
    ['v2.0.3', JSON.stringify({ ...manifest('v2.0.3'), unexpected: true }) + '\n', 'unsupported fields'],
    ['v2.0.4', JSON.stringify({
      ...manifest('v2.0.4'),
      cohort: [{ ...manifest('v2.0.4').cohort[0], channel: 'stable' }]
    }) + '\n', 'at least one canary'],
    ['v2.0.5', JSON.stringify({
      ...manifest('v2.0.5'),
      admissionProfile: 'blind-$(untrusted-shell)'
    }) + '\n', 'frozen admissionProfile']
  ]

  for (const [tag, raw, message] of cases) {
    await commitManifest(repo, raw, `hostile ${tag}`)
    await git(repo, ['tag', tag])
    const result = await resolve(repo, tag, tag, 'both')
    t.is(result.status, 1)
    t.is(result.stdout, '')
    t.ok(result.stderr.includes(message), `${tag} reports ${message}`)
  }

  const unknown = await run(process.execPath, [
    RESOLVER,
    '--repo', repo,
    '--ref', 'v2.0.4',
    '--release-target', 'v2.0.4',
    '--requested-channel', 'both',
    '--surprise', 'true'
  ])
  t.is(unknown.status, 1)
  t.ok(unknown.stderr.includes('unknown argument'))
})

test('release workflow resolves the tagged gateway policy before every irreversible publication', async (t) => {
  const workflow = await readFile('.github/workflows/release-surfaces.yml', 'utf8')
  const release = await readFile('scripts/release.sh', 'utf8')
  const resolver = workflow.indexOf('node hiverelay/scripts/resolve-public-hive-gateway-release.mjs')

  t.ok(resolver > 0)
  t.ok(resolver < workflow.indexOf('- name: Ensure GitHub Release exists'))
  t.ok(resolver < workflow.indexOf('docker buildx build'))
  t.ok(resolver < workflow.indexOf('npm publish "./$pkg"'))
  t.ok(workflow.includes('channel="$resolved_channel"'))
  t.ok(workflow.includes('--public-gateway-release "$' + '{{ steps.rel.outputs.public_gateway_enabled }}"'))
  t.ok(workflow.includes('HIVERELAY_FLEET_ROLLOUT_STATUS=$fleet_rollout_status'))
  t.ok(workflow.includes('fleet_rollout_status=deferred-gateway-canary-gated'))
  t.ok(workflow.includes('Release tag moved after public gateway policy resolution.'))

  const localResolver = release.indexOf('scripts/resolve-public-hive-gateway-release.mjs')
  const tagPush = release.indexOf('push origin "$version"')
  const githubRelease = release.indexOf('gh release create "$version"')
  t.ok(localResolver > 0)
  t.ok(localResolver < tagPush)
  t.ok(tagPush < githubRelease)
  t.ok(release.includes('GitHub Release creation is delegated to the manifest-gated release workflow'))
  t.ok(release.includes('--promote-canary is disabled for public gateway releases'))
})

async function gitRepo (t) {
  const repo = await mkdtemp(path.join(tmpdir(), 'hiverelay-gateway-release-'))
  t.teardown(async () => {
    await rm(repo, { recursive: true, force: true })
  })
  await git(repo, ['init', '-q'])
  await git(repo, ['config', 'user.name', 'Release Test'])
  await git(repo, ['config', 'user.email', 'release-test@example.test'])
  return repo
}

async function commitManifest (repo, raw, message) {
  await mkdir(path.join(repo, 'fleet'), { recursive: true })
  await writeFile(path.join(repo, MANIFEST_PATH), raw)
  await git(repo, ['add', MANIFEST_PATH])
  await git(repo, ['commit', '-m', message])
}

function resolve (repo, ref, releaseTarget, requestedChannel) {
  return run(process.execPath, [
    RESOLVER,
    '--repo', repo,
    '--ref', ref,
    '--release-target', releaseTarget,
    '--requested-channel', requestedChannel
  ])
}

function run (file, args) {
  return new Promise((resolve) => {
    execFile(file, args, {
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
}

function git (repo, args) {
  return new Promise((resolve, reject) => {
    execFile('git', args, {
      cwd: repo,
      env: { PATH: process.env.PATH || '' },
      timeout: 10000
    }, (err, stdout, stderr) => {
      if (err) {
        err.stdout = stdout
        err.stderr = stderr
        reject(err)
      } else {
        resolve(stdout)
      }
    })
  })
}

function pickResolution (body) {
  return {
    status: body.status,
    enabled: body.enabled,
    requestedChannel: body.requestedChannel,
    effectiveChannel: body.effectiveChannel,
    manifestSha256: body.manifestSha256
  }
}

function manifest (releaseTarget) {
  return {
    schema: 'hiverelay-public-gateway-release-v1',
    enabled: true,
    releaseTarget,
    admissionProfile: 'blind-substrate-public-v1',
    observationWindowMs: 24 * 60 * 60 * 1000,
    maxProbeGapMs: 20 * 60 * 1000,
    cohort: [{
      relay: 'canary-1',
      channel: 'canary',
      suffix: SUFFIX,
      origin: `https://${LABEL}.${SUFFIX}/`,
      connectAddress: '127.0.0.1',
      appKey: APP_KEY,
      path: '/index.html',
      contentSha256: 'bb'.repeat(32),
      driveVersion: '7',
      peerFingerprint256: FINGERPRINT,
      nginxConfigSha256: 'cc'.repeat(32),
      deploymentProfile: 'public-t1-gateway',
      operatorContractSha256: 'dd'.repeat(32)
    }]
  }
}

function z32 (bytes) {
  const alphabet = 'ybndrfg8ejkmcpqxot1uwisza345h769'
  let output = ''
  let accumulator = 0
  let bits = 0
  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte
    bits += 8
    while (bits >= 5) {
      bits -= 5
      output += alphabet[(accumulator >>> bits) & 31]
      accumulator &= bits === 0 ? 0 : (1 << bits) - 1
    }
  }
  if (bits > 0) output += alphabet[(accumulator << (5 - bits)) & 31]
  return output
}
