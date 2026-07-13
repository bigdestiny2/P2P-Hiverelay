import test from 'brittle'
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync
} from 'node:fs'
import { spawnSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import path from 'node:path'

const repoRoot = path.resolve('.')
const installer = path.join(repoRoot, 'fleet', 'install-updater.sh')
const launcher = path.join(repoRoot, 'fleet', 'updater-launcher.sh')
const quarantineHelper = path.join(repoRoot, 'fleet', 'quarantine-public-gateway.sh')

function have (bin) {
  return spawnSync('sh', ['-c', `command -v ${bin}`], { stdio: 'ignore' }).status === 0
}

function runInstaller (destdir, channel = 'canary', relay = 'utah') {
  return spawnSync('bash', [installer, channel, relay], {
    encoding: 'utf8',
    env: {
      ...process.env,
      DESTDIR: destdir,
      HIVERELAY_REPO_DIR: repoRoot
    }
  })
}

test('updater installer is idempotent and preserves its root-only environment', (t) => {
  const root = mkdtempSync(path.join(tmpdir(), 'hr-updater-install-'))
  t.teardown(() => rmSync(root, { recursive: true, force: true }))

  const envDir = path.join(root, 'etc', 'hiverelay')
  const envFile = path.join(envDir, 'hiverelay-updater.env')
  const original = [
    'HIVERELAY_PUBLIC_GATEWAY_PROBE_CONFIG=/root/.hiverelay/config.json',
    'HIVERELAY_PUBLIC_GATEWAY_PROBE_NGINX_CONFIG=/etc/nginx/conf.d/hiverelay-public-apps.conf',
    'HIVERELAY_PUBLIC_GATEWAY_PROBE_EVIDENCE=/root/.hiverelay/evidence.json',
    'HIVERELAY_PUBLIC_GATEWAY_OPS_CERTIFICATE=/etc/letsencrypt/live/hive/fullchain.pem',
    'HIVERELAY_PUBLIC_GATEWAY_OPS_CERTIFICATE_KEY=/etc/letsencrypt/live/hive/privkey.pem',
    'HIVERELAY_PUBLIC_GATEWAY_OPS_CERTIFICATE_ROOT=/etc/letsencrypt',
    'HIVERELAY_PUBLIC_GATEWAY_OPS_SS_BINARY=/usr/sbin/ss',
    'HIVERELAY_PUBLIC_GATEWAY_OPS_EVIDENCE=/root/.hiverelay/ops-evidence.json',
    ''
  ].join('\n')
  mkdirSync(envDir, { recursive: true })
  writeFileSync(envFile, original)
  chmodSync(envFile, 0o600)

  const first = runInstaller(root, 'canary', 'utah')
  t.is(first.status, 0, first.stderr || first.stdout)
  t.is(readFileSync(envFile, 'utf8'), original, 'install preserves every operator setting byte')
  t.is(statSync(envFile).mode & 0o777, 0o600, 'environment is root-only')
  t.is(
    readFileSync(path.join(root, 'usr', 'local', 'bin', 'hiverelay-updater'), 'utf8'),
    readFileSync(launcher, 'utf8'),
    'installed entry point is the stable trust-checking launcher'
  )
  t.is(
    readFileSync(path.join(root, 'usr', 'local', 'sbin', 'hiverelay-quarantine-public-gateway'), 'utf8'),
    readFileSync(quarantineHelper, 'utf8'),
    'installer deploys the narrow public-edge quarantine helper'
  )
  t.is(
    statSync(path.join(root, 'usr', 'local', 'sbin', 'hiverelay-quarantine-public-gateway')).mode & 0o777,
    0o755
  )
  t.alike(
    readFileSync(path.join(root, 'etc', 'hiverelay-updater.conf'), 'utf8').trim().split('\n'),
    ['CHANNEL=canary', 'RELAY_NAME=utah', `REPO_DIR=${repoRoot}`]
  )

  const second = runInstaller(root, 'stable', 'sing-1')
  t.is(second.status, 0, second.stderr || second.stdout)
  t.is(readFileSync(envFile, 'utf8'), original, 'reinstall still preserves environment bytes')
  t.ok(readFileSync(path.join(root, 'etc', 'hiverelay-updater.conf'), 'utf8').startsWith('CHANNEL=stable\n'))
  t.ok(readFileSync(path.join(root, 'etc', 'hiverelay-updater.conf'), 'utf8').includes('RELAY_NAME=sing-1\n'))
  t.ok(second.stdout.includes('skipped systemctl'), 'DESTDIR regression path never calls host systemd')
})

test('updater installer requires a bounded canonical relay identity', (t) => {
  const root = mkdtempSync(path.join(tmpdir(), 'hr-updater-install-identity-'))
  t.teardown(() => rmSync(root, { recursive: true, force: true }))

  const missing = runInstaller(root, 'stable', '')
  t.not(missing.status, 0)
  t.ok(missing.stderr.includes('Invalid or missing relay name'))
  t.absent(existsSync(path.join(root, 'etc', 'hiverelay-updater.conf')))

  const malformed = runInstaller(root, 'stable', 'bad relay')
  t.not(malformed.status, 0)
  t.ok(malformed.stderr.includes('Invalid or missing relay name'))
  t.absent(existsSync(path.join(root, 'etc', 'hiverelay-updater.conf')))

  const wrongChannel = runInstaller(root, 'stable', 'utah')
  t.not(wrongChannel.status, 0)
  t.ok(wrongChannel.stderr.includes("not uniquely assigned to channel 'stable'"))
  t.absent(existsSync(path.join(root, 'etc', 'hiverelay-updater.conf')))
})

test('updater installer quarantines an environment symlink without touching its target', (t) => {
  const root = mkdtempSync(path.join(tmpdir(), 'hr-updater-install-link-'))
  t.teardown(() => rmSync(root, { recursive: true, force: true }))

  const envDir = path.join(root, 'etc', 'hiverelay')
  const envFile = path.join(envDir, 'hiverelay-updater.env')
  const sentinel = path.join(root, 'sentinel')
  mkdirSync(envDir, { recursive: true })
  writeFileSync(sentinel, 'do-not-touch\n')
  symlinkSync(sentinel, envFile)

  const result = runInstaller(root)
  t.is(result.status, 0, result.stderr || result.stdout)
  t.ok(result.stderr.includes('quarantined unsafe updater environment path'))
  t.is(readFileSync(sentinel, 'utf8'), 'do-not-touch\n')
  t.is(readFileSync(envFile, 'utf8'), '')
  t.is(statSync(envFile).mode & 0o777, 0o600)
})

const canSign = have('git') && have('ssh-keygen')

test('updater launcher runs exact trusted-tag code and rejects checkout drift', { skip: !canSign }, (t) => {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), 'hr-updater-launcher-')))
  t.teardown(() => rmSync(root, { recursive: true, force: true }))

  const repo = path.join(root, 'repo')
  const fleet = path.join(repo, 'fleet')
  const key = path.join(root, 'release-key')
  const allowedSigners = path.join(root, 'allowed-signers')
  const updaterConf = path.join(root, 'hiverelay-updater.conf')
  const updaterEnv = path.join(root, 'hiverelay-updater.env')
  const marker = path.join(root, 'marker')
  mkdirSync(fleet, { recursive: true })
  writeFileSync(path.join(fleet, 'updater.sh'), '#!/bin/bash\nprintf \'%s\\n\' "$*" > "$MARKER"\n')

  const command = (bin, args, opts = {}) => {
    const result = spawnSync(bin, args, { encoding: 'utf8', ...opts })
    if (result.status !== 0 && opts.allowFail !== true) {
      t.fail(`${bin} ${args.join(' ')} failed: ${result.stderr || result.stdout}`)
    }
    return result
  }
  const git = (args, opts) => command('git', ['-C', repo, ...args], opts)

  command('ssh-keygen', ['-t', 'ed25519', '-f', key, '-N', '', '-q', '-C', 'release@hiverelay'])
  writeFileSync(allowedSigners, `release@hiverelay ${readFileSync(key + '.pub', 'utf8').trim()}\n`)
  writeFileSync(updaterConf, `REPO_DIR=${repo}\n`)
  writeFileSync(updaterEnv, '')
  chmodSync(updaterEnv, 0o600)
  command('git', ['init', '-q', repo])
  git(['config', 'user.name', 'tester'])
  git(['config', 'user.email', 'release@hiverelay'])
  git(['config', 'gpg.format', 'ssh'])
  git(['add', 'fleet/updater.sh'])
  git(['commit', '-qm', 'trusted updater'])
  git(['-c', `user.signingkey=${key}.pub`, 'tag', '-s', '-m', 'release', 'v1.2.3'])

  const run = (extraEnv = {}) => spawnSync('bash', [launcher, 'alpha', 'beta'], {
    encoding: 'utf8',
    env: {
      ...process.env,
      HIVERELAY_REPO_DIR: repo,
      HIVERELAY_ALLOWED_SIGNERS: allowedSigners,
      HIVERELAY_UPDATER_CONF: updaterConf,
      HIVERELAY_UPDATER_ENV_TRUST_FILE: updaterEnv,
      MARKER: marker,
      ...extraEnv
    }
  })

  const trusted = run()
  t.is(trusted.status, 0, trusted.stderr || trusted.stdout)
  t.is(readFileSync(marker, 'utf8'), 'alpha beta\n')

  const ancestorLink = path.join(root, 'repo-ancestor-link')
  symlinkSync(root, ancestorLink)
  const linkedAncestor = run({ HIVERELAY_REPO_DIR: path.join(ancestorLink, 'repo') })
  t.not(linkedAncestor.status, 0)
  t.ok(linkedAncestor.stderr.includes('path must be canonical and contain no symlink ancestors'))

  for (const line of [
    'HIVERELAY_HEALTH_TIMEOUT=1+2',
    'HIVERELAY_SERVICE=--no-block',
    'HIVERELAY_API=http://attacker.invalid:9100',
    'HIVERELAY_API=http://127.0.0.1:9100/path',
    'HIVERELAY_CONTROL_BRANCH=--upload-pack',
    'HIVERELAY_CONTROL_STATE=relative/state.json',
    'HIVERELAY_REQUIRE_SIGNED_TAGS=true',
    'HIVERELAY_PUBLIC_GATEWAY_PROBE_PUBLIC_SUFFIX_READY=2',
    'HIVERELAY_PUBLIC_GATEWAY_PROBE_CONFIG=/safe/../swap.json',
    'HIVERELAY_UNKNOWN_ROOT_OPTION=value'
  ]) {
    writeFileSync(updaterEnv, `${line}\n`)
    chmodSync(updaterEnv, 0o600)
    const hostile = run()
    t.not(hostile.status, 0, line)
    t.ok(hostile.stderr.includes('not canonical or in range') || hostile.stderr.includes('is not allowed'), line)
  }
  writeFileSync(updaterEnv, '')
  chmodSync(updaterEnv, 0o600)

  rmSync(marker)
  writeFileSync(path.join(fleet, 'updater.sh'), '#!/bin/bash\nprintf attack > "$MARKER"\n')
  const drifted = run()
  t.not(drifted.status, 0)
  t.ok(drifted.stderr.includes('differs from the signed checkout'))
  t.absent(existsSync(marker), 'modified updater is never executed')

  const missingTrust = run({ HIVERELAY_ALLOWED_SIGNERS: path.join(root, 'missing') })
  t.not(missingTrust.status, 0)

  chmodSync(root, 0o777)
  const unsafeAncestor = run()
  t.not(unsafeAncestor.status, 0)
  t.ok(unsafeAncestor.stderr.includes('parent must not be group/world writable'))
  chmodSync(root, 0o700)
})
