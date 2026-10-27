import test from 'brittle'
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
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

// The v0.24 installer must put the trust-checking launcher at
// /usr/local/bin/hiverelay-updater (not a frozen updater.sh copy), bind the
// channel + relay name + repo, and provision the root-only EnvironmentFile the
// launcher refuses to run without. Rollout checks compare the installed
// launcher and units byte-for-byte against the release tree.

const repoRoot = path.resolve('.')
const installer = path.join(repoRoot, 'fleet', 'install-updater.sh')
const launcher = path.join(repoRoot, 'fleet', 'updater-launcher.sh')

function runInstaller (destdir, args = ['canary', 'utah-2gb-a'], extraEnv = {}) {
  return spawnSync('bash', [installer, ...args], {
    encoding: 'utf8',
    env: {
      ...process.env,
      DESTDIR: destdir,
      HIVERELAY_REPO_DIR: repoRoot,
      HIVERELAY_NODE_BIN: process.execPath,
      ...extraEnv
    }
  })
}

function tempRoot (t) {
  const root = mkdtempSync(path.join(tmpdir(), 'hr-updater-install-'))
  t.teardown(() => rmSync(root, { recursive: true, force: true }))
  return root
}

const mode = (p) => (statSync(p).mode & 0o777)

test('installer and launcher parse as bash', (t) => {
  for (const file of [installer, launcher]) {
    const r = spawnSync('bash', ['-n', file], { encoding: 'utf8' })
    t.is(r.status, 0, `${path.basename(file)} parses (${r.stderr.trim()})`)
  }
})

test('installer installs the launcher, units, binding and root-only env file', (t) => {
  const root = tempRoot(t)
  const r = runInstaller(root)
  t.is(r.status, 0, `installer exits 0 (${r.stderr.trim()})`)

  const bin = path.join(root, 'usr', 'local', 'bin', 'hiverelay-updater')
  t.alike(readFileSync(bin), readFileSync(launcher), 'installed binary is the launcher, byte-for-byte')
  t.unlike(readFileSync(bin), readFileSync(path.join(repoRoot, 'fleet', 'updater.sh')), 'not the updater itself')
  t.is(mode(bin), 0o755, 'launcher is 0755')

  for (const unit of ['hiverelay-updater.service', 'hiverelay-updater.timer']) {
    const installed = path.join(root, 'etc', 'systemd', 'system', unit)
    t.alike(readFileSync(installed), readFileSync(path.join(repoRoot, 'fleet', unit)), `${unit} matches the release tree`)
  }

  const conf = readFileSync(path.join(root, 'etc', 'hiverelay-updater.conf'), 'utf8')
  t.is(conf, `CHANNEL=canary\nRELAY_NAME=utah-2gb-a\nREPO_DIR=${repoRoot}\n`, 'config binds channel, relay and repo')

  const envDir = path.join(root, 'etc', 'hiverelay')
  const envFile = path.join(envDir, 'hiverelay-updater.env')
  t.is(mode(envDir), 0o700, 'env directory is 0700')
  t.is(mode(envFile), 0o600, 'env file is 0600')
  t.is(readFileSync(envFile, 'utf8'), '', 'fresh env file is empty')
})

test('reinstall is idempotent and preserves a safe env file', (t) => {
  const root = tempRoot(t)
  const envDir = path.join(root, 'etc', 'hiverelay')
  const envFile = path.join(envDir, 'hiverelay-updater.env')
  mkdirSync(envDir, { recursive: true })
  chmodSync(envDir, 0o700)
  writeFileSync(envFile, 'HIVERELAY_HEALTH_TIMEOUT=60\n')
  chmodSync(envFile, 0o600)

  t.is(runInstaller(root).status, 0, 'first install')
  t.is(runInstaller(root, ['stable', 'sing-2']).status, 0, 'second install')
  t.is(readFileSync(envFile, 'utf8'), 'HIVERELAY_HEALTH_TIMEOUT=60\n', 'operator env preserved')
  t.is(mode(envFile), 0o600, 'still 0600')
  t.is(readFileSync(path.join(root, 'etc', 'hiverelay-updater.conf'), 'utf8'),
    `CHANNEL=stable\nRELAY_NAME=sing-2\nREPO_DIR=${repoRoot}\n`, 'config rebinds on reinstall')
  t.is(readdirSync(envDir).filter((f) => f.includes('unsafe')).length, 0, 'nothing quarantined')
})

test('unsafe env paths are quarantined, never trusted', (t) => {
  const root = tempRoot(t)
  const envDir = path.join(root, 'etc', 'hiverelay')
  const envFile = path.join(envDir, 'hiverelay-updater.env')
  mkdirSync(envDir, { recursive: true })
  chmodSync(envDir, 0o700)
  writeFileSync(envFile, 'HIVERELAY_HEALTH_TIMEOUT=60\n')
  chmodSync(envFile, 0o644)

  const r = runInstaller(root)
  t.is(r.status, 0, 'installer exits 0')
  t.ok(r.stderr.includes('quarantined unsafe updater environment path'), 'warns about the quarantine')
  t.is(readFileSync(envFile, 'utf8'), '', 'world-readable env content is not carried over')
  t.is(mode(envFile), 0o600, 'replacement is 0600')
  t.is(readdirSync(envDir).filter((f) => f.startsWith('hiverelay-updater.env.unsafe.')).length, 1, 'original kept aside')

  const target = path.join(root, 'elsewhere')
  writeFileSync(target, 'HIVERELAY_HEALTH_TIMEOUT=60\n')
  rmSync(envFile)
  symlinkSync(target, envFile)
  t.is(runInstaller(root).status, 0, 'installer exits 0 with a symlinked env file')
  t.absent(lstatSync(envFile).isSymbolicLink(), 'symlink replaced by a regular file')
  t.is(readFileSync(target, 'utf8'), 'HIVERELAY_HEALTH_TIMEOUT=60\n', 'symlink target untouched')
})

test('invalid inputs fail before anything is installed', (t) => {
  const cases = [
    { label: 'missing relay name', args: ['canary'] },
    { label: 'invalid relay name', args: ['canary', '../etc'] },
    { label: 'invalid channel', args: ['can ary', 'utah-2gb-a'] },
    { label: 'relative repo dir', args: ['canary', 'utah-2gb-a'], env: { HIVERELAY_REPO_DIR: 'hiverelay' } },
    { label: 'relative node binary', args: ['canary', 'utah-2gb-a'], env: { HIVERELAY_NODE_BIN: 'node' } }
  ]
  for (const c of cases) {
    const root = tempRoot(t)
    const r = runInstaller(root, c.args, c.env)
    t.not(r.status, 0, `${c.label} is rejected`)
    t.absent(existsSync(path.join(root, 'usr', 'local', 'bin', 'hiverelay-updater')), `${c.label}: no launcher installed`)
    t.absent(existsSync(path.join(root, 'etc', 'hiverelay-updater.conf')), `${c.label}: no config written`)
  }
  const r = spawnSync('bash', [installer, 'canary', 'utah-2gb-a'], {
    encoding: 'utf8',
    env: { ...process.env, DESTDIR: 'relative', HIVERELAY_REPO_DIR: repoRoot, HIVERELAY_NODE_BIN: process.execPath }
  })
  t.not(r.status, 0, 'relative DESTDIR is rejected')
})

const canSign = spawnSync('sh', ['-c', 'command -v ssh-keygen && test -x /usr/bin/git'], { stdio: 'ignore' }).status === 0

test('launcher runs this release\'s updater.sh only from a trusted signed checkout', { skip: !canSign }, (t) => {
  // Same canonical, non-world-writable staging as the fail-closed case below.
  const work = realpathSync(mkdtempSync(path.join(repoRoot, '.tmp-launcher-')))
  t.teardown(() => rmSync(work, { recursive: true, force: true }))
  chmodSync(work, 0o700)
  const run = (cmd, args, opts = {}) => {
    const r = spawnSync(cmd, args, { encoding: 'utf8', ...opts })
    if (r.status !== 0) throw new Error(`${cmd} ${args.join(' ')} failed: ${r.stderr}`)
    return r
  }
  const key = path.join(work, 'release_key')
  run('ssh-keygen', ['-t', 'ed25519', '-f', key, '-N', '', '-q', '-C', 'release@hiverelay'])
  const allowedSigners = path.join(work, 'allowed_signers')
  writeFileSync(allowedSigners, `release@hiverelay ${readFileSync(key + '.pub', 'utf8').trim()}\n`)
  chmodSync(allowedSigners, 0o644)

  const repo = path.join(work, 'hiverelay')
  mkdirSync(path.join(repo, 'fleet'), { recursive: true })
  writeFileSync(path.join(repo, 'fleet', 'updater.sh'), readFileSync(path.join(repoRoot, 'fleet', 'updater.sh')))
  const git = (args) => run('/usr/bin/git', ['-C', repo, ...args])
  git(['init', '-q'])
  git(['config', 'user.name', 'tester'])
  git(['config', 'user.email', 'release@hiverelay'])
  git(['config', 'gpg.format', 'ssh'])
  git(['add', 'fleet/updater.sh'])
  git(['commit', '-qm', 'release'])
  git(['-c', `user.signingkey=${key}.pub`, 'tag', '-s', '-m', 'v1.0.0', 'v1.0.0'])

  const conf = path.join(work, 'hiverelay-updater.conf')
  writeFileSync(conf, `CHANNEL=canary\nRELAY_NAME=utah-2gb-a\nREPO_DIR=${repo}\n`)
  chmodSync(conf, 0o644)
  const envFile = path.join(work, 'hiverelay-updater.env')
  writeFileSync(envFile, '')
  chmodSync(envFile, 0o600)

  const launch = (args) => spawnSync('bash', [launcher, ...args], {
    encoding: 'utf8',
    env: {
      ...process.env,
      HIVERELAY_UPDATER_CONF: conf,
      HIVERELAY_UPDATER_ENV_TRUST_FILE: envFile,
      HIVERELAY_ALLOWED_SIGNERS: allowedSigners,
      HIVERELAY_REPO_DIR: repo
    }
  })

  const ok = launch(['--verify-only', 'v1.0.0'])
  t.is(ok.status, 0, `signed HEAD: launcher hands off to updater.sh --verify-only (${ok.stderr.trim().split('\n').pop()})`)

  writeFileSync(path.join(repo, 'fleet', 'updater.sh'), readFileSync(path.join(repoRoot, 'fleet', 'updater.sh'), 'utf8') + '\n# tampered\n')
  const tampered = launch(['--verify-only', 'v1.0.0'])
  t.not(tampered.status, 0, 'a working-tree edit to updater.sh is refused')
  t.ok(tampered.stderr.includes('differs from the signed checkout'), 'refusal names the tampered updater')
  git(['checkout', '-q', '--', 'fleet/updater.sh'])

  writeFileSync(path.join(repo, 'unsigned'), 'x')
  git(['add', 'unsigned'])
  git(['commit', '-qm', 'unsigned'])
  t.not(launch(['--verify-only', 'v1.0.0']).status, 0, 'a HEAD without a trusted signed tag is refused')
})

test('launcher fails closed without its root-only EnvironmentFile', (t) => {
  // The launcher rejects symlinked ancestors and group/world-writable parents
  // before it reaches the env file, so stage under the (canonical) repo rather
  // than tmpdir(): macOS tmpdir() sits behind a /var symlink and Linux /tmp is
  // world-writable.
  const root = realpathSync(mkdtempSync(path.join(repoRoot, '.tmp-launcher-')))
  t.teardown(() => rmSync(root, { recursive: true, force: true }))
  chmodSync(root, 0o700)
  const conf = path.join(root, 'hiverelay-updater.conf')
  writeFileSync(conf, `CHANNEL=canary\nRELAY_NAME=utah-2gb-a\nREPO_DIR=${repoRoot}\n`)
  chmodSync(conf, 0o644)
  const r = spawnSync('bash', [launcher, '--verify-only', 'v0.0.0'], {
    encoding: 'utf8',
    env: {
      ...process.env,
      HIVERELAY_UPDATER_CONF: conf,
      HIVERELAY_UPDATER_ENV_TRUST_FILE: path.join(root, 'missing.env'),
      HIVERELAY_REPO_DIR: repoRoot
    }
  })
  t.not(r.status, 0, 'launcher refuses to run')
  t.ok(r.stderr.includes('updater EnvironmentFile'), `refuses because the env file is missing (${r.stderr.trim().split('\n').pop()})`)
})
