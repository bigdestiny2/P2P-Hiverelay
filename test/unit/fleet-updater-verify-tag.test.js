import test from 'brittle'
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import path from 'node:path'

// Regression coverage for the supply-chain fix (audit HR-DIS-003): the fleet
// updater must refuse to check out a channel-named tag it cannot verify was
// signed by a key in the operator-provisioned allowed-signers file. A moved /
// forged tag (repo, GitHub account, CDN, or CA MITM) would otherwise run
// arbitrary code as root on every box.

const repoRoot = path.resolve('.')
const updater = readFileSync('fleet/updater.sh', 'utf8')
const updaterPath = path.join(repoRoot, 'fleet', 'updater.sh')

function have (bin) {
  return spawnSync(bin, ['--version'], { stdio: 'ignore' }).status === 0 ||
    spawnSync('sh', ['-c', `command -v ${bin}`], { stdio: 'ignore' }).status === 0
}

const gitOk = have('git')
const sshKeygenOk = spawnSync('sh', ['-c', 'command -v ssh-keygen'], { stdio: 'ignore' }).status === 0

// ── static assertions: the gate is present and wired fail-closed ──────
test('updater defines a tag-signature gate wired before checkout', (t) => {
  t.ok(updater.includes('verify_tag()'), 'verify_tag function exists')
  // Gate runs before the working tree is ever moved to the target tag.
  const gateIdx = updater.indexOf('verify_tag "$TARGET" ||')
  const checkoutIdx = updater.indexOf('git checkout --quiet "$TARGET"')
  t.ok(gateIdx !== -1, 'target tag is gated by verify_tag')
  t.ok(checkoutIdx !== -1, 'target checkout still present')
  t.ok(gateIdx < checkoutIdx, 'verify_tag gate precedes the checkout')
  t.ok(gateIdx < updater.indexOf('if [ "$CUR_SHA" = "$TARGET_SHA" ]'),
    'signature gate also precedes the up-to-date early exit')
  t.ok(gateIdx < updater.indexOf('if [ "$DRY_RUN" = 1 ]'),
    'signature gate also precedes the dry-run early exit')

  // Fail-closed building blocks.
  t.ok(updater.includes('ALLOWED_SIGNERS='), 'allowed-signers path is configurable')
  t.ok(updater.includes('gpg.ssh.allowedSignersFile=$ALLOWED_SIGNERS'), 'pins allowed_signers for the verify')
  t.ok(updater.includes('gpg.format=ssh'), 'forces ssh signature format for the verify')
  t.ok(updater.includes('is not an annotated (signable) tag'), 'rejects lightweight/unsigned tags')
  t.ok(updater.includes('missing/unreadable — refusing'), 'refuses when allowed-signers file is absent')
  // The success branch is only reachable when `git verify-tag` exits 0,
  // so an untrusted signer (git exit 1) can never be accepted.
  t.ok(updater.includes('verify-tag --raw "$tag"'), 'uses git verify-tag')
})

// ── functional: run the real gate against real tags ───────────────────
const canRunFunctional = gitOk && sshKeygenOk

test('updater --verify-only accepts a trusted-signed tag and rejects everything else', { skip: !canRunFunctional }, (t) => {
  const work = mkdtempSync(path.join(tmpdir(), 'hr-updater-verify-'))
  t.teardown(() => rmSync(work, { recursive: true, force: true }))

  const trustedKey = path.join(work, 'trusted')
  const attackerKey = path.join(work, 'attacker')
  const allowedSigners = path.join(work, 'allowed_signers')
  const repo = path.join(work, 'repo')

  const run = (cmd, args, opts = {}) => {
    const r = spawnSync(cmd, args, { encoding: 'utf8', ...opts })
    if (r.status !== 0 && !opts.allowFail) {
      t.fail(`${cmd} ${args.join(' ')} failed: ${r.stderr || r.stdout}`)
    }
    return r
  }

  // Two ed25519 signing identities: one trusted, one the "attacker".
  run('ssh-keygen', ['-t', 'ed25519', '-f', trustedKey, '-N', '', '-q', '-C', 'good@hiverelay'])
  run('ssh-keygen', ['-t', 'ed25519', '-f', attackerKey, '-N', '', '-q', '-C', 'evil@attacker'])
  // Only the trusted key is an allowed signer.
  writeFileSync(allowedSigners, `good@hiverelay ${readFileSync(trustedKey + '.pub', 'utf8').trim()}\n`)

  run('git', ['init', '-q', repo])
  const git = (args, opts = {}) => run('git', ['-C', repo, ...args], opts)
  git(['config', 'user.name', 'tester'])
  git(['config', 'user.email', 'good@hiverelay'])
  git(['config', 'gpg.format', 'ssh'])
  writeFileSync(path.join(repo, 'a'), 'hi\n')
  writeFileSync(path.join(repo, 'package.json'), '{"version":"1.0.0"}\n')
  git(['add', 'a', 'package.json'])
  git(['commit', '-qm', 'init'])

  // 1. annotated tag signed by the TRUSTED key
  git(['-c', `user.signingkey=${trustedKey}.pub`, 'tag', '-s', '-m', 'release', 'v1.0.0-trusted'])
  // 2. annotated tag signed by the ATTACKER key (the MITM / stolen-account case)
  git(['-c', `user.signingkey=${attackerKey}.pub`, 'tag', '-s', '-m', 'forged', 'v9.9.9-forged'])
  // 3. lightweight, unsigned tag (a plain `git tag`)
  git(['tag', 'v2.0.0-unsigned'])

  const verify = (tag, env = {}) => spawnSync('bash', [updaterPath, '--verify-only', tag], {
    encoding: 'utf8',
    env: {
      ...process.env,
      HIVERELAY_REPO_DIR: repo,
      HIVERELAY_ALLOWED_SIGNERS: allowedSigners,
      ...env
    }
  })

  t.is(verify('v1.0.0-trusted').status, 0, 'trusted-signed tag is accepted')
  t.not(verify('v9.9.9-forged').status, 0, 'tag signed by an untrusted key is REFUSED')
  t.not(verify('v2.0.0-unsigned').status, 0, 'unsigned/lightweight tag is REFUSED')
  t.not(verify('v1.0.0-trusted', { HIVERELAY_ALLOWED_SIGNERS: path.join(work, 'nope') }).status, 0,
    'missing allowed-signers file fails closed even for an otherwise-good tag')

  // Break-glass override is honored but loud (documented emergency escape).
  t.is(verify('v2.0.0-unsigned', { HIVERELAY_REQUIRE_SIGNED_TAGS: '0' }).status, 0,
    'HIVERELAY_REQUIRE_SIGNED_TAGS=0 disables the gate (break-glass)')

  // A per-host pin must bypass the moving channel document, but it must not
  // bypass trust. Use a bare origin because the normal updater always fetches
  // tags before deciding whether the installed commit is already current.
  const origin = path.join(work, 'origin.git')
  run('git', ['clone', '--bare', '-q', repo, origin])
  git(['remote', 'add', 'origin', origin])
  const conf = path.join(work, 'updater.conf')
  const pinnedDryRun = (tag) => {
    writeFileSync(conf, `CHANNEL=stable\nPINNED_TAG=${tag}\n`)
    return spawnSync('bash', [updaterPath, '--dry-run'], {
      encoding: 'utf8',
      env: {
        ...process.env,
        HIVERELAY_REPO_DIR: repo,
        HIVERELAY_UPDATER_CONF: conf,
        HIVERELAY_ALLOWED_SIGNERS: allowedSigners,
        HIVERELAY_CHANNELS_URL: 'file:///definitely-not-a-channel-document'
      }
    })
  }

  const trustedPin = pinnedDryRun('v1.0.0-trusted')
  t.is(trustedPin.status, 0, 'trusted exact pin succeeds without reading the channel document')
  t.ok(trustedPin.stdout.includes('pinned=v1.0.0-trusted'), 'pin decision is visible to the operator')
  t.not(pinnedDryRun('v9.9.9-forged').status, 0, 'untrusted exact pin fails even when it resolves to current HEAD')
})
