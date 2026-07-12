import test from 'brittle'
import {
  chmodSync,
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

const resolver = path.resolve('scripts/resolve-signed-fleet-channel.mjs')
const gitBin = commandPath('git')
const canRun = Boolean(gitBin && commandPath('ssh-keygen') && statSafe('/usr/bin/ssh-keygen'))

test('signed fleet channel resolver advances monotonically and rejects replay/downgrade', { skip: !canRun }, (t) => {
  const f = fixture(t)
  const first = f.resolve()
  t.is(first.status, 0, first.stderr)
  const initialFields = first.stdout.trim().split('\t')
  t.alike(initialFields.slice(0, 3), ['resolved', 'v1.0.0', f.release1])
  t.is(initialFields[3], f.control1)
  t.is(statSync(f.state).mode & 0o777, 0o600, 'accepted control state is private')

  const accepted1 = JSON.parse(readFileSync(f.state, 'utf8'))
  t.is(accepted1.schema, 'hiverelay-fleet-control-state-v1')
  t.is(accepted1.channelCommit, f.control1)
  t.is(accepted1.targetSha, f.release1)

  const advanced = f.advance()
  const second = f.resolve()
  t.is(second.status, 0, second.stderr)
  const secondFields = second.stdout.trim().split('\t')
  t.alike(secondFields.slice(0, 3), ['resolved', 'v1.1.0', advanced.release])
  t.is(secondFields[3], advanced.control)
  const accepted2 = JSON.parse(readFileSync(f.state, 'utf8'))
  t.is(accepted2.channelCommit, advanced.control)
  t.is(accepted2.target, 'v1.1.0')

  const downgradedChannels = JSON.parse(readFileSync(f.channels, 'utf8'))
  downgradedChannels.canary = 'v1.0.0'
  downgradedChannels.stable = 'v1.0.0'
  writeFileSync(f.channels, JSON.stringify(downgradedChannels, null, 2) + '\n')
  f.gitPublisher(['add', 'fleet/channels.json'])
  f.gitPublisher([
    '-c', `user.signingkey=${f.signingKey}.pub`,
    'commit', '-S', '-m', 'fleet: attempted automatic downgrade to v1.0.0'
  ])
  f.gitPublisher(['push', 'origin', 'main'])
  const forwardDowngrade = f.resolve()
  t.not(forwardDowngrade.status, 0)
  t.ok(forwardDowngrade.stderr.includes('signed fleet target downgrade or divergent release rejected'))
  t.alike(JSON.parse(readFileSync(f.state, 'utf8')), accepted2,
    'a newer signed control commit cannot silently authorize a target downgrade')

  f.gitPublisher(['push', '--force', 'origin', `${f.control1}:refs/heads/main`])
  const replay = f.resolve()
  t.not(replay.status, 0)
  t.ok(replay.stderr.includes('replay or non-monotonic downgrade rejected'))
  t.alike(JSON.parse(readFileSync(f.state, 'utf8')), accepted2,
    'rejected replay cannot rewrite the last accepted control head')
})

test('signed fleet channel resolver rejects unsigned control and moved release tags', { skip: !canRun }, (t) => {
  const unsigned = fixture(t)
  t.is(unsigned.resolve().status, 0)
  const channels = JSON.parse(readFileSync(unsigned.channels, 'utf8'))
  channels._doc = 'unsigned rewrite'
  writeFileSync(unsigned.channels, JSON.stringify(channels, null, 2) + '\n')
  unsigned.gitPublisher(['add', 'fleet/channels.json'])
  unsigned.gitPublisher(['commit', '-qm', 'unsigned channel mutation'])
  unsigned.gitPublisher(['push', '--force', 'origin', 'main'])
  const rejectedUnsigned = unsigned.resolve()
  t.not(rejectedUnsigned.status, 0)
  t.ok(rejectedUnsigned.stderr.includes('not signed by an allowed signer'))

  const moved = fixture(t)
  t.is(moved.resolve().status, 0)
  const advanced = moved.advance()
  t.is(moved.resolve().status, 0)
  moved.gitPublisher(['tag', '-d', 'v1.1.0'])
  writeFileSync(path.join(moved.publisher, 'moved-tag'), 'different release object\n')
  moved.gitPublisher(['add', 'moved-tag'])
  moved.gitPublisher(['commit', '-qm', 'different release object'])
  moved.gitPublisher([
    '-c', `user.signingkey=${moved.signingKey}.pub`,
    'tag', '-s', '-m', 'moved release', 'v1.1.0'
  ])
  moved.gitPublisher(['push', '--force', 'origin', `${advanced.control}:refs/heads/main`, 'refs/tags/v1.1.0'])
  const rejectedMove = moved.resolve()
  t.not(rejectedMove.status, 0)
  t.ok(rejectedMove.stderr.includes('cannot fetch immutable release tag v1.1.0'))
})

test('signed fleet channel resolver refuses a symlinked durable state', { skip: !canRun }, (t) => {
  const f = fixture(t)
  t.is(f.resolve().status, 0)
  const sentinel = path.join(f.root, 'sentinel')
  writeFileSync(sentinel, 'do not overwrite\n')
  chmodSync(sentinel, 0o600)
  rmSync(f.state)
  symlinkSync(sentinel, f.state)

  const result = f.resolve()
  t.not(result.status, 0)
  t.ok(result.stderr.includes('control state must be a readable non-symlink file'))
  t.is(readFileSync(sentinel, 'utf8'), 'do not overwrite\n')
})

function fixture (t) {
  const root = mkdtempSync(path.join(tmpdir(), 'hr-signed-channel-'))
  t.teardown(() => rmSync(root, { recursive: true, force: true }))
  const remote = path.join(root, 'remote.git')
  const publisher = path.join(root, 'publisher')
  const node = path.join(root, 'node')
  const stateDirectory = path.join(root, 'state')
  const state = path.join(stateDirectory, 'channel.json')
  const signingKey = path.join(root, 'fleet-signer')
  const allowedSigners = path.join(root, 'allowed-signers')
  const channels = path.join(publisher, 'fleet', 'channels.json')

  command('ssh-keygen', ['-t', 'ed25519', '-f', signingKey, '-N', '', '-q', '-C', 'fleet@hiverelay'])
  writeFileSync(allowedSigners,
    `fleet@hiverelay ${readFileSync(signingKey + '.pub', 'utf8').trim()}\n`)
  command(gitBin, ['init', '--bare', '-q', '--initial-branch=main', remote])
  command(gitBin, ['init', '-q', '--initial-branch=main', publisher])
  const gitPublisher = args => command(gitBin, ['-C', publisher, ...args])
  gitPublisher(['config', 'user.name', 'fleet signer'])
  gitPublisher(['config', 'user.email', 'fleet@hiverelay'])
  gitPublisher(['config', 'gpg.format', 'ssh'])
  gitPublisher(['remote', 'add', 'origin', remote])

  mkdirSync(path.dirname(channels), { recursive: true })
  writeFileSync(path.join(publisher, 'package.json'), JSON.stringify({ version: '1.0.0' }) + '\n')
  writeFileSync(channels, JSON.stringify({
    _doc: 'fixture',
    canary: 'v0.9.0',
    stable: 'v0.9.0'
  }, null, 2) + '\n')
  gitPublisher(['add', 'package.json', 'fleet/channels.json'])
  gitPublisher(['commit', '-qm', 'release 1.0.0'])
  const release1 = gitPublisher(['rev-parse', 'HEAD']).stdout.trim()
  gitPublisher([
    '-c', `user.signingkey=${signingKey}.pub`,
    'tag', '-s', '-m', 'release 1.0.0', 'v1.0.0'
  ])

  const firstChannels = JSON.parse(readFileSync(channels, 'utf8'))
  firstChannels.canary = 'v1.0.0'
  firstChannels.stable = 'v1.0.0'
  writeFileSync(channels, JSON.stringify(firstChannels, null, 2) + '\n')
  gitPublisher(['add', 'fleet/channels.json'])
  gitPublisher([
    '-c', `user.signingkey=${signingKey}.pub`,
    'commit', '-S', '-m', 'fleet: promote stable to v1.0.0'
  ])
  const control1 = gitPublisher(['rev-parse', 'HEAD']).stdout.trim()
  gitPublisher(['push', '-q', 'origin', 'main', 'refs/tags/v1.0.0'])

  command(gitBin, ['clone', '-q', '--branch', 'main', remote, node])
  command(gitBin, ['-C', node, 'checkout', '-q', release1])
  mkdirSync(stateDirectory, { mode: 0o700 })

  const resolve = () => spawnSync(process.execPath, [
    resolver,
    '--repo', node,
    '--remote', 'origin',
    '--branch', 'main',
    '--channel', 'stable',
    '--allowed-signers', allowedSigners,
    '--state', state,
    '--git-bin', gitBin,
    '--installed-head', release1
  ], { encoding: 'utf8' })

  const advance = () => {
    writeFileSync(path.join(publisher, 'package.json'), JSON.stringify({ version: '1.1.0' }) + '\n')
    gitPublisher(['add', 'package.json'])
    gitPublisher(['commit', '-qm', 'release 1.1.0'])
    const release = gitPublisher(['rev-parse', 'HEAD']).stdout.trim()
    gitPublisher([
      '-c', `user.signingkey=${signingKey}.pub`,
      'tag', '-s', '-m', 'release 1.1.0', 'v1.1.0'
    ])
    const nextChannels = JSON.parse(readFileSync(channels, 'utf8'))
    nextChannels.canary = 'v1.1.0'
    nextChannels.stable = 'v1.1.0'
    writeFileSync(channels, JSON.stringify(nextChannels, null, 2) + '\n')
    gitPublisher(['add', 'fleet/channels.json'])
    gitPublisher([
      '-c', `user.signingkey=${signingKey}.pub`,
      'commit', '-S', '-m', 'fleet: promote stable to v1.1.0'
    ])
    const control = gitPublisher(['rev-parse', 'HEAD']).stdout.trim()
    gitPublisher(['push', '-q', 'origin', 'main', 'refs/tags/v1.1.0'])
    return { release, control }
  }

  return {
    root,
    publisher,
    signingKey,
    channels,
    state,
    release1,
    control1,
    gitPublisher,
    resolve,
    advance
  }
}

function command (bin, args) {
  const result = spawnSync(bin, args, { encoding: 'utf8' })
  if (result.status !== 0) {
    throw new Error(`${bin} ${args.join(' ')} failed: ${result.stderr || result.stdout}`)
  }
  return result
}

function commandPath (name) {
  const result = spawnSync('sh', ['-c', `command -v ${name}`], { encoding: 'utf8' })
  if (result.status !== 0 || !path.isAbsolute(result.stdout.trim())) return null
  return realpathSync(result.stdout.trim())
}

function statSafe (file) {
  try { return statSync(file).isFile() } catch { return false }
}
