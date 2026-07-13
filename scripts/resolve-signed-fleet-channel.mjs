#!/usr/bin/env node

import { execFile } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { constants as fsConstants } from 'node:fs'
import { lstat, mkdir, open, realpath, rename, unlink } from 'node:fs/promises'
import path from 'node:path'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)
const CHANNELS_PATH = 'fleet/channels.json'
const STATE_SCHEMA = 'hiverelay-fleet-control-state-v1'
const MAX_CHANNELS_BYTES = 256 * 1024
const MAX_ALLOWED_SIGNERS_BYTES = 256 * 1024
const MAX_STATE_BYTES = 8 * 1024
const MAX_PROCESS_OUTPUT_BYTES = 2 * 1024 * 1024
const RELEASE_TAG_PATTERN = /^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/
const OBJECT_ID_PATTERN = /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/
const REMOTE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/
const BRANCH_PATTERN = /^(?!\.)(?!.*(?:\.\.|\/\.|\.lock(?:\/|$)))[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$/
const CHANNEL_PATTERN = /^[A-Za-z0-9._-]{1,32}$/
const GOOD_SIGNATURE_PATTERN = /GOODSIG|TRUST_(?:FULLY|ULTIMATE)|Good[^\r\n]*signature/i
const SSH_KEYGEN_PROGRAM = '/usr/bin/ssh-keygen'
const DISABLED_HOOKS_PATH = '/dev/null'
const UNSAFE_GIT_ENV = new Set([
  'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_COMMON_DIR', 'GIT_CONFIG',
  'GIT_CONFIG_COUNT', 'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_PARAMETERS',
  'GIT_CONFIG_SYSTEM', 'GIT_DIR', 'GIT_EXEC_PATH', 'GIT_GRAFT_FILE',
  'GIT_INDEX_FILE', 'GIT_NAMESPACE', 'GIT_OBJECT_DIRECTORY', 'GIT_PREFIX',
  'GIT_PROXY_COMMAND', 'GIT_QUARANTINE_PATH', 'GIT_REPLACE_REF_BASE',
  'GIT_SHALLOW_FILE', 'GIT_SSH', 'GIT_SSH_COMMAND', 'GIT_SSL_CAINFO',
  'GIT_SSL_CAPATH', 'GIT_SSL_NO_VERIFY', 'GIT_WORK_TREE'
])

try {
  await main()
} catch (err) {
  console.error(`signed fleet channel resolver: ${safeError(err)}`)
  process.exitCode = 1
}

async function main () {
  const args = parseArgs(process.argv.slice(2))
  const repo = requireAbsolutePath(args.repo, '--repo')
  const allowedSigners = requireAbsolutePath(args.allowedSigners, '--allowed-signers')
  const statePath = requireAbsolutePath(args.state, '--state')
  const gitBin = requireAbsolutePath(args.gitBin, '--git-bin')
  const remote = args.remote || 'origin'
  const branch = args.branch || 'main'
  const channel = args.channel
  const installedHead = normalizeObjectId(args.installedHead, '--installed-head')

  if (!REMOTE_PATTERN.test(remote)) throw new Error('--remote is invalid')
  if (!BRANCH_PATTERN.test(branch) || branch.startsWith('-') || branch.endsWith('/') || branch.includes('//')) {
    throw new Error('--branch is invalid')
  }
  if (!CHANNEL_PATTERN.test(channel || '')) throw new Error('--channel is invalid')

  await requireSafeExecutable(gitBin, 'Git executable')
  await readBoundedSingleLinkFile(allowedSigners, 'allowed signers', MAX_ALLOWED_SIGNERS_BYTES, false)
  const repoStat = await lstat(repo).catch(() => null)
  if (!repoStat?.isDirectory() || repoStat.isSymbolicLink()) {
    throw new Error('--repo must be a real, non-symlink directory')
  }

  const git = createGit(gitBin, repo)
  const topLevel = (await git(['rev-parse', '--show-toplevel'], 'cannot resolve Git worktree')).stdout.trim()
  if (await realpath(path.resolve(topLevel)) !== await realpath(repo)) {
    throw new Error('--repo must be the exact Git worktree root')
  }
  const shallow = (await git(['rev-parse', '--is-shallow-repository'], 'cannot inspect Git history depth')).stdout.trim()
  if (shallow !== 'false') throw new Error('fleet control replay protection requires a complete Git history')

  const controlRef = `refs/remotes/${remote}/${branch}`
  await git([
    'fetch', '--quiet', '--force', '--no-tags', remote,
    `refs/heads/${branch}:${controlRef}`
  ], `cannot fetch signed fleet control branch ${remote}/${branch}`)
  const controlTip = normalizeObjectId((await git([
    'rev-parse', '--verify', controlRef
  ], 'cannot resolve fetched fleet control head')).stdout.trim(), 'control head')
  const controlCommit = normalizeObjectId((await git([
    'rev-list', '-1', controlTip, '--', CHANNELS_PATH
  ], `cannot locate ${CHANNELS_PATH} authority`)).stdout.trim(), 'channel control commit')

  await assertSignedControlCommit(git, controlCommit, allowedSigners)
  const channels = await readChannelsFromCommit(git, controlCommit)
  const target = channels[channel]
  if (!RELEASE_TAG_PATTERN.test(target || '')) {
    throw new Error(`signed fleet channels do not contain a valid target for ${channel}`)
  }

  await git([
    'fetch', '--quiet', '--no-tags', remote,
    `refs/tags/${target}:refs/tags/${target}`
  ], `cannot fetch immutable release tag ${target}`)
  const targetSha = await resolveReleaseTag(git, target, allowedSigners, args.allowUnsignedRelease === true)

  const stateDirectory = await requirePrivateStateDirectory(path.dirname(statePath))
  const prior = await readControlState(statePath, { optional: true })
  if (prior) {
    requireExactState(prior, { remote, branch, channel })
    const monotonic = await gitStatus(git, [
      'merge-base', '--is-ancestor', prior.channelCommit, controlCommit
    ], 'cannot compare accepted and fetched control heads')
    if (monotonic !== 0) {
      throw new Error('signed fleet control replay or non-monotonic downgrade rejected')
    }
    const targetMonotonic = await gitStatus(git, [
      'merge-base', '--is-ancestor', prior.targetSha, targetSha
    ], 'cannot compare accepted and selected release targets')
    if (targetMonotonic !== 0) {
      throw new Error('signed fleet target downgrade or divergent release rejected')
    }
    if (prior.channelCommit === controlCommit &&
        (prior.target !== target || prior.targetSha !== targetSha)) {
      throw new Error('accepted control state disagrees with the same signed control commit')
    }
  } else {
    const forwardFromInstalled = await gitStatus(git, [
      'merge-base', '--is-ancestor', installedHead, controlCommit
    ], 'cannot compare installed release and signed control head')
    if (forwardFromInstalled !== 0) {
      throw new Error('initial signed fleet control head predates or diverges from the installed release')
    }
    const targetForwardFromInstalled = await gitStatus(git, [
      'merge-base', '--is-ancestor', installedHead, targetSha
    ], 'cannot compare installed and selected release targets')
    if (targetForwardFromInstalled !== 0) {
      throw new Error('initial signed fleet target is a downgrade or divergent from the installed release')
    }
  }

  const state = {
    schema: STATE_SCHEMA,
    remote,
    branch,
    channel,
    channelCommit: controlCommit,
    target,
    targetSha
  }
  if (!args.dryRun) await writeControlStateAtomic(statePath, stateDirectory, state, prior)
  process.stdout.write(`resolved\t${target}\t${targetSha}\t${controlCommit}\t${controlTip}\n`)
}

function parseArgs (argv) {
  const out = {}
  const values = new Set([
    'repo', 'remote', 'branch', 'channel', 'allowed-signers', 'state', 'git-bin', 'installed-head'
  ])
  const booleans = new Set(['dry-run', 'allow-unsigned-release'])
  const seen = new Set()
  for (let i = 0; i < argv.length; i++) {
    const raw = argv[i]
    if (!raw.startsWith('--')) throw new Error(`unexpected positional argument ${JSON.stringify(raw)}`)
    const name = raw.slice(2)
    if (!values.has(name) && !booleans.has(name)) throw new Error(`unknown option --${name}`)
    if (seen.has(name)) throw new Error(`duplicate option --${name}`)
    seen.add(name)
    const key = name.replace(/-([a-z])/g, (_, char) => char.toUpperCase())
    if (booleans.has(name)) {
      out[key] = true
      continue
    }
    const value = argv[++i]
    if (!value || value.startsWith('--')) throw new Error(`missing value for --${name}`)
    out[key] = value
  }
  for (const name of ['repo', 'channel', 'allowedSigners', 'state', 'gitBin', 'installedHead']) {
    if (!out[name]) throw new Error(`--${name.replace(/[A-Z]/g, char => `-${char.toLowerCase()}`)} is required`)
  }
  return out
}

async function assertSignedControlCommit (git, commit, allowedSigners) {
  const parents = (await git(['rev-list', '--parents', '-n', '1', commit],
    'cannot inspect signed fleet control commit')).stdout.trim().split(/\s+/)
  if (parents.length !== 2 || parents[0] !== commit) {
    throw new Error('fleet channel authority must be a single-parent control commit')
  }
  const names = (await git([
    'diff-tree', '--no-commit-id', '--name-only', '-r', '-z', commit
  ], 'cannot inspect signed fleet control commit paths')).stdout
  if (names !== `${CHANNELS_PATH}\0`) {
    throw new Error(`signed fleet control commit must change only ${CHANNELS_PATH}`)
  }
  const verified = await git([
    '-c', 'gpg.format=ssh',
    '-c', `gpg.ssh.allowedSignersFile=${allowedSigners}`,
    '-c', `gpg.ssh.program=${SSH_KEYGEN_PROGRAM}`,
    'verify-commit', '--raw', commit
  ], 'fleet channel control commit is not signed by an allowed signer')
  if (!GOOD_SIGNATURE_PATTERN.test(`${verified.stdout}\n${verified.stderr}`)) {
    throw new Error('fleet channel control commit did not report a trusted signature')
  }
}

async function readChannelsFromCommit (git, commit) {
  const entry = (await git(['ls-tree', '-z', commit, '--', CHANNELS_PATH],
    `cannot inspect signed ${CHANNELS_PATH}`)).stdout
  const match = /^(100644) blob ([a-f0-9]{40}|[a-f0-9]{64})\t([^\0]+)\0$/.exec(entry)
  if (!match || match[3] !== CHANNELS_PATH) {
    throw new Error(`signed ${CHANNELS_PATH} must be one non-executable regular blob`)
  }
  const contents = (await git(['cat-file', 'blob', match[2]],
    `cannot read signed ${CHANNELS_PATH}`)).stdout
  const bytes = Buffer.from(contents)
  if (bytes.byteLength < 2 || bytes.byteLength > MAX_CHANNELS_BYTES || bytes.includes(0)) {
    throw new Error(`signed ${CHANNELS_PATH} exceeds its content bounds`)
  }
  let value
  try { value = JSON.parse(bytes.toString('utf8')) } catch { throw new Error(`signed ${CHANNELS_PATH} is not valid JSON`) }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`signed ${CHANNELS_PATH} must contain a JSON object`)
  }
  return value
}

async function resolveReleaseTag (git, target, allowedSigners, allowUnsigned) {
  const ref = `refs/tags/${target}`
  const type = (await git(['cat-file', '-t', ref], `release tag ${target} is missing`)).stdout.trim()
  if (type !== 'tag') throw new Error(`release tag ${target} must be annotated`)
  if (!allowUnsigned) {
    const verified = await git([
      '-c', 'gpg.format=ssh',
      '-c', `gpg.ssh.allowedSignersFile=${allowedSigners}`,
      '-c', `gpg.ssh.program=${SSH_KEYGEN_PROGRAM}`,
      'verify-tag', '--raw', target
    ], `release tag ${target} is not signed by an allowed signer`)
    if (!GOOD_SIGNATURE_PATTERN.test(`${verified.stdout}\n${verified.stderr}`)) {
      throw new Error(`release tag ${target} did not report a trusted signature`)
    }
  }
  return normalizeObjectId((await git([
    'rev-parse', '--verify', `${ref}^{commit}`
  ], `cannot resolve release tag ${target}`)).stdout.trim(), `${target} release commit`)
}

function createGit (gitBin, repo) {
  return async function git (args, failure) {
    try {
      return await execFileAsync(gitBin, [
        '--no-replace-objects', '-C', repo,
        '-c', `core.hooksPath=${DISABLED_HOOKS_PATH}`,
        '-c', 'core.fsmonitor=false',
        '-c', 'http.sslVerify=true',
        '-c', 'protocol.ext.allow=never',
        ...args
      ], {
        encoding: 'utf8',
        env: hardenedGitEnv(),
        maxBuffer: MAX_PROCESS_OUTPUT_BYTES,
        timeout: 30_000
      })
    } catch (err) {
      const wrapped = new Error(failure)
      wrapped.exitCode = Number.isInteger(err?.code) ? err.code : null
      throw wrapped
    }
  }
}

async function gitStatus (git, args, failure) {
  try {
    await git(args, failure)
    return 0
  } catch (err) {
    if (err.exitCode === 1) return 1
    throw err
  }
}

function hardenedGitEnv () {
  const env = { ...process.env }
  for (const name of UNSAFE_GIT_ENV) delete env[name]
  env.GIT_CONFIG_NOSYSTEM = '1'
  env.GIT_NO_REPLACE_OBJECTS = '1'
  env.GIT_GRAFT_FILE = '/dev/null/hiverelay-disabled'
  env.GIT_OPTIONAL_LOCKS = '0'
  env.LC_ALL = 'C'
  return env
}

async function requirePrivateStateDirectory (directory) {
  const resolved = path.resolve(directory)
  let stat = await lstat(resolved).catch(err => {
    if (err?.code === 'ENOENT') return null
    throw err
  })
  if (!stat) {
    const parent = path.dirname(resolved)
    const parentStat = await lstat(parent).catch(() => null)
    if (!parentStat?.isDirectory() || parentStat.isSymbolicLink()) {
      throw new Error('control state parent directory is unsafe')
    }
    await mkdir(resolved, { mode: 0o700 })
    stat = await lstat(resolved)
  }
  if (!stat.isDirectory() || stat.isSymbolicLink() ||
      (stat.mode & 0o077) !== 0 || !ownedByCurrentUser(stat)) {
    throw new Error('control state directory must be owned, non-symlink, and mode 0700')
  }
  return resolved
}

async function readControlState (file, opts = {}) {
  let buffer
  try {
    buffer = await readBoundedSingleLinkFile(file, 'control state', MAX_STATE_BYTES, true)
  } catch (err) {
    if (opts.optional && err?.code === 'ENOENT') return null
    throw err
  }
  let value
  try { value = JSON.parse(buffer.toString('utf8')) } catch { throw new Error('control state is not valid JSON') }
  requireOnlyKeys(value, [
    'schema', 'remote', 'branch', 'channel', 'channelCommit', 'target', 'targetSha'
  ], 'control state')
  if (value.schema !== STATE_SCHEMA) throw new Error('control state schema is invalid')
  normalizeObjectId(value.channelCommit, 'control state channelCommit')
  normalizeObjectId(value.targetSha, 'control state targetSha')
  if (!RELEASE_TAG_PATTERN.test(value.target || '')) throw new Error('control state target is invalid')
  return value
}

function requireExactState (state, expected) {
  for (const [name, value] of Object.entries(expected)) {
    if (state[name] !== value) throw new Error(`control state ${name} does not match this updater`)
  }
}

async function writeControlStateAtomic (file, directory, value, prior) {
  const bytes = Buffer.from(JSON.stringify(value, null, 2) + '\n')
  if (bytes.byteLength > MAX_STATE_BYTES) throw new Error('control state exceeds its write bound')
  if (prior && JSON.stringify(prior) === JSON.stringify(value)) return
  if (path.dirname(file) !== directory) throw new Error('control state path changed during validation')
  const temporary = path.join(directory,
    `.${path.basename(file)}.tmp-${process.pid}-${randomBytes(8).toString('hex')}`)
  let handle
  try {
    if (typeof fsConstants.O_NOFOLLOW !== 'number') throw new Error('platform lacks O_NOFOLLOW')
    handle = await open(temporary,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
      0o600)
    await handle.writeFile(bytes)
    await handle.sync()
    const stat = await handle.stat()
    if (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o777) !== 0o600 || !ownedByCurrentUser(stat)) {
      throw new Error('temporary control state permissions are unsafe')
    }
    await handle.close()
    handle = null
    await rename(temporary, file)
    const directoryHandle = await open(directory,
      fsConstants.O_RDONLY | (fsConstants.O_DIRECTORY || 0) | fsConstants.O_NOFOLLOW)
    try { await directoryHandle.sync() } finally { await directoryHandle.close() }
  } catch (err) {
    await handle?.close().catch(() => {})
    await unlink(temporary).catch(() => {})
    throw err
  }
}

async function readBoundedSingleLinkFile (file, label, maxBytes, privateMode) {
  let handle
  try {
    if (typeof fsConstants.O_NOFOLLOW !== 'number') throw new Error('platform lacks O_NOFOLLOW')
    handle = await open(file, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW)
    const before = await handle.stat({ bigint: true })
    const mode = Number(before.mode & 0o777n)
    if (!before.isFile() || before.nlink !== 1n || before.size < 1n || before.size > BigInt(maxBytes) ||
        (privateMode ? mode !== 0o600 : (mode & 0o022) !== 0) || !ownedByCurrentUser(before)) {
      throw new Error(`${label} must be a safe bounded single-link regular file`)
    }
    const buffer = Buffer.allocUnsafe(maxBytes + 1)
    let length = 0
    while (length < buffer.length) {
      const { bytesRead } = await handle.read(buffer, length, buffer.length - length, length)
      if (bytesRead === 0) break
      length += bytesRead
    }
    if (length > maxBytes) throw new Error(`${label} exceeds its read bound`)
    const after = await handle.stat({ bigint: true })
    if (!sameFileSnapshot(before, after) || BigInt(length) !== after.size) {
      throw new Error(`${label} changed while being read`)
    }
    return buffer.subarray(0, length)
  } catch (err) {
    if (err?.code === 'ENOENT') throw err
    if (err?.message?.startsWith(label) || err?.message === 'platform lacks O_NOFOLLOW') throw err
    throw new Error(`${label} must be a readable non-symlink file`)
  } finally {
    await handle?.close().catch(() => {})
  }
}

async function requireSafeExecutable (file, label) {
  const stat = await lstat(file).catch(() => null)
  if (!stat?.isFile() || stat.isSymbolicLink() || (stat.mode & 0o111) === 0 ||
      (stat.mode & 0o022) !== 0 || !ownedByRootOrCurrentUser(stat)) {
    throw new Error(`${label} is missing or unsafe`)
  }
}

function requireOnlyKeys (value, names, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`)
  const allowed = new Set(names)
  const unknown = Object.keys(value).filter(name => !allowed.has(name))
  const missing = names.filter(name => !Object.hasOwn(value, name))
  if (unknown.length || missing.length) throw new Error(`${label} fields are invalid`)
}

function sameFileSnapshot (left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode &&
    left.nlink === right.nlink && left.size === right.size && left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
}

function ownedByCurrentUser (stat) {
  return typeof process.geteuid !== 'function' || Number(stat.uid) === process.geteuid()
}

function ownedByRootOrCurrentUser (stat) {
  return Number(stat.uid) === 0 || ownedByCurrentUser(stat)
}

function normalizeObjectId (value, label) {
  const normalized = String(value || '').trim().toLowerCase()
  if (!OBJECT_ID_PATTERN.test(normalized)) throw new Error(`${label} is not a valid Git object ID`)
  return normalized
}

function requireAbsolutePath (value, label) {
  const candidate = String(value || '')
  if (!path.isAbsolute(candidate) || candidate !== path.resolve(candidate) || candidate.length > 4096 ||
      hasControlChars(candidate)) {
    throw new Error(`${label} must be a bounded canonical absolute path`)
  }
  return candidate
}

function hasControlChars (value) {
  for (const char of value) {
    const code = char.codePointAt(0)
    if (code <= 31 || code === 127) return true
  }
  return false
}

function safeError (err) {
  const value = err instanceof Error ? err.message : String(err)
  return value.replace(/[\r\n\0]/g, ' ').slice(0, 1000)
}
