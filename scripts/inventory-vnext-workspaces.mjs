#!/usr/bin/env node

import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const scriptPath = fileURLToPath(import.meta.url)
const repoRoot = path.resolve(path.dirname(scriptPath), '..')
const defaultWorkspaceRoot = path.resolve(repoRoot, '..', '..')
const defaultOutput = path.join(repoRoot, 'docs', 'vnext', 'workspace-inventory.json')
const GIT = '/usr/bin/git'
const MAX_GIT_OUTPUT = 64 * 1024 * 1024
const MAX_REPOSITORIES = 512
const MAX_CHANGES_PER_REPOSITORY = 10000
const SKIP_DIRECTORIES = new Set([
  '.build', '.git', '.forge-cache', '.gradle', '.next', '.turbo', '00-brain',
  'build', 'coverage', 'dist', 'node_modules', 'out', 'outputs'
])
const CATEGORY_DIRECTORIES = [
  '00-core', '01-browser', '02-apps', '03-sites', '04-experiments', '05-rollout'
]
const UNSAFE_GIT_ENV = new Set([
  'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_COMMON_DIR', 'GIT_CONFIG',
  'GIT_CONFIG_COUNT', 'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_PARAMETERS',
  'GIT_CONFIG_SYSTEM', 'GIT_DIR', 'GIT_EXEC_PATH', 'GIT_GRAFT_FILE',
  'GIT_INDEX_FILE', 'GIT_NAMESPACE', 'GIT_OBJECT_DIRECTORY', 'GIT_PREFIX',
  'GIT_PROXY_COMMAND', 'GIT_QUARANTINE_PATH', 'GIT_REPLACE_REF_BASE',
  'GIT_SHALLOW_FILE', 'GIT_SSH', 'GIT_SSH_COMMAND', 'GIT_SSL_CAINFO',
  'GIT_SSL_CAPATH', 'GIT_SSL_NO_VERIFY', 'GIT_WORK_TREE'
])

const usage = `
Usage:
  node scripts/inventory-vnext-workspaces.mjs [options]

Options:
  --workspace-root <absolute-path>  Ecosystem root (default: detected sibling root)
  --output <absolute-path>          Inventory JSON (default: docs/vnext/workspace-inventory.json)
  --include <absolute-path>         Include an external Git worktree; repeatable
  --observed-at <ISO-8601>          Fixed observation time for reproducible fixtures
  --check                           Recompute and compare with the existing inventory
  --help                            Show this help

The controller worktree is excluded from repository state to avoid a recursive
self-inventory. Its exact commit is recorded separately. No file contents are
written to evidence; dirty patches and untracked files are represented by
SHA-256 commitments.`

if (path.resolve(process.argv[1] || '') === scriptPath) {
  try {
    const args = parseArgs(process.argv.slice(2))
    if (args.help) {
      console.log(usage.trim())
    } else {
      const existing = args.check ? readInventory(args.output) : null
      const observedAt = args.observedAt || existing?.observedAt || new Date().toISOString()
      const inventory = inventoryVnextWorkspaces({ ...args, observedAt })
      if (args.check) {
        const actual = canonicalJson(inventory)
        const expected = canonicalJson(existing)
        if (actual !== expected) throw new Error('workspace inventory is stale; regenerate it before PG-0 review')
        console.log(JSON.stringify({ status: 'pass', output: args.output, summary: inventory.summary }, null, 2))
      } else {
        writeAtomicJson(args.output, inventory)
        console.log(JSON.stringify({ status: 'written', output: args.output, summary: inventory.summary }, null, 2))
      }
    }
  } catch (err) {
    console.error(`vNext workspace inventory: ${safeError(err)}`)
    process.exitCode = 1
  }
}

export function inventoryVnextWorkspaces (options = {}) {
  const workspaceRoot = path.resolve(options.workspaceRoot || defaultWorkspaceRoot)
  const controllerRoot = path.resolve(options.controllerRoot || repoRoot)
  assertDirectory(workspaceRoot, 'workspace root')
  assertGitWorktree(controllerRoot, 'controller root')

  const discoveredRoots = discoverGitRoots(workspaceRoot)
  for (const included of options.include || []) {
    const root = path.resolve(included)
    assertGitWorktree(root, 'included worktree')
    discoveredRoots.add(root)
  }
  const roots = new Set(discoveredRoots)
  roots.delete(controllerRoot)
  if (roots.size > MAX_REPOSITORIES) throw new Error(`repository count exceeds ${MAX_REPOSITORIES}`)

  const repositories = [...roots]
    .sort((a, b) => compareText(inventoryPath(a, workspaceRoot), inventoryPath(b, workspaceRoot)))
    .map(root => inventoryGitRepository(root, workspaceRoot))
  const nonGitProjects = discoverNonGitProjects(workspaceRoot, discoveredRoots)
  const controller = {
    path: inventoryPath(controllerRoot, workspaceRoot),
    branch: optionalGitText(controllerRoot, ['symbolic-ref', '--quiet', '--short', 'HEAD']),
    commit: requiredGitText(controllerRoot, ['rev-parse', '--verify', 'HEAD^{commit}'], 'controller commit')
  }
  const dirtyRepositories = repositories.filter(row => row.dirty)
  const unpreserved = [
    ...dirtyRepositories.map(row => row.path),
    ...nonGitProjects.map(row => row.path)
  ].sort()
  return {
    schema: 'pear-vnext-workspace-inventory-v1',
    observedAt: validateIsoTimestamp(options.observedAt),
    workspace: path.basename(workspaceRoot),
    controller,
    repositories,
    nonGitProjects,
    summary: {
      repositories: repositories.length,
      dirtyRepositories: dirtyRepositories.length,
      cleanRepositories: repositories.length - dirtyRepositories.length,
      nonGitProjects: nonGitProjects.length,
      preservationComplete: unpreserved.length === 0,
      preservationRequired: unpreserved
    }
  }
}

function inventoryGitRepository (root, workspaceRoot) {
  const rawStatus = runGit(root, ['status', '--porcelain=v1', '-z', '--untracked-files=all'])
  const changes = parsePorcelainV1(rawStatus)
  if (changes.length > MAX_CHANGES_PER_REPOSITORY) {
    throw new Error(`${root} has more than ${MAX_CHANGES_PER_REPOSITORY} status entries`)
  }
  const untracked = changes.filter(row => row.status === '??')
  const branch = optionalGitText(root, ['symbolic-ref', '--quiet', '--short', 'HEAD'])
  const head = optionalGitText(root, ['rev-parse', '--verify', 'HEAD^{commit}'])
  const unborn = head == null
  const upstream = optionalGitText(root, ['rev-parse', '--abbrev-ref', '--symbolic-full-name', '@{upstream}'])
  let ahead = null
  let behind = null
  if (upstream) {
    const counts = requiredGitText(root, ['rev-list', '--left-right', '--count', `HEAD...${upstream}`], 'ahead/behind')
      .split(/\s+/).map(Number)
    if (counts.length !== 2 || counts.some(value => !Number.isSafeInteger(value) || value < 0)) {
      throw new Error(`${root} returned malformed ahead/behind counts`)
    }
    ahead = counts[0]
    behind = counts[1]
  }
  const packageVersion = readPackageVersion(root)
  return {
    path: inventoryPath(root, workspaceRoot),
    branch,
    head,
    unborn,
    upstream,
    ahead,
    behind,
    packageVersion,
    dirty: changes.length > 0 || unborn,
    statusSha256: digest(rawStatus),
    stagedPatchSha256: digest(runGit(root, ['diff', '--cached', '--binary', '--full-index', '--no-ext-diff', '--'])),
    worktreePatchSha256: digest(runGit(root, ['diff', '--binary', '--full-index', '--no-ext-diff', '--'])),
    untrackedTreeSha256: hashUntrackedTree(root, untracked),
    trackedChanges: changes.filter(row => row.status !== '??').length,
    untrackedChanges: untracked.length,
    preservation: unborn
      ? 'initial-commit-or-immutable-archive-required'
      : (changes.length === 0 ? 'clean' : 'commit-or-immutable-bundle-required'),
    changes
  }
}

export function parsePorcelainV1 (raw) {
  const records = splitNul(raw)
  const changes = []
  for (let index = 0; index < records.length; index++) {
    const record = records[index]
    if (record.length < 4 || record[2] !== ' ') throw new Error('Git returned malformed porcelain status')
    const status = record.slice(0, 2)
    const target = record.slice(3)
    if (!target) throw new Error('Git returned an empty status path')
    const renamed = /[RC]/.test(status)
    const originalPath = renamed ? records[++index] : null
    if (renamed && !originalPath) throw new Error('Git returned an incomplete rename status')
    changes.push({ status, path: target, originalPath })
  }
  return changes.sort((a, b) => compareText(`${a.path}\0${a.originalPath || ''}`, `${b.path}\0${b.originalPath || ''}`))
}

function hashUntrackedTree (root, changes) {
  const hash = createHash('sha256')
  for (const row of [...changes].sort((a, b) => compareText(a.path, b.path))) {
    const absolute = path.resolve(root, row.path)
    if (!isInside(absolute, root)) throw new Error(`untracked path escapes repository: ${row.path}`)
    const stat = fs.lstatSync(absolute, { bigint: true })
    let kind
    let contentHash
    if (stat.isFile()) {
      kind = 'file'
      contentHash = hashRegularFileNoFollow(absolute, stat)
    } else if (stat.isSymbolicLink()) {
      kind = 'symlink'
      contentHash = digest(Buffer.from(fs.readlinkSync(absolute), 'utf8'))
    } else if (stat.isDirectory() && hasGitMarker(absolute)) {
      kind = 'nested-git-worktree'
      const nestedHead = optionalGitText(absolute, ['rev-parse', '--verify', 'HEAD^{commit}']) || 'unborn'
      const nestedStatus = runGit(absolute, ['status', '--porcelain=v1', '-z', '--untracked-files=all'])
      contentHash = digest(Buffer.concat([Buffer.from(`${nestedHead}\0`, 'utf8'), nestedStatus]))
    } else {
      throw new Error(`untracked path is not a regular file or symlink: ${row.path}`)
    }
    hash.update(`${kind}\0${stat.mode.toString()}\0${stat.size.toString()}\0${contentHash}\0${row.path}\0`)
  }
  return hash.digest('hex')
}

function hashRegularFileNoFollow (file, expected) {
  if (typeof fs.constants.O_NOFOLLOW !== 'number') throw new Error('platform lacks O_NOFOLLOW')
  const descriptor = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW)
  try {
    const before = fs.fstatSync(descriptor, { bigint: true })
    if (!sameFile(before, expected) || !before.isFile()) throw new Error(`untracked file changed before hashing: ${file}`)
    const hash = createHash('sha256')
    const buffer = Buffer.allocUnsafe(1024 * 1024)
    let position = 0
    while (true) {
      const length = fs.readSync(descriptor, buffer, 0, buffer.length, position)
      if (length === 0) break
      hash.update(buffer.subarray(0, length))
      position += length
    }
    const after = fs.fstatSync(descriptor, { bigint: true })
    if (!sameFile(before, after)) throw new Error(`untracked file changed while hashing: ${file}`)
    return hash.digest('hex')
  } finally {
    fs.closeSync(descriptor)
  }
}

function sameFile (a, b) {
  return a.dev === b.dev && a.ino === b.ino && a.mode === b.mode && a.size === b.size &&
    a.mtimeNs === b.mtimeNs && a.ctimeNs === b.ctimeNs
}

function discoverGitRoots (workspaceRoot) {
  const roots = new Set()
  walk(workspaceRoot)
  return roots

  function walk (directory) {
    let entries
    try {
      entries = fs.readdirSync(directory, { withFileTypes: true })
    } catch {
      return
    }
    if (entries.some(entry => entry.name === '.git' && (entry.isDirectory() || entry.isFile()))) roots.add(directory)
    for (const entry of entries) {
      if (!entry.isDirectory() || SKIP_DIRECTORIES.has(entry.name)) continue
      walk(path.join(directory, entry.name))
    }
  }
}

function hasGitMarker (directory) {
  try {
    const stat = fs.lstatSync(path.join(directory, '.git'))
    return stat.isDirectory() || stat.isFile()
  } catch {
    return false
  }
}

function discoverNonGitProjects (workspaceRoot, gitRoots) {
  const roots = [...gitRoots]
  const projects = []
  for (const category of CATEGORY_DIRECTORIES) {
    const directory = path.join(workspaceRoot, category)
    let entries
    try {
      entries = fs.readdirSync(directory, { withFileTypes: true })
    } catch {
      continue
    }
    for (const entry of entries) {
      if (!entry.isDirectory() || SKIP_DIRECTORIES.has(entry.name)) continue
      const candidate = path.join(directory, entry.name)
      if (roots.some(root => root === candidate)) continue
      const hasPackage = fs.existsSync(path.join(candidate, 'package.json'))
      const containsNestedRepo = roots.some(root => isInside(root, candidate))
      if (!hasPackage && !containsNestedRepo) continue
      projects.push({
        path: inventoryPath(candidate, workspaceRoot),
        containsNestedRepository: containsNestedRepo,
        preservation: 'source-custody-or-immutable-archive-required'
      })
    }
  }
  return projects.sort((a, b) => compareText(a.path, b.path))
}

function runGit (root, args) {
  try {
    return execFileSync(GIT, [
      '-c', 'core.hooksPath=/dev/null',
      '-c', 'core.fsmonitor=false',
      '-c', 'core.attributesFile=/dev/null',
      '-c', 'core.excludesFile=/dev/null',
      ...args
    ], {
      cwd: root,
      env: safeGitEnvironment(),
      encoding: 'buffer',
      maxBuffer: MAX_GIT_OUTPUT,
      stdio: ['ignore', 'pipe', 'pipe']
    })
  } catch (err) {
    const detail = Buffer.isBuffer(err?.stderr) ? err.stderr.toString('utf8').trim() : ''
    throw new Error(`Git ${args[0]} failed for ${root}${detail ? `: ${detail}` : ''}`)
  }
}

function requiredGitText (root, args, label) {
  const value = runGit(root, args).toString('utf8').trim()
  if (!value) throw new Error(`${root} has no ${label}`)
  return value
}

function optionalGitText (root, args) {
  try {
    return runGit(root, args).toString('utf8').trim() || null
  } catch {
    return null
  }
}

function safeGitEnvironment () {
  const env = {}
  for (const [name, value] of Object.entries(process.env)) {
    if (!UNSAFE_GIT_ENV.has(name) && !name.startsWith('GIT_CONFIG_KEY_') && !name.startsWith('GIT_CONFIG_VALUE_')) env[name] = value
  }
  env.GIT_NO_REPLACE_OBJECTS = '1'
  env.GIT_GRAFT_FILE = '/dev/null/hiverelay-disabled'
  return env
}

function parseArgs (argv) {
  const out = { workspaceRoot: defaultWorkspaceRoot, output: defaultOutput, include: [], check: false, help: false }
  const seen = new Set()
  for (let index = 0; index < argv.length; index++) {
    const name = argv[index]
    if (name === '--help') { out.help = true; continue }
    if (name === '--check') { out.check = true; continue }
    if (!['--workspace-root', '--output', '--include', '--observed-at'].includes(name)) throw new Error(`unknown option ${name}`)
    if (name !== '--include' && seen.has(name)) throw new Error(`duplicate option ${name}`)
    seen.add(name)
    const value = argv[++index]
    if (!value || value.startsWith('--')) throw new Error(`missing value for ${name}`)
    if (name === '--workspace-root') out.workspaceRoot = safeAbsolutePath(value, name)
    if (name === '--output') out.output = safeAbsolutePath(value, name)
    if (name === '--include') out.include.push(safeAbsolutePath(value, name))
    if (name === '--observed-at') out.observedAt = validateIsoTimestamp(value)
  }
  if (out.help && argv.length !== 1) throw new Error('--help cannot be combined with other options')
  return out
}

function readPackageVersion (root) {
  const file = path.join(root, 'package.json')
  if (!fs.existsSync(file)) return null
  const value = JSON.parse(fs.readFileSync(file, 'utf8'))
  return typeof value.version === 'string' ? value.version : null
}

function readInventory (file) {
  const value = JSON.parse(fs.readFileSync(file, 'utf8'))
  if (!value || value.schema !== 'pear-vnext-workspace-inventory-v1') throw new Error('existing inventory has the wrong schema')
  return value
}

function writeAtomicJson (file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o755 })
  const temporary = `${file}.tmp.${process.pid}`
  const bytes = canonicalJson(value)
  const descriptor = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600)
  try {
    fs.writeFileSync(descriptor, bytes)
    fs.fsyncSync(descriptor)
  } finally {
    fs.closeSync(descriptor)
  }
  fs.renameSync(temporary, file)
}

function canonicalJson (value) {
  return `${JSON.stringify(value, null, 2)}\n`
}

function splitNul (raw) {
  const text = raw.toString('utf8')
  if (text && !text.endsWith('\0')) throw new Error('Git returned unterminated NUL output')
  return text ? text.slice(0, -1).split('\0') : []
}

function inventoryPath (value, workspaceRoot) {
  return isInside(value, workspaceRoot) ? path.relative(workspaceRoot, value).split(path.sep).join('/') : `external:${value}`
}

function isInside (candidate, parent) {
  const relative = path.relative(parent, candidate)
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative))
}

function digest (bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function validateIsoTimestamp (value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) || new Date(value).toISOString() !== value) {
    throw new Error('observedAt must be a canonical UTC ISO-8601 timestamp')
  }
  return value
}

function safeAbsolutePath (value, label) {
  if (!path.isAbsolute(value) || hasControlChars(value) || value.length > 4096) throw new Error(`${label} must be a bounded absolute path`)
  return path.resolve(value)
}

function assertDirectory (value, label) {
  const stat = fs.lstatSync(value)
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error(`${label} must be a non-symlink directory`)
}

function assertGitWorktree (value, label) {
  assertDirectory(value, label)
  if (requiredGitText(value, ['rev-parse', '--is-inside-work-tree'], label) !== 'true') {
    throw new Error(`${label} must be a Git worktree`)
  }
}

function compareText (left, right) {
  return left < right ? -1 : (left > right ? 1 : 0)
}

function hasControlChars (value) {
  return Array.from(value).some(character => {
    const code = character.charCodeAt(0)
    return code <= 31 || code === 127
  })
}

function safeError (err) {
  return Array.from(String(err?.message || err || 'unknown error'), character => {
    const code = character.charCodeAt(0)
    return code <= 31 || code === 127 ? ' ' : character
  }).join('').slice(0, 1200)
}
