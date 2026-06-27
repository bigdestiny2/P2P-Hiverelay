#!/usr/bin/env node

import fs from 'node:fs'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import {
  CURRENT_HIVERELAY_VERSION,
  getExpectedCurrentConsumers,
  normalizeConsumerScope
} from './audit-ecosystem-consumers.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const hiverelayRoot = path.resolve(here, '..')
const workspaceRootDefault = path.resolve(hiverelayRoot, '..', '..')

const usage = `
Usage:
  node scripts/commit-ecosystem-consumers.mjs [--workspace-root <path>] [--version <vX.Y.Z>] [--consumer-scope <release|all>] [--no-push] [--check] [--github-env <path>]

Commits and pushes release-managed ecosystem app consumer changes after
release:prepare has moved their Hiverelay defaults to npm latest.
`

if (isMain()) main()

export function commitEcosystemConsumers (opts = {}) {
  const workspaceRoot = path.resolve(opts.workspaceRoot || workspaceRootDefault)
  const version = normalizeVersion(opts.version || CURRENT_HIVERELAY_VERSION)
  const consumerScope = normalizeConsumerScope(opts.consumerScope || 'release')
  const push = opts.push !== false && !opts.check
  const check = Boolean(opts.check)
  const expectedCurrent = opts.expectedCurrent || getExpectedCurrentConsumers({
    dependencyMode: 'npm-latest',
    consumerScope
  })
  const repos = releaseRepos(expectedCurrent)
  const rows = []
  const errors = []

  for (const repo of repos) {
    const repoRoot = path.join(workspaceRoot, repo.checkoutPath)
    const label = `${repo.repository}@${repo.ref}`
    if (!fs.existsSync(path.join(repoRoot, '.git'))) {
      errors.push(`${repo.checkoutPath}: missing git checkout for ${label}`)
      continue
    }

    const porcelain = git(repoRoot, ['status', '--porcelain'])
    if (!porcelain.ok) {
      errors.push(`${repo.checkoutPath}: ${porcelain.error}`)
      continue
    }
    if (!porcelain.stdout.trim()) {
      rows.push({ ...repo, status: 'current', commit: gitHead(repoRoot) })
      continue
    }

    if (check) {
      errors.push(`${repo.checkoutPath}: ecosystem consumer changes are not committed`)
      rows.push({ ...repo, status: 'dirty', commit: gitHead(repoRoot) })
      continue
    }

    const configName = git(repoRoot, ['config', 'user.name', 'hiverelay-release-bot'])
    const configEmail = git(repoRoot, ['config', 'user.email', 'hiverelay-release-bot@users.noreply.github.com'])
    const add = git(repoRoot, ['add', '-A'])
    const commit = git(repoRoot, ['commit', '-m', `chore: sync HiveRelay defaults ${version}`])
    if (!configName.ok || !configEmail.ok || !add.ok || !commit.ok) {
      errors.push(`${repo.checkoutPath}: ${firstError(configName, configEmail, add, commit)}`)
      continue
    }

    const commitSha = gitHead(repoRoot)
    if (push) {
      const pushed = git(repoRoot, ['push', 'origin', `HEAD:${repo.ref}`])
      if (!pushed.ok) {
        errors.push(`${repo.checkoutPath}: ${pushed.error}`)
        continue
      }
    }

    rows.push({ ...repo, status: push ? 'pushed' : 'committed', commit: commitSha })
  }

  return {
    ok: errors.length === 0,
    workspaceRoot,
    version,
    consumerScope,
    push,
    check,
    rows,
    errors
  }
}

function releaseRepos (expectedCurrent) {
  const repos = new Map()
  for (const consumer of expectedCurrent) {
    if (!consumer.release) continue
    const key = consumer.release.checkoutPath
    repos.set(key, {
      repository: consumer.release.repository,
      ref: consumer.release.ref,
      checkoutPath: consumer.release.checkoutPath
    })
  }
  return Array.from(repos.values()).sort((a, b) => a.checkoutPath.localeCompare(b.checkoutPath))
}

function gitHead (cwd) {
  const result = git(cwd, ['rev-parse', 'HEAD'])
  return result.ok ? result.stdout.trim() : ''
}

function git (cwd, argv) {
  const result = spawnSync('git', argv, {
    cwd,
    encoding: 'utf8',
    maxBuffer: 1024 * 1024
  })
  if (result.error) return { ok: false, error: result.error.message, stdout: '', stderr: '' }
  if (result.status !== 0) {
    return {
      ok: false,
      error: (result.stderr || result.stdout || `git ${argv.join(' ')} exited ${result.status}`).trim(),
      stdout: result.stdout || '',
      stderr: result.stderr || ''
    }
  }
  return { ok: true, stdout: result.stdout || '', stderr: result.stderr || '' }
}

function firstError (...results) {
  return results.find(result => !result.ok)?.error || 'unknown git failure'
}

function normalizeVersion (value) {
  const input = String(value || '').trim()
  const match = input.match(/^v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$/)
  if (!match) throw new Error(`Invalid --version ${JSON.stringify(value)}. Expected vX.Y.Z or X.Y.Z.`)
  return `v${match[1]}`
}

function parseArgs (argv) {
  const out = {
    consumerScope: 'release',
    push: true,
    check: false
  }
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--help' || arg === '-h') {
      console.log(usage.trim())
      process.exit(0)
    }
    if (arg === '--workspace-root') {
      out.workspaceRoot = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--version') {
      out.version = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--consumer-scope') {
      out.consumerScope = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--github-env') {
      out.githubEnv = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--no-push') {
      out.push = false
      continue
    }
    if (arg === '--check') {
      out.check = true
      out.push = false
      continue
    }
    throw new Error(`Unknown argument: ${arg}`)
  }
  return out
}

function readValue (argv, index, flag) {
  const value = argv[index]
  if (!value || value.startsWith('--')) throw new Error(`Missing value for ${flag}`)
  return value
}

function appendGithubEnv (file, result) {
  if (!file) return
  const status = result.ok
    ? result.rows.some(row => row.status === 'pushed' || row.status === 'committed') ? 'committed' : 'current'
    : 'failed'
  fs.appendFileSync(file, `HIVERELAY_ECOSYSTEM_CONSUMER_STATUS=${status}\n`)
  const commits = result.rows
    .filter(row => row.commit)
    .map(row => `${row.checkoutPath}@${row.commit}`)
    .join(',')
  fs.appendFileSync(file, `HIVERELAY_ECOSYSTEM_CONSUMER_COMMITS=${commits}\n`)
}

function main () {
  let args
  try {
    args = parseArgs(process.argv.slice(2))
    const result = commitEcosystemConsumers(args)
    appendGithubEnv(args.githubEnv, result)
    console.log(`HiveRelay ecosystem consumer commit (${result.workspaceRoot}, scope ${result.consumerScope}, target ${result.version})`)
    for (const row of result.rows) {
      const commit = row.commit ? ` ${row.commit}` : ''
      console.log(`- ${row.checkoutPath}: ${row.status}${commit}`)
    }
    for (const error of result.errors) console.error(`ERROR ${error}`)
    if (!result.ok) process.exit(1)
  } catch (err) {
    console.error(err.message)
    process.exit(1)
  }
}

function isMain () {
  return process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
}
