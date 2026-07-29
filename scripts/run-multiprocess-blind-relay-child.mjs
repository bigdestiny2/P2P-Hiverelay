#!/usr/bin/env node
import { createHash } from 'node:crypto'
import { execFile } from 'node:child_process'
import fs from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { runScopedRealBlindRelayLab } from './run-real-blind-relay-lab.mjs'
import {
  LOCAL_MULTIPROCESS_BLIND_CHILD_SCHEMA,
  sealLocalMultiprocessBlindChild,
  verifyLocalMultiprocessBlindChild
} from './verify-multiprocess-blind-relay-report.mjs'

const execFileAsync = promisify(execFile)
const REPOSITORY_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

function fail (message) {
  const error = new Error(message)
  error.code = 'BLIND_LOCAL_MULTIPROCESS_CHILD_INVALID'
  throw error
}

function boundedInteger (value, fallback, minimum, maximum, field) {
  if (value == null) return fallback
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail(`${field} must be an integer within ${minimum}..${maximum}`)
  }
  return value
}

function scopeName (value, field) {
  if (typeof value !== 'string' || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(value)) {
    fail(`${field} must match ^[a-z0-9][a-z0-9-]{0,63}$`)
  }
  return value
}

async function gitOutput (args) {
  const result = await execFileAsync('git', args, {
    cwd: REPOSITORY_ROOT,
    timeout: 10_000,
    maxBuffer: 1024 * 1024,
    encoding: 'utf8'
  })
  return result.stdout.trim()
}

async function trackedWorktreeClean () {
  for (const args of [
    ['diff', '--quiet'],
    ['diff', '--cached', '--quiet']
  ]) {
    try {
      await gitOutput(args)
    } catch (error) {
      if (error && error.code === 1) return false
      throw error
    }
  }
  return true
}

function parseCli (argv) {
  const options = {}
  for (let index = 0; index < argv.length; index++) {
    const value = argv[index]
    if (value === '--operator-scope') options.logicalOperatorScope = argv[++index]
    else if (value === '--identity-scope') options.identityScope = argv[++index]
    else if (value === '--root') options.root = argv[++index]
    else if (value === '--relays') options.relayCount = Number(argv[++index])
    else if (value === '--records') options.recordsPerRelay = Number(argv[++index])
    else if (value === '--concurrency') options.concurrency = Number(argv[++index])
    else if (value === '--content-bytes') options.contentBytes = Number(argv[++index])
    else if (value === '--keep') options.keep = true
    else fail(`unknown argument ${value}`)
  }
  options.logicalOperatorScope = scopeName(options.logicalOperatorScope, 'operator scope')
  options.identityScope = scopeName(options.identityScope, 'identity scope')
  if (typeof options.root !== 'string' || options.root.length === 0) fail('--root is required')
  options.relayCount = boundedInteger(options.relayCount, 2, 2, 8, 'relays')
  options.recordsPerRelay = boundedInteger(options.recordsPerRelay, 16, 1, 250000, 'records')
  options.concurrency = boundedInteger(options.concurrency, 8, 1, 128, 'concurrency')
  options.contentBytes = boundedInteger(options.contentBytes, 256, 32, 4000, 'content bytes')
  return options
}

export async function runLocalMultiprocessBlindChild (options) {
  if (typeof process.getuid !== 'function' || typeof process.getgid !== 'function') {
    fail('local multi-process blind child requires POSIX UID/GID and Unix sockets')
  }
  const startedAtMillis = Date.now()
  const root = await fs.realpath(options.root)
  const rootPathSha256 = createHash('sha256').update(root, 'utf8').digest('hex')
  const gitCommit = await gitOutput(['rev-parse', 'HEAD'])
  if (!/^[0-9a-f]{40}$/.test(gitCommit)) fail('git HEAD is not a full lowercase commit')
  const sourceClean = await trackedWorktreeClean()
  const { report, identities } = await runScopedRealBlindRelayLab({
    identityScope: options.identityScope,
    root,
    relayCount: options.relayCount,
    recordsPerRelay: options.recordsPerRelay,
    concurrency: options.concurrency,
    contentBytes: options.contentBytes,
    keep: options.keep === true
  })
  if (identities.identityScope !== options.identityScope ||
      identities.relays.length !== options.relayCount) {
    fail('real relay lab returned inconsistent scoped identity evidence')
  }
  const finishedAtMillis = Date.now()
  const finishedAt = new Date(finishedAtMillis).toISOString()
  const child = sealLocalMultiprocessBlindChild({
    schema: LOCAL_MULTIPROCESS_BLIND_CHILD_SCHEMA,
    generatedAt: finishedAt,
    source: {
      gitCommit,
      trackedWorktreeClean: sourceClean
    },
    process: {
      pid: process.pid,
      parentPid: process.ppid,
      uid: process.getuid(),
      gid: process.getgid(),
      logicalOperatorScope: options.logicalOperatorScope,
      identityScope: options.identityScope,
      rootPathSha256,
      startedAt: new Date(startedAtMillis).toISOString(),
      finishedAt,
      wallMs: finishedAtMillis - startedAtMillis
    },
    identity: {
      identityScope: identities.identityScope,
      relayCount: identities.relays.length,
      relayPublicKeys: identities.relays.map(relay => relay.relayPublicKey),
      storeIds: identities.relays.map(relay => relay.storeId),
      uniqueRelayPublicKeys: new Set(identities.relays.map(relay => relay.relayPublicKey)).size,
      uniqueStoreIds: new Set(identities.relays.map(relay => relay.storeId)).size
    },
    labReport: report
  })
  verifyLocalMultiprocessBlindChild(child)
  return child
}

async function main () {
  const options = parseCli(process.argv.slice(2))
  const child = await runLocalMultiprocessBlindChild(options)
  process.stdout.write(JSON.stringify(child) + '\n')
}

if (fileURLToPath(import.meta.url) === path.resolve(process.argv[1] || '')) {
  main().catch(error => {
    process.stderr.write(`[blind-local-multiprocess-child] ${error.code || 'ERROR'}: ${error.message}\n`)
    process.exitCode = 1
  })
}
