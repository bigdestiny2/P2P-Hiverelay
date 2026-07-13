#!/usr/bin/env node

import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import {
  normalizePublicHiveGatewayReleaseManifest,
  PUBLIC_HIVE_GATEWAY_RELEASE_MANIFEST_PATH,
  PUBLIC_HIVE_GATEWAY_RELEASE_SCHEMA
} from './lib/public-hive-gateway-release-manifest.mjs'

const MAX_MANIFEST_BYTES = 2 * 1024 * 1024
const RELEASE_TAG_PATTERN = /^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/
const CHANNELS = new Set(['canary', 'stable', 'both', 'none'])
const FORMATS = new Set(['json', 'github'])
const GIT_PROGRAM = '/usr/bin/git'
const UNSAFE_GIT_ENV = new Set([
  'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_COMMON_DIR', 'GIT_CONFIG',
  'GIT_CONFIG_COUNT', 'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_PARAMETERS',
  'GIT_CONFIG_SYSTEM', 'GIT_DIR', 'GIT_EXEC_PATH', 'GIT_GRAFT_FILE',
  'GIT_INDEX_FILE', 'GIT_NAMESPACE', 'GIT_OBJECT_DIRECTORY', 'GIT_PREFIX',
  'GIT_QUARANTINE_PATH', 'GIT_REPLACE_REF_BASE', 'GIT_SHALLOW_FILE',
  'GIT_WORK_TREE'
])

const usage = `
Usage:
  node scripts/resolve-public-hive-gateway-release.mjs \\
    --repo <git-repository> --ref <tag-or-commit> \\
    --release-target <vX.Y.Z> \\
    --requested-channel <canary|stable|both|none> \\
    [--format <json|github>]

The canonical manifest path is fixed at
${PUBLIC_HIVE_GATEWAY_RELEASE_MANIFEST_PATH}. Missing and explicitly disabled
manifests preserve the requested channel. A fully valid enabled manifest forces
the effective release channel to none.
`

try {
  const args = parseArgs(process.argv.slice(2))
  if (args.help) {
    console.log(usage.trim())
    process.exit(0)
  }
  const resolution = resolvePublicHiveGatewayRelease(args)
  if (args.format === 'github') writeGitHubOutput(resolution)
  else process.stdout.write(JSON.stringify(resolution, null, 2) + '\n')
} catch (err) {
  const message = boundedError(err)
  console.error(`Public gateway release resolution failed: ${message}`)
  process.exit(1)
}

export function resolvePublicHiveGatewayRelease ({ repo, ref, releaseTarget, requestedChannel }) {
  const repoRoot = resolveRepo(repo)
  requireSafeRef(ref)
  if (!RELEASE_TAG_PATTERN.test(releaseTarget || '')) {
    throw new Error('--release-target must be a v-prefixed semver tag')
  }
  if (!CHANNELS.has(requestedChannel)) {
    throw new Error('--requested-channel must be canary, stable, both, or none')
  }

  const commitSha = resolveCommit(repoRoot, ref)
  const blob = readCanonicalManifestBlob(repoRoot, commitSha)
  if (!blob) {
    return resolution({
      status: 'missing',
      enabled: false,
      releaseTarget,
      requestedChannel,
      effectiveChannel: requestedChannel,
      ref,
      commitSha,
      manifestSha256: '',
      admissionProfile: '',
      cohortSize: 0
    })
  }

  let manifest
  try {
    manifest = JSON.parse(blob.bytes.toString('utf8'))
  } catch (err) {
    throw new Error(`canonical manifest must be valid JSON: ${err.message}`)
  }
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    throw new Error('canonical manifest must be a JSON object')
  }
  if (manifest.schema !== PUBLIC_HIVE_GATEWAY_RELEASE_SCHEMA) {
    throw new Error(`canonical manifest schema must equal ${JSON.stringify(PUBLIC_HIVE_GATEWAY_RELEASE_SCHEMA)}`)
  }
  if (manifest.enabled !== true && manifest.enabled !== false) {
    throw new Error('canonical manifest enabled must be true or false')
  }

  const manifestSha256 = createHash('sha256').update(blob.bytes).digest('hex')
  if (manifest.enabled === false) {
    return resolution({
      status: 'disabled',
      enabled: false,
      releaseTarget,
      requestedChannel,
      effectiveChannel: requestedChannel,
      ref,
      commitSha,
      manifestSha256,
      admissionProfile: '',
      cohortSize: 0
    })
  }

  const normalized = normalizePublicHiveGatewayReleaseManifest(manifest, {
    releaseTarget,
    requirePublicT1: true
  })
  return resolution({
    status: 'enabled',
    enabled: true,
    releaseTarget,
    requestedChannel,
    effectiveChannel: 'none',
    ref,
    commitSha,
    manifestSha256,
    admissionProfile: normalized.admissionProfile,
    cohortSize: normalized.cohort.length
  })
}

function resolution (values) {
  return Object.freeze({
    schema: 'hiverelay-public-gateway-release-resolution-v1',
    manifestPath: PUBLIC_HIVE_GATEWAY_RELEASE_MANIFEST_PATH,
    ...values
  })
}

function parseArgs (argv) {
  const out = { format: 'json' }
  const seen = new Set()
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--help' || arg === '-h') {
      if (seen.has('help')) throw new Error(`duplicate argument: ${arg}`)
      seen.add('help')
      out.help = true
      continue
    }
    const names = {
      '--repo': 'repo',
      '--ref': 'ref',
      '--release-target': 'releaseTarget',
      '--requested-channel': 'requestedChannel',
      '--format': 'format'
    }
    const name = names[arg]
    if (!name) throw new Error(`unknown argument: ${arg}`)
    if (seen.has(name)) throw new Error(`duplicate argument: ${arg}`)
    seen.add(name)
    const value = argv[++i]
    if (!value || value.startsWith('--')) throw new Error(`missing value for ${arg}`)
    out[name] = value
  }
  if (out.help) return out
  for (const name of ['repo', 'ref', 'releaseTarget', 'requestedChannel']) {
    if (!out[name]) throw new Error(`missing required argument: ${argumentName(name)}`)
  }
  if (!FORMATS.has(out.format)) throw new Error('--format must be json or github')
  return out
}

function argumentName (name) {
  return ({
    repo: '--repo',
    ref: '--ref',
    releaseTarget: '--release-target',
    requestedChannel: '--requested-channel'
  })[name]
}

function resolveRepo (value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 4096 || hasControlChars(value)) {
    throw new Error('--repo is invalid')
  }
  let resolved
  try {
    resolved = fs.realpathSync(path.resolve(value))
  } catch {
    throw new Error(`repository does not exist: ${value}`)
  }
  const result = git(resolved, ['rev-parse', '--is-inside-work-tree'])
  if (result.stdout.toString('utf8').trim() !== 'true') throw new Error('--repo must name a Git work tree')
  return resolved
}

function requireSafeRef (value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 256 || value.startsWith('-') ||
      hasControlChars(value) || !/^[A-Za-z0-9][A-Za-z0-9._/@{}^~:+-]*$/.test(value)) {
    throw new Error('--ref is invalid')
  }
}

function resolveCommit (repo, ref) {
  const result = git(repo, ['rev-parse', '--verify', '--end-of-options', `${ref}^{commit}`])
  const sha = result.stdout.toString('utf8').trim()
  if (!/^[a-f0-9]{40}$/i.test(sha)) throw new Error(`ref did not resolve to a commit: ${ref}`)
  return sha.toLowerCase()
}

function readCanonicalManifestBlob (repo, commitSha) {
  const tree = git(repo, [
    'ls-tree',
    '-z',
    '--full-tree',
    commitSha,
    '--',
    PUBLIC_HIVE_GATEWAY_RELEASE_MANIFEST_PATH
  ]).stdout
  if (tree.length === 0) return null

  const records = tree.toString('utf8').split('\0').filter(Boolean)
  if (records.length !== 1) throw new Error('canonical manifest path resolved ambiguously')
  const match = /^(100644|100755) (blob) ([a-f0-9]{40})\t(.+)$/.exec(records[0])
  if (!match || match[4] !== PUBLIC_HIVE_GATEWAY_RELEASE_MANIFEST_PATH) {
    throw new Error('canonical manifest path must resolve to one regular Git blob')
  }

  const sizeResult = git(repo, ['cat-file', '-s', match[3]])
  const sizeText = sizeResult.stdout.toString('utf8').trim()
  if (!/^(?:0|[1-9][0-9]*)$/.test(sizeText)) throw new Error('canonical manifest blob size is malformed')
  const size = Number(sizeText)
  if (!Number.isSafeInteger(size) || size < 1 || size > MAX_MANIFEST_BYTES) {
    throw new Error(`canonical manifest must be between 1 and ${MAX_MANIFEST_BYTES} bytes`)
  }
  const bytes = git(repo, ['cat-file', 'blob', match[3]], MAX_MANIFEST_BYTES + 1).stdout
  if (bytes.length !== size) throw new Error('canonical manifest blob length changed while reading')
  return { bytes }
}

function git (cwd, args, maxBuffer = 256 * 1024) {
  const result = spawnSync(GIT_PROGRAM, ['--no-replace-objects', ...args], {
    cwd,
    encoding: null,
    env: hardenedGitEnv({
      GIT_GRAFT_FILE: '/dev/null/hiverelay-disabled',
      GIT_NO_REPLACE_OBJECTS: '1'
    }),
    maxBuffer,
    timeout: 10000,
    windowsHide: true
  })
  if (result.error) throw new Error(`git ${args[0]} failed: ${result.error.message}`)
  if (result.status !== 0) {
    const stderr = String(result.stderr || '').trim().replace(/[\r\n]+/g, ' ')
    throw new Error(`git ${args[0]} failed${stderr ? `: ${stderr}` : ''}`)
  }
  return result
}

function writeGitHubOutput (value) {
  const lines = [
    ['effective_channel', value.effectiveChannel],
    ['public_gateway_enabled', value.enabled ? 'true' : 'false'],
    ['public_gateway_manifest_status', value.status],
    ['public_gateway_manifest_path', value.manifestPath],
    ['public_gateway_manifest_sha256', value.manifestSha256],
    ['public_gateway_release_target', value.releaseTarget],
    ['public_gateway_commit_sha', value.commitSha],
    ['public_gateway_admission_profile', value.admissionProfile],
    ['public_gateway_cohort_size', value.cohortSize]
  ]
  for (const [name, rawValue] of lines) {
    const stringValue = String(rawValue)
    if (hasControlChars(stringValue)) throw new Error(`refusing unsafe GitHub output for ${name}`)
    process.stdout.write(`${name}=${stringValue}\n`)
  }
}

function hasControlChars (value) {
  for (const character of String(value)) {
    const code = character.charCodeAt(0)
    if (code <= 31 || code === 127) return true
  }
  return false
}

function hardenedGitEnv (overrides) {
  const env = { ...process.env }
  for (const name of Object.keys(env)) {
    if (UNSAFE_GIT_ENV.has(name) || /^GIT_CONFIG_(?:KEY|VALUE)_\d+$/.test(name)) delete env[name]
  }
  return { ...env, ...overrides }
}

function boundedError (err) {
  const message = String(err?.message || err || 'unknown error').replace(/[\r\n]+/g, ' ')
  return message.length > 1000 ? message.slice(0, 1000) + '…' : message
}
