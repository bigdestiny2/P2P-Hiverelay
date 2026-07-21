#!/usr/bin/env node

import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(here, '..')

const DEFAULT_WORKSPACES = [
  'packages/core',
  'packages/client',
  'packages/services',
  'packages/verifier'
]

const REQUIRED_PACK_FILES = [
  'README.md',
  'LICENSE'
]

const UNSAFE_PACK_PATH_PATTERNS = [
  [/(^|\/)node_modules(\/|$)/, 'nested dependency directory'],
  [/(^|\/)(?:test|tests|__tests__)(\/|$)/, 'test directory'],
  [/(^|\/)docs(\/|$)/, 'docs directory'],
  [/(^|\/)\.git(\/|$)/, 'git metadata'],
  [/(^|\/)\.env(?:\.|$)/, 'env file'],
  [/(^|\/)\.npmrc$/, 'npm credentials file'],
  [/(^|\/)[^/]+\.(?:pem|key|p12|pfx)$/i, 'key material']
]

const usage = `
Usage:
  node scripts/check-npm-package-pack.mjs [--workspace <path>]... [--cache <path>] [--json]

Runs npm pack --dry-run --json for each publishable HiveRelay workspace and
fails if the tarball metadata is missing README/LICENSE files, resolves to the
wrong package name/version, does not contain every local package export target,
or includes obvious unsafe paths such as nested dependencies, tests, docs, env
files, npm credentials, or key material.
`

if (isMain()) main()

export function checkNpmPackagePack (opts = {}) {
  const cwd = path.resolve(opts.cwd || repoRoot)
  const workspaces = opts.workspaces?.length > 0 ? opts.workspaces : DEFAULT_WORKSPACES
  const cacheDir = opts.cacheDir || path.join(os.tmpdir(), 'hiverelay-npm-pack-cache')
  const runner = opts.runner || runNpmPack
  const rows = []
  const errors = []
  const warnings = []

  for (const workspace of workspaces) {
    const relWorkspace = slash(workspace)
    const workspaceDir = path.resolve(cwd, workspace)
    const manifestFile = path.join(workspaceDir, 'package.json')
    let manifest = null
    try {
      manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf8'))
    } catch (err) {
      const error = `${relWorkspace}: package.json is not readable JSON: ${err.message}`
      rows.push({ ok: false, workspace: relWorkspace, errors: [error], warnings: [] })
      errors.push(error)
      continue
    }

    let pack
    try {
      const result = runner({ cwd, workspace: relWorkspace, cacheDir })
      pack = parsePackJson(result.stdout)
    } catch (err) {
      const error = `${relWorkspace}: npm pack dry-run failed: ${err.message}`
      rows.push({ ok: false, workspace: relWorkspace, name: manifest.name, version: manifest.version, errors: [error], warnings: [] })
      errors.push(error)
      continue
    }

    const row = inspectPack({ workspace: relWorkspace, manifest, pack })
    rows.push(row)
    errors.push(...row.errors)
    warnings.push(...row.warnings)
  }

  return {
    ok: errors.length === 0,
    cacheDir,
    workspaces: rows,
    errors,
    warnings
  }
}

export function inspectPack ({ workspace, manifest, pack }) {
  const paths = Array.isArray(pack.files) ? pack.files.map(file => slash(file.path || '')) : []
  const errors = []
  const warnings = []

  if (pack.name !== manifest.name) {
    errors.push(`${workspace}: packed package name ${JSON.stringify(pack.name)} does not match package.json ${JSON.stringify(manifest.name)}`)
  }
  if (pack.version !== manifest.version) {
    errors.push(`${workspace}: packed package version ${JSON.stringify(pack.version)} does not match package.json ${JSON.stringify(manifest.version)}`)
  }

  for (const required of REQUIRED_PACK_FILES) {
    if (!paths.includes(required)) errors.push(`${workspace}: packed tarball is missing ${required}`)
    const files = Array.isArray(manifest.files) ? manifest.files : []
    if (!files.includes(required)) errors.push(`${workspace}: package.json files allowlist is missing ${required}`)
  }

  const unsafe = findUnsafePackPaths(paths)
  for (const issue of unsafe) {
    errors.push(`${workspace}: unsafe packed path ${issue.path} (${issue.reason})`)
  }

  const missingExportTargets = findMissingExportTargets(manifest.exports, paths)
  for (const issue of missingExportTargets) {
    errors.push(`${workspace}: packed tarball is missing export target ${issue.target} for ${issue.subpath}`)
  }

  if (Number.isFinite(pack.entryCount) && pack.entryCount !== paths.length) {
    warnings.push(`${workspace}: npm reported entryCount ${pack.entryCount} but listed ${paths.length} files`)
  }

  return {
    ok: errors.length === 0,
    workspace,
    name: pack.name || manifest.name,
    version: pack.version || manifest.version,
    filename: pack.filename || '',
    size: numberOrZero(pack.size),
    unpackedSize: numberOrZero(pack.unpackedSize),
    entryCount: Number.isFinite(pack.entryCount) ? pack.entryCount : paths.length,
    hasReadme: paths.includes('README.md'),
    hasLicense: paths.includes('LICENSE'),
    missingExportTargets,
    unsafe,
    errors,
    warnings
  }
}

export function findMissingExportTargets (exportsField, paths) {
  if (exportsField === undefined || exportsField === null) return []
  const packed = paths.map(path => slash(path))
  const targets = collectExportTargets(exportsField)
  return targets.filter(({ target }) => {
    if (!target.startsWith('./')) return false
    const normalized = target.slice(2)
    if (!normalized.includes('*')) return !packed.includes(normalized)
    return !packed.some(path => exportPatternMatches(normalized, path))
  })
}

export function parsePackJson (stdout) {
  let parsed
  try {
    parsed = JSON.parse(stdout)
  } catch (err) {
    throw new Error(`invalid npm pack JSON: ${err.message}`)
  }
  if (!Array.isArray(parsed) || parsed.length !== 1 || !parsed[0] || typeof parsed[0] !== 'object') {
    throw new Error('expected npm pack JSON array with one package object')
  }
  return parsed[0]
}

export function findUnsafePackPaths (paths) {
  const issues = []
  for (const raw of paths) {
    const file = slash(raw)
    for (const [pattern, reason] of UNSAFE_PACK_PATH_PATTERNS) {
      if (pattern.test(file)) issues.push({ path: file, reason })
    }
  }
  return issues
}

export function formatReport (result) {
  const lines = [
    `HiveRelay npm package pack check (${result.workspaces.length} workspace${result.workspaces.length === 1 ? '' : 's'})`
  ]

  for (const row of result.workspaces) {
    const status = row.ok ? 'PASS' : 'FAIL'
    lines.push(`${status} ${row.name || row.workspace}@${row.version || '(unknown)'}: workspace=${row.workspace}, entries=${row.entryCount}, size=${row.size}, unpacked=${row.unpackedSize}, README=${row.hasReadme}, LICENSE=${row.hasLicense}, exports=${row.missingExportTargets?.length ? `missing:${row.missingExportTargets.map(issue => issue.target).join(',')}` : 'closed'}, unsafe=${row.unsafe?.length ? row.unsafe.map(issue => issue.path).join(',') : 'none'}`)
    for (const warning of row.warnings || []) lines.push(`WARN ${warning}`)
    for (const error of row.errors || []) lines.push(`FAIL ${error}`)
  }

  if (result.ok) lines.push('All HiveRelay npm package dry-runs are publish-shape clean.')
  else lines.push('Blocked: npm package publish metadata or file lists need correction before release publication.')
  return lines.join('\n')
}

function runNpmPack ({ cwd, workspace, cacheDir }) {
  const result = spawnSync('npm', ['pack', '--dry-run', '--json', '--workspace', workspace], {
    cwd,
    encoding: 'utf8',
    env: {
      ...process.env,
      npm_config_cache: cacheDir
    },
    timeout: 60000
  })
  if (result.status !== 0) {
    const message = [result.stderr, result.stdout].filter(Boolean).join('\n').trim()
    throw new Error(message || `npm exited with status ${result.status}`)
  }
  return { stdout: result.stdout }
}

function parseArgs (argv) {
  const out = { workspaces: [], json: false }
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--help' || arg === '-h') {
      out.help = true
      continue
    }
    if (arg === '--json') {
      out.json = true
      continue
    }
    if (arg === '--workspace') {
      const value = argv[++i]
      if (!value || value.startsWith('--')) throw new Error('Missing value for --workspace')
      out.workspaces.push(value)
      continue
    }
    if (arg === '--cache') {
      const value = argv[++i]
      if (!value || value.startsWith('--')) throw new Error('Missing value for --cache')
      out.cacheDir = value
      continue
    }
    throw new Error(`Unknown argument: ${arg}`)
  }
  return out
}

function main () {
  let args
  try {
    args = parseArgs(process.argv.slice(2))
  } catch (err) {
    console.error(err.message)
    console.error(usage.trim())
    process.exit(1)
  }

  if (args.help) {
    console.log(usage.trim())
    return
  }

  const result = checkNpmPackagePack({
    cwd: repoRoot,
    workspaces: args.workspaces,
    cacheDir: args.cacheDir
  })

  if (args.json) console.log(JSON.stringify(result, null, 2))
  else console.log(formatReport(result))

  if (!result.ok) process.exit(1)
}

function isMain () {
  return import.meta.url === `file://${process.argv[1]}`
}

function collectExportTargets (value, subpath = '.') {
  if (typeof value === 'string') return [{ subpath, target: value }]
  if (Array.isArray(value)) return value.flatMap(item => collectExportTargets(item, subpath))
  if (!value || typeof value !== 'object') return []

  const rows = []
  for (const [key, nested] of Object.entries(value)) {
    const nextSubpath = key === '.' || key.startsWith('./') ? key : subpath
    rows.push(...collectExportTargets(nested, nextSubpath))
  }
  return rows
}

function exportPatternMatches (pattern, file) {
  const escaped = pattern
    .split('*')
    .map(part => part.replace(/[|\\{}()[\]^$+?.]/g, '\\$&'))
    .join('.*')
  return new RegExp(`^${escaped}$`).test(file)
}

function slash (value) {
  return String(value).replace(/\\/g, '/')
}

function numberOrZero (value) {
  return Number.isFinite(value) ? value : 0
}
