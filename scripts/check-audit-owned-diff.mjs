#!/usr/bin/env node

import fs from 'node:fs'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { buildOwnedDiffReport } from './lib/audit-owned-diff.mjs'

const usage = `
Usage:
  node scripts/check-audit-owned-diff.mjs [--json]
  node scripts/check-audit-owned-diff.mjs --status-file <git-status-fixture> [--json]

Options:
  --root <path>         Repository root. Defaults to the HiveRelay checkout.
  --status-file <path>  Read git status --porcelain=v1 output from a fixture.
  --json                Print machine-readable output.
`

const here = path.dirname(fileURLToPath(import.meta.url))
const defaultRoot = path.resolve(here, '..')

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
  process.exit(0)
}

const root = path.resolve(args.root || defaultRoot)
let statusText

try {
  statusText = readStatusText(root, args.statusFile)
} catch (err) {
  const report = {
    schemaVersion: 1,
    kind: 'hiverelay-audit-owned-diff',
    scope: 'audit-owned development diff only; release closure still requires a clean worktree',
    status: 'error',
    error: err.message
  }
  if (args.json) console.log(JSON.stringify(report, null, 2))
  else {
    console.log('HiveRelay audit-owned diff check')
    console.log('status=error')
    console.log(err.message)
  }
  process.exit(1)
}

const report = buildOwnedDiffReport(statusText)

if (args.json) console.log(JSON.stringify(report, null, 2))
else console.log(formatReport(report))

process.exit(report.status === 'pass' ? 0 : 1)

function parseArgs (argv) {
  const out = {}
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
    if (arg === '--root') {
      out.root = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--status-file') {
      out.statusFile = readValue(argv, ++i, arg)
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

function readStatusText (root, statusFile) {
  if (statusFile) return fs.readFileSync(path.resolve(statusFile), 'utf8')

  const res = spawnSync('git', ['status', '--porcelain=v1'], {
    cwd: root,
    encoding: 'utf8',
    timeout: 10000
  })

  if (res.error) throw new Error(`git status failed: ${res.error.message}`)
  if (res.status !== 0) throw new Error(`git status failed: ${(res.stderr || '').trim() || `exit ${res.status}`}`)
  return res.stdout
}

function formatReport (report) {
  const lines = [
    'HiveRelay audit-owned diff check',
    `scope=${report.scope}`,
    `status=${report.status}`,
    `changed=${report.totals.changed} owned=${report.totals.owned} unknown=${report.totals.unknown} slices=${report.totals.slices}`
  ]

  if (report.entries.length === 0) {
    lines.push('PASS worktree has no changed or untracked paths.')
    return lines.join('\n')
  }

  for (const entry of report.entries) {
    const owners = entry.owners.map(owner => owner.id).join(', ')
    lines.push(`${entry.owners.length === 0 ? 'FAIL' : 'PASS'} ${entry.status} ${entry.path} — ${owners || 'unowned'}`)
  }

  if (report.unknown.length > 0) {
    lines.push('Unknown paths must be assigned to an audit slice before this development diff is reviewable.')
  }

  return lines.join('\n')
}
