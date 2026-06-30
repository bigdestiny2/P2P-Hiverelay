#!/usr/bin/env node

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(here, '..')
const DEFAULT_MANIFEST = path.join(repoRoot, 'umbrel-app', 'umbrel-app.yml')
const PENDING_SUBMISSION_URL = 'https://github.com/getumbrel/umbrel-apps/pull/PENDING'
const OFFICIAL_UMBREL_PR_URL_PATTERN = /^https:\/\/github\.com\/getumbrel\/umbrel-apps\/pull\/[1-9][0-9]*$/

const usage = `
Usage:
  node scripts/check-official-umbrel-pr.mjs [--manifest umbrel-app/umbrel-app.yml] [--allow-placeholder] [--json]

Fails release handoff unless the official Umbrel manifest submission field is
a real getumbrel/umbrel-apps pull request URL. Use --allow-placeholder only for
the first pre-PR export, where the PENDING URL is expected and releaseNotes
must stay empty.
`

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

  const result = checkOfficialUmbrelPr({
    manifestFile: path.resolve(args.manifest || DEFAULT_MANIFEST),
    allowPlaceholder: Boolean(args.allowPlaceholder)
  })

  if (args.json) console.log(JSON.stringify(result, null, 2))
  else console.log(formatReport(result))

  if (!result.ok) process.exit(1)
}

export function checkOfficialUmbrelPr ({ manifestFile = DEFAULT_MANIFEST, allowPlaceholder = false } = {}) {
  const manifestPath = path.resolve(manifestFile)
  const errors = []
  const warnings = []
  let text = ''

  try {
    const stat = fs.lstatSync(manifestPath)
    if (stat.isSymbolicLink()) {
      errors.push('Official Umbrel manifest must not be a symlink.')
    } else if (!stat.isFile()) {
      errors.push('Official Umbrel manifest path must be a regular file.')
    } else {
      text = fs.readFileSync(manifestPath, 'utf8')
    }
  } catch (err) {
    errors.push(`Official Umbrel manifest is not readable: ${err.message}`)
  }

  const submission = text ? readYamlField(text, 'submission') : ''
  const releaseNotes = text ? readYamlField(text, 'releaseNotes') : ''
  const version = text ? readYamlField(text, 'version') : ''
  const id = text ? readYamlField(text, 'id') : ''

  if (!submission) {
    errors.push('Official Umbrel manifest submission must be set.')
  } else if (submission === PENDING_SUBMISSION_URL) {
    if (!allowPlaceholder) {
      errors.push('Official Umbrel submission is still PENDING; open or update the getumbrel/umbrel-apps draft PR and rerun with the real PR URL before reviewer handoff.')
    } else {
      warnings.push('Official Umbrel submission is still PENDING and is allowed only for pre-PR export.')
    }
    if (releaseNotes !== '') {
      errors.push('Official Umbrel releaseNotes must stay empty while submission is PENDING for a first official submission.')
    }
  } else if (!OFFICIAL_UMBREL_PR_URL_PATTERN.test(submission)) {
    errors.push('Official Umbrel submission must be a getumbrel/umbrel-apps pull request URL.')
  }

  return {
    ok: errors.length === 0,
    manifest: slash(path.relative(process.cwd(), manifestPath)) || manifestPath,
    id,
    version,
    submission,
    allowPlaceholder,
    errors,
    warnings
  }
}

function formatReport (result) {
  const lines = [
    'Official Umbrel PR submission check',
    `manifest=${result.manifest}`,
    `app=${result.id || '(missing)'}`,
    `version=${result.version || '(missing)'}`,
    `submission=${result.submission || '(missing)'}`
  ]

  for (const warning of result.warnings) lines.push(`WARN ${warning}`)
  for (const error of result.errors) lines.push(`FAIL ${error}`)

  if (result.ok) {
    if (result.submission === PENDING_SUBMISSION_URL) lines.push('PASS Placeholder submission is allowed for pre-PR export only.')
    else lines.push('PASS Official Umbrel submission is ready for reviewer handoff.')
  } else {
    lines.push('Blocked: official Umbrel App Store handoff still needs a real getumbrel/umbrel-apps PR URL.')
  }

  return lines.join('\n')
}

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
    if (arg === '--allow-placeholder') {
      out.allowPlaceholder = true
      continue
    }
    if (arg === '--manifest') {
      const value = argv[++i]
      if (!value || value.startsWith('--')) throw new Error('Missing value for --manifest')
      out.manifest = value
      continue
    }
    throw new Error(`Unknown argument: ${arg}`)
  }
  return out
}

function readYamlField (text, key) {
  const lines = text.split(/\r?\n/)
  const re = new RegExp(`^${escapeRegExp(key)}:\\s*(.*)$`)
  for (let i = 0; i < lines.length; i++) {
    const match = lines[i].match(re)
    if (!match) continue
    const raw = match[1].trim()
    if (raw.startsWith('|') || raw.startsWith('>')) {
      const block = []
      for (let j = i + 1; j < lines.length; j++) {
        const line = lines[j]
        if (line.trim() === '') {
          block.push('')
          continue
        }
        if (!/^[ \t]/.test(line)) break
        block.push(line.replace(/^[ \t]+/, ''))
      }
      return raw.startsWith('>') ? block.join(' ').trim() : block.join('\n').trim()
    }
    return unquoteYamlScalar(raw)
  }
  return ''
}

function unquoteYamlScalar (value) {
  if (value === '""' || value === "''") return ''
  if (value.startsWith('"') && value.endsWith('"')) {
    try {
      return JSON.parse(value)
    } catch {
      return value.slice(1, -1)
    }
  }
  if (value.startsWith("'") && value.endsWith("'")) {
    return value.slice(1, -1).replaceAll("''", "'")
  }
  return value
}

function escapeRegExp (value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function slash (value) {
  return value.replace(/\\/g, '/')
}

if (import.meta.url === `file://${process.argv[1]}`) main()
