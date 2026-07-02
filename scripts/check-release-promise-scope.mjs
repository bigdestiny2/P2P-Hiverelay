#!/usr/bin/env node

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import {
  findOverbroadReleasePromises,
  NARROW_RELEASE_PROMISE_LABEL
} from './lib/release-promise-scope.mjs'

const here = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(here, '..')

const usage = `
Usage:
  node scripts/check-release-promise-scope.mjs [--json] [--text <release-notes>] [--file <path>]

With no --text/--file, checks the public release-promise surfaces in this repo:
the prepare-release default notes and the official Umbrel PR body template.
This intentionally does not scan all technical docs; optional services can be
documented internally while the public release handoff stays scoped to
${NARROW_RELEASE_PROMISE_LABEL}.
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

  const report = checkReleasePromiseScope({
    root: path.resolve(args.root || repoRoot),
    text: args.text,
    file: args.file
  })

  if (args.json) console.log(JSON.stringify(report, null, 2))
  else console.log(formatReport(report))

  if (report.status !== 'pass') process.exit(1)
}

export function checkReleasePromiseScope ({ root = repoRoot, text = null, file = null } = {}) {
  const targets = []
  if (text != null) {
    targets.push({ id: 'inline', label: 'inline release text', text: String(text) })
  }
  if (file) {
    const abs = path.resolve(root, file)
    targets.push({ id: slash(path.relative(root, abs)), label: 'release text file', text: fs.readFileSync(abs, 'utf8') })
  }
  if (targets.length === 0) targets.push(...defaultTargets(root))

  const items = targets.map(target => {
    const findings = findOverbroadReleasePromises(target.text)
    return {
      id: target.id,
      status: findings.length === 0 ? 'pass' : 'fail',
      label: target.label,
      findings
    }
  })

  const failed = items.filter(item => item.status === 'fail')
  return {
    schemaVersion: 1,
    kind: 'hiverelay-release-promise-scope',
    scope: NARROW_RELEASE_PROMISE_LABEL,
    status: failed.length === 0 ? 'pass' : 'fail',
    totals: {
      pass: items.length - failed.length,
      fail: failed.length
    },
    items
  }
}

function defaultTargets (root) {
  const prepareRelease = read(path.join(root, 'scripts', 'prepare-release.mjs'))
  const workflow = read(path.join(root, '.github', 'workflows', 'release-surfaces.yml'))
  return [
    {
      id: 'prepare-release.default-notes',
      label: 'prepare-release default release notes',
      text: extractPrepareReleaseDefaultNotes(prepareRelease)
    },
    {
      id: 'release-surfaces.official-umbrel-pr-body',
      label: 'official Umbrel PR body template',
      text: extractOfficialUmbrelPrBody(workflow)
    }
  ]
}

function extractPrepareReleaseDefaultNotes (source) {
  const match = source.match(/`Blindspark \$\{tag\}:([^`]+)`/)
  return match ? `Blindspark ${match[1]}` : source
}

function extractOfficialUmbrelPrBody (source) {
  const start = source.indexOf('cat > "$pr_body" <<BODY')
  if (start === -1) return source
  const bodyStart = source.indexOf('\n', start)
  const bodyEnd = source.indexOf('\n          BODY', bodyStart)
  if (bodyStart === -1 || bodyEnd === -1) return source.slice(start)
  return source.slice(bodyStart, bodyEnd)
}

function formatReport (report) {
  const lines = [
    'HiveRelay release-promise scope check',
    `scope=${report.scope}`,
    `status=${report.status}`,
    `pass=${report.totals.pass} fail=${report.totals.fail}`
  ]
  for (const item of report.items) {
    lines.push(`${item.status.toUpperCase()} ${item.id} — ${item.label}`)
    for (const finding of item.findings) {
      lines.push(`  ${finding.name}: ${JSON.stringify(finding.match)}`)
    }
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
    if (arg === '--text') {
      out.text = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--file') {
      out.file = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--root') {
      out.root = readValue(argv, ++i, arg)
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

function read (file) {
  const stat = fs.lstatSync(file)
  if (stat.isSymbolicLink()) throw new Error(`${file} must not be a symlink`)
  if (!stat.isFile()) throw new Error(`${file} must be a regular file`)
  return fs.readFileSync(file, 'utf8')
}

function slash (value) {
  return value.replace(/\\/g, '/')
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) main()
