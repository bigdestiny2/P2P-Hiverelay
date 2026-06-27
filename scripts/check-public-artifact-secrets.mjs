#!/usr/bin/env node

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(here, '..')

const DEFAULT_TARGETS = [
  'README.md',
  'docs',
  '.github'
]

const SKIP_DIRS = new Set([
  '.git',
  'node_modules'
])

const SKIP_EXTENSIONS = new Set([
  '.gif',
  '.jpg',
  '.jpeg',
  '.pdf',
  '.png',
  '.svg',
  '.webp'
])

const PATTERNS = [
  {
    name: 'GitHub token prefix example',
    regex: /(?:gh[pousr]_|github_pat_)/
  },
  {
    name: 'private key delimiter example',
    regex: /-----BEGIN (?:OPENSSH |RSA |EC |)PRIVATE KEY-----/
  },
  {
    name: 'Bearer authorization example',
    regex: /Authorization:\s*Bearer\s+[A-Za-z0-9_-]{20,}/
  }
]

const usage = `
Usage:
  node scripts/check-public-artifact-secrets.mjs [--root <path>] [--json]

Scans public documentation and GitHub workflow files for scanner-sensitive
secret examples. Test fixtures and implementation regexes are intentionally
outside this audit; this command protects files that are likely to be read,
copied, or scanned as public release artifacts.
`

if (isMain()) main()

export function scanPublicArtifacts (opts = {}) {
  const root = path.resolve(opts.root || repoRoot)
  const targets = opts.targets || DEFAULT_TARGETS
  const files = []

  for (const target of targets) {
    const abs = path.resolve(root, target)
    if (!exists(abs)) continue
    collectFiles(abs, files)
  }

  const findings = []
  for (const file of files) {
    const rel = slash(path.relative(root, file))
    const text = fs.readFileSync(file, 'utf8')
    for (const pattern of PATTERNS) {
      const lines = findPatternLines(text, pattern.regex)
      for (const line of lines) {
        findings.push({
          path: rel,
          line,
          pattern: pattern.name
        })
      }
    }
  }

  return {
    ok: findings.length === 0,
    filesScanned: files.length,
    findings
  }
}

function main () {
  const args = parseArgs(process.argv.slice(2))
  const result = scanPublicArtifacts({ root: args.root })

  if (args.json) {
    console.log(JSON.stringify(result, null, 2))
  } else if (result.ok) {
    console.log(`Public artifact secret-pattern audit passed (${result.filesScanned} files scanned).`)
  } else {
    console.error('Public artifact secret-pattern audit failed:')
    for (const finding of result.findings) {
      console.error(`- ${finding.path}:${finding.line} ${finding.pattern}`)
    }
  }

  process.exit(result.ok ? 0 : 1)
}

function collectFiles (entry, out) {
  const stat = fs.statSync(entry)
  if (stat.isDirectory()) {
    const name = path.basename(entry)
    if (SKIP_DIRS.has(name)) return
    for (const child of fs.readdirSync(entry).sort()) {
      collectFiles(path.join(entry, child), out)
    }
    return
  }

  if (!stat.isFile()) return
  if (SKIP_EXTENSIONS.has(path.extname(entry).toLowerCase())) return
  out.push(entry)
}

function findPatternLines (text, regex) {
  const lines = String(text || '').split(/\r?\n/)
  const hits = []
  for (let i = 0; i < lines.length; i++) {
    if (regex.test(lines[i])) hits.push(i + 1)
  }
  return hits
}

function parseArgs (argv) {
  const out = {}
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--help' || arg === '-h') {
      console.log(usage.trim())
      process.exit(0)
    }
    if (arg === '--root') {
      out.root = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--json') {
      out.json = true
      continue
    }
    die(`Unknown argument: ${arg}`)
  }
  return out
}

function readValue (argv, index, flag) {
  const value = argv[index]
  if (!value || value.startsWith('--')) die(`Missing value for ${flag}`)
  return value
}

function exists (file) {
  try {
    fs.accessSync(file)
    return true
  } catch (_) {
    return false
  }
}

function slash (value) {
  return String(value).split(path.sep).join('/')
}

function isMain () {
  return process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
}

function die (message) {
  console.error(message)
  process.exit(1)
}
