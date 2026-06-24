#!/usr/bin/env node

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(__dirname, '..')

const usage = `
Usage:
  node scripts/export-official-umbrel-app.mjs --target <umbrel-apps/blindspark> [options]

Options:
  --target <path>             Destination app directory in a getumbrel/umbrel-apps checkout
  --submission-url <url>      Replace the manifest submission field with the real PR URL
  --allow-placeholder         Permit the PENDING submission URL for the pre-PR export
  --check                     Verify the target is already in sync without writing
`

const args = parseArgs(process.argv.slice(2))
const target = args.target ? path.resolve(args.target) : ''
const checkOnly = Boolean(args.check)
const allowPlaceholder = Boolean(args.allowPlaceholder)
const submissionUrl = args.submissionUrl || ''

if (!target) die(usage.trim())
if (path.basename(target) !== 'blindspark') {
  die(`Refusing to export to ${target}; target directory must be named "blindspark".`)
}

if (submissionUrl && !/^https:\/\/github\.com\/getumbrel\/umbrel-apps\/pull\/[1-9][0-9]*$/.test(submissionUrl)) {
  die('--submission-url must be a getumbrel/umbrel-apps pull request URL.')
}

const manifest = normalizeManifest(readSource('umbrel-app.yml'))
const compose = readSource('docker-compose.yml')
const expected = new Map([
  ['umbrel-app.yml', manifest],
  ['docker-compose.yml', compose],
  ['data/.gitkeep', '']
])

assertSafeTargetRoot(target)
assertSafeTargetPaths(target, expected.keys())

if (!submissionUrl && !allowPlaceholder && manifest.includes('/pull/PENDING')) {
  die('Official export still has the PENDING submission URL. Pass --submission-url <PR URL> after opening the PR, or --allow-placeholder for the first pre-PR export.')
}

const extras = listExistingFiles(target).filter((file) => !expected.has(file))
if (extras.length > 0) {
  die('Official Umbrel app directory contains files that should not be in the PR:\n' + extras.map((file) => `- ${file}`).join('\n'))
}

const drift = []
for (const [rel, content] of expected) {
  const file = path.join(target, rel)
  if (fs.existsSync(file) && fs.readFileSync(file, 'utf8') === content) continue
  drift.push(rel)
}

if (checkOnly) {
  if (drift.length > 0) {
    die('Official Umbrel export is out of sync:\n' + drift.map((file) => `- ${file}`).join('\n'))
  }
  console.log(`Official Umbrel export is in sync at ${target}.`)
  process.exit(0)
}

for (const [rel, content] of expected) {
  const file = path.join(target, rel)
  fs.mkdirSync(path.dirname(file), { recursive: true })
  fs.writeFileSync(file, content)
}

console.log(`Official Umbrel app package exported to ${target}.`)
if (drift.length > 0) {
  for (const file of drift) console.log(`- wrote ${file}`)
} else {
  console.log('- no file changes needed')
}

function normalizeManifest (input) {
  let text = input
  text = replaceYamlField(text, 'manifestVersion', 'manifestVersion: 1.1')
  text = replaceYamlField(text, 'gallery', 'gallery: []')
  text = replaceYamlField(text, 'releaseNotes', 'releaseNotes: ""')
  if (submissionUrl) {
    text = replaceYamlField(text, 'submission', `submission: ${submissionUrl}`)
  }
  text = text.replace(/^icon:.*\n?/m, '')
  if (!/\n$/.test(text)) text += '\n'
  return text
}

function replaceYamlField (text, key, replacement) {
  const re = new RegExp(`^${escapeRegExp(key)}:.*(?:\\n[ \\t].*)*`, 'm')
  if (!re.test(text)) die(`Could not find ${key} in umbrel-app.yml.`)
  return text.replace(re, replacement)
}

function readSource (file) {
  return fs.readFileSync(path.join(repoRoot, 'umbrel-app', file), 'utf8')
}

function listExistingFiles (dir) {
  if (!fs.existsSync(dir)) return []
  const out = []
  walk(dir, '')
  return out.sort()

  function walk (abs, rel) {
    for (const entry of fs.readdirSync(abs, { withFileTypes: true })) {
      const childAbs = path.join(abs, entry.name)
      const childRel = rel ? `${rel}/${entry.name}` : entry.name
      if (entry.isDirectory()) walk(childAbs, childRel)
      else if (entry.isFile()) out.push(childRel)
      else out.push(childRel)
    }
  }
}

function assertSafeTargetRoot (root) {
  let current = root
  while (!fs.existsSync(current)) {
    const parent = path.dirname(current)
    if (parent === current) {
      die(`Refusing to export to ${root}; no existing parent directory was found.`)
    }
    current = parent
  }

  const stat = fs.lstatSync(current)
  if (stat.isSymbolicLink()) {
    die(`Refusing to export through symlinked official Umbrel path: ${current}`)
  }
  if (!stat.isDirectory()) {
    die(`Refusing to export through non-directory official Umbrel path: ${current}`)
  }
}

function assertSafeTargetPaths (root, relativeFiles) {
  if (fs.existsSync(root)) {
    const stat = fs.lstatSync(root)
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
      die(`Refusing to export to ${root}; target must be a real directory.`)
    }
  }

  for (const rel of relativeFiles) {
    const parts = rel.split('/')
    let current = root
    for (let i = 0; i < parts.length; i++) {
      current = path.join(current, parts[i])
      if (!fs.existsSync(current)) continue
      const stat = fs.lstatSync(current)
      if (stat.isSymbolicLink()) {
        die(`Refusing to export through symlinked official Umbrel path: ${path.relative(root, current)}`)
      }
      const isLeaf = i === parts.length - 1
      if (isLeaf && !stat.isFile()) {
        die(`Refusing to overwrite non-file official Umbrel path: ${path.relative(root, current)}`)
      }
      if (!isLeaf && !stat.isDirectory()) {
        die(`Refusing to export through non-directory official Umbrel path: ${path.relative(root, current)}`)
      }
    }
  }
}

function parseArgs (argv) {
  const out = {}
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--help' || arg === '-h') {
      console.log(usage.trim())
      process.exit(0)
    }
    if (arg === '--check') {
      out.check = true
      continue
    }
    if (arg === '--allow-placeholder') {
      out.allowPlaceholder = true
      continue
    }
    if (arg === '--target' || arg === '--submission-url') {
      const value = argv[++i]
      if (!value || value.startsWith('--')) die(`Missing value for ${arg}`)
      out[camel(arg.slice(2))] = value
      continue
    }
    die(`Unknown argument: ${arg}`)
  }
  return out
}

function camel (value) {
  return value.replace(/-([a-z])/g, (_, c) => c.toUpperCase())
}

function escapeRegExp (value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

function die (message) {
  console.error(message)
  process.exit(1)
}
