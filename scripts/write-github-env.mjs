#!/usr/bin/env node

import fs from 'node:fs'

const usage = `
Usage:
  node scripts/write-github-env.mjs <NAME> <VALUE> [--github-env <path>]

Writes one checked NAME=VALUE line to GitHub's environment file.
Values with control characters are rejected so untrusted metadata cannot create
extra environment assignments.
`

const args = parseArgs(process.argv.slice(2))
const githubEnv = args.githubEnv || process.env.GITHUB_ENV || ''

if (!args.name || args.value === undefined) die(usage.trim())
if (!githubEnv) die('GITHUB_ENV is not set; pass --github-env <path>.')
if (!/^[A-Z_][A-Z0-9_]*$/.test(args.name)) {
  die(`Refusing to write malformed GitHub environment variable name: ${JSON.stringify(args.name)}`)
}

const value = String(args.value)
if (hasControlChars(value)) {
  die(`Refusing to write multi-line or control-character value for ${args.name} to GitHub environment file`)
}

fs.appendFileSync(githubEnv, `${args.name}=${value}\n`)

function parseArgs (argv) {
  const out = {}
  const positional = []
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--help' || arg === '-h') {
      console.log(usage.trim())
      process.exit(0)
    }
    if (arg === '--github-env') {
      out.githubEnv = readValue(argv, ++i, arg)
      continue
    }
    if (arg.startsWith('--')) die(`Unknown argument: ${arg}`)
    positional.push(arg)
  }
  if (positional.length !== 2) die(usage.trim())
  out.name = positional[0]
  out.value = positional[1]
  return out
}

function readValue (argv, index, flag) {
  const value = argv[index]
  if (!value || value.startsWith('--')) die(`Missing value for ${flag}`)
  return value
}

function hasControlChars (value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if (code <= 31 || code === 127) return true
  }
  return false
}

function die (message) {
  console.error(message)
  process.exit(1)
}
