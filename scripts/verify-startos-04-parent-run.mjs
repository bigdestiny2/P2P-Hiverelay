#!/usr/bin/env node

import fs from 'node:fs'
import { verifyStartos04ParentRunAuthority } from './lib/startos-04-release-evidence.mjs'

const args = parseArgs(process.argv.slice(2))

try {
  const input = fs.readFileSync(0)
  if (input.length < 1 || input.length > 4 * 1024 * 1024) {
    throw new Error('StartOS parent run input must be between 1 and 4194304 bytes')
  }
  verifyStartos04ParentRunAuthority({
    run: JSON.parse(input.toString('utf8')),
    expectedRunId: required(args, 'runId'),
    expectedRunAttempt: required(args, 'runAttempt'),
    expectedRunUrl: required(args, 'runUrl'),
    expectedTag: required(args, 'tag'),
    expectedTagSha: required(args, 'tagSha')
  })
  console.log('Verified exact release-surfaces sync and StartOS image-authority checkpoint')
} catch (err) {
  console.error(err.message)
  process.exit(1)
}

function parseArgs (argv) {
  const names = new Map([
    ['--run-id', 'runId'],
    ['--run-attempt', 'runAttempt'],
    ['--run-url', 'runUrl'],
    ['--tag', 'tag'],
    ['--tag-sha', 'tagSha']
  ])
  const out = {}
  for (let i = 0; i < argv.length; i++) {
    const name = names.get(argv[i])
    if (!name) throw new Error(`Unknown argument: ${argv[i]}`)
    const value = argv[++i]
    if (!value || value.startsWith('--')) throw new Error(`Missing value for ${argv[i - 1]}`)
    out[name] = value
  }
  return out
}

function required (args, name) {
  const value = args[name]
  if (!value) throw new Error(`Missing required argument: ${name}`)
  return value
}
