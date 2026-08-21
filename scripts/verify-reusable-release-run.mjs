#!/usr/bin/env node

import fs from 'node:fs'
import { verifyReusableReleaseRunAuthority } from './lib/startos-04-release-evidence.mjs'

const MAX_RUN_JSON_BYTES = 4 * 1024 * 1024

try {
  const args = parseArgs(process.argv.slice(2))
  const raw = fs.readFileSync(0)
  if (raw.length === 0 || raw.length > MAX_RUN_JSON_BYTES) {
    throw new Error(`reusable release run JSON must be between 1 and ${MAX_RUN_JSON_BYTES} bytes`)
  }
  let run
  try {
    run = JSON.parse(raw.toString('utf8'))
  } catch (err) {
    throw new Error(`reusable release run must be JSON: ${err.message}`)
  }
  const authority = verifyReusableReleaseRunAuthority({
    run,
    expectedRunId: required(args, 'runId'),
    expectedRunAttempt: required(args, 'runAttempt'),
    expectedRunUrl: required(args, 'runUrl'),
    expectedTag: required(args, 'tag'),
    expectedTagSha: required(args, 'tagSha')
  })
  console.log(`Verified reusable Release surfaces ${authority.runId} for ${authority.tag}@${authority.tagSha}`)
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
