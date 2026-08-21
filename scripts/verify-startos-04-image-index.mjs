#!/usr/bin/env node

import fs from 'node:fs'
import { verifyStartos04ImageIndex } from './lib/startos-04-release-evidence.mjs'

const MAX_RAW_INDEX_BYTES = 2 * 1024 * 1024

try {
  const args = parseArgs(process.argv.slice(2))
  const raw = fs.readFileSync(0)
  if (raw.length < 1 || raw.length > MAX_RAW_INDEX_BYTES) {
    throw new Error(`release image raw index must be between 1 and ${MAX_RAW_INDEX_BYTES} bytes`)
  }
  const verified = verifyStartos04ImageIndex({
    raw,
    expectedDigest: required(args, 'indexDigest'),
    expectedAmd64Digest: required(args, 'amd64Digest'),
    expectedArm64Digest: required(args, 'arm64Digest')
  })
  console.log(`Verified signed release image index ${verified.digest} platform membership`)
} catch (err) {
  console.error(err.message)
  process.exit(1)
}

function parseArgs (argv) {
  const names = new Map([
    ['--index-digest', 'indexDigest'],
    ['--amd64-digest', 'amd64Digest'],
    ['--arm64-digest', 'arm64Digest']
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
