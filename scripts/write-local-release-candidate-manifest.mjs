#!/usr/bin/env node

import path from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  buildLocalReleaseCandidateManifest,
  collectLocalReleaseSnapshot,
  writeJsonAtomic
} from './lib/local-release-candidate-manifest.mjs'

const usage = `
Usage:
  node scripts/write-local-release-candidate-manifest.mjs --out <path> [options]

Options:
  --repo <path>                    HiveRelay repository (default: repository root)
  --umbrel-store <path>            Clean community-store checkout to bind read-only
  --known-blocker <IDENTIFIER>     Add a durable externally-known blocker; repeatable
  --require-local-preflight        Exit non-zero after writing when local checks are blocked

This command is offline and read-only except for the requested output file.
Local preflight covers clean pre-tag source, version, base-image, and workflow
configuration checks. External artifact, marketplace, fleet, signing, and
publication checks remain blockers and releaseReady remains false.
`

const here = path.dirname(fileURLToPath(import.meta.url))
const defaultRepo = path.resolve(here, '..')

try {
  const args = parseArgs(process.argv.slice(2))
  if (args.help) {
    console.log(usage.trim())
    process.exit(0)
  }
  if (!args.out) throw new Error('--out is required')

  const snapshot = collectLocalReleaseSnapshot(args.repo || defaultRepo, {
    umbrelStoreRoot: args.umbrelStore
  })
  const manifest = buildLocalReleaseCandidateManifest(snapshot, {
    declaredBlockers: args.knownBlockers
  })
  writeJsonAtomic(args.out, manifest)

  console.log(`Local release candidate manifest written: ${path.resolve(args.out)}`)
  console.log(`manifestDigest=${manifest.manifestDigest}`)
  console.log(`localPreflight=${manifest.release.localPreflight}`)
  console.log('releaseReady=false')

  if (args.requireLocalPreflight && manifest.release.localPreflight !== 'passed') process.exit(1)
} catch (err) {
  console.error(err.message)
  process.exit(1)
}

function parseArgs (argv) {
  const out = { knownBlockers: [] }
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--help' || arg === '-h') {
      out.help = true
      continue
    }
    if (arg === '--require-local-preflight') {
      out.requireLocalPreflight = true
      continue
    }
    if (arg === '--repo') {
      out.repo = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--out') {
      out.out = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--umbrel-store') {
      out.umbrelStore = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--known-blocker') {
      out.knownBlockers.push(readValue(argv, ++i, arg))
      continue
    }
    throw new Error(`unknown argument ${arg}\n${usage.trim()}`)
  }
  return out
}

function readValue (argv, index, flag) {
  const value = argv[index]
  if (!value || value.startsWith('--')) throw new Error(`missing value for ${flag}`)
  return value
}
