#!/usr/bin/env node

import fs from 'node:fs'
import path from 'node:path'
import { isDeepStrictEqual } from 'node:util'
import { fileURLToPath } from 'node:url'
import {
  buildLocalReleaseCandidateManifest,
  collectLocalReleaseSnapshot,
  verifyLocalReleaseManifestDigest
} from './lib/local-release-candidate-manifest.mjs'

const MAX_MANIFEST_BYTES = 2 * 1024 * 1024
const usage = `
Usage:
  node scripts/verify-local-release-candidate-manifest.mjs --manifest <path> [options]

Options:
  --repo <path>                    HiveRelay repository (default: repository root)
  --umbrel-store <path>            Exact clean community-store checkout bound by the manifest
  --require-local-preflight        Exit non-zero when the exact manifest is locally blocked

Verification requires the exact clean source commit named by the manifest. It
does not verify or grant signing, publication, deployment, fleet, appliance,
marketplace, or release authority.
`

const here = path.dirname(fileURLToPath(import.meta.url))
const defaultRepo = path.resolve(here, '..')

try {
  const args = parseArgs(process.argv.slice(2))
  if (args.help) {
    console.log(usage.trim())
    process.exit(0)
  }
  if (!args.manifest) throw new Error('--manifest is required')

  const manifest = readManifest(args.manifest)
  verifyLocalReleaseManifestDigest(manifest)
  if (manifest.appliances?.communityStore?.attached === true && !args.umbrelStore) {
    throw new Error('--umbrel-store is required to verify an attached community-store binding')
  }
  const snapshot = collectLocalReleaseSnapshot(args.repo || defaultRepo, {
    umbrelStoreRoot: args.umbrelStore
  })
  const expected = buildLocalReleaseCandidateManifest(snapshot, {
    declaredBlockers: manifest.declaredBlockers
  })
  if (!isDeepStrictEqual(manifest, expected)) {
    throw new Error('local release manifest does not match the exact clean source tree and release surfaces')
  }

  console.log(`Local release candidate manifest verified: ${manifest.manifestDigest}`)
  console.log(`localPreflight=${manifest.release.localPreflight}`)
  console.log('releaseReady=false')
  if (args.requireLocalPreflight && manifest.release.localPreflight !== 'passed') process.exit(1)
} catch (err) {
  console.error(err.message)
  process.exit(1)
}

function parseArgs (argv) {
  const out = {}
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
    if (arg === '--manifest') {
      out.manifest = readValue(argv, ++i, arg)
      continue
    }
    if (arg === '--umbrel-store') {
      out.umbrelStore = readValue(argv, ++i, arg)
      continue
    }
    throw new Error(`unknown argument ${arg}\n${usage.trim()}`)
  }
  return out
}

function readManifest (file) {
  const resolved = path.resolve(file)
  const stat = fs.lstatSync(resolved)
  if (stat.isSymbolicLink()) throw new Error(`manifest must not be a symlink: ${resolved}`)
  if (!stat.isFile()) throw new Error(`manifest must be a regular file: ${resolved}`)
  if (stat.size > MAX_MANIFEST_BYTES) throw new Error(`manifest must be ${MAX_MANIFEST_BYTES} bytes or smaller`)
  const body = JSON.parse(fs.readFileSync(resolved, 'utf8'))
  if (body == null || typeof body !== 'object' || Array.isArray(body)) {
    throw new Error('manifest must contain a JSON object')
  }
  return body
}

function readValue (argv, index, flag) {
  const value = argv[index]
  if (!value || value.startsWith('--')) throw new Error(`missing value for ${flag}`)
  return value
}
