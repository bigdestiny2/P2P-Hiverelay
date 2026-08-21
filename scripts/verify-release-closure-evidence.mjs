#!/usr/bin/env node

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  resolveStartos04ReleaseBinding,
  verifyPublishedReleaseClosureEvidence
} from './lib/startos-04-release-evidence.mjs'

const args = parseArgs(process.argv.slice(2))
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

try {
  const bundleDir = path.resolve(required(args, 'bundleDir'))
  const releaseEvidencePath = path.join(bundleDir, 'release-evidence.json')
  const imageManifestEvidencePath = path.join(bundleDir, 'release-image-manifest-evidence.json')
  const release = readIdentity(releaseEvidencePath)
  const binding = resolveStartos04ReleaseBinding({
    repoRoot,
    tag: release.tag,
    tagSha: release.tagSha,
    releaseSurfacesRunId: release.runId,
    releaseEvidencePath,
    imageManifestEvidencePath
  })
  verifyPublishedReleaseClosureEvidence({
    evidencePath: path.join(bundleDir, 'release-closure-evidence.json'),
    binding,
    sourceReleaseEvidencePath: releaseEvidencePath,
    imageManifestEvidencePath,
    releasePackagePath: firstPath(bundleDir, [
      'blindspark-startos-0.4.s9pk',
      'startos-0.4/blindspark-startos-0.4.s9pk'
    ]),
    releaseStartosEvidencePath: path.join(bundleDir, 'startos-0.4-release-evidence.json')
  })
  console.log(`Published release closure evidence verified for ${binding.tag}`)
} catch (err) {
  console.error(err.message)
  process.exit(1)
}

function parseArgs (argv) {
  const out = {}
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] !== '--bundle-dir') throw new Error(`Unknown argument: ${argv[i]}`)
    const value = argv[++i]
    if (!value || value.startsWith('--')) throw new Error('Missing value for --bundle-dir')
    out.bundleDir = value
  }
  return out
}

function required (body, name) {
  const value = body[name]
  if (!value) throw new Error(`Missing required argument: ${name}`)
  return value
}

function readIdentity (file) {
  const resolved = path.resolve(file)
  const stat = fs.lstatSync(resolved)
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 1 || stat.size > 2 * 1024 * 1024) {
    throw new Error('release checkpoint evidence must be a nonempty regular JSON file no larger than 2 MiB')
  }
  const body = JSON.parse(fs.readFileSync(resolved, 'utf8'))
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new Error('release checkpoint evidence must be a JSON object')
  }
  return {
    tag: body.release?.version,
    tagSha: body.release?.tagSha,
    runId: String(body.release?.workflow?.runId || '')
  }
}

function firstPath (root, candidates) {
  for (const candidate of candidates) {
    const file = path.join(root, candidate)
    if (fs.existsSync(file)) return file
  }
  return path.join(root, candidates[0])
}
