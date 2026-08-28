#!/usr/bin/env node

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  buildReleaseClosureEvidence,
  resolveStartos04ReleaseBinding,
  verifyReleaseClosureEvidence,
  writeJsonAtomic
} from './lib/startos-04-release-evidence.mjs'

const args = parseArgs(process.argv.slice(2))
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

try {
  if (Boolean(args.out) === Boolean(args.verify)) throw new Error('Exactly one of --out or --verify is required')
  const binding = resolveStartos04ReleaseBinding({
    repoRoot,
    tag: required(args, 'tag'),
    tagSha: required(args, 'tagSha'),
    releaseSurfacesRunId: required(args, 'releaseSurfacesRunId'),
    releaseEvidencePath: required(args, 'releaseEvidence'),
    imageManifestEvidencePath: required(args, 'imageManifestEvidence')
  })
  const common = {
    binding,
    sourceReleaseEvidencePath: args.releaseEvidence,
    imageManifestEvidencePath: args.imageManifestEvidence,
    artifactPackagePath: required(args, 'artifactPackage'),
    artifactStartosEvidencePath: required(args, 'artifactStartosEvidence'),
    releasePackagePath: required(args, 'releasePackage'),
    releaseStartosEvidencePath: required(args, 'releaseStartosEvidence'),
    commitmentPath: required(args, 'commitment'),
    artifactJavascriptBundlePath: required(args, 'artifactJavascriptBundle'),
    artifactAuthoringManifestPath: required(args, 'artifactAuthoringManifest'),
    packedManifestPath: required(args, 'packedManifest'),
    childRun: readJson(required(args, 'childRun'), 'child run'),
    childRunId: required(args, 'childRunId'),
    artifact: readJson(required(args, 'artifactMetadata'), 'child artifact metadata'),
    imageAuthorityArtifact: readJson(required(args, 'imageAuthorityMetadata'), 'image authority artifact metadata'),
    imageAuthorityArtifactId: required(args, 'imageAuthorityArtifactId')
  }
  if (args.out) {
    writeJsonAtomic(args.out, buildReleaseClosureEvidence(common))
    console.log(`Release closure evidence written to ${path.resolve(args.out)}`)
  } else {
    verifyReleaseClosureEvidence({ ...common, evidencePath: args.verify })
    console.log(`Release closure evidence verified for ${binding.tag}`)
  }
} catch (err) {
  console.error(err.message)
  process.exit(1)
}

function parseArgs (argv) {
  const names = new Map([
    ['--tag', 'tag'],
    ['--tag-sha', 'tagSha'],
    ['--release-surfaces-run-id', 'releaseSurfacesRunId'],
    ['--release-evidence', 'releaseEvidence'],
    ['--image-manifest-evidence', 'imageManifestEvidence'],
    ['--artifact-package', 'artifactPackage'],
    ['--artifact-startos-evidence', 'artifactStartosEvidence'],
    ['--release-package', 'releasePackage'],
    ['--release-startos-evidence', 'releaseStartosEvidence'],
    ['--commitment', 'commitment'],
    ['--artifact-javascript-bundle', 'artifactJavascriptBundle'],
    ['--artifact-authoring-manifest', 'artifactAuthoringManifest'],
    ['--packed-manifest', 'packedManifest'],
    ['--child-run', 'childRun'],
    ['--child-run-id', 'childRunId'],
    ['--artifact-metadata', 'artifactMetadata'],
    ['--image-authority-metadata', 'imageAuthorityMetadata'],
    ['--image-authority-artifact-id', 'imageAuthorityArtifactId'],
    ['--out', 'out'],
    ['--verify', 'verify']
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

function required (body, name) {
  const value = body[name]
  if (!value) throw new Error(`Missing required argument: ${name}`)
  return value
}

function readJson (file, label) {
  const resolved = path.resolve(file)
  const stat = fs.lstatSync(resolved)
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 1 || stat.size > 2 * 1024 * 1024) {
    throw new Error(`${label} must be a nonempty regular JSON file no larger than 2 MiB`)
  }
  const body = JSON.parse(fs.readFileSync(resolved, 'utf8'))
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error(`${label} must be a JSON object`)
  return body
}
