#!/usr/bin/env node

import path from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  buildStartos04ReleaseEvidence,
  resolveStartos04ReleaseBinding,
  verifyStartos04ReleaseEvidence,
  writeJsonAtomic
} from './lib/startos-04-release-evidence.mjs'

const args = parseArgs(process.argv.slice(2))
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')

try {
  const binding = resolveStartos04ReleaseBinding({
    repoRoot,
    tag: required(args, 'tag'),
    tagSha: required(args, 'tagSha'),
    releaseSurfacesRunId: required(args, 'releaseSurfacesRunId'),
    releaseEvidencePath: required(args, 'releaseEvidence'),
    imageManifestEvidencePath: required(args, 'imageManifestEvidence')
  })
  const packagePath = required(args, 'package')
  const commitmentPath = required(args, 'commitment')
  const packageManifestPath = required(args, 'manifest')
  if (args.out && args.verify) throw new Error('--out and --verify are mutually exclusive')
  if (!args.out && !args.verify) throw new Error('Exactly one of --out or --verify is required')
  if (args.out) {
    const evidence = buildStartos04ReleaseEvidence({ binding, packagePath, commitmentPath, packageManifestPath })
    writeJsonAtomic(args.out, evidence)
    console.log(`StartOS 0.4 release evidence written to ${path.resolve(args.out)}`)
  } else {
    verifyStartos04ReleaseEvidence({
      evidencePath: args.verify,
      binding,
      packagePath,
      commitmentPath,
      packageManifestPath
    })
    console.log(`StartOS 0.4 release evidence verified for ${binding.tag}`)
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
    ['--package', 'package'],
    ['--commitment', 'commitment'],
    ['--manifest', 'manifest'],
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

function required (args, name) {
  const value = args[name]
  if (!value) throw new Error(`Missing required argument: ${name}`)
  return value
}
