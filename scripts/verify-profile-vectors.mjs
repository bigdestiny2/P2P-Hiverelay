#!/usr/bin/env node
import { readFile, readdir } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  verifyProfileVectors
} from '../packages/core/core/protocol/profile-vector-verifier.js'

const here = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(here, '..')

async function main () {
  const args = parseArgs(process.argv.slice(2))
  const fixtureDir = path.resolve(repoRoot, args.fixtureDir || 'test/fixtures/relaykernel-profile')
  const hasExplicitFiles = args.files.length > 0
  const files = hasExplicitFiles
    ? args.files.map(file => path.resolve(repoRoot, file))
    : await fixtureFiles(fixtureDir)

  const vectors = []
  for (const file of files) {
    vectors.push(JSON.parse(await readFile(file, 'utf8')))
  }

  const summary = verifyProfileVectors(vectors, {
    requireSupportedSet: !hasExplicitFiles
  })
  if (args.json) {
    console.log(JSON.stringify(summary, null, 2))
  } else {
    console.log(`profile vectors: ${summary.passed}/${summary.count} passed`)
    for (const error of summary.inventory.errors) {
      console.error(`- inventory: ${error}`)
    }
    for (const result of summary.results) {
      if (result.valid) continue
      console.error(`- ${result.name || '(unnamed)'}: ${result.errors.join('; ')}`)
    }
  }

  if (!summary.valid) process.exitCode = 1
}

async function fixtureFiles (dir) {
  const entries = await readdir(dir, { withFileTypes: true })
  return entries
    .filter(entry => entry.isFile() && entry.name.endsWith('.json'))
    .map(entry => path.join(dir, entry.name))
    .sort()
}

function parseArgs (argv) {
  const args = { files: [], fixtureDir: null, json: false }
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--fixture-dir') {
      args.fixtureDir = argv[++i]
    } else if (arg === '--json') {
      args.json = true
    } else {
      args.files.push(arg)
    }
  }
  return args
}

main().catch(err => {
  console.error(err && err.stack ? err.stack : String(err))
  process.exitCode = 1
})
