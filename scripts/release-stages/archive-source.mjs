#!/usr/bin/env node
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { parseArgs, writeJson } from './io.mjs'
import { createExactReleaseSource } from './exact-source.mjs'
const args = parseArgs(process.argv.slice(2), ['--sha', '--destination', '--out'])
if (!args['--destination'] || !args['--out']) throw new Error('Source destination and receipt output required')
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const result = createExactReleaseSource({ repoRoot, sha: args['--sha'], destination: path.resolve(args['--destination']) })
writeJson(args['--out'], result.receipt)
console.log(result.source)
