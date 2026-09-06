#!/usr/bin/env node
import { assertArtifactSurfaceState, validateReleaseStage } from '../lib/release-evidence-contract.mjs'
import { readJson, parseArgs } from './io.mjs'
const args = parseArgs(process.argv.slice(2), ['--file'])
const release = readJson(args['--file'])
if (validateReleaseStage(release)) assertArtifactSurfaceState(release)
console.log('Shared release stage contract verified')
