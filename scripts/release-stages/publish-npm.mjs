#!/usr/bin/env node
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { RELEASE_NPM_PACKAGES, RELEASE_NPM_STAGING_TAG } from '../lib/release-evidence-contract.mjs'
import { run, readJson, writeJson, digest, parseArgs } from './io.mjs'
import { createExactReleaseSource, verifyPackedReleaseSource } from './exact-source.mjs'
import { waitForImmutableNpmDist } from './npm-immutable-dist.mjs'

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const args = parseArgs(process.argv.slice(2), ['--version', '--out', '--github-env', '--sha'])
const version = args['--version']
if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version || '')) throw new Error('Exact release version is required')
if (!args['--out']) throw new Error('--out is required')
const sha = args['--sha'] || process.env.HIVERELAY_RELEASE_SHA
if (!/^[a-f0-9]{40}$/.test(sha || '')) throw new Error('Exact admitted release SHA is required')
const output = path.resolve(args['--out'])
const retainedPackages = `${output}.packages`
if (/[\r\n]/.test(output) || [output, `${output}.source.json`, `${output}.progress.jsonl`, retainedPackages].some(file => fs.existsSync(file))) throw new Error('Fresh safe artifact evidence output paths are required')
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'hiverelay-artifact-npm-'))
const rows = []
let published = false
let progressFd
try {
  const exact = createExactReleaseSource({ repoRoot, sha, destination: path.join(temp, 'committed') })
  writeJson(`${output}.source.json`, exact.receipt)
  fs.mkdirSync(retainedPackages, { mode: 0o700 })
  progressFd = fs.openSync(`${output}.progress.jsonl`, 'wx', 0o600)
  const record = value => { fs.writeSync(progressFd, JSON.stringify({ sourceCommit: sha, ...value }) + '\n'); fs.fsyncSync(progressFd) }
  const artifacts = []
  for (const [i, directory] of ['core', 'client', 'verifier', 'services'].entries()) {
    const pkgPath = path.join(exact.source, 'packages', directory)
    const pkg = readJson(path.join(pkgPath, 'package.json'))
    if (pkg.name !== RELEASE_NPM_PACKAGES[i] || pkg.version !== version) throw new Error('Source package identity differs from release')
    // Publish precisely the packed bytes whose integrity is retained. On retry,
    // an occupied version must have these same bytes; version presence alone
    // is never permission to substitute another package.
    const packed = JSON.parse(run('npm', ['pack', pkgPath, '--json', '--ignore-scripts', '--pack-destination', retainedPackages], { cwd: exact.source, timeout: 600000 }))
    if (packed.length !== 1 || path.basename(packed[0].filename) !== packed[0].filename) throw new Error('npm pack returned an invalid artifact')
    const file = path.join(retainedPackages, packed[0].filename)
    const files = verifyPackedReleaseSource({ file, packageDirectory: `packages/${directory}`, inventory: exact.inventory, destination: path.join(temp, `verified-${directory}`) })
    const expected = { name: pkg.name, version, integrity: `sha512-${digest(file, 'sha512', 'base64')}`, shasum: digest(file, 'sha1') }
    record({ phase: 'prepared', package: expected, filename: packed[0].filename, files })
    artifacts.push({ file, expected })
  }
  // Finish checking every package before the first irreversible publication.
  for (const { file, expected } of artifacts) {
    const probe = run(process.execPath, [path.join(repoRoot, 'scripts/ensure-npm-dist-tag.mjs'), '--probe-only', '--package', expected.name, '--version', version, '--command-timeout-ms', '30000']).trim()
    if (probe === 'missing') {
      run('npm', ['publish', file, '--ignore-scripts', '--access', 'public', '--tag', RELEASE_NPM_STAGING_TAG], { cwd: repoRoot, timeout: 600000 })
      published = true
      record({ phase: 'publish-returned-success', package: expected })
    } else if (probe !== 'visible') throw new Error('Ambiguous immutable npm version probe')
    await waitForImmutableNpmDist({ packageName: expected.name, version, expected })
    record({ phase: 'immutable-dist-verified', package: expected })
    run(process.execPath, [path.join(repoRoot, 'scripts/ensure-npm-dist-tag.mjs'), '--package', expected.name, '--version', version, '--tag', RELEASE_NPM_STAGING_TAG], { timeout: 600000 })
    rows.push(expected)
    record({ phase: 'staging-tag-verified', package: expected })
  }
  writeJson(args['--out'], rows)
  if (args['--github-env']) {
    const file = path.resolve(args['--out'])
    if (/[\r\n]/.test(file)) throw new Error('Invalid evidence filename')
    fs.appendFileSync(args['--github-env'], `HIVERELAY_RELEASE_NPM_IDENTITY=${file}\nHIVERELAY_NPM_PUBLISH_STATUS=${published ? 'published' : 'current'}-next\n`)
  }
  console.log('Exact npm artifact versions verified under next; stable labels deferred')
} finally {
  if (progressFd != null) fs.closeSync(progressFd)
  fs.rmSync(temp, { recursive: true, force: true })
}
