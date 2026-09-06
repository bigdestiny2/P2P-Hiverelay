#!/usr/bin/env node
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { RELEASE_NPM_PACKAGES, RELEASE_NPM_STAGING_TAG } from '../lib/release-evidence-contract.mjs'
import { run, readJson, writeJson, digest, parseArgs } from './io.mjs'

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const args = parseArgs(process.argv.slice(2), ['--version', '--out', '--github-env'])
const version = args['--version']
if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version || '')) throw new Error('Exact release version is required')
if (!args['--out']) throw new Error('--out is required')
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'hiverelay-artifact-npm-'))
const rows = []
let published = false
try {
  for (const [i, directory] of ['core', 'client', 'verifier', 'services'].entries()) {
    const pkgPath = path.join(repoRoot, 'packages', directory)
    const pkg = readJson(path.join(pkgPath, 'package.json'))
    if (pkg.name !== RELEASE_NPM_PACKAGES[i] || pkg.version !== version) throw new Error('Source package identity differs from release')
    // Publish precisely the packed bytes whose integrity is retained. On retry,
    // an occupied version must have these same bytes; version presence alone
    // is never permission to substitute another package.
    const packed = JSON.parse(run('npm', ['pack', pkgPath, '--json', '--pack-destination', temp], { cwd: repoRoot, timeout: 600000 }))
    if (packed.length !== 1 || path.basename(packed[0].filename) !== packed[0].filename) throw new Error('npm pack returned an invalid artifact')
    const file = path.join(temp, packed[0].filename)
    const expected = { name: pkg.name, version, integrity: `sha512-${digest(file, 'sha512', 'base64')}`, shasum: digest(file, 'sha1') }
    const probe = run(process.execPath, [path.join(repoRoot, 'scripts/ensure-npm-dist-tag.mjs'), '--probe-only', '--package', pkg.name, '--version', version, '--command-timeout-ms', '30000']).trim()
    if (probe === 'missing') {
      run('npm', ['publish', file, '--access', 'public', '--tag', RELEASE_NPM_STAGING_TAG], { cwd: repoRoot, timeout: 600000 })
      published = true
    } else if (probe !== 'visible') throw new Error('Ambiguous immutable npm version probe')
    const actual = JSON.parse(run('npm', ['view', `${pkg.name}@${version}`, 'dist', '--json']))
    if (actual.integrity !== expected.integrity || actual.shasum !== expected.shasum) throw new Error('Published npm version differs from exact packed source bytes')
    run(process.execPath, [path.join(repoRoot, 'scripts/ensure-npm-dist-tag.mjs'), '--package', pkg.name, '--version', version, '--tag', RELEASE_NPM_STAGING_TAG], { timeout: 600000 })
    rows.push(expected)
  }
  writeJson(args['--out'], rows)
  if (args['--github-env']) {
    const file = path.resolve(args['--out'])
    if (/[\r\n]/.test(file)) throw new Error('Invalid evidence filename')
    fs.appendFileSync(args['--github-env'], `HIVERELAY_RELEASE_NPM_IDENTITY=${file}\nHIVERELAY_NPM_PUBLISH_STATUS=${published ? 'published' : 'current'}-next\n`)
  }
  console.log('Exact npm artifact versions verified under next; stable labels deferred')
} finally {
  fs.rmSync(temp, { recursive: true, force: true })
}
