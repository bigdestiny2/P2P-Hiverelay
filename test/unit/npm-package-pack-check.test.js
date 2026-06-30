import test from 'brittle'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { execFile } from 'node:child_process'
import {
  checkNpmPackagePack,
  findUnsafePackPaths,
  inspectPack,
  parsePackJson
} from '../../scripts/check-npm-package-pack.mjs'

test('npm package pack checker accepts clean workspace pack metadata', (t) => {
  const root = fixtureRoot()
  writePackage(root, 'packages/core', {
    name: 'p2p-hiverelay',
    version: '0.20.2',
    files: ['README.md', 'LICENSE', 'index.js']
  })

  const result = checkNpmPackagePack({
    cwd: root,
    workspaces: ['packages/core'],
    runner: () => ({
      stdout: JSON.stringify([{
        name: 'p2p-hiverelay',
        version: '0.20.2',
        filename: 'p2p-hiverelay-0.20.2.tgz',
        size: 123,
        unpackedSize: 456,
        entryCount: 3,
        files: [
          { path: 'README.md' },
          { path: 'LICENSE' },
          { path: 'index.js' }
        ]
      }])
    })
  })

  t.ok(result.ok)
  t.is(result.workspaces.length, 1)
  t.is(result.workspaces[0].hasReadme, true)
  t.is(result.workspaces[0].hasLicense, true)
  t.alike(result.workspaces[0].unsafe, [])
})

test('npm package pack checker rejects missing README/license and unsafe paths', (t) => {
  const root = fixtureRoot()
  writePackage(root, 'packages/core', {
    name: 'p2p-hiverelay',
    version: '0.20.2',
    files: ['index.js']
  })

  const result = checkNpmPackagePack({
    cwd: root,
    workspaces: ['packages/core'],
    runner: () => ({
      stdout: JSON.stringify([{
        name: 'p2p-hiverelay',
        version: '0.20.2',
        files: [
          { path: 'index.js' },
          { path: 'node_modules/bad/index.js' },
          { path: '.env' },
          { path: 'secret.pem' }
        ]
      }])
    })
  })

  t.absent(result.ok)
  t.ok(result.errors.some(error => error.includes('packed tarball is missing README.md')))
  t.ok(result.errors.some(error => error.includes('package.json files allowlist is missing LICENSE')))
  t.ok(result.errors.some(error => error.includes('unsafe packed path node_modules/bad/index.js')))
  t.ok(result.errors.some(error => error.includes('unsafe packed path .env')))
  t.ok(result.errors.some(error => error.includes('unsafe packed path secret.pem')))
})

test('npm package pack checker rejects name and version drift', (t) => {
  const row = inspectPack({
    workspace: 'packages/core',
    manifest: {
      name: 'p2p-hiverelay',
      version: '0.20.2',
      files: ['README.md', 'LICENSE']
    },
    pack: {
      name: 'wrong',
      version: '0.20.1',
      files: [
        { path: 'README.md' },
        { path: 'LICENSE' }
      ]
    }
  })

  t.absent(row.ok)
  t.ok(row.errors.some(error => error.includes('packed package name')))
  t.ok(row.errors.some(error => error.includes('packed package version')))
})

test('npm package pack checker parses npm JSON and rejects malformed output', (t) => {
  t.is(parsePackJson('[{"name":"pkg","files":[]}]').name, 'pkg')
  t.exception(() => parsePackJson('not-json'))
  t.exception(() => parsePackJson('[]'))
  t.exception(() => parsePackJson('[{"name":"a"},{"name":"b"}]'))
})

test('npm package pack checker classifies unsafe file paths', (t) => {
  const issues = findUnsafePackPaths([
    'README.md',
    'docs/private.md',
    'test/fixture.js',
    '.npmrc',
    'keys/relay.key'
  ])

  t.alike(issues.map(issue => issue.path), [
    'docs/private.md',
    'test/fixture.js',
    '.npmrc',
    'keys/relay.key'
  ])
})

test('npm package pack checker CLI emits JSON evidence', async (t) => {
  const res = await runCli(['--workspace', 'packages/verifier', '--json'])
  const payload = JSON.parse(res.stdout)

  t.is(res.status, 0)
  t.is(payload.ok, true)
  t.is(payload.workspaces.length, 1)
  t.is(payload.workspaces[0].name, 'p2p-hiverelay-verifier')
  t.is(payload.workspaces[0].hasReadme, true)
  t.is(payload.workspaces[0].hasLicense, true)
  t.alike(payload.workspaces[0].unsafe, [])
})

function fixtureRoot () {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'hiverelay-pack-check-'))
}

function writePackage (root, rel, pkg) {
  const dir = path.join(root, rel)
  fs.mkdirSync(dir, { recursive: true })
  fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(pkg, null, 2) + '\n')
}

function runCli (argv) {
  return new Promise((resolve) => {
    execFile(process.execPath, ['scripts/check-npm-package-pack.mjs', ...argv], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        npm_config_cache: path.join(os.tmpdir(), 'hiverelay-npm-pack-check-test-cache')
      },
      timeout: 20000
    }, (err, stdout, stderr) => {
      resolve({
        status: err && typeof err.code === 'number' ? err.code : 0,
        stdout,
        stderr
      })
    })
  })
}
