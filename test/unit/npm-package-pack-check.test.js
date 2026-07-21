import test from 'brittle'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { execFile } from 'node:child_process'
import {
  checkNpmPackagePack,
  findMissingExportTargets,
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

test('npm package pack checker rejects an export omitted from the packed tarball', async (t) => {
  const root = fixtureRoot()
  const out = path.join(root, 'dist')
  t.teardown(() => fs.rmSync(root, { recursive: true, force: true }))
  fs.mkdirSync(out)
  fs.writeFileSync(path.join(root, 'README.md'), '# fixture\n')
  fs.writeFileSync(path.join(root, 'LICENSE'), 'fixture\n')
  fs.writeFileSync(path.join(root, 'index.js'), 'export const present = true\n')
  fs.writeFileSync(path.join(root, 'exported.js'), 'export const shouldShip = true\n')

  const manifest = {
    name: 'hiverelay-export-closure-fixture',
    version: '1.0.0',
    type: 'module',
    exports: {
      '.': './index.js',
      './exported.js': './exported.js'
    },
    files: ['README.md', 'LICENSE', 'index.js']
  }
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify(manifest, null, 2) + '\n')

  const pack = parsePackJson((await execFileResult('npm', [
    'pack', '--json', '--pack-destination', out
  ], {
    cwd: root,
    env: {
      ...process.env,
      npm_config_cache: path.join(root, '.npm-cache')
    }
  })).stdout)
  const row = inspectPack({ workspace: '.', manifest, pack })

  t.absent(row.ok)
  t.alike(row.missingExportTargets, [{
    subpath: './exported.js',
    target: './exported.js'
  }])
  t.ok(row.errors.some(error => error.includes('packed tarball is missing export target ./exported.js')))
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

test('npm package pack checker closes exact, conditional, array, and wildcard exports', (t) => {
  const missing = findMissingExportTargets({
    '.': './index.js',
    './conditional': {
      import: './esm.js',
      require: './cjs.cjs'
    },
    './fallback': ['./preferred.js', './fallback.js'],
    './features/*': './features/*.js'
  }, [
    'index.js',
    'esm.js',
    'cjs.cjs',
    'preferred.js',
    'fallback.js',
    'features/one.js'
  ])

  t.alike(missing, [])
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

function execFileResult (file, argv, opts) {
  return new Promise((resolve, reject) => {
    execFile(file, argv, opts, (err, stdout, stderr) => {
      if (err) return reject(Object.assign(err, { stdout, stderr }))
      resolve({ stdout, stderr })
    })
  })
}
