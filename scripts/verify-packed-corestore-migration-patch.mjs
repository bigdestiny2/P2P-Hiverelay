#!/usr/bin/env node

import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import {
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, isAbsolute, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const repoRoot = resolve(here, '..')
const PATCH_SHA256 = 'sha256:fbcd793cfb4fd3334b04bfd9163a728064eef2500361cb83ef84e95d13b46b53'
const PATCHED_SOURCE_SHA256 = 'sha256:04153bfa8de76c0dc2a802936cbbeea6c22f20a1a79035cd65ed1957cc8ff2d5'

const args = parseArgs(process.argv.slice(2))
const scratch = mkdtempSync(join(tmpdir(), 'hiverelay-packed-core-patch-'))

try {
  const pack = run('npm', [
    'pack', '--json', '--workspace', 'packages/core', '--pack-destination', scratch
  ], repoRoot, 120_000, {
    npm_config_cache: join(scratch, 'npm-cache')
  })
  const metadata = parsePack(pack.stdout)
  const tarball = join(scratch, metadata.filename)
  const installRoot = join(scratch, 'consumer')
  mkdirSync(installRoot)
  writeFileSync(join(installRoot, 'package.json'), JSON.stringify({
    name: 'hiverelay-packed-core-patch-verifier',
    version: '1.0.0',
    private: true
  }, null, 2) + '\n')

  const install = run('npm', [
    'install', tarball, '--omit=dev', '--no-audit', '--no-fund', '--foreground-scripts'
  ], installRoot, 300_000, {
    npm_config_cache: join(scratch, 'npm-cache')
  })

  const installedPackage = readJson(join(installRoot, 'node_modules', 'p2p-hiverelay', 'package.json'))
  const installedDependency = readJson(join(installRoot, 'node_modules', 'hypercore-storage', 'package.json'))
  const installedPatch = join(installRoot, 'node_modules', 'p2p-hiverelay', 'patches', 'hypercore-storage+3.2.0.patch')
  const installedSource = join(installRoot, 'node_modules', 'hypercore-storage', 'migrations', '0', 'index.js')
  const installedPatchSha256 = sha256(regularBytes(installedPatch, 'installed tracked patch'))
  const installedSourceSha256 = sha256(regularBytes(installedSource, 'installed migration source'))

  if (installedPackage.scripts?.postinstall !== 'node platform/apply-hypercore-storage-migration-patch.js') {
    fatal('packed package lost the fail-closed postinstall contract')
  }
  if (installedPackage.dependencies?.['hypercore-storage'] !== '3.2.0' || installedDependency.version !== '3.2.0') {
    fatal('packed consumer did not install exact hypercore-storage 3.2.0')
  }
  if (installedPatchSha256 !== PATCH_SHA256) fatal('packed tracked patch digest is incorrect')
  if (installedSourceSha256 !== PATCHED_SOURCE_SHA256) fatal('packed install did not produce the exact patched migration source')

  const assertion = run(process.execPath, [
    '--input-type=module',
    '--eval',
    "import { assertPatchedHypercoreStorageMigration } from 'p2p-hiverelay/core/persistence/storage-root-restore.js'; const result = assertPatchedHypercoreStorageMigration(); process.stdout.write(JSON.stringify(result))"
  ], installRoot, 30_000)
  const runtimeAssertion = JSON.parse(assertion.stdout)
  if (`sha256:${runtimeAssertion.installedSourceSha256?.replace(/^sha256:/, '')}` !== PATCHED_SOURCE_SHA256) {
    fatal('packed runtime assertion did not return the exact patched source digest')
  }

  const evidence = {
    schema: 'hiverelay-packed-npm-corestore-patch-evidence-v1',
    package: {
      name: installedPackage.name,
      version: installedPackage.version,
      tarballSha256: sha256(regularBytes(tarball, 'packed tarball')),
      npmShasum: metadata.shasum,
      npmIntegrity: metadata.integrity
    },
    install: {
      dependency: `hypercore-storage@${installedDependency.version}`,
      lifecycle: installedPackage.scripts.postinstall,
      patchSha256: installedPatchSha256,
      installedMigrationSourceSha256: installedSourceSha256,
      runtimeAssertionSha256: runtimeAssertion.installedSourceSha256,
      result: 'passed'
    },
    externalPublicationPerformed: false,
    installLogTail: install.stdout.trim().split('\n').slice(-8)
  }
  const bytes = Buffer.from(JSON.stringify(evidence, null, 2) + '\n')
  if (args.out) writeEvidence(args.out, bytes)
  process.stdout.write(bytes)
} finally {
  if (!args.keep) rmSync(scratch, { recursive: true, force: true })
  else process.stderr.write(`kept verifier scratch directory: ${scratch}\n`)
}

function run (command, argv, cwd, timeout, extraEnv = {}) {
  const result = spawnSync(command, argv, {
    cwd,
    encoding: 'utf8',
    timeout,
    env: { ...process.env, ...extraEnv }
  })
  if (result.status !== 0) {
    const detail = [result.stderr, result.stdout].filter(Boolean).join('\n').trim()
    fatal(`${command} ${argv.join(' ')} failed (${result.status}): ${detail}`)
  }
  return result
}

function parsePack (stdout) {
  const value = JSON.parse(stdout)
  if (!Array.isArray(value) || value.length !== 1 || typeof value[0]?.filename !== 'string') {
    fatal('npm pack did not return one exact package record')
  }
  return value[0]
}

function readJson (file) {
  return JSON.parse(regularBytes(file, file).toString('utf8'))
}

function regularBytes (file, label) {
  const stat = lstatSync(file)
  if (stat.isSymbolicLink() || !stat.isFile()) fatal(`${label} must be a regular non-symlink file`)
  return readFileSync(file)
}

function writeEvidence (file, bytes) {
  file = resolve(file)
  if (!isAbsolute(file)) fatal('--out must resolve to an absolute path')
  mkdirSync(dirname(file), { recursive: true })
  writeFileSync(file, bytes, { flag: 'wx', mode: 0o600 })
}

function parseArgs (argv) {
  const out = { out: null, keep: false }
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--out') out.out = argv[++i]
    else if (argv[i] === '--keep') out.keep = true
    else if (argv[i] === '--help' || argv[i] === '-h') {
      process.stdout.write('Usage: node scripts/verify-packed-corestore-migration-patch.mjs [--out <evidence.json>] [--keep]\n')
      process.exit(0)
    } else fatal(`unknown argument: ${argv[i]}`)
  }
  if (out.out === undefined) fatal('--out requires a path')
  return out
}

function sha256 (bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`
}

function fatal (message) {
  throw new Error(message)
}
