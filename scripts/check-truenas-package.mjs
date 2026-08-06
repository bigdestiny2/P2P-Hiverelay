#!/usr/bin/env node

import fs from 'node:fs'
import crypto from 'node:crypto'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(__dirname, '..')
const appRoot = path.join(repoRoot, 'truenas-app')
const expectedFiles = [
  'README.md',
  'app.yaml',
  'item.yaml',
  'ix_values.yaml',
  'questions.yaml',
  'templates/docker-compose.yaml',
  'templates/library/base_v2_3_8/render.py',
  'templates/test_values/basic-values.yaml',
  'vendor/truenas-apps/LICENSE.LGPL-3.0',
  'vendor/truenas-apps/NOTICE.md',
  'vendor/truenas-apps/PROVENANCE.json'
]

const errors = []

for (const rel of expectedFiles) {
  if (!fs.existsSync(path.join(appRoot, rel))) errors.push(`missing truenas-app/${rel}`)
}

if (errors.length === 0) validatePackage()

if (errors.length) {
  console.error('TrueNAS package validation failed:')
  for (const error of errors) console.error(`- ${error}`)
  process.exit(1)
}

console.log('TrueNAS Community package validates for Blindspark.')

function validatePackage () {
  const readme = read(path.join(appRoot, 'README.md'))
  const app = read(path.join(appRoot, 'app.yaml'))
  const values = read(path.join(appRoot, 'ix_values.yaml'))
  const questions = read(path.join(appRoot, 'questions.yaml'))
  const template = read(path.join(appRoot, 'templates', 'docker-compose.yaml'))
  const testValues = read(path.join(appRoot, 'templates', 'test_values', 'basic-values.yaml'))
  const provenance = JSON.parse(read(path.join(appRoot, 'vendor', 'truenas-apps', 'PROVENANCE.json')))

  const upstreamVersion = topScalar(app, 'app_version')
  const catalogVersion = topScalar(app, 'version')
  const imageTag = imageScalar(values, 'ghcr.io/bigdestiny2/p2p-hiverelay', 'tag')

  equal(topScalar(app, 'name'), 'blindspark', 'catalog app name')
  equal(topScalar(app, 'train'), 'community', 'catalog train')
  // The checked-in Community package must remain deployable. It tracks the
  // newest image that is actually published in GHCR and may therefore lag an
  // unreleased repository version. Release preparation updates these fields
  // together once the corresponding image exists.
  equal(imageTag, upstreamVersion, 'catalog image tag')
  matches(catalogVersion, /^\d+\.\d+\.\d+$/, 'catalog package version')
  equal(topScalar(app, 'lib_version'), '2.3.8', 'TrueNAS rendering library version')
  equal(
    topScalar(app, 'lib_version_hash'),
    'cd75c897a1e8fef54b5bd00d0d8849f240bc50db2ef650eccc0ee74f3b2b2dc1',
    'TrueNAS rendering library hash'
  )
  validateVendorProvenance(provenance, app)
  includesAll(readme, [`Upstream HiveRelay release: \`${upstreamVersion}\``], 'TrueNAS app README')

  includesAll(app, [
    'uid: 999',
    'gid: 999',
    'user_name: Host user is [netdata]',
    'group_name: Host group is [docker]',
    'icon: https://media.sys.truenas.net/apps/blindspark/icons/icon.svg'
  ], 'app metadata')

  includesAll(questions, [
    'variable: api_key',
    'min_length: 32',
    'private: true',
    'variable: accept_mode',
    'default: review',
    'variable: expose_token',
    'default: 30452'
  ], 'install questions')
  const exposeTokenQuestion = questionBlock(questions, 'expose_token')
  includesAll(exposeTokenQuestion, ['type: boolean', 'default: false'], 'expose-token question')

  includesAll(template, [
    'c1.set_user(values.consts.run_as_user, values.consts.run_as_group)',
    'tpl.deps.perms(values.consts.perms_container_name)',
    'c1.healthcheck.set_test("wget"',
    'c1.environment.add_env("HIVERELAY_API_KEY"',
    'c1.environment.add_env("HIVERELAY_ACCEPT_MODE"',
    'c1.environment.add_env("HIVERELAY_MAX_STORAGE"',
    'c1.environment.add_env("HIVERELAY_UI_EXPOSE_TOKEN"',
    'c1.add_storage("/data"',
    'tpl.portals.add(values.network.web_port, {"scheme": "http", "path": "/"})'
  ], 'compose template')

  excludesAll(template, ['privileged', 'network_mode: host', 'set_user(0'], 'compose template')
  includesAll(testValues, [
    'accept_mode: review',
    'max_storage_gb: 10',
    'expose_token: false',
    'port_number: 30452'
  ], 'basic test values')
}

function validateVendorProvenance (provenance, app) {
  const libraryRoot = path.join(appRoot, 'templates', 'library', 'base_v2_3_8')
  const license = read(path.join(appRoot, 'vendor', 'truenas-apps', 'LICENSE.LGPL-3.0'))
  const notice = read(path.join(appRoot, 'vendor', 'truenas-apps', 'NOTICE.md'))
  const expectedDeviations = ['__init__.py', 'tests/__init__.py']
  const computed = computeContentIntegrity(libraryRoot)

  equal(provenance.schema, 'hiverelay-vendored-source-provenance-v1', 'vendor provenance schema')
  equal(provenance.version, '2.3.8', 'vendor library version')
  equal(provenance.license, 'LGPL-3.0-only', 'vendor license')
  equal(provenance.licenseSha256, crypto.createHash('sha256').update(license).digest('hex'), 'computed vendor license SHA-256')
  equal(provenance.localPath, 'truenas-app/templates/library/base_v2_3_8', 'vendor local path')
  equal(provenance.upstream?.repository, 'https://github.com/truenas/apps.git', 'vendor upstream repository')
  equal(provenance.upstream?.commit, '531009fca352356237287dbcc119c1365307ab86', 'vendor upstream commit')
  equal(provenance.upstream?.sourcePath, 'ix-dev/community/bambuddy/templates/library/base_v2_3_8', 'vendor upstream source path')
  equal(provenance.upstream?.tree, '3d946a0dbe832cb16e5da40c4a5d6f0dafb2be21', 'vendor upstream Git tree')
  equal(
    provenance.upstream?.officialLibraryHash,
    'cd75c897a1e8fef54b5bd00d0d8849f240bc50db2ef650eccc0ee74f3b2b2dc1',
    'vendor official library hash'
  )
  equal(provenance.upstream?.officialLibraryHash, topScalar(app, 'lib_version_hash'), 'vendor/app official library hash binding')
  equal(provenance.localContent?.algorithm, 'sha256(relative-path NUL decimal-byte-length NUL file-bytes NUL; paths sorted lexicographically)', 'vendor content-integrity algorithm')
  equal(provenance.localContent?.sha256, computed.sha256, 'computed vendor content SHA-256')
  equal(provenance.localContent?.fileCount, computed.fileCount, 'computed vendor file count')
  equal(provenance.localContent?.byteCount, computed.byteCount, 'computed vendor byte count')
  equal(
    provenance.localContent?.normalizedUpstreamGitTreeAlgorithm,
    'Git tree SHA-1 after replacing only the two declared newline-only deviations with their recorded upstream empty blobs',
    'normalized upstream Git-tree algorithm'
  )

  includesAll(license, [
    'GNU LESSER GENERAL PUBLIC LICENSE',
    'Version 3, 29 June 2007'
  ], 'vendored TrueNAS license')
  includesAll(notice, [
    'They are not covered by HiveRelay\'s Apache-2.0 license.',
    'LGPL-3.0-only',
    provenance.upstream.commit,
    provenance.upstream.tree,
    provenance.upstream.officialLibraryHash
  ], 'vendored TrueNAS notice')

  const deviations = Array.isArray(provenance.deviations) ? provenance.deviations : []
  equal(JSON.stringify(deviations.map(item => item.path)), JSON.stringify(expectedDeviations), 'vendor deviation paths')
  for (const deviation of deviations) {
    const bytes = fs.readFileSync(path.join(libraryRoot, deviation.path))
    equal(bytes.toString('hex'), '0a', `vendor deviation bytes for ${deviation.path}`)
    equal(deviation.upstreamGitBlob, 'e69de29bb2d1d6434b8b29ae775ad8c2e48c5391', `vendor upstream empty blob for ${deviation.path}`)
    equal(deviation.localGitBlob, gitBlobHash(bytes), `vendor local blob for ${deviation.path}`)
    equal(deviation.reason, 'newline-only package marker', `vendor deviation reason for ${deviation.path}`)
  }

  const normalizedTree = computeGitTree(libraryRoot, new Set(expectedDeviations))
  equal(provenance.localContent?.normalizedUpstreamGitTree, normalizedTree, 'content-computed normalized upstream Git tree')
  equal(normalizedTree, provenance.upstream.tree, 'normalized vendor content/upstream Git tree binding')
}

function computeContentIntegrity (root) {
  const files = listFiles(root)
  const hash = crypto.createHash('sha256')
  let byteCount = 0

  for (const rel of files) {
    const bytes = fs.readFileSync(path.join(root, rel))
    byteCount += bytes.length
    hash.update(rel)
    hash.update('\0')
    hash.update(String(bytes.length))
    hash.update('\0')
    hash.update(bytes)
    hash.update('\0')
  }

  return { sha256: hash.digest('hex'), fileCount: files.length, byteCount }
}

function listFiles (root, prefix = '') {
  const files = []
  for (const entry of fs.readdirSync(path.join(root, prefix), { withFileTypes: true })) {
    const rel = prefix ? `${prefix}/${entry.name}` : entry.name
    if (entry.isDirectory()) files.push(...listFiles(root, rel))
    else if (entry.isFile()) files.push(rel)
    else errors.push(`vendor library contains unsupported entry ${rel}`)
  }
  return files.sort()
}

function gitBlobHash (bytes) {
  return crypto.createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex')
}

function computeGitTree (root, normalizedEmptyPaths, prefix = '') {
  const entries = fs.readdirSync(path.join(root, prefix), { withFileTypes: true })
    .sort((left, right) => Buffer.compare(
      Buffer.from(`${left.name}${left.isDirectory() ? '/' : ''}`),
      Buffer.from(`${right.name}${right.isDirectory() ? '/' : ''}`)
    ))
  const chunks = []

  for (const entry of entries) {
    const rel = prefix ? `${prefix}/${entry.name}` : entry.name
    let mode
    let digest
    if (entry.isDirectory()) {
      mode = '40000'
      digest = computeGitTree(root, normalizedEmptyPaths, rel)
    } else if (entry.isFile()) {
      mode = '100644'
      const bytes = normalizedEmptyPaths.has(rel) ? Buffer.alloc(0) : fs.readFileSync(path.join(root, rel))
      digest = gitBlobHash(bytes)
    } else {
      errors.push(`vendor library contains unsupported Git-tree entry ${rel}`)
      continue
    }
    chunks.push(Buffer.from(`${mode} ${entry.name}\0`))
    chunks.push(Buffer.from(digest, 'hex'))
  }

  const content = Buffer.concat(chunks)
  return crypto.createHash('sha1').update(`tree ${content.length}\0`).update(content).digest('hex')
}

function read (file) {
  return fs.readFileSync(file, 'utf8')
}

function topScalar (text, key) {
  const match = text.match(new RegExp(`^${escapeRegExp(key)}:\\s*["']?([^"'\\n#]+?)["']?\\s*$`, 'm'))
  if (!match) {
    errors.push(`missing top-level ${key}`)
    return ''
  }
  return match[1].trim()
}

function imageScalar (text, repository, key) {
  const pattern = new RegExp(
    `repository:\\s*${escapeRegExp(repository)}\\s*\\n\\s+${escapeRegExp(key)}:\\s*["']?([^"'\\n#]+)`,
    'm'
  )
  const match = text.match(pattern)
  if (!match) {
    errors.push(`missing ${key} for image ${repository}`)
    return ''
  }
  return match[1].trim()
}

function questionBlock (text, variable) {
  const marker = `  - variable: ${variable}\n`
  const start = text.indexOf(marker)
  if (start === -1) return ''
  const next = text.indexOf('\n  - variable: ', start + marker.length)
  return text.slice(start, next === -1 ? text.length : next)
}

function equal (actual, expected, label) {
  if (actual !== expected) errors.push(`${label} must be ${expected}; found ${actual || '<missing>'}`)
}

function matches (actual, pattern, label) {
  if (!pattern.test(actual)) errors.push(`${label} is invalid: ${actual || '<missing>'}`)
}

function includesAll (text, terms, label) {
  for (const term of terms) {
    if (!text.includes(term)) errors.push(`${label} is missing ${JSON.stringify(term)}`)
  }
}

function excludesAll (text, terms, label) {
  for (const term of terms) {
    if (text.includes(term)) errors.push(`${label} must not contain ${JSON.stringify(term)}`)
  }
}

function escapeRegExp (value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}
