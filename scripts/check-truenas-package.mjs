#!/usr/bin/env node

import fs from 'node:fs'
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
  'templates/test_values/basic-values.yaml'
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
  const rootPackage = JSON.parse(read(path.join(repoRoot, 'package.json')))
  const readme = read(path.join(appRoot, 'README.md'))
  const app = read(path.join(appRoot, 'app.yaml'))
  const values = read(path.join(appRoot, 'ix_values.yaml'))
  const questions = read(path.join(appRoot, 'questions.yaml'))
  const template = read(path.join(appRoot, 'templates', 'docker-compose.yaml'))
  const testValues = read(path.join(appRoot, 'templates', 'test_values', 'basic-values.yaml'))

  const upstreamVersion = topScalar(app, 'app_version')
  const catalogVersion = topScalar(app, 'version')
  const imageTag = imageScalar(values, 'ghcr.io/bigdestiny2/p2p-hiverelay', 'tag')

  equal(topScalar(app, 'name'), 'blindspark', 'catalog app name')
  equal(topScalar(app, 'train'), 'community', 'catalog train')
  equal(upstreamVersion, rootPackage.version, 'catalog upstream version')
  equal(imageTag, rootPackage.version, 'catalog image tag')
  matches(catalogVersion, /^\d+\.\d+\.\d+$/, 'catalog package version')
  equal(topScalar(app, 'lib_version'), '2.3.8', 'TrueNAS rendering library version')
  equal(
    topScalar(app, 'lib_version_hash'),
    'cd75c897a1e8fef54b5bd00d0d8849f240bc50db2ef650eccc0ee74f3b2b2dc1',
    'TrueNAS rendering library hash'
  )
  includesAll(readme, [`Upstream HiveRelay release: \`${rootPackage.version}\``], 'TrueNAS app README')

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
