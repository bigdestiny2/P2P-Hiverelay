import test from 'brittle'
import { readFileSync } from 'fs'
import { fileURLToPath } from 'url'

const root = fileURLToPath(new URL('../..', import.meta.url))

function source (path) {
  return readFileSync(root + '/' + path, 'utf8')
}

function matches (path, pattern) {
  return source(path).split('\n').map(line => line.trim()).filter(line => pattern.test(line))
}

test('storage authority source invariant pins every exact proof caller', (t) => {
  const exactAdmission = matches('packages/core/config/storage-admission-authority.js', /this\.admission\(/)
  t.alike(exactAdmission, [
    'const admission = this.admission(newRemaining, { excluding: key, refresh: true })'
  ], 'reserve/cap-raise is the only direct exact admission caller')

  const reserveAllowlist = [
    ['packages/core/core/relay-node/app-lifecycle.js', /storageAdmission\.reserve\(/, 2, 'drive new/cap-raise'],
    ['packages/core/core/relay-node/seeder.js', /storageAdmission\.reserve\(/, 2, 'explicit core new/cap-raise'],
    ['packages/core/core/app-registry.js', /storageAdmission\.reserve\(/, 1, 'registry journal commitment'],
    ['packages/services/builtin/outboxlog/hypercore-journal.js', /authority\.reserve\(/, 1, 'outbox aggregate journal commitment']
  ]
  for (const [path, pattern, count, purpose] of reserveAllowlist) {
    t.is(matches(path, pattern).length, count, `${purpose}: exact reserve count`)
  }

  t.alike(
    matches('packages/core/core/app-registry.js', /storageAdmission\.runPhysicalMutation\(/),
    ['return await this.storageAdmission.runPhysicalMutation({ purpose, phase }, run)'],
    'configured AppRegistry physical writes retain pre/post attestation authority'
  )

  for (const path of [
    'packages/core/core/relay-node/index.js',
    'packages/core/core/relay-node/bare-relay.js'
  ]) {
    t.is(matches(path, /this\._storageUsedBytes\(\)/).length, 1, `${path}: exact tree resolver is constructor-bound only`)
    t.is(matches(path, /measureProvenStorageTreeBytes\(this\.config\)/).length, 1, `${path}: one exact tree implementation`)
    t.is(matches(path, /storageAdmission\.admission\(/).length, 0, `${path}: no speculative exact admission caller`)
  }

  for (const path of [
    'packages/core/core/auto-heal.js',
    'packages/core/core/relay-node/seeder.js'
  ]) {
    t.is(matches(path, /\.admission\(/).length, 0, `${path}: timer/preflight never calls exact admission`)
  }
})
