#!/usr/bin/env node

import { constants } from 'node:fs'
import { open, lstat } from 'node:fs/promises'

const path = process.argv[2]
if (!path || process.argv.length !== 3 || !path.startsWith('/') || path.length > 4096 || /[\r\n\0]/.test(path)) {
  throw new Error('disabled gateway config proof requires one bounded absolute path')
}

const before = await lstat(path)
if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size < 1 || before.size > 1024 * 1024) {
  throw new Error('disabled gateway config must be a bounded single-link regular file')
}
if (typeof process.geteuid === 'function' && before.uid !== process.geteuid()) {
  throw new Error('disabled gateway config must be owned by the effective user')
}
if ((before.mode & 0o022) !== 0) throw new Error('disabled gateway config must not be group/world writable')

const handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW || 0))
let text
try {
  const opened = await handle.stat()
  if (!opened.isFile() || opened.nlink !== 1 || opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size) {
    throw new Error('disabled gateway config changed before secure open')
  }
  text = await handle.readFile({ encoding: 'utf8' })
  const after = await handle.stat()
  if (after.dev !== opened.dev || after.ino !== opened.ino || after.size !== opened.size ||
      after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs) {
    throw new Error('disabled gateway config changed during verification')
  }
} finally {
  await handle.close()
}

let config
try { config = JSON.parse(text) } catch { throw new Error('disabled gateway config must be valid JSON') }
if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error('disabled gateway config must be an object')
for (const field of ['mode', 'productProfile']) {
  if (typeof config[field] !== 'string' || !config[field] || config[field].toLowerCase() === 'public-t1-gateway') {
    throw new Error(`disabled gateway config ${field} must explicitly select a non-public-t1 profile`)
  }
}
if (config.hiveAppHostSuffix !== null && config.hiveAppHostSuffix !== '') {
  throw new Error('disabled gateway config must clear hiveAppHostSuffix')
}
if (!Array.isArray(config.hiveAppPublicKeys) || config.hiveAppPublicKeys.length !== 0) {
  throw new Error('disabled gateway config must explicitly clear hiveAppPublicKeys')
}
if (!config.hiveAppPublicVersions || typeof config.hiveAppPublicVersions !== 'object' ||
    Array.isArray(config.hiveAppPublicVersions) || Object.keys(config.hiveAppPublicVersions).length !== 0) {
  throw new Error('disabled gateway config must explicitly clear hiveAppPublicVersions')
}

process.stdout.write('disabled\n')
