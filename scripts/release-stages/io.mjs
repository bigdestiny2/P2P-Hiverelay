import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { spawnSync } from 'node:child_process'

export function run (command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    timeout: 60000,
    maxBuffer: 16 * 1024 * 1024,
    ...options
  })
  if (result.error || result.status !== 0 || result.signal) {
    // Do not echo child stderr: publishing tools may include credential values.
    throw new Error(`${path.basename(command)} failed (${result.error?.code || result.signal || result.status})`)
  }
  return result.stdout
}

export function readJson (file) {
  const stat = fs.lstatSync(file)
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 1 || stat.size > 2 * 1024 * 1024) {
    throw new Error('Evidence must be a regular JSON file within 2 MiB')
  }
  return JSON.parse(fs.readFileSync(file, 'utf8'))
}

export function digest (file, algorithm = 'sha256', encoding = 'hex') {
  return crypto.createHash(algorithm).update(fs.readFileSync(file)).digest(encoding)
}

export function writeJson (file, value) {
  fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o600 })
}

export function parseArgs (argv, flags) {
  const out = {}
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i]
    if (!flags.includes(flag) || Object.hasOwn(out, flag)) throw new Error(`Unknown or repeated argument: ${flag}`)
    const value = argv[++i]
    if (!value || value.startsWith('--')) throw new Error(`Missing value for ${flag}`)
    out[flag] = value
  }
  return out
}

export function exactKeys (value, fields, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...fields].sort())) {
    throw new Error(`${label} has unknown or missing fields`)
  }
}
