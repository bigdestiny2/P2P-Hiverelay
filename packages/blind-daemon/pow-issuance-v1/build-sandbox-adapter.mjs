#!/usr/bin/env node
// Build the deployable pow-issuance-v1 sandbox adapter script: injects the fleet
// issuer key into sandbox-adapter.js, enforces the contract's forbidden-identifier
// scan, and prints the exact SHA-256 to pin in blind.env.
// Usage:
//   node build-sandbox-adapter.mjs --key-hex <64 hex> [--out <file>]
//   node build-sandbox-adapter.mjs --key-file <32-byte file> [--out <file>]
// The key is read into memory only, never logged.
import { createHash } from 'node:crypto'
import fs from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const PLACEHOLDER = '__POW_ISSUER_KEY_HEX__'
const FORBIDDEN = Object.freeze([
  ['import', /\bimport\b/u],
  ['Promise', /\bPromise\b/u],
  ['async', /\basync\b/u],
  ['await', /\bawait\b/u],
  ['Array.fromAsync', /\bArray\s*\.\s*fromAsync\b/u],
  ['process', /\bprocess\b/u],
  ['require', /\brequire\b/u],
  ['module', /\bmodule\b/u],
  ['global', /\bglobal\b/u],
  ['Buffer', /\bBuffer\b/u]
])

function fail (message) {
  process.stderr.write(`build-sandbox-adapter: ${message}\n`)
  process.exit(1)
}

const args = process.argv.slice(2)
let keyHex = null
let outFile = null
for (let index = 0; index < args.length; index++) {
  if (args[index] === '--key-hex') keyHex = args[++index]
  else if (args[index] === '--key-file') keyHex = (await fs.readFile(args[++index])).toString('hex')
  else if (args[index] === '--out') outFile = args[++index]
  else fail(`unknown argument ${args[index]}`)
}
if (keyHex == null || !/^[0-9a-f]{64}$/.test(keyHex)) {
  fail('a 32-byte fleet issuer key is required as --key-hex <64 lowercase hex> or --key-file <file>')
}

const templateFile = fileURLToPath(new URL('./sandbox-adapter.js', import.meta.url))
const template = await fs.readFile(templateFile, 'utf8')
if (!template.includes(PLACEHOLDER)) fail(`template has no ${PLACEHOLDER} placeholder`)
const source = template.split(PLACEHOLDER).join(keyHex)
if (source.includes(PLACEHOLDER)) fail('placeholder substitution incomplete')
if (source.includes('\0')) fail('built script contains NUL bytes')
for (const [name, pattern] of FORBIDDEN) {
  if (pattern.test(source)) fail(`built script contains forbidden ${name} syntax or authority`)
}
const bytes = Buffer.from(source, 'utf8')
const sha256 = createHash('sha256').update(bytes).digest('hex')
if (outFile) {
  await fs.writeFile(outFile, bytes, { mode: 0o640 })
  await fs.chmod(outFile, 0o640)
}
process.stdout.write(JSON.stringify({
  scriptFile: outFile == null ? null : path.resolve(outFile),
  scriptBytes: bytes.byteLength,
  scriptSha256: sha256
}) + '\n')
