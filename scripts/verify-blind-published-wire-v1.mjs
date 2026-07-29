#!/usr/bin/env node

import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { verifyBlindPublishedWireV1 } from './lib/blind-published-wire-v1.mjs'

const scriptPath = fileURLToPath(import.meta.url)
const repoRoot = path.resolve(path.dirname(scriptPath), '..')

export function main (argv = process.argv.slice(2)) {
  if (!Array.isArray(argv) || argv.length !== 1 || argv[0] !== '--check') {
    throw new Error('verify-blind-published-wire-v1 requires exactly --check; unknown and write flags are forbidden')
  }
  const result = verifyBlindPublishedWireV1({ root: repoRoot })
  process.stdout.write(JSON.stringify({ status: 'pass', ...result }, null, 2) + '\n')
  return result
}

if (path.resolve(process.argv[1] || '') === scriptPath) {
  try {
    main()
  } catch (error) {
    const detail = Array.from(String(error && error.message ? error.message : error), character => {
      const code = character.charCodeAt(0)
      return code <= 31 || code === 127 ? ' ' : character
    }).join('').slice(0, 1200)
    process.stderr.write(`published WIRE v1 verification failed: ${detail}\n`)
    process.exitCode = 1
  }
}
