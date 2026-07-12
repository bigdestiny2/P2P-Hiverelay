#!/usr/bin/env node
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import process from 'node:process'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { fileURLToPath, pathToFileURL } from 'node:url'
import b4a from 'b4a'
import { build } from 'esbuild'
import { computeClientCompositionRuntimeVectors } from '../packages/blind-protocol/client-composition-runtime-vectors.js'
import {
  blake2b256,
  hashClientCompositionFormat,
  hashClientCompositionVectorSet
} from '../packages/blind-protocol/hashes.js'

const run = promisify(execFile)
const root = fileURLToPath(new URL('..', import.meta.url))
const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'hiverelay-client-composition-runtime-'))
const format = await fs.readFile(path.join(root,
  'packages/blind-protocol/hiverelay-blind-client-composition-format-v1.cenc'))
const manifest = await fs.readFile(path.join(root,
  'packages/blind-protocol/hiverelay-blind-client-composition-vector-manifest-v1.cenc'))
const nodeVectors = Object.freeze({
  runtimeVectors: computeClientCompositionRuntimeVectors(),
  checkedFormatHash: b4a.toString(hashClientCompositionFormat(format), 'hex'),
  checkedVectorSetHash: b4a.toString(hashClientCompositionVectorSet(manifest), 'hex')
})

function same (left, right, label) {
  if (JSON.stringify(left) !== JSON.stringify(right)) {
    throw new Error(`${label} client-composition bytes differ from Node`)
  }
}

try {
  const bare = path.join(root, 'node_modules', 'bare', 'bin', 'bare')
  const bareRun = await run(bare, [path.join(root,
    'scripts/emit-blind-client-composition-runtime-vectors.mjs')], {
    cwd: root,
    maxBuffer: 16 * 1024 * 1024
  })
  same(nodeVectors, JSON.parse(bareRun.stdout.trim()), 'Bare')

  const browserBundle = path.join(temporary, 'browser.mjs')
  await build({
    stdin: {
      contents: 'export { computeClientCompositionRuntimeVectors } from \'./packages/blind-protocol/client-composition-runtime-vectors.js\'\n' +
        'export { hashClientCompositionFormat, hashClientCompositionVectorSet } from \'./packages/blind-protocol/hashes.js\'\n',
      resolveDir: root,
      sourcefile: 'hiverelay-client-composition-browser-entry.mjs'
    },
    bundle: true,
    platform: 'browser',
    format: 'esm',
    outfile: browserBundle,
    logLevel: 'silent'
  })
  const browser = await import(`${pathToFileURL(browserBundle).href}?v=${Date.now()}`)
  const browserVectors = {
    runtimeVectors: browser.computeClientCompositionRuntimeVectors(),
    checkedFormatHash: b4a.toString(browser.hashClientCompositionFormat(new Uint8Array(format)), 'hex'),
    checkedVectorSetHash: b4a.toString(browser.hashClientCompositionVectorSet(new Uint8Array(manifest)), 'hex')
  }
  same(nodeVectors, browserVectors, 'browser-targeted bundle')

  const fixtures = nodeVectors.runtimeVectors.vectorDigests
  for (const [vectorPath, expected] of Object.entries(fixtures)) {
    const bytes = await fs.readFile(path.join(root,
      'packages/blind-protocol/vectors/client-composition', vectorPath))
    if (bytes.byteLength !== expected.byteLength ||
        b4a.toString(blake2b256(bytes), 'hex') !== expected.hash) {
      throw new Error(`checked client-composition vector differs from runtime bytes: ${vectorPath}`)
    }
  }
  process.stdout.write('client-composition cross-runtime bytes verified ' +
    `(${Object.keys(fixtures).length} fixtures; Node=Bare=browser-targeted bundle)\n`)
} finally {
  await fs.rm(temporary, { recursive: true, force: true })
}
