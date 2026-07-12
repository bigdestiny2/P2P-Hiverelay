#!/usr/bin/env node
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import process from 'node:process'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { pathToFileURL } from 'node:url'
import { build } from 'esbuild'
import { computeWireRuntimeVectors } from '../packages/blind-protocol/wire-runtime-vectors.js'

const run = promisify(execFile)
const root = process.cwd()
const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'hiverelay-wire-runtime-'))

function same (left, right, label) {
  if (JSON.stringify(left) !== JSON.stringify(right)) {
    throw new Error(`${label} public WIRE bytes differ from Node`)
  }
}

try {
  const nodeVectors = computeWireRuntimeVectors()
  const bare = path.join(root, 'node_modules', 'bare', 'bin', 'bare')
  const bareRun = await run(bare, [path.join(root, 'scripts', 'emit-blind-wire-runtime-vectors.mjs')], {
    cwd: root,
    maxBuffer: 1024 * 1024
  })
  same(nodeVectors, JSON.parse(bareRun.stdout.trim()), 'Bare')

  const browserBundle = path.join(temporary, 'browser.mjs')
  await build({
    stdin: {
      contents: "export { computeWireRuntimeVectors } from './packages/blind-protocol/wire-runtime-vectors.js'\n",
      resolveDir: root,
      sourcefile: 'hiverelay-wire-runtime-browser-entry.mjs'
    },
    bundle: true,
    platform: 'browser',
    format: 'esm',
    outfile: browserBundle,
    logLevel: 'silent'
  })
  const browser = await import(`${pathToFileURL(browserBundle).href}?v=${Date.now()}`)
  same(nodeVectors, browser.computeWireRuntimeVectors(), 'browser bundle')

  const finalCell = await fs.readFile(path.join(root,
    'packages/blind-protocol/vectors/dispatch/cell-get-request.bin'))
  const finalForward = await fs.readFile(path.join(root,
    'packages/blind-protocol/vectors/dispatch/forward-data.bin'))
  const finalOuter = await fs.readFile(path.join(root,
    'packages/blind-protocol/vectors/outer/cell-get-class-1.bin'))
  if (finalCell.toString('hex') !== nodeVectors.cellGet ||
      finalForward.toString('hex') !== nodeVectors.forwardData ||
      finalOuter.toString('hex') !== nodeVectors.outer) {
    throw new Error('cross-runtime framing bytes differ from final checked-in WIRE vectors')
  }
  process.stdout.write(`blind public WIRE cross-runtime bytes verified (${Object.keys(nodeVectors).length} vectors; Node=Bare=browser)\n`)
} finally {
  await fs.rm(temporary, { recursive: true, force: true })
}
