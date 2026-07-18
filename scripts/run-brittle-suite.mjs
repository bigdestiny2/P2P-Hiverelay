#!/usr/bin/env node

import { readdir } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { spawn } from 'node:child_process'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const suite = process.argv[2]
const listOnly = process.argv.includes('--list')
const suites = Object.freeze({
  all: path.join(root, 'test'),
  integration: path.join(root, 'test', 'integration'),
  unit: path.join(root, 'test', 'unit')
})

if (!Object.hasOwn(suites, suite)) {
  process.stderr.write('usage: node scripts/run-brittle-suite.mjs <all|unit|integration>\n')
  process.exitCode = 2
} else {
  const discovered = await discoverTests(suites[suite])
  const ordinary = discovered.filter(file => path.basename(file) !== 'zz-finalize.test.js')
  const finalizers = discovered.filter(file => path.basename(file) === 'zz-finalize.test.js')
  const files = [...ordinary, ...finalizers]

  if (files.length === 0) {
    process.stderr.write(`no tests found for ${suite}\n`)
    process.exitCode = 2
  } else if (listOnly) {
    for (const file of files) process.stdout.write(`${relativeTestPath(file)}\n`)
  } else {
    const runner = ['node_modules/brittle/brittle-node.js', 'node_modules/brittle/bin/node.js']
      .map((candidate) => path.join(root, candidate))
      .find((candidate) => existsSync(candidate))
    if (!runner) throw new Error('brittle node runner not found (brittle 4: brittle-node.js at package root; brittle 3: bin/node.js)')
    const relativeFiles = files.map(relativeTestPath)
    const child = spawn(process.execPath, [runner, '--timeout', '120000', ...relativeFiles], {
      cwd: root,
      stdio: 'inherit',
      windowsHide: true
    })
    const result = await new Promise((resolve, reject) => {
      child.once('error', reject)
      child.once('exit', (code, signal) => resolve({ code, signal }))
    })
    if (result.signal) {
      process.stderr.write(`brittle ${suite} suite terminated by ${result.signal}\n`)
      process.exitCode = 1
    } else {
      process.exitCode = result.code ?? 1
    }
  }
}

async function discoverTests (directory) {
  const files = []
  await walk(directory, files)
  return files.sort(compareNames)
}

async function walk (directory, files) {
  const entries = await readdir(directory, { withFileTypes: true })
  entries.sort((left, right) => compareNames(left.name, right.name))
  for (const entry of entries) {
    const file = path.join(directory, entry.name)
    if (entry.isDirectory()) await walk(file, files)
    else if (entry.isFile() && entry.name.endsWith('.test.js')) files.push(file)
  }
}

function compareNames (left, right) {
  return left < right ? -1 : left > right ? 1 : 0
}

function relativeTestPath (file) {
  return path.relative(root, file).split(path.sep).join('/')
}
