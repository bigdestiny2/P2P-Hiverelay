import fs from 'node:fs/promises'
import path from 'node:path'
import os from 'node:os'
import test from 'brittle'
import { privateVectorRuntime } from '../../scripts/lib/private-vector-runtime.mjs'

test('private vector runtime does not fall back to ambient Bare when its qualified install is missing', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'hr-vector-runtime-'))
  t.teardown(() => fs.rm(root, { recursive: true, force: true }))
  await t.exception(privateVectorRuntime(root, ''), /private vector runtime failed.*ENOENT/)
  await t.exception(privateVectorRuntime(root, 'bare'), /must be an absolute path/)
  await t.exception(privateVectorRuntime(root, path.join(root, 'missing')), /private vector runtime failed.*ENOENT/)
})

test('private vector runtime rejects a different version, substituted executable and malformed probe', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'hr-vector-probe-'))
  t.teardown(() => fs.rm(root, { recursive: true, force: true }))
  const executable = path.join(root, 'adversarial-probe')
  const probe = async body => fs.writeFile(executable, '#!/usr/bin/env node\n' + body, { mode: 0o700 })
  await probe('console.log(JSON.stringify({ version: "v1.37.1", executable: process.argv[1] }))\n')
  await t.exception(privateVectorRuntime(root, executable), /exact v1.31.0 executable/)
  await probe('console.log(JSON.stringify({ version: "v1.31.0", executable: process.execPath }))\n')
  await t.exception(privateVectorRuntime(root, executable), /exact v1.31.0 executable/)
  await probe('console.log("not a receipt")\n')
  await t.exception(privateVectorRuntime(root, executable), /private vector runtime failed/)
})
