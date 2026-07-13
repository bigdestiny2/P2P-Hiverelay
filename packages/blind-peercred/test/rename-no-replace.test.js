import fs from 'node:fs/promises'
import path from 'node:path'
import b4a from 'b4a'
import test from 'brittle'
import {
  createBlindBoundaryScratch,
  removeBlindBoundaryScratch
} from '../../../test/blind-boundary-scratch.js'
import {
  renameFileNoReplace,
  renameFileNoReplacePlatformSupported
} from '../index.js'

test('native no-replace rename installs once and never overwrites', async t => {
  const root = await createBlindBoundaryScratch('hiverelay-rename-no-replace-')
  t.teardown(() => removeBlindBoundaryScratch(root))
  const source = path.join(root, 'source.tmp')
  const competing = path.join(root, 'competing.tmp')
  const destination = path.join(root, 'final.v1')
  await fs.writeFile(source, b4a.from('first'), { mode: 0o600 })
  await fs.writeFile(competing, b4a.from('second'), { mode: 0o600 })

  t.is(renameFileNoReplace(source, destination), true)
  t.alike(await fs.readFile(destination), b4a.from('first'))
  await t.exception(fs.lstat(source), /ENOENT/)
  t.is(renameFileNoReplace(competing, destination), false)
  t.alike(await fs.readFile(destination), b4a.from('first'))
  t.alike(await fs.readFile(competing), b4a.from('second'))
})

test('native no-replace rename validates path arguments', async t => {
  await t.exception.all(() => renameFileNoReplace('relative', '/tmp/destination'), /absolute/)
  await t.exception.all(() => renameFileNoReplace('/tmp/source', 'relative'), /absolute/)
  await t.exception.all(() => renameFileNoReplace('/tmp/source\0suffix', '/tmp/destination'), /NUL-free/)
  await t.exception.all(() => renameFileNoReplace('/tmp/../tmp/source', '/tmp/destination'), /canonical/)
})

test('native binding reports explicit platform support for no-replace rename', t => {
  t.is(typeof renameFileNoReplacePlatformSupported(), 'boolean')
  if (process.platform === 'darwin' || process.platform === 'linux') {
    t.is(renameFileNoReplacePlatformSupported(), true)
  }
})
