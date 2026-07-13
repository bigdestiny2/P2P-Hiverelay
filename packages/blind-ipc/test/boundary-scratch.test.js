import fs from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'brittle'
import {
  blindBoundaryScratchPath,
  blindBoundaryScratchRoot,
  createBlindBoundaryScratch,
  removeBlindBoundaryScratch
} from '../../../test/blind-boundary-scratch.js'

function isContained (parent, candidate) {
  const relative = path.relative(parent, candidate)
  return relative !== '' && !relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative)
}

test('blind boundary test scratch remains inside this checkout', async t => {
  const checkout = await fs.realpath(fileURLToPath(new URL('../../../', import.meta.url)))
  const root = await blindBoundaryScratchRoot()
  const directory = await createBlindBoundaryScratch('blind-boundary-containment-')
  t.teardown(() => removeBlindBoundaryScratch(directory))

  t.ok(isContained(checkout, root))
  t.ok(isContained(root, directory))
  t.ok((await fs.lstat(directory)).isDirectory())
  t.ok(isContained(root, await blindBoundaryScratchPath('never-created.sock')))
})

test('a symlinked scratch ancestor is rejected before it can create outside the checkout', async t => {
  const directory = await createBlindBoundaryScratch('blind-boundary-symlink-ancestor-')
  t.teardown(() => removeBlindBoundaryScratch(directory))
  const escape = path.join(directory, 'escape')
  const checkout = await fs.realpath(fileURLToPath(new URL('../../../', import.meta.url)))
  const outsideDirectory = path.dirname(checkout)
  const outsideName = `blind-boundary-must-not-exist-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}`
  const outside = path.join(outsideDirectory, outsideName)
  await fs.symlink(outsideDirectory, escape)

  const previous = process.env.HIVERELAY_BLIND_BOUNDARY_TEST_ROOT
  try {
    process.env.HIVERELAY_BLIND_BOUNDARY_TEST_ROOT = path.join(escape, outsideName)
    await t.exception(blindBoundaryScratchRoot(), /symbolic-link or non-directory ancestor/)
  } finally {
    if (previous === undefined) delete process.env.HIVERELAY_BLIND_BOUNDARY_TEST_ROOT
    else process.env.HIVERELAY_BLIND_BOUNDARY_TEST_ROOT = previous
  }

  let error = null
  try {
    await fs.lstat(outside)
  } catch (failure) {
    error = failure
  }
  t.is(error?.code, 'ENOENT', 'the rejected override did not create a child outside the checkout')
})
