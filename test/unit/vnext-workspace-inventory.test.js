import test from 'brittle'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { execFileSync } from 'node:child_process'
import {
  inventoryVnextWorkspaces,
  parsePorcelainV1
} from '../../scripts/inventory-vnext-workspaces.mjs'

test('vNext workspace inventory parses NUL-safe modifications and renames', (t) => {
  const parsed = parsePorcelainV1(Buffer.from(' M ordinary.js\0R  new name.js\0old name.js\0?? odd\nname.js\0'))
  t.alike(parsed, [
    { status: 'R ', path: 'new name.js', originalPath: 'old name.js' },
    { status: '??', path: 'odd\nname.js', originalPath: null },
    { status: ' M', path: 'ordinary.js', originalPath: null }
  ])
})

test('vNext workspace inventory commits to dirty tracked and untracked content without recording contents', (t) => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'vnext-inventory-'))
  const controller = path.join(workspace, '00-core', 'controller')
  const app = path.join(workspace, '02-apps', 'app')
  const noGit = path.join(workspace, '02-apps', 'no-git')
  const unborn = path.join(workspace, '04-experiments', 'unborn')
  initRepo(controller, 'controller')
  initRepo(app, 'app')
  initRepo(path.join(app, 'nested'), 'nested')
  fs.mkdirSync(unborn, { recursive: true })
  git(unborn, ['init', '-q'])
  fs.writeFileSync(path.join(unborn, 'package.json'), '{"name":"unborn","version":"0.0.0"}\n')
  fs.mkdirSync(noGit, { recursive: true })
  fs.writeFileSync(path.join(noGit, 'package.json'), '{"name":"no-git","version":"1.0.0"}\n')
  fs.writeFileSync(path.join(app, 'tracked.txt'), 'changed\n')
  fs.writeFileSync(path.join(app, 'untracked secret.txt'), 'private sentinel\n')

  const inventory = inventoryVnextWorkspaces({
    workspaceRoot: workspace,
    controllerRoot: controller,
    observedAt: '2026-07-12T00:00:00.000Z'
  })
  t.is(inventory.repositories.length, 3, 'controller excludes itself while nested and unborn repositories remain visible')
  const row = inventory.repositories.find(row => row.path === '02-apps/app')
  t.is(row.path, '02-apps/app')
  t.ok(row.dirty)
  t.is(row.trackedChanges, 1)
  t.is(row.untrackedChanges, 2)
  t.ok(row.changes.some(change => change.status === '??' && change.path === 'untracked secret.txt'))
  const serialized = JSON.stringify(inventory)
  t.absent(serialized.includes('private sentinel'), 'evidence contains commitments, never untracked contents')
  t.ok(inventory.repositories.some(row => row.path === '02-apps/app/nested'))
  const unbornRow = inventory.repositories.find(row => row.path === '04-experiments/unborn')
  t.ok(unbornRow.unborn)
  t.is(unbornRow.preservation, 'initial-commit-or-immutable-archive-required')
  t.is(inventory.nonGitProjects[0].path, '02-apps/no-git')
  t.absent(inventory.summary.preservationComplete)
  fs.rmSync(workspace, { recursive: true, force: true })
})

function initRepo (root, name) {
  fs.mkdirSync(root, { recursive: true })
  git(root, ['init', '-q'])
  git(root, ['config', 'user.name', 'Inventory Test'])
  git(root, ['config', 'user.email', 'inventory@example.invalid'])
  fs.writeFileSync(path.join(root, 'package.json'), `${JSON.stringify({ name, version: '1.0.0' }, null, 2)}\n`)
  fs.writeFileSync(path.join(root, 'tracked.txt'), 'base\n')
  git(root, ['add', '.'])
  git(root, ['commit', '-q', '-m', 'base'])
}

function git (root, args) {
  execFileSync('/usr/bin/git', args, { cwd: root, stdio: 'ignore' })
}
