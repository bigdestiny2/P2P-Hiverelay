import test from 'brittle'
import { readFileSync } from 'node:fs'

const root = json('package.json')
const lock = json('package-lock.json')
const internalNames = new Map()

for (const workspace of root.workspaces) {
  const manifest = json(`${workspace}/package.json`)
  internalNames.set(manifest.name, workspace)
}

test('production install resolves every internal dependency from its workspace', (t) => {
  for (const workspace of root.workspaces) {
    const manifest = json(`${workspace}/package.json`)
    const locked = lock.packages[workspace]
    const link = lock.packages[`node_modules/${manifest.name}`]

    t.ok(locked, `${workspace} has a lock entry`)
    t.is(locked.version, manifest.version, `${workspace} version matches its manifest`)
    t.is(link?.link, true, `${manifest.name} is a workspace link`)
    t.is(link?.resolved, workspace, `${manifest.name} resolves to ${workspace}`)

    for (const section of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
      for (const [name, version] of Object.entries(manifest[section] || {})) {
        if (!internalNames.has(name)) continue
        t.is(locked[section]?.[name], version, `${workspace} ${section}.${name} matches its manifest`)
      }
    }
  }
})

test('production lifecycle dependencies and clean-install CI gate are retained', (t) => {
  const workflow = readFileSync('.github/workflows/test.yml', 'utf8')
  const install = 'npm ci --omit=dev --no-audit --no-fund --include-workspace-root --workspace packages/core --workspace packages/services --workspace packages/client --workspace packages/verifier'

  t.is(root.dependencies['patch-package'], '^8.0.1')
  t.absent(root.devDependencies['patch-package'])
  t.absent(lock.packages['node_modules/patch-package'].dev)
  t.ok(workflow.includes('production-install:'))
  t.ok(workflow.includes('container: node:20-bookworm-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0'))
  t.ok(workflow.includes(install))
  t.ok(workflow.includes('test ! -e node_modules/@hiverelay/blind-peercred'))
  t.ok(workflow.includes('-type d -name node_modules -prune'))
  t.ok(workflow.includes('/tmp/source-before.sha256'))
  t.ok(workflow.includes('diff -u /tmp/source-before.sha256 /tmp/source-after.sha256'))
  t.absent(workflow.includes('git diff --exit-code'))
})

function json (file) {
  return JSON.parse(readFileSync(file, 'utf8'))
}
