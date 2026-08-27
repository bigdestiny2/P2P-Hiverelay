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

  t.is(root.dependencies['patch-package'], '^8.0.1')
  t.absent(root.devDependencies['patch-package'])
  t.absent(lock.packages['node_modules/patch-package'].dev)
  t.ok(workflow.includes('production-install:'))
  t.ok(workflow.includes('npm ci --omit=dev --no-audit --no-fund'))
  t.ok(workflow.includes('git diff --exit-code'))
})

function json (file) {
  return JSON.parse(readFileSync(file, 'utf8'))
}
