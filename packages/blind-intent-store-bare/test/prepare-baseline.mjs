import { createHash } from 'node:crypto'
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, symlinkSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

// Stage byte-identical accepted sources under our test ownership so qualification
// does not install dependencies into the accepted Node package or root workspace.
const directory = dirname(fileURLToPath(import.meta.url))
const root = join(directory, '../../..')
const target = join(directory, '.baseline')
const files = [
  'packages/blind-intent-store-node/package.json',
  'packages/blind-intent-store-node/index.js',
  'packages/blind-intent-store-node/test/process-fixture.mjs',
  'packages/blind-client/package.json',
  'packages/blind-client/intent.js',
  'packages/blind-client/bytes.js',
  'packages/blind-client/errors.js',
  'packages/blind-client/runtime/node.js',
  'packages/blind-client/runtime/bare.js',
  'packages/blind-protocol/package.json',
  'packages/blind-protocol/wire-runtime-authority.js'
]
const manifest = []
for (const path of files) {
  const source = join(root, path)
  const destination = join(target, path)
  mkdirSync(dirname(destination), { recursive: true })
  copyFileSync(source, destination)
  const digest = createHash('sha256').update(readFileSync(destination)).digest('hex')
  manifest.push({ path, sha256: digest })
}
const dependencies = join(directory, '../node_modules')
mkdirSync(join(target, 'node_modules/@hiverelay'), { recursive: true })
for (const name of readdirSync(dependencies)) {
  if (name.startsWith('.') || name.startsWith('@')) continue
  const path = join(target, 'node_modules', name)
  if (!existsSync(path)) symlinkSync(join(dependencies, name), path)
}
const protocol = join(target, 'node_modules/@hiverelay/blind-protocol')
if (!existsSync(protocol)) symlinkSync(join(target, 'packages/blind-protocol'), protocol)
writeFileSync(join(target, 'source-manifest.json'), JSON.stringify(manifest, null, 2) + '\n')
console.log(JSON.stringify({ stagedFiles: manifest }))
