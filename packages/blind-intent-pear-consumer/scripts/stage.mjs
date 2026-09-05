import { createHash } from 'node:crypto'
import { cpSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const target = dirname(dirname(fileURLToPath(import.meta.url)))
const root = join(target, '../..')
const backend = ['index.js', 'runtime.js', 'package.json', 'README.md', ...readdirSync(join(root, 'packages/blind-intent-store-bare/native')).map(name => 'native/' + name)]
const sources = backend.map(name => ['packages/blind-intent-store-bare/' + name, 'vendor/blind-intent-store-bare/' + name])
const fixtures = [
  'packages/blind-intent-store-node/package.json', 'packages/blind-intent-store-node/index.js',
  'packages/blind-client/package.json', 'packages/blind-client/intent.js', 'packages/blind-client/bytes.js',
  'packages/blind-client/errors.js', 'packages/blind-client/runtime/node.js',
  'packages/blind-protocol/package.json', 'packages/blind-protocol/wire-runtime-authority.js'
]
for (const name of fixtures) sources.push([name, 'test/baseline/' + name])
const manifest = []
for (const [source, relative] of sources) {
  const destination = join(target, relative)
  mkdirSync(dirname(destination), { recursive: true })
  cpSync(join(root, source), destination)
  manifest.push({ source, path: relative, sha256: createHash('sha256').update(readFileSync(destination)).digest('hex') })
}
// Resolve the exact unchanged protocol fixture without editing its imports.
mkdirSync(join(target, 'test/baseline/node_modules/@hiverelay'), { recursive: true })
cpSync(join(target, 'test/baseline/packages/blind-protocol'), join(target, 'test/baseline/node_modules/@hiverelay/blind-protocol'), { recursive: true })
writeFileSync(join(target, 'vendor/source-manifest.json'), JSON.stringify(manifest.filter(item => item.path.startsWith('vendor/')), null, 2) + '\n')
writeFileSync(join(target, 'test/source-manifest.json'), JSON.stringify(manifest.filter(item => item.path.startsWith('test/')), null, 2) + '\n')
console.log(JSON.stringify({ staged: manifest.length }))
