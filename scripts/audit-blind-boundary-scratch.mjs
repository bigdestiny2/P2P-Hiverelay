import fs from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(fileURLToPath(new URL('..', import.meta.url)))
const boundaryTestDirectories = [
  'packages/blind-ipc/test',
  'packages/blind-peercred/test',
  'packages/blind-edge/test',
  'packages/blind-daemon/test'
]
const prohibited = [
  { pattern: /(?:fs\.)?mkdtemp\s*\(/, reason: 'direct mkdtemp allocation bypasses the contained scratch helper' },
  { pattern: /\bos\.tmpdir\s*\(/, reason: 'os.tmpdir allocation bypasses the contained scratch helper' },
  { pattern: /fs\.realpath\s*\(\s*['"]\/tmp['"]\s*\)/, reason: 'the global /tmp directory bypasses the contained scratch helper' },
  { pattern: /(?:fs\.)?rm\s*\(/, reason: 'direct scratch cleanup bypasses the scoped removal helper' }
]

const violations = []
for (const directory of boundaryTestDirectories) {
  const absoluteDirectory = path.join(root, directory)
  const names = (await fs.readdir(absoluteDirectory)).filter(name => name.endsWith('.test.js')).sort()
  for (const name of names) {
    const relative = path.join(directory, name)
    const source = await fs.readFile(path.join(root, relative), 'utf8')
    for (const { pattern, reason } of prohibited) {
      if (pattern.test(source)) violations.push(`${relative}: ${reason}`)
    }
  }
}

if (violations.length > 0) {
  for (const violation of violations) console.error(violation)
  process.exitCode = 1
} else {
  console.log('blind boundary scratch audit: all temporary allocations use the contained helper')
}
