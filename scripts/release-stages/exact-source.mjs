import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { run, digest } from './io.mjs'

const blobHash = bytes => crypto.createHash('sha1').update(`blob ${bytes.byteLength}\0`).update(bytes).digest('hex')
function safePath (file) {
  if (!file || /[\x00-\x1f\x7f\\]/.test(file) || path.posix.isAbsolute(file) || path.posix.normalize(file) !== file || file.split('/').includes('..')) throw new Error('Unsafe source artifact path')
  return file
}
function filesBelow (root, prefix = '') {
  const files = []
  for (const name of fs.readdirSync(path.join(root, prefix))) {
    const relative = safePath(prefix ? `${prefix}/${name}` : name)
    const stat = fs.lstatSync(path.join(root, relative))
    if (stat.isDirectory()) files.push(...filesBelow(root, relative))
    else if (stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1) files.push(relative)
    else throw new Error('Source artifact contains a link or special file')
  }
  return files.sort()
}

// Builds from committed bytes, never from a post-install/test working folder.
// Archive attributes are not permission to omit or rewrite a reviewed blob.
export function createExactReleaseSource ({ repoRoot, sha, destination }) {
  if (!/^[a-f0-9]{40}$/.test(sha || '')) throw new Error('Exact admitted release SHA is required')
  if (run('git', ['rev-parse', '--verify', `${sha}^{commit}`], { cwd: repoRoot }).trim() !== sha) throw new Error('Release source is not the exact admitted commit')
  fs.mkdirSync(destination, { mode: 0o700 })
  const source = path.join(destination, 'source')
  fs.mkdirSync(source, { mode: 0o700 })
  const archive = path.join(destination, 'source.tar')
  const inventory = new Map()
  for (const record of run('git', ['ls-tree', '-rz', '--full-tree', sha], { cwd: repoRoot }).split('\0').filter(Boolean)) {
    const split = record.indexOf('\t')
    const [mode, kind, hash] = record.slice(0, split).split(' ')
    const file = safePath(record.slice(split + 1))
    if (kind !== 'blob' || !['100644', '100755'].includes(mode) || !/^[a-f0-9]{40}$/.test(hash)) throw new Error('Release source requires ordinary committed files')
    inventory.set(file, { path: file, mode, gitBlob: hash })
  }
  run('git', ['archive', '--format=tar', `--output=${archive}`, sha], { cwd: repoRoot })
  run('tar', ['-xf', archive, '-C', source])
  const files = filesBelow(source)
  if (files.length !== inventory.size) throw new Error('Archived source file inventory differs from admitted commit')
  for (const file of files) {
    const expected = inventory.get(file)
    const actual = fs.readFileSync(path.join(source, file))
    if (!expected || blobHash(actual) !== expected.gitBlob) throw new Error('Archived source bytes differ from admitted commit')
    const executable = (fs.statSync(path.join(source, file)).mode & 0o111) !== 0
    if (executable !== (expected.mode === '100755')) throw new Error('Archived source executable mode differs from admitted commit')
  }
  return { source, inventory, receipt: { schemaVersion: 1, sourceCommit: sha, archiveSha256: digest(archive), files: [...inventory.values()] } }
}

export function verifyPackedReleaseSource ({ file, packageDirectory, inventory, destination }) {
  safePath(packageDirectory)
  const names = run('tar', ['-tzf', file]).trim().split('\n').filter(Boolean)
  const seen = new Set()
  for (const name of names) {
    const normalized = name.endsWith('/') ? name.slice(0, -1) : name
    safePath(normalized)
    if (normalized !== 'package' && !normalized.startsWith('package/')) throw new Error('npm archive has an invalid root')
    if (seen.has(normalized)) throw new Error('npm archive file inventory is duplicated')
    seen.add(normalized)
  }
  // npm's ordinary packed files need no symbolic/hard links or special nodes.
  const types = run('tar', ['-tvzf', file]).trim().split('\n').filter(Boolean).map(line => line[0])
  if (types.some(type => type !== '-' && type !== 'd')) throw new Error('npm archive contains a link or special file')
  fs.mkdirSync(destination, { mode: 0o700 })
  run('tar', ['-xzf', file, '-C', destination])
  const files = filesBelow(path.join(destination, 'package'))
  if (files.length === 0) throw new Error('npm archive file inventory is empty')
  for (const name of files) {
    const expected = inventory.get(`${packageDirectory}/${name}`)
    if (!expected || blobHash(fs.readFileSync(path.join(destination, 'package', name))) !== expected.gitBlob) throw new Error('Packed npm bytes are absent from or differ from the admitted source')
  }
  return files.map(name => `${packageDirectory}/${name}`)
}
