#!/usr/bin/env node
import fs from 'node:fs'
import path from 'node:path'
import { run, parseArgs, digest } from './io.mjs'
import { RELEASE_REPOSITORY } from './distribution.mjs'
const args = parseArgs(process.argv.slice(2), ['--run-id', '--artifact-id', '--out'])
for (const key of ['--run-id', '--artifact-id']) if (!/^[1-9][0-9]*$/.test(args[key] || '')) throw new Error('Exact positive Actions IDs required')
if (!args['--out']) throw new Error('--out is required')
const out = path.resolve(args['--out'])
fs.mkdirSync(out, { mode: 0o700 })
const artifact = JSON.parse(run('gh', ['api', `repos/${RELEASE_REPOSITORY}/actions/artifacts/${args['--artifact-id']}`]))
if (String(artifact.id) !== args['--artifact-id'] || String(artifact.workflow_run?.id) !== args['--run-id'] || artifact.expired !== false || !/^sha256:[a-f0-9]{64}$/.test(artifact.digest || '') || !Number.isSafeInteger(artifact.size_in_bytes) || artifact.size_in_bytes < 1 || artifact.size_in_bytes > 512 * 1024 * 1024) throw new Error('Qualification artifact is unavailable or exceeds its bound')
const archive = path.join(out, '.download.zip')
const fd = fs.openSync(archive, 'wx', 0o600)
try { run('gh', ['api', `repos/${RELEASE_REPOSITORY}/actions/artifacts/${args['--artifact-id']}/zip`], { stdio: ['ignore', fd, 'pipe'], timeout: 120000 }) } finally { fs.closeSync(fd) }
if (fs.statSync(archive).size !== artifact.size_in_bytes || `sha256:${digest(archive)}` !== artifact.digest) throw new Error('Qualification archive differs from immutable REST identity')
// Check the complete ZIP inventory before writing any entry. Bundles may include
// large immutable appliance packages; proof JSON remains separately bounded.
run('python3', ['-c', `import pathlib,stat,sys,zipfile
archive,out=sys.argv[1:]
with zipfile.ZipFile(archive) as z:
 rows=z.infolist()
 assert 1 <= len(rows) <= 25000
 assert sum(i.file_size for i in rows) <= 1024*1024*1024
 names=[i.filename for i in rows]
 assert len(names)==len(set(names))
 for i in rows:
  p=pathlib.PurePosixPath(i.filename)
  assert not p.is_absolute() and '..' not in p.parts and '.' not in p.parts
  assert not stat.S_ISLNK(i.external_attr >> 16)
  assert not i.filename.startswith('.') and '\\\\' not in i.filename
 z.extractall(out)
`, archive, out], { timeout: 120000 })
fs.unlinkSync(archive)
console.log('Downloaded exact immutable qualification bundle; independent signature verification is still required')
