import test from 'brittle'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import yaml from 'js-yaml'

const ROOT = process.cwd()
const SOURCE_SHA = spawnSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).stdout.trim()
const NPM_CLI = fs.realpathSync(spawnSync('which', ['npm'], { encoding: 'utf8' }).stdout.trim())
const workflow = yaml.load(fs.readFileSync('.github/workflows/release-surfaces.yml', 'utf8'))
function fixture (t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hiverelay-stage-fixture-'))
  t.teardown(() => fs.rmSync(dir, { recursive: true, force: true }))
  fs.mkdirSync(path.join(dir, 'bin'))
  return dir
}
function stub (dir, command, source) {
  fs.writeFileSync(path.join(dir, 'bin', command), `#!${process.execPath}\n${source}`, { mode: 0o755 })
}
function cli (file, args, dir, extra = {}) {
  return spawnSync(process.execPath, [path.join(ROOT, 'scripts/release-stages', file), ...args], { cwd: dir, env: { PATH: `${dir}/bin:${process.env.PATH}`, HIVERELAY_RELEASE_SHA: SOURCE_SHA, REAL_NPM_CLI: NPM_CLI, npm_config_cache: path.join(dir, 'npm-cache'), ...extra }, encoding: 'utf8', timeout: 30000 })
}

test('published artifact readback succeeds before deferred promotion assets exist', t => {
  const dir = fixture(t)
  const log = path.join(dir, 'readback.jsonl')
  const assets = ['release-evidence.json', 'release-image-manifest-evidence.json', 'release-image-smoke-evidence.json', 'umbrel-package-smoke-evidence.json', 'blindspark.s9pk']
  stub(dir, 'gh', `const fs=require('fs'),a=process.argv.slice(2);fs.appendFileSync(process.env.LOG,JSON.stringify(a)+String.fromCharCode(10));const name=a[a.indexOf('--pattern')+1];if(!${JSON.stringify(assets)}.includes(name)||name===process.env.MISSING)process.exit(7)`)
  stub(dir, 'npm', "require('fs').appendFileSync(process.env.LOG,JSON.stringify(['verify',...process.argv.slice(2)])+String.fromCharCode(10))")
  const step = workflow.jobs.sync.steps.find(s => s.name === 'Verify published release evidence assets')
  for (const version of ['v0.27.0', 'v0.27.0-rc.1']) {
    for (const gateway of ['true', 'false']) {
      const script = step.run.replaceAll('$' + '{{ steps.rel.outputs.version }}', version)
        .replaceAll('$' + '{{ steps.rel.outputs.is_prerelease }}', String(version.includes('-')))
        .replaceAll('$' + '{{ steps.rel.outputs.public_gateway_enabled }}', gateway)
      fs.writeFileSync(log, '')
      const env = { PATH: `${dir}/bin:${process.env.PATH}`, LOG: log, TMPDIR: dir }
      const result = spawnSync('bash', ['-c', script], { cwd: dir, env, encoding: 'utf8', timeout: 30000 })
      t.is(result.status, 0, `${version}, gateway=${gateway}: ${result.stderr}`)
      const calls = fs.readFileSync(log, 'utf8').trim().split('\n').map(JSON.parse)
      t.alike(calls.filter(c => c[0] === 'release').map(c => c[c.indexOf('--pattern') + 1]), assets)
      t.is(calls.at(-1)[0], 'verify', 'still verifies all required artifact evidence')
      fs.writeFileSync(log, '')
      const missing = spawnSync('bash', ['-c', script], { cwd: dir, env: { ...env, MISSING: assets[1] }, encoding: 'utf8', timeout: 30000 })
      t.is(missing.status, 7, 'missing required artifact still fails closed')
      t.absent(fs.readFileSync(log, 'utf8').includes('["verify"'), 'does not verify an incomplete bundle')
    }
  }
})

test('artifact workflow resolves actual tag, Release and dispatch scripts without fleet promotion', t => {
  const dir = fixture(t)
  stub(dir, 'node', "console.log('effective_channel=none\\npublic_gateway_enabled=false')")
  const script = workflow.jobs.sync.steps.find(s => s.name === 'Resolve release inputs').run
  for (const event of ['push', 'release', 'workflow_dispatch']) {
    for (const version of ['v0.26.0', 'v0.26.1-rc.1']) {
      const output = path.join(dir, `${event}-${version}.env`)
      const env = { PATH: `${dir}/bin:${process.env.PATH}`, RELEASE_EVENT_NAME: event, RELEASE_TAG_NAME: version, RELEASE_IS_PRERELEASE: 'false', PUSH_REF_NAME: version, WORKFLOW_REF: `refs/tags/${version}`, DISPATCH_VERSION: version, DISPATCH_CHANNEL: '', GITHUB_OUTPUT: output }
      const result = spawnSync('bash', ['-c', script], { cwd: dir, env, encoding: 'utf8' })
      t.is(result.status, 0, result.stderr)
      t.ok(fs.readFileSync(output, 'utf8').includes('channel=none\n'))
      const rejected = spawnSync('bash', ['-c', script], { cwd: dir, env: { ...env, HIVERELAY_RELEASE_CHANNEL: 'both', DISPATCH_CHANNEL: 'both' }, encoding: 'utf8' })
      t.is(rejected.status, 1, `${event} rejects fleet override`)
    }
  }
})

test('fresh and reused artifact image workflow commands have version-only tags', t => {
  const dir = fixture(t)
  const log = path.join(dir, 'docker.log')
  stub(dir, 'docker', "require('fs').appendFileSync(process.env.LOG, JSON.stringify(process.argv.slice(2))+'\\n')")
  const steps = workflow.jobs.sync.steps.filter(s => s.run?.includes('docker buildx build') || s.run?.includes('docker buildx imagetools create'))
  t.is(steps.length, 2, 'both fresh and reuse branches covered')
  for (const step of steps) {
    const lines = step.run.split('\n')
    const start = lines.findIndex(l => /docker buildx (build|imagetools create)/.test(l))
    let end = start
    while (lines[end]?.trimEnd().endsWith('\\')) end++
    const tags = lines.find(l => l.trim().startsWith('tags='))
    const loop = step.run.includes('for tag in')
    const command = [tags, ...(loop ? ['for tag in "$' + '{tags[@]}"; do'] : []), ...lines.slice(start, end + 1), ...(loop ? ['done'] : [])].join('\n').replaceAll('$' + '{{ steps.rel.outputs.semver }}', '0.26.0')
    const result = spawnSync('bash', ['-c', command], { cwd: dir, env: { PATH: `${dir}/bin:${process.env.PATH}`, LOG: log, RUNNER_TEMP: dir, IMAGE_NAME: 'ghcr.io/example/release', HIVERELAY_IMAGE_DIGEST: 'sha256:' + 'a'.repeat(64), HIVERELAY_RELEASE_SHA: 'b'.repeat(40) }, encoding: 'utf8' })
    t.is(result.status, 0, result.stderr)
  }
  const calls = fs.readFileSync(log, 'utf8').trim().split('\n').map(JSON.parse)
  t.is(calls.length, 2)
  t.is(calls.find(c => c[1] === 'build').at(-1), path.join(dir, 'release-image-source/source'), 'build uses the exact archived source')
  for (const call of calls) {
    t.absent(call.some(arg => arg.includes(':latest')), 'no stable image tag')
    t.ok(call.some(arg => arg.endsWith(':0.26.0')), 'version tag present')
  }
  t.absent(workflow.jobs.sync.steps.some(s => /Publish to StartOS registry|Commit ecosystem consumer|Publish Umbrel community|Create or update official Umbrel/.test(s.name)))
})

test('actual artifact GitHub CLI creates explicit non-latest GA and refuses changed identity', t => {
  const dir = fixture(t)
  const state = path.join(dir, 'state.json')
  fs.writeFileSync(state, JSON.stringify({ exists: false, calls: [] }))
  stub(dir, 'gh', 'const fs=require(\'fs\');const a=process.argv.slice(2);const s=JSON.parse(fs.readFileSync(process.env.STATE));s.calls.push(a);let out=\'\';if(a[0]===\'release\'){if(!a.includes(\'--latest=false\'))process.exit(2);s.exists=true}else {const latest=a.at(-1).endsWith(\'/latest\');const code=latest||!s.exists?\'404\':\'200\';out=\'HTTP/2.0 \'+code+\' OK\\ncontent-type: application/json\\n\\n\'+JSON.stringify(code===\'200\'?{id:1,tag_name:\'v0.26.0\',draft:false,prerelease:process.env.WRONG===\'true\'}:{message:\'Not Found\'});}fs.writeFileSync(process.env.STATE,JSON.stringify(s));process.stdout.write(out)')
  const args = ['--tag', 'v0.26.0', '--prerelease', 'false']
  t.is(cli('github-artifact.mjs', args, dir, { STATE: state }).status, 0)
  t.is(cli('github-artifact.mjs', args, dir, { STATE: state }).status, 0, 'same immutable identity retry')
  t.is(JSON.parse(fs.readFileSync(state)).calls.filter(c => c[0] === 'release').length, 1)
  t.is(cli('github-artifact.mjs', args, dir, { STATE: state, WRONG: 'true' }).status, 1)
})

// Packing uses the actual installed npm. All registry operations below are
// local fixtures, so this test can never publish or contact a registry.
function npmRegistryFixture (dir, state) {
  stub(dir, 'npm', `
const fs = require('fs'), path = require('path'), crypto = require('crypto'), cp = require('child_process')
const a = process.argv.slice(2), s = JSON.parse(fs.readFileSync(process.env.STATE))
s.calls.push(a)
let out = '', code = 0
if (a[0] === 'pack') {
  const result = cp.spawnSync(process.execPath, [process.env.REAL_NPM_CLI, ...a], { encoding: 'utf8', env: process.env })
  if (result.status !== 0) { process.stderr.write(result.stderr); process.exit(result.status || 1) }
  out = result.stdout
} else if (a[0] === 'publish') {
  if (a.at(-1) !== 'next') process.exit(3)
  const bytes = fs.readFileSync(a[1])
  const pkg = JSON.parse(cp.execFileSync('tar', ['-xOzf', a[1], 'package/package.json']))
  s.packages[pkg.name] = { version: pkg.version, next: pkg.version, distReads: 0,
    integrity: 'sha512-' + crypto.createHash('sha512').update(bytes).digest('base64'),
    shasum: crypto.createHash('sha1').update(bytes).digest('hex') }
} else if (a[0] === 'view') {
  const p = s.packages[a[1].split('@')[0]]
  if (!p) { process.stderr.write('npm error code E404\\n'); code = 1 }
  else if (a[2] === 'version') out = p.version
  else if (a[2] === 'dist') {
    p.distReads++
    if (process.env.AUTH_FAILURE) { process.stderr.write('npm error code E401\\n'); code = 1 }
    else if (process.env.DELAYED && p.distReads === 1) { process.stderr.write('npm error code E404\\n'); code = 1 }
    else out = JSON.stringify({ integrity: process.env.CONFLICT ? 'sha512-wrong' : p.integrity, shasum: p.shasum })
  } else if (a[2] === 'dist-tags.next') out = p.next
  else process.exit(4)
} else if (a[0] === 'dist-tag') {
  if (a.at(-1) !== 'next') process.exit(5)
  s.packages[a[2].split('@')[0]].next = process.env.VERSION
} else process.exit(6)
fs.writeFileSync(process.env.STATE, JSON.stringify(s)); process.stdout.write(out); process.exit(code)
`)
  fs.writeFileSync(state, JSON.stringify({ packages: {}, calls: [] }))
}

test('actual npm artifact CLI retains exact packed integrity through delayed visibility, retries and conflicts', t => {
  const dir = fixture(t)
  const version = JSON.parse(fs.readFileSync(path.join(ROOT, 'packages/core/package.json'))).version
  const state = path.join(dir, 'npm-state.json')
  npmRegistryFixture(dir, state)
  const output = path.join(dir, 'identity.json')
  const first = cli('publish-npm.mjs', ['--version', version, '--out', output], dir, { STATE: state, VERSION: version, DELAYED: 'true' })
  t.is(first.status, 0, first.stderr)
  if (first.status !== 0) return
  const identities = JSON.parse(fs.readFileSync(output))
  const firstState = JSON.parse(fs.readFileSync(state))
  t.is(identities.length, 4)
  for (const row of identities) {
    t.is(row.integrity, firstState.packages[row.name].integrity)
    t.is(row.shasum, firstState.packages[row.name].shasum)
    t.is(firstState.packages[row.name].distReads, 2, 'retries the explicit first E404')
  }
  const source = JSON.parse(fs.readFileSync(output + '.source.json'))
  t.is(source.sourceCommit, SOURCE_SHA)
  t.ok(source.files.some(f => f.path === 'packages/core/package.json'))
  const progress = fs.readFileSync(output + '.progress.jsonl', 'utf8').trim().split('\n').map(JSON.parse)
  t.alike(progress.slice(0, 4).map(p => p.phase), Array(4).fill('prepared'), 'all artifacts prepared before mutation')
  t.is(progress.filter(p => p.phase === 'publish-returned-success').length, 4)
  t.is(progress.filter(p => p.phase === 'immutable-dist-verified').length, 4)
  t.is(firstState.calls.slice(0, 4).filter(c => c[0] === 'pack').length, 4)
  const retry = cli('publish-npm.mjs', ['--version', version, '--out', path.join(dir, 'retry.json')], dir, { STATE: state, VERSION: version })
  t.is(retry.status, 0, retry.stderr)
  const before = JSON.parse(fs.readFileSync(state)).calls.length
  const conflict = cli('publish-npm.mjs', ['--version', version, '--out', path.join(dir, 'conflict.json')], dir, { STATE: state, VERSION: version, CONFLICT: 'true' })
  t.is(conflict.status, 1)
  const calls = JSON.parse(fs.readFileSync(state)).calls
  t.is(calls.filter(c => c[0] === 'publish').length, 4, 'retry never republishes immutable versions')
  t.absent(calls.slice(before).some(c => c[0] === 'dist-tag'), 'conflict fails before label mutation')
  t.absent(calls.some(c => c.includes('latest')), 'artifact flow never uses latest')
})

test('post-publication readback failure retains partial receipts without release success', t => {
  const dir = fixture(t)
  const version = JSON.parse(fs.readFileSync(path.join(ROOT, 'packages/core/package.json'))).version
  const state = path.join(dir, 'npm-state.json')
  npmRegistryFixture(dir, state)
  const output = path.join(dir, 'failed.json')
  const result = cli('publish-npm.mjs', ['--version', version, '--out', output], dir, { STATE: state, VERSION: version, AUTH_FAILURE: 'true' })
  t.is(result.status, 1, result.stderr)
  t.absent(fs.existsSync(output), 'no complete identity receipt')
  const progress = fs.readFileSync(output + '.progress.jsonl', 'utf8').trim().split('\n').map(JSON.parse)
  t.alike(progress.map(p => p.phase), [...Array(4).fill('prepared'), 'publish-returned-success'])
  const calls = JSON.parse(fs.readFileSync(state)).calls
  t.is(calls.filter(c => c[0] === 'publish').length, 1)
  t.absent(calls.some(c => c[0] === 'dist-tag'))
  const upload = workflow.jobs.sync.steps.find(s => s.name === 'Upload exact source and npm attempt receipts')
  t.ok(upload.if.includes('always()'), 'attempt receipts survive failed workflow')
  t.ok(upload.with.path.includes('release-npm-identities.json.progress.jsonl'))
  t.ok(upload.with.path.includes('release-image-source.json'))
})
