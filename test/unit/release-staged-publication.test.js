import test from 'brittle'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import { spawnSync } from 'node:child_process'
import yaml from 'js-yaml'

const ROOT = process.cwd()
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
  return spawnSync(process.execPath, [path.join(ROOT, 'scripts/release-stages', file), ...args], { cwd: dir, env: { PATH: `${dir}/bin:${process.env.PATH}`, ...extra }, encoding: 'utf8', timeout: 30000 })
}

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
    const result = spawnSync('bash', ['-c', command], { cwd: dir, env: { PATH: `${dir}/bin:${process.env.PATH}`, LOG: log, IMAGE_NAME: 'ghcr.io/example/release', HIVERELAY_IMAGE_DIGEST: 'sha256:' + 'a'.repeat(64), HIVERELAY_RELEASE_SHA: 'b'.repeat(40) }, encoding: 'utf8' })
    t.is(result.status, 0, result.stderr)
  }
  const calls = fs.readFileSync(log, 'utf8').trim().split('\n').map(JSON.parse)
  t.is(calls.length, 2)
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

test('actual npm artifact CLI retains packed integrity, fixed next, immutable retries and conflicts', t => {
  const dir = fixture(t)
  const version = JSON.parse(fs.readFileSync(path.join(ROOT, 'packages/core/package.json'))).version
  const state = path.join(dir, 'npm-state.json')
  fs.writeFileSync(state, JSON.stringify({ packages: {}, calls: [] }))
  stub(dir, 'npm', 'const fs=require(\'fs\'),path=require(\'path\'),crypto=require(\'crypto\');const a=process.argv.slice(2),s=JSON.parse(fs.readFileSync(process.env.STATE));s.calls.push(a);let out=\'\';let code=0;if(a[0]===\'pack\'){const p=JSON.parse(fs.readFileSync(path.join(a[1],\'package.json\'))),name=p.name+\'.tgz\',bytes=Buffer.from(\'fixture:\'+p.name+\'@\'+p.version);fs.writeFileSync(path.join(a[a.indexOf(\'--pack-destination\')+1],name),bytes);out=JSON.stringify([{filename:name}])}else if(a[0]===\'publish\'){if(a.at(-1)!==\'next\')process.exit(3);const bytes=fs.readFileSync(a[1]),name=path.basename(a[1],\'.tgz\');s.packages[name]={version:process.env.VERSION,next:process.env.VERSION,integrity:\'sha512-\'+crypto.createHash(\'sha512\').update(bytes).digest(\'base64\'),shasum:crypto.createHash(\'sha1\').update(bytes).digest(\'hex\')}}else if(a[0]===\'view\'){const name=a[1].split(\'@\')[0],p=s.packages[name];if(!p){process.stderr.write(\'npm error code E404\\n\');code=1}else if(a[2]===\'version\')out=p.version;else if(a[2]===\'dist\')out=JSON.stringify({integrity:process.env.CONFLICT?\'sha512-wrong\':p.integrity,shasum:p.shasum});else if(a[2]===\'dist-tags.next\')out=p.next;else process.exit(4)}else if(a[0]===\'dist-tag\'){if(a.at(-1)!==\'next\')process.exit(5);s.packages[a[2].split(\'@\')[0]].next=process.env.VERSION}else process.exit(6);fs.writeFileSync(process.env.STATE,JSON.stringify(s));process.stdout.write(out);process.exit(code)')
  const args = ['--version', version, '--out', path.join(dir, 'identity.json')]
  const first = cli('publish-npm.mjs', args, dir, { STATE: state, VERSION: version })
  t.is(first.status, 0, first.stderr)
  const identities = JSON.parse(fs.readFileSync(args[3]))
  t.is(identities.length, 4)
  for (const row of identities) t.is(row.integrity, 'sha512-' + crypto.createHash('sha512').update(`fixture:${row.name}@${version}`).digest('base64'))
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
