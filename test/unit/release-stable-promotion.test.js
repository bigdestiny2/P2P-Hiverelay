import test from 'brittle'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { stablePromotion } from '../../scripts/release-stages/promote.mjs'
import { verifyQualification, QUALIFICATION_NAMESPACE } from '../../scripts/release-stages/qualification.mjs'
import { distributionTargets } from '../../scripts/release-stages/distribution.mjs'
import { RELEASE_DEFERRED_SURFACES, RELEASE_NPM_PACKAGES } from '../../scripts/lib/release-evidence-contract.mjs'
import { digest, run } from '../../scripts/release-stages/io.mjs'

// These are ordinary composition fixtures. Only external command boundaries are
// stubbed. Detached signatures are actually generated/verified, and OCI index
// and child revision checks execute the real existing verifiers. They are not
// real consumer/device/fleet evidence and their ephemeral trust is never used
// outside this disposable fixture.
const SHA = 'a'.repeat(40)
const TREE = 'b'.repeat(40)
const NOW = Date.now() - 2000
function fixture (t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hiverelay-stable-fixture-'))
  t.teardown(() => fs.rmSync(dir, { recursive: true, force: true }))
  const write = (name, value) => {
    const file = path.join(dir, name)
    fs.mkdirSync(path.dirname(file), { recursive: true })
    fs.writeFileSync(file, typeof value === 'string' ? value : JSON.stringify(value, null, 2) + '\n')
    return { path: name, sha256: digest(file) }
  }
  const rawIndex = JSON.stringify({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.index.v1+json', manifests: ['amd64', 'arm64'].map((architecture, i) => ({ mediaType: 'application/vnd.oci.image.manifest.v1+json', digest: `sha256:${String(i + 1).repeat(64)}`, size: 123, platform: { os: 'linux', architecture } })) })
  const imageDigest = 'sha256:' + crypto.createHash('sha256').update(rawIndex).digest('hex')
  const blankRef = { path: '', sha256: '' }
  const release = { schemaVersion: 1, generatedAt: new Date(NOW - 86400001).toISOString(), release: { version: 'v0.26.0', semver: '0.26.0', tagSha: SHA, channel: 'none', prerelease: false, candidate: false, stage: { schemaVersion: 1, name: 'artifact-v1', npmDistTag: 'next', githubLatest: false, metadataBranch: 'main', deferredSurfaces: RELEASE_DEFERRED_SURFACES, promotionEvidence: 'release-stable-promotion-evidence.json', packages: RELEASE_NPM_PACKAGES.map(name => ({ name, version: '0.26.0', integrity: 'sha512-' + Buffer.alloc(64).toString('base64'), shasum: '0'.repeat(40) })) } }, image: { name: 'ghcr.io/bigdestiny2/p2p-hiverelay', digest: imageDigest, ref: `ghcr.io/bigdestiny2/p2p-hiverelay:0.26.0@${imageDigest}` }, gates: { distributionPreflight: 'passed-artifact' }, artifacts: { startosPackage: { sha256: write('blindspark.s9pk', 'fixture package').sha256 } }, surfaces: { npmPackages: 'published-next', metadataCommit: 'deferred-stable-promotion', fleetRollout: 'deferred-stable-promotion', startosRegistry: 'deferred-stable-promotion', umbrelOfficial: { status: 'deferred-stable-promotion' }, umbrelCommunityStore: { validation: 'deferred-stable-promotion', publish: 'deferred-stable-promotion', commit: '', commitUrl: '' }, fleetRolloutChannel: '', fleetRolloutEvidence: blankRef, fleetChannelConfig: blankRef, startosRegistryUrl: '', startosRegistryPackageUrl: '', startosRegistryEvidence: blankRef } }
  const releaseRef = write('release-evidence.json', release)
  const manifest = { platforms: JSON.parse(rawIndex).manifests.map(m => ({ ...m.platform, digest: m.digest })) }
  const manifestRef = write('release-image-manifest-evidence.json', manifest)
  const closureRef = write('release-closure-evidence.json', { fixture: 'actual semantic closure verifiers have separate exhaustive suites' })
  for (const name of ['release-image-smoke-evidence.json', 'umbrel-package-smoke-evidence.json', 'blindspark-startos-0.4.s9pk', 'startos-0.4-release-evidence.json']) write(name, 'fixture artifact')
  const artifact = { version: 'v0.26.0', tagSha: SHA, releaseEvidenceSha256: releaseRef.sha256, closureSha256: closureRef.sha256, imageManifestSha256: manifestRef.sha256, image: release.image, packages: release.release.stage.packages }
  const inventory = write('inventory.json', [{ name: 'canary-a', channel: 'canary', tailnet: 'canary.invalid' }, { name: 'stable-a', channel: 'stable', tailnet: 'stable.invalid' }])
  const channels = write('channels.json', { canary: 'v0.26.0', stable: 'v0.26.0' })
  const raw = write('actual-command-output.txt', 'ordinary fixture command output, not a real qualification\n')
  const checks = names => names.map(name => ({ name, status: 'passed', exitCode: 0, execution: 'actual', command: `fixture ${name}`, completedAt: new Date(NOW - 5000).toISOString(), rawOutput: raw }))
  const fleet = (names, at) => ({ schemaVersion: 1, generatedAt: new Date(at).toISOString(), status: 'verified', target: { tag: 'v0.26.0', version: '0.26.0', sha: SHA, channel: names.length === 1 ? 'canary' : 'both' }, inventory: { sha256: inventory.sha256, relayNames: names }, channelConfig: { sha256: channels.sha256 }, probes: { timeoutMs: 600000, intervalMs: 5000, sshTimeoutMs: 25000 }, summary: Object.fromEntries(['total', 'updated', 'packageVersionMatches', 'healthy', 'runtimeVersionMatches'].map(key => [key, names.length])), relays: names.map(name => ({ name, packageVersion: 'v0.26.0', healthVersion: '0.26.0', headSha: SHA, targetSha: SHA, observedAt: new Date(at).toISOString(), updated: true, packageVersionMatches: true, healthy: true, runtimeVersionMatches: true, note: 'ok', error: '' })) })
  const samples = []
  for (let i = 0; i <= 288; i++) samples.push(write(`samples/${i}.json`, fleet(['canary-a'], NOW - 86400000 + i * 300000)))
  const q = { schemaVersion: 1, kind: QUALIFICATION_NAMESPACE, issuedAt: new Date(NOW + 1000).toISOString(), expiresAt: new Date(NOW + 1800000).toISOString(), producer: 'fixture-producer', reviewer: 'fixture-reviewer', artifact, proofs: { inventory, inventoryPlan: write('inventory-plan.json', { schemaVersion: 1, kind: 'hiverelay-intended-fleet-v1', sourceTagSha: SHA, sourceInventory: inventory, excluded: [] }), channels, fleet: write('fleet-rollout-evidence.json', fleet(['canary-a', 'stable-a'], NOW)), consumers: write('consumers.json', { kind: 'hiverelay-reference-consumer-proof-v1', artifact, consumers: ['pearbrowser-desktop', 'pearbrowser', 'peerit'].map(name => ({ name, sourceCommit: SHA, sourceDisposition: 'reviewed-no-change', sourceReceipt: raw, runtime: 'fixture-node22', platform: 'fixture', execution: 'actual-consumer', checks: checks(['clean-install', 'seed', 'gateway', 'restart', 'browser-compatibility', 'migration', 'rollback']) })) }), canary: write('canary.json', { kind: 'hiverelay-canary-observation-v1', artifact, channels, startedAt: new Date(NOW - 86400000).toISOString(), completedAt: new Date(NOW).toISOString(), requiredObservationMillis: 86400000, maximumSampleGapMillis: 300000, samples }), rehearsals: write('rehearsals.json', { kind: 'hiverelay-release-rehearsal-proof-v1', artifact, checks: checks(['restore', 'device-rebind', 'rollback', 'offline-author-fresh-reader', 'capacity-replica-floor']) }), umbrelRuntimeReview: write('umbrel-runtime-review-evidence.json', { fixture: true }) }, distribution: {} }
  const env = { ...process.env, GITHUB_ACTIONS: 'true', GITHUB_REPOSITORY: 'bigdestiny2/P2P-Hiverelay', GITHUB_EVENT_NAME: 'workflow_dispatch', GITHUB_REF: 'refs/tags/v0.26.0', GITHUB_SHA: SHA, GITHUB_WORKFLOW_REF: 'bigdestiny2/P2P-Hiverelay/.github/workflows/release-stable-promotion.yml@refs/tags/v0.26.0', GITHUB_RUN_ID: '101', GITHUB_RUN_ATTEMPT: '1', UMBREL_OFFICIAL_FORK: 'fixture/umbrel-apps', STARTOS_REGISTRY_URL: 'https://registry.example.test', HIVERELAY_FLEET_KNOWN_HOSTS_FILE: path.join(dir, 'known-hosts'), HIVERELAY_FLEET_SSH_KEY_FILE: path.join(dir, 'fixture-fleet-key'), HIVERELAY_PROMOTION_SIGNER_IDENTITY: 'fixture-reviewer' }
  const patch = write('reviewed.patch', '# already reviewed current tree\n')
  q.distribution = { repositories: distributionTargets(release, env).map(r => ({ role: r.role, repository: r.repository, branch: r.branch, baseCommit: SHA, treeSha: TREE, patch, files: [] })), officialPr: { url: '', base: 'master', headOwner: 'fixture', headRef: 'blindspark-v0.26.0', reviewUrl: 'https://github.com/getumbrel/umbrel-apps/pull/99', reviewHeadSha: SHA, reviewTreeSha: TREE }, startosRegistry: { url: env.STARTOS_REGISTRY_URL, packageUrl: env.STARTOS_REGISTRY_URL + '/blindspark.s9pk', packageSha256: release.artifacts.startosPackage.sha256 } }
  const key = path.join(dir, 'fixture-reviewer')
  run('/usr/bin/ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', key])
  const allowedSigners = path.join(dir, 'allowed-signers')
  write('allowed-signers', `fixture-reviewer namespaces="${QUALIFICATION_NAMESPACE}" ${fs.readFileSync(key + '.pub', 'utf8')}`)
  env.HIVERELAY_PROMOTION_ALLOWED_SIGNERS_SHA256 = digest(allowedSigners)
  const sign = () => {
    write('release-qualification.json', q)
    fs.rmSync(path.join(dir, 'release-qualification.json.sig'), { force: true })
    run('/usr/bin/ssh-keygen', ['-Y', 'sign', '-f', key, '-n', QUALIFICATION_NAMESPACE, path.join(dir, 'release-qualification.json')])
  }
  sign()
  const calls = []
  const state = { receiptArchive: null, badRun: false, readbacks: 0, latest: false, registry: false, fail: '', branchAbsent: false, prExists: false }
  const execute = (command, args, options = {}) => {
    calls.push({ command: path.basename(command), args })
    const script = path.basename(args[0] || '')
    if (state.fail && (script === state.fail || command === state.fail)) throw new Error('injected external failure')
    if (command === process.execPath) {
      if (script === 'verify-startos-04-image-index.mjs' || script === 'verify-startos-04-image-revision.mjs') return run(command, args, options)
      if (script === 'check-fleet-rollout.mjs') fs.writeFileSync(args[args.indexOf('--evidence') + 1], JSON.stringify(fleet(['canary-a', 'stable-a'], Date.now())))
      if (script === 'ensure-npm-dist-tag.mjs') state.latest = true
      return 'fixture external verifier passed'
    }
    if (command === 'git') {
      if (args[0] === 'show') return fs.readFileSync(path.join(dir, 'inventory.json'), 'utf8')
      if (args[0] === 'clone') fs.mkdirSync(args.at(-1))
      if (args[0] === 'ls-remote') return state.branchAbsent && args.at(-1).includes('blindspark-v') ? '' : SHA + '\t' + args.at(-1)
      if (args[0] === 'rev-parse') return args[1] === 'HEAD^{tree}' ? TREE : SHA
      if (args[0] === 'write-tree') return TREE
      if (args[0] === 'push') state.branchAbsent = false
      return ''
    }
    if (command === 'npm') {
      if (args[2] === 'dist-tags.latest') return JSON.stringify(state.latest ? '0.26.0' : '0.25.0')
      return JSON.stringify(release.release.stage.packages.find(r => args[1].startsWith(r.name + '@')))
    }
    if (command === 'docker') {
      if (args.at(-1) === '--raw') return rawIndex
      if (args.includes('--format')) return JSON.stringify({ os: 'linux', architecture: args[3].includes('1'.repeat(64)) ? 'amd64' : 'arm64', config: { Labels: { 'org.opencontainers.image.revision': SHA } } })
      return ''
    }
    if (command === 'unzip') return run(command, args, options)
    if (command === 'gh') {
      if (args[0] === 'release' && args[1] === 'download') { const name = path.basename(args.at(-1)); fs.copyFileSync(path.join(dir, name), args.at(-1)); return '' }
      if (args.at(-1).includes('/attempts/')) { state.readbacks++; return JSON.stringify({ id: 101, run_attempt: 1, path: '.github/workflows/release-stable-promotion.yml', head_sha: SHA, head_branch: 'v0.26.0', event: 'workflow_dispatch', status: 'completed', conclusion: state.badRun ? 'failure' : 'success', run_started_at: q.issuedAt, updated_at: new Date().toISOString() }) }
      if (args.at(-1).includes('/artifacts?')) return JSON.stringify({ total_count: 1, artifacts: [{ id: 202, name: 'stable-promotion-v0.26.0-101-1', expired: false, digest: 'sha256:' + crypto.createHash('sha256').update(state.receiptArchive).digest('hex'), size_in_bytes: state.receiptArchive.length, workflow_run: { head_sha: SHA } }] })
      if (args.at(-1).includes('/artifacts/202/zip')) return state.receiptArchive

      if (args[0] === 'pr') {
        if (args[1] === 'list') return JSON.stringify(state.prExists ? [{ url: 'https://github.com/getumbrel/umbrel-apps/pull/100' }] : [])
        if (args[1] === 'create') { state.prExists = true; return 'https://github.com/getumbrel/umbrel-apps/pull/100' }
        if (args[2].endsWith('/99')) return JSON.stringify({ headRefOid: SHA, headRepositoryOwner: { login: 'fixture' }, headRepository: { name: 'umbrel-apps' } })
        return JSON.stringify({ state: 'OPEN', isDraft: true, baseRefName: 'master', headRepositoryOwner: { login: 'fixture' }, headRefName: 'blindspark-v0.26.0', headRefOid: SHA })
      }
      if (args.at(-1).includes('/contents/')) return `image: ${release.image.ref}\n`
      if (args.at(-1).includes('/git/commits/')) return JSON.stringify({ tree: { sha: TREE } })
      return JSON.stringify({ id: 1, tag_name: 'v0.26.0', prerelease: false, draft: false })
    }
    if (command === 'start-sdk') { state.registry = true; return '' }
    if (command === 'curl') {
      fs.writeFileSync(args[args.indexOf('--output') + 1], state.registry ? 'fixture package' : 'not found')
      return args.includes('--write-out') ? (state.registry ? '200' : '404') : ''
    }
    throw new Error(`Unexpected fixture command: ${command}`)
  }
  return { dir, q, release, env, allowedSigners, sign, write, calls, state, execute }
}

test('qualification verifies actual independent fixture signatures and rejects changed authority/content/time', t => {
  const f = fixture(t)
  const verify = () => verifyQualification({ bundleDir: f.dir, release: f.release, allowedSigners: f.allowedSigners, env: f.env })
  t.is(verify().identity, 'fixture-reviewer')
  const pin = f.env.HIVERELAY_PROMOTION_ALLOWED_SIGNERS_SHA256
  delete f.env.HIVERELAY_PROMOTION_ALLOWED_SIGNERS_SHA256
  t.exception(verify, /authority/)
  f.env.HIVERELAY_PROMOTION_ALLOWED_SIGNERS_SHA256 = '0'.repeat(64)
  t.exception(verify, /pin/)
  f.env.HIVERELAY_PROMOTION_ALLOWED_SIGNERS_SHA256 = pin
  f.env.HIVERELAY_PROMOTION_SIGNER_IDENTITY = 'someone-else'
  t.exception(verify, /ssh-keygen failed/)
  f.env.HIVERELAY_PROMOTION_SIGNER_IDENTITY = 'fixture-reviewer'
  fs.appendFileSync(path.join(f.dir, 'release-qualification.json'), ' ')
  t.exception(verify, /ssh-keygen failed/)
  f.q.producer = f.q.reviewer
  f.sign()
  t.exception(verify, /independent/)
  f.q.producer = 'fixture-producer'
  f.q.expiresAt = new Date(Date.now() - 1).toISOString()
  f.sign()
  t.exception(verify, /expired/)
})

test('signed canary proof rejects stale reused per-relay observations and unlinked consumer outputs', t => {
  const f = fixture(t)
  const verify = () => verifyQualification({ bundleDir: f.dir, release: f.release, allowedSigners: f.allowedSigners, env: f.env })
  const sample = JSON.parse(fs.readFileSync(path.join(f.dir, 'samples/100.json')))
  sample.relays[0].observedAt = new Date(Date.parse(sample.generatedAt) - 600000).toISOString()
  const ref = f.write('samples/100.json', sample)
  const canary = JSON.parse(fs.readFileSync(path.join(f.dir, 'canary.json')))
  canary.samples[100] = ref
  f.q.proofs.canary = f.write('canary.json', canary)
  f.sign()
  t.exception(verify, /observation older/)
  fs.appendFileSync(path.join(f.dir, 'actual-command-output.txt'), 'changed')
  t.exception(verify, /changed/)
})

test('stable composition promotes only verified existing bytes with new draft, current repository and registry retries', t => {
  const f = fixture(t)
  f.state.branchAbsent = true
  const immutable = digest(path.join(f.dir, 'release-evidence.json'))
  const receipt = stablePromotion({ bundleDir: f.dir, allowedSigners: f.allowedSigners, mode: 'promote', env: f.env, execute: f.execute })
  t.is(receipt.status, 'verified')
  t.is(receipt.distribution.officialPr.url, 'https://github.com/getumbrel/umbrel-apps/pull/100')
  t.is(receipt.distribution.officialPr.reviewUrl, 'https://github.com/getumbrel/umbrel-apps/pull/99')
  t.is(digest(path.join(f.dir, 'release-evidence.json')), immutable)
  t.ok(f.calls.some(c => c.command === 'gh' && c.args[0] === 'pr' && c.args[1] === 'create'))
  t.ok(f.calls.some(c => c.command === 'git' && c.args.includes('--force-with-lease=refs/heads/blindspark-v0.26.0:')))
  t.absent(f.calls.some(c => c.command === 'npm' && c.args[0] === 'publish'))
  t.absent(f.calls.some(c => c.command === 'docker' && c.args.includes('build')))
  t.is(f.calls.filter(c => path.basename(c.args[0] || '') === 'check-fleet-rollout.mjs').length, 2)
  fs.unlinkSync(path.join(f.dir, 'release-stable-promotion-evidence.json'))
  fs.unlinkSync(path.join(f.dir, 'stable-promotion-fleet-evidence.json'))
  const publishes = f.calls.filter(c => c.command === 'start-sdk').length
  stablePromotion({ bundleDir: f.dir, allowedSigners: f.allowedSigners, mode: 'promote', env: f.env, execute: f.execute })
  t.is(f.calls.filter(c => c.command === 'start-sdk').length, publishes, 'current registry bytes reused without publication')
})

test('stable CLI and composition fail closed before publication on absent proof and child verifier failure', t => {
  const f = fixture(t)
  const invoke = () => stablePromotion({ bundleDir: f.dir, allowedSigners: f.allowedSigners, mode: 'promote', env: f.env, execute: f.execute })
  f.state.fail = 'verify-release-closure-evidence.mjs'
  t.exception(invoke, /injected external failure/)
  t.absent(f.calls.some(c => ['start-sdk', 'npm', 'docker'].includes(c.command)))
  t.absent(fs.existsSync(path.join(f.dir, 'release-stable-promotion-evidence.json')))
  fs.unlinkSync(path.join(f.dir, 'release-qualification.json.sig'))
  const cli = spawnSync(process.execPath, ['scripts/release-stages/promote.mjs', '--mode', 'promote', '--bundle-dir', f.dir, '--allowed-signers', f.allowedSigners], { cwd: process.cwd(), env: f.env, encoding: 'utf8', timeout: 10000 })
  t.is(cli.status, 1)
  t.absent(fs.existsSync(path.join(f.dir, 'release-stable-promotion-evidence.json')))
})

test('partial external failure emits no success and same reviewed source retry rereads every surface', t => {
  const f = fixture(t)
  f.state.fail = 'start-sdk'
  const invoke = () => stablePromotion({ bundleDir: f.dir, allowedSigners: f.allowedSigners, mode: 'promote', env: f.env, execute: f.execute })
  t.exception(invoke, /injected external failure/)
  t.ok(f.state.prExists, 'draft creation completed before registry failure')
  t.absent(f.state.latest, 'latest not reached')
  t.absent(fs.existsSync(path.join(f.dir, 'release-stable-promotion-evidence.json')))
  f.state.fail = ''
  t.is(invoke().status, 'verified')
  t.is(f.calls.filter(c => c.command === 'gh' && c.args[0] === 'pr' && c.args[1] === 'create').length, 1, 'existing draft reused on retry')
})

test('final promotion requires terminal successful run and immutable receipt bytes with terminal revalidation', t => {
  const f = fixture(t)
  const options = { bundleDir: f.dir, allowedSigners: f.allowedSigners, env: f.env, execute: f.execute }
  stablePromotion({ ...options, mode: 'promote' })
  const receiptFile = path.join(f.dir, 'release-stable-promotion-evidence.json')
  const archive = path.join(f.dir, 'receipt.zip')
  run('zip', ['-q', '-j', archive, receiptFile, path.join(f.dir, 'stable-promotion-fleet-evidence.json')])
  f.state.receiptArchive = fs.readFileSync(archive)
  const verify = () => stablePromotion({ ...options, mode: 'verify' })
  t.is(verify().status, 'verified')
  t.is(f.state.readbacks, 2, 'receipt run authority revalidated after final surface/fleet reads')
  f.state.badRun = true
  t.exception(verify, /Live promotion run/)
  f.state.badRun = false
  const receipt = JSON.parse(fs.readFileSync(receiptFile))
  receipt.completedAt = 'not-a-date'
  fs.writeFileSync(receiptFile, JSON.stringify(receipt))
  t.exception(verify, /timestamp/)
  receipt.completedAt = new Date().toISOString()
  fs.writeFileSync(receiptFile, JSON.stringify(receipt))
  t.exception(verify, /immutable workflow artifact/)
})

test('reviewed complete inventory cannot silently omit a relay and original review tree cannot drift', t => {
  const f = fixture(t)
  const intended = JSON.parse(fs.readFileSync(path.join(f.dir, 'inventory.json')))
  const source = f.write('source-inventory.json', [...intended, { name: 'omitted', channel: 'hold', tailnet: 'held.invalid' }])
  f.q.proofs.inventoryPlan = f.write('inventory-plan.json', { schemaVersion: 1, kind: 'hiverelay-intended-fleet-v1', sourceTagSha: SHA, sourceInventory: source, excluded: [] })
  f.sign()
  t.exception(() => verifyQualification({ bundleDir: f.dir, release: f.release, allowedSigners: f.allowedSigners, env: f.env }), /omits source relays/)
  f.q.proofs.inventoryPlan = f.write('inventory-plan.json', { schemaVersion: 1, kind: 'hiverelay-intended-fleet-v1', sourceTagSha: SHA, sourceInventory: f.q.proofs.inventory, excluded: [] })
  f.q.distribution.officialPr.reviewTreeSha = 'c'.repeat(40)
  f.sign()
  t.exception(() => stablePromotion({ bundleDir: f.dir, allowedSigners: f.allowedSigners, mode: 'promote', env: f.env, execute: f.execute }), /trees differ/)
  t.absent(f.calls.some(c => c.command === 'git' && c.args[0] === 'push'), 'review equivalence fails before repository publication')
})

test('receipt publication CLI preserves partial attempts and retries exact run-bound bytes without clobber', t => {
  const f = fixture(t)
  stablePromotion({ bundleDir: f.dir, allowedSigners: f.allowedSigners, mode: 'promote', env: f.env, execute: f.execute })
  const bin = path.join(f.dir, 'bin')
  fs.mkdirSync(bin)
  const state = path.join(f.dir, 'publication-state.json')
  fs.writeFileSync(state, JSON.stringify({ assets: [], uploads: [] }))
  fs.writeFileSync(path.join(bin, 'gh'), `#!${process.execPath}
const fs=require('fs'),path=require('path'),crypto=require('crypto');const a=process.argv.slice(2),s=JSON.parse(fs.readFileSync(process.env.STATE));let out='';let status=0;
if(a[0]==='release'){const file=a[3],name=path.basename(file);s.uploads.push(name);if(a.includes('--clobber'))process.exit(7);if(process.env.FAIL_FLEET==='true'&&name.startsWith('stable-promotion-fleet-'))status=1;else {const b=fs.readFileSync(file);s.assets.push({id:s.assets.length+1,name,state:'uploaded',size:b.length,digest:'sha256:'+crypto.createHash('sha256').update(b).digest('hex'),data:b.toString('base64')})}}
else if(a.at(-1).includes('/releases/tags/'))out=JSON.stringify({id:201,tag_name:'v0.26.0',draft:false,prerelease:false});else if(a.at(-1).includes('/assets?'))out=JSON.stringify([s.assets]);else if(a.at(-1).includes('/releases/assets/'))out=Buffer.from(s.assets.find(r=>r.id===Number(a.at(-1).split('/').at(-1))).data,'base64');else status=9;
fs.writeFileSync(process.env.STATE,JSON.stringify(s));process.stdout.write(out);process.exit(status)
`, { mode: 0o755 })
  const invoke = fail => spawnSync(process.execPath, ['scripts/release-stages/publish-receipt.mjs', '--bundle-dir', f.dir], { cwd: process.cwd(), env: { ...f.env, PATH: `${bin}:${process.env.PATH}`, STATE: state, FAIL_FLEET: String(fail), HIVERELAY_PROMOTION_ALLOWED_SIGNERS_FILE: f.allowedSigners }, encoding: 'utf8', timeout: 15000 })
  t.is(invoke(true).status, 1, 'partial second-asset failure is propagated')
  t.is(JSON.parse(fs.readFileSync(state)).assets.length, 1)
  const retry = invoke(false)
  t.is(retry.status, 0, retry.stderr)
  const after = JSON.parse(fs.readFileSync(state))
  t.is(after.assets.length, 2)
  t.alike(after.assets.map(a => a.name).sort(), ['release-stable-promotion-101-1.json', 'stable-promotion-fleet-101-1.json'])
  t.is(invoke(false).status, 0, 'fully occupied exact bytes are reread only')
  t.is(JSON.parse(fs.readFileSync(state)).uploads.length, after.uploads.length)
  fs.appendFileSync(path.join(f.dir, 'release-stable-promotion-evidence.json'), ' ')
  t.is(invoke(false).status, 1, 'conflicting occupied receipt is never overwritten')
})
