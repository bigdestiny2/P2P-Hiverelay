import test from 'brittle'
import { execFile, spawnSync } from 'node:child_process'
import { chmod, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { promisify } from 'node:util'
import { publishFleetChannel } from '../../scripts/publish-fleet-channel.mjs'
import { createPublicT1OpsFixture } from '../fixtures/public-hive-gateway-ops.js'

const execFileAsync = promisify(execFile)
const canRunGitSigning = !spawnSync('git', ['--version']).error &&
  !spawnSync('ssh-keygen', ['-V']).error

const REPO = '/controller/hiverelay'
const START = 'a'.repeat(40)
const TARGET = 'b'.repeat(40)
const TAG = 'c'.repeat(40)
const PUBLISHED = 'd'.repeat(40)
const PREVIOUS_TARGET_SHA = 'e'.repeat(40)
const PREVIOUS_TAG = '8'.repeat(40)
const BLOB = '9'.repeat(40)
const CHANNELS = `${REPO}/fleet/channels.json`
const ENDPOINT = 'git@example.invalid:hiverelay.git'
const PREDECESSOR_AUTHORITY = [
  ['fleet/updater.sh', '100755'],
  ['fleet/quarantine-public-gateway.sh', '100755'],
  ['scripts/verify-public-hive-gateway-quarantine.mjs', '100644'],
  ['scripts/lib/public-hive-gateway-quarantine-authority.mjs', '100644'],
  ['scripts/lib/public-hive-gateway-release-manifest.mjs', '100644'],
  ['scripts/lib/public-hive-gateway-policy.mjs', '100644']
]

function promotion (status, wouldChange = true) {
  return {
    schema: 'hiverelay-fleet-channel-promotion-v1',
    status,
    channel: 'canary',
    previousTarget: 'v1.2.2',
    target: 'v1.2.3',
    tagObjectSha: TAG,
    targetSha: TARGET,
    channelsPath: CHANNELS,
    wouldChange,
    publicGatewayRequired: true,
    operatorContracts: [],
    canaryEvidence: null
  }
}

function fixture (opts = {}) {
  const trustedFiles = new Map()
  const predecessorFiles = new Map()
  const trustedPathsByOid = new Map()
  let trustedIndex = 1
  for (const [name, bytes] of Object.entries(opts.trustedFiles || {})) {
    const oid = (trustedIndex++).toString(16).padStart(40, '0')
    trustedFiles.set(name, { oid, bytes: Buffer.from(bytes) })
    trustedPathsByOid.set(oid, trustedFiles.get(name))
  }
  if ((opts.operatorContracts || []).length > 0) {
    for (const [name, mode] of PREDECESSOR_AUTHORITY) {
      const bytes = Buffer.from(`reviewed bootstrap authority ${name}\n`)
      const targetOid = (trustedIndex++).toString(16).padStart(40, '0')
      const target = { oid: targetOid, bytes, mode }
      trustedFiles.set(name, target)
      trustedPathsByOid.set(targetOid, target)
      if (opts.missingPredecessorPath === name) continue
      const previousBytes = opts.predecessorDriftPath === name
        ? Buffer.from(`drifted predecessor ${name}\n`)
        : bytes
      const previousOid = opts.predecessorDriftPath === name
        ? (trustedIndex++).toString(16).padStart(40, '0')
        : targetOid
      const previous = {
        oid: previousOid,
        bytes: previousBytes,
        mode: opts.predecessorModePath === name ? '120000' : mode
      }
      predecessorFiles.set(name, previous)
      trustedPathsByOid.set(previousOid, previous)
    }
  }
  const state = {
    head: START,
    remote: START,
    changed: [],
    staged: [],
    commitCreated: false,
    pushed: false,
    remoteReads: 0,
    tagReads: 0,
    gitCalls: [],
    promoterCalls: [],
    expectedCurrentReads: 0,
    trustedReads: {}
  }

  const git = async (args) => {
    state.gitCalls.push(args)
    const command = args.join(' ')
    if (command === 'rev-parse --show-toplevel') return output(REPO)
    if (command === 'symbolic-ref --quiet --short HEAD') return output('main')
    if (command === 'status --porcelain=v1 -z --untracked-files=all') {
      const names = [...state.changed, ...state.staged]
      return output(names.map(name => ` M ${name}\0`).join(''))
    }
    if (command === 'ls-files -v -z') {
      return output(opts.hiddenIndexFlag
        ? `${opts.hiddenIndexFlag} scripts/promote-fleet-channel.mjs\0`
        : 'H fleet/allowed-signers\0H fleet/channels.json\0H scripts/promote-fleet-channel.mjs\0')
    }
    if (command === 'rev-parse --verify HEAD') return output(state.head)
    if (command === 'rev-parse --verify HEAD^') return output(START)
    if (command === 'rev-parse --verify refs/tags/v1.2.2^{commit}') {
      state.expectedCurrentReads++
      return output(opts.driftExpectedCurrentAt === state.expectedCurrentReads
        ? 'f'.repeat(40)
        : PREVIOUS_TARGET_SHA)
    }
    if (command === 'rev-parse --verify refs/tags/v1.2.2^{tag}') return output(PREVIOUS_TAG)
    if (command === 'cat-file -t refs/tags/v1.2.2') return output('tag')
    if (command.includes('verify-tag --raw v1.2.2')) {
      return opts.badPredecessorSignature ? output('signature status unknown') : { stdout: '', stderr: 'GOODSIG trusted predecessor' }
    }
    if (command === 'config --null --list') {
      return output(opts.urlRewrite ? 'url.https://intermediate.invalid/.insteadof\nhttps://trusted.invalid/\0' : '')
    }
    if (command === 'remote get-url --all origin') return output(opts.fetchUrls || ENDPOINT)
    if (command === 'remote get-url --push --all origin') return output(opts.pushUrls || ENDPOINT)
    if (command === `ls-remote --exit-code -- ${ENDPOINT} refs/heads/main`) {
      state.remoteReads++
      if (opts.raceAtRemoteRead === state.remoteReads) state.remote = 'e'.repeat(40)
      return output(`${state.remote}\trefs/heads/main`)
    }
    if (command === `ls-remote --exit-code -- ${ENDPOINT} refs/tags/v1.2.3 refs/tags/v1.2.3^{}`) {
      state.tagReads++
      const tag = opts.badRemoteTag ? 'f'.repeat(40) : TAG
      return output(`${tag}\trefs/tags/v1.2.3\n${TARGET}\trefs/tags/v1.2.3^{}`)
    }
    if (command === `ls-remote --exit-code -- ${ENDPOINT} refs/tags/v1.2.2 refs/tags/v1.2.2^{}`) {
      const tag = opts.badRemotePredecessor ? '7'.repeat(40) : PREVIOUS_TAG
      return output(`${tag}\trefs/tags/v1.2.2\n${PREVIOUS_TARGET_SHA}\trefs/tags/v1.2.2^{}`)
    }
    if (command === 'diff --name-only -z') return output(nul(state.changed))
    if (command === 'diff --cached --name-only -z') return output(nul(state.staged))
    if (command === 'ls-files --others --exclude-standard -z') return output('')
    if (command === 'diff --check -- fleet/channels.json') return output('')
    if (command === 'add -- fleet/channels.json') {
      state.staged = [...state.changed]
      state.changed = []
      return output('')
    }
    if (command === 'ls-files --stage -z -- fleet/channels.json') {
      return output(`${opts.indexMode || '100644'} ${opts.indexBlob || BLOB} 0\tfleet/channels.json\0`)
    }
    if (command.startsWith('-c core.hooksPath=/dev/null -c gpg.format=ssh commit -S -m fleet: promote canary to v1.2.3')) {
      if (opts.commitFails) throw new Error('commit failed')
      state.staged = []
      state.head = PUBLISHED
      state.commitCreated = true
      return output('committed')
    }
    if (command === 'diff-tree --no-commit-id --name-only -r -z HEAD') {
      return output(opts.commitFiles ? nul(opts.commitFiles) : 'fleet/channels.json\0')
    }
    if (command === 'ls-tree -z HEAD -- fleet/channels.json') {
      return output(`${opts.commitMode || '100644'} blob ${opts.commitBlob || BLOB}\tfleet/channels.json\0`)
    }
    if (args[0] === 'ls-tree' && args[1] === '-z' && [TARGET, PREVIOUS_TARGET_SHA].includes(args[2]) && args[3] === '--') {
      const name = args[4]
      const file = (args[2] === TARGET ? trustedFiles : predecessorFiles).get(name)
      return output(file ? `${file.mode || '100644'} blob ${file.oid}\t${name}\0` : '')
    }
    if (args[0] === 'cat-file' && args[1] === 'blob' && trustedPathsByOid.has(args[2])) {
      const file = trustedPathsByOid.get(args[2])
      const name = [...trustedFiles, ...predecessorFiles].find(([, value]) => value === file)?.[0] || args[2]
      state.trustedReads[name] = (state.trustedReads[name] || 0) + 1
      if (opts.onTrustedRead) await opts.onTrustedRead(name, state.trustedReads[name])
      return { stdout: file.bytes, stderr: '' }
    }
    if (command.includes('verify-commit --raw')) {
      if (opts.badSignature) return output('signature status unknown')
      return { stdout: '', stderr: 'GOODSIG trusted publisher' }
    }
    if (command === `-c core.hooksPath=/dev/null push --atomic --porcelain --no-follow-tags --force-with-lease=refs/heads/main:${START} --force-with-lease=refs/tags/v1.2.3:${TAG} -- ${ENDPOINT} ${TAG}:refs/tags/v1.2.3 ${PUBLISHED}:refs/heads/main`) {
      state.remote = state.head
      state.pushed = true
      return output('ok')
    }
    throw new Error(`unexpected git command: ${command}`)
  }

  const promote = async (args) => {
    state.promoterCalls.push(args)
    const dryRun = args.includes('--dry-run')
    if (!dryRun) {
      state.changed = opts.changedFiles || ['fleet/channels.json']
    }
    const result = promotion(dryRun ? 'dry-run' : (opts.wouldChange === false ? 'unchanged' : 'updated'),
      opts.wouldChange !== false)
    if (!dryRun && opts.appliedPreviousTarget) result.previousTarget = opts.appliedPreviousTarget
    result.operatorContracts = structuredClone(opts.operatorContracts || [])
    return result
  }

  const deriveChannels = async () => ({ blobOid: BLOB })
  const pinAllowedSigners = async source => ({ path: source, cleanup: async () => {} })

  return { state, git, promote, deriveChannels, pinAllowedSigners }
}

test('fleet channel publisher - default is a remote-bound validation-only dry run', async (t) => {
  const harness = fixture()
  const result = await publishFleetChannel({
    repo: REPO,
    channel: 'canary',
    target: 'v1.2.3'
  }, harness)

  t.is(result.status, 'dry-run')
  t.ok(result.publicGatewayRequired)
  t.ok(result.wouldChange)
  t.is(harness.state.promoterCalls.length, 1)
  t.ok(harness.state.promoterCalls[0].includes('--dry-run'))
  t.absent(harness.state.commitCreated)
  t.absent(harness.state.pushed)
})

test('fleet channel publisher - public-t1 publication requires fresh signed-contract ops evidence', async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), 'hiverelay-publisher-ops-'))
  t.teardown(() => rm(root, { recursive: true, force: true }))
  const evidenceDirectory = path.join(root, 'ops')
  await mkdir(evidenceDirectory)
  const ops = createPublicT1OpsFixture({ releaseSha: TARGET })
  const evidencePath = path.join(evidenceDirectory, `${ops.contract.relay}.json`)
  await writeFile(evidencePath, ops.evidenceBytes)
  const trustedFiles = {
    'fleet/public-hive-gateway-release.json': ops.manifestBytes,
    [ops.contractPath]: ops.contractBytes
  }

  const missing = fixture({ operatorContracts: [ops.binding], trustedFiles })
  await t.exception(async () => publishFleetChannel({
    repo: REPO,
    channel: 'canary',
    target: 'v1.2.3'
  }, missing), /--gateway-ops-evidence-dir is required/)

  const harness = fixture({ operatorContracts: [ops.binding], trustedFiles })
  const result = await publishFleetChannel({
    repo: REPO,
    channel: 'canary',
    target: 'v1.2.3',
    gatewayOpsEvidenceDir: evidenceDirectory
  }, harness)
  t.is(result.status, 'dry-run')
  t.is(result.operatorContracts.length, 1)
  t.is(result.operatorContracts[0].relay, ops.contract.relay)
  t.is(result.operatorContracts[0].operatorContractSha256, ops.operatorContractSha256)
  t.is(result.operatorContracts[0].suffix, ops.contract.suffix)
  t.is(result.predecessorAuthority.target, 'v1.2.2')
  t.is(result.predecessorAuthority.commitSha, PREVIOUS_TARGET_SHA)
  t.is(result.predecessorAuthority.files.length, PREDECESSOR_AUTHORITY.length)

  const linkedDirectory = path.join(root, 'linked-ops')
  await symlink(evidenceDirectory, linkedDirectory)
  const linkedHarness = fixture({ operatorContracts: [ops.binding], trustedFiles })
  await t.exception(async () => publishFleetChannel({
    repo: REPO,
    channel: 'canary',
    target: 'v1.2.3',
    gatewayOpsEvidenceDir: linkedDirectory
  }, linkedHarness), /existing non-symlink directory/)

  const stale = structuredClone(ops.evidence)
  stale.checkedAt = new Date(Date.now() - 16 * 60 * 1000).toISOString()
  await writeFile(evidencePath, JSON.stringify(stale) + '\n')
  const staleHarness = fixture({ operatorContracts: [ops.binding], trustedFiles })
  await t.exception(async () => publishFleetChannel({
    repo: REPO,
    channel: 'canary',
    target: 'v1.2.3',
    gatewayOpsEvidenceDir: evidenceDirectory
  }, staleHarness), /15 minutes/)

  await writeFile(evidencePath, ops.evidenceBytes)
  const driftHarness = fixture({
    operatorContracts: [ops.binding],
    trustedFiles,
    onTrustedRead: async (name, count) => {
      if (name === ops.contractPath && count === 2) {
        await writeFile(evidencePath, JSON.stringify(ops.evidence, null, 2) + '\n')
      }
    }
  })
  await t.exception(async () => publishFleetChannel({
    repo: REPO,
    channel: 'canary',
    target: 'v1.2.3',
    gatewayOpsEvidenceDir: evidenceDirectory,
    publish: true
  }, driftHarness), /readiness evidence changed after publication validation/)
  t.absent(driftHarness.state.commitCreated, 'ops evidence drift stops before control-plane mutation')

  const legacy = fixture()
  await t.exception(async () => publishFleetChannel({
    repo: REPO,
    channel: 'canary',
    target: 'v1.2.3',
    gatewayOpsEvidenceDir: evidenceDirectory
  }, legacy), /valid only for a public-t1-gateway release/)
})

test('fleet channel publisher - enabled gateway requires blob-identical predecessor authority', async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), 'hiverelay-publisher-predecessor-'))
  t.teardown(() => rm(root, { recursive: true, force: true }))
  const evidenceDirectory = path.join(root, 'ops')
  await mkdir(evidenceDirectory)
  const ops = createPublicT1OpsFixture({ releaseSha: TARGET })
  await writeFile(path.join(evidenceDirectory, `${ops.contract.relay}.json`), ops.evidenceBytes)
  const trustedFiles = {
    'fleet/public-hive-gateway-release.json': ops.manifestBytes,
    [ops.contractPath]: ops.contractBytes
  }
  const input = {
    repo: REPO,
    channel: 'canary',
    target: 'v1.2.3',
    gatewayOpsEvidenceDir: evidenceDirectory
  }

  for (const [options, expected] of [
    [{ predecessorDriftPath: PREDECESSOR_AUTHORITY[0][0] }, /blob-identical fleet\/updater\.sh/],
    [{ predecessorDriftPath: 'fleet/quarantine-public-gateway.sh' }, /blob-identical fleet\/quarantine-public-gateway\.sh/],
    [{ missingPredecessorPath: PREDECESSOR_AUTHORITY[2][0] }, /must be one tracked 100644 regular blob/],
    [{ predecessorModePath: PREDECESSOR_AUTHORITY[3][0] }, /must be one tracked 100644 regular blob/],
    [{ badPredecessorSignature: true }, /did not report a trusted signature/],
    [{ badRemotePredecessor: true }, /does not match its trusted local tag/]
  ]) {
    const harness = fixture({ operatorContracts: [ops.binding], trustedFiles, ...options })
    await t.exception(async () => publishFleetChannel(input, harness), expected)
    t.absent(harness.state.commitCreated)
    t.absent(harness.state.pushed)
  }
})

test('fleet channel publisher - publishes one trusted signed non-force control commit', async (t) => {
  const harness = fixture()
  const result = await publishFleetChannel({
    repo: REPO,
    channel: 'canary',
    target: 'v1.2.3',
    publish: true
  }, harness)

  t.is(result.status, 'published')
  t.is(result.startingHead, START)
  t.is(result.publishedHead, PUBLISHED)
  t.is(result.remoteHead, PUBLISHED)
  t.is(harness.state.promoterCalls.length, 2)
  t.ok(harness.state.promoterCalls[0].includes('--dry-run'))
  t.absent(harness.state.promoterCalls[1].includes('--dry-run'))
  t.ok(harness.state.commitCreated)
  t.ok(harness.state.pushed)
  t.is(harness.state.tagReads, 4, 'remote release tag is pinned before mutation, atomically during push, and after publication')
  const push = harness.state.gitCalls.find(args => args.includes('push'))
  t.alike(push, [
    '-c', 'core.hooksPath=/dev/null',
    'push', '--atomic', '--porcelain', '--no-follow-tags',
    `--force-with-lease=refs/heads/main:${START}`,
    `--force-with-lease=refs/tags/v1.2.3:${TAG}`,
    '--', ENDPOINT,
    `${TAG}:refs/tags/v1.2.3`,
    `${PUBLISHED}:refs/heads/main`
  ])
  t.absent(push.includes('--force'), 'publisher has no unguarded force update')
})

test('fleet channel publisher - forward recovery CAS binds the starting tag and commit through mutation', async (t) => {
  const valid = fixture()
  const result = await publishFleetChannel({
    repo: REPO,
    channel: 'canary',
    target: 'v1.2.3',
    expectedCurrentTarget: 'v1.2.2',
    expectedCurrentTargetSha: PREVIOUS_TARGET_SHA
  }, valid)
  t.is(result.status, 'dry-run')
  t.is(valid.state.expectedCurrentReads, 1)

  const wrongTag = fixture()
  await t.exception(async () => publishFleetChannel({
    repo: REPO,
    channel: 'canary',
    target: 'v1.2.3',
    expectedCurrentTarget: 'v1.2.1',
    expectedCurrentTargetSha: PREVIOUS_TARGET_SHA,
    publish: true
  }, wrongTag), /does not match the recovery expected-current target/)
  t.absent(wrongTag.state.commitCreated)

  const wrongSha = fixture()
  await t.exception(async () => publishFleetChannel({
    repo: REPO,
    channel: 'canary',
    target: 'v1.2.3',
    expectedCurrentTarget: 'v1.2.2',
    expectedCurrentTargetSha: '1'.repeat(40),
    publish: true
  }, wrongSha), /target SHA does not match the recovery receipt/)
  t.absent(wrongSha.state.commitCreated)

  const tagRace = fixture({ driftExpectedCurrentAt: 2 })
  await t.exception(async () => publishFleetChannel({
    repo: REPO,
    channel: 'canary',
    target: 'v1.2.3',
    expectedCurrentTarget: 'v1.2.2',
    expectedCurrentTargetSha: PREVIOUS_TARGET_SHA,
    publish: true
  }, tagRace), /target SHA does not match the recovery receipt/)
  t.is(tagRace.state.promoterCalls.length, 1, 'expected-current tag race stops before the applying promoter')
  t.absent(tagRace.state.commitCreated)

  const appliedDrift = fixture({ appliedPreviousTarget: 'v1.2.1' })
  await t.exception(async () => publishFleetChannel({
    repo: REPO,
    channel: 'canary',
    target: 'v1.2.3',
    expectedCurrentTarget: 'v1.2.2',
    expectedCurrentTargetSha: PREVIOUS_TARGET_SHA,
    publish: true
  }, appliedDrift), /promotion result changed between validation and application/)
  t.absent(appliedDrift.state.commitCreated)
  t.absent(appliedDrift.state.pushed)
})

test('fleet channel publisher - remote tag substitution fails before mutation', async (t) => {
  const harness = fixture({ badRemoteTag: true })
  await t.exception(async () => publishFleetChannel({
    repo: REPO,
    channel: 'canary',
    target: 'v1.2.3',
    publish: true
  }, harness), /does not match the locally verified signed tag/)

  t.is(harness.state.promoterCalls.length, 1)
  t.absent(harness.state.commitCreated)
  t.absent(harness.state.pushed)
})

test('fleet channel publisher - URL rewrites and split push destinations fail before promotion', async (t) => {
  for (const options of [
    { urlRewrite: true },
    { pushUrls: `${ENDPOINT}\ngit@backup.invalid:hiverelay.git` },
    { fetchUrls: ENDPOINT, pushUrls: 'git@other.invalid:hiverelay.git' }
  ]) {
    const harness = fixture(options)
    await t.exception(async () => publishFleetChannel({
      repo: REPO,
      channel: 'canary',
      target: 'v1.2.3',
      publish: true
    }, harness), /URL rewrite configuration is forbidden|exactly one identical fetch and push endpoint/)
    t.is(harness.state.promoterCalls.length, 0)
    t.absent(harness.state.pushed)
  }
})

test('fleet channel publisher - concealed tracked changes fail before promotion', async (t) => {
  for (const hiddenIndexFlag of ['h', 'S']) {
    const harness = fixture({ hiddenIndexFlag })
    await t.exception(async () => publishFleetChannel({
      repo: REPO,
      channel: 'canary',
      target: 'v1.2.3',
      publish: true
    }, harness), /forbids assume-unchanged, skip-worktree/)
    t.is(harness.state.promoterCalls.length, 0)
    t.absent(harness.state.pushed)
  }
})

test('fleet channel publisher - remote races stop before local mutation', async (t) => {
  const harness = fixture({ raceAtRemoteRead: 2 })
  await t.exception(async () => publishFleetChannel({
    repo: REPO,
    channel: 'canary',
    target: 'v1.2.3',
    publish: true
  }, harness), /changed after validation/)

  t.is(harness.state.promoterCalls.length, 1)
  t.absent(harness.state.commitCreated)
  t.absent(harness.state.pushed)
})

test('fleet channel publisher - promoter side effects outside channels fail closed', async (t) => {
  const harness = fixture({ changedFiles: ['fleet/channels.json', 'fleet/relays.json'] })
  await t.exception(async () => publishFleetChannel({
    repo: REPO,
    channel: 'canary',
    target: 'v1.2.3',
    publish: true
  }, harness), /outside fleet\/channels\.json/)

  t.absent(harness.state.commitCreated)
  t.absent(harness.state.pushed)
})

test('fleet channel publisher - staged and committed channel bytes and mode are exact', async (t) => {
  for (const options of [
    { indexBlob: '8'.repeat(40) },
    { indexMode: '120000' },
    { commitBlob: '7'.repeat(40) },
    { commitMode: '100755' }
  ]) {
    const harness = fixture(options)
    await t.exception(async () => publishFleetChannel({
      repo: REPO,
      channel: 'canary',
      target: 'v1.2.3',
      publish: true
    }, harness), /channel mode or bytes changed|unvalidated channel mode or blob/)
    t.absent(harness.state.pushed)
  }
})

test('fleet channel publisher - untrusted commit signature never reaches push', async (t) => {
  const harness = fixture({ badSignature: true })
  await t.exception(async () => publishFleetChannel({
    repo: REPO,
    channel: 'canary',
    target: 'v1.2.3',
    publish: true
  }, harness), /did not report a trusted signature/)

  t.ok(harness.state.commitCreated, 'signed local commit is retained for inspection')
  t.absent(harness.state.pushed)
})

test('fleet channel publisher - stable remains an explicit evidence-bound operation', async (t) => {
  const harness = fixture()
  await t.exception(async () => publishFleetChannel({
    repo: REPO,
    channel: 'stable',
    target: 'v1.2.3',
    publish: true
  }, harness), /--canary-evidence is required/)
  t.is(harness.state.gitCalls.length, 0)
  t.is(harness.state.promoterCalls.length, 0)
})

test('fleet channel publisher - real Git integration signs and publishes only channels.json', {
  skip: !canRunGitSigning,
  timeout: 30_000
}, async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), 'hiverelay-publisher-'))
  const repo = path.join(root, 'repo')
  const remote = path.join(root, 'remote.git')
  const key = path.join(root, 'publisher-key')
  const hooks = path.join(root, 'hostile-hooks')
  const hookMarker = path.join(hooks, 'ran')
  try {
    await gitAt(root, ['init', '--bare', remote])
    await gitAt(root, ['init', '-b', 'main', repo])
    await gitAt(repo, ['config', 'user.name', 'Fleet Publisher'])
    await gitAt(repo, ['config', 'user.email', 'publisher@example.test'])
    await gitAt(repo, ['config', 'gpg.format', 'ssh'])
    await execFileAsync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', key])
    await gitAt(repo, ['config', 'user.signingkey', key])
    await mkdir(path.join(repo, 'fleet'), { recursive: true })
    await mkdir(path.join(repo, 'scripts', 'lib'), { recursive: true })
    await writeFile(path.join(repo, 'fleet', 'channels.json'), JSON.stringify({
      stable: 'v1.2.2',
      canary: 'v1.2.2'
    }, null, 2) + '\n')
    await writeFile(path.join(repo, 'package.json'), '{"version":"1.2.3"}\n')
    const trustedPromoter = await readFile('scripts/promote-fleet-channel.mjs')
    const trustedManifestLibrary = await readFile('scripts/lib/public-hive-gateway-release-manifest.mjs')
    const trustedPolicyLibrary = await readFile('scripts/lib/public-hive-gateway-policy.mjs')
    await writeFile(path.join(repo, 'scripts', 'promote-fleet-channel.mjs'), trustedPromoter)
    await writeFile(path.join(repo, 'scripts', 'lib', 'public-hive-gateway-release-manifest.mjs'),
      trustedManifestLibrary)
    await writeFile(path.join(repo, 'scripts', 'lib', 'public-hive-gateway-policy.mjs'),
      trustedPolicyLibrary)
    const publicKey = (await readFile(`${key}.pub`, 'utf8')).trim().split(/\s+/).slice(0, 2).join(' ')
    await writeFile(path.join(repo, 'fleet', 'allowed-signers'), `publisher@example.test ${publicKey}\n`)
    await gitAt(repo, ['add', 'fleet/channels.json', 'fleet/allowed-signers', 'package.json', 'scripts'])
    await gitAt(repo, ['commit', '-m', 'initial control state'])
    await gitAt(repo, ['-c', 'gpg.format=ssh', 'tag', '-s', '-m', 'v1.2.3 release', 'v1.2.3'])
    await gitAt(repo, ['remote', 'add', 'origin', remote])
    await gitAt(repo, ['push', '-u', 'origin', 'main'])
    await gitAt(repo, ['push', 'origin', 'refs/tags/v1.2.3'])
    const targetSha = (await gitAt(repo, ['rev-parse', 'v1.2.3^{}'])).stdout.trim()
    const maliciousChannels = path.join(root, 'replacement-channels.json')
    const replacementIndex = path.join(root, 'replacement.index')
    await writeFile(maliciousChannels, JSON.stringify({
      stable: 'v0.0.0',
      canary: 'v1.2.2'
    }, null, 2) + '\n')
    const maliciousBlob = (await gitAt(repo, ['hash-object', '-w', '--', maliciousChannels])).stdout.trim()
    const replacementEnv = { GIT_INDEX_FILE: replacementIndex }
    await gitAt(repo, ['read-tree', targetSha], { env: replacementEnv })
    await gitAt(repo, [
      'update-index', '--add', '--cacheinfo', `100644,${maliciousBlob},fleet/channels.json`
    ], { env: replacementEnv })
    const replacementTree = (await gitAt(repo, ['write-tree'], { env: replacementEnv })).stdout.trim()
    const replacementCommit = (await gitAt(repo, [
      'commit-tree', replacementTree, '-m', 'hostile replacement commit'
    ])).stdout.trim()
    await gitAt(repo, ['replace', targetSha, replacementCommit])
    t.is(JSON.parse((await gitAt(repo, ['show', 'HEAD:fleet/channels.json'])).stdout).stable, 'v0.0.0',
      'hostile replace ref is active in the fixture')
    await mkdir(path.join(repo, '.git', 'info'), { recursive: true })
    await writeFile(path.join(repo, '.git', 'info', 'grafts'), `${targetSha} ${replacementCommit}\n`)
    t.is((await gitAt(repo, ['--no-replace-objects', 'rev-parse', 'HEAD^'])).stdout.trim(), replacementCommit,
      'legacy graft is active in the fixture')
    const cleanFilterSource = path.join(root, 'trusted-promoter.mjs')
    await writeFile(cleanFilterSource, trustedPromoter)
    await writeFile(path.join(repo, '.git', 'info', 'attributes'),
      'scripts/promote-fleet-channel.mjs filter=publisher-test\n')
    await gitAt(repo, ['config', 'filter.publisher-test.clean', `/bin/cat ${cleanFilterSource}`])
    await gitAt(repo, ['config', 'filter.publisher-test.required', 'true'])
    await writeFile(path.join(repo, 'scripts', 'promote-fleet-channel.mjs'),
      'throw new Error("hostile worktree promoter executed")\n')
    await gitAt(repo, ['add', '--', 'scripts/promote-fleet-channel.mjs'])
    const concealedStatus = (await gitAt(repo, ['--no-replace-objects', 'status', '--porcelain'], {
      env: { GIT_GRAFT_FILE: '/dev/null/hiverelay-disabled' }
    })).stdout
    t.is(concealedStatus, '', 'hostile clean filter conceals the raw promoter change')
    await gitAt(repo, ['-c', 'gpg.format=ssh', 'tag', '-s', '-m', 'unrelated release', 'v9.9.9'])
    await gitAt(repo, ['config', 'push.followTags', 'true'])
    await mkdir(hooks)
    for (const name of ['post-index-change', 'post-commit', 'pre-push']) {
      const hook = path.join(hooks, name)
      await writeFile(hook, `#!/bin/sh\nprintf ${name} >> "$(dirname "$0")/ran"\n`)
      await chmod(hook, 0o755)
    }
    await gitAt(repo, ['config', 'core.hooksPath', hooks])
    const poisonedGitEnv = {
      GIT_CONFIG_COUNT: '1',
      GIT_CONFIG_KEY_0: 'url.git@evil.invalid:.insteadOf',
      GIT_CONFIG_VALUE_0: ENDPOINT,
      GIT_DIR: remote,
      GIT_INDEX_FILE: replacementIndex,
      GIT_WORK_TREE: repo
    }
    const savedGitEnv = Object.fromEntries(Object.keys(poisonedGitEnv).map(name => [name, process.env[name]]))
    Object.assign(process.env, poisonedGitEnv)
    let result
    try {
      result = await publishFleetChannel({
        repo,
        channel: 'canary',
        target: 'v1.2.3',
        publish: true
      })
    } finally {
      for (const [name, value] of Object.entries(savedGitEnv)) {
        if (value === undefined) delete process.env[name]
        else process.env[name] = value
      }
    }
    t.is(result.status, 'published')
    t.is(result.publishedHead, result.remoteHead)
    t.is(await readFile(hookMarker, 'utf8').catch(() => null), null,
      'local index/commit/push hooks never execute')
    const changed = (await gitAt(repo, [
      '--no-replace-objects', 'diff-tree', '--no-commit-id', '--name-only', '-r', result.publishedHead
    ], { env: { GIT_GRAFT_FILE: '/dev/null/hiverelay-disabled' } })).stdout.trim()
    t.is(changed, 'fleet/channels.json')
    const remoteChannels = (await gitAt(root, [
      '--git-dir', remote, 'show', 'main:fleet/channels.json'
    ])).stdout
    t.is(JSON.parse(remoteChannels).canary, 'v1.2.3')
    t.is(JSON.parse(remoteChannels).stable, 'v1.2.2', 'replace ref cannot alter the other channel')
    t.is((await gitAt(repo, ['--no-replace-objects', 'status', '--porcelain'], {
      env: { GIT_GRAFT_FILE: '/dev/null/hiverelay-disabled' }
    })).stdout, '')
    const remoteFiles = (await gitAt(root, [
      '--git-dir', remote, 'ls-tree', '-r', '--name-only', 'main'
    ])).stdout.trim().split('\n')
    t.alike(remoteFiles, [
      'fleet/allowed-signers',
      'fleet/channels.json',
      'package.json',
      'scripts/lib/public-hive-gateway-policy.mjs',
      'scripts/lib/public-hive-gateway-release-manifest.mjs',
      'scripts/promote-fleet-channel.mjs'
    ])
    const remotePromoter = (await gitAt(root, [
      '--git-dir', remote, 'show', 'main:scripts/promote-fleet-channel.mjs'
    ])).stdout
    t.absent(remotePromoter.includes('hostile worktree promoter executed'),
      'only trusted HEAD promoter code reaches the remote')
    t.is((await gitAt(repo, ['ls-remote', 'origin', 'refs/tags/v9.9.9'])).stdout, '',
      'push.followTags cannot publish unrelated tags')
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

function output (stdout) {
  return { stdout: `${stdout}${stdout && !stdout.endsWith('\0') ? '\n' : ''}`, stderr: '' }
}

function nul (values) {
  return values.length ? `${values.join('\0')}\0` : ''
}

async function gitAt (cwd, args, options = {}) {
  return execFileAsync('git', args, {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, ...(options.env || {}) },
    maxBuffer: 2 * 1024 * 1024,
    timeout: 15_000
  })
}
