#!/usr/bin/env node
import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import fs from 'node:fs/promises'
import { createReadStream } from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'
import {
  BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT_PROFILES,
  decodeBlindClientPublicBrowserArtifactManifestV1,
  encodeBlindClientPublicBrowserCrossHostEvidenceV1,
  hashBlindClientPublicBrowserArtifactManifestV1,
  hashBlindClientPublicBrowserNormalizedGraphSetV1,
  verifyBlindClientPublicBrowserArtifactReleaseEvidenceV1,
  verifyBlindClientPublicBrowserArtifactV1
} from '../browser-artifact.js'

if (process.argv.length !== 2) {
  throw new Error('usage: test-blind-client-public-browser-artifact-cross-host.mjs')
}

const execute = promisify(execFile)
const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const root = path.resolve(packageRoot, '../..')
const canonicalSourceRoot = '/Users/localllm/.pear-wt/s29artifact5'
const hostNode = '/opt/homebrew/Cellar/node@22/22.22.0/bin/node'
const hostNodeHash = '59776c1735b2c28a28b0ae00b58bd9cbe524572e0caf62e043d5e44a62d98cce'
const headerCache = '/Users/localllm/Library/Caches/node-gyp/22.22.0'
const headerCacheHash = 'dcd517fb9670e6192712badf0bdf1a9dfc4c8ff88887d06e4d4f4eb42e574990'
const headerInstallVersionHash = '25d4f2a86deb5e2574bb3210b67bb24fcc4afb19f93a7b65a057daa874a9d18e'
const headerNodeH = '/Users/localllm/Library/Caches/node-gyp/22.22.0/include/node/node.h'
const headerNodeHHash = '4da8d691b256d4bef9c0e89114645f08787dc4892eae76240d28efdf4fa55019'
const image = 'sha256:813a7480f28fdadac1f7f5c824bcdad435b5bc1322a5968bbbdef8d058f9dff4'
const patchHash = 'fbcd793cfb4fd3334b04bfd9163a728064eef2500361cb83ef84e95d13b46b53'
const gateRoot = path.join(root, '.t/seq29-browser-artifact-gates')
const stage = path.join(gateRoot, 'container-stage')
const stageRepository = path.join(stage, 'repository')
const nativeAddonRelative = 'packages/blind-peercred/build/Release/blind_peercred.node'
const evidenceRelatives = Object.values(BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT_PROFILES)
  .flatMap(identity => [identity.chromiumEvidencePath, identity.crossHostEvidencePath])
const outputRelatives = Object.values(BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT_PROFILES)
  .flatMap(identity => [identity.artifactPath, identity.manifestPath])

function absolute (relative, base = root) {
  if (!relative || path.isAbsolute(relative) || relative.split('/').some(part => part === '..')) {
    throw new Error(`path is not a closed repository-relative path: ${relative}`)
  }
  return path.resolve(base, ...relative.split('/'))
}

async function sha256File (file) {
  const hash = createHash('sha256')
  await new Promise((resolve, reject) => {
    const stream = createReadStream(file)
    stream.on('data', chunk => hash.update(chunk))
    stream.once('error', reject)
    stream.once('end', resolve)
  })
  return hash.digest('hex')
}

async function requireRealDirectoryAncestry (expected, field) {
  if (!path.isAbsolute(expected)) throw new Error(`${field} must be absolute`)
  const parsed = path.parse(expected)
  let current = parsed.root
  for (const component of expected.slice(parsed.root.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, component)
    const stat = await fs.lstat(current)
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      throw new Error(`${field} ancestry must contain only real directories: ${current}`)
    }
  }
  if (await fs.realpath(expected) !== expected) throw new Error(`${field} realpath changed`)
}

async function assertHostEnvironment () {
  const expected = {
    TMPDIR: path.join(gateRoot, 'tmp'),
    npm_config_cache: path.join(gateRoot, 'npm-cache'),
    npm_config_devdir: '/Users/localllm/Library/Caches/node-gyp'
  }
  for (const [name, value] of Object.entries(expected)) {
    if (process.env[name] !== value) throw new Error(`${name} must be ${value}`)
    await requireRealDirectoryAncestry(value, name)
  }
  if (process.execPath !== hostNode || process.version !== 'v22.22.0' ||
      process.versions.modules !== '127' || process.versions.napi !== '10' ||
      process.platform !== 'darwin' || process.arch !== 'arm64' ||
      await sha256File(process.execPath) !== hostNodeHash) {
    throw new Error('cross-host gate requires the exact pinned host Node identity')
  }
}

function byteCompare (left, right) {
  return Buffer.compare(Buffer.from(left), Buffer.from(right))
}

async function headerIdentity () {
  await requireRealDirectoryAncestry(headerCache, 'node-gyp header cache')
  const files = []
  let symlinks = 0
  async function visit (directory) {
    for (const name of await fs.readdir(directory)) {
      const target = path.join(directory, name)
      const stat = await fs.lstat(target)
      if (stat.isSymbolicLink()) {
        symlinks++
      } else if (stat.isDirectory()) {
        await visit(target)
      } else if (stat.isFile()) {
        files.push(`./${path.relative(headerCache, target).split(path.sep).join('/')}`)
      } else {
        throw new Error(`node-gyp header cache contains a non-file entry: ${target}`)
      }
    }
  }
  await visit(headerCache)
  files.sort(byteCompare)
  const normalized = createHash('sha256')
  for (const relative of files) {
    const digest = await sha256File(path.join(headerCache, relative.slice(2)))
    normalized.update(`${digest}  ${relative}\n`)
  }
  const installVersion = await fs.readFile(path.join(headerCache, 'installVersion'), 'utf8')
  const nodeHeader = await fs.readFile(headerNodeH)
  const identity = {
    fileCount: files.length,
    symlinkCount: symlinks,
    digest: normalized.digest('hex'),
    installVersion: installVersion.trim(),
    installVersionHash: await sha256File(path.join(headerCache, 'installVersion')),
    nodeHeaderBytes: nodeHeader.byteLength,
    nodeHeaderHash: await sha256File(headerNodeH)
  }
  if (identity.fileCount !== 2726 || identity.symlinkCount !== 0 ||
      identity.digest !== headerCacheHash || identity.installVersion !== '11' ||
      identity.installVersionHash !== headerInstallVersionHash ||
      identity.nodeHeaderBytes !== 69621 || identity.nodeHeaderHash !== headerNodeHHash) {
    throw new Error(`pinned node-gyp header cache identity changed: ${JSON.stringify(identity)}`)
  }
  return identity
}

async function inspectImage () {
  const result = await execute('docker', [
    'image', 'inspect', image, '--format', '{{.Id}} {{.Os}}/{{.Architecture}}'
  ], { encoding: 'utf8', timeout: 30_000, maxBuffer: 1024 * 1024 })
  if (result.stdout.trim() !== `${image} linux/arm64`) {
    throw new Error(`pinned container image identity changed: ${result.stdout.trim()}`)
  }
}

async function pathHashOrAbsent (file) {
  try { return await sha256File(file) } catch (error) {
    if (error && error.code === 'ENOENT') return null
    throw error
  }
}

async function evidenceInventory (base = root) {
  return Promise.all(evidenceRelatives.map(async relative => ({
    path: relative,
    sha256: await pathHashOrAbsent(absolute(relative, base))
  })))
}

function sameInventory (left, right) {
  return JSON.stringify(left) === JSON.stringify(right)
}

async function requireAbsentStage () {
  try {
    await fs.lstat(stage)
    throw new Error(`container stage already exists and cannot be reused: ${stage}`)
  } catch (error) {
    if (error && error.code === 'ENOENT') return
    throw error
  }
}

async function removeOwnedStage (identity) {
  const stat = await fs.lstat(stage)
  if (!stat.isDirectory() || stat.isSymbolicLink() || `${stat.dev}:${stat.ino}` !== identity ||
      path.dirname(await fs.realpath(stage)) !== await fs.realpath(gateRoot)) {
    throw new Error('container stage custody changed before cleanup')
  }
  await fs.rm(stage, { recursive: true, force: false })
}

function mount (source, target, readonly = false) {
  return `type=bind,source=${source},target=${target}${readonly ? ',readonly' : ''}`
}

async function runContainerProof (committedEvidenceBefore) {
  await inspectImage()
  await requireAbsentStage()
  await fs.mkdir(stage, { mode: 0o700 })
  const stat = await fs.lstat(stage)
  const identity = `${stat.dev}:${stat.ino}`
  let proof
  try {
    await Promise.all([
      fs.mkdir(stageRepository, { mode: 0o700 }),
      fs.mkdir(path.join(stage, 'npm-cache'), { mode: 0o700 }),
      fs.mkdir(path.join(stage, 'tmp'), { mode: 0o700 }),
      fs.mkdir(path.join(stage, 'home'), { mode: 0o700 }),
      fs.mkdir(path.join(stage, 'node-gyp'), { mode: 0o700 })
    ])
    const installScript = `set -eu
cd /source
tar --exclude='./.git' --exclude='./node_modules' --exclude='./.t/seq29-browser-artifact-gates' --exclude='./packages/blind-peercred/build' -cf - . | tar -xf - -C /stage/repository
cd /stage/repository
npm ci --ignore-scripts --no-audit --no-fund
node node_modules/patch-package/index.js --error-on-fail
mkdir -p .t/seq29-browser-artifact-gates/tmp .t/seq29-browser-artifact-gates/npm-cache
node -e "process.stdout.write('HIVERELAY_INSTALL_ENV=' + JSON.stringify({node:process.version,modules:process.versions.modules,napi:process.versions.napi,platform:process.platform,architecture:process.arch}) + '\\n')"`
    const common = [
      'run', '--rm', '--read-only', '--cap-drop', 'ALL',
      '--security-opt', 'no-new-privileges',
      '--tmpfs', '/tmp:rw,exec,nosuid,size=1024m',
      '--mount', mount(root, '/source', true),
      '--mount', mount(stage, '/stage'),
      '--env', 'HOME=/stage/home', '--env', 'npm_config_cache=/stage/npm-cache',
      '--env', 'TMPDIR=/stage/tmp', '--env', 'npm_config_devdir=/stage/node-gyp'
    ]
    const installed = await execute('docker', [
      ...common, image, 'sh', '-lc', installScript
    ], {
      encoding: 'utf8',
      timeout: 12 * 60_000,
      killSignal: 'SIGKILL',
      maxBuffer: 32 * 1024 * 1024
    })
    const installLine = installed.stdout.split(/\r?\n/)
      .find(line => line.startsWith('HIVERELAY_INSTALL_ENV='))
    if (!installLine) throw new Error(`container install did not emit its runtime identity:\n${installed.stdout}`)
    const installEnvironment = JSON.parse(installLine.slice('HIVERELAY_INSTALL_ENV='.length))
    if (JSON.stringify(installEnvironment) !== JSON.stringify({
      node: 'v22.23.1', modules: '127', napi: '10', platform: 'linux', architecture: 'arm64'
    })) throw new Error(`container runtime identity changed: ${JSON.stringify(installEnvironment)}`)

    const stagedEvidenceBefore = await evidenceInventory(stageRepository)
    if (!sameInventory(committedEvidenceBefore, stagedEvidenceBefore)) {
      throw new Error('container archive evidence inputs do not match the source inputs')
    }
    const generationMounts = []
    for (const item of stagedEvidenceBefore) {
      if (item.sha256 != null) {
        generationMounts.push('--mount', mount(
          absolute(item.path, stageRepository), `/stage/repository/${item.path}`, true))
      }
    }
    const generationScript = `set -eu
cd /stage/repository
node packages/blind-client-public-browser/scripts/generate-blind-client-public-browser-artifacts.mjs
node -e "process.stdout.write('HIVERELAY_GENERATION_ENV=' + JSON.stringify({node:process.version,modules:process.versions.modules,napi:process.versions.napi,platform:process.platform,architecture:process.arch}) + '\\n')"`
    const generated = await execute('docker', [
      'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
      '--security-opt', 'no-new-privileges',
      '--tmpfs', '/tmp:rw,exec,nosuid,size=1024m',
      '--mount', mount(root, '/source', true),
      '--mount', mount(stage, '/stage'),
      '--mount', mount(path.join(stage, 'node-gyp'), '/Users/localllm/Library/Caches/node-gyp'),
      ...generationMounts,
      '--env', 'HOME=/stage/home',
      '--env', 'TMPDIR=/stage/repository/.t/seq29-browser-artifact-gates/tmp',
      '--env', 'npm_config_cache=/stage/repository/.t/seq29-browser-artifact-gates/npm-cache',
      '--env', 'npm_config_devdir=/Users/localllm/Library/Caches/node-gyp',
      image, 'sh', '-lc', generationScript
    ], {
      encoding: 'utf8',
      timeout: 8 * 60_000,
      killSignal: 'SIGKILL',
      maxBuffer: 32 * 1024 * 1024
    })
    const reports = generated.stdout.split(/\r?\n/).filter(Boolean).map(line => {
      try { return JSON.parse(line) } catch { return null }
    }).filter(value => value && value.schema === 'HiveRelayBlindClientPublicBrowserArtifactGenerationV1')
    const environmentLine = generated.stdout.split(/\r?\n/)
      .find(line => line.startsWith('HIVERELAY_GENERATION_ENV='))
    if (reports.length !== 1 || !environmentLine) {
      throw new Error(`container generation did not emit exact reports:\n${generated.stdout}\n${generated.stderr}`)
    }
    const report = reports[0]
    const environment = JSON.parse(environmentLine.slice('HIVERELAY_GENERATION_ENV='.length))
    if (JSON.stringify(environment) !== JSON.stringify(installEnvironment) ||
        Reflect.ownKeys(report.profiles).join(',') !== 'full,limited' ||
        report.releaseReady !== false || report.standaloneAuthority !== false ||
        report.authority !== 'external-postcommit-final-sequence-required' ||
        !/^[0-9a-f]{64}$/.test(report.normalizedGraphSetHash)) {
      throw new Error('container generator report changed its exact non-authoritative identity')
    }
    for (const id of ['full', 'limited']) {
      const profile = report.profiles[id]
      if (!profile || !/^[0-9a-f]{64}$/.test(profile.normalizedGraphHash) ||
          profile.nativeAddonReachable !== false || profile.nativeAddonUnreachable !== true ||
          profile.releaseReady !== false || profile.standaloneAuthority !== false) {
        throw new Error(`${id} container graph report changed its required identity`)
      }
    }
    if (hashBlindClientPublicBrowserNormalizedGraphSetV1({
      full: report.profiles.full.normalizedGraphHash,
      limited: report.profiles.limited.normalizedGraphHash
    }) !== report.normalizedGraphSetHash) {
      throw new Error('container normalized graph set digest is not independently reproducible')
    }
    for (const relative of outputRelatives) {
      const [sourceBytes, stagedBytes] = await Promise.all([
        fs.readFile(absolute(relative)), fs.readFile(absolute(relative, stageRepository))
      ])
      if (!sourceBytes.equals(stagedBytes)) throw new Error(`container output differs: ${relative}`)
    }
    const stagedEvidenceAfter = await evidenceInventory(stageRepository)
    const committedEvidenceAfter = await evidenceInventory()
    if (!sameInventory(stagedEvidenceBefore, stagedEvidenceAfter) ||
        !sameInventory(committedEvidenceBefore, committedEvidenceAfter)) {
      throw new Error('container phases changed committed evidence inputs')
    }
    proof = { report, environment, evidenceInputCount: committedEvidenceBefore.filter(x => x.sha256).length }
  } finally {
    await removeOwnedStage(identity)
  }
  try {
    await fs.lstat(stage)
    throw new Error('container stage cleanup left residue')
  } catch (error) {
    if (!error || error.code !== 'ENOENT') throw error
  }
  return proof
}

async function verifiedProfile (id, report) {
  const identity = BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT_PROFILES[id]
  const [artifactBytes, manifestBytes] = await Promise.all([
    fs.readFile(absolute(identity.artifactPath)),
    fs.readFile(absolute(identity.manifestPath))
  ])
  const manifest = decodeBlindClientPublicBrowserArtifactManifestV1(manifestBytes)
  const verified = verifyBlindClientPublicBrowserArtifactV1({
    profile: id,
    artifactBytes,
    manifestBytes,
    expectedManifestHash: hashBlindClientPublicBrowserArtifactManifestV1(manifestBytes),
    expectedSourceClosureHash: manifest.sourceClosureHash,
    expectedTupleHash: manifest.tupleHash
  })
  const reported = report.profiles[id]
  if (reported.profile !== verified.profile || reported.artifactPath !== verified.artifactPath ||
      reported.artifactLength !== verified.artifactLength || reported.artifactHash !== verified.artifactHash ||
      reported.manifestHash !== verified.manifestHash || reported.tupleHash !== verified.tupleHash ||
      report.sourceClosureHash !== verified.sourceClosureHash) {
    throw new Error(`${id} container report does not bind the verified source artifact`)
  }
  return { identity, artifactBytes, manifestBytes, verified }
}

async function nativeIdentity () {
  const addon = absolute(nativeAddonRelative)
  const packageJson = JSON.parse(await fs.readFile(absolute('packages/blind-peercred/package.json'), 'utf8'))
  if (packageJson.name !== '@hiverelay/blind-peercred' || packageJson.version !== '1.0.0-rc.1') {
    throw new Error('native addon package identity changed')
  }
  const architecture = (await execute('/usr/bin/file', ['-b', addon], {
    encoding: 'utf8', timeout: 10_000, maxBuffer: 1024 * 1024
  })).stdout.trim()
  if (architecture !== 'Mach-O 64-bit bundle arm64') {
    throw new Error(`native addon architecture changed: ${architecture}`)
  }
  const hash = await sha256File(addon)
  const canonicalAddon = absolute(nativeAddonRelative, canonicalSourceRoot)
  if (root !== canonicalSourceRoot && hash !== await sha256File(canonicalAddon)) {
    throw new Error('clean archive native addon differs from the canonical source addon')
  }
  return { architecture, hash }
}

await assertHostEnvironment()
const headerBefore = await headerIdentity()
const committedEvidenceBefore = await evidenceInventory()
const container = await runContainerProof(committedEvidenceBefore)
const [headerAfter, native] = await Promise.all([headerIdentity(), nativeIdentity()])
if (JSON.stringify(headerBefore) !== JSON.stringify(headerAfter)) {
  throw new Error('pinned node-gyp header cache changed across cross-host work')
}

const generatedEvidence = {}
for (const id of ['full', 'limited']) {
  const item = await verifiedProfile(id, container.report)
  generatedEvidence[id] = encodeBlindClientPublicBrowserCrossHostEvidenceV1({
    schema: 'HiveRelayBlindClientPublicBrowserArtifactCrossHostEvidenceV1',
    version: 1,
    evidenceClass: 'clean-linux-container',
    profile: item.verified.profile,
    artifactPath: item.verified.artifactPath,
    artifactLength: item.verified.artifactLength,
    artifactHash: item.verified.artifactHash,
    manifestHash: item.verified.manifestHash,
    tupleHash: item.verified.tupleHash,
    sourceClosureHash: item.verified.sourceClosureHash,
    acceptedSourceCommit: '1a114f64c97547cab6a18102c2ef4bff930e53ed',
    acceptedSourceTree: '5a341ba17a3d91a750cac94ba51116fe3552a6aa',
    candidateIdentityBinding: 'external-postcommit-final-sequence',
    standaloneAuthority: false,
    sourceArchiveIdentity: 'same-committed-relative-bytes',
    hostNodeExecutable: hostNode,
    hostNodeExecutableHash: hostNodeHash,
    hostNode: 'v22.22.0',
    hostModulesAbi: '127',
    hostNapi: '10',
    hostPlatform: 'darwin',
    hostArchitecture: 'arm64',
    headerCachePath: headerCache,
    headerCacheFileCount: headerAfter.fileCount,
    headerCacheSymlinkCount: headerAfter.symlinkCount,
    headerCacheDigest: headerBefore.digest,
    headerCachePostflightDigest: headerAfter.digest,
    headerCacheInstallVersion: headerAfter.installVersion,
    headerCacheInstallVersionHash: headerAfter.installVersionHash,
    headerCacheNodeHeaderPath: headerNodeH,
    headerCacheNodeHeaderBytes: headerAfter.nodeHeaderBytes,
    headerCacheNodeHeaderHash: headerAfter.nodeHeaderHash,
    nativeAddonPath: nativeAddonRelative,
    nativeAddonPackage: '@hiverelay/blind-peercred',
    nativeAddonVersion: '1.0.0-rc.1',
    nativeAddonArchitecture: native.architecture,
    nativeAddonHash: native.hash,
    sourceArchiveNativeAddonEqual: true,
    containerImageId: image,
    containerPlatform: 'linux/arm64',
    containerArchitecture: container.environment.architecture,
    containerNode: container.environment.node,
    containerModulesAbi: container.environment.modules,
    containerNapi: container.environment.napi,
    containerRootReadOnly: true,
    containerCapabilitiesDropped: true,
    containerNoNewPrivileges: true,
    installNetworkPhase: 'networked-exact-lock-npm-ci-ignore-scripts',
    generationNetworkPhase: 'none',
    patchApplied: 'hypercore-storage@3.2.0',
    patchHash,
    containerNativeRebuild: 'omitted-unreachable',
    fullNativeAddonReachable: false,
    limitedNativeAddonReachable: false,
    normalizedGraphHash: container.report.profiles[id].normalizedGraphHash,
    normalizedGraphSetHash: container.report.normalizedGraphSetHash,
    artifactManifestByteEquality: true,
    committedEvidenceInputsUntouched: true,
    committedEvidenceInputsProof: 'external-f2-pre-post-sha256',
    toolchain: item.verified.manifest.toolchain,
    checks: item.identity.crossHostChecks,
    passed: true
  })
  const chromiumEvidenceBytes = await fs.readFile(absolute(item.identity.chromiumEvidencePath))
  const release = verifyBlindClientPublicBrowserArtifactReleaseEvidenceV1({
    profile: id,
    artifactBytes: item.artifactBytes,
    manifestBytes: item.manifestBytes,
    expectedManifestHash: item.verified.manifestHash,
    expectedSourceClosureHash: item.verified.sourceClosureHash,
    expectedTupleHash: item.verified.tupleHash,
    expectedNormalizedGraphHash: container.report.profiles[id].normalizedGraphHash,
    expectedNormalizedGraphSetHash: container.report.normalizedGraphSetHash,
    chromiumEvidenceBytes,
    crossHostEvidenceBytes: generatedEvidence[id]
  })
  if (release.evidenceValid !== true || release.releaseReady !== false ||
      release.standaloneAuthority !== false) {
    throw new Error(`${id} combined release evidence changed its external-only authority`)
  }
}

await Promise.all(['full', 'limited'].map(id => fs.writeFile(
  absolute(BLIND_CLIENT_PUBLIC_BROWSER_ARTIFACT_PROFILES[id].crossHostEvidencePath),
  generatedEvidence[id], { mode: 0o644 }
)))
const report = {
  schema: 'HiveRelayBlindClientPublicBrowserArtifactCrossHostGateV1',
  containerImageId: image,
  containerPlatform: 'linux/arm64',
  containerNode: container.environment.node,
  containerModulesAbi: container.environment.modules,
  containerNapi: container.environment.napi,
  normalizedGraphSetHash: container.report.normalizedGraphSetHash,
  committedEvidenceInputCount: container.evidenceInputCount,
  committedEvidenceInputsProof: 'external-f2-pre-post-sha256',
  releaseReady: false,
  standaloneAuthority: false,
  authority: 'external-postcommit-final-sequence-required',
  profiles: Object.fromEntries(['full', 'limited'].map(id => [id, {
    normalizedGraphHash: container.report.profiles[id].normalizedGraphHash,
    nativeAddonReachable: false,
    artifactManifestByteEquality: true,
    evidenceWritten: true,
    ok: true
  }])),
  stageResidue: 0,
  ok: true
}
process.stdout.write(`${JSON.stringify(report)}\n`)
