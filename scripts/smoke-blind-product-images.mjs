#!/usr/bin/env node
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { execFileSync, spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const policyPath = path.join(root, 'deploy/blind/image-inventory-policy.json')
const policy = JSON.parse(fs.readFileSync(policyPath, 'utf8'))
const args = new Set(process.argv.slice(2))
const staticOnly = args.has('--static-only')
const noBuild = args.has('--no-build')

function command (program, commandArgs, options = {}) {
  const result = spawnSync(program, commandArgs, {
    cwd: root,
    encoding: 'utf8',
    stdio: options.capture ? 'pipe' : 'inherit'
  })
  if (result.error) throw result.error
  if (result.status !== 0) {
    const detail = options.capture ? `${result.stdout || ''}${result.stderr || ''}` : ''
    throw new Error(`${program} ${commandArgs.join(' ')} failed (${result.status})${detail ? `\n${detail}` : ''}`)
  }
  return options.capture ? result.stdout : ''
}

function exactKeys (value) {
  return Object.keys(value).sort()
}

function verifyStaticPackaging () {
  const dockerfile = fs.readFileSync(path.join(root, 'Dockerfile.blind'), 'utf8')
  const compose = fs.readFileSync(path.join(root, 'docker-compose.blind.yml'), 'utf8')
  const edgeManifest = JSON.parse(fs.readFileSync(path.join(root, 'deploy/blind/edge/package.json'), 'utf8'))
  const daemonManifest = JSON.parse(fs.readFileSync(path.join(root, 'deploy/blind/daemon/package.json'), 'utf8'))
  const edgeLock = fs.readFileSync(path.join(root, 'deploy/blind/edge/package-lock.json'), 'utf8')
  const daemonLock = fs.readFileSync(path.join(root, 'deploy/blind/daemon/package-lock.json'), 'utf8')

  assert.deepEqual(exactKeys(edgeManifest.dependencies), [
    '@hiverelay/blind-edge',
    '@hiverelay/blind-ipc',
    '@hiverelay/blind-peercred',
    '@hiverelay/blind-protocol'
  ])
  assert.deepEqual(exactKeys(daemonManifest.dependencies), [
    '@hiverelay/blind-daemon',
    '@hiverelay/blind-ipc',
    '@hiverelay/blind-peercred',
    '@hiverelay/blind-protocol'
  ])
  assert.equal(edgeLock.includes('blind-daemon'), false)
  assert.equal(edgeLock.includes('blind-peercred'), true)
  assert.equal(daemonLock.includes('blind-edge'), false)

  assert.match(dockerfile, /^# syntax=docker\/dockerfile:1\.7@sha256:[0-9a-f]{64}$/m)
  assert.match(dockerfile, /ARG NODE_IMAGE=node:22-bookworm-slim@sha256:[0-9a-f]{64}/)
  assert.match(dockerfile, /AS blind-native-toolchain/)
  assert.match(dockerfile, /AS blind-edge-toolchain/)
  assert.match(dockerfile, /AS blind-daemon-toolchain/)
  assert.match(dockerfile, /AS blind-edge$/m)
  assert.match(dockerfile, /AS blind-daemon$/m)
  assert.equal(dockerfile.split('npm_config_build_from_source=true npm ci').length - 1, 2)
  assert.equal(dockerfile.split('blind_peercred.node').length - 1, 2)
  assert.match(dockerfile, /USER 998:997/)
  assert.match(dockerfile, /USER 999:997/)
  assert.equal(dockerfile.split('HIVERELAY_BLIND_UNARY_SOCKET=/run/hiverelay-blind/unary.sock').length - 1, 2)
  assert.equal(dockerfile.split('HIVERELAY_BLIND_STREAM_SOCKET=/run/hiverelay-blind/stream.sock').length - 1, 2)
  assert.equal(dockerfile.includes('HIVERELAY_BLIND_SOCKET='), false)

  assert.match(compose, /target: blind-edge/)
  assert.match(compose, /target: blind-daemon/)
  assert.match(compose, /condition: service_healthy/)
  assert.match(compose, /condition: service_completed_successfully/)
  assert.equal(compose.includes('condition: service_started'), false)
  assert.equal(compose.split('HIVERELAY_BLIND_UNARY_SOCKET: /run/hiverelay-blind/unary.sock').length - 1, 2)
  assert.equal(compose.split('HIVERELAY_BLIND_STREAM_SOCKET: /run/hiverelay-blind/stream.sock').length - 1, 2)
  assert.match(compose, /entrypoint: \["\/usr\/bin\/timeout", "--signal=KILL", "59s", "\/bin\/sh", "-ec"\]/)
  const daemonService = compose.match(/ {2}blind-daemon:[\s\S]+?\n {2}blind-edge:/)?.[0] || ''
  const edgeService = compose.match(/ {2}blind-edge:[\s\S]+?\nvolumes:/)?.[0] || ''
  assert.equal(daemonService.includes('cap_add:'), false)
  assert.equal(edgeService.includes('cap_add:'), false)
  assert.match(daemonService, /network_mode: none/)
  assert.equal(daemonService.includes('ports:'), false)
  assert.equal(daemonService.includes('blind-public'), false)
  assert.match(edgeService, /networks:\n {6}- blind-public/)
  assert.match(edgeService, /ports:/)
  assert.match(compose, /cap_add:\n {6}- CHOWN\n {6}- DAC_OVERRIDE\n {6}- FOWNER/)
  assert.match(compose, /blind-runtime:\/run\/hiverelay-blind:ro/)
  command('docker', ['compose', '-f', 'docker-compose.blind.yml', 'config', '--quiet'])
}

const probeSource = String.raw`
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'

const component = process.env.BLIND_PROBE_COMPONENT
const root = '/opt/hiverelay/' + component
const runtime = fs.statSync('/run/hiverelay-blind')
const status = fs.readFileSync('/proc/self/status', 'utf8')
const capEff = status.match(/^CapEff:\s+(.+)$/m)?.[1]?.trim()
const commandPaths = process.env.PATH.split(':')
const compilerCommands = JSON.parse(process.env.BLIND_PROBE_COMPILERS)
const compilers = compilerCommands.filter(name => commandPaths.some(directory => fs.existsSync(path.join(directory, name))))
const forbiddenRoots = JSON.parse(process.env.BLIND_PROBE_FORBIDDEN_ROOTS).filter(candidate => fs.existsSync(candidate))
const packages = fs.readdirSync(path.join(root, 'node_modules/@hiverelay')).sort()
function hashTree (directory) {
  const files = []
  function visit (current, relative) {
    for (const entry of fs.readdirSync(current, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const next = path.join(current, entry.name)
      const nextRelative = relative ? relative + '/' + entry.name : entry.name
      if (entry.isDirectory()) visit(next, nextRelative)
      else if (entry.isFile()) files.push([nextRelative, next])
      else throw new Error('unexpected non-file package entry: ' + nextRelative)
    }
  }
  visit(directory, '')
  const hash = crypto.createHash('sha256')
  for (const [relative, file] of files) {
    hash.update(relative)
    hash.update('\0')
    hash.update(fs.readFileSync(file))
    hash.update('\0')
  }
  return hash.digest('hex')
}
const result = {
  component,
  uid: process.geteuid(),
  gid: process.getegid(),
  capEff,
  packages,
  compilers,
  forbiddenRoots,
  sharedPackageHashes: Object.fromEntries(['blind-ipc', 'blind-protocol'].map(name => [
    name,
    hashTree(path.join(root, 'node_modules/@hiverelay', name))
  ])),
  runtime: { uid: runtime.uid, gid: runtime.gid, mode: runtime.mode & 0o777 },
  runtimeWritable: true,
  peercredAddon: false,
  peercredImport: false,
  targetArchitecture: null,
  data: null
}
try {
  fs.accessSync('/run/hiverelay-blind', fs.constants.W_OK)
} catch {
  result.runtimeWritable = false
}
const addon = path.join(root, 'node_modules/@hiverelay/blind-peercred/build/Release/blind_peercred.node')
result.peercredAddon = fs.statSync(addon).isFile()
const imported = await import(path.join(root, 'node_modules/@hiverelay/blind-peercred/index.js'))
result.peercredImport = typeof imported.socketPeerCredentials === 'function'
result.targetArchitecture = fs.readFileSync(path.join(root, 'peercred-target-architecture'), 'utf8').trim()
if (component === 'daemon') {
  const data = fs.statSync('/data/blind')
  result.data = { uid: data.uid, gid: data.gid, mode: data.mode & 0o777 }
}
process.stdout.write(JSON.stringify(result))
`

function imageInspect (image) {
  return JSON.parse(execFileSync('docker', ['image', 'inspect', image], { cwd: root, encoding: 'utf8' }))[0]
}

function imageProbe (component, image) {
  const output = execFileSync('docker', [
    'run', '--rm',
    '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges:true',
    '--network', 'none',
    '--env', `BLIND_PROBE_COMPONENT=${component}`,
    '--env', `BLIND_PROBE_COMPILERS=${JSON.stringify(policy.forbiddenCompilerCommands)}`,
    '--env', `BLIND_PROBE_FORBIDDEN_ROOTS=${JSON.stringify(policy.forbiddenRoots)}`,
    '--entrypoint', 'node',
    image,
    '--input-type=module', '--eval', probeSource
  ], { cwd: root, encoding: 'utf8' })
  return JSON.parse(output)
}

function verifyImage (component, image) {
  const expected = policy.components[component]
  const inspected = imageInspect(image)
  const config = inspected.Config
  const labels = config.Labels || {}
  const probe = imageProbe(component, image)

  assert.equal(config.User, expected.user)
  assert.deepEqual(config.Entrypoint, expected.entrypoint)
  assert.equal(labels['org.opencontainers.image.hiverelay.product-mode'], policy.productMode)
  assert.equal(labels['org.opencontainers.image.hiverelay.component'], component)
  assert.ok(labels[policy.bundleLabel])
  assert.ok(config.Healthcheck && Array.isArray(config.Healthcheck.Test))
  assert.deepEqual(probe.packages, expected.hiverelayPackages)
  assert.deepEqual(probe.compilers, [])
  assert.deepEqual(probe.forbiddenRoots, [])
  assert.equal(probe.capEff, '0000000000000000')
  assert.deepEqual(probe.runtime, { uid: 999, gid: 997, mode: 0o750 })
  assert.equal(probe.uid, Number(expected.user.split(':')[0]))
  assert.equal(probe.gid, 997)
  assert.equal(probe.peercredAddon, true)
  assert.equal(probe.peercredImport, true)
  assert.equal(probe.targetArchitecture, inspected.Architecture)
  const env = Object.fromEntries((config.Env || []).map(entry => {
    const separator = entry.indexOf('=')
    return [entry.slice(0, separator), entry.slice(separator + 1)]
  }))
  assert.equal(env.HIVERELAY_BLIND_UNARY_SOCKET, '/run/hiverelay-blind/unary.sock')
  assert.equal(env.HIVERELAY_BLIND_STREAM_SOCKET, '/run/hiverelay-blind/stream.sock')
  assert.equal(env.HIVERELAY_BLIND_DAEMON_UID, '999')
  assert.equal(env.HIVERELAY_BLIND_DAEMON_GID, '997')
  assert.equal(env.HIVERELAY_BLIND_SHARED_GID, '997')
  assert.equal(env.HIVERELAY_BLIND_SOCKET, undefined)

  for (const forbidden of policy.forbiddenHiverelayPackages) {
    assert.equal(probe.packages.includes(forbidden), false)
  }
  if (component === 'edge') {
    assert.equal(probe.packages.includes('blind-daemon'), false)
    assert.equal(probe.packages.includes('blind-peercred'), true)
    assert.equal(probe.runtimeWritable, false)
    assert.ok(config.ExposedPorts && config.ExposedPorts['9100/tcp'])
  } else {
    assert.equal(probe.packages.includes('blind-edge'), false)
    assert.equal(probe.runtimeWritable, true)
    assert.deepEqual(probe.data, { uid: 999, gid: 997, mode: 0o700 })
    assert.equal(config.ExposedPorts == null, true)
  }
  return {
    component,
    image,
    id: inspected.Id,
    architecture: inspected.Architecture,
    packages: probe.packages,
    sharedPackageHashes: probe.sharedPackageHashes
  }
}

verifyStaticPackaging()
if (staticOnly) {
  process.stdout.write('blind product packaging static smoke: ok\n')
  process.exit(0)
}
if (!noBuild) command('docker', ['compose', '-f', 'docker-compose.blind.yml', 'build', 'blind-edge', 'blind-daemon'])

const edgeImage = process.env.HIVERELAY_BLIND_EDGE_IMAGE || policy.components.edge.image
const daemonImage = process.env.HIVERELAY_BLIND_DAEMON_IMAGE || policy.components.daemon.image
const edge = verifyImage('edge', edgeImage)
const daemon = verifyImage('daemon', daemonImage)
assert.notEqual(edge.id, daemon.id)
assert.deepEqual(edge.sharedPackageHashes, daemon.sharedPackageHashes)

const edgeBundle = imageInspect(edgeImage).Config.Labels[policy.bundleLabel]
const daemonBundle = imageInspect(daemonImage).Config.Labels[policy.bundleLabel]
assert.equal(edgeBundle, daemonBundle)
process.stdout.write(`${JSON.stringify({ schema: 'HiveRelayBlindImageSmokeV1', bundleId: edgeBundle, images: [edge, daemon] }, null, 2)}\n`)
