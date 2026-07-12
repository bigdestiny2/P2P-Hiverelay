import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { spawn } from 'node:child_process'

const children = new Set()
let closing = false
let temporaryRuntimeDir = null

function requiredUnsignedEnvironment (name, maximum = 0xffffffff, minimum = 0) {
  const value = process.env[name]
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${name} is required from the signed launch topology as an unsigned integer`)
  }
  const decoded = Number(value)
  if (!Number.isSafeInteger(decoded) || decoded < minimum || decoded > maximum) {
    throw new Error(`${name} is outside its signed launch-topology range`)
  }
  return decoded
}

function requiredTopologyHash () {
  const value = process.env.HIVERELAY_BLIND_LAUNCH_TOPOLOGY_HASH
  if (typeof value !== 'string' || !/^[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error('HIVERELAY_BLIND_LAUNCH_TOPOLOGY_HASH must be the exact 32-byte signed topology hash in hex')
  }
  return value.toLowerCase()
}

function canonicalSocketPath (value, field) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || value.includes('\0') || path.normalize(value) !== value) {
    throw new Error(`${field} must be a canonical absolute Unix socket path`)
  }
  if (Buffer.byteLength(value) > 100) throw new Error(`${field} exceeds the portable Unix socket path bound`)
  return value
}

function launch (entrypoint, env) {
  const child = spawn(process.execPath, [entrypoint], { env, stdio: 'inherit' })
  children.add(child)
  child.once('exit', () => children.delete(child))
  return child
}

function waitForExit (child) {
  if (child.exitCode != null || child.signalCode != null) return Promise.resolve()
  return new Promise(resolve => child.once('exit', resolve))
}

async function waitForSockets (child, unarySocketPath, streamSocketPath) {
  for (let attempt = 0; attempt < 200; attempt++) {
    if (child.exitCode != null || child.signalCode != null) {
      throw new Error(`blind daemon exited before readiness sockets were bound (${child.exitCode ?? child.signalCode})`)
    }
    try {
      const [unary, stream] = await Promise.all([
        fs.lstat(unarySocketPath),
        fs.lstat(streamSocketPath)
      ])
      if (!unary.isSocket() || !stream.isSocket()) throw new Error('blind daemon readiness paths are not both Unix sockets')
      if (unary.dev === stream.dev && unary.ino === stream.ino) throw new Error('blind daemon readiness paths resolve to one inode')
      if ((unary.mode & 0o777) !== 0o660 || (stream.mode & 0o777) !== 0o660) {
        throw new Error('blind daemon readiness sockets are not both mode 0660')
      }
      return
    } catch (error) {
      if (!error || (error.code !== 'ENOENT' && !String(error.message).includes('readiness'))) throw error
    }
    await new Promise(resolve => setTimeout(resolve, 25))
  }
  throw new Error('blind daemon did not create both private sockets within five seconds')
}

async function close (code = 0) {
  if (closing) return
  closing = true
  const running = [...children]
  for (const child of running) child.kill('SIGTERM')
  const exited = Promise.all(running.map(waitForExit))
  const grace = new Promise(resolve => setTimeout(resolve, 5000))
  await Promise.race([exited, grace])
  for (const child of running) {
    if (child.exitCode == null && child.signalCode == null) child.kill('SIGKILL')
  }
  await Promise.all(running.map(waitForExit))
  if (temporaryRuntimeDir) await fs.rm(temporaryRuntimeDir, { recursive: true, force: true })
  process.exit(code)
}

async function main () {
  const launchTopologyHash = requiredTopologyHash()
  const endpointId = requiredUnsignedEnvironment('HIVERELAY_BLIND_ENDPOINT_ID', 0xff, 1)
  if (typeof process.getuid !== 'function' || typeof process.getgid !== 'function') {
    throw new Error('the local two-process launcher requires POSIX peer credentials')
  }
  const localUid = process.getuid()
  const localGid = process.getgid()

  let runtimeDir = process.env.HIVERELAY_BLIND_RUNTIME_DIR
  if (!runtimeDir) {
    const created = await fs.mkdtemp(path.join(os.tmpdir(), 'hiverelay-blind-'))
    runtimeDir = await fs.realpath(created)
    temporaryRuntimeDir = runtimeDir
  }
  if (!path.isAbsolute(runtimeDir) || path.normalize(runtimeDir) !== runtimeDir || await fs.realpath(runtimeDir) !== runtimeDir) {
    throw new Error('HIVERELAY_BLIND_RUNTIME_DIR must be one canonical non-symlink absolute directory')
  }

  const unarySocketPath = canonicalSocketPath(
    process.env.HIVERELAY_BLIND_UNARY_SOCKET || path.join(runtimeDir, 'unary.sock'),
    'HIVERELAY_BLIND_UNARY_SOCKET'
  )
  const streamSocketPath = canonicalSocketPath(
    process.env.HIVERELAY_BLIND_STREAM_SOCKET || path.join(runtimeDir, 'stream.sock'),
    'HIVERELAY_BLIND_STREAM_SOCKET'
  )
  if (unarySocketPath === streamSocketPath) throw new Error('blind unary and stream socket paths must be unequal')

  // Both development children necessarily run as the invoking local account.
  // Production uses the image-frozen unequal UIDs in docker-compose.blind.yml.
  const daemonUid = process.env.HIVERELAY_BLIND_DAEMON_UID == null
    ? localUid
    : requiredUnsignedEnvironment('HIVERELAY_BLIND_DAEMON_UID')
  const daemonGid = process.env.HIVERELAY_BLIND_DAEMON_GID == null
    ? localGid
    : requiredUnsignedEnvironment('HIVERELAY_BLIND_DAEMON_GID')
  const sharedGid = process.env.HIVERELAY_BLIND_SHARED_GID == null
    ? localGid
    : requiredUnsignedEnvironment('HIVERELAY_BLIND_SHARED_GID')
  if (daemonUid !== localUid || daemonGid !== localGid || sharedGid !== localGid) {
    throw new Error('local launcher UID/GID topology must match the invoking POSIX account; use packaged services for unequal production identities')
  }

  const env = {
    ...process.env,
    HIVERELAY_BLIND_RUNTIME_DIR: runtimeDir,
    HIVERELAY_BLIND_UNARY_SOCKET: unarySocketPath,
    HIVERELAY_BLIND_STREAM_SOCKET: streamSocketPath,
    HIVERELAY_BLIND_LAUNCH_TOPOLOGY_HASH: launchTopologyHash,
    HIVERELAY_BLIND_ENDPOINT_ID: String(endpointId),
    HIVERELAY_BLIND_ENDPOINT_IDS: String(endpointId),
    HIVERELAY_BLIND_EDGE_UID: String(localUid),
    HIVERELAY_BLIND_DAEMON_UID: String(daemonUid),
    HIVERELAY_BLIND_DAEMON_GID: String(daemonGid),
    HIVERELAY_BLIND_SHARED_GID: String(sharedGid)
  }

  const daemon = launch('packages/blind-daemon/cli.js', env)
  try {
    await waitForSockets(daemon, unarySocketPath, streamSocketPath)
  } catch (error) {
    process.stderr.write(`[blind-launcher] ${error.message}\n`)
    await close(1)
    return
  }
  const edge = launch('packages/blind-edge/cli.js', env)

  for (const child of [daemon, edge]) {
    child.once('exit', code => {
      if (!closing) close(code === 0 ? 1 : (code || 1))
    })
  }
  process.once('SIGINT', () => close(0))
  process.once('SIGTERM', () => close(0))
}

main().catch(error => {
  process.stderr.write(`[blind-launcher] ${error.message}\n`)
  close(1)
})
