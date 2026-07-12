import fs from 'node:fs'
import path from 'node:path'
import tls from 'node:tls'

const runtimeDir = process.env.HIVERELAY_BLIND_RUNTIME_DIR || '/run/hiverelay-blind'
const unarySocketPath = process.env.HIVERELAY_BLIND_UNARY_SOCKET || `${runtimeDir}/unary.sock`
const streamSocketPath = process.env.HIVERELAY_BLIND_STREAM_SOCKET || `${runtimeDir}/stream.sock`
const daemonUid = unsignedEnvironment('HIVERELAY_BLIND_DAEMON_UID')
const daemonGid = unsignedEnvironment('HIVERELAY_BLIND_DAEMON_GID')
const sharedGid = unsignedEnvironment('HIVERELAY_BLIND_SHARED_GID')
const port = Number(process.env.HIVERELAY_BLIND_PORT || 9100)

function fail (message) {
  process.stderr.write(`[blind-edge-health] ${message}\n`)
  process.exit(1)
}

function unsignedEnvironment (name) {
  const raw = process.env[name]
  if (typeof raw !== 'string' || !/^(0|[1-9][0-9]*)$/.test(raw)) fail(`${name} is not an unsigned integer`)
  const value = Number(raw)
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) fail(`${name} is outside u32`)
  return value
}

function procField (name) {
  const match = fs.readFileSync('/proc/1/status', 'utf8').match(new RegExp(`^${name}:\\s+(.+)$`, 'm'))
  if (!match) fail(`/proc/1/status has no ${name}`)
  return match[1].trim()
}

function canonicalSocket (socketPath, label) {
  if (!path.isAbsolute(socketPath) || path.normalize(socketPath) !== socketPath) fail(`${label} path is not canonical and absolute`)
  let resolved
  let socket
  try {
    resolved = fs.realpathSync(socketPath)
    socket = fs.lstatSync(socketPath)
  } catch (error) {
    fail(`${label} socket is unavailable: ${error.message}`)
  }
  if (resolved !== socketPath || socket.isSymbolicLink() || !socket.isSocket()) fail(`${label} path is not one exact non-symlink Unix socket`)
  if (socket.uid !== daemonUid || socket.gid !== sharedGid || (socket.mode & 0o777) !== 0o660) {
    fail(`${label} socket must match daemon UID, shared GID, and mode 0660`)
  }
  return socket
}

if (procField('CapEff') !== '0000000000000000') fail('edge CapEff is not zero')
if (procField('Uid').split(/\s+/)[1] !== '998') fail('edge effective UID is not 998')
if (procField('Gid').split(/\s+/)[1] !== '997') fail('edge effective GID is not 997')
if (daemonUid === 998) fail('edge and daemon UIDs must be unequal')
if (daemonGid !== sharedGid) fail('daemon effective GID must equal the signed shared GID in this image topology')
if (unarySocketPath === streamSocketPath) fail('unary and stream socket paths must be unequal')

const directory = fs.statSync(runtimeDir)
if (!directory.isDirectory()) fail('runtime path is not a directory')
if (directory.uid !== daemonUid || directory.gid !== daemonGid || (directory.mode & 0o777) !== 0o750) {
  fail('runtime directory does not match the signed daemon identity and mode 0750')
}
const unarySocket = canonicalSocket(unarySocketPath, 'unary')
const streamSocket = canonicalSocket(streamSocketPath, 'stream')
if (unarySocket.dev === streamSocket.dev && unarySocket.ino === streamSocket.ino) fail('unary and stream paths resolve to one inode')
try {
  fs.accessSync(runtimeDir, fs.constants.W_OK)
  fail('edge unexpectedly has write access to the runtime directory')
} catch (error) {
  if (error && error.code !== 'EACCES' && error.code !== 'EROFS') throw error
}

await new Promise((resolve, reject) => {
  const client = tls.connect({ host: '127.0.0.1', port, rejectUnauthorized: false })
  const timer = setTimeout(() => {
    client.destroy()
    reject(new Error('public TLS listener connection timed out'))
  }, 1000)
  client.once('secureConnect', () => {
    clearTimeout(timer)
    client.destroy()
    resolve()
  })
  client.once('error', error => {
    clearTimeout(timer)
    reject(error)
  })
}).catch(error => fail(error.message))
