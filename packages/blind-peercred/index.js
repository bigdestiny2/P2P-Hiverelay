import { createRequire } from 'node:module'
import path from 'node:path'

const require = createRequire(import.meta.url)
const native = require('./build/Release/blind_peercred.node')

function fileDescriptor (handle) {
  const fd = handle && handle.fd
  if (!Number.isInteger(fd) || fd < 0) {
    const error = new Error('open file handle has no native file descriptor')
    error.code = 'BLIND_FILE_LOCK_UNAVAILABLE'
    throw error
  }
  return fd
}

export function socketPeerCredentials (socket) {
  const fd = socket && socket._handle && socket._handle.fd
  if (!Number.isInteger(fd) || fd < 0) {
    const error = new Error('connected Unix socket has no readable native file descriptor')
    error.code = 'BLIND_PEERCRED_UNAVAILABLE'
    throw error
  }
  const credentials = native.getPeerCredentials(fd)
  if (!credentials || !Number.isSafeInteger(credentials.uid) || !Number.isSafeInteger(credentials.gid) ||
      !Number.isSafeInteger(credentials.pid)) {
    const error = new Error('native peer credentials are malformed')
    error.code = 'BLIND_PEERCRED_INVALID'
    throw error
  }
  return Object.freeze({ pid: credentials.pid, uid: credentials.uid, gid: credentials.gid })
}

export function tryExclusiveFileLock (handle) {
  const acquired = native.tryExclusiveFileLock(fileDescriptor(handle))
  if (typeof acquired !== 'boolean') {
    const error = new Error('native file-lock result is malformed')
    error.code = 'BLIND_FILE_LOCK_INVALID'
    throw error
  }
  return acquired
}

export function releaseExclusiveFileLock (handle) {
  native.releaseExclusiveFileLock(fileDescriptor(handle))
}

function canonicalAbsolutePath (value, field) {
  if (typeof value !== 'string' || value.includes('\0') || !path.isAbsolute(value) || path.normalize(value) !== value) {
    throw new TypeError(`${field} must be a canonical absolute NUL-free path`)
  }
  return value
}

// Atomically move a fully fsynced same-filesystem temporary file into its final
// name without replacing anything already present there. A false result is the
// only non-error outcome when the destination already exists.
export function renameFileNoReplace (source, destination) {
  source = canonicalAbsolutePath(source, 'source')
  destination = canonicalAbsolutePath(destination, 'destination')
  const installed = native.renameFileNoReplace(source, destination)
  if (typeof installed !== 'boolean') {
    const error = new Error('native no-replace rename result is malformed')
    error.code = 'BLIND_RENAME_NOREPLACE_INVALID'
    throw error
  }
  return installed
}

export function renameFileNoReplacePlatformSupported () {
  const supported = native.renameFileNoReplacePlatformSupported()
  if (typeof supported !== 'boolean') {
    const error = new Error('native no-replace platform-support result is malformed')
    error.code = 'BLIND_RENAME_NOREPLACE_INVALID'
    throw error
  }
  return supported
}
