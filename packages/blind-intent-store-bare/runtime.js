import fs from 'bare-fs'
import posix from 'bare-posix'
import selectNativeFlags from './native/targets.cjs'

const native = selectNativeFlags(Bare.platform, Bare.arch, Bare.version)

function failure (message) {
  return Object.assign(new Error(message), { code: 'INTENT_STORE_PLATFORM' })
}

// Verify the selected artifact too; never borrow another target's flags.
if (Bare.platform !== native.platform || Bare.arch !== native.arch || Bare.version !== 'v1.31.0') {
  throw failure('intent backend requires its qualified Bare v1.31.0 native flag target')
}
for (const name of ['O_RDONLY', 'O_WRONLY', 'O_RDWR', 'O_CREAT', 'O_EXCL', 'O_NOFOLLOW', 'O_DIRECTORY', 'O_NONBLOCK']) {
  const value = native.constants[name]
  if (!Number.isSafeInteger(value) || value < 0 || (name !== 'O_RDONLY' && value === 0)) throw failure('required native open flag unavailable: ' + name)
  if (fs.constants[name] !== undefined && fs.constants[name] !== value) throw failure('Bare and native open flags disagree: ' + name)
}

export const constants = Object.freeze({ ...native.constants })
export const BARE_INTENT_BACKEND_RUNTIME = Object.freeze({
  runtime: Bare.version,
  platform: Bare.platform,
  arch: Bare.arch,
  flagsSourceSha256: native.sourceSha256,
  flagsProbeSha256: native.probeSha256
})
export const getuid = () => posix.getuid()

export function exactStat (stat) {
  // bare-fs represents stat fields as Numbers. Reject rounded identities/sizes.
  for (const name of ['dev', 'ino', 'uid', 'mode', 'nlink', 'size']) {
    if (!Number.isSafeInteger(stat[name]) || stat[name] < 0) {
      throw Object.assign(new Error('intent stat field is not an exact nonnegative integer: ' + name), { code: 'INTENT_STORE_CUSTODY' })
    }
  }
  return stat
}

export async function writeAll (handle, bytes) {
  let offset = 0
  while (offset < bytes.length) {
    const { bytesWritten } = await handle.write(bytes, offset, bytes.length - offset, offset)
    if (!Number.isSafeInteger(bytesWritten) || bytesWritten <= 0 || bytesWritten > bytes.length - offset) {
      throw Object.assign(new Error('intent write made invalid or no progress'), { code: 'EIO' })
    }
    offset += bytesWritten
  }
}

class FileHandle {
  constructor (handle) {
    this._handle = handle
    this._closePromise = null
  }

  async stat () { return exactStat(await this._handle.stat()) }
  async sync () { return this._handle.sync() }
  async write (buffer, offset, length, position) { return this._handle.write(buffer, offset, length, position) }
  async read (buffer, offset, length, position) {
    const result = await this._handle.read(buffer, offset, length, position)
    if (!Number.isSafeInteger(result.bytesRead) || result.bytesRead < 0 || result.bytesRead > length) {
      throw Object.assign(new Error('intent read returned an invalid byte count'), { code: 'EIO' })
    }
    return result
  }

  close () {
    // Do not retry a possibly completed native close on a reused descriptor.
    if (!this._closePromise) this._closePromise = this._handle.close()
    return this._closePromise
  }
}

export const openSync = (...args) => fs.openSync(...args)
export const closeSync = fd => fs.closeSync(fd)
export const fstatSync = fd => exactStat(fs.fstatSync(fd))
export const fsyncSync = fd => fs.fsyncSync(fd)
export const lstat = async path => exactStat(await fs.promises.lstat(path))
export const mkdir = (...args) => fs.promises.mkdir(...args)
export const rename = (...args) => fs.promises.rename(...args)
export const unlink = (...args) => fs.promises.unlink(...args)
export const open = async (...args) => new FileHandle(await fs.promises.open(...args))
export const opendir = (...args) => fs.promises.opendir(...args)
