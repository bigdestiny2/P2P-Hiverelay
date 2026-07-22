import { constants as FS_CONSTANTS } from 'node:fs'
import fs from 'node:fs/promises'
import path from 'node:path'
import { createHash } from 'node:crypto'

const MAX_ADMISSION_ADAPTER_BYTES = 256 * 1024

export const PRODUCTION_RUNTIME_PROFILE = Object.freeze({
  DESCRIBE_ONLY_V1: 'DESCRIBE_ONLY_V1',
  CELL_V1: 'CELL_V1',
  CELL_INBOX_V1: 'CELL_INBOX_V1',
  CELL_INBOX_CORE_V1: 'CELL_INBOX_CORE_V1'
})

function entrypointFailure (code, message, cause = null) {
  const error = new Error(message, cause == null ? undefined : { cause })
  error.code = code
  throw error
}

function optionalEnvironment (environment, name) {
  const value = environment[name]
  if (value == null || value === '') return null
  if (typeof value !== 'string') {
    entrypointFailure('BLIND_ENTRYPOINT_CONFIG_INVALID', `${name} must be a string`)
  }
  return value
}

function canonicalAbsolutePath (value, name) {
  if (value == null || !path.isAbsolute(value) || value.includes('\0') || path.normalize(value) !== value) {
    entrypointFailure('BLIND_ENTRYPOINT_CONFIG_INVALID', `${name} must be one canonical absolute path`)
  }
  return value
}

function sha256Hex (value, name) {
  if (value == null || !/^[0-9a-f]{64}$/.test(value)) {
    entrypointFailure('BLIND_ENTRYPOINT_CONFIG_INVALID', `${name} must be one canonical lowercase SHA-256 digest`)
  }
  return value
}

function profileFlags (profile) {
  switch (profile) {
    case PRODUCTION_RUNTIME_PROFILE.DESCRIBE_ONLY_V1:
      return { enableCellRuntime: false, enableInboxRuntime: false, enableCoreRuntime: false }
    case PRODUCTION_RUNTIME_PROFILE.CELL_V1:
      return { enableCellRuntime: true, enableInboxRuntime: false, enableCoreRuntime: false }
    case PRODUCTION_RUNTIME_PROFILE.CELL_INBOX_V1:
      return { enableCellRuntime: true, enableInboxRuntime: true, enableCoreRuntime: false }
    case PRODUCTION_RUNTIME_PROFILE.CELL_INBOX_CORE_V1:
      return { enableCellRuntime: true, enableInboxRuntime: true, enableCoreRuntime: true }
    default:
      entrypointFailure('BLIND_ENTRYPOINT_CONFIG_INVALID',
        'HIVERELAY_BLIND_RUNTIME_PROFILE must select one exact supported production runtime profile')
  }
}

export function loadProductionEntrypointConfig (environment = process.env, options = {}) {
  const profile = optionalEnvironment(environment, 'HIVERELAY_BLIND_RUNTIME_PROFILE')
  const flags = profileFlags(profile)
  const modulePath = optionalEnvironment(environment, 'HIVERELAY_BLIND_ADMISSION_ADAPTER_MODULE')
  const moduleSha256 = optionalEnvironment(environment, 'HIVERELAY_BLIND_ADMISSION_ADAPTER_SHA256')

  if (!flags.enableCellRuntime) {
    if (modulePath != null || moduleSha256 != null) {
      entrypointFailure('BLIND_ENTRYPOINT_CONFIG_INVALID',
        'DESCRIBE_ONLY_V1 forbids admission adapter configuration')
    }
    return Object.freeze({ profile, ...flags, admissionAdapter: null })
  }

  if (options.allowInjectedAdmissionAdapter === true && modulePath == null && moduleSha256 == null) {
    return Object.freeze({ profile, ...flags, admissionAdapter: null })
  }
  if (modulePath == null || moduleSha256 == null) {
    entrypointFailure('BLIND_ENTRYPOINT_CONFIG_INVALID',
      'CELL runtime profiles require both an admission adapter module and its exact SHA-256 digest')
  }
  return Object.freeze({
    profile,
    ...flags,
    admissionAdapter: Object.freeze({
      modulePath: canonicalAbsolutePath(modulePath, 'HIVERELAY_BLIND_ADMISSION_ADAPTER_MODULE'),
      moduleSha256: sha256Hex(moduleSha256, 'HIVERELAY_BLIND_ADMISSION_ADAPTER_SHA256')
    })
  })
}

function sameInode (left, right) {
  return left.dev === right.dev && left.ino === right.ino
}

function sameFileState (left, right) {
  return sameInode(left, right) && left.size === right.size && left.mode === right.mode &&
    left.uid === right.uid && left.gid === right.gid && left.nlink === right.nlink &&
    left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs
}

async function readProtectedModule (file, expectedSha256, identity) {
  let handle
  try {
    handle = await fs.open(file, FS_CONSTANTS.O_RDONLY | FS_CONSTANTS.O_NOFOLLOW)
    const [opened, linked] = await Promise.all([handle.stat(), fs.lstat(file)])
    const currentUid = typeof identity?.getuid === 'function' ? identity.getuid() : null
    if (!opened.isFile() || linked.isSymbolicLink() || !sameInode(opened, linked) || opened.size < 1 ||
        opened.size > MAX_ADMISSION_ADAPTER_BYTES || linked.nlink !== 1 || (linked.mode & 0o022) !== 0 ||
        currentUid == null || (linked.uid !== currentUid && linked.uid !== 0) || await fs.realpath(file) !== file) {
      entrypointFailure('BLIND_ADMISSION_ADAPTER_MODULE_INVALID',
        'admission adapter must be a stable root- or daemon-owned protected regular file')
    }
    const bytes = await handle.readFile()
    const [after, linkedAfter] = await Promise.all([handle.stat(), fs.lstat(file)])
    if (!sameFileState(opened, after) || !sameFileState(after, linkedAfter) ||
        bytes.byteLength !== opened.size || await fs.realpath(file) !== file) {
      entrypointFailure('BLIND_ADMISSION_ADAPTER_MODULE_INVALID',
        'admission adapter module changed while it was read')
    }
    const actualSha256 = createHash('sha256').update(bytes).digest('hex')
    if (actualSha256 !== expectedSha256) {
      entrypointFailure('BLIND_ADMISSION_ADAPTER_DIGEST_MISMATCH',
        'admission adapter module does not match its exact configured SHA-256 digest')
    }
    return bytes
  } catch (error) {
    if (typeof error?.code === 'string' && error.code.startsWith('BLIND_')) throw error
    entrypointFailure('BLIND_ADMISSION_ADAPTER_MODULE_INVALID',
      'admission adapter module could not be opened as a protected file', error)
  } finally {
    if (handle) await handle.close().catch(() => {})
  }
}

function adapterContext (config, bootstrap) {
  if (!bootstrap || !bootstrap.launchTopologyHash || !Array.isArray(bootstrap.endpointIds)) {
    throw new TypeError('validated daemon bootstrap configuration is required for the admission adapter')
  }
  return Object.freeze({
    runtimeProfile: config.profile,
    launchTopologyHash: Buffer.from(bootstrap.launchTopologyHash),
    endpointIds: Object.freeze([...bootstrap.endpointIds])
  })
}

export async function loadProductionAdmissionAdapter (config, bootstrap, options = {}) {
  if (!config || config.enableCellRuntime !== true || !config.admissionAdapter) {
    throw new TypeError('an explicit CELL production entrypoint configuration is required')
  }
  const bytes = await readProtectedModule(config.admissionAdapter.modulePath,
    config.admissionAdapter.moduleSha256, options.identity || process)
  let loaded
  try {
    const source = `data:text/javascript;base64,${bytes.toString('base64')}#sha256=${config.admissionAdapter.moduleSha256}`
    loaded = await import(source)
  } catch (error) {
    entrypointFailure('BLIND_ADMISSION_ADAPTER_MODULE_INVALID',
      'admission adapter module did not load as one self-contained ES module', error)
  }
  const factory = loaded.createAdmissionAdapterResolver
  if (typeof factory !== 'function') {
    entrypointFailure('BLIND_ADMISSION_ADAPTER_EXPORT_INVALID',
      'admission adapter module must export createAdmissionAdapterResolver')
  }
  let resolver
  try {
    resolver = await factory(adapterContext(config, bootstrap))
  } catch (error) {
    entrypointFailure('BLIND_ADMISSION_ADAPTER_INITIALIZATION_FAILED',
      'admission adapter resolver initialization failed', error)
  }
  if (typeof resolver !== 'function') {
    entrypointFailure('BLIND_ADMISSION_ADAPTER_EXPORT_INVALID',
      'createAdmissionAdapterResolver must return one resolver function')
  }
  return Object.freeze({
    modulePath: config.admissionAdapter.modulePath,
    moduleSha256: config.admissionAdapter.moduleSha256,
    resolveAdmissionAdapter: input => resolver(input)
  })
}
