import { createHash } from 'node:crypto'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import test from 'brittle'
import {
  PRODUCTION_ADMISSION_ADAPTER_SCRIPT_CONTRACT,
  PRODUCTION_RUNTIME_PROFILE,
  loadProductionAdmissionAdapter,
  loadProductionEntrypointConfig
} from '../production-entrypoint.js'

const SCHEMA = PRODUCTION_ADMISSION_ADAPTER_SCRIPT_CONTRACT.schema

function entrypointEnvironment (profile, overrides = {}) {
  return {
    HIVERELAY_BLIND_RUNTIME_PROFILE: profile,
    ...overrides
  }
}

function captureFailure (fn) {
  try {
    fn()
    return null
  } catch (error) {
    return error
  }
}

async function captureRejection (promise) {
  try {
    await promise
    return null
  } catch (error) {
    return error
  }
}

async function scratch (t) {
  const created = await fs.mkdtemp(path.join(os.tmpdir(), 'blind-entrypoint-'))
  const directory = await fs.realpath(created)
  t.teardown(async () => fs.rm(created, { recursive: true, force: true }))
  return directory
}

async function writeProtected (directory, name, source) {
  const file = path.join(directory, name)
  const bytes = Buffer.isBuffer(source) ? source : Buffer.from(source)
  await fs.writeFile(file, bytes, { mode: 0o400 })
  await fs.chmod(file, 0o400)
  return { file, bytes, digest: createHash('sha256').update(bytes).digest('hex') }
}

function cellConfig (record, overrides = {}) {
  return loadProductionEntrypointConfig(entrypointEnvironment(PRODUCTION_RUNTIME_PROFILE.CELL_V1, {
    HIVERELAY_BLIND_ADMISSION_ADAPTER_SCRIPT_FILE: record.file,
    HIVERELAY_BLIND_ADMISSION_ADAPTER_SCRIPT_SHA256: record.digest,
    ...overrides
  }))
}

function bootstrap () {
  return {
    launchTopologyHash: Buffer.alloc(32, 0x42),
    endpointIds: [2, 4]
  }
}

function validScript () {
  return `
({
  schema: '${SCHEMA}',
  createAdmissionAdapterResolver (context) {
    if (Object.getPrototypeOf(context) !== null || !Object.isFrozen(context) ||
        !Object.isFrozen(context.endpointIds) || !Object.isFrozen(context.launchTopologyHash) ||
        context.constructor !== undefined || context.launchTopologyHash.$hiverelayType !== 'bytes' ||
        context.launchTopologyHash.hex !== '${'42'.repeat(32)}') {
      throw new Error('runtime context is not one frozen sandbox-realm record')
    }
    const live = new WeakSet()
    const proof = input => ({
      spendTag: input.admission.token,
      requestCommitment: input.requestCommitment,
      costClass: input.costClass,
      walCommitRecord: input.admission.token,
      profileId: input.admission.profileId,
      schemeId: input.admission.schemeId,
      parameterHash: input.admission.parameterHash
    })
    return function resolve (input) {
      if (!Object.isFrozen(input) || Object.getPrototypeOf(input) !== null ||
          input.profileId !== 7 || input.endpointId !== 2) return null
      return Object.freeze({
        prepare (input) { return proof(input) },
        preparePreflight () {
          const capability = Object.freeze({})
          live.add(capability)
          return capability
        },
        confirmAfterEof (input) {
          if (!live.has(input.adapterPreflight)) throw new Error('unknown preflight')
          live.delete(input.adapterPreflight)
          return proof(input)
        }
      })
    }
  }
})
`
}

function resolveInput () {
  return {
    profileId: 7,
    schemeId: 9,
    parameterHash: Buffer.alloc(32, 0x51),
    descriptor: { descriptorSequence: 1n },
    parameters: { tokenMaxBytes: 1024 },
    endpointId: 2,
    endpointRoleBits: 7,
    signal: null
  }
}

function admissionInput (adapterPreflight = null) {
  return {
    admission: {
      profileId: 7,
      schemeId: 9,
      parameterHash: Buffer.alloc(32, 0x51),
      token: Buffer.alloc(32, 0x52)
    },
    costClass: { resourceClass: 1, leaseClass: 2, costUnits: 3n },
    requestCommitment: Buffer.alloc(32, 0x53),
    adapterPreflight,
    signal: null
  }
}

test('production entrypoint selects only explicit script-backed fail-closed profiles', t => {
  for (const environment of [{}, entrypointEnvironment('CELL_V2')]) {
    const error = captureFailure(() => loadProductionEntrypointConfig(environment))
    t.is(error?.code, 'BLIND_ENTRYPOINT_CONFIG_INVALID')
  }

  const profiles = [
    [PRODUCTION_RUNTIME_PROFILE.DESCRIBE_ONLY_V1, false, false, false],
    [PRODUCTION_RUNTIME_PROFILE.CELL_V1, true, false, false],
    [PRODUCTION_RUNTIME_PROFILE.CELL_INBOX_V1, true, true, false],
    [PRODUCTION_RUNTIME_PROFILE.CELL_INBOX_CORE_V1, true, true, true]
  ]
  for (const [profile, cell, inbox, core] of profiles) {
    const config = loadProductionEntrypointConfig(entrypointEnvironment(profile), {
      allowInjectedAdmissionAdapter: true
    })
    t.is(config.profile, profile)
    t.is(config.enableCellRuntime, cell)
    t.is(config.enableInboxRuntime, inbox)
    t.is(config.enableCoreRuntime, core)
    t.is(Object.isFrozen(config), true)
  }

  for (const legacy of [
    { HIVERELAY_BLIND_ADMISSION_ADAPTER_MODULE: '/adapter.mjs' },
    { HIVERELAY_BLIND_ADMISSION_ADAPTER_SHA256: 'aa'.repeat(32) }
  ]) {
    const error = captureFailure(() => loadProductionEntrypointConfig(entrypointEnvironment(
      PRODUCTION_RUNTIME_PROFILE.DESCRIBE_ONLY_V1, legacy
    )))
    t.is(error?.code, 'BLIND_ENTRYPOINT_CONFIG_INVALID')
  }

  const describeWithScript = captureFailure(() => loadProductionEntrypointConfig(entrypointEnvironment(
    PRODUCTION_RUNTIME_PROFILE.DESCRIBE_ONLY_V1,
    { HIVERELAY_BLIND_ADMISSION_ADAPTER_SCRIPT_FILE: '/adapter.js' }
  )))
  t.is(describeWithScript?.code, 'BLIND_ENTRYPOINT_CONFIG_INVALID')

  const missingScript = captureFailure(() => loadProductionEntrypointConfig(entrypointEnvironment(
    PRODUCTION_RUNTIME_PROFILE.CELL_V1
  )))
  t.is(missingScript?.code, 'BLIND_ENTRYPOINT_CONFIG_INVALID')

  const uppercaseDigest = captureFailure(() => loadProductionEntrypointConfig(entrypointEnvironment(
    PRODUCTION_RUNTIME_PROFILE.CELL_V1,
    {
      HIVERELAY_BLIND_ADMISSION_ADAPTER_SCRIPT_FILE: '/adapter.js',
      HIVERELAY_BLIND_ADMISSION_ADAPTER_SCRIPT_SHA256: 'AA'.repeat(32)
    }
  )))
  t.is(uppercaseDigest?.code, 'BLIND_ENTRYPOINT_CONFIG_INVALID')

  const noncanonicalPath = captureFailure(() => loadProductionEntrypointConfig(entrypointEnvironment(
    PRODUCTION_RUNTIME_PROFILE.CELL_V1,
    {
      HIVERELAY_BLIND_ADMISSION_ADAPTER_SCRIPT_FILE: '/opt/../adapter.js',
      HIVERELAY_BLIND_ADMISSION_ADAPTER_SCRIPT_SHA256: 'aa'.repeat(32)
    }
  )))
  t.is(noncanonicalPath?.code, 'BLIND_ENTRYPOINT_CONFIG_INVALID')
})

test('script bridge uses only frozen sandbox data and maps opaque preflight capabilities', async t => {
  const directory = await scratch(t)
  const record = await writeProtected(directory, 'adapter.js', validScript())
  const loaded = await loadProductionAdmissionAdapter(cellConfig(record), bootstrap())
  t.is(loaded.scriptFile, record.file)
  t.is(loaded.scriptSha256, record.digest)
  t.is(Object.isFrozen(loaded), true)

  const adapter = loaded.resolveAdmissionAdapter(resolveInput())
  t.is(Object.isFrozen(adapter), true)
  const prepared = adapter.prepare(admissionInput())
  t.alike(prepared.spendTag, Buffer.alloc(32, 0x52))
  t.alike(prepared.requestCommitment, Buffer.alloc(32, 0x53))
  t.is(prepared.costClass.costUnits, 3n)

  const capability = adapter.preparePreflight(admissionInput())
  t.is(Object.isFrozen(capability), true)
  t.alike(Reflect.ownKeys(capability), [])
  const confirmed = adapter.confirmAfterEof(admissionInput(capability))
  t.alike(confirmed.parameterHash, Buffer.alloc(32, 0x51))
  const reuse = captureFailure(() => adapter.confirmAfterEof(admissionInput(capability)))
  t.is(reuse?.code, 'BLIND_ADMISSION_ADAPTER_EXECUTION_FAILED')
  adapter.preparePreflight(admissionInput())
  const afterAbandon = adapter.preparePreflight(admissionInput())
  t.alike(adapter.confirmAfterEof(admissionInput(afterAbandon)).profileId, 7)

  const replacement = await writeProtected(directory, 'adapter-replacement.js',
    'this is no longer the verified script')
  await fs.rename(replacement.file, record.file)
  const retained = loaded.resolveAdmissionAdapter(resolveInput())
  t.is(typeof retained.prepare, 'function')
  const freshLoad = await captureRejection(loadProductionAdmissionAdapter(cellConfig(record), bootstrap()))
  t.is(freshLoad?.code, 'BLIND_ADMISSION_ADAPTER_DIGEST_MISMATCH')
})

test('script loader rejects imports, host authorities and constructor escapes', async t => {
  const directory = await scratch(t)
  const forbidden = [
    "import value from 'node:fs'\n({})",
    `({ schema: '${SCHEMA}', createAdmissionAdapterResolver () { import('node:fs'); return () => null } })`,
    `({ schema: '${SCHEMA}', createAdmissionAdapterResolver () { import('file:///tmp/x.js'); return () => null } })`,
    `({ schema: '${SCHEMA}', createAdmissionAdapterResolver () { import('left-pad'); return () => null } })`,
    `({ schema: '${SCHEMA}', createAdmissionAdapterResolver () { return process } })`,
    `({ schema: '${SCHEMA}', createAdmissionAdapterResolver () { return require } })`,
    `({ schema: '${SCHEMA}', createAdmissionAdapterResolver () { return module } })`,
    `({ schema: '${SCHEMA}', createAdmissionAdapterResolver () { return global } })`,
    `({ schema: '${SCHEMA}', createAdmissionAdapterResolver () { return Buffer } })`
  ]
  for (let index = 0; index < forbidden.length; index++) {
    const record = await writeProtected(directory, `forbidden-${index}.js`, forbidden[index])
    const error = await captureRejection(loadProductionAdmissionAdapter(cellConfig(record), bootstrap()))
    t.is(error?.code, 'BLIND_ADMISSION_ADAPTER_SCRIPT_INVALID')
  }

  const escapes = [
    `({ schema: '${SCHEMA}', createAdmissionAdapterResolver (context) {
      context.constructor.constructor('return pro' + 'cess')(); return () => null
    } })`,
    `({ schema: '${SCHEMA}', createAdmissionAdapterResolver (context) {
      context.runtimeProfile.constructor.constructor('return pro' + 'cess')(); return () => null
    } })`,
    `({ schema: '${SCHEMA}', createAdmissionAdapterResolver () {
      ({}).constructor.constructor('return 7')(); return () => null
    } })`,
    `({ schema: '${SCHEMA}', createAdmissionAdapterResolver () {
      new WebAssembly.Module(new Uint8Array()); return () => null
    } })`
  ]
  for (let index = 0; index < escapes.length; index++) {
    const record = await writeProtected(directory, `escape-${index}.js`, escapes[index])
    const error = await captureRejection(loadProductionAdmissionAdapter(cellConfig(record), bootstrap()))
    t.is(error?.code, 'BLIND_ADMISSION_ADAPTER_INITIALIZATION_FAILED')
  }
})

test('script loader rejects malformed, unsafe, linked and asynchronous contracts', async t => {
  const directory = await scratch(t)
  const malformed = [
    [Buffer.from([0xff, 0xfe, 0xfd]), 'BLIND_ADMISSION_ADAPTER_SCRIPT_INVALID'],
    ['({', 'BLIND_ADMISSION_ADAPTER_SCRIPT_INVALID'],
    ['({ schema: \'wrong\', createAdmissionAdapterResolver () { return () => null } })',
      'BLIND_ADMISSION_ADAPTER_EXPORT_INVALID'],
    [`({ schema: '${SCHEMA}', createAdmissionAdapterResolver: true })`,
      'BLIND_ADMISSION_ADAPTER_EXPORT_INVALID'],
    [`(() => {
      const contract = { schema: '${SCHEMA}', createAdmissionAdapterResolver () { return () => null } }
      Object.defineProperty(contract, 'hidden', { value: true })
      return contract
    })()`, 'BLIND_ADMISSION_ADAPTER_EXPORT_INVALID'],
    [`(() => {
      const contract = { schema: '${SCHEMA}', createAdmissionAdapterResolver () { return () => null } }
      Object.defineProperty(contract, 'schema', { enumerable: false })
      return contract
    })()`, 'BLIND_ADMISSION_ADAPTER_EXPORT_INVALID'],
    [`({ schema: '${SCHEMA}', async createAdmissionAdapterResolver () { return () => null } })`,
      'BLIND_ADMISSION_ADAPTER_INITIALIZATION_FAILED'],
    [`({ schema: '${SCHEMA}', createAdmissionAdapterResolver () { while (true) {} } })`,
      'BLIND_ADMISSION_ADAPTER_INITIALIZATION_FAILED'],
    [`({ schema: '${SCHEMA}', createAdmissionAdapterResolver () { return async () => null } })`,
      'BLIND_ADMISSION_ADAPTER_RESOLUTION_FAILED'],
    [`({ schema: '${SCHEMA}', createAdmissionAdapterResolver () {
      return () => {
        const adapter = Object.freeze({
          prepare () {}, preparePreflight () {}, confirmAfterEof () {}, hidden: true
        })
        return adapter
      }
    } })`, 'BLIND_ADMISSION_ADAPTER_RESOLUTION_FAILED']
  ]
  for (let index = 0; index < malformed.length; index++) {
    const [source, expected] = malformed[index]
    const record = await writeProtected(directory, `malformed-${index}.js`, source)
    const load = loadProductionAdmissionAdapter(cellConfig(record), bootstrap())
    const error = expected === 'BLIND_ADMISSION_ADAPTER_RESOLUTION_FAILED'
      ? await captureRejection(load.then(loaded => loaded.resolveAdmissionAdapter(resolveInput())))
      : await captureRejection(load)
    t.is(error?.code, expected)
  }

  const valid = await writeProtected(directory, 'valid.js', validScript())
  const wrongDigest = cellConfig(valid, {
    HIVERELAY_BLIND_ADMISSION_ADAPTER_SCRIPT_SHA256: '00'.repeat(32)
  })
  const digestError = await captureRejection(loadProductionAdmissionAdapter(wrongDigest, bootstrap()))
  t.is(digestError?.code, 'BLIND_ADMISSION_ADAPTER_DIGEST_MISMATCH')

  const symlink = path.join(directory, 'adapter-link.js')
  await fs.symlink(valid.file, symlink)
  const symlinkError = await captureRejection(loadProductionAdmissionAdapter(cellConfig({
    ...valid,
    file: symlink
  }), bootstrap()))
  t.is(symlinkError?.code, 'BLIND_ADMISSION_ADAPTER_SCRIPT_INVALID')

  const hardlink = path.join(directory, 'adapter-hardlink.js')
  await fs.link(valid.file, hardlink)
  const hardlinkError = await captureRejection(loadProductionAdmissionAdapter(cellConfig(valid), bootstrap()))
  t.is(hardlinkError?.code, 'BLIND_ADMISSION_ADAPTER_SCRIPT_INVALID')
  await fs.unlink(hardlink)

  await fs.chmod(valid.file, 0o622)
  const modeError = await captureRejection(loadProductionAdmissionAdapter(cellConfig(valid), bootstrap()))
  t.is(modeError?.code, 'BLIND_ADMISSION_ADAPTER_SCRIPT_INVALID')
})

test('host serialization rejects accessors without invoking them and methods reject thenables', async t => {
  const directory = await scratch(t)
  const record = await writeProtected(directory, 'adapter.js', validScript())
  const loaded = await loadProductionAdmissionAdapter(cellConfig(record), bootstrap())
  let getterCalls = 0
  const input = resolveInput()
  Object.defineProperty(input, 'profileId', {
    enumerable: true,
    get () {
      getterCalls++
      return 7
    }
  })
  const getterError = captureFailure(() => loaded.resolveAdmissionAdapter(input))
  t.is(getterError?.code, 'BLIND_ADMISSION_ADAPTER_BRIDGE_INVALID')
  t.is(getterCalls, 0)

  let proxyCalls = 0
  const proxied = new Proxy(resolveInput(), {
    getOwnPropertyDescriptor () {
      proxyCalls++
      throw new Error('proxy trap must not run')
    }
  })
  const proxyError = captureFailure(() => loaded.resolveAdmissionAdapter(proxied))
  t.is(proxyError?.code, 'BLIND_ADMISSION_ADAPTER_BRIDGE_INVALID')
  t.is(proxyCalls, 0)

  let abortedGetterCalls = 0
  const fakeSignal = {}
  Object.defineProperty(fakeSignal, 'aborted', {
    get () {
      abortedGetterCalls++
      return false
    }
  })
  const fakeSignalInput = resolveInput()
  fakeSignalInput.signal = fakeSignal
  const signalError = captureFailure(() => loaded.resolveAdmissionAdapter(fakeSignalInput))
  t.ok(signalError instanceof TypeError)
  t.is(abortedGetterCalls, 0)

  let signalProxyCalls = 0
  const proxySignalInput = resolveInput()
  proxySignalInput.signal = new Proxy(new AbortController().signal, {
    getPrototypeOf () {
      signalProxyCalls++
      throw new Error('signal proxy trap must not run')
    }
  })
  const proxySignalError = captureFailure(() => loaded.resolveAdmissionAdapter(proxySignalInput))
  t.ok(proxySignalError instanceof TypeError)
  t.is(signalProxyCalls, 0)

  let byteGetterCalls = 0
  const accessorBytes = Buffer.alloc(32, 0x51)
  for (const key of ['toString', 'buffer', 'byteOffset', 'byteLength']) {
    Object.defineProperty(accessorBytes, key, {
      get () {
        byteGetterCalls++
        throw new Error('byte accessor must not run')
      }
    })
  }
  const accessorBytesInput = resolveInput()
  accessorBytesInput.parameterHash = accessorBytes
  t.is(typeof loaded.resolveAdmissionAdapter(accessorBytesInput).prepare, 'function')
  t.is(byteGetterCalls, 0)

  const sharedBytesInput = resolveInput()
  sharedBytesInput.parameterHash = new Uint8Array(new SharedArrayBuffer(32))
  const sharedBytesError = captureFailure(() => loaded.resolveAdmissionAdapter(sharedBytesInput))
  t.is(sharedBytesError?.code, 'BLIND_ADMISSION_ADAPTER_BRIDGE_INVALID')

  const liveSignalInput = resolveInput()
  liveSignalInput.signal = new AbortController().signal
  t.is(typeof loaded.resolveAdmissionAdapter(liveSignalInput).prepare, 'function')

  const asyncMethod = await writeProtected(directory, 'async-method.js', `
({
  schema: '${SCHEMA}',
  createAdmissionAdapterResolver () {
    return () => Object.freeze({
      async prepare () { return null },
      preparePreflight () { return Object.freeze({}) },
      confirmAfterEof () { return null }
    })
  }
})
`)
  const asyncLoaded = await loadProductionAdmissionAdapter(cellConfig(asyncMethod), bootstrap())
  const adapter = asyncLoaded.resolveAdmissionAdapter(resolveInput())
  const methodError = captureFailure(() => adapter.prepare(admissionInput()))
  t.is(methodError?.code, 'BLIND_ADMISSION_ADAPTER_EXECUTION_FAILED')
})
