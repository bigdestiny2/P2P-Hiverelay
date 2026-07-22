import { createHash } from 'node:crypto'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import test from 'brittle'
import {
  PRODUCTION_RUNTIME_PROFILE,
  loadProductionAdmissionAdapter,
  loadProductionEntrypointConfig
} from '../production-entrypoint.js'

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

test('production entrypoint selects only explicit fail-closed runtime profiles', t => {
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

  const describeWithAdapter = captureFailure(() => loadProductionEntrypointConfig(entrypointEnvironment(
    PRODUCTION_RUNTIME_PROFILE.DESCRIBE_ONLY_V1,
    { HIVERELAY_BLIND_ADMISSION_ADAPTER_MODULE: '/adapter.mjs' }
  )))
  t.is(describeWithAdapter?.code, 'BLIND_ENTRYPOINT_CONFIG_INVALID')

  const missingAdapter = captureFailure(() => loadProductionEntrypointConfig(entrypointEnvironment(
    PRODUCTION_RUNTIME_PROFILE.CELL_V1
  )))
  t.is(missingAdapter?.code, 'BLIND_ENTRYPOINT_CONFIG_INVALID')

  const uppercaseDigest = captureFailure(() => loadProductionEntrypointConfig(entrypointEnvironment(
    PRODUCTION_RUNTIME_PROFILE.CELL_V1,
    {
      HIVERELAY_BLIND_ADMISSION_ADAPTER_MODULE: '/adapter.mjs',
      HIVERELAY_BLIND_ADMISSION_ADAPTER_SHA256: 'AA'.repeat(32)
    }
  )))
  t.is(uppercaseDigest?.code, 'BLIND_ENTRYPOINT_CONFIG_INVALID')

  const noncanonicalPath = captureFailure(() => loadProductionEntrypointConfig(entrypointEnvironment(
    PRODUCTION_RUNTIME_PROFILE.CELL_V1,
    {
      HIVERELAY_BLIND_ADMISSION_ADAPTER_MODULE: '/opt/../adapter.mjs',
      HIVERELAY_BLIND_ADMISSION_ADAPTER_SHA256: 'aa'.repeat(32)
    }
  )))
  t.is(noncanonicalPath?.code, 'BLIND_ENTRYPOINT_CONFIG_INVALID')
})

test('production admission adapter is protected, hash-bound and bootstrap-bound', async t => {
  const created = await fs.mkdtemp(path.join(os.tmpdir(), 'blind-entrypoint-'))
  const directory = await fs.realpath(created)
  t.teardown(async () => fs.rm(created, { recursive: true, force: true }))
  const modulePath = path.join(directory, 'adapter.mjs')
  const source = `
export function createAdmissionAdapterResolver (context) {
  const launchTopologyHash = context.launchTopologyHash.toString('hex')
  const endpointIds = [...context.endpointIds]
  const contextFrozen = Object.isFrozen(context) && Object.isFrozen(context.endpointIds)
  return input => ({ input, runtimeProfile: context.runtimeProfile, launchTopologyHash, endpointIds, contextFrozen })
}
`
  await fs.writeFile(modulePath, source, { mode: 0o400 })
  await fs.chmod(modulePath, 0o400)
  const moduleSha256 = createHash('sha256').update(source).digest('hex')
  const environment = entrypointEnvironment(PRODUCTION_RUNTIME_PROFILE.CELL_V1, {
    HIVERELAY_BLIND_ADMISSION_ADAPTER_MODULE: modulePath,
    HIVERELAY_BLIND_ADMISSION_ADAPTER_SHA256: moduleSha256
  })
  const config = loadProductionEntrypointConfig(environment)
  t.is(Object.isFrozen(config.admissionAdapter), true)

  const bootstrap = {
    launchTopologyHash: Buffer.alloc(32, 0x42),
    endpointIds: [2, 4]
  }
  const loaded = await loadProductionAdmissionAdapter(config, bootstrap)
  t.is(loaded.modulePath, modulePath)
  t.is(loaded.moduleSha256, moduleSha256)
  t.is(Object.isFrozen(loaded), true)
  const input = { admissionProfileId: 7 }
  t.alike(await loaded.resolveAdmissionAdapter(input), {
    input,
    runtimeProfile: PRODUCTION_RUNTIME_PROFILE.CELL_V1,
    launchTopologyHash: '42'.repeat(32),
    endpointIds: [2, 4],
    contextFrozen: true
  })
  t.alike(bootstrap.endpointIds, [2, 4])
  t.alike(bootstrap.launchTopologyHash, Buffer.alloc(32, 0x42))

  const wrongDigest = loadProductionEntrypointConfig({
    ...environment,
    HIVERELAY_BLIND_ADMISSION_ADAPTER_SHA256: '00'.repeat(32)
  })
  const digestError = await captureRejection(loadProductionAdmissionAdapter(wrongDigest, bootstrap))
  t.is(digestError?.code, 'BLIND_ADMISSION_ADAPTER_DIGEST_MISMATCH')

  const noExportPath = path.join(directory, 'no-export.mjs')
  const noExportSource = 'export const adapter = true\n'
  await fs.writeFile(noExportPath, noExportSource, { mode: 0o400 })
  await fs.chmod(noExportPath, 0o400)
  const noExportConfig = loadProductionEntrypointConfig(entrypointEnvironment(
    PRODUCTION_RUNTIME_PROFILE.CELL_V1,
    {
      HIVERELAY_BLIND_ADMISSION_ADAPTER_MODULE: noExportPath,
      HIVERELAY_BLIND_ADMISSION_ADAPTER_SHA256: createHash('sha256').update(noExportSource).digest('hex')
    }
  ))
  const exportError = await captureRejection(loadProductionAdmissionAdapter(noExportConfig, bootstrap))
  t.is(exportError?.code, 'BLIND_ADMISSION_ADAPTER_EXPORT_INVALID')

  const symlinkPath = path.join(directory, 'adapter-link.mjs')
  await fs.symlink(modulePath, symlinkPath)
  const symlinkConfig = loadProductionEntrypointConfig(entrypointEnvironment(
    PRODUCTION_RUNTIME_PROFILE.CELL_V1,
    {
      HIVERELAY_BLIND_ADMISSION_ADAPTER_MODULE: symlinkPath,
      HIVERELAY_BLIND_ADMISSION_ADAPTER_SHA256: moduleSha256
    }
  ))
  const symlinkError = await captureRejection(loadProductionAdmissionAdapter(symlinkConfig, bootstrap))
  t.is(symlinkError?.code, 'BLIND_ADMISSION_ADAPTER_MODULE_INVALID')
})
