#!/usr/bin/env node
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { loadDaemonBootstrapConfig } from './bootstrap-config.js'
import {
  loadProductionAdmissionAdapter,
  loadProductionEntrypointConfig
} from './production-entrypoint.js'
import {
  assembleProductionBlindDaemon,
  loadProductionRuntimeConfig,
  productionReleaseGateFor
} from './production-runtime.js'

function report (error, phase = 'runtime') {
  const code = error && typeof error.code === 'string' ? ` ${error.code}` : ''
  process.stderr.write(`[blind-daemon] ${phase} failed${code}: ${error.message}\n`)
}

export async function runBlindDaemonCli (options = {}) {
  const environment = options.environment || process.env
  const bootstrap = loadDaemonBootstrapConfig(environment, options.identity || process)
  const releaseGate = options.releaseGate || productionReleaseGateFor(environment)
  const injectedAdmissionAdapter = typeof options.resolveAdmissionAdapter === 'function'
  const entrypointConfig = loadProductionEntrypointConfig(environment, {
    allowInjectedAdmissionAdapter: injectedAdmissionAdapter
  })
  const runtimeConfig = loadProductionRuntimeConfig(environment, bootstrap.endpointIds)
  const enableCellRuntime = entrypointConfig.enableCellRuntime
  const enableInboxRuntime = entrypointConfig.enableInboxRuntime
  const enableCoreRuntime = entrypointConfig.enableCoreRuntime
  let productionAdmissionPromise = null
  const resolveAdmissionAdapter = options.resolveAdmissionAdapter || (enableCellRuntime
    ? async input => {
      productionAdmissionPromise ||= loadProductionAdmissionAdapter(entrypointConfig, bootstrap, {
        identity: options.identity || process
      })
      const productionAdmission = await productionAdmissionPromise
      return productionAdmission.resolveAdmissionAdapter(input)
    }
    : undefined)
  let runtime
  try {
    runtime = await assembleProductionBlindDaemon({
      bootstrap,
      runtimeConfig,
      releaseGate,
      enableCellRuntime,
      enableInboxRuntime,
      enableCoreRuntime,
      resolveAdmissionAdapter,
      requireCompleteAdmissionCapture: enableCellRuntime,
      testOnlyPrivateIpcReplayJournalOptions: options.testOnlyPrivateIpcReplayJournalOptions,
      onError: error => {
        if (typeof options.onError === 'function') options.onError(error)
        else report(error)
      }
    })
    await runtime.start()
  } catch (error) {
    if (runtime) await runtime.close().catch(closeError => report(closeError, 'startup cleanup'))
    throw error
  }

  const status = runtime.status()
  const operations = enableCellRuntime
    ? enableInboxRuntime
      ? enableCoreRuntime ? 'DESCRIBE,CELL,INBOX,CORE' : 'DESCRIBE,CELL,INBOX'
      : 'DESCRIBE,CELL'
    : 'DESCRIBE only'
  const writeState = enableCellRuntime
    ? `; CELL.PUT=${status.v2WritePathReady ? 'ready' : status.privateIpcReplayJournal?.reason || 'not-ready'}`
    : ''
  process.stdout.write(`[blind-daemon] private IPC ready at ${bootstrap.unarySocketPath} and ${bootstrap.streamSocketPath}; ` +
    `public operations=${operations}${writeState}\n`)

  if (options.installSignalHandlers !== false) {
    let shutdownPromise = null
    const shutdown = signal => {
      if (shutdownPromise) return shutdownPromise
      shutdownPromise = runtime.close().catch(error => {
        process.exitCode = 1
        report(error, `${signal} shutdown`)
      })
      return shutdownPromise
    }
    process.once('SIGINT', () => shutdown('SIGINT'))
    process.once('SIGTERM', () => shutdown('SIGTERM'))
  }
  return runtime
}

const entrypoint = process.argv[1] == null ? null : path.resolve(process.argv[1])
if (entrypoint === fileURLToPath(import.meta.url)) {
  try {
    await runBlindDaemonCli()
  } catch (error) {
    report(error, 'startup')
    process.exitCode = 1
  }
}
