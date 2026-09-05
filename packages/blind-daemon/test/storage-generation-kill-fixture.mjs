import b4a from 'b4a'
import { openBlindStoreGenerationFloor } from '../storage-generation-v12.js'

const [root, killPhase = 'after-record-sync'] = process.argv.slice(2)
if (root === '--production-cell') {
  const { once } = await import('node:events')
  const { loadDaemonBootstrapConfig } = await import('../bootstrap-config.js')
  const { assembleProductionBlindDaemon, loadProductionRuntimeConfig } = await import('../production-runtime.js')
  const [{ environment, cell }] = await once(process, 'message')
  // Assembly only: the fixture never starts either Unix listener.
  environment.HIVERELAY_BLIND_UNARY_SOCKET = `/tmp/gq-kill-${process.pid}/unary.sock`
  environment.HIVERELAY_BLIND_STREAM_SOCKET = `/tmp/gq-kill-${process.pid}/stream.sock`
  const bootstrap = loadDaemonBootstrapConfig(environment)
  const runtime = await assembleProductionBlindDaemon({
    bootstrap: { ...bootstrap, expectedPeerUid: process.getuid() },
    runtimeConfig: loadProductionRuntimeConfig(environment, bootstrap.endpointIds),
    enableCellRuntime: true,
    enableInboxRuntime: true,
    enableCoreRuntime: true,
    resolveAdmissionAdapter: async () => { throw new Error('kill fixture uses already prepared direct engine admission') },
    releaseGate: async () => {}
  })
  const acknowledge = runtime.storage.onBlindWriteAcknowledged
  runtime.storage.onBlindWriteAcknowledged = Object.assign(async evidence => {
    if (killPhase === 'after-floor-acknowledgment') await acknowledge(evidence)
    process.send('ready')
    await new Promise(() => {})
  }, acknowledge)
  await runtime.storage.putCell(cell)
  process.exit(1)
}
const floor = await openBlindStoreGenerationFloor(root, {
  manifestKey: b4a.alloc(32, 0xa1),
  storeIdentity: b4a.from('authenticated-runtime-store-binding'),
  storeEvidence: { walSequence: 1n, walHash: b4a.alloc(32, 1) },
  faultInjector: async phase => {
    if (phase === killPhase) {
      if (process.send) process.send('ready')
      await new Promise(() => {})
    }
  }
})
await floor.acknowledgeBlindOnlyWrite({ walSequence: 2n, walHash: b4a.alloc(32, 2) })
