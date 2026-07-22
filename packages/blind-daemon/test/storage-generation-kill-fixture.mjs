import b4a from 'b4a'
import { openBlindStoreGenerationFloor } from '../storage-generation-v12.js'

const [root] = process.argv.slice(2)
const floor = await openBlindStoreGenerationFloor(root, {
  manifestKey: b4a.alloc(32, 0xa1),
  storeIdentity: b4a.from('authenticated-runtime-store-binding'),
  storeEvidence: { walSequence: 1n, walHash: b4a.alloc(32, 1) },
  faultInjector: async phase => {
    if (phase === 'after-record-sync') {
      if (process.send) process.send('ready')
      await new Promise(() => {})
    }
  }
})
await floor.acknowledgeBlindOnlyWrite({ walSequence: 2n, walHash: b4a.alloc(32, 2) })
