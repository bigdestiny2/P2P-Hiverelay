import { clock, openHistory, putFixture, atomicPut, retireCells } from './generation-history-fixture.js'

const [root, phase] = process.argv.slice(2)
const time = clock()
let compacting = false
async function barrier () {
  process.send({ phase, trigger: owned.startup.floor.triggerReceipt() })
  await new Promise(() => {})
}
const owned = await openHistory(root, time, {
  allowFreshGenesis: true,
  async faultInjector (point) {
    if (compacting && phase === 'compaction-wal-synced' && point === 'wal:after-sync') await barrier()
  }
})
await atomicPut(owned.engine, putFixture())
const compact = owned.engine.compact.bind(owned.engine)
owned.engine.compact = (...args) => { compacting = true; return compact(...args) }
await retireCells(owned.engine, time)
if (phase === 'compaction-applied') await barrier()
throw new Error('expected kill barrier')
