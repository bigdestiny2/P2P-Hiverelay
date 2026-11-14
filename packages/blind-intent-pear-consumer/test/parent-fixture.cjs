const { PearIntentBackend } = require(process.argv[2])
const backend = new PearIntentBackend(process.argv[3], {
  pauseAtPhase: 'after-publication',
  onPhase: phase => {
    console.log(JSON.stringify({ phase, workerPid: backend.runtime.pid }))
    return new Promise(() => {})
  }
})
backend.compareAndSwap('intent:' + '1'.padStart(64, '0'), 0n, Buffer.from('parent-lost')).catch(error => {
  console.error(error.code)
  process.exitCode = 1
})
