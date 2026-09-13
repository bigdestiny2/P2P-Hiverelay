/* global Bare */
import os from 'bare-os'
import TextDecoder from 'text-decoder'
import { BareIntentBackend, BARE_INTENT_BACKEND_RUNTIME } from './vendor/blind-intent-store-bare/index.js'

const MAX_MESSAGE = (8 * 1024 * 1024 + 264 + 28) * 2 + 65536
let buffer = ''
const decoder = new TextDecoder()
let backend = null
let closing = false
let active = 0
let resume = null
const send = value => Bare.IPC.write(JSON.stringify(value) + '\n')
function failure (code, message) { return Object.assign(new Error(message), { code }) }

async function dispatch (message) {
  if (message.op === 'resume') { resume?.(); resume = null; return }
  if (!Number.isSafeInteger(message.id) || message.id < 1) throw failure('INTENT_STORE_INPUT', 'invalid request ID')
  if (closing) throw failure('INTENT_STORE_CLOSED', 'worker is closing')
  if (active >= 8 && message.op !== 'close') throw failure('INTENT_STORE_BUSY', 'worker operation admission is full')
  active++
  try {
    let result
    if (message.op === 'open') {
      if (Bare.version !== 'v1.29.4') throw failure('INTENT_STORE_PLATFORM', 'Pear sidecar must use its exact qualified embedded runtime')
      if (backend) throw failure('INTENT_STORE_INPUT', 'worker already initialized')
      backend = new BareIntentBackend(message.directory, {
        onCommitPhase: async phase => {
          if (closing || phase !== message.pauseAtPhase) return
          await new Promise(resolve => { resume = resolve; send({ event: 'phase', phase }) })
        }
      })
      await backend.ready()
      result = {
        ...BARE_INTENT_BACKEND_RUNTIME,
        versions: Bare.versions,
        executable: os.execPath(),
        pid: os.pid(),
        nativeLibraries: Object.values(Bare.Addon.cache).map(addon => addon.url.href).sort()
      }
    } else {
      if (!backend) throw failure('INTENT_STORE_INPUT', 'worker has not initialized')
      switch (message.op) {
        case 'read': {
          const record = await backend.read(message.key)
          result = { revision: String(record.revision), ciphertext: record.ciphertext?.toString('hex') ?? null }
          break
        }
        case 'cas': result = await backend.compareAndSwap(message.key, BigInt(message.revision), Buffer.from(message.ciphertext, 'hex')); break
        case 'keysPage': result = await backend.keysPage({ cursor: message.cursor, limit: message.limit }); break
        case 'closeScan': result = await backend.closeScan(message.cursor); break
        case 'close':
          closing = true
          await backend.close()
          result = { drained: true }
          break
        default: throw failure('INTENT_STORE_INPUT', 'unknown worker operation')
      }
    }
    send({ id: message.id, result })
    if (message.op === 'close') Bare.IPC.end()
  } finally { active-- }
}

Bare.IPC.on('data', bytes => {
  buffer += decoder.push(bytes)
  while (buffer.includes('\n')) {
    const end = buffer.indexOf('\n')
    if (end > MAX_MESSAGE) return Bare.exit(1)
    const line = buffer.slice(0, end)
    buffer = buffer.slice(end + 1)
    let message
    try { message = JSON.parse(line) } catch { return Bare.exit(1) }
    dispatch(message).catch(error => send({ id: message.id, error: { code: error.code || 'INTENT_STORE_WORKER_UNKNOWN', message: error.message } }))
  }
  if (buffer.length > MAX_MESSAGE) Bare.exit(1)
})
Bare.IPC.on('end', () => {
  if (!closing) {
    closing = true
    resume?.()
    resume = null
    Promise.resolve(backend?.close()).then(() => Bare.IPC.end(), () => Bare.exit(1))
  }
})
