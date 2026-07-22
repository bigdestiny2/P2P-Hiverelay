import b4a from 'b4a'
import { createHmac, timingSafeEqual } from 'node:crypto'
import { open, mkdir, readFile, readdir, rename, unlink } from 'node:fs/promises'
import path from 'node:path'
import { blake2b256 } from '@hiverelay/blind-protocol'

export const BLIND_STORE_GENERATION = Object.freeze({
  schema: 'hiverelay-blind-store-generation-record-v1',
  formatVersion: '1.2',
  legacyFormatVersion: '1.1',
  headFile: 'blind-store-generation-head-v1.json'
})

export const BLIND_STORE_READER_MODE = Object.freeze({ BLIND_ONLY: 'blind-only' })
const RECORD = /^blind-store-generation-record-([0-9]{16})-v1\.json$/
const TEMP = /^\.blind-store-generation-.*\.tmp-[0-9]+$/

export async function openBlindStoreGenerationFloor (controlDirectory, options = {}) {
  if (typeof controlDirectory !== 'string' || controlDirectory.length === 0) {
    throw new TypeError('controlDirectory must be a non-empty string')
  }
  const manifestKey = asBytes(options.manifestKey, 'manifestKey', 32)
  const storeIdentityHash = hashHex(asBytes(options.storeIdentity, 'storeIdentity'))
  const currentEvidence = evidence(options.storeEvidence)
  await mkdir(controlDirectory, { recursive: true, mode: 0o700 })
  for (const name of await readdir(controlDirectory)) {
    if (TEMP.test(name)) await unlink(path.join(controlDirectory, name)).catch(() => {})
  }
  let records = await loadRecords()
  if (records.length === 0) {
    if (options.allowCreate !== true) throw new Error('blind store generation evidence is missing')
    const initial = record(0, false, null, currentEvidence)
    await writeExclusive(recordPath(0), signed(initial))
    await writeHead(initial)
    records = [initial]
  }
  const head = await readSigned(path.join(controlDirectory, BLIND_STORE_GENERATION.headFile), 'generation head')
  validateChain(records)
  if (head.storeIdentityHash !== storeIdentityHash || head.sequence > records.at(-1).sequence) {
    throw new Error('invalid blind store generation head')
  }
  let latest = records.at(-1)
  if (head.sequence < latest.sequence || head.recordHash !== recordHash(latest)) await writeHead(latest)
  if (latest.storeIdentityHash !== storeIdentityHash) throw new Error('blind store generation evidence belongs to another store')
  const latestSequence = BigInt(latest.storeEvidence.walSequence)
  const currentSequence = BigInt(currentEvidence.walSequence)
  if (latestSequence > currentSequence ||
      (latestSequence === currentSequence && latest.storeEvidence.walHash !== currentEvidence.walHash) ||
      (!latest.firstBlindOnlyWriteAcknowledged && currentSequence > latestSequence)) {
    throw new Error('blind store generation evidence was rolled back or replayed')
  }
  let acknowledged = latest.firstBlindOnlyWriteAcknowledged
  let acknowledgmentTail = Promise.resolve()

  return {
    get firstBlindOnlyWriteAcknowledged () { return acknowledged },
    assertReaderMode (mode) {
      if (mode !== BLIND_STORE_READER_MODE.BLIND_ONLY) {
        throw new Error('only blind-only reader mode is implemented; legacy stores require full replacement')
      }
      return true
    },
    acknowledgeBlindOnlyWrite (storeEvidence) {
      const operation = acknowledgmentTail.then(() => advanceAcknowledgment(storeEvidence))
      acknowledgmentTail = operation.catch(() => {})
      return operation
    }
  }

  async function advanceAcknowledgment (storeEvidence) {
    const diskRecords = await loadRecords()
    validateChain(diskRecords)
    if (diskRecords.at(-1).sequence > latest.sequence) {
      latest = diskRecords.at(-1)
      acknowledged = latest.firstBlindOnlyWriteAcknowledged
      await writeHead(latest)
    }
    const nextEvidence = evidence(storeEvidence)
    const nextWalSequence = BigInt(nextEvidence.walSequence)
    const latestWalSequence = BigInt(latest.storeEvidence.walSequence)
    if (nextWalSequence < latestWalSequence) return false
    if (nextWalSequence === latestWalSequence) {
      if (nextEvidence.walHash !== latest.storeEvidence.walHash) {
        throw new Error('blind-only acknowledgment conflicts with durable WAL evidence')
      }
      if (acknowledged) return false
      throw new Error('blind-only acknowledgment must bind a newer durable WAL write')
    }
    const next = record(latest.sequence + 1, true, recordHash(latest), nextEvidence)
    await writeExclusive(recordPath(next.sequence), signed(next))
    if (options.faultInjector) await options.faultInjector('after-record-sync')
    await writeHead(next)
    latest = next
    acknowledged = true
    return true
  }

  function record (sequence, value, previousRecordHash, storeEvidence) {
    return {
      schema: BLIND_STORE_GENERATION.schema,
      formatVersion: BLIND_STORE_GENERATION.formatVersion,
      storeIdentityHash,
      sequence,
      previousRecordHash,
      firstBlindOnlyWriteAcknowledged: value,
      storeEvidence
    }
  }
  function signed (body) { return { ...body, mac: mac(body, manifestKey) } }
  function recordPath (sequence) {
    return path.join(controlDirectory, `blind-store-generation-record-${String(sequence).padStart(16, '0')}-v1.json`)
  }
  async function loadRecords () {
    const names = (await readdir(controlDirectory)).filter(name => RECORD.test(name)).sort()
    const output = []
    for (const name of names) output.push(await readSigned(path.join(controlDirectory, name), 'generation record'))
    return output
  }
  async function readSigned (file, label) {
    let value
    try { value = JSON.parse(await readFile(file, 'utf8')) } catch (error) {
      if (error.code === 'ENOENT') throw new Error(`blind store ${label} is missing`)
      throw new Error(`invalid blind store ${label}`)
    }
    if (!validMac(value, manifestKey)) throw new Error(`invalid blind store ${label}`)
    const body = { ...value }; delete body.mac
    return body
  }
  function validateChain (values) {
    for (let index = 0; index < values.length; index++) {
      const value = values[index]
      if (value.sequence !== index || value.storeIdentityHash !== storeIdentityHash ||
          value.previousRecordHash !== (index === 0 ? null : recordHash(values[index - 1])) ||
          (index > 0 && values[index - 1].firstBlindOnlyWriteAcknowledged && !value.firstBlindOnlyWriteAcknowledged)) {
        throw new Error('invalid blind store generation evidence chain')
      }
    }
  }
  async function writeHead (value) {
    const body = {
      schema: 'hiverelay-blind-store-generation-head-v1',
      storeIdentityHash,
      sequence: value.sequence,
      recordHash: recordHash(value)
    }
    await writeAtomic(path.join(controlDirectory, BLIND_STORE_GENERATION.headFile), signed(body))
  }
  async function writeExclusive (file, value) {
    const handle = await open(file, 'wx', 0o600)
    try { await handle.writeFile(JSON.stringify(value) + '\n'); await handle.sync() } finally { await handle.close() }
    await syncDirectory()
  }
  async function writeAtomic (file, value) {
    const temporary = path.join(controlDirectory, `.blind-store-generation-head.tmp-${process.pid}`)
    const handle = await open(temporary, 'w', 0o600)
    try { await handle.writeFile(JSON.stringify(value) + '\n'); await handle.sync() } finally { await handle.close() }
    await rename(temporary, file)
    await syncDirectory()
  }
  async function syncDirectory () {
    const directory = await open(controlDirectory, 'r')
    try { await directory.sync() } finally { await directory.close() }
  }
}

function evidence (value) {
  if (!value || typeof value.walSequence !== 'bigint' || value.walSequence < 0n) {
    throw new TypeError('storeEvidence.walSequence must be a non-negative bigint')
  }
  return { walSequence: value.walSequence.toString(), walHash: hashHex(asBytes(value.walHash, 'storeEvidence.walHash', 32)) }
}
function recordHash (value) { return hashHex(b4a.from(JSON.stringify(value), 'utf8')) }
function hashHex (value) { return b4a.toString(blake2b256(value), 'hex') }
function mac (body, key) { return createHmac('sha256', key).update(JSON.stringify(body)).digest('hex') }
function validMac (value, key) {
  if (!value || typeof value.mac !== 'string' || !/^[0-9a-f]{64}$/.test(value.mac)) return false
  const body = { ...value }; delete body.mac
  return timingSafeEqual(b4a.from(value.mac, 'hex'), b4a.from(mac(body, key), 'hex'))
}
function asBytes (value, label, length = null) {
  if (!b4a.isBuffer(value) && !(value instanceof Uint8Array)) throw new TypeError(`${label} must be bytes`)
  const bytes = b4a.from(value)
  if (length != null && bytes.byteLength !== length) throw new TypeError(`${label} must be ${length} bytes`)
  return bytes
}
