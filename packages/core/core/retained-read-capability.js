/** Explicit local-read authority; never a storage commitment or replication grant. */
import { createHash } from 'crypto'
import { EventEmitter } from 'events'
import { constants as C, openSync, closeSync, fstatSync, lstatSync, readSync, realpathSync, statSync } from 'fs'
import { isAbsolute, normalize, relative, posix } from 'path'
import { Readable } from 'stream'
import Hyperbee from 'hyperbee'
import Hyperblobs from 'hyperblobs'
import Hyperdrive from 'hyperdrive'
import c from 'compact-encoding'
import { corestoreGenerationPublicConfig, corestoreGenerationStatus } from './persistence/corestore-generation-envelope.js'

export const RETAINED_READ_LIMITS = Object.freeze({ manifestBytes: 8 * 1024 * 1024, drives: 8192, rowBytes: 1024 * 1024, depth: 32, proofNodes: 256, signatureBytes: 64 * 1024, blockBytes: 16 * 1024 * 1024, requestBlocks: 4096, requestBytes: 80 * 1024 * 1024, responseBytes: 64 * 1024 * 1024 })
const HEX = /^[0-9a-f]{64}$/
const SHA = /^sha256:[0-9a-f]{64}$/
const SCHEMA = 'HiveRelayRetainedLocalReadCapabilityV1'
const SELECTED = new WeakSet()

function fail (message = 'selected local snapshot unavailable', code = 'RETAINED_LOCAL_UNAVAILABLE') {
  const error = new Error(message)
  error.code = code
  throw error
}
function exact (value, keys, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join('\0') !== [...keys].sort().join('\0')) fail('invalid retained-read ' + label)
}
function digest (bytes) { return 'sha256:' + createHash('sha256').update(bytes).digest('hex') }
function safe (value) { return Number.isSafeInteger(value) && value >= 0 }
function jsonValue (value, depth = 0) {
  if (depth > RETAINED_READ_LIMITS.depth) fail('retained-read JSON depth exceeded')
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return value
  if (typeof value === 'number' && Number.isFinite(value)) return value
  if (Array.isArray(value)) return value.map(v => jsonValue(v, depth + 1))
  if (value && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    return Object.fromEntries(Object.keys(value).sort().map(k => [k, jsonValue(value[k], depth + 1)]))
  }
  fail('invalid retained-read JSON value')
}
export function retainedReadCanonicalBytes (value) { return Buffer.from(JSON.stringify(jsonValue(value)) + '\n') }
export function retainedReadRowSha256 (row) {
  const bytes = retainedReadCanonicalBytes(row)
  if (bytes.length > RETAINED_READ_LIMITS.rowBytes) fail('retained-read row limit exceeded')
  return digest(bytes)
}
function absolute (file) {
  if (typeof file !== 'string' || !isAbsolute(file) || normalize(file) !== file || file.includes('\0')) fail('retained-read path must be canonical absolute')
  return file
}
function outside (file, root) {
  const rel = relative(root, file)
  if (!rel || (!rel.startsWith('../') && rel !== '..' && !isAbsolute(rel))) fail('retained-read authority must be outside storage')
}
function sameStat (a, b) { return a.dev === b.dev && a.ino === b.ino && a.size === b.size && a.mode === b.mode && a.nlink === b.nlink && a.mtimeNs === b.mtimeNs && a.ctimeNs === b.ctimeNs }
function protectedFile (file, maximum, root) {
  absolute(file); outside(file, root)
  if (realpathSync(file) !== file) fail('retained-read authority path contains a symlink')
  const before = lstatSync(file, { bigint: true })
  if (!before.isFile() || before.nlink !== 1n || before.size < 1n || before.size > BigInt(maximum)) fail('retained-read authority is not a bounded single-link file')
  let writable = null
  try { writable = openSync(file, C.O_WRONLY | C.O_NOFOLLOW | C.O_NONBLOCK) } catch (error) {
    if (!['EROFS', 'EACCES', 'EPERM'].includes(error.code)) throw error
  }
  if (writable !== null) { closeSync(writable); fail('retained-read authority must be read-only to runtime') }
  let fd
  try {
    fd = openSync(file, C.O_RDONLY | C.O_NOFOLLOW | C.O_NONBLOCK)
    const opened = fstatSync(fd, { bigint: true })
    if (!sameStat(before, opened)) fail('retained-read authority changed before read')
    const bytes = Buffer.alloc(Number(opened.size) + 1)
    let size = 0
    while (size < bytes.length) {
      const n = readSync(fd, bytes, size, bytes.length - size, size)
      if (n === 0) break
      size += n
    }
    if (size !== Number(opened.size) || !sameStat(opened, fstatSync(fd, { bigint: true })) || !sameStat(opened, lstatSync(file, { bigint: true }))) fail('retained-read authority changed during read')
    return bytes.subarray(0, size)
  } finally { if (fd !== undefined) closeSync(fd) }
}
function rootIdentity (node) {
  const status = corestoreGenerationStatus(node.store)
  if (!status?.ready || status.participant !== 'relay-node') fail('retained reads require a verified relay generation')
  const configuredRoot = realpathSync(absolute(node.config.storage))
  const generationRoot = realpathSync(status.generationRoot)
  if (configuredRoot !== node.config.storage || status.configuredRoot !== configuredRoot) fail('retained-read generation root mismatch')
  const a = statSync(configuredRoot, { bigint: true }); const b = statSync(generationRoot, { bigint: true })
  return { configuredRoot, generationRoot, device: String(a.dev), inode: String(a.ino), generationDevice: String(b.dev), generationInode: String(b.ino) }
}
function equalJSON (a, b) { return retainedReadCanonicalBytes(a).equals(retainedReadCanonicalBytes(b)) }
function descriptor (value) {
  exact(value, ['key', 'fork', 'length', 'byteLength', 'treeHash'], 'core descriptor')
  if (!HEX.test(value.key) || !HEX.test(value.treeHash) || !safe(value.fork) || !safe(value.length) || !safe(value.byteLength) || (value.length === 0 && value.byteLength !== 0)) fail('invalid retained-read core tuple')
}
function loadSelection (node, declaration) {
  exact(declaration, ['manifestPath', 'pinPath'], 'declaration')
  if (declaration.manifestPath === declaration.pinPath) fail('retained-read manifest and pin must be distinct')
  const pin = protectedFile(declaration.pinPath, 72, node.config.storage)
  if (pin.length !== 72 || pin[71] !== 10 || !SHA.test(pin.subarray(0, 71).toString('ascii'))) fail('invalid retained-read pin')
  const bytes = protectedFile(declaration.manifestPath, RETAINED_READ_LIMITS.manifestBytes, node.config.storage)
  if (digest(bytes) !== pin.subarray(0, 71).toString('ascii')) fail('retained-read pin mismatch')
  let value
  try { value = JSON.parse(bytes.toString('utf8')) } catch { fail('invalid retained-read JSON') }
  if (!retainedReadCanonicalBytes(value).equals(bytes)) fail('noncanonical retained-read selection')
  exact(value, ['schema', 'purpose', 'generation', 'root', 'sourceQualificationSha256', 'inventorySha256', 'drives'], 'manifest')
  if (value.schema !== SCHEMA || value.purpose !== 'serve-selected-local-snapshots-only' || !SHA.test(value.sourceQualificationSha256) || !SHA.test(value.inventorySha256)) fail('invalid retained-read purpose or provenance')
  exact(value.generation, ['mode', 'expectedInstallationId', 'expectedAuthorityKeySha256', 'expectedManifestSha256'], 'generation')
  if (!equalJSON(corestoreGenerationPublicConfig(node.config.hiverelayGeneration), value.generation)) fail('retained-read generation binding mismatch')
  exact(value.root, ['configuredRoot', 'generationRoot', 'device', 'inode', 'generationDevice', 'generationInode'], 'root')
  if (!equalJSON(rootIdentity(node), value.root)) fail('retained-read device binding mismatch')
  if (!Array.isArray(value.drives) || value.drives.length < 1 || value.drives.length > RETAINED_READ_LIMITS.drives) fail('retained-read drive limit exceeded')
  let previous = ''
  for (const entry of value.drives) {
    exact(entry, ['appKey', 'registryRowSha256', 'driveVersion', 'metadata', 'blobs'], 'drive')
    descriptor(entry.metadata); descriptor(entry.blobs)
    if (!HEX.test(entry.appKey) || entry.appKey <= previous || entry.metadata.key !== entry.appKey || !SHA.test(entry.registryRowSha256) || !safe(entry.driveVersion) || entry.driveVersion < 2 || entry.driveVersion !== entry.metadata.length) fail('invalid retained-read drive selection')
    previous = entry.appKey
  }
  SELECTED.add(value)
  return value
}
function headMatches (core, value) {
  return core && !core.closed && !core.closing && core.key.toString('hex') === value.key && core.fork === value.fork && core.length === value.length && core.byteLength === value.byteLength && !core.encryption
}
function proofShape (proof) {
  let nodes = 0
  for (const list of [proof?.block?.nodes, proof?.hash?.nodes, proof?.seek?.nodes, proof?.upgrade?.nodes, proof?.upgrade?.additionalNodes]) {
    if (list === undefined) continue
    if (!Array.isArray(list)) fail('invalid retained-read proof')
    nodes += list.length
    if (nodes > RETAINED_READ_LIMITS.proofNodes) fail('retained-read proof limit exceeded', 'RETAINED_LOCAL_LIMIT')
  }
  if (!proof?.upgrade || !Buffer.isBuffer(proof.upgrade.signature) || proof.upgrade.signature.length > RETAINED_READ_LIMITS.signatureBytes) fail('invalid retained-read signed proof')
}
function verifyBatch (batch, selected) {
  if (batch.fork !== selected.fork || batch.length !== selected.length || batch.byteLength !== selected.byteLength || batch.hash().toString('hex') !== selected.treeHash) fail('retained-read signed root mismatch')
}
function width (index) {
  let n = index + 1; let w = 1
  while (n % 2 === 0) { n /= 2; w *= 2 }
  return w
}
function verifiedLeafRange (batch, index) {
  const target = 2 * index
  const nodes = new Map([...batch.nodes, ...batch.roots].map(node => [node.index, node]))
  let offset = 0
  for (const root of batch.roots) {
    if (target > root.index + width(root.index) - 1) { offset += root.size; continue }
    let node = root
    while (node.index !== target) {
      const half = width(node.index) / 2
      if (half < 1) fail('retained-read leaf proof incomplete')
      const left = nodes.get(node.index - half)
      const right = nodes.get(node.index + half)
      if (!left || !right) fail('retained-read leaf proof incomplete')
      if (target < node.index) node = left
      else { offset += left.size; node = right }
    }
    return { offset, size: node.size }
  }
  fail('retained-read leaf outside selection')
}

class VerifiedCore {
  constructor (live, selected, owner, metadata) { this.live = live; this.selected = selected; this.owner = owner; this.metadata = metadata; this.snapshot = null }
  async ready () {
    await this.owner.check()
    if (!headMatches(this.live, this.selected)) fail('retained-read live head changed')
    this.snapshot = this.live.snapshot({ wait: false, writable: false })
    await this.snapshot.ready()
    if (!headMatches(this.snapshot, this.selected)) fail('retained-read snapshot changed')
    if (this.selected.length === 0) {
      if ((await this.snapshot.treeHash(0)).toString('hex') !== this.selected.treeHash) fail('retained-read empty tree mismatch')
    } else await this.proof({})
  }

  async check () { await this.owner.check(); if (!headMatches(this.live, this.selected) || !headMatches(this.snapshot, this.selected)) fail('retained-read head changed') }
  proof (request) { return this.owner.run(() => this._proof(request)) }
  async _proof (request) {
    await this.check()
    const proof = await this.snapshot.proof({ ...request, upgrade: { start: 0, length: this.selected.length } })
    proofShape(proof)
    const batch = await this.snapshot.verifyFullyRemote(proof)
    verifyBatch(batch, this.selected)
    await this.check()
    return { proof, batch }
  }

  get (index) { return this.owner.run(() => this._get(index)) }
  async _get (index) {
    if (!safe(index) || index >= this.selected.length) fail('retained-read block outside selection')
    await this.check()
    if (!(await this.live.has(index))) fail('selected local block missing')
    // Verify the signed leaf size before allocating a local body proof.
    const header = await this.proof({ hash: { index: 2 * index, nodes: 0 } })
    const leaf = header.batch.nodes.find(node => node.index === 2 * index)
    if (!leaf || !safe(leaf.size) || leaf.size > RETAINED_READ_LIMITS.blockBytes) fail('retained-read block limit exceeded', 'RETAINED_LOCAL_LIMIT')
    this.owner.charge(leaf.size)
    const { proof } = await this.proof({ block: { index, nodes: 0 } })
    if (proof.block?.index !== index || !Buffer.isBuffer(proof.block.value) || proof.block.value.length !== leaf.size || !(await this.live.has(index))) fail('selected local block changed or missing')
    if (this.metadata) this.owner.metadataReads.add(index)
    await this.check()
    if (!(await this.live.has(index))) fail('selected local block was cleared')
    this.owner.checkCurrent?.()
    if (!headMatches(this.live, this.selected)) fail('retained-read head changed')
    return proof.block.value
  }

  async seek (bytes) {
    if (!safe(bytes) || bytes > this.selected.byteLength) fail('retained-read seek outside selection')
    await this.check()
    if (bytes === this.selected.byteLength) return [this.selected.length, 0]
    // The local seek is only a hint. Its result is accepted only after the
    // leaf offset/size is recomputed from nodes in a verified signed proof.
    const hint = await this.snapshot.seek(bytes, { wait: false })
    if (!hint || !safe(hint[0]) || !safe(hint[1]) || hint[0] >= this.selected.length) fail('retained-read local seek unavailable')
    const { batch } = await this.proof({ hash: { index: 2 * hint[0], nodes: 0 } })
    const range = verifiedLeafRange(batch, hint[0])
    if (hint[1] >= range.size || range.offset + hint[1] !== bytes) fail('retained-read seek proof mismatch')
    await this.check()
    return hint
  }

  async close () { if (this.snapshot) { await this.snapshot.close(); this.snapshot = null } }
}
class ReadCoreView extends EventEmitter {
  constructor (reader, encoding = null) { super(); this.reader = reader; this.encoding = encoding; this.opened = true; this.closed = false; this.writable = false; this.globalCache = null; this.replicator = { setInflightRange () {} } }
  get key () { return this.reader.live.key }
  get length () { return this.reader.selected.length }
  get byteLength () { return this.reader.selected.byteLength }
  get fork () { return this.reader.selected.fork }
  async ready () { if (this.closed) fail(); await this.reader.check() }
  async get (index, opts = {}) {
    if (this.closed) fail()
    const bytes = await this.reader.get(index)
    const encoding = opts.valueEncoding ? c.from(opts.valueEncoding) : this.encoding
    return encoding ? c.decode(encoding, bytes) : bytes
  }

  async seek (bytes) { if (this.closed) fail(); return this.reader.seek(bytes) }
  session (opts = {}) { if (this.closed) fail(); return new ReadCoreView(this.reader, opts.valueEncoding ? c.from(opts.valueEncoding) : this.encoding) }
  snapshot (opts) { return this.session(opts) }
  async update () { await this.ready(); return false }
  async close () { this.closed = true }
}
function normalizedPath (name) {
  if (typeof name !== 'string' || name.includes('\0') || name.split('/').includes('..')) fail('invalid retained-read path')
  return posix.resolve('/', name)
}

class RetainedDrive {
  constructor (owner, selected) {
    this.owner = owner; this.selected = selected; this.version = selected.driveVersion; this.closed = false; this.closing = null
    this.key = owner.drive.key
    this.metadata = new VerifiedCore(owner.drive.core, selected.metadata, owner, true)
    this.blobReader = new VerifiedCore(owner.drive.blobs.core, selected.blobs, owner, false)
    this.bee = null; this.files = null; this.blobs = null
  }

  async ready () {
    if (this.bee) return
    await this.metadata.ready(); await this.blobReader.ready()
    this.bee = new Hyperbee(new ReadCoreView(this.metadata), { keyEncoding: 'utf-8', valueEncoding: 'json', extension: false, readonly: true, checkout: this.version, sessions: false })
    await this.bee.ready()
    const header = await this.bee.getHeader({ wait: false })
    const contentFeed = header?.metadata?.contentFeed
    const blobKey = contentFeed ? Buffer.from(contentFeed).subarray(0, 32) : Hyperdrive.getContentKey(this.metadata.live.manifest, this.metadata.live.key)
    if (!blobKey || blobKey.toString('hex') !== this.selected.blobs.key) fail('retained-read content key binding mismatch')
    this.files = this.bee.sub('files', { keyEncoding: 'utf-8', valueEncoding: 'json' })
    this.blobs = new Hyperblobs(new ReadCoreView(this.blobReader))
  }

  async entry (name) {
    await this.ready(); await this.owner.check()
    const result = await this.files.get(normalizedPath(name), { wait: false, update: false })
    await this.owner.check()
    // Callers cannot poison Hyperbee's cached decoded metadata for later reads.
    return result === null ? null : structuredClone(result)
  }

  async layout (name, opts = {}) {
    const node = await this.entry(name)
    const blob = node?.value?.blob
    if (!blob) fail('selected local file missing')
    for (const key of ['byteOffset', 'byteLength', 'blockOffset', 'blockLength']) if (!safe(blob[key])) fail('invalid retained-read blob descriptor')
    if (!safe(blob.blockOffset + blob.blockLength) || blob.blockOffset + blob.blockLength > this.selected.blobs.length) fail('retained-read blob outside selection')
    const start = opts.start === undefined ? 0 : opts.start
    const length = opts.length === undefined ? (opts.end === undefined ? blob.byteLength - start : opts.end - start + 1) : opts.length
    if (!safe(start) || !safe(length) || !safe(start + length) || start + length > blob.byteLength || length > RETAINED_READ_LIMITS.responseBytes) fail('retained-read response limit exceeded', 'RETAINED_LOCAL_LIMIT')
    let map = null
    if (blob.blockMap) {
      if (blob.blockLength > 64) fail('retained-read block map limit exceeded', 'RETAINED_LOCAL_LIMIT')
      map = await this.blobs.getBlockMap(blob)
      if (!Array.isArray(map?.blocks) || map.blocks.length > RETAINED_READ_LIMITS.requestBlocks) fail('retained-read block map limit exceeded', 'RETAINED_LOCAL_LIMIT')
      let total = 0
      for (const item of map.blocks) {
        if (!safe(item.index) || item.index >= this.selected.blobs.length || !safe(item.byteLength) || item.byteLength > RETAINED_READ_LIMITS.blockBytes) fail('invalid retained-read block map')
        total += item.byteLength
        if (!safe(total)) fail('invalid retained-read block map size')
      }
      if (total !== blob.byteLength) fail('retained-read block map length mismatch')
    } else if (blob.byteLength > 0) {
      const begin = await this.blobReader.seek(blob.byteOffset)
      const end = await this.blobReader.seek(blob.byteOffset + blob.byteLength)
      if (begin[0] !== blob.blockOffset || begin[1] !== 0 || end[0] !== blob.blockOffset + blob.blockLength || end[1] !== 0) fail('retained-read blob range mismatch')
    }
    await this.owner.check()
    return { blob, start, length, map }
  }

  async * chunks (name, opts = {}) {
    const { blob, start, length, map } = await this.layout(name, opts)
    let remaining = length
    if (remaining === 0) return
    if (map) {
      let offset = 0
      for (const item of map.blocks) {
        const finish = offset + item.byteLength
        if (finish <= start) { offset = finish; continue }
        const bytes = await this.blobReader.get(item.index)
        if (bytes.length !== item.byteLength) fail('retained-read mapped block size mismatch')
        const from = Math.max(0, start - offset); const size = Math.min(bytes.length - from, remaining)
        yield bytes.subarray(from, from + size)
        remaining -= size; offset = finish
        if (remaining === 0) break
      }
    } else {
      let [index, offset] = await this.blobReader.seek(blob.byteOffset + start)
      while (remaining > 0) {
        if (index >= blob.blockOffset + blob.blockLength) fail('retained-read body range exceeded')
        const bytes = await this.blobReader.get(index++)
        const size = Math.min(bytes.length - offset, remaining)
        if (size <= 0) fail('invalid retained-read body block')
        yield bytes.subarray(offset, offset + size)
        remaining -= size; offset = 0
      }
    }
    if (remaining !== 0) fail('selected local body incomplete')
  }

  createReadStream (name, opts = {}) { return Readable.from(this.chunks(name, opts), { objectMode: false }) }
  async get (name) {
    const parts = []
    for await (const part of this.chunks(name)) parts.push(part)
    return Buffer.concat(parts)
  }

  close () {
    if (this.closing) return this.closing
    this.closing = (async () => {
      this.owner.closing = true
      await Promise.allSettled([...this.owner.operations])
      if (this.files) await this.files.close()
      if (this.bee) await this.bee.close()
      await this.metadata.close(); await this.blobReader.close()
      this.closed = true
      this.owner.release()
    })()
    this.closing.catch(() => { this.closing = null })
    return this.closing
  }
}

function entryPolicy (entry) {
  return retainedReadCanonicalBytes(Object.fromEntries(['appId', 'type', 'parentKey', 'mountPath', 'privacyTier', 'blind', 'storageClass', 'availabilityClass', 'custodyIntentId', 'blindContentId', 'ciphertextRoot', 'contentVersion', 'retainUntil', 'shardIds', 'publisherPubkey', 'revocable', 'leaseManaged', 'maxStorage'].map(key => [key, entry[key] ?? null])))
}
class RetainedReadController {
  #node
  #selection
  #entries
  #active
  #closed
  constructor (node, selection) {
    if (!SELECTED.has(selection)) fail('retained-read selection is not verified')
    this.#node = node; this.#selection = selection; this.#entries = new Map(selection.drives.map(entry => [entry.appKey, entry])); this.#active = new Set(); this.#closed = false
  }

  versionFor (key) { return this.#closed ? null : this.#entries.get(key)?.driveVersion || null }
  async acquire (key, { signal, expectedVersion } = {}) {
    const selected = this.#entries.get(key)
    if (this.#closed || !selected || (expectedVersion !== undefined && expectedVersion !== selected.driveVersion)) return null
    const node = this.#node; const entry = node.appRegistry.get(key)
    if (!entry || entry.blind || entry.privacyTier !== 'public' || entry.maxStorage !== null || !entry.drive?.blobs || entry.drive.encryptionKey) return null
    const borrowed = node.appLifecycle.acquireDriveReadLease(key)
    if (!borrowed || borrowed.drive !== entry.drive) { borrowed?.release(); return null }
    const generation = node.appRegistry._entryGenerations.get(key)
    const policy = entryPolicy(entry)
    const controller = this
    let released = false
    const owner = {
      drive: entry.drive,
      metadataReads: new Set(),
      operations: new Set(),
      closing: false,
      blocks: 0,
      bytes: 0,
      run (operation) {
        if (this.closing) return Promise.reject(Object.assign(new Error('retained reader closing'), { code: 'RETAINED_LOCAL_UNAVAILABLE' }))
        const pending = Promise.resolve().then(operation)
        this.operations.add(pending)
        pending.then(() => this.operations.delete(pending), () => this.operations.delete(pending))
        return pending
      },
      charge (bytes) { this.blocks++; this.bytes += bytes; if (this.blocks > RETAINED_READ_LIMITS.requestBlocks || this.bytes > RETAINED_READ_LIMITS.requestBytes) fail('retained-read work limit exceeded', 'RETAINED_LOCAL_LIMIT') },
      release () { if (released) return; released = true; borrowed.release(); controller.#active.delete(facade) },
      checkCurrent () {
        const authority = node.storageAdmission?.get('drive:' + key)
        if (this.closing || controller.#closed || signal?.aborted || node._scope?.aborted || node.appLifecycle._shutdownFenced || node.appRegistry.get(key) !== entry || entry.retiring || node.appRegistry.isRetirementPending(key) || node.appRegistry._entryGenerations.get(key) !== generation || !entryPolicy(entry).equals(policy) || node.storageAdmission?.fatalReason || authority?.state !== 'unknown-recovery' || authority.boundBytes !== null || authority.kind !== 'drive' || authority.recovery !== true || !equalJSON(rootIdentity(node), controller.#selection.root)) fail()
      },
      async check () {
        this.checkCurrent()
        const raw = await node.appRegistry._bee.get(key)
        if (!raw || retainedReadRowSha256(raw.value) !== selected.registryRowSha256) fail('retained-read registry row changed')
        this.checkCurrent()
        for (const index of this.metadataReads) if (!(await entry.drive.core.has(index))) fail('selected local metadata was cleared')
        this.checkCurrent()
      }
    }
    const facade = new RetainedDrive(owner, selected)
    this.#active.add(facade)
    try {
      await owner.check(); await facade.ready(); await owner.check()
      const publicDrive = Object.freeze({
        get key () { return Buffer.from(facade.key) },
        get version () { return facade.version },
        get closed () { return facade.closed },
        ready: () => facade.ready(),
        entry: name => facade.entry(name),
        get: name => facade.get(name),
        createReadStream: (name, options) => facade.createReadStream(name, options),
        close: () => facade.close()
      })
      return Object.freeze({ drive: publicDrive, immutable: true, retainedLocal: true, pinnedVersion: selected.driveVersion, release: () => { if (facade.closed) owner.release() } })
    } catch (error) {
      await facade.close()
      if (error.code === 'RETAINED_LOCAL_UNAVAILABLE') return null
      throw error
    }
  }

  async close () {
    this.#closed = true
    for (const facade of [...this.#active]) await facade.close()
  }

  async stop () { await this.close() }
}

export async function createRetainedReadController (node, declaration = node.config?.retainedReadCapability) {
  if (declaration == null) return null
  if (!node.storageAdmission?.recoveryReady || node.storageAdmission.fatalReason || !node.appRegistry?._bee) fail('retained-read inventory is not ready')
  return new RetainedReadController(node, loadSelection(node, declaration))
}

/** Offline inspection only. The result is a proposal ingredient, never a
 * runtime authorization. Only the externally pinned loader grants reads. */
export async function inspectRetainedReadCore (core, { maxCoreBlocks, maxLocalBytes } = {}) {
  if (!safe(maxCoreBlocks) || !safe(maxLocalBytes) || maxCoreBlocks < 1 || maxLocalBytes < 1) fail('explicit retained inspection limits required')
  await core.ready()
  if (core.encryption || core.length > maxCoreBlocks) fail('unsupported or oversized retained inspection core')
  const selected = { key: core.key.toString('hex'), fork: core.fork, length: core.length, byteLength: core.byteLength, treeHash: null }
  if (core.length === 0) selected.treeHash = (await core.treeHash(0)).toString('hex')
  else {
    const head = await core.proof({ upgrade: { start: 0, length: core.length } })
    proofShape(head)
    const batch = await core.verifyFullyRemote(head)
    selected.treeHash = batch.hash().toString('hex')
    verifyBatch(batch, selected)
  }
  descriptor(selected)
  let presentBlocks = 0; let localBytes = 0
  const presence = createHash('sha256')
  const owner = {
    metadataReads: new Set(),
    checkCurrent () { if (!headMatches(core, selected)) fail('retained inspection head changed') },
    async check () { this.checkCurrent() },
    run: operation => Promise.resolve().then(operation),
    charge (bytes) { localBytes += bytes; if (!safe(localBytes) || localBytes > maxLocalBytes) fail('retained inspection byte limit exceeded', 'RETAINED_LOCAL_LIMIT') }
  }
  const reader = new VerifiedCore(core, selected, owner, false)
  try {
    await reader.ready()
    for (let i = 0; i < selected.length; i++) {
      if (await core.has(i)) { await reader.get(i); presentBlocks++; presence.update('1') } else presence.update('0')
    }
    owner.checkCurrent()
    return { descriptor: selected, presentBlocks, missingBlocks: selected.length - presentBlocks, localBytes, presenceSha256: 'sha256:' + presence.digest('hex') }
  } finally { await reader.close() }
}
