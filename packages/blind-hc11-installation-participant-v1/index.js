import fs from 'node:fs'
import path from 'node:path'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import { createHash, createHmac, timingSafeEqual } from 'node:crypto'
import { performance } from 'node:perf_hooks'
import FDLock from 'fd-lock'
import {
  CORESTORE_GENERATION_ENVELOPE, CORESTORE_GENERATION_MIGRATION_BINDING,
  prepareCorestoreGenerationOpen, guardCorestoreGenerationReady,
  corestoreGenerationStatus
} from '../core/core/persistence/corestore-generation-envelope.js'
import { PROFILE_DIGEST } from '../blind-core-upstream-hc11-v1/format.js'
import { encode, decode } from '../blind-protocol/checkpoint-format-successor/codec.js'

// Resolve the actual accepted private graph, not a caller-provided constructor
// or the root's independently patched migration dependency selection.
const requireNative = createRequire(new URL('../blind-core-upstream-hc11-v1/package.json', import.meta.url))
const privateModules = path.resolve(fileURLToPath(new URL('../blind-core-upstream-hc11-v1/node_modules/', import.meta.url))) + path.sep
for (const name of ['corestore', 'hypercore', 'hypercore-storage']) {
  if (!requireNative.resolve(name).startsWith(privateModules)) throw new Error('Private native graph is absent; root dependency fallback is forbidden')
}
const Corestore = requireNative('corestore')
const versions = Object.freeze(Object.fromEntries(['corestore', 'hypercore', 'hypercore-storage'].map(name => [name, requireNative(name + '/package.json').version])))
if (versions.corestore !== '7.11.1' || versions.hypercore !== '11.34.1' || versions['hypercore-storage'] !== '3.2.0') throw new Error('Unsupported private native dependency profile')
const OWNERS = new Map()
const TOKENS = new WeakMap()
const MAX_FILE = 1024 * 1024
const fail = (code, message) => { throw Object.assign(new Error(message), { code }) }
const sha = bytes => createHash('sha256').update(bytes).digest()
const tagged = bytes => 'sha256:' + sha(bytes).toString('hex')
const same = (a, b) => Buffer.from(a).equals(Buffer.from(b))
const stable = value => Array.isArray(value) ? value.map(stable) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])])) : value
const canonical = value => Buffer.from(JSON.stringify(stable(value)) + '\n')
const hash = (value, label) => {
  if (!(value instanceof Uint8Array) || value.byteLength !== 32 || value.every(n => n === 0)) fail('HC11_PARTICIPANT_INPUT', label + ' must be nonzero bytes32')
  return Buffer.from(value)
}
const timeout = value => {
  if (!Number.isSafeInteger(value) || value < 10 || value > 60000) fail('HC11_PARTICIPANT_INPUT', 'timeoutMillis must be10..60000')
  return value
}
const identity = st => [st.dev, st.ino, st.uid, st.mode].join(':')
function privateDirectory (file) {
  const st = fs.lstatSync(file)
  if (!st.isDirectory() || st.isSymbolicLink() || (st.mode & 0o077) !== 0 || (process.getuid && st.uid !== process.getuid()) || fs.realpathSync(file) !== file) fail('HC11_PARTICIPANT_IDENTITY', 'Unsafe or rebound directory')
  return identity(st)
}
function readFile (file, maximum = MAX_FILE, privateMode = false) {
  const before = fs.lstatSync(file)
  if (!before.isFile() || before.isSymbolicLink() || before.size < 1 || before.size > maximum || (process.getuid && before.uid !== process.getuid()) || (privateMode && (before.mode & 0o777) !== 0o600)) fail('HC11_PARTICIPANT_IDENTITY', 'Unsafe or oversized participant file')
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW)
  try {
    const opened = fs.fstatSync(fd)
    if (identity(opened) !== identity(before) || opened.size !== before.size) fail('HC11_PARTICIPANT_IDENTITY', 'Participant file changed while opening')
    const bytes = Buffer.alloc(opened.size)
    let offset = 0
    while (offset < bytes.length) {
      const count = fs.readSync(fd, bytes, offset, bytes.length - offset, offset)
      if (!count) fail('HC11_PARTICIPANT_IDENTITY', 'Short participant file')
      offset += count
    }
    const after = fs.fstatSync(fd)
    if (after.size !== opened.size || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs || identity(fs.lstatSync(file)) !== identity(opened)) fail('HC11_PARTICIPANT_IDENTITY', 'Participant file changed during read')
    return { bytes, identity: identity(opened) }
  } finally { fs.closeSync(fd) }
}
function signedBody (bytes, key) {
  const signed = JSON.parse(bytes.toString('utf8'))
  if (!signed || !/^[0-9a-f]{64}$/.test(signed.mac)) fail('HC11_PARTICIPANT_AUTH', 'Invalid participant MAC')
  const { mac, ...body } = signed
  const expected = createHmac('sha256', key).update(canonical(body)).digest()
  if (!timingSafeEqual(Buffer.from(mac, 'hex'), expected) || !same(bytes, canonical(signed))) fail('HC11_PARTICIPANT_AUTH', 'Noncanonical or unauthenticated participant bytes')
  return body
}
function optionsOf (value) {
  const allowed = ['root', 'rootId', 'profileDigest', 'envelope', 'timeoutMillis']
  if (!value || typeof value !== 'object' || Object.keys(value).some(key => !allowed.includes(key))) fail('HC11_PARTICIPANT_INPUT', 'Only fixed-source participant options are supported')
  if (typeof value.root !== 'string' || !path.isAbsolute(value.root) || path.normalize(value.root) !== value.root || value.root.includes('\0')) fail('HC11_PARTICIPANT_INPUT', 'Canonical absolute envelope root required')
  if (!same(hash(value.profileDigest, 'profileDigest'), PROFILE_DIGEST)) fail('HC11_PARTICIPANT_INPUT', 'Explicit accepted private HC11 profile required')
  const envelope = value.envelope
  const fields = ['mode', 'expectedInstallationId', 'expectedAuthorityKeySha256', 'expectedManifestSha256', 'participant']
  if (!envelope || Object.keys(envelope).length !== fields.length || fields.some(key => typeof envelope[key] !== 'string')) fail('HC11_PARTICIPANT_INPUT', 'Externally pinned envelope configuration required')
  return { root: value.root, rootId: hash(value.rootId, 'rootId'), envelope: Object.freeze({ ...envelope }), timeoutMillis: timeout(value.timeoutMillis ?? 10000) }
}
export const STATUS = Object.freeze({
  profile: 'private-hc11-installation-participant-v1',
  versions,
  defaultSelected: false,
  productionReady: false,
  sharedAuthorityComposed: false,
  commonReadyAcknowledged: false,
  pruneAuthority: false,
  nodeOnly: true
})

// A successful read is passive typed evidence. Only a future fixed-source
// common coordinator may commit it; this function never grants ready or prune.
export async function readPreparedHc11Participant (token, options = {}) {
  const state = TOKENS.get(token)
  if (!state) fail('HC11_PARTICIPANT_TOKEN', 'Forged or unsupported HC11 participant token')
  return state.read(options)
}

export class Hc11InstallationParticipantV1 {
  #options
  #prepared = null
  #store = null
  #lock = null
  #fd = null
  #paths = null
  #files = null
  #activationPins = null
  #evidence = null
  #trigger = null
  #token = null
  #job = null
  #closing = false
  #closed = false
  #failure = null
  #cleanup = null
  #reserved = false

  constructor (options) { this.#options = optionsOf(options) }

  status () {
    return Object.freeze({ ...STATUS, prepared: this.#token !== null && !this.#failure && !this.#closing && !this.#job, custodyHeld: this.#reserved, inFlight: this.#job ? 1 : 0, closing: this.#closing, closed: this.#closed, quarantineReason: this.#failure?.code || null })
  }

  async prepare (options = {}) {
    if (this.#token) fail('HC11_PARTICIPANT_STATE', 'Participant already prepared')
    return this.#run(options, async check => {
      const o = this.#options
      // Read-only envelope validation precedes any native opening. Imported
      // legacy/device-rebind profiles need their own accepted composition.
      this.#prepared = prepareCorestoreGenerationOpen(o.root, o.envelope)
      if (this.#prepared.importReceipt || this.#prepared.restoreReceipt) fail('HC11_PARTICIPANT_PROFILE', 'Only fresh HC11 envelopes are qualified by this private participant')
      if (OWNERS.has(o.root)) fail('HC11_PARTICIPANT_BUSY', 'Installation custody is already held')
      OWNERS.set(o.root, this); this.#reserved = true
      const p = this.#prepared.binding.paths
      this.#paths = new Map([o.root, p.authority, p.generations, p.generationRoot].map(file => [file, privateDirectory(file)]))
      this.#files = new Map([p.installationId, p.authorityKey, p.envelope].map(file => [file, readFile(file, file === p.envelope ? MAX_FILE : 32, true)]))
      this.#fd = fs.openSync(p.installationId, fs.constants.O_RDWR | fs.constants.O_NOFOLLOW)
      if (identity(fs.fstatSync(this.#fd)) !== this.#files.get(p.installationId).identity) fail('HC11_PARTICIPANT_IDENTITY', 'Installation inode changed at custody acquisition')
      this.#lock = new FDLock(this.#fd)
      await this.#lock.ready()
      check(); this.#verifyCustody()
      this.#store = new Corestore(this.#prepared.storage)
      guardCorestoreGenerationReady(this.#store, this.#prepared)
      await this.#store.ready()
      check(); this.#verifyCustody()
      const observed = await this.#observe(check)
      check(); this.#verifyCustody()
      this.#verifyPins(observed.pins)
      this.#activationPins = observed.pins
      this.#evidence = encode('Hc11Evidence', observed.evidence)
      this.#trigger = Buffer.from(observed.trigger)
      const token = Object.freeze({})
      this.#token = token
      TOKENS.set(token, { read: input => this.#read(input) })
      return token
    })
  }

  #verifyCustody () {
    if (!this.#reserved || OWNERS.get(this.#options.root) !== this || !this.#lock?.locked || this.#closed) fail('HC11_PARTICIPANT_CUSTODY', 'Native installation custody is unavailable')
    for (const [file, expected] of this.#paths) if (privateDirectory(file) !== expected) fail('HC11_PARTICIPANT_IDENTITY', 'Installation directory was rebound')
    for (const [file, expected] of this.#files) {
      const actual = readFile(file, expected.bytes.length, true)
      if (actual.identity !== expected.identity || !same(actual.bytes, expected.bytes)) fail('HC11_PARTICIPANT_IDENTITY', 'Installation authority file changed')
    }
    if (identity(fs.fstatSync(this.#fd)) !== this.#files.get(this.#prepared.binding.paths.installationId).identity) fail('HC11_PARTICIPANT_CUSTODY', 'Native installation lease changed')
  }

  async #observe (check) {
    this.#verifyCustody()
    const fresh = prepareCorestoreGenerationOpen(this.#options.root, this.#options.envelope)
    if (fresh.importReceipt || fresh.restoreReceipt) fail('HC11_PARTICIPANT_PROFILE', 'Unsupported envelope profile change')
    const binding = this.#prepared.binding
    const p = binding.paths
    const triggerFile = readFile(p.trigger, MAX_FILE, true)
    const trigger = signedBody(triggerFile.bytes, binding.authorityKey)
    const status = corestoreGenerationStatus(this.#store)
    if (!status?.ready || status.receipt.triggerRecordSha256 !== tagged(triggerFile.bytes) || this.#store.closing || this.#store.closed) fail('HC11_PARTICIPANT_AUTH', 'Guarded Corestore activation is unavailable or changed')
    const marker = readFile(path.join(p.generationRoot, 'CORESTORE'), 4096)
    const database = readFile(path.join(p.generationRoot, 'db/IDENTITY'), 4096)
    if (trigger.databaseIdentitySha256 !== tagged(database.bytes) || trigger.corestoreMarkerSha256 !== tagged(marker.bytes)) fail('HC11_PARTICIPANT_IDENTITY', 'Native database identity differs from original activation')
    const core = this.#store.get({ name: CORESTORE_GENERATION_ENVELOPE.activationCoreName })
    try {
      await core.ready(); check(); this.#verifyCustody()
      if (core.length !== 1 || core.fork !== 0) fail('HC11_PARTICIPANT_SENTINEL', 'Activation sentinel must have exact length1/fork0')
      const block = Buffer.from(await core.get(0)); check()
      const expected = canonical({ schema: CORESTORE_GENERATION_ENVELOPE.activationSchema, installationId: binding.installationId, manifestSha256: binding.manifestSha256, generation: CORESTORE_GENERATION_ENVELOPE.generation, participant: this.#options.envelope.participant, migrationTooling: CORESTORE_GENERATION_MIGRATION_BINDING })
      const sentinel = trigger.activationSentinel
      if (!same(block, expected) || !sentinel || sentinel.key !== Buffer.from(core.key).toString('hex') || sentinel.length !== 1 || sentinel.fork !== 0 || sentinel.blockSha256 !== tagged(block) || sentinel.participant !== this.#options.envelope.participant) fail('HC11_PARTICIPANT_SENTINEL', 'Original activation sentinel does not match actual native state')
      if (trigger.installationId !== binding.installationId || trigger.manifestSha256 !== binding.manifestSha256 || trigger.kind !== 'hc11-only-write') fail('HC11_PARTICIPANT_AUTH', 'Activation belongs to another installation envelope')
      const evidence = { rootId: Buffer.from(this.#options.rootId), envelopeManifestHash: Buffer.from(binding.manifestSha256.slice(7), 'hex'), databaseIdentityHash: sha(database.bytes), activationKey: Buffer.from(core.key), length: 1n, fork: 0n, activationBlockHash: sha(block), triggerReceiptHash: sha(triggerFile.bytes) }
      // All file/lease checks repeat after asynchronous native reads and close.
      return { evidence, trigger: triggerFile.bytes, pins: [[p.trigger, triggerFile], [path.join(p.generationRoot, 'CORESTORE'), marker], [path.join(p.generationRoot, 'db/IDENTITY'), database]] }
    } finally { await core.close(); check(); this.#verifyCustody() }
  }

  #verifyPins (pins) {
    for (const [file, expected] of pins) {
      const actual = readFile(file, expected.bytes.length, file === this.#prepared.binding.paths.trigger)
      if (actual.identity !== expected.identity || !same(actual.bytes, expected.bytes)) fail('HC11_PARTICIPANT_IDENTITY', 'Activation source changed after native read')
    }
  }

  async #read (options) {
    return this.#run(options, async check => {
      if (!this.#token) fail('HC11_PARTICIPANT_TOKEN', 'No prepared participant')
      this.#verifyCustody()
      this.#verifyPins(this.#activationPins)
      const observed = await this.#observe(check)
      this.#verifyPins(this.#activationPins)
      this.#verifyPins(observed.pins)
      if (!same(encode('Hc11Evidence', observed.evidence), this.#evidence) || !same(observed.trigger, this.#trigger)) fail('HC11_PARTICIPANT_IDENTITY', 'Prepared activation changed')
      check(); this.#verifyCustody()
      return Object.freeze({ evidence: decode('Hc11Evidence', Buffer.from(this.#evidence)), installationId: Buffer.from(this.#prepared.binding.installationId, 'hex'), triggerBytes: Buffer.from(this.#trigger), sharedAuthorityComposed: false, commonReadyAcknowledged: false })
    })
  }

  #run (options, work) {
    if (!options || Object.keys(options).some(k => !['signal', 'timeoutMillis'].includes(k))) fail('HC11_PARTICIPANT_INPUT', 'Only signal and timeout options accepted')
    if (this.#closing || this.#closed || this.#failure) fail('HC11_PARTICIPANT_FENCED', 'Participant is fenced or closing')
    if (this.#job) fail('HC11_PARTICIPANT_BUSY', 'Native participant work remains pending')
    const external = options.signal
    if (external != null && !(external instanceof AbortSignal)) fail('HC11_PARTICIPANT_INPUT', 'AbortSignal required')
    if (external?.aborted) fail('HC11_PARTICIPANT_ABORTED', 'Participant cancelled before admission')
    const expires = performance.now() + timeout(options.timeoutMillis ?? this.#options.timeoutMillis)
    const controller = new AbortController()
    const abort = () => controller.abort()
    const check = () => {
      if (performance.now() >= expires) abort()
      if (controller.signal.aborted || this.#closing) fail('HC11_PARTICIPANT_ABORTED', 'Participant cancelled or deadline expired')
    }
    external?.addEventListener('abort', abort, { once: true })
    if (external?.aborted) abort()
    const timer = setTimeout(abort, Math.max(0, expires - performance.now()))
    const cancellation = new Promise((resolve, reject) => controller.signal.addEventListener('abort', () => reject(Object.assign(new Error('Participant cancelled or deadline expired'), { code: 'HC11_PARTICIPANT_ABORTED' })), { once: true }))
    cancellation.catch(() => {})
    const job = { controller, done: null }; this.#job = job
    job.done = (async () => {
      try { check(); const result = await work(check); check(); return result } catch (error) { this.#failure ||= error; throw error } finally { clearTimeout(timer); external?.removeEventListener('abort', abort); this.#job = null }
    })()
    job.done.catch(() => {})
    return Promise.race([job.done, cancellation])
  }

  async close ({ timeoutMillis = 1000 } = {}) {
    timeout(timeoutMillis)
    this.#closing = true
    const job = this.#job; job?.controller.abort()
    if (!this.#cleanup) {
      this.#cleanup = (async () => {
        await job?.done.catch(() => {})
        if (this.#store) {
          await this.#store.close()
          if (!this.#store.closed) fail('HC11_PARTICIPANT_CLOSE', 'Native Corestore closure did not settle')
        }
        if (this.#lock) await this.#lock.close()
        else if (this.#fd !== null) fs.closeSync(this.#fd)
        if (this.#reserved && OWNERS.get(this.#options.root) === this) OWNERS.delete(this.#options.root)
        this.#reserved = false; this.#closed = true
        return true
      })().catch(error => { this.#failure ||= error; return false })
    }
    let timer
    try { return await Promise.race([this.#cleanup, new Promise(resolve => { timer = setTimeout(() => resolve(false), timeoutMillis) })]) } finally { clearTimeout(timer) }
  }
}
