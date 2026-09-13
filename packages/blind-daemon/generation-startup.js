import path from 'node:path'
import { BlindStoreSession, acquireBlindStoreSessionTransactionLease, verifyBlindStoreSessionTransactionLease } from './store-session.js'
import { inspectBlindGenerationStore, verifyBlindGenerationStoreEvidence, closeBlindGenerationStoreEvidence } from './generation-store-evidence.js'
import { inspectBlindStoreGenerationFloor, openBlindStoreGenerationFloor, BLIND_STORE_READER_MODE } from './storage-generation-v12.js'

const HANDOFFS = new WeakMap()

export async function verifyBlindGenerationStartupHandoff (handoff, root) {
  const state = HANDOFFS.get(handoff)
  if (!state || state.root !== root || !state.owner.committed || state.owner.closed) throw new Error('invalid or expired generation startup handoff')
  await verifyBlindStoreSessionTransactionLease(state.lease, root)
  await verifyBlindGenerationStoreEvidence(state.evidence, root, state.lease)
  return state.lease
}

// Every read and ownership acquisition finishes before the first mutation.
// The returned owner must outlive its engines: close engines, then this owner.
export async function prepareBlindGenerationStartup (options) {
  const { stores, manifestKey, installationIdentity } = options
  if (!Array.isArray(stores) || stores.length < 1 || stores.length > 3 || stores[0].role !== 'cell' ||
      stores.some(store => store.root !== store.engineOptions.root) ||
      new Set(stores.map(store => store.role)).size !== stores.length || new Set(stores.map(store => store.root)).size !== stores.length) {
    throw new TypeError('startup requires CELL and unique participating blind roots')
  }
  if (options.readerMode !== BLIND_STORE_READER_MODE.BLIND_ONLY) throw new Error('only blind-only reader mode is implemented')
  const controlDirectory = path.join(stores[0].root, 'control')
  const owner = { committed: false, closed: false }
  const acquired = []
  async function releaseValidation () {
    let failure = null
    for (const entry of acquired) {
      try { if (entry.evidence) await closeBlindGenerationStoreEvidence(entry.evidence) } catch (error) { failure ||= error }
    }
    if (failure) throw failure
  }
  async function close () {
    if (owner.closed) return
    owner.closed = true
    let failure = null
    for (const entry of acquired) entry.lease?.release()
    for (const entry of [...acquired].reverse()) {
      try { if (entry.evidence) await closeBlindGenerationStoreEvidence(entry.evidence) } catch (error) { failure ||= error }
      try { await entry.session.close() } catch (error) { failure ||= error }
    }
    if (failure) throw failure
  }
  try {
    for (const store of stores) {
      const session = new BlindStoreSession({
        root: store.root,
        validationOnly: true,
        allowUnmanifestedWal: true,
        allowPristineBootstrap: options.allowFreshGenesis === true,
        faultInjector: options.faultInjector
      })
      const entry = { ...store, session }
      acquired.push(entry)
      await session.open()
      entry.lease = await acquireBlindStoreSessionTransactionLease(session.lockContext(), store.root)
    }
    if (options.validateBindings) await options.validateBindings()
    for (const entry of acquired) {
      entry.evidence = await inspectBlindGenerationStore({ ...entry, limits: options.limits })
    }
    const currentStores = acquired.map(entry => ({
      role: entry.role,
      storeIdentity: installationIdentity,
      storeEvidence: entry.evidence.storeEvidence,
      hasIrreversibleState: entry.evidence.hasIrreversibleState
    }))
    const floorOptions = { manifestKey, installationIdentity, currentStores }
    let inspection = null
    let creationProof
    try {
      inspection = await inspectBlindStoreGenerationFloor(controlDirectory, floorOptions)
    } catch (error) {
      const allFresh = acquired.every(entry => entry.session.rootClassification.kind === 'pristine' ||
        (entry.session.rootClassification.kind === 'genesis-incomplete' &&
          entry.session.rootClassification.controlNames.every(name => name === 'writer.lock.v1' ||
            /^\.blind-store-generation-(?:record|head)\.tmp-[0-9a-f]{32}$/.test(name))))
      const missing = error.code === 'BLIND_STORE_GENERATION_MISSING' || (error.code === 'ENOENT' && allFresh)
      if (!missing || (!(options.allowFreshGenesis === true && allFresh) && options.allowSealedGenesis !== true)) throw error
      if (!allFresh && !acquired[0].evidence.snapshotValidated) throw new Error('generation bootstrap requires a verified sealed snapshot')
      if (currentStores.some(store => store.hasIrreversibleState)) throw new Error('cannot create generation authority over irreversible state')
      creationProof = allFresh ? { freshStoreBindingCreated: true } : { sealedGenesisValidated: true }
    }
    if (options.faultInjector) await options.faultInjector('generation-startup:after-inspection', Object.freeze({ inspection }))
    // Revalidate the exact observed roots, WALs, bindings and generation chain
    // while every lease remains held, before changing any family.
    for (const entry of acquired) {
      await entry.session.assertUnchanged()
      await verifyBlindGenerationStoreEvidence(entry.evidence, entry.root, entry.lease)
    }
    if (options.validateBindings) await options.validateBindings()
    let refreshed = null
    try { refreshed = await inspectBlindStoreGenerationFloor(controlDirectory, floorOptions) } catch (error) {
      const pristineControlAbsent = acquired[0].session.rootClassification.kind === 'pristine' && error.code === 'ENOENT'
      if (inspection !== null || (error.code !== 'BLIND_STORE_GENERATION_MISSING' && !pristineControlAbsent)) throw error
    }
    if (JSON.stringify(refreshed) !== JSON.stringify(inspection)) throw new Error('generation snapshot changed before startup mutation')
    for (const entry of acquired) await entry.session.prepareMutation(entry.lease)
    if (options.bindIdentities) await options.bindIdentities(acquired.map(entry => ({ root: entry.root, lease: entry.lease })))
    for (const entry of acquired) await verifyBlindGenerationStoreEvidence(entry.evidence, entry.root, entry.lease)
    const floor = await openBlindStoreGenerationFloor(controlDirectory, {
      ...floorOptions,
      expectedInspection: inspection,
      allowCreate: creationProof != null,
      creationProof,
      faultInjector: options.faultInjector
    })
    floor.assertReaderMode(options.readerMode)
    owner.committed = true
    const handoffs = new Map()
    for (const entry of acquired) {
      const handoff = Object.freeze({ root: entry.root })
      HANDOFFS.set(handoff, { ...entry, owner })
      handoffs.set(entry.role, handoff)
    }
    return Object.freeze({
      floor,
      releaseValidation,
      handoffs,
      close,
      inspection,
      currentStores,
      usage: Object.freeze(acquired.map(entry => ({ role: entry.role, ...entry.evidence.usage })))
    })
  } catch (error) {
    await close().catch(() => {})
    throw error
  }
}
