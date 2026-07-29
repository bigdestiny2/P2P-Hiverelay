import b4a from 'b4a'
import sodium from 'sodium-universal'
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { signAppRelease } from '../../packages/core/core/release-lifecycle.js'
import { serializeSeedRequestForReplaySigning } from '../../packages/core/core/protocol/seed-request.js'

export const DEFAULT_RELEASE_STORAGE_BUDGET = 1024 * 1024 * 1024
export const DEFAULT_RELEASE_ROLLBACK_WINDOW = 3
export const ROTATION_POINTER_RESERVE_BYTES = 64 * 1024
export const RELEASE_STATE_FILE = 'release-state.json'

export function parseStorageBytes (input) {
  const units = {
    B: 1,
    KB: 1024,
    MB: 1024 ** 2,
    GB: 1024 ** 3,
    TB: 1024 ** 4,
    KIB: 1024,
    MIB: 1024 ** 2,
    GIB: 1024 ** 3,
    TIB: 1024 ** 4
  }
  const match = String(input || '').trim().match(/^(\d+(?:\.\d+)?)\s*(TiB|GiB|MiB|KiB|TB|GB|MB|KB|B)?$/i)
  if (!match) return null
  const value = Math.floor(Number(match[1]) * units[(match[2] || 'B').toUpperCase()])
  return Number.isSafeInteger(value) && value > 0 ? value : null
}

export function formatStorageBytes (bytes) {
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  let value = bytes
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit++
  }
  return `${value.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`
}

export async function loadReleaseState (storagePath) {
  try {
    const parsed = JSON.parse(await readFile(join(storagePath, RELEASE_STATE_FILE), 'utf8'))
    if (parsed && parsed.schemaVersion === 1 && parsed.apps && typeof parsed.apps === 'object') return parsed
  } catch (err) {
    if (err && err.code !== 'ENOENT') throw new Error(`could not read ${RELEASE_STATE_FILE}: ${err.message}`)
  }
  return { schemaVersion: 1, apps: {} }
}

export async function saveReleaseState (storagePath, state) {
  await mkdir(storagePath, { recursive: true })
  const target = join(storagePath, RELEASE_STATE_FILE)
  const temporary = target + '.tmp'
  await writeFile(temporary, JSON.stringify(state, null, 2), { mode: 0o600 })
  await rename(temporary, target)
}

export function publisherKeyPairForApp (state, appId) {
  if (!state || !state.apps || !appId) throw new Error('publisher state and appId are required')
  const current = state.apps[appId] || {}
  let seed
  if (typeof current.publisherSeed === 'string' && /^[0-9a-f]{64}$/i.test(current.publisherSeed)) {
    seed = b4a.from(current.publisherSeed, 'hex')
  } else {
    seed = b4a.alloc(32)
    sodium.randombytes_buf(seed)
  }
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, seed)
  const publisherPubkey = b4a.toString(publicKey, 'hex')
  if (current.publisherPubkey && current.publisherPubkey.toLowerCase() !== publisherPubkey) {
    throw new Error(`publisher key state for ${appId} is inconsistent`)
  }
  state.apps[appId] = {
    ...current,
    publisherSeed: b4a.toString(seed, 'hex'),
    publisherPubkey
  }
  return { publicKey, secretKey }
}

export function createSignedSeedRequest ({
  appKey,
  maxStorageBytes,
  blind = false,
  keyPair,
  issuedAt = Date.now(),
  requestNonce = null
}) {
  const nonce = requestNonce || b4a.alloc(16)
  if (!requestNonce) sodium.randombytes_buf(nonce)
  const request = {
    appKey: b4a.from(appKey, 'hex'),
    discoveryKeys: [],
    replicationFactor: 3,
    maxStorageBytes,
    ttlSeconds: 30 * 24 * 3600,
    bountyRate: 0,
    revocable: true,
    unseedFreezeMs: 0,
    durability: 0,
    issuedAt,
    requestNonce: nonce,
    publisherPubkey: keyPair.publicKey
  }
  const signature = b4a.alloc(64)
  sodium.crypto_sign_detached(signature, serializeSeedRequestForReplaySigning(request), keyPair.secretKey)
  return {
    appKey,
    replicationFactor: request.replicationFactor,
    maxStorageBytes,
    ttlSeconds: request.ttlSeconds,
    bountyRate: request.bountyRate,
    revocable: request.revocable,
    unseedFreezeMs: request.unseedFreezeMs,
    durability: request.durability,
    issuedAt,
    requestNonce: b4a.toString(nonce, 'hex'),
    publisherPubkey: b4a.toString(keyPair.publicKey, 'hex'),
    publisherSignature: b4a.toString(signature, 'hex'),
    type: 'app',
    blind
  }
}

function priorReleaseHistory (appState) {
  return Array.isArray(appState?.releases)
    ? appState.releases.filter(release => release && typeof release.driveKey === 'string')
    : []
}

export function createPublisherRelease ({
  appState = {},
  appId,
  version,
  driveKey,
  previousDriveKey = null,
  storageBudgetBytes,
  rollbackWindow,
  treeHash,
  issuedAt = Date.now(),
  keyPair
}) {
  const sequence = Number.isSafeInteger(appState.sequence) && appState.sequence > 0
    ? appState.sequence + 1
    : 1
  const priorGeneration = Number.isSafeInteger(appState.generation) && appState.generation > 0
    ? appState.generation
    : 1
  const generation = previousDriveKey ? priorGeneration + 1 : priorGeneration
  const history = priorReleaseHistory(appState)
  const relevantHistory = history.slice(-Math.max(0, rollbackWindow - 1))
  const rollbackDriveKeys = []
  const seen = new Set([driveKey])
  for (let i = relevantHistory.length - 1; i >= 0 && rollbackDriveKeys.length < rollbackWindow - 1; i--) {
    const key = relevantHistory[i].driveKey.toLowerCase()
    if (!/^[0-9a-f]{64}$/.test(key) || seen.has(key)) continue
    seen.add(key)
    rollbackDriveKeys.push(key)
  }
  if (previousDriveKey && rollbackWindow > 1 && !seen.has(previousDriveKey)) {
    rollbackDriveKeys.unshift(previousDriveKey)
    if (rollbackDriveKeys.length > rollbackWindow - 1) rollbackDriveKeys.pop()
  }

  const release = signAppRelease({
    protocolVersion: 1,
    appId,
    version,
    sequence,
    generation,
    driveKey,
    previousDriveKey,
    rotationReason: previousDriveKey ? 'storage-budget' : null,
    storageBudgetBytes,
    rollbackWindow,
    rollbackDriveKeys,
    treeHash,
    issuedAt
  }, keyPair)

  const releases = [...history, {
    version,
    sequence,
    generation,
    driveKey,
    issuedAt
  }].slice(-rollbackWindow)

  return {
    release,
    appState: {
      ...appState,
      publisherPubkey: release.publisherPubkey,
      sequence,
      generation,
      currentDriveKey: driveKey,
      releases
    }
  }
}

export function driveLogicalBytes (drive) {
  const metadataBytes = Number(drive?.core?.byteLength) || 0
  const blobBytes = Number(drive?.blobs?.core?.byteLength) || 0
  return metadataBytes + blobBytes
}

export function estimateReleaseAppendBytes (plan) {
  const mutations = (plan?.writes?.length || 0) + (plan?.removed?.length || 0)
  const contentBytes = Number(plan?.contentBytes) || 0
  return contentBytes + Math.max(4096, mutations * 4096)
}

export function shouldRotateReleaseDrive ({ driveBytes, plan, storageBudgetBytes }) {
  const projectedBytes = driveBytes + estimateReleaseAppendBytes(plan) + ROTATION_POINTER_RESERVE_BYTES
  return {
    rotate: projectedBytes > storageBudgetBytes,
    projectedBytes
  }
}
