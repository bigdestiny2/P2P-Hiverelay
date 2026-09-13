import b4a from 'b4a'
import { verifyBlindWalRecoveryScanResult } from './wal-recovery-scan.js'
import { verifyBlindStoreSessionTransactionLease } from './store-session.js'

// Data/validation helpers only. Capture brands and constructors stay inside each
// engine module; importing this helper cannot manufacture an original capture.
export function copyFamilyCaptureValue (value) {
  if (value == null || typeof value !== 'object') return value
  if (ArrayBuffer.isView(value)) return b4a.from(value)
  if (value instanceof Map) return new Map([...value].map(([key, child]) => [key, copyFamilyCaptureValue(child)]))
  if (Array.isArray(value)) return value.map(copyFamilyCaptureValue)
  return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, copyFamilyCaptureValue(child)]))
}

export function familyCaptureLimits (limits = {}, maximumRows = 262144) {
  if (!Number.isSafeInteger(maximumRows) || maximumRows < 1 || maximumRows > 262144) throw new TypeError('maximumRows is outside the private capture bound')
  for (const [field, ceiling] of [['maximumWalBytes', 256 * 1024 * 1024], ['maximumWalFrames', 262144]]) {
    if (limits[field] != null && (!Number.isSafeInteger(limits[field]) || limits[field] < 1 || limits[field] > ceiling)) throw new TypeError(`${field} exceeds the private observed-work bound`)
  }
  return maximumRows
}

export function checkFamilyCaptureStateBound (engine, maximumRows, complete = false) {
  let count = 1 + engine.integrityEvidence.length
  for (const field of ['spends', 'requestResults', 'cells', 'inboxes', 'frames']) count += engine[field]?.size || 0
  count += engine.retryPins?.size || 0
  if (complete) {
    for (const pin of engine.retryPins?.values() || []) count += pin.pinnedEntries?.length || 0
    for (const spend of engine.spends.values()) count += spend.entries?.length || 0
  }
  if (count > maximumRows) throw new TypeError('family capture exceeds its retained-row bound')
}

export async function revalidateFamilyCapture (wal, root, lease) {
  await verifyBlindWalRecoveryScanResult(wal, root, lease)
  // File verification awaits after its initial ownership check. Success needs
  // current ownership after every asynchronous file/cleanup boundary.
  await verifyBlindStoreSessionTransactionLease(lease, root)
}
