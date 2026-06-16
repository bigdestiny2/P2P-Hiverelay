// dedup-report.js — a zero-risk, read-only estimate of how much on-disk
// storage is redundant and could be reclaimed. NO deletes; this is the
// "is dedup even worth it" number, computed entirely from data the relay
// already holds (the AppRegistry + StorageAccounting's byte cache).
//
// Blind-safety: the ONLY duplication class reported is "superseded version
// still resident" — an `app`-type entry whose appId is indexed to a DIFFERENT
// (newer) appKey, i.e. a stale version the catalog view already hides but whose
// cores still occupy disk. This groups strictly within ONE relay's own
// registry and keys only on appId (manifest-declared) + appKey (opaque). It
// NEVER buckets by ciphertextRoot/blindContentId (that would assert content
// identity across blind drives — see the blind-path audit). Blind entries are
// never appId-indexed, so they never appear here.

/**
 * @param {AppRegistry} appRegistry
 * @param {StorageAccounting|null} storageAccounting
 * @returns {{
 *   supersededVersions: { groups: Array, count: number, reclaimableBytes: number, unmeasured: number },
 *   reclaimableBytes: number,
 *   note: string
 * }}
 */
export function buildDedupReport (appRegistry, storageAccounting = null) {
  const byAppId = appRegistry.byAppId // appId -> current (latest) appKey
  const getBytes = storageAccounting && typeof storageAccounting.getBytes === 'function'
    ? (k) => storageAccounting.getBytes(k)
    : () => null

  // appId -> { current, superseded: [{appKey, bytes|null}] }
  const groups = new Map()
  let reclaimableBytes = 0
  let unmeasured = 0
  let supersededCount = 0

  for (const [appKey, entry] of appRegistry.apps) {
    // app-type + indexed appId only; blind/redactable entries are never indexed.
    if (!entry || entry.appId == null || entry.blind === true) continue
    const current = byAppId.get(entry.appId)
    if (!current || current === appKey) continue // this IS the current version

    // This entry is a superseded version still resident on disk.
    supersededCount++
    const bytes = getBytes(appKey)
    if (bytes == null) unmeasured++
    else reclaimableBytes += bytes

    if (!groups.has(entry.appId)) groups.set(entry.appId, { appId: entry.appId, current, superseded: [] })
    groups.get(entry.appId).superseded.push({ appKey, bytes: bytes == null ? null : bytes })
  }

  return {
    supersededVersions: {
      groups: [...groups.values()],
      count: supersededCount,
      reclaimableBytes,
      unmeasured // superseded entries whose bytes StorageAccounting hasn't measured yet
    },
    reclaimableBytes,
    note: unmeasured > 0
      ? `${unmeasured} superseded entr${unmeasured === 1 ? 'y' : 'ies'} not yet measured — reclaimableBytes is a lower bound`
      : 'all superseded entries measured'
  }
}
