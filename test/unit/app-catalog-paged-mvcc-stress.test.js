import test from 'brittle'
import { AppCatalogMvccStore } from '../../packages/core/core/relay-node/app-catalog-paged-runtime.js'

const POPULATION = 100_000

function hexKey (index) {
  return (index + 1).toString(16).padStart(64, '0')
}

function source (index) {
  return {
    catalogPublic: true,
    record: {
      appKey: hexKey(index),
      appId: null,
      type: 'drive',
      parentKey: null,
      mountPath: null,
      version: null,
      discoveryKey: null,
      blind: false,
      storageClass: 'persistent',
      availabilityClass: 'best-effort',
      privacyTier: 'public',
      seededAt: null,
      redacted: false,
      metadataVisibility: 'public',
      blindContentId: null,
      anchored: false,
      maxStorageBytes: null,
      publisherPubkey: null,
      durability: 0,
      revocable: false,
      retainUntil: null
    }
  }
}

function permutedIndex (position) {
  return (position * 99_991) % POPULATION
}

test('MVCC sustains literal 100,000-record insert/delete/reinsert churn with bounded index work', (t) => {
  const store = new AppCatalogMvccStore({ maxSources: POPULATION })
  let before = store.indexMetrics.rowComparisons
  for (let i = 0; i < POPULATION; i++) store.put(`source-${i}`, source(i))
  let after = store.indexMetrics.rowComparisons
  t.is(store.size, POPULATION)
  t.ok(after - before < POPULATION * 80, '100,000 randomized row-key inserts remain logarithmic')
  t.exception(() => store.put('source-over-cap', source(POPULATION)), /source cap/)

  before = after
  for (let i = 0; i < POPULATION; i++) store.delete(`source-${permutedIndex(i)}`)
  after = store.indexMetrics.rowComparisons
  t.is(store.size, 0)
  t.ok(after - before < POPULATION * 80, '100,000 permuted deletes remain logarithmic')

  before = after
  for (let i = POPULATION - 1; i >= 0; i--) {
    const index = permutedIndex(i)
    store.put(`source-${index}`, source(index))
  }
  after = store.indexMetrics.rowComparisons
  t.is(store.size, POPULATION)
  t.ok(after - before < POPULATION * 80, '100,000 permuted reinserts remain logarithmic')

  let cursor = null
  let prior = null
  let visited = 0
  let ordered = true
  const beforeVisit = after
  let pageCount = 0
  while (true) {
    const page = store.readSnapshotPage({
      highWater: store.lastCatalogRevision,
      cursor,
      limit: 500
    })
    pageCount++
    for (const row of page.rows) {
      if (prior !== null && row[0] <= prior) ordered = false
      prior = row[0]
      visited++
    }
    if (page.complete) break
    cursor = page.lastRowKey
  }
  const afterVisit = store.indexMetrics.rowComparisons
  t.is(visited, POPULATION, 'bounded pages eventually visit every reinserted row')
  t.is(ordered, true)
  t.ok(afterVisit - beforeVisit < pageCount * 80, 'page visitation performs one logarithmic seek per bounded page')
})
