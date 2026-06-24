import test from 'brittle'
import {
  MAX_FORK_PROOF_EVIDENCE_FIELD_BYTES,
  MAX_FORK_PROOF_EVIDENCE_PER_RECORD,
  MAX_FORK_PROOF_RECORDS,
  buildForkProofsPayload
} from 'p2p-hiverelay/core/relay-node/api-fork-proofs.js'

function record (key = 'a'.repeat(64), overrides = {}) {
  return {
    hypercoreKey: key,
    discoveredAt: 10,
    blockIndex: 7,
    evidence: [
      { fromRelay: ' relay-a ', block: 'block-a', signature: 'sig-a', secret: 'hidden' },
      { fromRelay: 'relay-b', block: 'block-b', signature: 'sig-b' }
    ],
    operatorAcknowledged: false,
    resolution: null,
    resolutionNote: 'do-not-leak',
    secretToken: 'do-not-leak',
    ...overrides
  }
}

test('api fork proofs: missing detector returns empty bounded payload', (t) => {
  const out = buildForkProofsPayload()
  t.is(out.ok, true)
  t.alike(out.payload, {
    schemaVersion: 1,
    proofs: [],
    count: 0,
    total: 0,
    truncated: false,
    maxProofs: MAX_FORK_PROOF_RECORDS
  })
  t.alike(out.headers, { 'Cache-Control': 'public, max-age=30' })
})

test('api fork proofs: sanitizes public records without raw store fields', (t) => {
  const out = buildForkProofsPayload({
    forkDetector: {
      list () {
        return [record('A'.repeat(64), {
          resolvedAt: 20,
          resolution: 'rotated'
        })]
      }
    }
  })

  t.is(out.payload.count, 1)
  t.alike(out.payload.proofs[0], {
    hypercoreKey: 'a'.repeat(64),
    blockIndex: 7,
    evidence: [
      { fromRelay: 'relay-a', block: 'block-a', signature: 'sig-a' },
      { fromRelay: 'relay-b', block: 'block-b', signature: 'sig-b' }
    ],
    discoveredAt: 10,
    operatorAcknowledged: false,
    resolution: 'rotated',
    resolvedAt: 20
  })
  t.absent(JSON.stringify(out.payload).includes('resolutionNote'))
  t.absent(JSON.stringify(out.payload).includes('secretToken'))
  t.absent(JSON.stringify(out.payload).includes('do-not-leak'))
})

test('api fork proofs: caps records and per-record evidence', (t) => {
  t.is(MAX_FORK_PROOF_RECORDS, 200)
  t.is(MAX_FORK_PROOF_EVIDENCE_PER_RECORD, 16)
  t.is(MAX_FORK_PROOF_EVIDENCE_FIELD_BYTES, 8192)
  const records = []
  for (let i = 0; i < 205; i++) {
    const evidence = []
    for (let j = 0; j < 18; j++) {
      evidence.push({ fromRelay: 'relay-' + j, block: 'block-' + j, signature: 'sig-' + j })
    }
    records.push(record(String(i % 10).repeat(64), { evidence }))
  }

  const out = buildForkProofsPayload({
    forkDetector: { list: () => records }
  })

  t.is(out.payload.total, 205)
  t.is(out.payload.count, 200)
  t.is(out.payload.truncated, true)
  t.is(out.payload.proofs.length, 200)
  t.is(out.payload.proofs[0].evidence.length, 16)
  t.is(out.payload.proofs[0].evidenceTruncated, true)
})

test('api fork proofs: skips invalid or oversized proof records', (t) => {
  const out = buildForkProofsPayload({
    maxEvidenceFieldBytes: 8,
    forkDetector: {
      list () {
        return [
          record('not-hex'),
          record('b'.repeat(64), { blockIndex: -1 }),
          record('c'.repeat(64), { evidence: [{ fromRelay: 'a', block: 'short', signature: 'sig' }] }),
          record('d'.repeat(64), {
            evidence: [
              { fromRelay: 'relay-a', block: 'too-long-block', signature: 'sig-a' },
              { fromRelay: 'relay-b', block: 'block-b', signature: 'sig-b' }
            ]
          }),
          record('e'.repeat(64))
        ]
      }
    }
  })

  t.is(out.payload.total, 5)
  t.is(out.payload.count, 1)
  t.is(out.payload.proofs[0].hypercoreKey, 'e'.repeat(64))
})
