import test from 'brittle'
import b4a from 'b4a'
import c from 'compact-encoding'
import sodium from 'sodium-universal'
import { ProofOfRelay } from 'p2p-hiverelay/core/protocol/proof-of-relay.js'
import {
  MAX_PROOF_BLOCK_BYTES,
  MAX_PROOF_MERKLE_PROOF_BYTES,
  proofChallengeEncoding,
  proofResponseEncoding
} from 'p2p-hiverelay/core/protocol/messages.js'

function randomKey () {
  const buf = b4a.alloc(32)
  sodium.randombytes_buf(buf)
  return buf
}

function encodeFrame (encoding, msg) {
  const state = { start: 0, end: 0, buffer: null }
  encoding.preencode(state, msg)
  state.buffer = b4a.alloc(state.end)
  state.start = 0
  encoding.encode(state, msg)
  return state.buffer
}

function declaredProofResponseFrame ({ blockLen, blockPayload = null, proofLen, proofPayload = null }) {
  const coreKey = b4a.alloc(32, 0x11)
  const nonce = b4a.alloc(32, 0x22)
  const state = { start: 0, end: 0, buffer: null }
  c.fixed32.preencode(state, coreKey)
  c.uint.preencode(state, 7)
  c.uint.preencode(state, blockLen)
  state.end += blockPayload ? blockPayload.byteLength : 0
  c.uint.preencode(state, proofLen)
  state.end += proofPayload ? proofPayload.byteLength : 0
  c.fixed32.preencode(state, nonce)
  state.buffer = b4a.alloc(state.end)
  c.fixed32.encode(state, coreKey)
  c.uint.encode(state, 7)
  c.uint.encode(state, blockLen)
  if (blockPayload) {
    blockPayload.copy(state.buffer, state.start)
    state.start += blockPayload.byteLength
  }
  c.uint.encode(state, proofLen)
  if (proofPayload) {
    proofPayload.copy(state.buffer, state.start)
    state.start += proofPayload.byteLength
  }
  c.fixed32.encode(state, nonce)
  return state.buffer
}

function truncatedProofResponseFrame (blockLen) {
  const coreKey = b4a.alloc(32, 0x11)
  const state = { start: 0, end: 0, buffer: null }
  c.fixed32.preencode(state, coreKey)
  c.uint.preencode(state, 7)
  c.uint.preencode(state, blockLen)
  state.buffer = b4a.alloc(state.end)
  c.fixed32.encode(state, coreKey)
  c.uint.encode(state, 7)
  c.uint.encode(state, blockLen)
  return state.buffer
}

test('proof encodings: round-trip valid challenge and response frames', (t) => {
  const challenge = {
    coreKey: b4a.alloc(32, 0x01),
    blockIndex: 42,
    nonce: b4a.alloc(32, 0x02),
    maxLatencyMs: 5000
  }
  const response = {
    coreKey: challenge.coreKey,
    blockIndex: challenge.blockIndex,
    blockData: b4a.from('block-data'),
    merkleProof: b4a.from('legacy-proof'),
    nonce: challenge.nonce
  }

  const challengeFrame = encodeFrame(proofChallengeEncoding, challenge)
  const responseFrame = encodeFrame(proofResponseEncoding, response)

  t.alike(proofChallengeEncoding.decode({ buffer: challengeFrame, start: 0, end: challengeFrame.length }), challenge)
  t.alike(proofResponseEncoding.decode({ buffer: responseFrame, start: 0, end: responseFrame.length }), response)
})

test('proof encodings: reject bad outbound frames before allocation growth', (t) => {
  const badChallenge = { start: 0, end: 0, buffer: null }
  t.exception(() => {
    proofChallengeEncoding.preencode(badChallenge, {
      coreKey: b4a.alloc(31),
      blockIndex: 1,
      nonce: b4a.alloc(32),
      maxLatencyMs: 5000
    })
  }, /coreKey/, 'bad challenge core key rejected')
  t.is(badChallenge.end, 0, 'bad challenge does not grow state.end')

  const badBlock = { start: 0, end: 0, buffer: null }
  t.exception(() => {
    proofResponseEncoding.preencode(badBlock, {
      coreKey: b4a.alloc(32),
      blockIndex: 1,
      blockData: b4a.alloc(MAX_PROOF_BLOCK_BYTES + 1),
      merkleProof: b4a.alloc(0),
      nonce: b4a.alloc(32)
    })
  }, /blockData too large/, 'oversized block data rejected')
  t.is(badBlock.end, 0, 'oversized block data does not grow state.end')

  const badProof = { start: 0, end: 0, buffer: null }
  t.exception(() => {
    proofResponseEncoding.preencode(badProof, {
      coreKey: b4a.alloc(32),
      blockIndex: 1,
      blockData: b4a.from('ok'),
      merkleProof: b4a.alloc(MAX_PROOF_MERKLE_PROOF_BYTES + 1),
      nonce: b4a.alloc(32)
    })
  }, /merkleProof too large/, 'oversized legacy merkle proof rejected')
  t.is(badProof.end, 0, 'oversized merkle proof does not grow state.end')
})

test('proof encodings: reject oversized declared inbound frames before materializing them', (t) => {
  const hugeBlock = declaredProofResponseFrame({
    blockLen: MAX_PROOF_BLOCK_BYTES + 1,
    proofLen: 0
  })
  const blockOut = proofResponseEncoding.decode({ buffer: hugeBlock, start: 0, end: hugeBlock.length })
  t.is(blockOut.error, 'blockData too large')
  t.absent(blockOut.blockData)

  const hugeProof = declaredProofResponseFrame({
    blockLen: 2,
    blockPayload: b4a.from('ok'),
    proofLen: MAX_PROOF_MERKLE_PROOF_BYTES + 1
  })
  const proofOut = proofResponseEncoding.decode({ buffer: hugeProof, start: 0, end: hugeProof.length })
  t.is(proofOut.error, 'merkleProof too large')
  t.absent(proofOut.merkleProof)
})

test('proof encodings: reject malformed and truncated frames without throwing', (t) => {
  let challengeOut = null
  t.execution(() => {
    challengeOut = proofChallengeEncoding.decode({ buffer: b4a.alloc(31), start: 0, end: 31 })
  }, 'truncated proof challenge does not throw')
  t.is(challengeOut.error, 'malformed proof challenge')

  let responseOut = null
  t.execution(() => {
    const frame = truncatedProofResponseFrame(16)
    responseOut = proofResponseEncoding.decode({ buffer: frame, start: 0, end: frame.length })
  }, 'truncated proof response block data does not throw')
  t.is(responseOut.error, 'malformed proof response')
})

test('ProofOfRelay handlers ignore decoded proof protocol errors without throwing', async (t) => {
  const por = new ProofOfRelay()
  const invalid = { challenge: [], response: [] }
  por.on('invalid-challenge', event => invalid.challenge.push(event.reason))
  por.on('invalid-response', event => invalid.response.push(event.reason))

  await por._onChallenge({ stream: {} }, { error: 'malformed proof challenge' })
  t.execution(() => por._onResponse(null, { error: 'blockData too large' }), 'response error handled')
  t.alike(invalid.challenge, ['malformed proof challenge'])
  t.alike(invalid.response, ['blockData too large'])

  por.destroy()
})

test('ProofOfRelay - challenge stores pending entry', async (t) => {
  const por = new ProofOfRelay({ maxLatencyMs: 5000 })

  const mockChannel = {
    opened: true,
    _hiverelay: {
      challengeMsg: { send () {} },
      responseMsg: { send () {} }
    }
  }

  por.challenge(mockChannel, randomKey(), 0, randomKey())
  t.is(por.pendingChallenges.size, 1)

  por.destroy()
})

test('ProofOfRelay - pending challenge cap rejects new single challenges', async (t) => {
  const por = new ProofOfRelay({ maxLatencyMs: 5000, maxPendingChallenges: 1 })
  const rejected = []
  por.on('challenge-rejected', (evt) => rejected.push(evt))

  const mockChannel = {
    opened: true,
    _hiverelay: {
      challengeMsg: { send () {} },
      responseMsg: { send () {} }
    }
  }

  const first = por.challenge(mockChannel, randomKey(), 0, randomKey())
  const second = por.challenge(mockChannel, randomKey(), 1, randomKey())

  t.is(first, true, 'first challenge accepted')
  t.is(second, false, 'second challenge rejected at cap')
  t.is(por.pendingChallenges.size, 1, 'pending map stays at cap')
  t.is(rejected.length, 1)
  t.is(rejected[0].reason, 'pending-capacity-exceeded')

  por.destroy()
})

test('ProofOfRelay - oversized batch is rejected before allocating pending entries', async (t) => {
  const por = new ProofOfRelay({ maxLatencyMs: 5000, maxBatchSize: 2 })
  const rejected = []
  por.on('batch-challenge-rejected', (evt) => rejected.push(evt))

  const mockChannel = {
    opened: true,
    _hiverelay: {
      challengeMsg: { send () {} },
      responseMsg: { send () {} }
    }
  }

  const batchId = por.challengeBatch(mockChannel, randomKey(), [0, 1, 2], randomKey())

  t.is(batchId, null, 'oversized batch rejected')
  t.is(por.pendingChallenges.size, 0, 'no batch state allocated')
  t.is(rejected.length, 1)
  t.is(rejected[0].reason, 'batch-too-large')
  t.is(rejected[0].maxBatchSize, 2)

  por.destroy()
})

test('ProofOfRelay - batch reserves one batch slot plus per-index slots', async (t) => {
  const por = new ProofOfRelay({ maxLatencyMs: 5000, maxBatchSize: 4, maxPendingChallenges: 3 })
  const rejected = []
  por.on('batch-challenge-rejected', (evt) => rejected.push(evt))

  const mockChannel = {
    opened: true,
    _hiverelay: {
      challengeMsg: { send () {} },
      responseMsg: { send () {} }
    }
  }

  const accepted = por.challengeBatch(mockChannel, randomKey(), [0, 1], randomKey())
  t.ok(accepted, 'two-block batch fits in three slots')
  t.is(por.pendingChallenges.size, 3, 'batch stores batch id plus two per-index entries')

  const denied = por.challengeBatch(mockChannel, randomKey(), [2], randomKey())
  t.is(denied, null, 'next batch rejected at pending cap')
  t.is(por.pendingChallenges.size, 3, 'pending map does not grow past cap')
  t.is(rejected.length, 1)
  t.is(rejected[0].reason, 'pending-capacity-exceeded')

  por.destroy()
})

test('ProofOfRelay - valid response scores a pass', async (t) => {
  t.plan(2)
  const por = new ProofOfRelay({ maxLatencyMs: 5000 })
  const coreKey = randomKey()
  const relayPubkey = randomKey()
  const nonce = b4a.alloc(32)
  sodium.randombytes_buf(nonce)

  // Manually insert a pending challenge
  por.pendingChallenges.set(b4a.toString(nonce, 'hex'), {
    coreKey: b4a.toString(coreKey, 'hex'),
    blockIndex: 5,
    sentAt: Date.now(),
    relayPubkey: b4a.toString(relayPubkey, 'hex')
  })

  por.on('proof-result', (result) => {
    t.ok(result.passed, 'challenge passed')
  })

  // Simulate response
  por._onResponse(null, {
    coreKey,
    blockIndex: 5,
    blockData: Buffer.from('block-data'),
    merkleProof: Buffer.from('proof'),
    nonce
  })

  const score = por.getScore(b4a.toString(relayPubkey, 'hex'))
  t.is(score.passes, 1)

  por.destroy()
})

test('ProofOfRelay - latency exceeded scores a fail', async (t) => {
  const por = new ProofOfRelay({ maxLatencyMs: 1 })
  const coreKey = randomKey()
  const relayPubkey = randomKey()
  const nonce = b4a.alloc(32)
  sodium.randombytes_buf(nonce)

  por.pendingChallenges.set(b4a.toString(nonce, 'hex'), {
    coreKey: b4a.toString(coreKey, 'hex'),
    blockIndex: 0,
    sentAt: Date.now() - 1000, // sent 1s ago, max is 1ms
    relayPubkey: b4a.toString(relayPubkey, 'hex')
  })

  por._onResponse(null, {
    coreKey,
    blockIndex: 0,
    blockData: Buffer.from('data'),
    merkleProof: Buffer.from('proof'),
    nonce
  })

  const score = por.getScore(b4a.toString(relayPubkey, 'hex'))
  t.is(score.fails, 1)

  por.destroy()
})

test('ProofOfRelay - unknown nonce emits unexpected-response', async (t) => {
  t.plan(1)
  const por = new ProofOfRelay()

  por.on('unexpected-response', () => {
    t.pass('unexpected-response emitted')
  })

  por._onResponse(null, {
    coreKey: randomKey(),
    blockIndex: 0,
    blockData: Buffer.from('data'),
    merkleProof: Buffer.from('proof'),
    nonce: randomKey()
  })

  por.destroy()
})

test('ProofOfRelay - getReliability', async (t) => {
  const por = new ProofOfRelay({ maxLatencyMs: 5000 })
  const relay = b4a.toString(randomKey(), 'hex')

  // Simulate 4 passes and 1 fail via _updateScore
  for (let i = 0; i < 4; i++) por._updateScore(relay, true, 100)
  por._updateScore(relay, false, 0)

  t.is(por.getReliability(relay), 0.8)

  por.destroy()
})

test('ProofOfRelay - stale challenge cleanup', async (t) => {
  const por = new ProofOfRelay({ maxLatencyMs: 50 })

  por.pendingChallenges.set('stale', {
    coreKey: 'abc',
    blockIndex: 0,
    sentAt: Date.now() - 200, // well past 2 * 50ms
    relayPubkey: 'def'
  })

  por.pendingChallenges.set('fresh', {
    coreKey: 'abc',
    blockIndex: 1,
    sentAt: Date.now(),
    relayPubkey: 'def'
  })

  por._cleanupStale()

  t.is(por.pendingChallenges.size, 1)
  t.ok(por.pendingChallenges.has('fresh'))

  por.destroy()
})
