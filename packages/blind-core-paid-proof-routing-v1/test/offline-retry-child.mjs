import fs from 'node:fs/promises'
import assert from 'node:assert/strict'
import { OPERATION, coreServeChallengeV1, decodeCanonical } from '../../blind-protocol/index.js'
import { setup } from './fixture.mjs'
const config = JSON.parse(await fs.readFile(process.argv[2], 'utf8'))
const after = []
try {
  const h = await setup({ after: callback => after.push(callback) }, { restoreRoot: config.root, corePublicKey: config.corePublicKey })
  const request = decodeCanonical(coreServeChallengeV1, Buffer.from(config.request, 'hex'), { copyBytes: true })
  h.admissionToken(request.admission.token[0])
  const before = h.stats()
  const result = await h.dispatch(OPERATION.CORE.PROVE, request, Buffer.alloc(16, 9))
  assert.equal(result.dispatch.toString('hex'), config.expectedDispatch)
  assert.equal(h.stats().walSequence, before.walSequence)
  assert.equal(h.stats().proofPins, before.proofPins)
  assert.deepEqual(h.stats().walHash, before.walHash)
  assert.equal(h.stats().connections, 0)
  assert.equal(h.lookupInputs.length, 0)
  assert.ok(h.reads.length > 0 && h.reads.every(r => r.reserved > 0))
  console.log(JSON.stringify({ identicalDispatch: true, newWalRecords: 0, newProofPins: 0, sourceConnections: 0, activeCorpusEstimates: 0, allRetiredReadsReserved: true, node: process.version }))
} finally {
  for (const cleanup of after.reverse()) await cleanup()
}
