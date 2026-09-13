import fs from 'node:fs/promises'
import assert from 'node:assert/strict'
import { RealCoreUpstreamV1 } from '../index.js'
const input = JSON.parse(await fs.readFile(process.argv[2]))
const corpus = Buffer.from(input.corpus, 'hex')
const request = { corePublicKey: Buffer.from(input.key, 'hex'), fork: BigInt(input.fork), length: BigInt(input.length), signedHeadHash: Buffer.from(input.head, 'hex'), blockIndices: input.indices.map(BigInt) }
let network = 0
const upstream = new RealCoreUpstreamV1({ root: input.scratch, connect: () => { network++; throw Error('offline') }, readCorpus: () => corpus })
try {
  const estimated = await upstream.estimateProofBytes({ request })
  const proof = await upstream.serveProof({ generation: request, blockIndices: request.blockIndices, corpus })
  assert.equal(proof.length, estimated); assert.equal(proof.toString('hex'), input.expected)
  assert.equal(await upstream.verifyProofBundle({ request, proof }), true)
  assert.equal(network, 0)
  console.log('offline-proof-identical; genuine key-only verification; network=0')
} finally { await upstream.close() }
