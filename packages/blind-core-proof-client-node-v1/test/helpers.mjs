import fs from 'node:fs/promises'
import path from 'node:path'
import { createRequire } from 'node:module'
import sodium from 'sodium-universal'
import { RealCoreUpstreamV1, headHash } from '../../blind-core-upstream-hc11-v1/index.js'
import { PROFILE_DIGEST } from '../../blind-core-upstream-hc11-v1/format.js'
import { createCoreProveRequest } from '../../blind-client/core.js'
import { verifiedEndpointFixture } from '../../blind-client/test/endpoint-fixture.js'
import { verifiedEndpointContext } from '../../blind-client/verified-endpoint.js'
import { FAMILY, OPERATION, CORE_ACK_RESULT, RESULT_SIGNATURE_DOMAIN_ID } from '../../blind-protocol/wire-runtime-authority.js'
import { blindCoreAckV1, coreServeResultV1 } from '../../blind-protocol/schemas.js'
import { encodeCanonical } from '../../blind-protocol/codec.js'
import { resultSignaturePayload } from '../../blind-protocol/hashes.js'
import { NodeCoreProofClientV1 } from '../index.js'

const require = createRequire(new URL('../../blind-core-upstream-hc11-v1/package.json', import.meta.url))
export const Corestore = require('corestore')
export const Hypercore = require('hypercore')
export function gate () {
  let release
  const waiting = new Promise(resolve => { release = resolve })
  return { waiting, release }
}
export const turn = () => new Promise(resolve => setImmediate(resolve))

export async function fixture (t) {
  const parent = new URL('../.scratch/', import.meta.url)
  await fs.mkdir(parent, { recursive: true })
  const root = await fs.mkdtemp(path.join(parent.pathname, 'client-'))
  const store = new Corestore(path.join(root, 'writer'))
  const writer = store.get({ name: 'encrypted-private-proof', encryptionKey: Buffer.alloc(32, 17) })
  await writer.ready()
  await writer.append([Buffer.from('private-ciphertext-one'), Buffer.from('private-ciphertext-two'), Buffer.from('private-ciphertext-three')])
  const head = { corePublicKey: Buffer.from(writer.key), fork: BigInt(writer.fork), length: BigInt(writer.length), signedHeadHash: headHash({ corePublicKey: writer.key, fork: writer.fork, length: writer.length, treeHash: await writer.treeHash() }) }
  const acquisition = new RealCoreUpstreamV1({ root: path.join(root, 'acquisition'), connect: () => writer.replicate(false), readCorpus: async () => { throw Error('not used') } })
  const activation = await acquisition.activateMirror({ request: head })
  if (activation.verified !== true) throw Error('real acquisition failed')
  const proof = await acquisition.serveProof({ generation: head, blockIndices: [0n, 2n], corpus: activation.corpus })
  await acquisition.close(); await store.close()
  const publicKey = Buffer.alloc(32); const secretKey = Buffer.alloc(64)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, Buffer.alloc(32, 56))
  const continuityRoot = Buffer.alloc(32, 0x94)
  const endpoint = verifiedEndpointFixture({ endpointId: 1, transportId: 1, canonicalUrl: Buffer.from('http://127.0.0.1/private-proof-test') }, FAMILY.CORE, OPERATION.CORE.PROVE, { relayPublicKey: publicKey, continuityRoot })
  const clients = []
  t.after(async () => { for (const client of clients) await client.close(); await fs.rm(root, { recursive: true, force: true }) })
  const request = changes => createCoreProveRequest({ relayPublicKey: publicKey, ...head, blockIndices: [0n, 2n], clientNonce: Buffer.alloc(32, 9), ...changes })
  function response (created, proofBytes = proof, ackChanges = {}) {
    const context = verifiedEndpointContext(endpoint)
    const ack = {
      version: 1,
      relayBinding: { version: 1, ...context, externalCommitWitness: null },
      ...head,
      observedAtEpoch: 1000,
      leaseEpoch: 1001,
      result: CORE_ACK_RESULT.RECENTLY_SERVED,
      requestNonce: created.request.clientNonce,
      requestCommitment: created.requestCommitment,
      signature: Buffer.alloc(64),
      ...ackChanges
    }
    const encoded = encodeCanonical(blindCoreAckV1, ack)
    sodium.crypto_sign_detached(ack.signature, resultSignaturePayload(RESULT_SIGNATURE_DOMAIN_ID.CORE_ACK, encoded.subarray(0, -64)), secretKey)
    return { ok: true, body: encodeCanonical(coreServeResultV1, { version: 1, acknowledgement: ack, proofsAndBlocks: proofBytes }) }
  }
  function client (transport = null, overrides = {}) {
    const value = new NodeCoreProofClientV1({ root: path.join(root, 'verifier-' + clients.length), profileDigest: Buffer.from(PROFILE_DIGEST), transport, ...overrides })
    clients.push(value); return value
  }
  return { root, head, proof, endpoint, continuityRoot, client, request, response, options: created => ({ endpoint, requestBytes: created.requestBytes, requestCommitment: created.requestCommitment }) }
}
