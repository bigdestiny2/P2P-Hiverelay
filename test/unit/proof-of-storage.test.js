/**
 * Proof-of-Storage (Tier 2) — adversarial suite.
 *
 * A false trustless proof is worse than none, so this exercises the REAL
 * Hypercore primitives (temp-dir cores, genuine Merkle proofs) and asserts that
 * every forgery is rejected: fake content (even with a self-consistent relay
 * signature), wrong index, wrong core, wrong/forged relay signature, replayed
 * nonce, and a relay that simply doesn't hold the block.
 */
import test from 'brittle'
import Hypercore from 'hypercore'
import b4a from 'b4a'
import os from 'os'
import path from 'path'
import c from 'compact-encoding'
import sodium from 'sodium-universal'
import { wire } from 'hypercore/lib/messages.js'
import {
  buildStorageProof,
  verifyStorageProof,
  storageProofSignable
} from 'p2p-hiverelay/core/protocol/proof-of-storage.js'

let _n = 0
function tmp () { return path.join(os.tmpdir(), 'hr-pos-' + process.pid + '-' + (_n++)) }
function relayKeyPair () {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(publicKey, secretKey)
  return { publicKey, secretKey }
}
function freshNonce () { const n = b4a.alloc(32); sodium.randombytes_buf(n); return n }

async function seededCore (blocks) {
  const core = new Hypercore(tmp())
  await core.ready()
  await core.append(blocks)
  return core
}
async function verifierFor (key) {
  const v = new Hypercore(tmp(), key)
  await v.ready()
  return v
}

test('VALID proof: genuine block + relay signature over the challenge => valid', async (t) => {
  const core = await seededCore([b4a.from('a'), b4a.from('bb'), b4a.from('ccc'), b4a.from('dddd')])
  const relay = relayKeyPair()
  const nonce = freshNonce()
  const response = await buildStorageProof({ core, index: 2, nonce, keyPair: relay })
  const verifierCore = await verifierFor(core.key)
  const v = await verifyStorageProof({
    verifierCore,
    response,
    expect: { driveKey: core.key, index: 2, nonce, relayPubkey: relay.publicKey }
  })
  t.ok(v.valid, 'valid'); t.ok(v.contentValid, 'content verified vs drive key'); t.ok(v.sigValid, 'relay sig ok')
  await core.close(); await verifierCore.close()
})

test('one verifier core validates MULTIPLE random samples', async (t) => {
  const core = await seededCore(['0', '1', '2', '3', '4', '5'].map((s) => b4a.from('blk-' + s)))
  const relay = relayKeyPair()
  const verifierCore = await verifierFor(core.key)
  for (const i of [5, 0, 3]) {
    const nonce = freshNonce()
    const response = await buildStorageProof({ core, index: i, nonce, keyPair: relay })
    const v = await verifyStorageProof({ verifierCore, response, expect: { driveKey: core.key, index: i, nonce, relayPubkey: relay.publicKey } })
    t.ok(v.valid, 'sample ' + i + ' valid')
  }
  await core.close(); await verifierCore.close()
})

test('FORGED content: relay claims a block it does not have (fake value + self-consistent sig) => rejected', async (t) => {
  const core = await seededCore([b4a.from('real-0'), b4a.from('real-1'), b4a.from('real-2')])
  const relay = relayKeyPair()
  const nonce = freshNonce()
  const honest = await buildStorageProof({ core, index: 1, nonce, keyPair: relay })

  // Attacker rewrites the proven block to fake content and RE-SIGNS honestly over
  // the fake content — so the signature is internally consistent. Only the
  // Hypercore Merkle check can catch this, and it must.
  const decoded = c.decode(wire.data, b4a.from(honest.proof, 'hex'))
  decoded.block.value = b4a.from('FORGERY')
  const proofBytes = c.encode(wire.data, decoded)
  const { signable, blockHash } = storageProofSignable(core.key, 1, nonce, decoded.block.value)
  const sig = b4a.alloc(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(sig, signable, relay.secretKey)
  const forged = { ...honest, proof: b4a.toString(proofBytes, 'hex'), blockHash: b4a.toString(blockHash, 'hex'), signature: b4a.toString(sig, 'hex') }

  const verifierCore = await verifierFor(core.key)
  const v = await verifyStorageProof({ verifierCore, response: forged, expect: { driveKey: core.key, index: 1, nonce, relayPubkey: relay.publicKey } })
  t.absent(v.valid, 'forged content rejected'); t.absent(v.contentValid)
  t.ok(String(v.reason).startsWith('CONTENT_INVALID'), 'rejected by Hypercore Merkle check: ' + v.reason)
  await core.close(); await verifierCore.close()
})

test('WRONG index: response for a different block than challenged => rejected', async (t) => {
  const core = await seededCore([b4a.from('a'), b4a.from('b'), b4a.from('c')])
  const relay = relayKeyPair(); const nonce = freshNonce()
  const response = await buildStorageProof({ core, index: 0, nonce, keyPair: relay })
  const verifierCore = await verifierFor(core.key)
  const v = await verifyStorageProof({ verifierCore, response, expect: { driveKey: core.key, index: 2, nonce, relayPubkey: relay.publicKey } })
  t.absent(v.valid); t.is(v.reason, 'INDEX_MISMATCH')
  await core.close(); await verifierCore.close()
})

test('WRONG core: proof for a different drive than expected => rejected', async (t) => {
  const core = await seededCore([b4a.from('a'), b4a.from('b')])
  const other = await seededCore([b4a.from('x'), b4a.from('y')])
  const relay = relayKeyPair(); const nonce = freshNonce()
  const response = await buildStorageProof({ core, index: 1, nonce, keyPair: relay })
  const verifierCore = await verifierFor(other.key)
  const v = await verifyStorageProof({ verifierCore, response, expect: { driveKey: other.key, index: 1, nonce, relayPubkey: relay.publicKey } })
  t.absent(v.valid); t.is(v.reason, 'CORE_MISMATCH')
  await core.close(); await other.close(); await verifierCore.close()
})

test('FORGED signature: signed by an attacker key but labelled as the honest relay => rejected', async (t) => {
  const core = await seededCore([b4a.from('a'), b4a.from('b'), b4a.from('c')])
  const honestRelay = relayKeyPair(); const attacker = relayKeyPair(); const nonce = freshNonce()
  // Attacker produces a genuine content proof but signs with its own key, then
  // labels the response with the honest relay's pubkey to impersonate it.
  const resp = await buildStorageProof({ core, index: 2, nonce, keyPair: attacker })
  resp.relayPubkey = b4a.toString(honestRelay.publicKey, 'hex')
  const verifierCore = await verifierFor(core.key)
  const v = await verifyStorageProof({ verifierCore, response: resp, expect: { driveKey: core.key, index: 2, nonce, relayPubkey: honestRelay.publicKey } })
  t.absent(v.valid); t.ok(v.contentValid, 'content is genuine'); t.absent(v.sigValid); t.is(v.reason, 'SIG_INVALID')
  await core.close(); await verifierCore.close()
})

test('REPLAY: a proof signed for an old nonce, re-labelled with the new nonce => rejected', async (t) => {
  const core = await seededCore([b4a.from('a'), b4a.from('b'), b4a.from('c')])
  const relay = relayKeyPair()
  const oldNonce = freshNonce(); const newNonce = freshNonce()
  const captured = await buildStorageProof({ core, index: 1, nonce: oldNonce, keyPair: relay })
  // Attacker relabels the captured proof's nonce to the fresh challenge but
  // cannot re-sign (no relay key) — sig still covers oldNonce.
  const replay = { ...captured, nonce: b4a.toString(newNonce, 'hex') }
  const verifierCore = await verifierFor(core.key)
  const v = await verifyStorageProof({ verifierCore, response: replay, expect: { driveKey: core.key, index: 1, nonce: newNonce, relayPubkey: relay.publicKey } })
  t.absent(v.valid, 'replay rejected'); t.is(v.reason, 'SIG_INVALID', 'sig was bound to the old nonce')
  // And the un-relabelled capture is rejected on the nonce check itself.
  const v2 = await verifyStorageProof({ verifierCore: await verifierFor(core.key), response: captured, expect: { driveKey: core.key, index: 1, nonce: newNonce, relayPubkey: relay.publicKey } })
  t.is(v2.reason, 'NONCE_MISMATCH')
  await core.close(); await verifierCore.close()
})

test('BLOCKHASH mismatch: relay lies about the content hash it signed => rejected', async (t) => {
  const core = await seededCore([b4a.from('a'), b4a.from('b'), b4a.from('c')])
  const relay = relayKeyPair(); const nonce = freshNonce()
  const resp = await buildStorageProof({ core, index: 0, nonce, keyPair: relay })
  resp.blockHash = b4a.toString(b4a.alloc(32, 0xff), 'hex') // wrong hash
  const verifierCore = await verifierFor(core.key)
  const v = await verifyStorageProof({ verifierCore, response: resp, expect: { driveKey: core.key, index: 0, nonce, relayPubkey: relay.publicKey } })
  t.absent(v.valid); t.is(v.reason, 'BLOCKHASH_MISMATCH')
  await core.close(); await verifierCore.close()
})

test('LENGTH PIN: a proof against an old/short signed version is rejected when a min length is required', async (t) => {
  const core = await seededCore([b4a.from('a'), b4a.from('b'), b4a.from('c')]) // length 3
  const relay = relayKeyPair(); const nonce = freshNonce()
  const response = await buildStorageProof({ core, index: 1, nonce, keyPair: relay })
  const verifierCore = await verifierFor(core.key)
  const exp = { driveKey: core.key, index: 1, nonce, relayPubkey: relay.publicKey }

  // Client knows the current head is 5 blocks — an old length-3 proof is stale.
  const stale = await verifyStorageProof({ verifierCore, response, expect: { ...exp, minLength: 5 } })
  t.absent(stale.valid, 'stale (short) proof rejected'); t.is(stale.reason, 'LENGTH_TOO_SHORT')
  t.is(stale.provenLength, 3, 'reports the author-signed length it proved')

  // Same proof passes when the pin matches what it actually proved.
  const ok = await verifyStorageProof({ verifierCore: await verifierFor(core.key), response, expect: { ...exp, minLength: 3 } })
  t.ok(ok.valid, 'accepted when minLength is satisfied'); t.ok(ok.lengthValid)
  await core.close(); await verifierCore.close()
})

test('relay does NOT hold the block: buildStorageProof fails honestly (no fetch-on-demand)', async (t) => {
  // A key-only core that has never downloaded block 0.
  const author = await seededCore([b4a.from('a'), b4a.from('b')])
  const empty = await verifierFor(author.key) // knows the key, holds nothing
  const relay = relayKeyPair(); const nonce = freshNonce()
  await t.exception(buildStorageProof({ core: empty, index: 0, nonce, keyPair: relay }), /BLOCK_NOT_LOCAL|BLOCK_OUT_OF_RANGE/)
  await author.close(); await empty.close()
})
