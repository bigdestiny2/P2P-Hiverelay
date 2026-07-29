/**
 * Verifiable retrieval mode (R1) — trustless proof bundles for gateway reads.
 *
 * A normal gateway GET returns raw file bytes and the client must TRUST the
 * gateway (TLS proves transport, not Hypercore provenance). When the request
 * carries `?verify=1` or `Accept: application/vnd.hiverelay.hc-block`, the
 * gateway instead returns a versioned VERIFICATION BUNDLE: the blob block's
 * bytes + a Hypercore Merkle block proof + the drive's signed tree headers,
 * so a client can verify the bytes hash into the drive key's signed root
 * WITHOUT trusting the gateway.
 *
 * Envelope — Content-Type `application/vnd.hiverelay.hc-block+json`, `v: 1`:
 *
 *   {
 *     v: 1,                      // envelope format version
 *     driveKey,                  // 64-hex drive (metadata/bee core) key — the
 *                                //   client's root of trust; on hc11 it is the
 *                                //   manifest hash, checked against the entry proof
 *     driveVersion,              // bee core length the bundle pins to (the same
 *                                //   version X-Hive-Drive-Version advertises)
 *     path,                      // resolved drive path the bundle serves
 *     blockIndex,                // absolute index of blockBytes in the BLOBS core
 *     blockBytes,                // hex raw blob block (one block of file bytes)
 *     fileRange: { start, end }, // file-byte offsets blockBytes covers (inclusive)
 *     blob: { blockOffset, blockLength, byteOffset, byteLength, blockSize },
 *                                // the path's blob descriptor (proved via entry);
 *                                //   blockSize is the blob store's chunk size,
 *                                //   checked arithmetically vs blockLength/byteLength
 *     blobsKey,                  // 64-hex blobs (content) core key — derived
 *                                //   independently from the drive manifest
 *     proof,                     // hex wire.data block proof of blockBytes in the
 *                                //   blobs core (embeds the blobs-core manifest)
 *     treeHeader: { fork, length, rootHash, signature },
 *                                // blobs core signed tree header at the proven length
 *     entry: {
 *       blockIndex,              // bee-core index of the path's node block
 *       blockBytes,              // hex raw protobuf bee node (binds path → blob)
 *       proof,                   // hex wire.data block proof in the bee core,
 *                                //   upgrade pinned at driveVersion (drive manifest)
 *       treeHeader               // bee core signed tree header AT driveVersion
 *     }
 *   }
 *
 * Trust chain (all re-derived client-side — see packages/client/verify-block.js):
 * driveKey ⇒ manifest hash ⇒ drive manifest ⇒ getContentManifest ⇒ blobs key;
 * the entry proof binds path→blob into the drive key's signed root at
 * driveVersion; the block proof binds blockBytes into the blobs core's signed
 * root. Forged/substituted bytes, a wrong block, a wrong path binding, or a
 * stale header all fail verification.
 *
 * Scope: ONE blob block per request (single range only; the frozen byte caps
 * refuse exactly like the raw lane); clients iterate blocks using the proved
 * blob descriptor. Public drives only — the admission chain runs BEFORE this
 * module, so blind/custody keys stay hard-403 exactly as on the raw lane.
 * Proofs read local storage only (core.proof never fetches): a gateway that
 * cannot prove honestly fails the request instead of fetching to fabricate.
 */

import c from 'compact-encoding'
import b4a from 'b4a'
import { wire } from 'hypercore/lib/messages.js'
import { parseRange } from './hyper-gateway.js'

export const HC_BLOCK_ENVELOPE_VERSION = 1
export const HC_BLOCK_MEDIA_TYPE = 'application/vnd.hiverelay.hc-block'
export const HC_BLOCK_MEDIA_TYPE_JSON = 'application/vnd.hiverelay.hc-block+json'

/**
 * Verify-mode trigger surfaces: an explicit `?verify=1` query flag, or content
 * negotiation for the bundle media type (with or without the `+json` suffix).
 */
export function isVerifyRequest (url, headers) {
  if (url && url.searchParams && url.searchParams.get('verify') === '1') return true
  const accept = headers && headers.accept
  return typeof accept === 'string' && accept.includes(HC_BLOCK_MEDIA_TYPE)
}

/**
 * Build + send the verification bundle for an already-resolved file entry.
 * Called from HyperGateway._handleRequest AFTER the normal admission chain
 * (seeded/blind/tier/PolicyGuard) and drive pinning, with the same `readDrive`
 * the raw lane would stream from. All failure modes answer with the same JSON
 * error shape as the raw lane.
 *
 * @param {HyperGateway} gateway - owning gateway (timeouts, byte caps, events)
 * @param {object} res - HTTP response
 * @param {Hyperdrive} drive - the (possibly checked-out) drive being served
 * @param {string} keyHex - 64-hex drive key
 * @param {string} filePath - resolved file path (after index.html rewrite)
 * @param {object} entry - the bee entry for filePath (entry.value.blob present)
 * @param {number} byteLength - entry.value.blob.byteLength (already validated)
 * @param {object} opts - { head, exactBytes, rangeHeader, driveVersion, signal,
 *   sendJson, reserveResponseBytes, egressRetryAfterSeconds }
 */
export async function serveVerifyBundle (gateway, res, drive, keyHex, filePath, entry, byteLength, opts = {}) {
  const sendJson = opts.sendJson
  const blob = entry && entry.value && entry.value.blob
  const blobFields = blob && [blob.blockOffset, blob.blockLength, blob.byteOffset, blob.byteLength]
  if (!blobFields || !blobFields.every(Number.isSafeInteger) ||
      blob.blockOffset < 0 || blob.blockLength < 1 || blob.byteOffset < 0 || blob.byteLength < 1 ||
      !Number.isSafeInteger(entry.seq) || entry.seq < 0) {
    // Empty files have no blob block to prove; anything else malformed is not provable.
    sendJson({ error: 'Verify mode requires a file with blob blocks', path: filePath }, 400)
    return
  }

  const blobs = await gateway._withTimeout(
    drive.getBlobs(),
    gateway._driveOperationTimeout,
    'drive.getBlobs()',
    opts.signal
  )
  const blobsCore = blobs && blobs.core
  const blockSize = blobs && blobs.blockSize
  if (!blobsCore || typeof blobsCore.proof !== 'function' || !Number.isSafeInteger(blockSize) || blockSize < 1) {
    sendJson({ error: 'Gateway verify bundle failed' }, 502)
    return
  }
  const beeCore = drive.core
  if (!beeCore || typeof beeCore.proof !== 'function') {
    sendJson({ error: 'Gateway verify bundle failed' }, 502)
    return
  }

  // ─── Range → single blob block ─────────────────────────────────
  // Same parser, statuses, and frozen byte caps as the raw lane; verify mode
  // is simply stricter about one thing the raw lane never needed: the span
  // must fit inside ONE blob block, because the block is the proof unit.
  let blockRel = 0
  const rangeHeader = opts.rangeHeader
  if (rangeHeader) {
    const parsed = parseRange(rangeHeader, byteLength)
    if (parsed === 'invalid' || parsed === 'unsupported') {
      res.setHeader('Content-Range', `bytes */${byteLength}`)
      sendJson({ error: 'Range Not Satisfiable' }, 416)
      return
    }
    const { start, end } = parsed
    const responseLength = end - start + 1
    if (responseLength > gateway._maxResponseBytes) {
      res.setHeader('Content-Range', `bytes */${byteLength}`)
      sendJson({
        error: 'Requested range exceeds gateway byte limit',
        maxResponseBytes: gateway._maxResponseBytes
      }, 416)
      return
    }
    const firstBlock = Math.floor(start / blockSize)
    if (Math.floor(end / blockSize) !== firstBlock) {
      sendJson({
        error: 'Verify mode proves one blob block per request — narrow the range to a single block',
        blockSize
      }, 400)
      return
    }
    blockRel = firstBlock
  } else if (byteLength > gateway._maxResponseBytes) {
    sendJson({
      error: 'A bounded single byte range is required',
      maxResponseBytes: gateway._maxResponseBytes
    }, 413)
    return
  }

  const blockIndex = blob.blockOffset + blockRel
  if (blockIndex >= blobsCore.length) {
    sendJson({ error: 'Gateway verify bundle failed' }, 502)
    return
  }

  // ─── Proofs (local storage only — proof() never touches the swarm) ───
  const driveVersion = opts.driveVersion
  const blobProof = await gateway._withTimeout(
    blobsCore.proof({ block: { index: blockIndex }, upgrade: { start: 0, length: blobsCore.length } }),
    gateway._driveOperationTimeout,
    'blobs.proof()',
    opts.signal
  )
  if (!blobProof || !blobProof.block || !b4a.isBuffer(blobProof.block.value) ||
      !blobProof.upgrade || !b4a.isBuffer(blobProof.upgrade.signature)) {
    // We claim to serve these bytes, so we must hold them — no fetch-on-demand.
    sendJson({ error: 'Gateway verify bundle failed' }, 502)
    return
  }
  const entryProof = await gateway._withTimeout(
    beeCore.proof({ block: { index: entry.seq }, upgrade: { start: 0, length: driveVersion } }),
    gateway._driveOperationTimeout,
    'drive.proof()',
    opts.signal
  )
  if (!entryProof || !entryProof.block || !b4a.isBuffer(entryProof.block.value) ||
      !entryProof.upgrade || !b4a.isBuffer(entryProof.upgrade.signature)) {
    sendJson({ error: 'Gateway verify bundle failed' }, 502)
    return
  }

  const blobTreeHash = await gateway._withTimeout(
    blobsCore.treeHash(blobProof.upgrade.length),
    gateway._driveOperationTimeout,
    'blobs.treeHash()',
    opts.signal
  )
  const entryTreeHash = await gateway._withTimeout(
    beeCore.treeHash(driveVersion),
    gateway._driveOperationTimeout,
    'drive.treeHash()',
    opts.signal
  )

  // Same wire shaping as proof-of-storage.js: manifest cores need their
  // manifest shipped so a key-only verifier can check the signed upgrade.
  const blobManifest = blobsCore.core.compat ? null : blobsCore.core.header.manifest
  const entryManifest = beeCore.core.compat ? null : beeCore.core.header.manifest
  const blockBytes = blobProof.block.value
  const fileStart = blockRel * blockSize

  const envelope = {
    v: HC_BLOCK_ENVELOPE_VERSION,
    driveKey: keyHex,
    driveVersion,
    path: filePath,
    blockIndex,
    blockBytes: b4a.toString(blockBytes, 'hex'),
    fileRange: { start: fileStart, end: fileStart + blockBytes.byteLength - 1 },
    blob: {
      blockOffset: blob.blockOffset,
      blockLength: blob.blockLength,
      byteOffset: blob.byteOffset,
      byteLength: blob.byteLength,
      blockSize
    },
    blobsKey: b4a.toString(blobsCore.key, 'hex'),
    proof: b4a.toString(c.encode(wire.data, {
      request: 0,
      fork: blobProof.fork,
      block: blobProof.block,
      hash: null,
      seek: null,
      upgrade: blobProof.upgrade || null,
      manifest: blobManifest
    }), 'hex'),
    treeHeader: {
      fork: blobProof.fork,
      length: blobProof.upgrade.length,
      rootHash: b4a.toString(blobTreeHash, 'hex'),
      signature: b4a.toString(blobProof.upgrade.signature, 'hex')
    },
    entry: {
      blockIndex: entry.seq,
      blockBytes: b4a.toString(entryProof.block.value, 'hex'),
      proof: b4a.toString(c.encode(wire.data, {
        request: 0,
        fork: entryProof.fork,
        block: entryProof.block,
        hash: null,
        seek: null,
        upgrade: entryProof.upgrade || null,
        manifest: entryManifest
      }), 'hex'),
      treeHeader: {
        fork: entryProof.fork,
        length: driveVersion,
        rootHash: b4a.toString(entryTreeHash, 'hex'),
        signature: b4a.toString(entryProof.upgrade.signature, 'hex')
      }
    }
  }

  const payload = Buffer.from(JSON.stringify(envelope) + '\n')

  if (
    opts.exactBytes &&
    !opts.head &&
    payload.byteLength > 0 &&
    typeof opts.reserveResponseBytes === 'function' &&
    opts.reserveResponseBytes(payload.byteLength) !== true
  ) {
    sendJson({ error: 'Gateway byte-rate limit exceeded' }, 429, {
      'Retry-After': String(opts.egressRetryAfterSeconds || 60)
    })
    return
  }

  res.setHeader('Content-Type', HC_BLOCK_MEDIA_TYPE_JSON)
  res.setHeader('X-Hyper-Key', keyHex)
  res.setHeader('X-Served-By', 'hiverelay-gateway')
  res.setHeader('X-Content-Type-Options', 'nosniff')
  res.setHeader('Cache-Control', opts.exactBytes ? 'no-store, max-age=0' : 'public, max-age=60')
  res.setHeader('X-Hive-Drive-Version', String(driveVersion))
  if (opts.exactBytes) {
    res.setHeader('X-Hive-App-Key', keyHex)
    res.setHeader('X-Hive-Byte-Mode', 'verified')
    res.setHeader('Vary', 'Host')
    res.setHeader('Origin-Agent-Cluster', '?1')
  }
  res.setHeader('Content-Length', payload.byteLength)
  res.writeHead(200)
  if (opts.head) {
    res.end()
    return
  }
  gateway._totalBytesServed += payload.byteLength
  res.end(payload)
  gateway.emit('served', { keyHex, filePath, bytes: payload.byteLength })
}
