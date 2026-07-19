/**
 * R1 verifiable retrieval mode — gateway proof bundles + client verifier.
 *
 * Round-trips through a REAL Hyperdrive on an in-process Corestore (golden
 * drive, known content): the gateway's `?verify=1` / hc-block Accept surfaces
 * return a versioned bundle instead of raw bytes, and the independent client
 * verifier (packages/client/verify-block.js) must ACCEPT genuine bundles and
 * REJECT every tamper — wrong bytes, wrong index, stale header, wrong key,
 * path swap, forged signature — without trusting the gateway.
 *
 * Also pins the mode's edges: single-range-only behavior + frozen byte caps
 * identical to the raw lane, and identical admission (blind stays hard-403).
 */
import test from 'brittle'
import http from 'http'
import os from 'os'
import path from 'path'
import Corestore from 'corestore'
import Hyperdrive from 'hyperdrive'
import c from 'compact-encoding'
import { wire } from 'hypercore/lib/messages.js'
import { HyperGateway } from 'p2p-hiverelay/gateway'
import { verifyBlockBundle } from 'p2p-hiverelay-client/verify-block.js'
import { issueExactAppContext } from '../../packages/core/gateway/exact-app-context.js'

const HELLO = Buffer.from('hello world hello world hello world') // 35 bytes, 1 block
const BIG = Buffer.alloc(200000) // 4 blocks: 3 × 65536 + 3392
for (let i = 0; i < BIG.length; i++) BIG[i] = i % 251

let _n = 0
function tmp () { return path.join(os.tmpdir(), 'hr-gw-verify-' + process.pid + '-' + (_n++)) }

async function goldenDrive () {
  const store = new Corestore(tmp())
  const drive = new Hyperdrive(store)
  await drive.ready()
  await drive.put('/hello.txt', HELLO)
  await drive.put('/big.bin', BIG)
  await drive.put('/index.html', Buffer.from('<h1>golden</h1>'))
  await drive.put('/empty.txt', Buffer.alloc(0))
  return { store, drive }
}

async function bootGateway (t, drive, store, { entryExtras = {}, gatewayOpts = {}, context = null } = {}) {
  const keyHex = drive.key.toString('hex')
  const node = {
    config: { gatewayPublicOnlyPrivacyTier: true, hiveAppPublicKeys: [keyHex] },
    seededApps: new Map([[keyHex, { drive, blind: false, privacyTier: 'public', ...entryExtras }]])
  }
  const gateway = new HyperGateway(node, gatewayOpts)
  const server = http.createServer((req, res) => {
    if (!context) return gateway.handle(req, res)
    const url = new URL(req.url, 'http://localhost')
    gateway.handle(req, res, issueExactAppContext({
      appKey: keyHex,
      path: url.pathname,
      byteMode: 'exact',
      publicAppKeys: [keyHex]
    }))
  })
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  t.teardown(async () => {
    if (typeof server.closeAllConnections === 'function') {
      try { server.closeAllConnections() } catch (_) {}
    }
    await new Promise(resolve => server.close(resolve))
    await gateway.close()
    await drive.close()
    await store.close()
  })
  return {
    gateway,
    keyHex,
    port: server.address().port,
    path: (filePath = '/hello.txt', query = '') => `/v1/hyper/${keyHex}${filePath}${query}`
  }
}

function request (port, method, urlPath, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      hostname: '127.0.0.1',
      port,
      method,
      path: urlPath,
      agent: false,
      headers: { Connection: 'close', ...headers }
    }, (res) => {
      const chunks = []
      res.on('data', chunk => chunks.push(chunk))
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }))
      res.on('error', reject)
    })
    req.on('error', reject)
    req.end()
  })
}

const getJson = async (port, urlPath, headers = {}) => {
  const res = await request(port, 'GET', urlPath, headers)
  let body = null
  try { body = JSON.parse(res.body.toString()) } catch {}
  return { ...res, json: body }
}

function flipHexByte (hex, at = 0) {
  const i = at * 2
  const flipped = hex.slice(i, i + 2) === '00' ? 'ff' : '00'
  return hex.slice(0, i) + flipped + hex.slice(i + 2)
}

test('verify=1 round-trip: bundle proves golden file bytes against the drive key', async (t) => {
  const { store, drive } = await goldenDrive()
  const { port, keyHex, path: p } = await bootGateway(t, drive, store)

  const res = await getJson(port, p('/hello.txt', '?verify=1'))
  t.is(res.status, 200)
  t.is(res.headers['content-type'], 'application/vnd.hiverelay.hc-block+json')
  t.is(res.headers['x-hive-drive-version'], String(drive.version))

  const b = res.json
  t.is(b.v, 1)
  t.is(b.driveKey, keyHex)
  t.is(b.driveVersion, drive.version)
  t.is(b.path, '/hello.txt')
  t.is(b.blockIndex, 0)
  t.alike(b.blob, { blockOffset: 0, blockLength: 1, byteOffset: 0, byteLength: HELLO.length, blockSize: 65536 })
  t.alike(b.fileRange, { start: 0, end: HELLO.length - 1 })
  t.ok(/^[0-9a-f]{64}$/.test(b.blobsKey))
  t.ok(b.treeHeader.length >= 1 && /^[0-9a-f]{64}$/.test(b.treeHeader.rootHash) && b.treeHeader.signature.length > 0)
  t.ok(b.entry.treeHeader.length === drive.version)

  const verdict = await verifyBlockBundle(b)
  t.ok(verdict.valid, 'reason: ' + verdict.reason)
  t.ok(verdict.blockBytes.equals(HELLO))
  t.is(verdict.driveVersion, drive.version)
})

test('Accept: application/vnd.hiverelay.hc-block triggers the same bundle (+json form too)', async (t) => {
  const { store, drive } = await goldenDrive()
  const { port, path: p } = await bootGateway(t, drive, store)

  for (const accept of ['application/vnd.hiverelay.hc-block', 'application/vnd.hiverelay.hc-block+json']) {
    const res = await getJson(port, p('/hello.txt'), { Accept: accept })
    t.is(res.status, 200, accept)
    t.is(res.headers['content-type'], 'application/vnd.hiverelay.hc-block+json')
    const verdict = await verifyBlockBundle(res.json)
    t.ok(verdict.valid, accept + ' reason: ' + verdict.reason)
  }

  // No trigger → the raw lane is untouched.
  const raw = await request(port, 'GET', p('/hello.txt'))
  t.is(raw.status, 200)
  t.ok(raw.body.equals(HELLO))
  t.is(raw.headers['content-type'], 'text/plain; charset=utf-8')
})

test('multi-block file: ranges map to single blob blocks, all blocks verify', async (t) => {
  const { store, drive } = await goldenDrive()
  const { port, path: p } = await bootGateway(t, drive, store)

  // No range → first block of the file (clients iterate via the blob descriptor).
  const first = await getJson(port, p('/big.bin', '?verify=1'))
  t.is(first.status, 200)
  t.is(first.json.blockIndex, first.json.blob.blockOffset)
  t.alike(first.json.fileRange, { start: 0, end: 65535 })
  t.is(first.json.blob.blockLength, 4)
  t.ok((await verifyBlockBundle(first.json)).valid)
  t.ok(Buffer.from(first.json.blockBytes, 'hex').equals(BIG.subarray(0, 65536)))

  // Interior range → the block containing it.
  const mid = await getJson(port, p('/big.bin', '?verify=1'), { Range: 'bytes=70000-70010' })
  t.is(mid.status, 200)
  t.is(mid.json.blockIndex, mid.json.blob.blockOffset + 1)
  t.alike(mid.json.fileRange, { start: 65536, end: 131071 })
  const midVerdict = await verifyBlockBundle(mid.json)
  t.ok(midVerdict.valid, 'reason: ' + midVerdict.reason)
  t.ok(midVerdict.blockBytes.subarray(70000 - 65536, 70011 - 65536).equals(BIG.subarray(70000, 70011)))

  // Last (short) block.
  const tail = await getJson(port, p('/big.bin', '?verify=1'), { Range: 'bytes=199000-199999' })
  t.is(tail.status, 200)
  t.is(tail.json.blockIndex, tail.json.blob.blockOffset + 3)
  t.alike(tail.json.fileRange, { start: 196608, end: 199999 })
  const tailVerdict = await verifyBlockBundle(tail.json)
  t.ok(tailVerdict.valid, 'reason: ' + tailVerdict.reason)
  t.ok(tailVerdict.blockBytes.equals(BIG.subarray(196608)))
})

test('single-range only: spanning range 400, invalid range 416, multi-range 416', async (t) => {
  const { store, drive } = await goldenDrive()
  const { port, path: p } = await bootGateway(t, drive, store)

  const spanning = await getJson(port, p('/big.bin', '?verify=1'), { Range: 'bytes=65500-65600' })
  t.is(spanning.status, 400)
  t.ok(spanning.json.error.includes('one blob block'))

  const invalid = await getJson(port, p('/big.bin', '?verify=1'), { Range: 'bytes=999999999-' })
  t.is(invalid.status, 416)
  t.is(invalid.headers['content-range'], 'bytes */200000')

  const multi = await getJson(port, p('/big.bin', '?verify=1'), { Range: 'bytes=0-1,4-5' })
  t.is(multi.status, 416)
})

test('frozen limits: range beyond cap 416s, no-range oversized file 413s — like the raw lane', async (t) => {
  const { store, drive } = await goldenDrive()
  const { port, path: p } = await bootGateway(t, drive, store, { gatewayOpts: { maxResponseBytes: 100 } })

  const noRange = await getJson(port, p('/big.bin', '?verify=1'))
  t.is(noRange.status, 413)
  t.is(noRange.json.maxResponseBytes, 100)

  // A range whose length exceeds the cap refuses like the raw lane (a range
  // that clamps inside the file — bytes=0-199 on a 35-byte file — does not).
  const overCap = await getJson(port, p('/big.bin', '?verify=1'), { Range: 'bytes=0-199' })
  t.is(overCap.status, 416)
  t.is(overCap.json.maxResponseBytes, 100)

  // Within cap still serves (blockBytes are the proof unit and stay whole).
  const ok = await getJson(port, p('/hello.txt', '?verify=1'), { Range: 'bytes=0-10' })
  t.is(ok.status, 200)
  t.ok((await verifyBlockBundle(ok.json)).valid)
})

test('verify mode edges: directory 400, empty file 400, missing 404, HEAD headers-only', async (t) => {
  const { store, drive } = await goldenDrive()
  const { port, path: p } = await bootGateway(t, drive, store)

  const dir = await getJson(port, p('/missing-dir/', '?verify=1'))
  t.is(dir.status, 400)
  t.ok(dir.json.error.includes('file blocks only'))

  // A directory WITH an index.html resolves to the file and proves normally.
  const index = await getJson(port, p('/', '?verify=1'))
  t.is(index.status, 200)
  t.is(index.json.path, '/index.html')
  t.ok((await verifyBlockBundle(index.json)).valid)

  const empty = await getJson(port, p('/empty.txt', '?verify=1'))
  t.is(empty.status, 400)
  t.ok(empty.json.error.includes('blob blocks'))

  const missing = await getJson(port, p('/nope.txt', '?verify=1'))
  t.is(missing.status, 404)

  const head = await request(port, 'HEAD', p('/hello.txt', '?verify=1'))
  t.is(head.status, 200)
  t.is(head.headers['content-type'], 'application/vnd.hiverelay.hc-block+json')
  t.is(head.body.length, 0)
  t.ok(Number(head.headers['content-length']) > 0)
})

test('same admission as the raw lane: blind app stays hard-403 in verify mode', async (t) => {
  const { store, drive } = await goldenDrive()
  const { port, path: p } = await bootGateway(t, drive, store, { entryExtras: { blind: true } })

  const res = await getJson(port, p('/hello.txt', '?verify=1'))
  t.is(res.status, 403)
  t.ok(res.json.blind)
})

test('app-origin lane: exact context serves a verifying bundle with exact-lane headers', async (t) => {
  const { store, drive } = await goldenDrive()
  const { port } = await bootGateway(t, drive, store, {
    entryExtras: { storageClass: 'persistent', availabilityClass: 'always-on' },
    context: true
  })

  const res = await getJson(port, '/hello.txt?verify=1')
  t.is(res.status, 200)
  t.is(res.headers['content-type'], 'application/vnd.hiverelay.hc-block+json')
  t.is(res.headers['x-hive-byte-mode'], 'verified')
  t.is(res.headers['x-hive-app-key'], drive.key.toString('hex'))
  t.is(res.headers.vary, 'Host')
  t.is(res.headers['cache-control'], 'no-store, max-age=0')
  t.is(res.headers['x-hive-drive-version'], String(drive.version))

  const verdict = await verifyBlockBundle(res.json)
  t.ok(verdict.valid, 'reason: ' + verdict.reason)
  t.ok(verdict.blockBytes.equals(HELLO))

  // Accept trigger works on the app-origin lane too.
  const negotiated = await getJson(port, '/hello.txt', { Accept: 'application/vnd.hiverelay.hc-block' })
  t.is(negotiated.status, 200)
  t.ok((await verifyBlockBundle(negotiated.json)).valid)
})

test('tamper: wrong bytes, wrong index, stale header, wrong key, path swap, forgeries all REJECT', async (t) => {
  const { store, drive } = await goldenDrive()
  const { port, path: p } = await bootGateway(t, drive, store)

  const bundle = (await getJson(port, p('/big.bin', '?verify=1'), { Range: 'bytes=0-10' })).json
  t.ok((await verifyBlockBundle(bundle)).valid, 'baseline verifies')

  // Wrong bytes (envelope no longer matches the proved block).
  const wrongBytes = { ...bundle, blockBytes: flipHexByte(bundle.blockBytes, 10) }
  let v = await verifyBlockBundle(wrongBytes)
  t.absent(v.valid); t.is(v.reason, 'BLOCK_BYTES_MISMATCH')

  // Wrong index, still inside the blob extent.
  const wrongIndex = { ...bundle, blockIndex: bundle.blockIndex + 1 }
  v = await verifyBlockBundle(wrongIndex)
  t.absent(v.valid); t.is(v.reason, 'BLOCK_INDEX_MISMATCH')

  // Wrong index beyond the entry-proved blob extent.
  const outOfRange = { ...bundle, blockIndex: bundle.blob.blockOffset + bundle.blob.blockLength + 4 }
  v = await verifyBlockBundle(outOfRange)
  t.absent(v.valid); t.is(v.reason, 'BLOCK_OUT_OF_RANGE')

  // Wrong drive key — the manifest hash no longer matches.
  const other = await goldenDrive()
  t.teardown(async () => { await other.drive.close(); await other.store.close() })
  const wrongKey = { ...bundle, driveKey: other.drive.key.toString('hex') }
  v = await verifyBlockBundle(wrongKey)
  t.absent(v.valid); t.is(v.reason, 'DRIVE_KEY_MISMATCH')

  // Path swap — the proved bee node names the real path.
  const wrongPath = { ...bundle, path: '/hello.txt' }
  v = await verifyBlockBundle(wrongPath)
  t.absent(v.valid); t.is(v.reason, 'PATH_MISMATCH')

  // Blob descriptor claim that disagrees with the proved entry.
  const wrongBlob = { ...bundle, blob: { ...bundle.blob, byteLength: bundle.blob.byteLength - 1 } }
  v = await verifyBlockBundle(wrongBlob)
  t.absent(v.valid); t.is(v.reason, 'BLOB_MISMATCH')

  // Forged tree header signature (no longer the signature the proof carried).
  const forgedHeader = { ...bundle, treeHeader: { ...bundle.treeHeader, signature: flipHexByte(bundle.treeHeader.signature, 4) } }
  v = await verifyBlockBundle(forgedHeader)
  t.absent(v.valid); t.is(v.reason, 'BLOCK_HEADER_MISMATCH')

  // Forged proof (flipped byte inside the signed upgrade) — rejected: the
  // header no longer matches the tampered proof, or hypercore itself rejects.
  const decoded = c.decode(wire.data, Buffer.from(bundle.proof, 'hex'))
  decoded.upgrade.signature[0] ^= 0xff
  const forgedProof = { ...bundle, proof: c.encode(wire.data, decoded).toString('hex') }
  v = await verifyBlockBundle(forgedProof)
  t.absent(v.valid)
  t.ok(v.reason === 'BLOCK_HEADER_MISMATCH' || (v.reason && v.reason.startsWith('BLOCK_INVALID')), 'reason: ' + v.reason)

  // Stale header: bundle the drive BEFORE a write, then mix its tree headers
  // into the post-write bundle — old headers must not ride a new proof.
  const before = { treeHeader: bundle.treeHeader, entryHeader: bundle.entry.treeHeader, driveVersion: bundle.driveVersion }
  await drive.put('/later.txt', Buffer.from('written after the first bundle'))
  const after = (await getJson(port, p('/big.bin', '?verify=1'), { Range: 'bytes=0-10' })).json
  t.ok(after.driveVersion > before.driveVersion)

  const staleEntryHeader = { ...after, entry: { ...after.entry, treeHeader: before.entryHeader } }
  v = await verifyBlockBundle(staleEntryHeader)
  t.absent(v.valid); t.is(v.reason, 'ENTRY_HEADER_MISMATCH')

  const staleBlobHeader = { ...after, treeHeader: before.treeHeader }
  v = await verifyBlockBundle(staleBlobHeader)
  t.absent(v.valid); t.is(v.reason, 'BLOCK_HEADER_MISMATCH')

  // …but a self-consistent OLD bundle still verifies at ITS pinned version:
  // staleness is a version-pinning decision for the client, not a forgery.
  t.ok((await verifyBlockBundle(bundle)).valid, 'old bundle remains valid at its driveVersion')
})

test('envelope version gate: unknown v rejects before any crypto', async (t) => {
  const { store, drive } = await goldenDrive()
  const { port, path: p } = await bootGateway(t, drive, store)
  const bundle = (await getJson(port, p('/hello.txt', '?verify=1'))).json
  const v = await verifyBlockBundle({ ...bundle, v: 2 })
  t.absent(v.valid)
  t.is(v.reason, 'ENVELOPE_VERSION_UNSUPPORTED')
})
