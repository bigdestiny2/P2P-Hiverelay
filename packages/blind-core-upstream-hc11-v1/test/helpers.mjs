import fs from 'node:fs/promises'
import path from 'node:path'
import Corestore from 'corestore'
import crypto from 'hypercore-crypto'
import { RealCoreUpstreamV1, headHash } from '../index.js'
export async function fixture (t, opts = {}) {
  const parent = new URL('../.scratch/', import.meta.url)
  await fs.mkdir(parent, { recursive: true })
  const root = await fs.mkdtemp(path.join(parent.pathname, 'case-'))
  const writerStore = new Corestore(path.join(root, 'writer'))
  const keyPair = crypto.keyPair(Buffer.alloc(32, opts.seed ?? 7))
  const writer = writerStore.get({ keyPair, encryptionKey: Buffer.alloc(32, 19) })
  await writer.ready()
  let persisted = null; let connections = 0
  const upstream = new RealCoreUpstreamV1({
    root: path.join(root, 'upstream'),
    connect: opts.connect || (() => { connections++; return writer.replicate(false) }),
    readCorpus: async () => { if (!persisted) throw new Error('no persisted corpus'); return persisted },
    limits: opts.limits
  })
  t.after(async () => { await upstream.close(); await writerStore.close(); await fs.rm(root, { recursive: true, force: true }) })
  return { root, writer, writerStore, upstream, keyPair, connections: () => connections, persist: bytes => { persisted = Buffer.from(bytes) } }
}
export async function headRequest (writer) {
  return { corePublicKey: Buffer.from(writer.key), fork: BigInt(writer.fork), length: BigInt(writer.length), signedHeadHash: headHash({ corePublicKey: writer.key, fork: writer.fork, length: writer.length, treeHash: await writer.treeHash() }) }
}
