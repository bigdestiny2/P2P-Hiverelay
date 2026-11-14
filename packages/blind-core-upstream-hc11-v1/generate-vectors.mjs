import fs from 'node:fs/promises'
import path from 'node:path'
import Corestore from 'corestore'
import crypto from 'hypercore-crypto'
import { FORMAT_CONTRACT, PROFILE_DIGEST, encodeFrame, encodeContainer, headIdentity, headHash, limitsOf } from './format.js'
const parent = new URL('./.scratch/', import.meta.url)
await fs.mkdir(parent, { recursive: true })
const root = await fs.mkdtemp(path.join(parent.pathname, 'vectors-'))
const store = new Corestore(root)
let serialized
try {
  const writer = store.get({ keyPair: crypto.keyPair(Buffer.alloc(32, 7)), encryptionKey: Buffer.alloc(32, 19) })
  await writer.ready()
  await writer.append([Buffer.from('private-vector-alpha'), Buffer.from('private-vector-bravo'), Buffer.from('private-vector-charlie')])
  const limits = limitsOf()
  const head = { corePublicKey: writer.key, fork: writer.fork, length: writer.length, treeHash: await writer.treeHash() }
  const headFrame = encodeFrame(writer, await writer.proof({ upgrade: { start: 0, length: writer.length } }), limits, true)
  const frames = []
  for (let index = 0; index < writer.length; index++) frames.push(encodeFrame(writer, await writer.proof({ block: { index }, upgrade: { start: 0, length: writer.length } }), limits))
  const corpus = encodeContainer(head, headFrame, frames, limits)
  const sample = encodeContainer(head, headFrame, [frames[0], frames[2]], limits, true)
  serialized = JSON.stringify({ version: 1, profileDigest: PROFILE_DIGEST.toString('hex'), fixtureOnly: true, keySeedHex: Buffer.alloc(32, 7).toString('hex'), encryptionKeyHex: Buffer.alloc(32, 19).toString('hex'), identityHex: headIdentity(head).toString('hex'), headHashHex: headHash(head).toString('hex'), headFrameHex: headFrame.toString('hex'), corpusHex: corpus.toString('hex'), sampleIndices: [0, 2], sampleHex: sample.toString('hex') }, null, 2) + '\n'
} finally { await store.close(); await fs.rm(root, { recursive: true, force: true }) }
for (const [file, contents] of [['vectors.json', serialized], ['format-contract.json', JSON.stringify(FORMAT_CONTRACT, null, 2) + '\n']]) {
  const target = new URL(file, import.meta.url)
  if (process.argv.includes('--check')) {
    if (await fs.readFile(target, 'utf8') !== contents) throw Error(file + ' is stale')
  } else await fs.writeFile(target, contents)
}
console.log('private head/corpus/proof vectors exact; profile=' + PROFILE_DIGEST.toString('hex'))
