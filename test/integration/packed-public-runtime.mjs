// Run explicitly against a real npm consumer containing the two local tarballs:
// node test/integration/packed-public-runtime.mjs /absolute/consumer-directory
// This verifies installed runtime paths; it never installs or publishes packages.
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { createRequire } from 'node:module'
import { pathToFileURL } from 'node:url'
import { spawnSync } from 'node:child_process'

const consumer = path.resolve(process.argv[2] || '')
assert(process.argv[2], 'consumer directory is required')
const require = createRequire(path.join(consumer, 'package.json'))
const load = specifier => import(pathToFileURL(require.resolve(specifier)).href)
const core = path.dirname(require.resolve('p2p-hiverelay/package.json'))
const services = path.dirname(require.resolve('p2p-hiveservices/builtin/arbitration-service.js'))
assert.equal(core, path.join(consumer, 'node_modules/p2p-hiverelay'))
assert.equal(services, path.join(consumer, 'node_modules/p2p-hiveservices/builtin'))
assert.equal(fs.realpathSync(core), core)
assert.equal(fs.realpathSync(services), services)
assert.throws(() => require.resolve('@hyperswarm/testnet'), { code: 'MODULE_NOT_FOUND' })
assert.throws(() => require.resolve('p2p-hiverelay-client'), { code: 'MODULE_NOT_FOUND' })

const { BandwidthReceipt } = await load('p2p-hiverelay/core/protocol/bandwidth-receipt.js')
const { ArbitrationService } = await load('p2p-hiveservices/builtin/arbitration-service.js')
const sodium = require('sodium-universal')
const keyPair = { publicKey: Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES), secretKey: Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES) }
sodium.crypto_sign_keypair(keyPair.publicKey, keyPair.secretKey)
const issuer = new BandwidthReceipt(keyPair)
const signed = issuer.createReceipt(Buffer.alloc(32, 1), 4096, Buffer.alloc(16, 2))
const tampered = { ...signed, bytesTransferred: signed.bytesTransferred + 1 }
assert.equal(BandwidthReceipt.verify(signed), true)
assert.equal(BandwidthReceipt.verify(tampered), false)
const service = new ArbitrationService()
const dispute = await service.submit({ type: 'receipt-dispute', respondent: 'fixture-relay', receipts: [signed, tampered, {}, null] }, { remotePubkey: 'fixture-claimant' })
const evidence = await service.evidence({ id: dispute.id })
assert.deepEqual(evidence.receipts.map(row => row.valid), [true, false, false, false])
assert.equal((await service.get({ id: dispute.id })).status, 'open', 'evidence inspection does not resolve or vote')
assert.deepEqual((await service.evidence({ id: dispute.id })).receipts.map(row => row.valid), [true, false, false, false], 'repeat inspection is stable')

const cli = path.join(core, 'cli/index.js')
const outputs = []
for (const args of [['testnet'], ['testnet', '--no-client']]) {
  const child = spawnSync(process.execPath, [cli, ...args], { cwd: consumer, encoding: 'utf8', timeout: 15000, env: { ...process.env, NODE_PATH: '' } })
  const output = child.stdout + child.stderr
  assert.equal(child.status, 1, output)
  assert.match(output, /source-workspace development command/)
  assert.match(output, /npm ci/)
  assert.doesNotMatch(output, /ERR_MODULE_NOT_FOUND|DHT bootstrap:|Testnet ID:/)
  outputs.push({ args, exitCode: child.status, stdout: child.stdout, stderr: child.stderr })
}
console.log(JSON.stringify({ status: 'passed', consumer, core, services, receiptVerification: [true, false, false, false], repeatInspection: true, disputeStillOpen: true, installedDevelopmentDependencies: false, cli: outputs }, null, 2))
