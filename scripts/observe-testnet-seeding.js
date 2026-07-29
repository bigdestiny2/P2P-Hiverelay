#!/usr/bin/env node

import createTestnet from '@hyperswarm/testnet'
import { RelayNode } from '../packages/core/core/relay-node/index.js'
import Hyperdrive from 'hyperdrive'
import b4a from 'b4a'
import { createHash, randomBytes } from 'crypto'
import { mkdir, rm } from 'fs/promises'
import { join } from 'path'
import { tmpdir } from 'os'
import { hashHex } from '../packages/core/core/custody-signing.js'

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms))
const TEST_MAX_STORAGE_BYTES = 64 * 1024 * 1024

async function waitFor (label, fn, timeoutMs = 30_000) {
  const start = Date.now()
  while (Date.now() - start < timeoutMs) {
    const value = await fn()
    if (value) return value
    await sleep(250)
  }
  throw new Error(`${label} timed out after ${timeoutMs}ms`)
}

async function settleWithin (promise, ms) {
  try {
    await Promise.race([
      promise,
      new Promise(resolve => setTimeout(resolve, ms))
    ])
  } catch {}
}

async function fetchText (url) {
  const res = await fetch(url, { signal: AbortSignal.timeout(10_000) })
  const body = await res.text()
  return { status: res.status, body }
}

async function main () {
  const expiryMode = process.argv.includes('--expiry')
  const blindMode = process.argv.includes('--blind') || expiryMode
  const id = randomBytes(4).toString('hex')
  const baseDir = join(tmpdir(), `hiverelay-observe-${id}`)
  const basePort = 19400 + Math.floor(Math.random() * 500)
  const testnet = await createTestnet(3)
  const relays = []
  const custodyEvents = []
  let publisher = null

  await mkdir(baseDir, { recursive: true })
  await mkdir(join(baseDir, 'publisher'), { recursive: true })
  for (let i = 0; i < 3; i++) await mkdir(join(baseDir, `relay-${i}`), { recursive: true })

  try {
    publisher = new RelayNode({
      storage: join(baseDir, 'publisher'),
      bootstrapNodes: testnet.bootstrap,
      enableAPI: false,
      enableRelay: false,
      enableSeeding: false,
      enableServices: false,
      shutdownTimeoutMs: 5000
    })
    await publisher.start()

    for (let i = 0; i < 3; i++) {
      const relay = new RelayNode({
        storage: join(baseDir, `relay-${i}`),
        bootstrapNodes: testnet.bootstrap,
        enableAPI: true,
        apiHost: '127.0.0.1',
        apiPort: basePort + i,
        enableRelay: true,
        enableSeeding: true,
        enableServices: false,
        acceptMode: 'open',
        custodyExpiryInterval: expiryMode ? 10_000 : undefined,
        custodyExpiryGraceMs: 0,
        shutdownTimeoutMs: 5000
      })
      await relay.start()
      relay.appLifecycle.on('custody-receipt', event => {
        custodyEvents.push({ relay: i, type: 'custody-receipt', intentId: event.intentId })
      })
      relay.appLifecycle.on('custody-receipt-error', event => {
        custodyEvents.push({ relay: i, type: 'custody-receipt-error', error: event.error, intentId: event.intentId })
      })
      relays.push(relay)
    }

    const drive = new Hyperdrive(publisher.store)
    await drive.ready()
    let ciphertextHash = null
    if (blindMode) {
      const ciphertext = randomBytes(4096)
      ciphertextHash = createHash('sha256').update(ciphertext).digest('hex')
      await drive.put('/sealed/blob.bin', ciphertext)
      await drive.put('/sealed/manifest.json', b4a.from(JSON.stringify({
        version: 1,
        kind: 'blind-observer-testnet',
        ciphertextRoot: ciphertextHash,
        note: 'Synthetic encrypted payload; relay must treat it as opaque bytes.'
      }, null, 2)))
    } else {
      await drive.put('/hello.txt', b4a.from('Hello from HiveRelay observer testnet!'))
      await drive.put('/test.json', b4a.from(JSON.stringify({ id, kind: 'observer-testnet' })))
      await drive.put('/docs/readme.md', b4a.from('# Observer Test\n\nThis file should survive publisher shutdown.\n'))
    }

    publisher.swarm.join(drive.discoveryKey, { server: true, client: true })
    await publisher.swarm.flush()

    const appKey = b4a.toString(drive.key, 'hex')
    const discoveryKey = b4a.toString(drive.discoveryKey, 'hex')
    const publisherKeyPair = publisher.swarm.keyPair
    const retainUntil = Date.now() + (expiryMode ? 15_000 : 30 * 24 * 60 * 60 * 1000)
    const blindContentId = blindMode ? hashHex({ appKey, ciphertextHash, id }) : null
    let custodyIntent = null
    if (blindMode) {
      custodyIntent = await relays[0].seedingRegistry.publishCustodyIntent({
        addressKey: appKey,
        blindContentId,
        ciphertextRoot: ciphertextHash,
        contentVersion: 1,
        requiredReplicas: relays.length,
        deadline: Date.now() + 60_000,
        retainUntil,
        shardPolicy: 'all'
      }, publisherKeyPair)
    }

    for (let i = 0; i < relays.length; i++) {
      await relays[i].seedApp(appKey, {
        type: 'drive',
        name: blindMode ? 'Observer Private Payload' : 'Observer Test Drive',
        categories: blindMode ? ['testnet', 'blind'] : ['testnet', 'files'],
        privacyTier: blindMode ? 'p2p-only' : 'public',
        blind: blindMode,
        storageClass: blindMode ? 'temporary' : 'persistent',
        availabilityClass: blindMode ? 'atomic-handoff' : 'always-on',
        custodyIntentId: custodyIntent?.intentId || null,
        blindContentId,
        ciphertextRoot: ciphertextHash,
        contentVersion: blindMode ? 1 : null,
        maxStorage: TEST_MAX_STORAGE_BYTES,
        retainUntil,
        shardIds: blindMode ? [i] : null
      })
    }

    await waitFor('relay anchoring', async () => {
      return relays.every(relay => relay.appRegistry.get(appKey)?.anchored === true)
    }, 45_000)

    const beforePublisherStop = await fetchText(
      blindMode
        ? `http://127.0.0.1:${basePort}/v1/hyper/${appKey}/sealed/manifest.json`
        : `http://127.0.0.1:${basePort}/v1/hyper/${appKey}/hello.txt`
    )

    await publisher.stop()
    publisher = null

    const afterPublisherStop = await fetchText(
      blindMode
        ? `http://127.0.0.1:${basePort + 1}/v1/hyper/${appKey}/sealed/blob.bin`
        : `http://127.0.0.1:${basePort + 1}/v1/hyper/${appKey}/docs/readme.md`
    )

    let retainedCiphertext = null
    let custodyStatus = null
    let expiryStatus = null
    if (blindMode) {
      const relayEntry = relays[1].seededApps.get(appKey)
      const retained = relayEntry ? await relayEntry.drive.get('/sealed/blob.bin') : null
      const retainedHash = retained ? createHash('sha256').update(retained).digest('hex') : null
      retainedCiphertext = {
        bytes: retained ? retained.byteLength : 0,
        expectedSha256: ciphertextHash,
        retainedSha256: retainedHash,
        matches: retainedHash === ciphertextHash
      }

      try {
        await waitFor('local custody receipts', async () => {
          return relays.every(relay => relay.seedingRegistry.getCustodyStatus(custodyIntent.intentId).receiptCount >= 1)
        }, 15_000)
      } catch (err) {
        err.message += ' ' + JSON.stringify({
          custodyEvents,
          localReceiptCounts: relays.map(relay => relay.seedingRegistry.getCustodyStatus(custodyIntent.intentId).receiptCount)
        })
        throw err
      }

      custodyStatus = await waitFor('custody quorum receipts', async () => {
        const status = relays[0].seedingRegistry.getCustodyStatus(custodyIntent.intentId)
        return status.receiptCount >= relays.length ? status : null
      }, 60_000)

      await relays[0].seedingRegistry.publishCustodyCommit({
        intentId: custodyIntent.intentId
      }, publisherKeyPair)

      await relays[0].seedingRegistry.publishSourceRetired({
        intentId: custodyIntent.intentId
      }, publisherKeyPair)

      await relays[0].seedingRegistry.recordCustodyProof({
        intentId: custodyIntent.intentId,
        relayPubkey: b4a.toString(relays[1].swarm.keyPair.publicKey, 'hex'),
        challengeNonce: hashHex({ id, challenge: 'blind-observer' }),
        shardIds: [1],
        blockIndices: [0],
        passed: retainedHash === ciphertextHash,
        latencyMs: 1
      }, publisherKeyPair)

      custodyStatus = relays[0].seedingRegistry.getCustodyStatus(custodyIntent.intentId)

      if (expiryMode) {
        await waitFor('temporary custody expiry', async () => {
          return relays.every(relay => !relay.appRegistry.has(appKey)) ? true : null
        }, 20_000)

        const nonServingProof = await relays[0].createCustodyNonServingProof(custodyIntent.intentId, {
          challengeNonce: hashHex({ id, challenge: 'post-expiry-not-serving' }),
          notServingReason: 'expired-unseeded'
        })

        const afterExpiry = await fetchText(
          `http://127.0.0.1:${basePort + 2}/v1/hyper/${appKey}/sealed/blob.bin`
        )
        custodyStatus = relays[0].seedingRegistry.getCustodyStatus(custodyIntent.intentId)
        expiryStatus = {
          retainUntil,
          expiredOnAllRelays: relays.every(relay => !relay.appRegistry.has(appKey)),
          seededAppsAfterExpiry: relays.map(relay => relay.seededApps.size),
          gatewayAfterExpiry: afterExpiry,
          nonServingProof: {
            type: nonServingProof.type,
            relayPubkey: nonServingProof.relayPubkey,
            challengeNonce: nonServingProof.challengeNonce,
            notServing: nonServingProof.notServing,
            catalogPresent: nonServingProof.catalogPresent,
            activeSwarmServing: nonServingProof.activeSwarmServing,
            limitationHash: nonServingProof.limitationHash
          }
        }
      }
    }

    const catalogRes = await fetch(`http://127.0.0.1:${basePort}/catalog.json?pageSize=20`, {
      signal: AbortSignal.timeout(10_000)
    })
    const catalog = await catalogRes.json()

    const statuses = relays.map((relay, i) => {
      const stats = relay.getStats()
      const entry = relay.appRegistry.get(appKey)
      return {
        relay: i,
        port: basePort + i,
        publicKey: stats.publicKey,
        seededApps: stats.seededApps,
        connections: stats.connections,
        custody: relay.config.custody,
        catalogEntry: entry
          ? {
              type: entry.type,
              name: entry.name,
              blind: entry.blind,
              storageClass: entry.storageClass,
              availabilityClass: entry.availabilityClass,
              privacyTier: entry.privacyTier,
              anchored: entry.anchored,
              anchoredLength: entry.anchoredLength
            }
          : null
      }
    })

    console.log(JSON.stringify({
      ok: true,
      mode: blindMode ? 'blind' : 'public',
      id,
      baseDir,
      basePort,
      appKey,
      discoveryKey,
      beforePublisherStop,
      afterPublisherStop,
      retainedCiphertext,
      expiryStatus,
      custodyStatus: custodyStatus
        ? {
            intentId: custodyStatus.intentId,
            receiptCount: custodyStatus.receiptCount,
            quorumReached: custodyStatus.quorumReached,
            committed: custodyStatus.committed,
            sourceRetired: custodyStatus.sourceRetired,
            proofCount: custodyStatus.proofCount,
            passingProofs: custodyStatus.passingProofs,
            nonServingProofCount: custodyStatus.nonServingProofCount,
            nonServingRelays: custodyStatus.nonServingRelays,
            relayQuorum: custodyStatus.relayQuorum
          }
        : null,
      catalogCounts: catalog.count,
      catalogFirstEntry: catalog.entries?.[0] || null,
      statuses
    }, null, 2))
  } finally {
    if (publisher) {
      await settleWithin(publisher.stop(), 5000)
    }
    for (const relay of relays.reverse()) {
      await settleWithin(relay.stop(), 5000)
    }
    await settleWithin(testnet.destroy(), 5000)
    await rm(baseDir, { recursive: true, force: true })
  }
}

main().then(() => {
  process.exit(0)
}).catch((err) => {
  console.error(err)
  process.exit(1)
})
