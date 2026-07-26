import { EventEmitter } from 'node:events'
import { Readable } from 'node:stream'
import test from 'brittle'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  OUTBOXLOG_FEDERATION_QUORUM_PATH,
  OutboxLogApp,
  createOutboxFederationQuorum,
  createFederationReceipt,
  verifyFederationReceipt
} from '../../packages/services/builtin/outboxlog/index.js'
import { createOutboxLogTokenAuth, handleOutboxLogRoute } from '../../packages/services/builtin/outboxlog/http-adapter.js'

const APP_ID = 'a'.repeat(64)
const COMMIT_ID = 'b'.repeat(64)
const HEAD = { version: 7, count: 11, root: 'c'.repeat(64) }
const LOCAL_RECEIPT = { ok: true, durable: true, appId: APP_ID, commitId: COMMIT_ID, head: HEAD }
const COMMIT = { commitId: COMMIT_ID }

test('outboxlog federation quorum: signed remote receipt binds one exact durable transition', async (t) => {
  const primaryKey = keyPair(11)
  const remoteKey = keyPair(12)
  let remoteCommits = 0
  const remote = createOutboxFederationQuorum({
    config: federationConfig(primaryKey.publicKeyHex, 'https://primary.example'),
    keyPair: remoteKey,
    now: () => 1000
  })
  const primary = createOutboxFederationQuorum({
    config: federationConfig(remoteKey.publicKeyHex, 'https://operator.example'),
    keyPair: primaryKey,
    now: () => 1000,
    fetch: async (url, opts) => {
      t.is(url, 'https://operator.example' + OUTBOXLOG_FEDERATION_QUORUM_PATH)
      const receipt = await remote.accept(JSON.parse(opts.body), {
        commit: async (appId, commit) => {
          remoteCommits++
          t.is(appId, APP_ID)
          t.alike(commit, COMMIT)
          return LOCAL_RECEIPT
        }
      })
      return { ok: true, json: async () => ({ receipt }) }
    }
  })

  const durability = await primary.confirm({ appId: APP_ID, commit: COMMIT, localReceipt: LOCAL_RECEIPT })
  t.is(remoteCommits, 1)
  t.is(durability.requiredRemoteAcks, 1)
  t.is(durability.receipts.length, 1)
  t.is(durability.receipts[0].relayPubkey, remoteKey.publicKeyHex)
  t.alike(verifyFederationReceipt(durability.receipts[0], {
    appId: APP_ID,
    commitId: COMMIT_ID,
    head: HEAD,
    relayPubkey: remoteKey.publicKeyHex
  }), { valid: true, receipt: durability.receipts[0] })
  t.alike(primary.descriptor(), {
    enabled: true,
    protocol: 'hiverelay-outboxlog-federation-v1',
    version: 1,
    requiredRemoteAcks: 1,
    relays: [{ id: 'operator', publicKey: remoteKey.publicKeyHex }]
  }, 'public descriptor exposes verification keys, never operator URLs')
})

test('outboxlog federation quorum: invalid or unavailable remote acknowledgement fails closed', async (t) => {
  const primaryKey = keyPair(21)
  const configuredRemote = keyPair(22)
  const attacker = keyPair(23)
  const primary = createOutboxFederationQuorum({
    config: federationConfig(configuredRemote.publicKeyHex, 'https://operator.example'),
    keyPair: primaryKey,
    fetch: async () => ({
      ok: true,
      json: async () => ({
        receipt: createFederationReceipt({
          appId: APP_ID,
          commitId: COMMIT_ID,
          head: HEAD,
          committedAt: 1000
        }, attacker)
      })
    })
  })

  const err = await rejects(primary.confirm({ appId: APP_ID, commit: COMMIT, localReceipt: LOCAL_RECEIPT }))
  t.is(err.status, 503)
  t.is(err.code, 'OUTBOXLOG_FEDERATION_QUORUM_UNAVAILABLE')
  t.is(err.message, 'network durability quorum not reached')
})

test('outboxlog federation quorum: HTTP route bypasses browser token only for relay-signed commits', async (t) => {
  const auth = createOutboxLogTokenAuth({ secret: 'a'.repeat(32) })
  const token = auth.issue()
  let confirmCalls = 0
  const app = {
    sync: {
      capabilities: () => ({ ready: true, serviceVersion: 'test', atomicCommit: { ready: true }, legacyWrites: { create: false, append: false } }),
      commit: async () => LOCAL_RECEIPT
    },
    federationQuorum: {
      enabled: true,
      confirm: async () => {
        confirmCalls++
        return { protocol: 'hiverelay-outboxlog-federation-v1', version: 1, requiredRemoteAcks: 1, receipts: [] }
      },
      accept: async input => ({ accepted: input.senderPubkey })
    },
    federationCapabilities: () => ({ enabled: true, requiredRemoteAcks: 1, relays: [] })
  }
  const ctx = { outboxLogApp: app, auth }

  const publicCommit = fakeRes()
  await handleOutboxLogRoute(jsonReq('/api/sync/commit', { appId: APP_ID, commit: COMMIT }, token), publicCommit, ctx)
  t.is(publicCommit.statusCode, 200)
  t.is(confirmCalls, 1)
  t.alike(jsonBody(publicCommit).networkDurability, {
    protocol: 'hiverelay-outboxlog-federation-v1', version: 1, requiredRemoteAcks: 1, receipts: []
  })

  const relayCommit = fakeRes()
  await handleOutboxLogRoute(jsonReq('/api/sync/federation/commit', { senderPubkey: 'd'.repeat(64) }), relayCommit, ctx)
  t.is(relayCommit.statusCode, 200, 'no browser token is consulted for the relay-only route')
  t.alike(jsonBody(relayCommit), { receipt: { accepted: 'd'.repeat(64) } })

  const status = fakeRes()
  await handleOutboxLogRoute(fakeReq('GET', '/api/bridge/status', null, { 'x-pear-token': token }), status, ctx)
  t.is(jsonBody(status).networkQuorum.enabled, true)
})

test('outboxlog federation quorum: service startup binds the configured relay identity', async (t) => {
  const primaryKey = keyPair(31)
  const remoteKey = keyPair(32)
  const app = new OutboxLogApp()
  await app.start({
    node: { swarm: { keyPair: primaryKey } },
    config: { outboxlog: { federationQuorum: federationConfig(remoteKey.publicKeyHex, 'https://operator.example') } }
  })
  t.is(app.federationQuorum.enabled, true)
  t.alike(app.federationCapabilities(), {
    enabled: true,
    protocol: 'hiverelay-outboxlog-federation-v1',
    version: 1,
    requiredRemoteAcks: 1,
    relays: [{ id: 'operator', publicKey: remoteKey.publicKeyHex }]
  })
  await app.stop()
})

function federationConfig (publicKey, url) {
  return {
    enabled: true,
    quorum: 1,
    peers: [{ id: 'operator', url, publicKey }]
  }
}

function keyPair (seedByte) {
  const publicKey = b4a.alloc(32)
  const secretKey = b4a.alloc(64)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, b4a.alloc(32, seedByte))
  return { publicKey, secretKey, publicKeyHex: b4a.toString(publicKey, 'hex') }
}

function fakeReq (method, url, body = null, headers = {}) {
  const req = Readable.from(body == null ? [] : [body])
  req.method = method
  req.url = url
  req.headers = { ...headers }
  req.socket = { remoteAddress: '127.0.0.1' }
  return req
}

function jsonReq (url, body, token = '') {
  const text = JSON.stringify(body)
  const headers = { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(text)) }
  if (token) headers['x-pear-token'] = token
  return fakeReq('POST', url, text, headers)
}

function fakeRes () {
  const res = new EventEmitter()
  res.headers = {}
  res.statusCode = null
  res.body = ''
  res.setHeader = function (name, value) { this.headers[name] = value }
  res.getHeader = function (name) { return this.headers[name] }
  res.hasHeader = function (name) { return this.headers[name] !== undefined }
  res.writeHead = function (status) { this.statusCode = status }
  res.end = function (body = '') { this.body = String(body); this.emit('finish') }
  return res
}

function jsonBody (res) {
  return JSON.parse(res.body)
}

async function rejects (promise) {
  try {
    await promise
  } catch (err) {
    return err
  }
  throw new Error('expected promise to reject')
}
