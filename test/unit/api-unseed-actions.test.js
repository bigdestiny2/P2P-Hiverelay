import test from 'brittle'
import {
  OPERATOR_UNSEED_AUTH_MESSAGE,
  resolveUnseedRoute,
  runOperatorUnseedAction,
  runPublisherUnseedAction
} from 'p2p-hiverelay/core/relay-node/api-unseed-actions.js'

test('api unseed actions: route resolver maps only exact operator and publisher unseed routes', (t) => {
  t.alike(resolveUnseedRoute('POST', '/unseed'), {
    kind: 'operator-unseed',
    authMessage: OPERATOR_UNSEED_AUTH_MESSAGE
  })
  t.alike(resolveUnseedRoute('POST', '/api/v1/unseed'), {
    kind: 'publisher-unseed'
  })
  t.is(resolveUnseedRoute('GET', '/unseed'), null, 'wrong method falls through')
  t.is(resolveUnseedRoute('POST', '/unseed/extra'), null, 'operator subpath falls through')
  t.is(resolveUnseedRoute('POST', '/api/v1/unseed/extra'), null, 'publisher subpath falls through')
  t.is(resolveUnseedRoute('POST', '/api/v1/seed'), null, 'adjacent publisher route falls through')
})

test('api unseed actions: operator unseed validates app key before mutation', async (t) => {
  const calls = []
  const node = {
    async unseedApp (appKey) {
      calls.push(appKey)
    }
  }

  let out = await runOperatorUnseedAction({ body: {}, node })
  t.is(out.status, 400)
  t.alike(out.payload, { error: 'appKey required' })

  out = await runOperatorUnseedAction({ body: { appKey: 'not-hex' }, node })
  t.is(out.status, 400)
  t.alike(out.payload, { error: 'appKey must be 64 hex characters' })
  t.alike(calls, [], 'invalid operator unseed does not mutate')

  out = await runOperatorUnseedAction({ body: { appKey: 'a'.repeat(64) }, node })
  t.is(out.ok, true)
  t.alike(out.payload, { ok: true })
  t.alike(calls, ['a'.repeat(64)])
})

test('api unseed actions: publisher-signed unseed validates body before verifier and mutation', async (t) => {
  const calls = []
  const node = {
    verifyUnseedRequest (...args) {
      calls.push(['verify', ...args])
      return { ok: true }
    },
    async unseedApp (appKey) {
      calls.push(['unseed', appKey])
    },
    broadcastUnseed (...args) {
      calls.push(['broadcast', ...args])
    }
  }
  const validBody = {
    appKey: 'a'.repeat(64),
    publisherPubkey: 'b'.repeat(64),
    signature: 'c'.repeat(128),
    timestamp: 123456789
  }

  for (const timestamp of ['123456789', 1.5, -1, Number.MAX_SAFE_INTEGER + 1]) {
    const out = await runPublisherUnseedAction({
      body: { ...validBody, timestamp },
      node
    })
    t.is(out.status, 400, 'malformed timestamp rejected')
    t.alike(out.payload, { error: 'timestamp must be a positive safe integer' })
  }
  t.alike(calls, [], 'malformed signed unseed does not verify, mutate, or broadcast')
})

test('api unseed actions: publisher-signed unseed preserves verifier decision and broadcast order', async (t) => {
  const calls = []
  const node = {
    verifyUnseedRequest (...args) {
      calls.push(['verify', ...args])
      return { ok: true }
    },
    async unseedApp (appKey) {
      calls.push(['unseed', appKey])
    },
    broadcastUnseed (...args) {
      calls.push(['broadcast', ...args])
    }
  }
  const body = {
    appKey: 'd'.repeat(64),
    publisherPubkey: 'e'.repeat(64),
    signature: 'f'.repeat(128),
    timestamp: 987654321
  }

  const out = await runPublisherUnseedAction({ body, node })
  t.is(out.ok, true)
  t.alike(out.payload, { ok: true, message: 'App unseeded and unseed broadcast to network' })
  t.alike(calls, [
    ['verify', body.appKey, body.publisherPubkey, body.signature, body.timestamp],
    ['unseed', body.appKey],
    ['broadcast', body.appKey, body.publisherPubkey, body.signature, body.timestamp]
  ])

  node.verifyUnseedRequest = () => ({ ok: false, error: 'STALE_TIMESTAMP' })
  const beforeReject = calls.length
  const rejected = await runPublisherUnseedAction({ body, node })
  t.is(rejected.status, 403)
  t.alike(rejected.payload, { error: 'STALE_TIMESTAMP' })
  t.is(calls.length, beforeReject, 'verifier rejection does not mutate or broadcast')
})
