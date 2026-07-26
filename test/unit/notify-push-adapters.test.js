import test from 'brittle'
import { generateKeyPairSync, createPublicKey, verify as cryptoVerify } from 'node:crypto'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import { createApnsProvider, APNS_HOST_SANDBOX } from '../../packages/services/builtin/notify-push/apns.js'
import { createFcmProvider } from '../../packages/services/builtin/notify-push/fcm.js'
import { createWebPushProvider } from '../../packages/services/builtin/notify-push/webpush.js'
import { createPushProvider, sealDeviceToken, createTokenOpener } from '../../packages/services/builtin/notify-push/index.js'

const NOW = 1782864000000

// Every key here is generated in-process. Nothing reads a credential file and
// nothing touches the network — all HTTP goes through a recording transport.
function ecPem () {
  return generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    .privateKey.export({ type: 'pkcs8', format: 'pem' })
}

function rsaPem () {
  return generateKeyPairSync('rsa', { modulusLength: 2048 })
    .privateKey.export({ type: 'pkcs8', format: 'pem' })
}

function recorder (responses) {
  const calls = []
  const queue = Array.isArray(responses) ? [...responses] : null
  return {
    calls,
    transport: async (req) => {
      calls.push(req)
      if (queue) return queue.length > 1 ? queue.shift() : queue[0]
      return responses
    }
  }
}

const plainToken = createTokenOpener('plaintext')

// The watch-wake shape: NO `intent` key, empty payload, `watch` metadata.
// An adapter that dereferences `delivery.intent` blows up only on this path,
// which is exactly the path that matters for waking a bot.
function watchDelivery (overrides = {}) {
  return {
    provider: 'apns',
    credentialMode: 'runtime-owned',
    providerTokenCiphertext: 'device-token-abc',
    app: 'a'.repeat(64),
    device: 'd'.repeat(64),
    channel: 'mail',
    urgency: 'normal',
    ttlSeconds: 600,
    collapseKey: 'watch:' + 'f'.repeat(64),
    payloadCiphertext: '',
    genericDisplay: true,
    watch: { watchId: 'f'.repeat(64), seq: 3 },
    ...overrides
  }
}

test('notify push apns: signs a bearer JWT and survives the intent-less watch shape', async (t) => {
  const pem = ecPem()
  const rec = recorder({ status: 200, body: {} })
  const apns = createApnsProvider({
    credentials: { privateKey: pem, keyId: 'KID', teamId: 'TEAM', bundleId: 'app.bundle.id', host: APNS_HOST_SANDBOX },
    transport: rec.transport,
    openToken: plainToken,
    now: () => NOW
  })

  t.is(apns.kind, 'apns')
  t.is(apns.live, true)

  const result = await apns.send(watchDelivery())
  t.is(result.status, 'accepted_by_provider')
  t.is(rec.calls.length, 1)

  const req = rec.calls[0]
  t.ok(req.url.startsWith(APNS_HOST_SANDBOX), 'sandbox host honoured, not a hardcoded production host')
  t.ok(req.url.endsWith('/3/device/device-token-abc'))
  t.ok(req.headers.authorization.startsWith('bearer '), 'lowercase bearer per APNS')
  t.is(req.headers['apns-topic'], 'app.bundle.id')
  t.is(req.headers['apns-push-type'], 'background', 'no payload → silent background wake')
  t.is(req.headers['apns-collapse-id'].length, 64, 'collapse id truncated to the APNS limit')
  t.is(req.headers['apns-expiration'], String(Math.floor(NOW / 1000) + 600))
  t.is(req.body.aps['content-available'], 1)
  t.absent(req.body.c, 'no payload key when there is no ciphertext')

  // The JWT must verify against the configured key.
  const [h, p, s] = req.headers.authorization.slice('bearer '.length).split('.')
  t.ok(cryptoVerify(
    'sha256',
    Buffer.from(h + '.' + p, 'utf8'),
    { key: createPublicKey(pem), dsaEncoding: 'ieee-p1363' },
    Buffer.from(s, 'base64url')
  ), 'APNS JWT verifies')
  const payload = JSON.parse(Buffer.from(p, 'base64url').toString())
  t.is(payload.iss, 'TEAM')
  t.is(JSON.parse(Buffer.from(h, 'base64url').toString()).kid, 'KID')
})

test('notify push apns: caches the JWT for 55 minutes', async (t) => {
  let clock = NOW
  const rec = recorder({ status: 200, body: {} })
  const apns = createApnsProvider({
    credentials: { privateKey: ecPem(), keyId: 'KID', teamId: 'TEAM', bundleId: 'b' },
    transport: rec.transport,
    openToken: plainToken,
    now: () => clock
  })

  await apns.send(watchDelivery())
  const first = rec.calls[0].headers.authorization

  clock += 54 * 60 * 1000
  await apns.send(watchDelivery())
  t.is(rec.calls[1].headers.authorization, first, 'reused inside the window')

  clock += 2 * 60 * 1000
  await apns.send(watchDelivery())
  t.not(rec.calls[2].headers.authorization, first, 're-minted after expiry')
})

test('notify push apns: maps provider responses to the four-status vocabulary', async (t) => {
  const credentials = { privateKey: ecPem(), keyId: 'KID', teamId: 'TEAM', bundleId: 'b' }
  const build = (response) => createApnsProvider({
    credentials, transport: recorder(response).transport, openToken: plainToken, now: () => NOW
  })

  // token_invalid permanently stales the binding — only Apple's two "this token
  // is dead" responses may produce it.
  t.is((await build({ status: 410, body: { reason: 'Unregistered' } }).send(watchDelivery())).status, 'token_invalid')
  t.is((await build({ status: 400, body: { reason: 'BadDeviceToken' } }).send(watchDelivery())).status, 'token_invalid')

  // A throttle or an outage must NOT stale the binding.
  t.is((await build({ status: 429, body: { reason: 'TooManyRequests' } }).send(watchDelivery())).status, 'provider_attempted')
  t.is((await build({ status: 503, body: {} }).send(watchDelivery())).status, 'provider_attempted')
  t.is((await build({ status: 400, body: { reason: 'BadTopic' } }).send(watchDelivery())).status, 'provider_rejected')

  const thrower = createApnsProvider({
    credentials,
    transport: async () => { throw new Error('econnreset') },
    openToken: plainToken,
    now: () => NOW
  })
  const errored = await thrower.send(watchDelivery())
  t.is(errored.status, 'provider_attempted')
  t.is(errored.billable, false, 'an unknown outcome is never billed')
})

test('notify push apns: an unreadable token is token_invalid, not a crash', async (t) => {
  const apns = createApnsProvider({
    credentials: { privateKey: ecPem(), keyId: 'KID', teamId: 'TEAM', bundleId: 'b' },
    transport: recorder({ status: 200, body: {} }).transport,
    openToken: () => null,
    now: () => NOW
  })
  t.is((await apns.send(watchDelivery())).status, 'token_invalid')
})

test('notify push fcm: exchanges an assertion for an access token and caches it', async (t) => {
  const pem = rsaPem()
  const tokenRec = recorder({ status: 200, body: { access_token: 'ya29.test', expires_in: 3600 } })
  const sendRec = recorder({ status: 200, body: { name: 'projects/p/messages/1' } })
  let clock = NOW
  const fcm = createFcmProvider({
    credentials: { privateKey: pem, clientEmail: 'svc@p.iam.gserviceaccount.com', projectId: 'proj-1' },
    transport: sendRec.transport,
    tokenTransport: tokenRec.transport,
    openToken: plainToken,
    now: () => clock
  })

  const result = await fcm.send(watchDelivery({ provider: 'fcm' }))
  t.is(result.status, 'accepted_by_provider')
  t.is(tokenRec.calls.length, 1, 'one token exchange')
  t.is(sendRec.calls[0].headers.Authorization, 'Bearer ya29.test')
  t.ok(sendRec.calls[0].url.includes('proj-1'), 'project-scoped send URL')

  // Data-only: an FCM `notification` block would make the OS render text the
  // relay does not have.
  const message = sendRec.calls[0].body.message
  t.is(message.token, 'device-token-abc')
  t.absent(message.notification, 'no OS-rendered notification block')
  t.is(message.android.ttl, '600s')

  // The assertion itself must verify.
  const form = tokenRec.calls[0].form
  t.is(form.grant_type, 'urn:ietf:params:oauth:grant-type:jwt-bearer')
  const [h, p, s] = form.assertion.split('.')
  t.ok(cryptoVerify('sha256', Buffer.from(h + '.' + p, 'utf8'), createPublicKey(pem), Buffer.from(s, 'base64url')))

  clock += 30 * 60 * 1000
  await fcm.send(watchDelivery({ provider: 'fcm' }))
  t.is(tokenRec.calls.length, 1, 'access token reused, not re-minted per send')

  clock += 30 * 60 * 1000
  await fcm.send(watchDelivery({ provider: 'fcm' }))
  t.is(tokenRec.calls.length, 2, 're-exchanged after expires_in - 60s')
})

test('notify push fcm: auth failure never stales the binding', async (t) => {
  const fcm = createFcmProvider({
    credentials: { privateKey: rsaPem(), clientEmail: 'svc@p.iam', projectId: 'p' },
    transport: recorder({ status: 200, body: {} }).transport,
    tokenTransport: recorder({ status: 401, body: { error: 'invalid_grant' } }).transport,
    openToken: plainToken,
    now: () => NOW
  })
  const result = await fcm.send(watchDelivery({ provider: 'fcm' }))
  // An operator's broken service account must not mark every user's device dead.
  t.is(result.status, 'provider_attempted')
  t.is(result.reason, 'fcm_auth_failed')
})

test('notify push fcm: UNREGISTERED is token_invalid, 5xx is not', async (t) => {
  const credentials = { privateKey: rsaPem(), clientEmail: 'svc@p.iam', projectId: 'p' }
  const build = (response) => createFcmProvider({
    credentials,
    transport: recorder(response).transport,
    tokenTransport: recorder({ status: 200, body: { access_token: 't', expires_in: 3600 } }).transport,
    openToken: plainToken,
    now: () => NOW
  })

  const unregistered = await build({
    status: 404,
    body: { error: { status: 'NOT_FOUND', details: [{ errorCode: 'UNREGISTERED' }] } }
  }).send(watchDelivery({ provider: 'fcm' }))
  t.is(unregistered.status, 'token_invalid')

  t.is((await build({ status: 503, body: {} }).send(watchDelivery({ provider: 'fcm' }))).status, 'provider_attempted')
  t.is((await build({ status: 400, body: { error: { status: 'INVALID_ARGUMENT' } } }).send(watchDelivery({ provider: 'fcm' }))).status, 'provider_rejected')
})

test('notify push webpush: vapid header is audience-bound to the endpoint origin', async (t) => {
  const jwk = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({ format: 'jwk' })
  const rec = recorder({ status: 201, body: null })
  const wp = createWebPushProvider({
    credentials: { privateKey: jwk.d, subject: 'mailto:ops@example.com' },
    transport: rec.transport,
    openToken: plainToken,
    now: () => NOW
  })

  const result = await wp.send(watchDelivery({
    provider: 'webpush',
    providerTokenCiphertext: 'https://push.example.com/sub/abc?tok=1'
  }))
  t.is(result.status, 'accepted_by_provider')

  const auth = rec.calls[0].headers.Authorization
  t.ok(auth.startsWith('vapid t='), 'RFC 8292 vapid scheme')
  t.ok(auth.includes(',k='), 'advertises the public key')
  const jwt = auth.slice('vapid t='.length).split(',k=')[0]
  const payload = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString())
  t.is(payload.aud, 'https://push.example.com', 'origin only — never the full endpoint path')
  t.is(payload.sub, 'mailto:ops@example.com')
  t.is(rec.calls[0].headers.TTL, '600')
  // A `watch:<64 hex>` collapse key is neither short enough nor in-alphabet for
  // an RFC 8030 Topic header.
  t.ok(/^[A-Za-z0-9\-_]{1,32}$/.test(rec.calls[0].headers.Topic), 'Topic is web-safe and bounded')
})

test('notify push webpush: rejects bad config and bad endpoints', async (t) => {
  const jwk = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey.export({ format: 'jwk' })
  const base = { privateKey: jwk.d, subject: 'mailto:ops@example.com' }

  t.exception(
    () => createWebPushProvider({ credentials: { privateKey: jwk.d }, openToken: plainToken }),
    /subject required/,
    'VAPID requires a contact subject'
  )
  t.exception(
    () => createWebPushProvider({ credentials: { ...base, subject: 'ops@example.com' }, openToken: plainToken }),
    /mailto: or https:/,
    'bare email rejected'
  )

  const wp = createWebPushProvider({
    credentials: base, transport: recorder({ status: 201 }).transport, openToken: plainToken, now: () => NOW
  })
  t.is((await wp.send(watchDelivery({ providerTokenCiphertext: 'http://insecure.example/s' }))).status, 'token_invalid')
  t.is((await wp.send(watchDelivery({ providerTokenCiphertext: 'not a url' }))).status, 'token_invalid')

  const gone = createWebPushProvider({
    credentials: base, transport: recorder({ status: 410 }).transport, openToken: plainToken, now: () => NOW
  })
  t.is((await gone.send(watchDelivery({ providerTokenCiphertext: 'https://push.example/s' }))).status, 'token_invalid')

  const busy = createWebPushProvider({
    credentials: base, transport: recorder({ status: 429 }).transport, openToken: plainToken, now: () => NOW
  })
  t.is((await busy.send(watchDelivery({ providerTokenCiphertext: 'https://push.example/s' }))).status, 'provider_attempted')
})

test('notify push factory: unknown kinds throw, multi routes on the binding provider', async (t) => {
  await t.exception(createPushProvider({ kind: 'nope' }), /NOTIFY_PUSH_UNKNOWN_KIND/)
  await t.exception(createPushProvider(null), /NOTIFY_PUSH_BAD_CONFIG/)
  await t.exception(createPushProvider({ kind: 'multi', providers: {} }), /at least one entry/)

  const apnsCalls = []
  const fcmCalls = []
  const multi = await createPushProvider({
    kind: 'multi',
    tokenEncoding: 'plaintext',
    providers: {
      apns: { send: async (d) => { apnsCalls.push(d); return { status: 'accepted_by_provider' } } },
      fcm: { send: async (d) => { fcmCalls.push(d); return { status: 'accepted_by_provider' } } }
    }
  })

  t.is(multi.kind, 'multi')
  t.is(multi.live, true)
  await multi.send(watchDelivery({ provider: 'apns' }))
  await multi.send(watchDelivery({ provider: 'fcm' }))
  t.is(apnsCalls.length, 1)
  t.is(fcmCalls.length, 1)

  // An unconfigured provider must be *rejected*, not marked token_invalid —
  // staling the binding would leave the device permanently unreachable even
  // after the operator adds the missing adapter.
  const missing = await multi.send(watchDelivery({ provider: 'webpush' }))
  t.is(missing.status, 'provider_rejected')
  t.is(missing.reason, 'provider_not_configured')

  const runtime = await multi.send(watchDelivery({ provider: 'runtime' }))
  t.is(runtime.status, 'provider_rejected')
})

test('notify push token codec: sealed tokens open only with the relay key', async (t) => {
  const relay = keyPair(1)
  const other = keyPair(2)

  const sealed = sealDeviceToken('apns-device-token', relay.publicKey)
  const open = createTokenOpener('sealed', relay)
  t.is(open(sealed), 'apns-device-token', 'relay opens its own sealed token')

  t.is(createTokenOpener('sealed', other)(sealed), null, 'another relay cannot open it')
  t.is(open('not-base64-sealed'), null, 'garbage returns null, never throws')
  t.is(open(''), null)
  t.is(open(null), null)

  t.exception(() => createTokenOpener('sealed', null), /requires the relay key pair/)
  t.exception(() => createTokenOpener('bogus', relay), /NOTIFY_PUSH_BAD_TOKEN_ENCODING/)

  // Plaintext mode is opt-in and passes the token through verbatim.
  t.is(createTokenOpener('plaintext')('raw-token'), 'raw-token')
  t.is(createTokenOpener('plaintext')(''), null)
})

function keyPair (seed) {
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  const s = b4a.alloc(sodium.crypto_sign_SEEDBYTES)
  s.fill(seed)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, s)
  return { publicKey, secretKey }
}
