import { createHash, createHmac, randomBytes } from 'node:crypto'
import test from 'brittle'
import b4a from 'b4a'
import {
  POW_ISSUANCE_V1_CHALLENGE_BYTES,
  POW_ISSUANCE_V1_SCHEME_ID,
  POW_ISSUANCE_V1_TOKEN_BYTES,
  buildPowIssuanceV1Presentation,
  countLeadingZeroBits,
  derivePowIssuanceV1Keys,
  hmacSha256,
  mintPowIssuanceV1Challenge,
  mintPowIssuanceV1Token,
  parsePowIssuanceV1Challenge,
  parsePowIssuanceV1Presentation,
  parsePowIssuanceV1Token,
  powIssuanceV1IssuerKeyCommitment,
  powIssuanceV1Preimage,
  powIssuanceV1RecordBindingRoot,
  powIssuanceV1SpendTag,
  verifyPowIssuanceV1Work
} from '../pow-issuance-v1/token-codec.js'
import {
  PowIssuanceV1AdmissionAdapter,
  createPowIssuanceV1AdapterResolver
} from '../pow-issuance-v1/admission-adapter.js'
import { createPowIssuanceV1Issuer } from '../pow-issuance-v1/issuer-service.js'

const issuerKey = b4a.from(randomBytes(32))
const keys = derivePowIssuanceV1Keys(issuerKey)

function mineNonce (challengePayload, recordCommitment, difficultyBits, start = 0n) {
  for (let nonce = start; nonce < start + (1n << 28n); nonce++) {
    const digest = createHash('sha256')
      .update(powIssuanceV1Preimage(challengePayload, recordCommitment, nonce))
      .digest()
    if (countLeadingZeroBits(digest) >= difficultyBits) return nonce
  }
  throw new Error('mining space exhausted')
}

function adapterInput (overrides = {}) {
  const commitment = b4a.from(randomBytes(32))
  const token = mintPowIssuanceV1Token(keys.tokenKey, {
    challengeId: b4a.from(randomBytes(32)),
    recordCommitment: powIssuanceV1RecordBindingRoot([commitment]),
    allowance: 1,
    expiryEpoch: 100
  })
  return {
    admission: {
      profileId: 8,
      schemeId: POW_ISSUANCE_V1_SCHEME_ID,
      parameterHash: b4a.alloc(32, 0x44),
      token: buildPowIssuanceV1Presentation(token, 0, [commitment])
    },
    familyId: 3,
    operationId: 4,
    costClass: Object.freeze({ resourceClass: 4, leaseClass: 0, costUnits: 10n }),
    requestCommitment: commitment,
    parameters: null,
    endpointId: 1,
    signal: null,
    ...overrides
  }
}

function assertPublicBrowserHeaders (t, response, label) {
  t.is(response.headers.get('access-control-allow-origin'), '*', `${label}: public wildcard origin`)
  t.is(response.headers.get('cross-origin-resource-policy'), 'cross-origin', `${label}: public cross-origin resource`)
  t.is(response.headers.get('access-control-allow-credentials'), null, `${label}: credentials are never allowed`)
  t.is(response.headers.get('vary'), null, `${label}: no origin-dependent Vary`)
  t.is(response.headers.get('set-cookie'), null, `${label}: no cookie is set`)
}

async function assertPreflight (t, response, { label, methods, allowHeaders }) {
  t.is(response.status, 204, `${label}: preflight accepted`)
  assertPublicBrowserHeaders(t, response, label)
  t.is(response.headers.get('access-control-allow-methods'), methods, `${label}: exact methods`)
  t.is(response.headers.get('access-control-allow-headers'), allowHeaders, `${label}: exact allowed headers`)
  t.is(response.headers.get('access-control-max-age'), '600', `${label}: bounded preflight cache`)
  t.is(response.headers.get('cache-control'), 'no-store', `${label}: response is not cacheable`)
  t.is(response.headers.get('content-length'), '0', `${label}: empty response length`)
  t.is(await response.text(), '', `${label}: empty response body`)
}

test('codec: challenge mint/parse roundtrip, foreign key and expiry rejected', t => {
  const challenge = mintPowIssuanceV1Challenge(keys.challengeKey, {
    ttlSeconds: 120,
    difficultyBits: 20,
    issuedAtUnix: 1000
  })
  t.is(challenge.byteLength, POW_ISSUANCE_V1_CHALLENGE_BYTES)
  const parsed = parsePowIssuanceV1Challenge(keys.challengeKey, challenge, { nowUnix: 1100 })
  t.is(parsed.difficultyBits, 20)
  t.is(parsed.issuedAtUnix, 1000)
  t.is(parsed.ttlSeconds, 120)
  t.exception(() => parsePowIssuanceV1Challenge(b4a.from(randomBytes(32)), challenge, { nowUnix: 1100 }),
    /challenge signature is invalid/)
  t.exception(() => parsePowIssuanceV1Challenge(keys.challengeKey, challenge, { nowUnix: 1000 + 120 }),
    /challenge has expired/)
  const tampered = b4a.from(challenge)
  tampered[5] ^= 1
  t.exception(() => parsePowIssuanceV1Challenge(keys.challengeKey, tampered, { nowUnix: 1100 }),
    /challenge signature is invalid/)
})

test('codec: token mint/parse roundtrip, foreign key and version tamper rejected', t => {
  const token = mintPowIssuanceV1Token(keys.tokenKey, {
    challengeId: b4a.alloc(32, 0x11),
    recordCommitment: b4a.alloc(32, 0x22),
    allowance: 2,
    expiryEpoch: 4242
  })
  t.is(token.byteLength, POW_ISSUANCE_V1_TOKEN_BYTES)
  const parsed = parsePowIssuanceV1Token(keys.tokenKey, token)
  t.is(parsed.allowance, 2)
  t.is(parsed.expiryEpoch, 4242)
  t.alike(parsed.challengeId, b4a.alloc(32, 0x11))
  t.exception(() => parsePowIssuanceV1Token(b4a.from(randomBytes(32)), token), /token signature is invalid/)
  const tampered = b4a.from(token)
  tampered[1] = 99
  t.exception(() => parsePowIssuanceV1Token(keys.tokenKey, tampered), /token signature is invalid/)
})

test('codec: derivations are HMAC-SHA256 (sandbox-portable), never blake2b', t => {
  const data = b4a.from('derivation probe', 'utf8')
  const expected = b4a.from(createHmac('sha256', b4a.from('hiverelay/pow-issuance-v1/spend-tag', 'ascii'))
    .update(data).digest())
  t.alike(hmacSha256(b4a.from('hiverelay/pow-issuance-v1/spend-tag', 'ascii'), data), expected)
  const token = mintPowIssuanceV1Token(keys.tokenKey, {
    challengeId: b4a.alloc(32, 1),
    recordCommitment: b4a.alloc(32, 2),
    allowance: 1,
    expiryEpoch: 100
  })
  t.alike(powIssuanceV1SpendTag(token, 0),
    b4a.from(createHmac('sha256', b4a.from('hiverelay/pow-issuance-v1/spend-tag', 'ascii'))
      .update(b4a.concat([token, b4a.from([0])])).digest()))
  const root = powIssuanceV1RecordBindingRoot([b4a.alloc(32, 0xa0), b4a.alloc(32, 0xb1)])
  t.alike(root, b4a.from(createHmac('sha256', b4a.from('hiverelay/pow-issuance-v1/record-binding', 'ascii'))
    .update(b4a.concat([b4a.from([2]), b4a.alloc(32, 0xa0), b4a.alloc(32, 0xb1)])).digest()))
  t.alike(powIssuanceV1IssuerKeyCommitment(issuerKey),
    b4a.from(createHmac('sha256', b4a.from('hiverelay/pow-issuance-v1/issuer-key-commitment', 'ascii'))
      .update(issuerKey).digest()))
})

test('codec: leading zero bits counting and PoW verify at 8 and 20 bits', t => {
  t.is(countLeadingZeroBits(b4a.from([0, 0, 0xff])), 16)
  t.is(countLeadingZeroBits(b4a.from([0x80])), 0)
  t.is(countLeadingZeroBits(b4a.from([0x01])), 7)
  t.is(countLeadingZeroBits(b4a.alloc(32, 0)), 256)
  const challenge = parsePowIssuanceV1Challenge(keys.challengeKey, mintPowIssuanceV1Challenge(keys.challengeKey))
  const commitment = b4a.from(randomBytes(32))
  const nonce8 = mineNonce(challenge.payload, commitment, 8)
  t.ok(verifyPowIssuanceV1Work({ difficultyBits: 8, challengePayload: challenge.payload, recordCommitment: commitment, nonce: nonce8 }))
  t.absent(verifyPowIssuanceV1Work({ difficultyBits: 24, challengePayload: challenge.payload, recordCommitment: commitment, nonce: nonce8 }))
  const started = Date.now()
  const nonce20 = mineNonce(challenge.payload, commitment, 20)
  const elapsed = Date.now() - started
  t.ok(verifyPowIssuanceV1Work({ difficultyBits: 20, challengePayload: challenge.payload, recordCommitment: commitment, nonce: nonce20 }))
  t.comment(`20-bit default difficulty minted in ${elapsed}ms (nonce=${nonce20})`)
})

test('codec: binding root, presentation roundtrip, spend tag derivation', t => {
  const c0 = b4a.alloc(32, 0xa0)
  const c1 = b4a.alloc(32, 0xb1)
  const root = powIssuanceV1RecordBindingRoot([c0, c1])
  t.is(root.byteLength, 32)
  t.not(b4a.toString(root, 'hex'), b4a.toString(powIssuanceV1RecordBindingRoot([c1, c0]), 'hex'),
    'slot order is committed')
  t.not(b4a.toString(root, 'hex'), b4a.toString(powIssuanceV1RecordBindingRoot([c0]), 'hex'),
    'slot count is committed')
  const token = mintPowIssuanceV1Token(keys.tokenKey, {
    challengeId: b4a.alloc(32, 1),
    recordCommitment: root,
    allowance: 2,
    expiryEpoch: 100
  })
  const presentation = buildPowIssuanceV1Presentation(token, 1, [c0, c1])
  t.is(presentation.byteLength, POW_ISSUANCE_V1_TOKEN_BYTES + 1 + 32)
  const parsed = parsePowIssuanceV1Presentation(presentation)
  t.is(parsed.spendIndex, 1)
  t.is(parsed.siblings.length, 1)
  t.alike(parsed.siblings[0], c0)
  t.exception(() => parsePowIssuanceV1Presentation(b4a.concat([presentation, b4a.from([1])])),
    /presentation is malformed/)
  t.exception(() => buildPowIssuanceV1Presentation(token, 2, [c0, c1]), /outside the commitment list/)
  const tag0 = powIssuanceV1SpendTag(token, 0)
  const tag1 = powIssuanceV1SpendTag(token, 1)
  t.is(tag0.byteLength, 32)
  t.not(b4a.toString(tag0, 'hex'), b4a.toString(tag1, 'hex'), 'spend tag is per allowance unit')
  t.alike(powIssuanceV1SpendTag(token, 0), tag0, 'spend tag is deterministic')
})

test('adapter: unary prepare happy path echoes the exact binding', async t => {
  const adapter = new PowIssuanceV1AdmissionAdapter({ issuerKey, epochNow: () => 99 })
  const input = adapterInput()
  const prepared = await adapter.prepare(input)
  t.alike(prepared.spendTag, powIssuanceV1SpendTag(parsePowIssuanceV1Presentation(input.admission.token).token, 0))
  t.alike(prepared.requestCommitment, input.requestCommitment)
  t.is(prepared.profileId, 8)
  t.is(prepared.schemeId, POW_ISSUANCE_V1_SCHEME_ID)
  t.alike(prepared.parameterHash, input.admission.parameterHash)
  t.is(prepared.costClass.resourceClass, 4)
  t.is(prepared.costClass.leaseClass, 0)
  t.is(prepared.costClass.costUnits, 10n)
  const wal = prepared.walCommitRecord
  t.is(wal.byteLength, 95)
  t.is(wal.readUInt16BE(1), 8)
  t.is(wal.readUInt16BE(3), POW_ISSUANCE_V1_SCHEME_ID)
  t.is(wal[5], 0)
  t.is(wal[6], 1)
  t.is(wal.readUInt32BE(7), 100)
  t.is(wal[75], 3)
  t.is(wal[76], 4)
  t.is(wal.readBigUInt64BE(79), 10n)
  t.is(wal.readBigUInt64BE(87), 0n)
  adapter.close()
})

test('adapter: split preflight returns an empty frozen capability and confirm re-verifies', async t => {
  const adapter = new PowIssuanceV1AdmissionAdapter({ issuerKey, epochNow: () => 99 })
  const input = adapterInput()
  const capability = await adapter.preparePreflight(input)
  t.ok(Object.isFrozen(capability))
  t.is(Reflect.ownKeys(capability).length, 0)
  const prepared = await adapter.confirmAfterEof({ ...input, adapterPreflight: capability })
  t.alike(prepared.spendTag, (await adapter.prepare(input)).spendTag)
  adapter.close()
})

test('adapter: expired token, foreign key, binding mismatch, allowance violations rejected', async t => {
  const adapter = new PowIssuanceV1AdmissionAdapter({ issuerKey, epochNow: () => 100 })
  await t.exception(adapter.prepare(adapterInput()), /token is expired/)
  const foreign = new PowIssuanceV1AdmissionAdapter({ issuerKey: b4a.from(randomBytes(32)), epochNow: () => 99 })
  await t.exception(foreign.prepare(adapterInput()), /token signature is invalid/)
  const wrongBinding = adapterInput()
  wrongBinding.requestCommitment = b4a.alloc(32, 0xee)
  const fresh = new PowIssuanceV1AdmissionAdapter({ issuerKey, epochNow: () => 99 })
  await t.exception(fresh.prepare(wrongBinding), /not bound to this request commitment/)
  const overflow = adapterInput()
  const parsed = parsePowIssuanceV1Presentation(overflow.admission.token)
  overflow.admission.token = b4a.concat([parsed.token, b4a.from([7])])
  await t.exception(fresh.prepare(overflow), /does not match its signed allowance/)
  const capped = new PowIssuanceV1AdmissionAdapter({ issuerKey, epochNow: () => 99, maxAllowance: 1 })
  const twoSlotCommitments = [b4a.alloc(32, 0xc0), b4a.alloc(32, 0xc1)]
  const twoSlotToken = mintPowIssuanceV1Token(keys.tokenKey, {
    challengeId: b4a.alloc(32, 2),
    recordCommitment: powIssuanceV1RecordBindingRoot(twoSlotCommitments),
    allowance: 2,
    expiryEpoch: 100
  })
  await t.exception(capped.prepare(adapterInput({
    requestCommitment: twoSlotCommitments[0],
    admission: {
      profileId: 8,
      schemeId: POW_ISSUANCE_V1_SCHEME_ID,
      parameterHash: b4a.alloc(32, 0x44),
      token: buildPowIssuanceV1Presentation(twoSlotToken, 0, twoSlotCommitments)
    }
  })), /allowance exceeds the relay cap/)
  const foreignScheme = adapterInput()
  foreignScheme.admission = { ...foreignScheme.admission, schemeId: 9 }
  await t.exception(fresh.prepare(foreignScheme), /foreign schemeId/)
})

test('adapter: resolver routes only schemeId 1', async t => {
  const adapter = new PowIssuanceV1AdmissionAdapter({ issuerKey, epochNow: () => 99 })
  const resolver = createPowIssuanceV1AdapterResolver(adapter)
  t.is(await resolver({ schemeId: POW_ISSUANCE_V1_SCHEME_ID }), adapter)
  t.is(await resolver({ schemeId: 9 }), null)
  t.is(await resolver(null), null)
  adapter.close()
})

test('issuer: challenge → bad PoW rejected → valid PoW redeems once, replay rejected', async t => {
  const issuer = createPowIssuanceV1Issuer({ issuerKey, difficultyBits: 8, port: 0 })
  await issuer.start()
  t.teardown(() => issuer.close())
  const base = `http://127.0.0.1:${issuer.address().port}`

  const health = await fetch(`${base}/health`).then(response => response.json())
  t.is(health.scheme, 'pow-issuance-v1')
  t.is(health.schemeId, POW_ISSUANCE_V1_SCHEME_ID)

  const challengeResponse = await fetch(`${base}/challenge`)
  t.is(challengeResponse.status, 200)
  const challengeJson = await challengeResponse.json()
  t.is(challengeJson.difficultyBits, 8)
  const challengeBytes = b4a.from(challengeJson.challenge.replace(/-/g, '+').replace(/_/g, '/'), 'base64')
  const parsed = parsePowIssuanceV1Challenge(keys.challengeKey, challengeBytes)
  const commitment = b4a.from(randomBytes(32))

  const bad = await fetch(`${base}/redeem`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      challenge: challengeJson.challenge,
      nonce: '0000000000000000',
      recordCommitment: b4a.toString(commitment, 'hex')
    })
  })
  t.is(bad.status, 400)
  t.is((await bad.json()).error, 'POW_INSUFFICIENT_WORK')

  const nonce = mineNonce(parsed.payload, commitment, 8)
  const nonceBytes = b4a.alloc(8)
  nonceBytes.writeBigUInt64BE(nonce, 0)
  const good = await fetch(`${base}/redeem`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      challenge: challengeJson.challenge,
      nonce: b4a.toString(nonceBytes, 'hex'),
      recordCommitment: b4a.toString(commitment, 'hex')
    })
  })
  t.is(good.status, 200)
  const redeemed = await good.json()
  t.is(redeemed.allowance, 2)
  const token = parsePowIssuanceV1Token(keys.tokenKey, b4a.from(redeemed.token, 'hex'))
  t.alike(token.challengeId, parsed.challengeId)
  t.alike(token.recordCommitment, commitment)
  t.is(token.allowance, 2)

  const replay = await fetch(`${base}/redeem`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      challenge: challengeJson.challenge,
      nonce: b4a.toString(nonceBytes, 'hex'),
      recordCommitment: b4a.toString(commitment, 'hex')
    })
  })
  t.is(replay.status, 400)
  t.is((await replay.json()).error, 'POW_CHALLENGE_REPLAYED')

  const forgedChallenge = challengeJson.challenge.slice(0, 10) +
    (challengeJson.challenge[10] === 'a' ? 'b' : 'a') + challengeJson.challenge.slice(11)
  const forged = await fetch(`${base}/redeem`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      challenge: forgedChallenge,
      nonce: '00'.repeat(8),
      recordCommitment: b4a.toString(commitment, 'hex')
    })
  })
  t.is(forged.status, 400)
  t.is((await forged.json()).error, 'POW_CHALLENGE_INVALID')

  const allowance = await fetch(`${base}/redeem`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      challenge: challengeJson.challenge,
      nonce: '00'.repeat(8),
      recordCommitment: b4a.toString(commitment, 'hex'),
      allowance: 9
    })
  })
  t.is(allowance.status, 400)
  t.is((await allowance.json()).error, 'POW_ALLOWANCE_INVALID')

  t.is((await fetch(`${base}/nope`)).status, 404)
})

test('issuer: browser CORS is public, credential-free, route-bounded, and side-effect-free', async t => {
  const issuer = createPowIssuanceV1Issuer({ issuerKey, difficultyBits: 1, port: 0 })
  await issuer.start()
  t.teardown(() => issuer.close())
  const base = `http://127.0.0.1:${issuer.address().port}`
  const origin = 'https://unrelated.example'

  const challengeResponse = await fetch(`${base}/challenge`, { headers: { origin } })
  t.is(challengeResponse.status, 200)
  assertPublicBrowserHeaders(t, challengeResponse, 'challenge JSON')
  t.is(challengeResponse.headers.get('cache-control'), 'no-store')
  const challengeJson = await challengeResponse.json()
  const challengeBytes = b4a.from(challengeJson.challenge.replace(/-/g, '+').replace(/_/g, '/'), 'base64')
  const parsed = parsePowIssuanceV1Challenge(keys.challengeKey, challengeBytes)
  const recordCommitment = b4a.from(randomBytes(32))
  const nonce = mineNonce(parsed.payload, recordCommitment, 1)
  const nonceBytes = b4a.alloc(8)
  nonceBytes.writeBigUInt64BE(nonce, 0)
  const redeemBody = JSON.stringify({
    challenge: challengeJson.challenge,
    nonce: b4a.toString(nonceBytes, 'hex'),
    recordCommitment: b4a.toString(recordCommitment, 'hex')
  })

  for (const path of ['/challenge', '/health']) {
    const response = await fetch(base + path, {
      method: 'OPTIONS',
      headers: {
        origin,
        'access-control-request-method': 'GET',
        'access-control-request-headers': 'authorization'
      }
    })
    await assertPreflight(t, response, {
      label: `${path} preflight`,
      methods: 'GET, OPTIONS',
      allowHeaders: null
    })
  }

  const redeemPreflight = await fetch(`${base}/redeem`, {
    method: 'OPTIONS',
    headers: {
      origin,
      'content-type': 'application/json',
      'access-control-request-method': 'POST',
      'access-control-request-headers': 'content-type'
    },
    body: redeemBody
  })
  await assertPreflight(t, redeemPreflight, {
    label: '/redeem preflight',
    methods: 'POST, OPTIONS',
    allowHeaders: 'content-type'
  })

  const unknownPreflight = await fetch(`${base}/unknown`, {
    method: 'OPTIONS',
    headers: {
      origin,
      'content-type': 'application/json',
      'access-control-request-method': 'POST',
      'access-control-request-headers': 'content-type'
    },
    body: redeemBody
  })
  t.is(unknownPreflight.status, 404, 'unknown OPTIONS stays unknown')
  assertPublicBrowserHeaders(t, unknownPreflight, 'unknown OPTIONS JSON error')
  t.is(unknownPreflight.headers.get('access-control-allow-methods'), null, 'unknown route advertises no methods')
  t.is(unknownPreflight.headers.get('access-control-allow-headers'), null, 'unknown route advertises no headers')
  t.is(unknownPreflight.headers.get('access-control-max-age'), null, 'unknown route advertises no preflight cache')
  t.is((await unknownPreflight.json()).error, 'NOT_FOUND')

  const good = await fetch(`${base}/redeem`, {
    method: 'POST',
    headers: { origin, 'content-type': 'application/json' },
    body: redeemBody
  })
  t.is(good.status, 200, 'preflight and unknown route did not consume the challenge')
  assertPublicBrowserHeaders(t, good, 'redeem JSON success')
  t.is(good.headers.get('cache-control'), 'no-store')
  const redeemed = await good.json()
  t.is(redeemed.scheme, 'pow-issuance-v1')

  const malformed = await fetch(`${base}/redeem`, {
    method: 'POST',
    headers: { origin, 'content-type': 'application/json' },
    body: '{'
  })
  t.is(malformed.status, 400)
  assertPublicBrowserHeaders(t, malformed, 'redeem JSON error')
  t.is((await malformed.json()).error, 'POW_ISSUANCE_INVALID')

  const health = await fetch(`${base}/health`, { headers: { origin } })
  t.is(health.status, 200)
  assertPublicBrowserHeaders(t, health, 'health JSON')
  t.is((await health.json()).ok, true)
})

test('issuer: key commitment is a stable public identifier, not the key', t => {
  const commitment = powIssuanceV1IssuerKeyCommitment(issuerKey)
  t.is(commitment.byteLength, 32)
  t.alike(powIssuanceV1IssuerKeyCommitment(issuerKey), commitment)
  t.not(b4a.toString(commitment, 'hex'), b4a.toString(issuerKey, 'hex'))
  t.not(b4a.toString(commitment, 'hex'), b4a.toString(powIssuanceV1IssuerKeyCommitment(b4a.from(randomBytes(32))), 'hex'))
})
