import test from 'brittle'
import {
  MAX_DELEGATION_REVOCATION_LIST_ENTRIES,
  buildDelegationRevocationsPayload,
  buildDelegationRevocationsRoutePayload,
  resolveDelegationManagementRoute,
  runDelegationRevokeAction
} from 'p2p-hiverelay/core/relay-node/api-delegation-management.js'

test('api delegation management: route helper maps list and revoke routes by method', (t) => {
  t.alike(resolveDelegationManagementRoute('GET', '/api/manage/delegation/revocations'), {
    kind: 'list',
    authMessage: 'Unauthorized — API key required for /api/manage/delegation/revocations'
  })
  t.alike(resolveDelegationManagementRoute('POST', '/api/manage/delegation/revoke'), {
    kind: 'revoke',
    authMessage: 'Unauthorized — API key required for /api/manage/delegation/revoke'
  })
  t.is(resolveDelegationManagementRoute('POST', '/api/manage/delegation/revocations'), null)
  t.is(resolveDelegationManagementRoute('GET', '/api/manage/delegation/revoke'), null)
  t.is(resolveDelegationManagementRoute('GET', '/api/manage/delegation/revocations/extra'), null)
})

test('api delegation management: revocation route payload helper dispatches list reads', (t) => {
  const route = resolveDelegationManagementRoute('GET', '/api/manage/delegation/revocations')
  const result = buildDelegationRevocationsRoutePayload({
    route,
    listRevocations: () => [{
      revokedCertSignature: 'A'.repeat(128),
      primaryPubkey: 'B'.repeat(64),
      revokedAt: 10,
      secretToken: 'do-not-leak'
    }]
  })

  t.is(result.ok, true)
  t.is(result.status, undefined)
  t.alike(result.payload, {
    count: 1,
    total: 1,
    truncated: false,
    revocations: [{
      revokedCertSignature: 'a'.repeat(128),
      primaryPubkey: 'b'.repeat(64),
      revokedAt: 10
    }]
  })

  t.alike(buildDelegationRevocationsRoutePayload({ route: null }), {
    ok: false,
    status: 404,
    payload: { error: 'unknown delegation revocation route' }
  })
})

test('api delegation management: revoke validates body and cert expiry before mutation', (t) => {
  let calls = 0
  const node = {
    submitRevocation () {
      calls++
      return { ok: true, revokedCertSignature: 'a'.repeat(128) }
    }
  }

  const missing = runDelegationRevokeAction({ body: {}, node })
  t.is(missing.status, 400)
  t.alike(missing.payload, { error: 'revocation required (signed message from primary identity)' })

  const arrayRevocation = runDelegationRevokeAction({ body: { revocation: [] }, node })
  t.is(arrayRevocation.status, 400)

  const malformedExpiry = runDelegationRevokeAction({
    body: { revocation: { version: 1 }, certExpiresAt: '1e3' },
    node
  })
  t.is(malformedExpiry.status, 400)
  t.alike(malformedExpiry.payload, { error: 'certExpiresAt must be a positive safe integer' })
  t.is(calls, 0, 'invalid requests never call submitRevocation')
})

test('api delegation management: revoke delegates with sanitized success payload', (t) => {
  const seen = []
  const node = {
    submitRevocation (revocation, opts) {
      seen.push({ revocation, opts })
      return { ok: true, revokedCertSignature: 'B'.repeat(128), extraSecret: 'nope' }
    }
  }
  const revocation = { version: 1, marker: 'signed-by-primary' }

  const result = runDelegationRevokeAction({
    body: { revocation, certExpiresAt: 123456 },
    node
  })

  t.is(result.ok, true)
  t.alike(seen, [{ revocation, opts: { certExpiresAt: 123456 } }])
  t.alike(result.payload, { ok: true, revokedCertSignature: 'B'.repeat(128) })

  node.submitRevocation = () => ({ ok: false, reason: 'bad signature' })
  const rejected = runDelegationRevokeAction({ body: { revocation }, node })
  t.is(rejected.status, 400)
  t.alike(rejected.payload, { error: 'bad signature' })
})

test('api delegation management: revocation list is capped and sanitized', (t) => {
  t.is(MAX_DELEGATION_REVOCATION_LIST_ENTRIES, 1000)
  const entries = [
    {
      revokedCertSignature: 'A'.repeat(128),
      revokedAt: 10,
      expiresAt: 20,
      primaryPubkey: 'B'.repeat(64),
      reason: 'lost phone',
      secretToken: 'should not leak'
    },
    {
      revokedCertSignature: 'C'.repeat(128),
      revokedAt: 30,
      expiresAt: 40,
      primaryPubkey: 'D'.repeat(64),
      reason: 'x'.repeat(257)
    },
    {
      revokedCertSignature: 'E'.repeat(128),
      revokedAt: 50,
      expiresAt: 60,
      primaryPubkey: 'F'.repeat(64),
      reason: 'not returned due to cap'
    }
  ]

  const payload = buildDelegationRevocationsPayload({
    listRevocations: () => entries,
    maxEntries: 2
  })

  t.is(payload.count, 2)
  t.is(payload.total, 3)
  t.is(payload.truncated, true)
  t.alike(payload.revocations[0], {
    revokedCertSignature: 'a'.repeat(128),
    revokedAt: 10,
    expiresAt: 20,
    primaryPubkey: 'b'.repeat(64),
    reason: 'lost phone'
  })
  t.absent(payload.revocations[0].secretToken)
  t.absent(payload.revocations[1].reason, 'oversized reason omitted from list response')
})

test('api delegation management: revocation list tolerates missing or malformed stores', (t) => {
  t.alike(buildDelegationRevocationsPayload(), {
    count: 0,
    total: 0,
    truncated: false,
    revocations: []
  })
  t.alike(buildDelegationRevocationsPayload({ listRevocations: () => ({ nope: true }) }), {
    count: 0,
    total: 0,
    truncated: false,
    revocations: []
  })
})
