import test from 'brittle'
import b4a from 'b4a'
import { createDaemonPrivatePostEofAuthorityIssuer } from '../post-eof-authority.js'

function binding (overrides = {}) {
  return {
    endpointId: 7,
    familyId: 2,
    operationId: 1,
    descriptorSequence: 9n,
    descriptorHash: b4a.alloc(32, 0xd1),
    requestId: b4a.alloc(16, 0xa1),
    requestCommitment: b4a.alloc(32, 0xc1),
    ...overrides
  }
}

function minted (issuer, overrides = {}) {
  return issuer.mint({
    actualPeerEof: true,
    exactRequestValidated: true,
    ...binding(overrides)
  })
}

test('daemon-private PostEOF authority is exact-request bound and one use', t => {
  const issuer = createDaemonPrivatePostEofAuthorityIssuer()
  const authority = minted(issuer)
  t.ok(Object.isFrozen(authority))
  t.is(Reflect.ownKeys(authority).length, 0)
  t.is(issuer.consume({ authority, ...binding() }), true)
  t.exception(() => issuer.consume({ authority, ...binding() }), /already consumed/)
})

test('PostEOF substitution burns the authority before request mismatch rejection', t => {
  const issuer = createDaemonPrivatePostEofAuthorityIssuer()
  const authority = minted(issuer)
  t.exception(() => issuer.consume({
    authority,
    ...binding({ requestId: b4a.alloc(16, 0xa2) })
  }), /exact authenticated stream binding/)
  t.exception(() => issuer.consume({ authority, ...binding() }), /already consumed/)
})

test('same requestId on a different-commitment stream cannot cross-substitute and burns authority', t => {
  const issuer = createDaemonPrivatePostEofAuthorityIssuer()
  const firstStream = binding({ requestCommitment: b4a.alloc(32, 0xc1) })
  const secondStream = binding({ requestCommitment: b4a.alloc(32, 0xc2) })
  const authority = minted(issuer, firstStream)
  t.exception(() => issuer.consume({
    authority,
    ...secondStream
  }), /exact authenticated stream binding/)
  t.exception(() => issuer.consume({ authority, ...firstStream }), /already consumed/)
})

test('PostEOF authority cannot cross issuer instances or be caller asserted', t => {
  const first = createDaemonPrivatePostEofAuthorityIssuer()
  const second = createDaemonPrivatePostEofAuthorityIssuer()
  const authority = minted(first)
  t.exception(() => second.consume({ authority, ...binding() }), /absent, forged/)
  t.is(first.consume({ authority, ...binding() }), true)
  t.exception(() => first.consume({ authority: Object.freeze({}), ...binding() }), /absent, forged/)
  t.exception(() => first.mint({ ...binding(), actualPeerEof: false, exactRequestValidated: true }), /actual peer EOF/)
})
