import b4a from 'b4a'

const ISSUERS = new WeakSet()
const AUTHORITIES = new WeakMap()

function fail (message) {
  const error = new Error(message)
  error.code = 'SPEND_INVALID'
  throw error
}

function bytes32 (value, field) {
  if (!value || typeof value.byteLength !== 'number' || value.byteLength !== 32) {
    fail(`${field} must be exactly 32 bytes`)
  }
  return b4a.from(value)
}

function bytes16 (value, field) {
  if (!value || typeof value.byteLength !== 'number' || value.byteLength !== 16) {
    fail(`${field} must be exactly 16 bytes`)
  }
  return b4a.from(value)
}

function integer (value, field, maximum = 0xffffffff) {
  if (!Number.isInteger(value) || value < 0 || value > maximum) fail(`${field} is invalid`)
  return value
}

function u64 (value, field) {
  if (typeof value === 'number') value = BigInt(value)
  if (typeof value !== 'bigint' || value < 0n || value > ((1n << 64n) - 1n)) fail(`${field} is invalid`)
  return value
}

function same (left, right) {
  return Boolean(left && right && left.byteLength === right.byteLength && b4a.equals(left, right))
}

// This issuer is constructed inside the daemon assembly and shared only with
// the private IPC server and AdmissionCoordinator. The capability itself is an
// empty frozen object; no public field or caller assertion can substitute for
// the server-observed EOF event that causes mint() to be invoked.
export function createDaemonPrivatePostEofAuthorityIssuer () {
  const issuer = {
    mint (input = {}) {
      if (input.actualPeerEof !== true || input.exactRequestValidated !== true) {
        fail('post-EOF authority requires actual peer EOF and exact request validation')
      }
      const authority = Object.freeze({})
      AUTHORITIES.set(authority, Object.freeze({
        owner: issuer,
        endpointId: integer(input.endpointId, 'endpointId', 0xffff),
        familyId: integer(input.familyId, 'familyId', 0xff),
        operationId: integer(input.operationId, 'operationId', 0xff),
        descriptorSequence: u64(input.descriptorSequence, 'descriptorSequence'),
        descriptorHash: bytes32(input.descriptorHash, 'descriptorHash'),
        requestId: bytes16(input.requestId, 'requestId'),
        requestCommitment: bytes32(input.requestCommitment, 'requestCommitment')
      }))
      return authority
    },

    consume (input = {}) {
      const retained = input.authority && AUTHORITIES.get(input.authority)
      if (!retained || retained.owner !== issuer) fail('post-EOF authority is absent, forged, or already consumed')
      // Burn before validating every echo so a failed substitution cannot be
      // retried against a different admission preflight.
      AUTHORITIES.delete(input.authority)
      if (retained.endpointId !== input.endpointId || retained.familyId !== input.familyId ||
          retained.operationId !== input.operationId || retained.descriptorSequence !== u64(
        input.descriptorSequence, 'descriptorSequence') ||
          !same(retained.descriptorHash, bytes32(input.descriptorHash, 'descriptorHash')) ||
          !same(retained.requestId, bytes16(input.requestId, 'requestId')) ||
          !same(retained.requestCommitment, bytes32(input.requestCommitment, 'requestCommitment'))) {
        fail('post-EOF authority does not match its exact authenticated stream binding')
      }
      if (input.signal && input.signal.aborted) {
        const error = new Error('post-EOF authority crossed its abort fence')
        error.code = 'ABORT_ERR'
        throw error
      }
      return true
    }
  }
  Object.freeze(issuer)
  ISSUERS.add(issuer)
  return issuer
}

export function isDaemonPrivatePostEofAuthorityIssuer (value) {
  return Boolean(value && typeof value === 'object' && Object.isFrozen(value) && ISSUERS.has(value))
}
