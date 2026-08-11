// pow-issuance-v1 daemon admission adapter — module form of the deployer-injected
// split contract from admission-coordinator.js (preparePreflight/confirmAfterEof)
// plus the single-phase unary path (prepare). Side-effect-free per the contract:
// one-use enforcement is storage-owned via the deterministic spendTag; this
// adapter never contacts the issuer, never consumes a spend, never mutates state.
//
// Fleet note: on the deployed relays the same verification runs inside the
// sandboxed adapter-script contract (production-entrypoint.js) via
// sandbox-adapter.js; this module form is the reference implementation the
// drills and parity tests pin against.
import fs from 'node:fs/promises'
import b4a from 'b4a'
import {
  POW_ISSUANCE_V1_MAX_ALLOWANCE,
  POW_ISSUANCE_V1_SCHEME_ID,
  derivePowIssuanceV1Keys,
  parsePowIssuanceV1Presentation,
  parsePowIssuanceV1Token,
  powIssuanceV1RecordBindingRoot,
  powIssuanceV1SpendTag,
  wipePowIssuanceV1Key
} from './token-codec.js'

const SIX_HOURS_MILLIS = 21_600_000
const WAL_COMMIT_RECORD_BYTES = 95

function fail (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function sameBytes (left, right) {
  return Boolean(left && right && left.byteLength === right.byteLength && b4a.equals(left, right))
}

function defaultEpochNow () {
  return Math.floor(Date.now() / SIX_HOURS_MILLIS)
}

function walCommitRecord (input, fields, spendIndex) {
  const record = b4a.alloc(WAL_COMMIT_RECORD_BYTES)
  record[0] = 1
  record.writeUInt16BE(input.admission.profileId, 1)
  record.writeUInt16BE(input.admission.schemeId, 3)
  record[5] = spendIndex
  record[6] = fields.allowance
  record.writeUInt32BE(fields.expiryEpoch, 7)
  b4a.copy(fields.challengeId, record, 11)
  b4a.copy(b4a.from(input.requestCommitment), record, 43)
  record[75] = input.familyId
  record[76] = input.operationId
  record[77] = input.costClass.resourceClass
  record[78] = input.costClass.leaseClass
  record.writeBigUInt64BE(BigInt(input.costClass.costUnits), 79)
  record.writeBigUInt64BE(input.descriptorSequence == null ? 0n : BigInt(input.descriptorSequence), 87)
  return record
}

export class PowIssuanceV1AdmissionAdapter {
  constructor (options = {}) {
    const issuerKey = options.issuerKey
    if (!issuerKey || typeof issuerKey.byteLength !== 'number' || issuerKey.byteLength !== 32) {
      throw new TypeError('pow-issuance-v1 adapter requires the 32-byte fleet issuer key')
    }
    const keys = derivePowIssuanceV1Keys(issuerKey)
    this._tokenKey = keys.tokenKey
    keys.challengeKey.fill(0) // the redeemer never verifies challenges
    this._epochNow = typeof options.epochNow === 'function' ? options.epochNow : defaultEpochNow
    this._maxAllowance = options.maxAllowance == null ? POW_ISSUANCE_V1_MAX_ALLOWANCE : options.maxAllowance
    if (!Number.isInteger(this._maxAllowance) || this._maxAllowance < 1 ||
        this._maxAllowance > POW_ISSUANCE_V1_MAX_ALLOWANCE) {
      throw new TypeError('maxAllowance must be within 1..8')
    }
    this._closed = false
  }

  _verify (input) {
    if (this._closed) fail('SPEND_INVALID', 'pow-issuance-v1 adapter is closed')
    if (!input || typeof input !== 'object' || !input.admission) {
      fail('SPEND_INVALID', 'pow-issuance-v1 admission input is required')
    }
    if (input.admission.schemeId !== POW_ISSUANCE_V1_SCHEME_ID) {
      fail('SPEND_INVALID', 'pow-issuance-v1 adapter received a foreign schemeId')
    }
    if (input.signal && input.signal.aborted === true) {
      const error = new Error('pow-issuance-v1 verification crossed its abort fence')
      error.code = 'ABORT_ERR'
      throw error
    }
    const presentation = parsePowIssuanceV1Presentation(b4a.from(input.admission.token))
    const fields = parsePowIssuanceV1Token(this._tokenKey, presentation.token)
    if (fields.allowance > this._maxAllowance) {
      fail('SPEND_INVALID', 'pow-issuance-v1 token allowance exceeds the relay cap')
    }
    if (presentation.spendIndex >= fields.allowance ||
        presentation.siblings.length !== fields.allowance - 1) {
      fail('SPEND_INVALID', 'pow-issuance-v1 presentation does not match its signed allowance')
    }
    const epoch = this._epochNow()
    if (!Number.isInteger(epoch) || epoch < 0 || epoch >= fields.expiryEpoch) {
      fail('SPEND_INVALID', 'pow-issuance-v1 token is expired')
    }
    const commitments = []
    let sibling = 0
    for (let index = 0; index < fields.allowance; index++) {
      commitments.push(index === presentation.spendIndex
        ? b4a.from(input.requestCommitment)
        : presentation.siblings[sibling++])
    }
    if (!sameBytes(powIssuanceV1RecordBindingRoot(commitments), fields.recordCommitment)) {
      fail('SPEND_INVALID', 'pow-issuance-v1 token is not bound to this request commitment')
    }
    return Object.freeze({
      token: presentation.token,
      spendIndex: presentation.spendIndex,
      fields
    })
  }

  _proof (input, verified) {
    return Object.freeze({
      spendTag: powIssuanceV1SpendTag(verified.token, verified.spendIndex),
      requestCommitment: b4a.from(input.requestCommitment),
      costClass: Object.freeze({
        resourceClass: input.costClass.resourceClass,
        leaseClass: input.costClass.leaseClass,
        costUnits: BigInt(input.costClass.costUnits)
      }),
      walCommitRecord: walCommitRecord(input, verified.fields, verified.spendIndex),
      profileId: input.admission.profileId,
      schemeId: input.admission.schemeId,
      parameterHash: b4a.from(input.admission.parameterHash)
    })
  }

  // Unary admitted operations (INBOX.CREATE/APPEND, charged READ/WATCH): verify and
  // return the confirmed proof in one phase. No spend is consumed here; the
  // storage-owned spend marker enforces one-use atomically with the mutation.
  async prepare (input) {
    return this._proof(input, this._verify(input))
  }

  // Staged CELL.PUT split, phase one: full side-effect-free verification. The
  // coordinator brands the returned empty frozen capability; no state is carried.
  async preparePreflight (input) {
    this._verify(input)
    return Object.freeze({})
  }

  // Staged CELL.PUT split, phase two: re-verify against the echoed binding (the
  // preflight carried no state) and return the confirmed proof.
  async confirmAfterEof (input) {
    return this._proof(input, this._verify(input))
  }

  close () {
    if (this._closed) return
    this._closed = true
    wipePowIssuanceV1Key(this._tokenKey)
  }
}

export function createPowIssuanceV1AdapterResolver (adapter) {
  if (!adapter || typeof adapter.prepare !== 'function' ||
      typeof adapter.preparePreflight !== 'function' || typeof adapter.confirmAfterEof !== 'function') {
    throw new TypeError('a PowIssuanceV1AdmissionAdapter instance is required')
  }
  return async input => {
    if (!input || input.schemeId !== POW_ISSUANCE_V1_SCHEME_ID) return null
    return adapter
  }
}

// Deployer seam: builds the adapter + resolver from the environment.
// HIVERELAY_BLIND_POW_ISSUER_KEY_FILE (preferred, 32 raw bytes) or
// HIVERELAY_BLIND_POW_ISSUER_KEY_HEX (64 hex chars).
export async function powIssuanceV1AdapterFromEnvironment (environment = process.env, options = {}) {
  let issuerKey = null
  const keyFile = environment.HIVERELAY_BLIND_POW_ISSUER_KEY_FILE
  const keyHex = environment.HIVERELAY_BLIND_POW_ISSUER_KEY_HEX
  try {
    if (typeof keyFile === 'string' && keyFile.length > 0) {
      const bytes = await fs.readFile(keyFile)
      if (bytes.byteLength !== 32) fail('POW_ISSUANCE_CONFIG_INVALID', 'issuer key file must contain exactly 32 bytes')
      issuerKey = b4a.from(bytes)
    } else if (typeof keyHex === 'string' && /^[0-9a-fA-F]{64}$/.test(keyHex)) {
      issuerKey = b4a.from(keyHex, 'hex')
    } else {
      fail('POW_ISSUANCE_CONFIG_INVALID',
        'pow-issuance-v1 requires HIVERELAY_BLIND_POW_ISSUER_KEY_FILE or HIVERELAY_BLIND_POW_ISSUER_KEY_HEX')
    }
    const adapter = new PowIssuanceV1AdmissionAdapter({
      issuerKey,
      epochNow: options.epochNow,
      maxAllowance: options.maxAllowance
    })
    return Object.freeze({
      adapter,
      resolveAdmissionAdapter: createPowIssuanceV1AdapterResolver(adapter)
    })
  } finally {
    if (issuerKey) issuerKey.fill(0)
  }
}
