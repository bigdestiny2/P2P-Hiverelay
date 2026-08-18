// pow-issuance-v1 sandbox adapter contract test: the deployable script (fleet
// issuer key injected) loaded through the real production adapter bridge
// (loadProductionAdmissionAdapter), exercising both schemes and the
// SPEND_INVALID preservation for pow rejections.
import { createHash, randomBytes } from 'node:crypto'
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import test from 'brittle'
import b4a from 'b4a'
import {
  loadProductionEntrypointConfig,
  loadProductionAdmissionAdapter,
  PRODUCTION_RUNTIME_PROFILE
} from '../production-entrypoint.js'
import {
  POW_ISSUANCE_V1_SCHEME_ID,
  buildPowIssuanceV1Presentation,
  derivePowIssuanceV1Keys,
  mintPowIssuanceV1Token,
  powIssuanceV1RecordBindingRoot,
  powIssuanceV1SpendTag
} from '../pow-issuance-v1/token-codec.js'

const PLACEHOLDER = '__POW_ISSUER_KEY_HEX__'

const issuerKey = b4a.from(randomBytes(32))
const keys = derivePowIssuanceV1Keys(issuerKey)

async function scratch (t) {
  const created = await fs.mkdtemp(path.join(os.tmpdir(), 'blind-pow-sandbox-'))
  const directory = await fs.realpath(created)
  t.teardown(async () => fs.rm(created, { recursive: true, force: true }))
  return directory
}

async function builtScript (t, keyHex = b4a.toString(issuerKey, 'hex')) {
  const template = await fs.readFile(new URL('../pow-issuance-v1/sandbox-adapter.js', import.meta.url), 'utf8')
  if (!template.includes(PLACEHOLDER)) throw new Error('template placeholder missing')
  const source = template.split(PLACEHOLDER).join(keyHex)
  const directory = await scratch(t)
  const file = path.join(directory, 'adapter.js')
  await fs.writeFile(file, source, { mode: 0o400 })
  await fs.chmod(file, 0o400)
  return { file, digest: createHash('sha256').update(source).digest('hex') }
}

async function load (t, record) {
  const config = loadProductionEntrypointConfig({
    HIVERELAY_BLIND_RUNTIME_PROFILE: PRODUCTION_RUNTIME_PROFILE.CELL_V1,
    HIVERELAY_BLIND_ADMISSION_ADAPTER_SCRIPT_FILE: record.file,
    HIVERELAY_BLIND_ADMISSION_ADAPTER_SCRIPT_SHA256: record.digest
  })
  return loadProductionAdmissionAdapter(config, {
    launchTopologyHash: Buffer.alloc(32, 0x42),
    endpointIds: [1]
  })
}

function mintToken (commitments, overrides = {}) {
  return mintPowIssuanceV1Token(overrides.tokenKey || keys.tokenKey, {
    challengeId: b4a.from(randomBytes(32)),
    recordCommitment: powIssuanceV1RecordBindingRoot(commitments),
    allowance: commitments.length,
    expiryEpoch: overrides.expiryEpoch == null ? currentEpoch() + 2 : overrides.expiryEpoch
  })
}

function currentEpoch () {
  return Math.floor(Date.now() / 21600000)
}

function powInput (commitments, spendIndex, overrides = {}) {
  const token = overrides.token || mintToken(commitments, overrides)
  return {
    admission: {
      profileId: 8,
      schemeId: POW_ISSUANCE_V1_SCHEME_ID,
      parameterHash: b4a.alloc(32, 0x44),
      token: buildPowIssuanceV1Presentation(token, spendIndex, commitments)
    },
    familyId: 3,
    operationId: 4,
    costClass: Object.freeze({ resourceClass: 4, leaseClass: 2, costUnits: 10n }),
    requestCommitment: b4a.from(commitments[spendIndex]),
    parameters: null,
    endpointId: 1,
    descriptorSequence: 1n,
    descriptorHash: b4a.alloc(32, 0x45),
    signal: null
  }
}

test('sandbox: combined script initializes; scheme 9 passthrough is verbatim', async t => {
  const loaded = await load(t, await builtScript(t))
  const resolveInput = {
    profileId: 7,
    schemeId: 9,
    parameterHash: b4a.alloc(32, 0x50),
    endpointId: 1,
    endpointRoleBits: 49,
    signal: null
  }
  const adapter = await loaded.resolveAdmissionAdapter(resolveInput)
  const token = b4a.alloc(104, 0x51)
  const prepared = await adapter.prepare({
    admission: { profileId: 7, schemeId: 9, parameterHash: b4a.alloc(32, 0x50), token },
    familyId: 2,
    operationId: 1,
    costClass: Object.freeze({ resourceClass: 1, leaseClass: 1, costUnits: 10n }),
    requestCommitment: b4a.alloc(32, 0x52),
    parameters: null,
    endpointId: 1,
    signal: null
  })
  t.alike(prepared.spendTag, token, 'scheme 9 spendTag is the token passthrough')
  t.alike(prepared.walCommitRecord, token, 'scheme 9 walCommitRecord is the token passthrough')
  t.is(prepared.schemeId, 9)
  const capability = await adapter.preparePreflight({
    admission: { profileId: 7, schemeId: 9, parameterHash: b4a.alloc(32, 0x50), token },
    familyId: 2,
    operationId: 1,
    costClass: Object.freeze({ resourceClass: 1, leaseClass: 1, costUnits: 10n }),
    requestCommitment: b4a.alloc(32, 0x52),
    parameters: null,
    endpointId: 1,
    signal: null
  })
  t.ok(Object.isFrozen(capability))
  t.is(Reflect.ownKeys(capability).length, 0)
  let foreign = null
  try {
    loaded.resolveAdmissionAdapter({ ...resolveInput, schemeId: 7 })
  } catch (caught) {
    foreign = caught
  }
  t.is(foreign && foreign.code, 'BLIND_ADMISSION_ADAPTER_RESOLUTION_FAILED',
    'the host maps a script null-resolution to an exact resolution failure')
})

test('sandbox: pow adapter verifies a valid token and returns the exact proof', async t => {
  const loaded = await load(t, await builtScript(t))
  const adapter = await loaded.resolveAdmissionAdapter({
    profileId: 8,
    schemeId: POW_ISSUANCE_V1_SCHEME_ID,
    parameterHash: b4a.alloc(32, 0x44),
    endpointId: 1,
    endpointRoleBits: 49,
    signal: null
  })
  const commitments = [b4a.from(randomBytes(32)), b4a.from(randomBytes(32))]
  const token = mintToken(commitments)
  const input = powInput(commitments, 0, { token })
  const prepared = await adapter.prepare(input)
  t.alike(prepared.spendTag, powIssuanceV1SpendTag(token, 0),
    'sandbox spendTag matches the module derivation byte-exactly')
  t.alike(prepared.requestCommitment, input.requestCommitment)
  t.alike(prepared.parameterHash, input.admission.parameterHash)
  t.is(prepared.profileId, 8)
  t.is(prepared.schemeId, POW_ISSUANCE_V1_SCHEME_ID)
  t.is(prepared.costClass.resourceClass, 4)
  t.is(prepared.costClass.leaseClass, 2)
  t.is(prepared.costClass.costUnits, 10n)
  const wal = b4a.from(prepared.walCommitRecord)
  t.is(wal.byteLength, 95)
  t.is(wal.readUInt16BE(1), 8)
  t.is(wal.readUInt16BE(3), POW_ISSUANCE_V1_SCHEME_ID)
  t.is(wal[5], 0)
  t.is(wal[6], 2)
  t.is(wal[75], 3)
  t.is(wal[76], 4)
  t.is(wal.readBigUInt64BE(79), 10n)
  t.is(wal.readBigUInt64BE(87), 1n)

  const slotOne = powInput(commitments, 1, { token })
  const preparedOne = await adapter.prepare(slotOne)
  t.alike(preparedOne.spendTag, powIssuanceV1SpendTag(token, 1),
    'slot-1 spendTag matches the module derivation byte-exactly')

  const capability = await adapter.preparePreflight(input)
  t.ok(Object.isFrozen(capability))
  t.is(Reflect.ownKeys(capability).length, 0)
  const confirmed = await adapter.confirmAfterEof({ ...input, adapterPreflight: capability })
  t.alike(confirmed.spendTag, prepared.spendTag, 'split confirm reproduces the preflight binding')
})

test('sandbox: pow rejections surface SPEND_INVALID, not an opaque execution failure', async t => {
  const loaded = await load(t, await builtScript(t))
  const adapter = await loaded.resolveAdmissionAdapter({
    profileId: 8,
    schemeId: POW_ISSUANCE_V1_SCHEME_ID,
    parameterHash: b4a.alloc(32, 0x44),
    endpointId: 1,
    endpointRoleBits: 49,
    signal: null
  })
  const commitments = [b4a.from(randomBytes(32))]
  const capture = operation => {
    try {
      return operation()
    } catch (caught) {
      return caught
    }
  }

  const expired = powInput(commitments, 0, { expiryEpoch: currentEpoch() - 1 })
  let error = capture(() => adapter.prepare(expired))
  t.is(error.code, 'SPEND_INVALID', 'expired token rejects with SPEND_INVALID')

  const foreignToken = mintToken(commitments, { tokenKey: derivePowIssuanceV1Keys(b4a.from(randomBytes(32))).tokenKey })
  error = capture(() => adapter.prepare(powInput(commitments, 0, { token: foreignToken })))
  t.is(error.code, 'SPEND_INVALID', 'foreign-key token rejects with SPEND_INVALID')

  const rebound = powInput(commitments, 0, { token: mintToken([b4a.from(randomBytes(32))]) })
  error = capture(() => adapter.prepare(rebound))
  t.is(error.code, 'SPEND_INVALID', 'binding mismatch rejects with SPEND_INVALID')

  error = capture(() => adapter.preparePreflight(powInput(commitments, 0, { expiryEpoch: currentEpoch() - 1 })))
  t.is(error.code, 'SPEND_INVALID', 'preflight rejects with SPEND_INVALID too')
})

test('sandbox: build with an uninjected placeholder fails closed at initialization', async t => {
  const record = await builtScript(t, PLACEHOLDER)
  let error = null
  try {
    await load(t, record)
  } catch (caught) {
    error = caught
  }
  t.ok(error != null, 'unbuilt template must not initialize')
  t.is(error.code, 'BLIND_ADMISSION_ADAPTER_INITIALIZATION_FAILED')
})
