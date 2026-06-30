import test from 'brittle'
import { readFile } from 'fs/promises'
import {
  ACCOUNTING_RECEIPT_KIND
} from 'p2p-hiverelay/core/protocol/accounting-receipt.js'
import {
  RETRIEVABILITY_PROOF_SIGNATURE_PROFILE,
  STORAGE_PROOF_LEGACY_SIGNATURE_PROFILE
} from 'p2p-hiverelay/core/protocol/proof-of-storage.js'
import {
  BLINDSPARK_HTTP_SURFACES,
  RELAYKERNEL_REQUIRED_CONTRACTS,
  buildRelayKernelProfile,
  validateRelayKernelProfile
} from 'p2p-hiverelay/core/protocol/relaykernel-profile.js'

const VECTOR_URL = new URL('../fixtures/relaykernel-profile/relaykernel-profile-v1-minimal-compat.json', import.meta.url)

async function loadVector () {
  return JSON.parse(await readFile(VECTOR_URL, 'utf8'))
}

function baseInput () {
  return {
    capabilityDoc: {
      schemaVersion: 1,
      pubkey: 'a'.repeat(64),
      runtime: 'node',
      features: ['capability-doc', 'seed-revocability', 'seeding-registry'],
      supported_transports: ['hyperswarm'],
      signature: { v: 1, sig: 'b'.repeat(128) }
    },
    circuitRelay: true,
    proofSignatureProfile: RETRIEVABILITY_PROOF_SIGNATURE_PROFILE,
    accountingReceiptKind: ACCOUNTING_RECEIPT_KIND
  }
}

test('RelayKernel profile vector is stable and valid', async (t) => {
  const vector = await loadVector()
  const profile = buildRelayKernelProfile(vector.input)
  const verdict = validateRelayKernelProfile(profile)

  t.alike(profile, vector.profile, 'profile manifest matches fixture')
  t.alike(verdict, vector.verdict, 'verdict matches fixture')
  t.alike(RELAYKERNEL_REQUIRED_CONTRACTS, [
    'seed-control',
    'circuit-relay',
    'proof-of-retrievability',
    'capability-meta',
    'os-accounting'
  ])
})

test('RelayKernel profile keeps Blindspark browser gateway compatibility explicit', (t) => {
  const profile = buildRelayKernelProfile(baseInput())
  const gateway = profile.compatibility.blindsparkHttpGateway

  t.ok(gateway.present, 'gateway compatibility is present')
  t.alike(gateway.surfaces, BLINDSPARK_HTTP_SURFACES, 'all browser surfaces are named')
  t.ok(validateRelayKernelProfile(profile).valid, 'profile validates with gateway compatibility')

  const missingGateway = buildRelayKernelProfile({ ...baseInput(), httpGateway: false })
  const verdict = validateRelayKernelProfile(missingGateway)
  t.absent(verdict.valid, 'dropping gateway compatibility fails the profile')
  t.ok(verdict.errors.includes('missing Blindspark HTTP gateway compatibility surfaces'))
})

test('RelayKernel profile flags bundled app modules without failing compatibility tests', (t) => {
  const profile = buildRelayKernelProfile({
    ...baseInput(),
    features: ['publish-channel-v1'],
    appModules: ['custody', 'services']
  })
  const verdict = validateRelayKernelProfile(profile)

  t.ok(verdict.valid, 'kernel contracts still validate')
  t.alike(profile.appModules, ['custody', 'publish', 'services'], 'app modules are detected')
  t.absent(profile.security.appModulesExcludedFromKernel, 'profile records that modules are not excluded')
  t.ok(verdict.warnings.some(w => w.includes('application modules present outside kernel profile')))
})

test('RelayKernel profile rejects legacy proof signatures and missing accounting receipts', (t) => {
  const legacyProof = buildRelayKernelProfile({
    ...baseInput(),
    proofSignatureProfile: STORAGE_PROOF_LEGACY_SIGNATURE_PROFILE
  })
  const legacyVerdict = validateRelayKernelProfile(legacyProof)
  t.absent(legacyVerdict.valid, 'legacy proof signature profile is not enough for kernel profile')
  t.ok(legacyVerdict.errors.includes('contract not present: proof-of-retrievability'))
  t.ok(legacyVerdict.errors.includes('proof signature profile is not domain-separated'))

  const missingAccounting = buildRelayKernelProfile({
    ...baseInput(),
    accountingReceiptKind: null
  })
  const accountingVerdict = validateRelayKernelProfile(missingAccounting)
  t.absent(accountingVerdict.valid, 'missing OS-grounded receipt fails profile')
  t.ok(accountingVerdict.errors.includes('contract not present: os-accounting'))
  t.ok(accountingVerdict.errors.includes('accounting receipt kind is not OS-grounded'))
})

test('RelayKernel profile warns when the capability document is unsigned', (t) => {
  const input = baseInput()
  delete input.capabilityDoc.signature
  const profile = buildRelayKernelProfile(input)
  const verdict = validateRelayKernelProfile(profile)

  t.ok(verdict.valid, 'unsigned capability doc is a warning, not a hard profile failure')
  t.ok(verdict.warnings.includes('capability document is not signed'))
})
