import {
  RETRIEVABILITY_PROOF_SIGNATURE_PROFILE
} from './proof-of-storage.js'
import {
  ACCOUNTING_RECEIPT_KIND
} from './accounting-receipt.js'

export const RELAYKERNEL_PROFILE_KIND = 'hiverelay-relaykernel-profile'
export const RELAYKERNEL_PROFILE_VERSION = 1

export const RELAYKERNEL_REQUIRED_CONTRACTS = [
  'seed-control',
  'circuit-relay',
  'proof-of-retrievability',
  'capability-meta',
  'os-accounting'
]

export const BLINDSPARK_HTTP_SURFACES = [
  '/.well-known/hiverelay.json',
  '/catalog.json',
  '/v1/hyper/:driveKey/*path'
]

const APP_MODULE_NAMES = new Set([
  'ai',
  'anchor',
  'arbitration',
  'custody',
  'payments',
  'poker',
  'publish',
  'registry',
  'services',
  'vrf',
  'zk'
])

const APP_FEATURES = new Map([
  ['publish-channel-v1', 'publish'],
  ['service-registry', 'services'],
  ['qvac', 'ai'],
  ['qvac-models', 'ai'],
  ['poker', 'poker'],
  ['custody', 'custody'],
  ['custody-channel-v1', 'custody'],
  ['anchor-channel-v1', 'anchor'],
  ['payments', 'payments']
])

export function buildRelayKernelProfile (opts = {}) {
  const capabilityDoc = opts.capabilityDoc || {}
  const features = sortedStrings([
    ...arrayOfStrings(capabilityDoc.features),
    ...arrayOfStrings(opts.features)
  ])
  const transports = sortedStrings([
    ...arrayOfStrings(capabilityDoc.supported_transports),
    ...arrayOfStrings(opts.transports)
  ])
  const appModules = detectAppModules({ features, appModules: opts.appModules })
  const httpSurfaces = opts.httpGateway === false
    ? []
    : orderedUnique([
      ...BLINDSPARK_HTTP_SURFACES,
      ...arrayOfStrings(opts.httpSurfaces)
    ])

  const proofSignatureProfile = opts.proofSignatureProfile || null
  const accountingReceiptKind = opts.accountingReceiptKind || null

  return {
    kind: RELAYKERNEL_PROFILE_KIND,
    version: RELAYKERNEL_PROFILE_VERSION,
    relayPubkey: typeof capabilityDoc.pubkey === 'string' ? capabilityDoc.pubkey : null,
    runtime: typeof capabilityDoc.runtime === 'string' ? capabilityDoc.runtime : null,
    source: {
      capabilitySchemaVersion: Number.isSafeInteger(capabilityDoc.schemaVersion)
        ? capabilityDoc.schemaVersion
        : null,
      capabilitySigned: !!capabilityDoc.signature
    },
    contracts: [
      contract('seed-control', hasSeedControl(features, opts), {
        channel: 'seed-request-v1',
        evidence: evidence(features, ['seed-revocability', 'seeding-registry'])
      }),
      contract('circuit-relay', opts.circuitRelay === true || features.includes('circuit-relay'), {
        channel: 'relay-circuit-v1',
        evidence: evidence(features, ['circuit-relay'])
      }),
      contract('proof-of-retrievability', proofSignatureProfile === RETRIEVABILITY_PROOF_SIGNATURE_PROFILE, {
        channel: 'hiverelay-proof',
        signatureProfile: proofSignatureProfile
      }),
      contract('capability-meta', capabilityDoc.schemaVersion === 1 && features.includes('capability-doc'), {
        surface: '/.well-known/hiverelay.json',
        signed: !!capabilityDoc.signature
      }),
      contract('os-accounting', accountingReceiptKind === ACCOUNTING_RECEIPT_KIND, {
        receiptKind: accountingReceiptKind
      })
    ],
    compatibility: {
      blindsparkHttpGateway: {
        present: includesAll(httpSurfaces, BLINDSPARK_HTTP_SURFACES),
        surfaces: httpSurfaces
      }
    },
    security: {
      proofSignatureProfile,
      accountingReceiptKind,
      appModulesExcludedFromKernel: appModules.length === 0
    },
    transports,
    features,
    appModules
  }
}

export function validateRelayKernelProfile (profile) {
  const errors = []
  const warnings = []

  if (!profile || typeof profile !== 'object') {
    return { valid: false, errors: ['profile object required'], warnings }
  }
  if (profile.kind !== RELAYKERNEL_PROFILE_KIND) errors.push('kind mismatch')
  if (profile.version !== RELAYKERNEL_PROFILE_VERSION) errors.push('version mismatch')

  const contracts = Array.isArray(profile.contracts) ? profile.contracts : []
  for (const name of RELAYKERNEL_REQUIRED_CONTRACTS) {
    const c = contracts.find(entry => entry && entry.name === name)
    if (!c) errors.push('missing contract: ' + name)
    else if (c.status !== 'present') errors.push('contract not present: ' + name)
  }

  const gateway = profile.compatibility && profile.compatibility.blindsparkHttpGateway
  const surfaces = gateway && Array.isArray(gateway.surfaces) ? gateway.surfaces : []
  if (!gateway || gateway.present !== true || !includesAll(surfaces, BLINDSPARK_HTTP_SURFACES)) {
    errors.push('missing Blindspark HTTP gateway compatibility surfaces')
  }

  if (profile.security?.proofSignatureProfile !== RETRIEVABILITY_PROOF_SIGNATURE_PROFILE) {
    errors.push('proof signature profile is not domain-separated')
  }
  if (profile.security?.accountingReceiptKind !== ACCOUNTING_RECEIPT_KIND) {
    errors.push('accounting receipt kind is not OS-grounded')
  }

  if (profile.source && profile.source.capabilitySigned !== true) {
    warnings.push('capability document is not signed')
  }
  if (Array.isArray(profile.appModules) && profile.appModules.length > 0) {
    warnings.push('application modules present outside kernel profile: ' + profile.appModules.join(','))
  }

  return { valid: errors.length === 0, errors, warnings }
}

function hasSeedControl (features, opts) {
  return opts.seedControl === true ||
    (features.includes('seed-revocability') && features.includes('seeding-registry'))
}

function contract (name, present, details) {
  return {
    name,
    status: present ? 'present' : 'missing',
    ...details
  }
}

function evidence (features, names) {
  return names.filter(name => features.includes(name))
}

function detectAppModules ({ features, appModules }) {
  const modules = new Set()
  for (const name of arrayOfStrings(appModules)) {
    const normalized = name.toLowerCase()
    if (APP_MODULE_NAMES.has(normalized)) modules.add(normalized)
  }
  for (const feature of features) {
    const mapped = APP_FEATURES.get(feature)
    if (mapped) modules.add(mapped)
  }
  return [...modules].sort()
}

function sortedStrings (values) {
  return orderedUnique(values).sort()
}

function orderedUnique (values) {
  const out = []
  const seen = new Set()
  for (const value of values) {
    if (typeof value !== 'string' || value.length === 0) continue
    if (seen.has(value)) continue
    seen.add(value)
    out.push(value)
  }
  return out
}

function arrayOfStrings (value) {
  return Array.isArray(value) ? value.filter(v => typeof v === 'string') : []
}

function includesAll (haystack, needles) {
  return needles.every(needle => haystack.includes(needle))
}
