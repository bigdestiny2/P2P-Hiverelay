# HiveRelay Blind Public WIRE v1

Status: frozen public binary authority for `hiverelay-blind/1`.

This document is the canonical `specBytes` input for the public WIRE tuple. It
defines only bytes exchanged with blind-relay clients and the public registries
needed to validate those bytes. Product evidence, application/client records,
daemon persistence, and edge-to-daemon IPC have separate authorities and cannot
change this document, the WIRE ABI artifact, or the WIRE vector manifest.

The broader master and implementation documents explain architecture, operation,
storage, deployment, and privacy profiles. They are not inputs to the public WIRE
`specHash`.

## 1. Normative language and closed version

MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, and MAY have the
meanings in RFC 2119 and RFC 8174. Version 1 is closed: unknown versions, family
IDs, operation IDs, frame kinds, enum values, bits, classes, tags, domains,
recipes, schema IDs, trailing bytes, overlong lengths, and non-canonical encodings
fail closed. No implementation-language object layout is authoritative.

The protocol identity is exactly:

```text
protocolFamily = "hiverelay-blind"
protocolMajor = 1
protocolMinor = 0
mediaType = "application/vnd.hiverelay.blind-v1"
```

The final authority files are:

```text
docs/protocol/HIVERELAY-BLIND-WIRE-V1.md
packages/blind-protocol/hiverelay-blind-abi-v1.cenc
packages/blind-protocol/vector-manifest-v1.cenc
packages/blind-protocol/vectors/<manifest path>
```

The `.draft` ABI and vector-manifest names, when present during transition, MUST
be byte-identical aliases of the final files and are never separate hash inputs.

## 2. Category boundary

The ABI artifact contains exactly the 73 category-1 WIRE schemas and no schema
from categories 2 through 5. The vector manifest contains only fixtures for those
WIRE schemas, public dispatch/envelope framing, public commitments, domains,
errors, and registry rows. It MUST NOT contain product-evidence, client-example,
internal-store, or private-IPC schema catalogs or fixtures.

The manifest includes one individually named canonical declaration vector for
each of the 73 WIRE schemas, every one of the 22 operation rows, all 40 domain
rows, all 20 error rows, and all 11 admission-cost rows. These exhaustive
inventory vectors supplement the positive and negative framing/body/commitment
fixtures; a bundled catalog alone cannot substitute for an omitted row.
The manifest also contains `registry/release-operation-profile-v1.json`, whose
exact canonical JSON bytes classify every frozen row as advertised or reserved.

`ReadCellCapV1`, `WriteCellCapV1`, `BlindCoreReadCapV1`, opaque application-chain
records, and replica-planning records are not relay WIRE: relays never receive or
decode them. An application profile that serializes such a capability owns and
hashes its exact declaration and vectors in that application profile. Public
relay receipts and acknowledgements are WIRE schemas and are included here.
`BlindStoreManifestV1` is daemon persistence only and MUST NOT be imported by a
client, application profile, WIRE codec, or WIRE vector.

## 3. Public framing

Every transport-neutral dispatch item is exactly:

```text
BlindDispatchFrameV1 {
  frameLength: u32be
  version: u8 = 1
  frameKind: u8                 // 1 request, 2 response, 3 error, 4 stream
  familyId: u8                  // 1 DESCRIBE, 2 CELL, 3 INBOX, 4 CORE, 5 FORWARD
  operationId: u8
  flags: u8 = 0
  requestId: bytes[16]
  streamId: u64be
  sequence: u64be
  bodyLength: u32be
  body: bytes[bodyLength]
}
```

`frameLength` is the exact number of bytes after its prefix. The fixed header
after the prefix is 41 bytes. The complete item is at most 4,194,372 bytes and its
body is at most 4,194,304 bytes. The family/operation row fixes allowed frame-kind
bits and exact request/result body caps before body allocation. Unary request IDs
are nonzero correlation values; stream IDs and sequences obey the transition in
the operation row. Reserved flags, contradictory unary/stream fields, truncation,
coalesced trailing bytes, and cap violations fail closed.

The transport-neutral padded envelope is exactly:

```text
BlindOuterEnvelopeV1 {
  version: u8 = 1
  outerClass: u8
  innerLength: u32be
  innerDispatch: bytes[innerLength]
  randomPadding: bytes[outerClassBytes - 6 - innerLength]
}
```

Outer class byte lengths are 1=4 KiB, 2=16 KiB, 3=64 KiB, 4=256 KiB,
5=1 MiB, and 6=8 MiB. The total encoded envelope length MUST equal its selected
class. Padding is random and is not interpreted.

The canonical operation registry has 22 rows ordered by `(familyId,
operationId)`: DESCRIBE 1..3, CELL 1..6, INBOX 1..6, CORE 1..3, and FORWARD
1..4. Each row binds request/result schema IDs, request/result kind bits, stream
transition, request/result caps, admission mode and cost rule, request-commitment
domain, result-signature domain, error profile, and allowed transport bits. The
operation ordinal is its zero-based position in that order and its descriptor bit
is exactly `2^ordinal`.

The RC1 advertised profile contains only the first 17 rows (bits
`0x0001ffff`). `CORE.OPEN_REPLICATION` and all four `FORWARD` rows retain their
numeric/schema assignments solely for compatibility and are reserved (bits
`0x003e0000`). A descriptor or readiness result MUST set every reserved bit to
zero. Dispatch to a reserved row MUST fail closed with `UNSUPPORTED_OPERATION`
before body allocation or admission; implementations MUST NOT advertise or
negotiate these rows.

## 4. Canonical ABI registry bytes

The final ABI file uses compact-encoding version 1. `uint` is the canonical
compact-encoding unsigned integer. `string` is `uint byteLength` followed by exact
UTF-8 bytes. `buffer` is `uint byteLength` followed by exact bytes. `list<T>` is
`uint count` followed by exactly `count` entries. Lists have no optional fields or
implicit defaults.

`WireAbiRegistryV1` encodes these fields in this exact order:

```text
string magic = "hiverelay-blind-abi-v1"
uint formatVersion = 1
string protocolFamily
uint protocolMajor
uint protocolMinor
string mediaType
list<Family> families
list<NameId> schemaCategories
list<NameId> frameKinds
list<NameId> admissionModes
list<NameId> streamTransitions
list<NameId> transportSupportBits
list<NameId> endpointRoles
list<NameId> privacyProfiles
list<NameId> domainPurposes
list<NameId> domainRecipes
list<NameId> costClassRuleKinds
list<NameId> errorCodes
list<NameId> errorProfileIds
list<NameId> errorRetryAfterModes
list<NameId> ohttpTransportErrorCodes
list<NameId> ohttpDeliveryBoundaries
list<NameId> ohttpRetryActions
list<NameId> transportIds
list<NameId> transportExporterIds
list<NameId> controlChannelIdTypes
list<NameId> durabilityProfileIds
list<NameId> durabilityRpoBands
list<NameId> durabilityRtoBands
list<NameId> redundancyClasses
list<NameId> ageBands
list<NameId> cellReceiptResults
list<NameId> inboxManageOperations
list<NameId> inboxAppendAuthModes
list<NameId> inboxReceiptResults
list<NameId> inboxAppendResults
list<NameId> admissionConformanceClasses
list<NameId> coreAckResults
list<NameId> forwardCloseKinds
list<NameId> storeLifecycleStates
list<NameId> healthClockStates
list<NameId> healthIntegrityStates
list<NameId> healthRebalanceStates
list<Class> cellClasses
list<Class> inboxClasses
list<Class> outerClasses
list<Class> streamClasses
list<Class> leaseClasses
list<NamedValue> dispatchLimits
list<NamedValue> endpointLimits
list<NamedValue> publicProfileLimits
list<NamedValue> operationRegistryValues
list<ForwardCircuitClass> forwardCircuitClasses
list<CoreSessionClass> coreSessionClasses
list<DomainRegistryEntryV1> domainRegistry
list<ErrorProfileEntryV1> errorProfiles
list<OhttpTransportErrorProfile> ohttpTransportErrorProfiles
list<AdmissionCostRuleV1> admissionCostRules
list<OperationProfileV1> operationProfiles
list<OperationCap> operationCaps
list<OperationBit> operationBits
list<Schema> implementedSchemas
list<string> requiredSchemaNames
list<string> missingSchemaNames
```

Entry layouts are exact:

```text
NameId = uint id || string name
Class = uint id || uint value
NamedValue = string name || uint value
Family = uint id || string name || string route || list<NameId> operations
ForwardCircuitClass = uint id || uint grantedInitialWindow ||
  uint maxCircuitBytes || uint idleMillis || uint lifetimeMillis
CoreSessionClass = uint id || uint maxSessionBytes || uint idleMillis ||
  uint lifetimeMillis
OhttpTransportErrorProfile = uint code || uint protectedStatus ||
  uint deliveryBoundary || uint retryAction
OperationCap = uint familyId || uint operationId || uint requestSchemaId ||
  uint resultSchemaId || uint maxRequestBodyBytes || uint maxResultBodyBytes
OperationBit = uint familyId || uint operationId || uint ordinal || uint bit
Schema = uint category || uint categoryLocalSchemaId || string name ||
  buffer canonicalSchemaBytes
```

`DomainRegistryEntryV1`, `ErrorProfileEntryV1`, `AdmissionCostRuleV1`, and
`OperationProfileV1` use their own canonical fixed-width WIRE schema bytes present
in the same ABI catalog. Every registry list is in numeric-ID order (then raw name
bytes for a tie), every named limit list is in raw-name order, families and
operation rows are numeric order, and schemas and required names are raw-ASCII
name order. `missingSchemaNames` is empty. Release-state booleans, blockers,
source paths, generator versions, timestamps, and implementation metadata are
forbidden from ABI bytes.

The category registry names all five catalog categories so
`SchemaCatalogEntryV1` has a closed discriminator table, but every `Schema` entry
inside this WIRE artifact has `category=1`; no non-WIRE schema name, schema ID, or
canonical schema bytes may appear.

## 5. Domains, signatures, errors, and commitments

The ABI contains exactly 39 unique domain rows: request commitment IDs 1..16,
result-signature IDs 101..111, and auxiliary-signature IDs 201..212. Request rows
use purpose 1 and recipe 1. Result and auxiliary rows use purposes 2 and 3 and
recipe 2. Exact printable ASCII domain bytes are part of each row and cannot be
inferred from a symbol name.

Recipe 2 signs and verifies exactly:

```text
exactAsciiDomainBytes || u64be(canonicalUnsignedBytes.length) ||
canonicalUnsignedBytes
```

Recipe 1 uses the operation-defined commitment preimage bound by the corresponding
request row. The frozen commitment vectors are mandatory. An unknown domain,
wrong purpose, wrong recipe, changed length, non-canonical unsigned bytes, or
signature under another row fails closed.

Error profile 1 contains exactly codes 1..20. Correlated direct and protected
inner protocol errors both use status 200; retryability and retry-after presence
are fixed per row. OHTTP failures before a valid correlated dispatch are a
separate three-row mapping for statuses 400, 503, and 504, with exact delivery
boundaries and retry actions in the ABI. Free-form errors and unknown error codes
are forbidden.

## 6. Hashes and vector manifest

Canonical text has UTF-8 bytes, no BOM, LF line endings, no CR bytes, and exactly
one final LF. Let `len64(x)` be unsigned big-endian u64 byte length. The final
public tuple is:

```text
specHash = BLAKE2b-256(
  "hiverelay.blind.spec-hash.v1" || len64(specBytes) || specBytes
)

abiHash = BLAKE2b-256(
  "hiverelay.blind.abi-hash.v1" || len64(abiRegistryBytes) ||
  abiRegistryBytes
)

vectorSetHash = BLAKE2b-256(
  "hiverelay.blind.vector-set-hash.v1" || len64(vectorManifestBytes) ||
  vectorManifestBytes
)
```

`specBytes` are this exact file. `abiRegistryBytes` are the exact final ABI file.
`vectorManifestBytes` are the exact final vector-manifest file.

The vector manifest is `u32be entryCount` followed by entries:

```text
u16be pathLength || UTF8_NFC(path) || u64be vectorLength ||
BLAKE2b-256(vectorBytes)
```

Paths are relative, NFC, slash-separated UTF-8 with no leading slash, backslash,
empty component, `.`, or `..`; they sort by raw UTF-8 bytes and duplicates after
normalization fail. The set is nonempty. Lengths are exact and vector bytes are
not normalized. Manifest truncation, trailing bytes, unsorted paths, duplicate
paths, an unavailable vector, length mismatch, or hash mismatch fails closed.

## 7. Runtime equality and publication rule

A conforming Node, Bare, browser, Pear, Rust, or other implementation MUST produce
the same mandatory dispatch, envelope, commitment, schema, ABI, manifest, and hash
bytes. Browser builds may replace cryptographic implementations but not recipes,
preimages, encodings, or bytes. Publication requires byte-equality tests across
the supported Node, Bare, and browser implementations plus exhaustive rejection
of unknown public IDs, tags, reserved bits, bounds, truncations, and trailing
bytes.

This public WIRE authority does not claim that a daemon store, private IPC,
release image, relay fleet, transport deployment, or application profile is
production-ready. Each has independent artifacts and release gates.
