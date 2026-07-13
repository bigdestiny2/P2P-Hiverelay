# HiveRelay Blind Substrate — Implementation Specification

**Status:** build-ready component contract

**Date:** 2026-07-11

**Protocol family:** `hiverelay-blind/1`

**Canonical HiveRelay path:**
`docs/protocol/BLIND-SUBSTRATE-IMPLEMENTATION-SPEC.md`

**Target repository reviewed:** `p2p-hiverelay` at
`999b0afd7584bb727cef6e6a88a054f11513927a` (`0.24.3`)

This document turns the architectural requirements in
`BLIND-APP-AGNOSTIC-HIVERELAY-MASTER-SPEC.md` into the replacement
application-serving product boundary implemented as HiveRelay. It specifies a
generic blind substrate, not an application backend or optional semantic-service
sidecar. The canonical maintained copy lives beside the master
protocol document under HiveRelay's `docs/protocol/`; app repositories may carry
only pinned consumer profiles or delivery snapshots.

The strict substrate provides only bounded ciphertext storage, opaque inboxes,
encrypted-core availability, generic admission, signed evidence, discovery, and
opaque forwarding. It has no application registration, schema, author, record
type, social graph, semantic index, or application-specific policy.

`MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` are normative.

---

## 1. Decisions fixed by this specification

1. The strict substrate is one deterministic two-component distribution with
   mandatory disjoint `blind-edge` and `blind-daemon` workspaces, binaries/images,
   entrypoints, processes, users, service units, and capabilities. Edge alone owns
   public listeners and metadata stripping; daemon owns only private IPC,
   canonical dispatch, storage, admission and signing. Neither is an in-process
   `p2p-hiveservices` plugin or receives HiveRelay's current
   `{ node, store, config }` service context. Exactly one signed, networkless,
   bounded volume-ownership initializer may reuse the daemon image and must exit
   before those two long-running services become ready; it is not a third product
   component.
2. One executable public WIRE registry is the sole source for public type/operation
   IDs, fields, domains, limits, errors and encodings. One disjoint PRIVATE_IPC
   registry is the sole source for the two components' local frames. Its only
   cross-category dependency imports the generated public family/transport/outer-
   class/wire-class values and records exact `abiHash`; it may not copy or extend
   those enums. Endpoint readiness is a closed local-control variant of
   `LocalDispatchV1`/`LocalUnaryResponseV1`, not another schema or WIRE operation.
3. The public surface has exactly five families: `DESCRIBE`, `CELL`, `INBOX`,
   `CORE`, and `FORWARD`. Operation-specific aliases are not advertised by a strict
   profile.
4. Relays store generic fixed ciphertext. Encryption, capabilities, application
   signatures, merge, indexing, moderation, repair policy, and interpretation are
   client responsibilities.
5. Storage is divided into deterministic virtual buckets, never application or
   author partitions. Version 1 has exactly one write authority per relay identity
   and one atomic WAL coordinator across all local partitions.
6. Direct, OHTTP, Protomux split, MASQUE, and Tor are adapters around the same
   canonical service messages. A transport cannot add an application field or
   inherit a privacy claim merely because it moves opaque bytes.
7. Supporting a new application requires no daemon code, configuration, route,
   key, namespace, metric label, restart, or operator approval.
8. A production build has exactly one `BuildManifestV1.productMode` value:
   `BLIND_APPLICATION_SUBSTRATE_V1`. Signed isolation evidence binds the artifact
   and proves legacy/plugin components absent; a signed launch topology freezes
   the two components and a signed support horizon freezes upgrade/rollback
   behavior. A combined blind+semantic production mode does not exist.

### 1.1 Explicit exclusions

This component does not specify or own:

- Peerit authority, records, migration, bootstrap, UI, or release policy;
- any other application's schema, membership, identity, merge, or moderation;
- semantic search, ranking, recommendation, graph traversal, content scanning,
  or per-application abuse rules;
- a global relay roster, consensus, blockchain, or proof that two keys represent
  independent operators;
- active-reader secrecy for public content; or
- PIR, ORAM, mixnet cryptography, TEE processing, MPC, or FHE in version 1.

Legacy OutboxLog, shard-store, custody, and semantic services may coexist outside
the membrane only during bounded migration and only as a separately released
compatibility product with a valid signed sunset. They MUST NOT share the strict
artifact, process, endpoints, identity, descriptor profile, storage root, release
channel, metrics namespace, or privacy claims.

The normative end state is the replacement architecture in the master spec
section 1: the generic blind substrate becomes HiveRelay's application-serving
surface and Peerit has no legacy write path after cutover. Any legacy service kept
for a not-yet-migrated consumer is a separately released, explicitly sunset
compatibility product; it is not a permanent alternate substrate, cannot be
selected by a strict client, and cannot delay another application's permissionless
use of `hiverelay-blind/1`.

The final clean install runs the signed one-shot volume initializer to completion,
then starts exactly the blind edge and daemon as HiveRelay's only long-running
application-serving surface. Compatibility delivery is built from a frozen
full historical runtime source tree and uses a different
executable/image, service unit, identity, listener, descriptor, store, release
channel, logs, metrics, and credentials; its signed write/read deadlines can only
shorten.

---

## 2. Sole source, version, and hash relationship

### 2.1 Authority chain

The following artifacts have distinct authority:

| Artifact | Authority |
| --- | --- |
| Canonical HiveRelay blind protocol document | Normative protocol, invariants, state transitions, and allowed behavior identified by `specHash` |
| This implementation specification | Required component/process boundaries, delivery gates, and HiveRelay repository map; its file hash is recorded in the build manifest |
| Executable protocol registry | Exact wire IDs, canonical field order, domains, caps, and error mapping |
| Canonical vectors | Byte-exact proof that each runtime implements the registry |
| Signed service descriptor | What one running daemon currently offers |
| Generic build manifest | Which implementation inputs, dependencies, tools, and artifact produced a deployment |
| Signed launch topology/support horizon | Exact two-component entrypoints/users/mounts/two unequal sockets/listeners/default command, one bounded completed initializer, and fenced upgrade/rollback deadlines |
| Signed product-isolation evidence | Exact artifact/file/import/listener/route/process proof that product mode 1 contains no forbidden legacy/plugin surface |
| Signed compatibility manifest/genesis/head/sunset/authority chain | Separately authenticated EVIDENCE and enforced time gates governing a full non-blind migration product; never a daemon input or descriptor |

Prose examples are never a second wire definition. Code MUST import operation IDs,
domains, limits, and codecs from the protocol package; copied constants fail the
source-consistency gate.

### 2.2 Required identifiers

Every build records one `BuildProfileV1`:

```text
protocolFamily  = "hiverelay-blind"
protocolMajor   = 1
protocolMinor   = non-negative u16

specHash = BLAKE2b-256(
  "hiverelay.blind.spec-hash.v1" || len64(specBytes) || specBytes
)

abiHash = BLAKE2b-256(
  "hiverelay.blind.abi-hash.v1" || len64(abiRegistryBytes) || abiRegistryBytes
)

vectorSetHash = BLAKE2b-256(
  "hiverelay.blind.vector-set-hash.v1" ||
  len64(vectorManifestBytes) || vectorManifestBytes
)

buildArtifactHash = BLAKE2b-256(
  "hiverelay.blind.build-artifact-hash.v1" ||
  len64(releaseArtifactBytes) || releaseArtifactBytes
)

buildManifestHash = BLAKE2b-256(
  "hiverelay.blind.build-manifest-hash.v1" ||
  len64(buildManifestBytes) || buildManifestBytes
)

BuildProfileV1 {
  specHash:            32 bytes
  abiHash:             32 bytes
  vectorSetHash:       32 bytes
  evidenceFormatHash:  32 bytes
  evidenceVectorSetHash:32 bytes
  storeFormatHash:     32 bytes
  storeVectorSetHash:  32 bytes
  privateIpcFormatHash:32 bytes
  privateIpcVectorSetHash:32 bytes
  buildArtifactHash:   32 bytes
  buildArtifactUrl:    canonical HTTPS URL bytes[1..512]
  buildManifestUrl:    canonical HTTPS URL bytes[1..512]
  buildManifestHash:   32 bytes
  releaseEvidenceBundleUrl:canonical HTTPS URL bytes[1..512]
  releaseEvidenceBundleHash:32 bytes
  releaseSupportHorizonHash:32 bytes
  runtimeBoundaryEvidenceUrl:canonical HTTPS URL bytes[1..512]
  runtimeBoundaryEvidenceHash:32 bytes
}
```

`len64(x)` is an unsigned big-endian `u64` byte length. `specBytes` are the exact
canonical bytes of `docs/protocol/HIVERELAY-BLIND-WIRE-V1.md`: UTF-8 without BOM,
LF only, no CR bytes, and exactly one final LF. Nonconforming files are rejected,
never silently normalized. The broader master document is not hashed into the
public WIRE tuple, so evidence, client-example, store, and private-IPC prose cannot
churn an otherwise byte-identical public protocol.

`abiRegistryBytes` are the exact checked-in
`hiverelay-blind-abi-v1.cenc` bytes. Its version-1 `compact-encoding` schema
serializes only WIRE operation rows, enums/fields/caps/domains, and category-local
schemas. EVIDENCE, INTERNAL_STORE, and PRIVATE_IPC are separate canonical files
hashed by their respective format/vector fields; CLIENT_EXAMPLE schemas enter none
of the four runtime/evidence formats. Generated bindings import only their category and MUST
byte-reproduce each selected registry. The build rejects an unclassified schema,
any cross-category numeric reference except PRIVATE_IPC's generated five-table WIRE
dependency, missing operation closure, or internal schema in a client bundle.

The new product-release schemas have one category authority. WIRE gains no product
or compatibility schema. EVIDENCE contains `BlindProductDistributionBundleV1`,
`BuildManifestV1`,
`BlindLaunchTopologyV1`, `BlindReleaseSupportHorizonV1`,
`BlindReleaseEvidenceBundleV1`, all six typed isolation reports plus their bundle,
`BlindProductIsolationEvidenceV1`, `BlindRuntimeBoundaryEvidenceV1`,
`HiveRelayCompatibilityBuildManifestV1`,
`HiveRelayCompatibilitySunsetGenesisV1`,
`HiveRelayLegacyCompatibilitySunsetV1`,
`HiveRelayCompatibilitySunsetHeadV1`,
`HiveRelayCompatibilityAuthorityTransitionV1`, and
`HiveRelayCompatibilityRuntimeBoundaryEvidenceV1` under the exact master schemas,
hashes, domains, time/floor/key-transition rules, and vectors. PRIVATE_IPC v1 contains
exactly the seven local edge↔daemon schemas named in the master; its registry/vectors hash into the build
and topology but never WIRE. INTERNAL_STORE contains none of them and gains no
product mode. A generator must reject a duplicate copy or category change.

The additive PRIVATE_IPC v2 staged-`CELL.PUT` authority retains those seven v1
rows and adds IDs 8..12 under separate registry, vector, and hash-domain artifacts.
V1 staged writes are forbidden. A v2 record is never decoded or retried as v1.
The v2 contract is not a release gate by itself.

`vectorManifestBytes` are `u32 entryCount` followed by entries encoded as
`u16 pathLength || pathBytes || u64 vectorLength || BLAKE2b-256(vectorBytes)`.
Paths are strict UTF-8 NFC with `/` separators, no leading slash, empty component,
`.`, `..`, or backslash; they sort by raw UTF-8 bytes and duplicates after
normalization fail. Empty sets fail. Vector bytes are not newline-normalized unless
their own declared format requires it.

`releaseArtifactBytes` are the exact downloadable content-addressed
canonical `BlindProductDistributionBundleV1` verified before execution. Its first
two byte strings are the selectively built edge and daemon deterministic OCI
layouts or signed native sub-bundles; sorted packaging files contain only the
launcher/service metadata. The exact topology may execute one bounded
`VOLUME_OWNERSHIP_V1` initializer from the daemon artifact before readiness; its
signed argv/capabilities/mounts and completed evidence do not create a third
component. Component and packaging file hashes all reproduce.
Compatibility is never a component, file or layer of this bundle.

The canonical generic `buildManifestBytes` are exact `BuildManifestV1` from the
master: `productMode=1`, implementation/source tree, this implementation-spec hash,
protocol and store-format tuple, toolchain/dependency/SBOM, sorted exact inputs,
artifact, private-IPC tuple, nonzero signed launch topology/support horizon/
`productIsolationEvidenceHash`, and independent reproduction attestations. The
manifest, topology, horizon, isolation/release evidence, compatibility build/
genesis/head/sunset/boundary/transition objects, and generated runtime descriptor
are detached from the artifact bytes they hash, so no hash cycle exists. Git,
Node, and containers are not protocol requirements. Different compliant
implementations share spec/ABI/vector hashes and may have different artifact
hashes.

The master-spec EVIDENCE schemas are mandatory here. The release verifier starts
from the descriptor's deterministic content-addressed manifest/evidence URLs and
recomputes the launch topology, support horizon, complete two-component file
inventory, two entrypoints, closed import graph, listeners, allowed/forbidden route
probes, the exact completed initializer, process/mount inspection, report bundle
and isolation signature. It derives
the zero forbidden bitset; no opaque hash or self-reported zero is accepted.
Compatibility verification covers the full separate runtime artifact/source/build
manifest, pinned sunset genesis, fresh no-store current head, exact chain/floor,
monotonic trusted-time gates, runtime boundary comparison, and dual-signed authority
transition. Inputs are the complete
regular-file tree, sort by raw canonical path bytes, and reject duplicates and
non-regular aliases. Reproduction rows sort by their complete canonical entry
bytes using unsigned raw-byte lexicographic order and reject duplicate
`(builderPublicKey, environmentHash)` pairs. Toolchain and reproduction-environment
sidecars use their frozen schemas; exact dependency-lock/SBOM bytes and every file,
toolchain distribution, image, and environment value use the named length-delimited
BLAKE2b domains. Generators/verifiers reject unsorted, duplicate, unexplained, or
unrecomputable 32-byte evidence labels and run the corresponding negative vectors.
Production uses `DISTINCT_RELEASE_SIGNER_KEY_V1`: at least one valid reproduced
artifact signature must use a builder key unequal to the release-signer key.
Self-rebuilds do not satisfy it. This proves key separation only; an
“independent reproduction” claim additionally requires the named detached
organizational-independence evidence from the master spec.
Builder reproduction and release-manifest signatures are both exact Ed25519 over
their frozen master-spec domains; canonical-key/signature and role-substitution
negative vectors are mandatory. The reproduction signature uses only canonical
`BuildReproductionAttestationV1`: row key/environment/artifact hash plus the
length-delimited unsigned-manifest-prefix commitment. It never reconstructs an
implementation-selected list of “input hashes.”

Rules:

- One `(major, minor)` MUST NOT identify two `abiHash` values.
- Any change to field order, signed preimage, operation meaning, error meaning,
  required validation, or accepted non-canonical input requires a major bump.
- A backward-compatible optional operation or feature requires a minor bump and a
  new `abiHash`. It cannot change an existing operation.
- Build metadata or implementation-only changes alter `buildArtifactHash` and the
  generic manifest, not the protocol version or ABI hash.
- A daemon MUST fail startup if its compiled registry, vectors, descriptor
  template, build profile, and artifact manifest disagree.
- Both production components MUST fail before public listeners unless
  `productMode=1`; the exact manifest/evidence bundle/topology/support horizon and
  six isolation reports are retrievable and recompute; their component artifacts,
  entrypoints, private-IPC tuple and running process/listener shape match; and the
  derived forbidden-component bits are zero. Compatibility build/genesis/head/
  sunset/boundary/transition bytes are never passed to either component.
- A client MUST reject a descriptor that repeats a known version with a different
  ABI hash or rolls back below a locally witnessed version/hash floor.

### 2.3 Compatibility product enforcement

`packages/legacy-compat` is a full frozen runtime workspace and its only
application entrypoint. It is built independently as `productMode=2` under exact
`HiveRelayCompatibilityBuildManifestV1`; `packages/legacy-compat-release` contains
only detached build/genesis/head/sunset/boundary tooling. Neither workspace is a
dependency, layer, mode, child, route or configuration branch of blind-edge or
blind-daemon.

Before opening a compatibility listener, and before every semantic read/write,
the runtime fetches `sunsetLatestUrl` with no-store/no-redirect, verifies the
release-channel-pinned genesis, exact predecessor chain and same-sequence fork
absence, validates the fresh 15-minute signed head against its persisted monotonic
sunset/time floor, and requires the head's build manifest to equal the running
artifact. Local clock skew beyond 120 seconds, head expiry/unavailability, floor
rollback, another genesis, or any boundary/authority mismatch fails closed.
It computes `effectiveNow = max(localWall, signedHeadIssued, persistedTimeFloor)`
with checked integer arithmetic and atomically persists the maximum.

At or after the signed write deadline, routing rejects all semantic mutation
before body allocation and the service advertises read-only only. At or after the
read deadline, it closes every public semantic/discovery route and exposes only
the signed sunset/status object plus authenticated archive/shutdown administration.
Tests set the clock one millisecond before/at/after both boundaries, roll it back,
substitute a second genesis or predecessor-free/sequence-skipping sunset,
expire/withhold/fork the head, crash before/after floor persistence, rotate the
authority, swap product/successor/runtime evidence, and prove zero late mutation or
read. No operator flag, stale cached head, or unavailable blind product extends a
deadline.

---

## 3. Trust and process boundary

### 3.1 Required processes

```text
blind-volume-init                       one-shot; no network/listener/product-code execution
  `-- create/chmod/chown only signed runtime/data mount roots, then exit 0

@hiverelay/blind-edge                  sole public/TLS/HTTP/transport process
  |-- fixed family routes + CORS/TLS
  |-- ambient metadata stripping
  |-- bounded raw stream/backpressure
  |
  | two authenticated private Unix sockets; frozen PRIVATE_IPC
  v
@hiverelay/blind-daemon                private canonical/storage/signing process
  |-- protocol decoder
  |-- admission verifier + transaction coordinator
  |-- cell engine
  |-- inbox engine
  |-- blind-core adapter/sidecar controller
  |-- descriptor/receipt signer
  |-- virtual-bucket store + WAL
  `-- forward policy
```

Edge and daemon MUST be separately built entrypoints, processes and nonzero,
unequal unprivileged UIDs under exact signed `BlindLaunchTopologyV1`. Container
deployments use two component images/services inside one deterministic distribution;
native/systemd uses two long-running service units. Before either is ready, the
topology runs exactly one `VOLUME_OWNERSHIP_V1` initializer from the daemon image
as UID/GID 0 with normalized CHOWN/DAC_OVERRIDE/FOWNER bits only, read-only root
filesystem, no network, no-new-privileges, a 32-PID limit, no secret/config/log/
host mount, and only the daemon's two top-level runtime/data roots writable. Its
signed argv may create and change
owner/group/mode only on those root directory entries: runtime ends daemon-owned
0750 and data daemon-owned 0700. `targetsAfter` proves both are non-symlink
directories inside the process-inspection window. It may never recurse, follow a
symlink, read content, load a product entrypoint/module, or listen. It must exit
zero within at most 60 seconds; process evidence must match its complete signed
artifact/argv/UID/GID/capability/network/root-filesystem/mount tuple and duration,
and no initializer process may remain. Failure prevents both components from
advertising. This initializer is packaging bootstrap, not a third component.

Edge has read-only code/TLS mounts and no store or relay-signing-key access. Daemon
has one dedicated volume, relay key and
two absolute, unequal, non-symlink private IPC sockets but no public listener or
TLS credential. Neither has a Docker socket. Failure to match topology prevents advertisement of
`strict-membrane-v1`.

There is no reuse of `packages/core/core/relay-node/index.js`, no mode flag that
turns the old general host into edge, and no one-file/product dual role. A
temporary compatibility service is built from `packages/legacy-compat`, has its
own artifact/manifest/entrypoint/process/identity/listener/store/release and fresh
sunset head, and is absent from this process tree and distribution.

Daemon alone constructs and signs the service descriptor, DHT pointer payload,
health result, receipt and proof under the blind relay identity. Edge owns the
public descriptor/operation listeners and returns those exact signed bytes; it has
no relay signing handle and cannot edit an endpoint, role or readiness bit. The
descriptor's public endpoints name edge listeners, while readiness is daemon state
bound to those endpoint IDs through PRIVATE_IPC and the signed topology.

The upstream `blind-peer` runtime MAY be a daemon-owned child process when its
Corestore/Hypercore dependency generation differs from HiveRelay Core. It inherits
no additional filesystem or network capability.

### 3.2 Capability-limited bootstrap context

The launcher resolves the signed topology, opens resources, drops privilege and
passes these disjoint contexts:

```text
BlindEdgeBootstrapV1 {
  publicListenerHandles
  tlsCredentialHandles
  unaryIpcConnectHandle
  streamIpcConnectHandle
  fixedEndpointBindings
  genericOuterLimits
  edgeLogSinkHandle
  edgeMetricSinkHandle
}

BlindDaemonBootstrapV1 {
  storageRootHandle
  unaryIpcListenHandle
  streamIpcListenHandle
  blindIdentityKeyHandle
  genericLimits
  enabledGenericRoles
  admissionParameterFiles
  signedRouteCatalogFiles
  logSinkHandle
  metricSinkHandle
}
```

All file paths are resolved and opened by the launcher before privilege drop. The
daemon MUST reject unknown configuration keys. Reload accepts only a fully
validated, atomically replaced generic configuration generation.

It MUST NOT receive or be able to open:

- HiveRelay's application registry, main Corestore, semantic service stores, or
  plugin directory;
- the parent `RelayNode`, unrestricted configuration object, management API, or
  arbitrary callback;
- application environment variables, origins, API keys, namespaces, signing
  keys, or release manifests;
- an unrestricted filesystem root or arbitrary outbound socket API; or
- raw HTTP headers, cookies, referrers, user agents, client hints, query strings,
  or trace baggage.

The blind identity is a dedicated Ed25519 key used only for blind descriptors,
health responses, receipts, and proofs. It is not an application key and is not
the key of a co-resident semantic service. Its file is readable only by the blind
daemon user. Rotation follows section 10.

### 3.3 IPC contract

The HiveRelay edge is a streaming byte proxy. It may enforce total connection,
body, and timeout caps before the daemon, but MUST NOT parse a blind body, convert
it to JSON/base64, buffer a maximum-size body globally, attach application
metadata, or log it.

PRIVATE_IPC is its own canonical category, hashed by
`privateIpcFormatHash`/`privateIpcVectorSetHash`; it is neither WIRE nor an
implementation-selected object. Each socket authenticates the edge UID from the
signed topology; edge also authenticates daemon UID and the opened socket inode's
signed owner/group/mode/path. Unary and stream use two absolute, unequal,
non-symlink Unix-domain paths; multiplexing both over one socket is forbidden.
Every frame begins with big-endian `totalLength:u32` equal to all remaining bytes.

For staged HTTPS `CELL.PUT`, the operation-specific v2 contract in
`HIVERELAY-BLIND-PRIVATE-IPC-V2.md` supersedes the generic v1 stream row without
changing it. It carries one full outer envelope over 65,535-byte local frames,
requires peercred-authenticated TLS-exporter edge attestation, exposes separate
write-readiness and feature masks, and validates a same-class correlated
`RESPONSE`/`ERROR` fit before publish, WAL, spend, or signing. Raw binding bytes
are not authority and no v1 fallback is permitted.

The unary socket request and response are exactly:

```text
LocalDispatchV1 {
  version:                 u8 = 1
  family:                  u8 // 1..5
  transportId:             u8 // public 1..9; zero only for local readiness control
  transportSupportBit:     u16 // explicit registered one-hot bit; readiness zero
  endpointId:              u8 // 1..255
  outerClass:              u8 // public class 1..6; zero only for local readiness control
  acceptedMonotonicMillis: u64
  absoluteDeadlineMonotonicMillis:u64
  adjacentRelayKeyPresent: u8 // 0 or 1
  adjacentRelayKey:        present iff tag=1, nonzero 32 bytes
  bodyLength:              u32
  externalCanonicalBytes:  bytes[bodyLength]
}

LocalUnaryResponseV1 {
  version:                 u8 = 1
  responseKind:            u8 // 1 external canonical, 2 local broker error, 3 local ready ACK
  localBrokerError:        u8 // kinds 1/3: zero; kind 2: master closed enum 1..6
  bodyLength:              u32
  externalCanonicalBytes:  bytes[bodyLength]
}
```

Inclusive of the u32 prefix, unary request headers are exactly 32/64 bytes without/
with an adjacent key and response headers are 11 bytes. Stream-open headers are
33/65 bytes and stream-frame headers are 21 bytes. All multi-byte integers are
unsigned big-endian; split/coalesce/
truncation vectors cover every boundary.

Every external request carries one explicit registered one-hot
`transportSupportBit`; no component infers it from `transportId`. Request and
external-response body lengths equal the selected 4-KiB through 8-MiB class
exactly. Non-OHTTP bytes are one complete `BlindOuterEnvelopeV1`; OHTTP bytes
are the decapsulated canonical known-length bHTTP plaintext. A local-error response
has zero body and never becomes a WIRE error. One connection has at most one
in-flight pair and may be reused only sequentially; one direct HTTP/OHTTP exchange
or one readiness probe creates exactly one pair.

The only unary local-control variant is the master-spec readiness handshake. Edge
sends `family=DESCRIBE`, `transportId=0`, `transportSupportBit=0`, target
`endpointId`, `outerClass=0`, no adjacent key, and exact body
`u8(EDGE_READY_PROBE=1) || edgeInstanceNonce[32] ||
launchTopologyHash[32]`. For this variant only, `externalCanonicalBytes` is that
PRIVATE_IPC control body and is never public. Probe `t0` is construction time and its deadline is
exactly `t0+2000`. Before it, edge gives each topology path at most two seconds for
connect, mutual peer-credential, and inode owner/group/mode/path verification. The
stream check sends no frame and closes after authentication; daemon accepts that
pre-dispatch EOF only for this readiness-path check. After both unequal sockets are
bound and the current signed descriptor plus nonce-bound health result have been
constructed/self-verified from
one state snapshot with all three DESCRIBE operations ready, daemon returns kind 3
with the exact 120-byte body fixed in the master: control kind, echoed nonce and
topology hash, endpoint ID, descriptor sequence/hash, ready role/operation bits,
and monotonic expiry. Edge validates only this PRIVATE_IPC layout, authenticated
daemon peer credentials, exact echo/endpoint, monotonic descriptor tuple, required
DESCRIBE bits, and expiry no later than `t0+5000`; lower sequence or equal sequence
with another hash fails, while a higher sequence replaces the remembered tuple.
It does not parse WIRE or hold a relay signing key. It binds no public listener
before the first ACK, refreshes at
least 1,000 ms before expiry, and closes the listener plus accepted connections by
expiry on failure or rollback. The ACK is a same-host execution gate, not another
signed/public readiness claim; clients verify the exact signed WIRE descriptor and
`DESCRIBE.CHALLENGE` that edge relays opaquely. Readiness split/coalesce, wrong
path/UID/mode, nonce/topology/endpoint substitution, stale/forked tuple, missing
stream socket, key-unavailable, timeout, and expiry-close cases are mandatory
PRIVATE_IPC vectors.

For external unary dispatch, edge records both time fields from shared kernel
`CLOCK_MONOTONIC` at the first byte of each unary request on a new or reused
authenticated connection. Non-INBOX
requests have absolute deadline `t0+15000`; opaque
INBOX gets provisional `t0+35000`. After decode, daemon tightens non-WATCH INBOX to
15,000 ms and WATCH to `min(edgeDeadline, t0+maxWaitMillis+5000, t0+35000)`; its
waiter stops at `min(dispatchNow+maxWaitMillis, effectiveDeadline-2000)`. It rejects
future/expired/over-cap fields and no stage resets the absolute budget. This
replaces a blanket 15-second daemon socket timeout, which is invalid for the
allowed 30-second WATCH.

Edge enforces the master stage caps: TLS handshake 5,000 ms from connection accept;
headers 5,000 ms from first request byte with
1,024-byte request line, 32 fields and 16,384 aggregate bytes; first body byte and
body idle 2,000 ms, body completion 10,000 ms; IPC connect+request write 2,000 ms;
daemon result-frame write 2,000 ms; public response first byte 2,000 ms and write
idle 5,000 ms. Absolute 15,000/35,000-ms completion-or-abort always wins. Direct
POST requires exact `Content-Length` and no `Transfer-Encoding`; OPTIONS is empty
and capped at 5,000 ms. These values come only from the signed listener/profile and
canonical WATCH body, never caller headers or query data.

The stream socket uses exact master `LocalStreamOpenV1` followed by
`LocalUnaryResponseV1`, then `LocalStreamFrameV1`. Open carries closed `openKind`,
explicit `transportId` plus one-hot `transportSupportBit`, endpoint, closed
`streamMode`, class 0..3, one 15,000-ms maximum absolute open deadline, optional
adjacent key, and one exact private context. The decoder rejects unknown
kind/mode/class/context/adjacent combinations before allocation. The only table
rows are public dispatch-content and outer-envelope-content (class 1..3,
authenticated-channel context, optional adjacent key), authorized egress
forward-hop content (class 1..3, one-use-attach context, required adjacent key),
CORE raw child (class zero, attach context, no adjacent key), and local Noise
endpoint (class 1..3, attach context, no adjacent key).

The authenticated-channel context is the exact 225-byte master schema bound by
the authenticated native-session exporter, topology, complete open, process/local
channel nonces, parent session, transport profile, and final Noise handshake hash.
Verification returns an opaque branded handle; decoded/raw bytes never grant
authority. The attach context is exactly 137 bytes and contains a random 32-byte
ticket bound to parent session, descriptor sequence/hash, and child binding hash.
Tickets expire within 2,000 ms, have a 1,024-record cap, are deleted before any
consume comparison, and return authority only as an opaque branded handle.

Stream frames carry direction, first-zero exact-`+1` physical sequence, kind
CONTENT/CORE_RAW/CIPHERTEXT/CONTROL/ABORT, class, FIN-only flags, and variable
bytes. CONTENT class caps are 4,073/16,361/65,512; zero content is legal only with
FIN. Edge terminates and validates
outer encrypted record framing/padding, then forwards only content fragments;
daemon bounded-reassembles the u32-length-prefixed canonical WIRE item under one
maximum item plus one maximum record and performs all canonical decode/state work.
CORE_RAW is class zero and at most 65,535 bytes, with an empty body only on FIN.
CIPHERTEXT is exact class-zero Noise flights 32/96/64 or exact transport class
4,096/16,384/65,535 and never carries FIN. CONTROL is a class-zero, zero-flag,
closed `LocalStreamControlV1`; ABORT is a class-zero, zero-flag single generic
code. No freeform diagnostic or arbitrary payload exists.

The seven control variants are exact: CHANNEL_ACCEPT 42 bytes, CHANNEL_REJECT 11,
ATTACH_TICKET 74, EGRESS_DIAL 167, EGRESS_RESULT 76 failure/108 success,
CORE_CHILD_OPEN 82, and NOISE_SESSION_OPEN 139. Sequence counts every fragment,
flight, control, FIN, and abort. FIN terminates one direction; ABORT terminates the
stream. Any short/overlong/trailing frame, incomplete FIN reassembly, sequence
gap/replay, byte after FIN, peer change, drain, ticket replay, or cap violation
closes both directions and releases all reservations.

Every local field is synthesized from the bound signed listener/route and
authenticated outer channel; it is never copied from an external header, source
address, caller preface, URL, or body. `adjacentRelayKey` is present only after
cryptographic peer authentication. Daemon rechecks endpoint/transport/family/
class/adjacent-key binding before body allocation. Edge cannot attach caller
metadata or invent an identity.

No source IP or browser metadata crosses the IPC boundary. An explicitly weaker
per-IP edge limiter may run outside the membrane, but its state and claim are not
part of the strict substrate.

Every open store, listener, stream, watch, timer, child, and staging file belongs
to one lifecycle scope with `AbortSignal` cancellation and an idempotent bounded
`close()`.

---

## 4. Minimal external ABI

### 4.1 Bindings

The strict HTTP binding mounted only by `blind-edge` has exactly one POST route per family:

| Method | Route | Body/result |
| --- | --- | --- |
| `POST` | `/api/blind/v1/describe` | `DESCRIBE.GET`, `CHALLENGE`, or `ADMISSION_PARAMETERS` |
| `POST` | `/api/blind/v1/cell` | Tagged cell operation / result |
| `POST` | `/api/blind/v1/inbox` | Tagged inbox operation / result |
| `POST` | `/api/blind/v1/core` | Tagged core control operation / result or stream handoff |
| `POST` | `/api/blind/v1/forward` | Bounded opaque request or authorized stream handoff |

`OPTIONS` exists only for generic CORS preflight. No `GET` by locator, query
parameter, per-operation path, app alias, WebSocket room path, or semantic route
is part of the strict ABI. `DESCRIBE.GET` is a POST dispatch operation. The
existing `GET /.well-known/hiverelay.json` MAY carry the same canonical signed
descriptor bytes and hash as a cacheable compatibility representation; JSON
reserialization is not a signature preimage and challenge/parameter operations
remain POST-only.

Every unary semantic unit contains the same complete dispatch frame from section
4.2. Direct HTTP uses `application/vnd.hiverelay.blind-v1` with that frame inside
`BlindOuterEnvelopeV1`; OHTTP uses the RFC 9292 bHTTP/RFC 9458 mapping in section
8.2. Protomux/Noise and onion stream adapters carry repeated dispatch frames on an
authenticated channel. HTTP content length, outer envelope, bHTTP, HPKE, and
lower-level stream framing are not operation-signature preimages.

Success is HTTP 200. Only malformed outer framing (400), transport body overflow
(413), outer transport throttling (429), and unavailable daemon (503) use distinct
HTTP status. Protocol outcomes use a `RESULT` or `ERROR` dispatch frame inside a
200 response so an oblivious adapter preserves the same error contract. Responses
set `Cache-Control: no-store`; generic CORS never permits credentials.

### 4.2 Canonical dispatch/frame registry

The sole-source ABI registry defines this exact transport-neutral frame. Integer
fields are unsigned big-endian fixed-width values; no adapter may infer, omit, or
reinterpret one:

```text
BlindDispatchFrameV1 {
  frameLength:   u32                  // bytes after this field, <= 4 MiB + 64
  version:       u8 = 1
  frameKind:     u8                   // 1 request, 2 response, 3 error,
                                      // 4 stream-control/data
  familyId:      u8
  operationId:   u8
  flags:         u8 = 0               // all bits reserved in v1
  requestId:     16 bytes             // random nonzero for unary/open; zero for stream
  streamId:      u64                  // zero for unary/open request; nonzero after open
  sequence:      u64                  // zero for unary; per-sender monotonic for stream
  bodyLength:    u32                  // exact following bytes, <= family/op cap
  body:          exact canonical operation bytes
}
```

The frozen registry is:

| Family ID | Operations (`name=id`) |
| --- | --- |
| `1 DESCRIBE` | `GET=1`, `CHALLENGE=2`, `ADMISSION_PARAMETERS=3` |
| `2 CELL` | `PUT=1`, `GET=2`, `RENEW=3`, `DROP=4`, `PROVE=5`, `BATCH_GET=6` |
| `3 INBOX` | `CREATE=1`, `RENEW=2`, `CLOSE=3`, `APPEND=4`, `READ=5`, `WATCH=6` |
| `4 CORE` | `MIRROR=1`, `PROVE=2`, `OPEN_REPLICATION=3` |
| `5 FORWARD` | `OPEN=1`, `DATA=2`, `WINDOW=3`, `CLOSE=4` |

The executable registry MUST import the master spec's complete
`OperationProfileV1` row for every pair: request/result schema IDs, kind/transition,
body caps, admission/cost rule, commitment/result domains, error profile, and
transport bits. The generated dispatcher is built only from those rows. CI rejects
missing/duplicate pairs, schema/category drift, uncovered codecs, unsupported
transport exposure, cap mismatch, or a hand-written route/operation switch whose
projection differs from the registry.

It also imports the complete `DomainRegistryEntryV1` and
`ErrorProfileEntryV1` tables. Request domains use operation-defined commitment
recipe 1. Every result or auxiliary WIRE Ed25519 signature uses recipe 2 exactly:
`domain || u64be(payload.length) || canonicalPayload`; local omission of the
length, prehash/context, unregistered domain, or alternative payload fails vectors
and startup self-test.

A response repeats the request family, operation, and random `requestId` with
`frameKind=2`. A unary error repeats them with `frameKind=3` and canonical
`BlindErrorV1`. Stream frames use kind 4, zero request ID, their assigned stream
ID, and a strictly increasing sequence independently in each direction; a stream
error uses kind 3 with that stream ID. Unknown family/operation/kind, nonzero
flags, invalid ID combination, length mismatch, duplicate/non-monotonic stream
sequence, trailing bytes, or a body above its registry/descriptor/route cap fails
closed before body allocation or dispatch.

HTTP POST bodies and responses contain one complete frame and the fixed route
MUST match `familyId`; mismatch is `BAD_ENCODING`. OHTTP wraps one complete unary
request/response. Protomux/Noise and onion stream adapters carry repeated frames
on one authenticated control channel. `CORE.OPEN_REPLICATION` returns a child
stream ID and then switches that distinct bounded child to the pinned upstream
wire with no kind-4 BlindDispatch bodies; FORWARD alone uses canonical kind-4
DATA/WINDOW/CLOSE. Both require a stream-capable adapter; `INBOX.WATCH` remains a bounded unary long poll.

`requestId` is transport correlation only: it is excluded from signed request
commitments, never reused across hops, and never retained in logs. The operation
body still carries its signed `clientNonce` where specified. The absolute frame
cap is the length prefix plus at most 4 MiB + 64 bytes after it; each operation's
smaller cap is frozen into `abiHash`. Source-language objects and lower transport
framing are not protocol authority.

All operation bodies use the canonical byte grammar frozen by master-spec section
9.2.1. In particular, named `u8/u16/u32/u64` fields are fixed-width big-endian;
bounded byte/string and array lengths use the shortest
`compact-encoding.uint` prefix (whose extended payload is little-endian);
optionals use one explicit `0|1` presence byte; tagged unions use one explicit
`u8` tag; exact class/remainder fields have no nested length prefix; and a decoder
rejects invalid UTF-8/NFC, overlong prefixes, bad tags, unsorted/duplicate arrays,
truncation, or trailing bytes before dispatch. Implementations MUST use an exact
integer representation for `u64` values and MUST enforce a declared bound before
allocating children.

```text
DomainRegistryEntryV1 {
  domainId:         u16
  purpose:          u8 // 1 request commitment, 2 result signature,
                       // 3 auxiliary WIRE signature
  recipeId:         u8 // 1 operation-defined commitment preimage,
                       // 2 Ed25519(domain || len64(payload) || payload)
  exactAsciiBytes:  canonical ASCII bytes[1..96]
}

ErrorProfileEntryV1 {
  errorProfileId:        u8 = 1
  code:                  u8
  directCorrelatedStatus:u16 = 200
  protectedInnerStatus:  u16 = 200
  retryable:             u8 = 0 | 1
  retryAfterMode:        u8 // 0 MUST be absent, 1 MUST be present
}

AdmissionCostRuleV1 {
  costClassRuleId:  u16
  ruleKind:         u8
}

RelayResultBindingV1 { // nested in every persistent signed operation result
  version:               u8 = 1
  relayPublicKey:        32 bytes
  storeId:               32 random nonzero bytes
  descriptorSequence:    u64
  descriptorHash:        32 bytes
  durabilityProfileId:   u8
  durabilityContinuityHash:32 bytes
  durabilityProfileHash: 32 bytes
  externalCommitWitness: optional BlindExternalCommitWitnessV1
}

BlindExternalCommitWitnessV1 {
  version:               u8 = 1
  relayPublicKey:        32 bytes
  storeId:               32 random nonzero bytes
  externalJournalId:     32 random nonzero bytes
  durabilityContinuityHash:32 bytes
  durabilityProfileHash: 32 bytes
  familyId:              u8
  operationId:           u8
  requestCommitment:     32 bytes
  resultCommitment:      32 bytes
  commitWalSequence:     u64
  commitWalHash:         32 bytes
  coveringFloorRevision:u64
  coveringFloorHash:     32 bytes
  coveringFloorWalSequence:u64
  coveringFloorWalHash:  32 bytes
  writerEpoch:           u64
  writerFenceTokenHash:  32 bytes
  externalLeaseRevision: u64
  witnessedUnixMillis:   u64
  witnessPublicKey:      32-byte Ed25519 public key
  signature:             64-byte Ed25519 signature
}

BlindErrorV1 {
  version:         u8 = 1
  code:            stable u8 enum
  retryable:       u8 = 0 | 1
  retryAfterEpoch: optional u32
}
```

The executable ABI imports the master spec's complete 20-row
`ErrorProfileEntryV1` registry. Correlated direct and protected-inner errors are
HTTP 200 kind-3 frames; codes, retryability, and retry-after presence must match
their row byte-for-byte. Only `RENEW_NOT_DUE` carries a future
`retryAfterEpoch`. The dispatcher implements the frozen first-failure order:
cap, version, canonical encoding, transport support, locator relation,
authorization, authenticated cheap-state guards, admission, terminal visibility/
retry state, capacity, internal. Uncorrelated outer-adapter failures never invent
a `BlindErrorV1`. Pairwise/multiple-fault vectors prove identical selection across
direct and OHTTP paths; public absence always maps to one `NOT_FOUND` path.

Errors never distinguish a never-created, expired, owner-dropped, suppressed, or
reclaimed locator unless a valid management capability is part of that operation.

Persistent-result witnessing has no circular signature. Let
`unsignedPersistentResultBytes` be the complete canonical result with
`relayBinding.externalCommitWitness` encoded absent and only that result schema's
final relay signature omitted; all other fields and nested signatures remain.

```text
persistentResultCommitment = BLAKE2b-256(
  "hiverelay.blind.persistent-result.v1" || familyId(u8) || operationId(u8) ||
  len64(unsignedPersistentResultBytes) || unsignedPersistentResultBytes
)
```

Profile 1 always encodes the witness absent and signs after the local commit point.
Profile 2 creates a witness only after the final result WAL record and a covering
floor are majority-fsynced, inserts it into the binding, and then applies the
ordinary result signature. The witness fields must equal the request, result,
commit, live writer fence, active descriptor, continuity hash, exact dynamic
profile hash, and covering floor; its purpose-3 recipe-2 signature uses
`hiverelay.blind.external-commit-witness.v1`. The closed witness inventory is:

| Operation | Witness-bearing signed schema/path | Omitted final signature | Profile-2 condition |
| --- | --- | --- | --- |
| CELL.PUT / RENEW / DROP | `BlindReceiptV1` at root | `signature` | always |
| CELL.PROVE | `BlindReceiptV1` at `receipt` | `receipt.signature` | request has admission |
| CELL.BATCH_GET | `BatchGetResultV1` at root | `signature` | request has admission |
| INBOX.CREATE / RENEW / CLOSE | `InboxReceiptV1` at root | `signature` | always |
| INBOX.APPEND | `InboxAppendAckV1` at root | `signature` | always |
| INBOX.READ | `InboxReadResultV1` at root | `signature` | request has admission |
| INBOX.WATCH | `InboxReadResultV1` at root | `signature` | always |
| CORE.MIRROR | `BlindCoreAckV1` at root | `signature` | always |
| CORE.PROVE | `BlindCoreAckV1` at `acknowledgement` | `acknowledgement.signature` | request has admission |
| CORE.OPEN_REPLICATION | `CoreOpenReplicationResultV1` at root | `signature` | always |
| FORWARD.OPEN previous hop | `BlindForwardOpenResultV1` at root | `signature` | always |
| FORWARD.OPEN next hop | `BlindForwardHopAcceptV1` at `nextHopAccept` | `nextSignature` | always; built first |

DESCRIBE, CELL.GET, and FORWARD DATA/WINDOW/CLOSE have no witness-bearing signed
result. Uncharged optional reads/proofs carry the complete relay/store/profile
binding with witness absent. An extra, missing, copied, or mismatched witness fails.
For forwarding, the next-hop commitment/witness/signature is completed first and
its exact bytes are retained in the outer commitment/witness/signature.

Every purpose-2 result signature uses recipe 2 over the complete canonical payload,
including its `RelayResultBindingV1` and any witness. The two compressed large-result
payloads are exact:

```text
BatchGetSignaturePayloadV1 {
  version:          u8 = 1
  relayBinding:     RelayResultBindingV1
  requestNonce:     32 bytes
  requestCommitment:32 bytes
  entriesCommitment:32 bytes
}

InboxReadSignaturePayloadV1 {
  version:          u8 = 1
  relayBinding:     RelayResultBindingV1
  requestNonce:     32 bytes
  requestCommitment:32 bytes
  snapshotRevision:u64
  entriesCommitment:32 bytes
  nextCursor:       optional opaque bytes[0..128]
}
```

The raw entries must reproduce their commitment before signature verification;
the obsolete relay-key-only/header-subset payload is invalid.

### 4.3 Describe and health

`DESCRIBE.GET` returns `BlindServiceDescriptorV1` from section 10 and no mutable
counters. `DESCRIBE.ADMISSION_PARAMETERS` returns the exact signed parameter
object whose hash is in that descriptor. Descriptor representations are cacheable
only until signed expiry.

```text
BlindDescribeGetV1 {
  version:          u8 = 1
  descriptorHash:   optional 32 bytes // absent=current; present=history by hash
  clientNonce:      32 bytes
}

BlindAdmissionParametersRequestV1 {
  version:          u8 = 1
  profileId:        u16
  schemeId:         u16
  clientNonce:      32 bytes
}

BlindHealthChallengeV1 {
  version:          u8 = 1
  descriptorSequence:u64
  descriptorHash:   32 bytes
  endpointId:       u8 // exact signed TransportEndpointV1 endpoint
  transportSupportBit:u16 // exactly one frozen support bit
  requestedRoleBits:u16
  requestedOperationBits:u32
  clientNonce:      32 bytes
}

BlindHealthResultV1 {
  version:          u8 = 1
  relayPublicKey:   32 bytes
  storeId:          32 random nonzero bytes
  descriptorSequence:u64
  descriptorHash:   32 bytes
  endpointId:       u8 // exact challenged endpoint
  transportSupportBit:u16 // exact challenged one-hot support bit
  durabilityContinuityHash:32 bytes
  durabilityProfileHash:32 bytes
  clientNonce:      32 bytes
  readyRoleBits:    u16
  readyOperationBits:u32
  clockState:       u8 // 1 ready, 2 unsafe, 3 verifying
  effectiveEpochFloor:u32
  integrityState:   u8 // 1 verified, 2 degraded, 3 failed
  checkpointAgeBand:u8 // coarse universal band, no exact revision/time
  scrubAgeBand:     u8 // coarse universal band, no exact revision/time
  rebalanceState:   u8 // 0 stable, 1 copying, 2 catching-up, 3 fenced
  capacityBand:     u8
  challengeEpoch:   u32
  signature:        64 bytes
}
```

Both challenge bitmaps are nonzero. The endpoint ID and exact one-hot transport
support bit MUST match the authenticated endpoint/transport tuple, the bit MUST
belong to the bound endpoint's pinned transport profile and support the requested
operation subset, and the signed result MUST echo both fields. A proof cannot
qualify another endpoint or transport. Health handles issued under the earlier
draft shape are invalid and MUST NOT have a backward-compatible acceptance path.
Every signed
`TransportEndpointV1.canonicalUrl` uses the exact generic listener-authority
anchor `/api/blind/v1/describe`; clients derive each family route from the same
scheme and authority. It is never an app namespace or independently selectable
family backend.

The health result uses the master registry's purpose-2 recipe 2 domain
`hiverelay.blind.health-result.v1` with every preceding field as payload. It is produced only when the challenged listener
reaches the same coordinator and identity key as the advertised role. Health is a
fresh liveness/readiness statement, not a storage, independence, or anonymity
proof. Operation bits use the frozen 22-operation row-major bitmap; ready bits are
an exact subset of requested and descriptor-enabled bits, with bits 22..31 zero.

---

## 5. Cells service

### 5.1 Operations and limits

| ID | Operation | Authority | Persistent effect |
| --- | --- | --- | --- |
| 1 | `PUT` | one-time create signature + admission | Immutable cell, spend, retry result, receipt |
| 2 | `GET` | random locator; optional admission | None unless charged read idempotency is enabled |
| 3 | `RENEW` | renew signature + admission + revision CAS | Lease/revision, spend, receipt |
| 4 | `DROP` | drop signature + revision CAS | Terminal owner tombstone, receipt |
| 5 | `PROVE` | random locator + nonce; optional admission | Charged-read result when applicable |
| 6 | `BATCH_GET` | 1–64 distinct locators; optional admission | Charged-read result when applicable |

Exact request/result fields, commitment domains, `BlindReceiptV1`, and stable
errors are imported into the executable registry from the master protocol. The
implementation MUST preserve these fixed version-1 properties:

- slots, create/renew/drop public keys, nonces, and blob hashes are 32 bytes;
- signatures are Ed25519 and 64 bytes;
- the slot is the BLAKE2b-256 domain-separated commitment to the six-hour
  allocation epoch and random create public key;
- cell classes are exactly 4 KiB, 16 KiB, 64 KiB, 256 KiB, and 1 MiB total;
- lease classes are 1, 7, 30, and 90 days in six-hour epochs;
- renew computes `targetLeaseEpoch = max(oldLeaseEpoch, effectiveNowEpoch +
  duration(requestedLeaseClass))`. If target equals old it returns management-only
  `RENEW_NOT_DUE`, commits no spend, and changes no revision. Otherwise it sets the
  lease to target. It never adds a duration to an already-future lease;
- cells are first-write-wins and never overwritten;
- separately selected relays receive independently randomized ciphertext, slots,
  and management keys in the unlinkable profile;
- plain reads expose no lease or tombstone history; and
- a proof returns the complete blob plus a nonce-bound signed receipt. A stored
  hash alone is not a retrievability proof.

### 5.2 Persisted state

```text
CellIndexRecordV1 { // internal index; not a second wire schema
  slot
  allocationEpoch
  sizeClass
  leaseClass
  leaseEpoch
  stateRevision
  policyRevision
  cellBlobHash
  blobReference
  createPublicKey
  renewPublicKey
  dropPublicKey
  allocationCommitment
  objectState       // PRESENT or terminal TOMBSTONE
  policyState       // VISIBLE or SUPPRESSED while present
}
```

`blobReference` is internal and MUST NOT contain an app path. The blob store is
addressed by virtual bucket plus random internal object ID, not plaintext or
ciphertext hash. Hashes verify integrity; they are not filesystem namespaces.

The state machine is:

```text
ABSENT -> STAGING -> PRESENT/VISIBLE -> TOMBSTONE(owner-drop | expired-gc)
                         |   ^
                         v   |
                      SUPPRESSED

ACTIVE -> EXPIRED_GRACE -> RECLAIMABLE
```

Grace is four six-hour epochs. Renew/drop and GC use `stateRevision`; operator
suppress/restore uses `policyRevision`. Suppression cannot invalidate an owner
management capability. Tombstones, spent tags, create idempotency, and compact
write-receipt identities remain for 1,460 epochs so an accepted old create cannot
replay after compaction. Charged unary body/proof regeneration pins remain at most
15 minutes as specified in section 9.4; only their compact spent/terminal marker
survives for the longer horizon.

The persisted epoch floor never moves backward. While ready, even an idle daemon
appends a small floor-advance record at each crossed epoch and uses a monotonic
clock to detect wall discontinuity. A runtime jump over four epochs, or restart
more than four epochs beyond the persisted floor, enters `CLOCK_UNSAFE`: create,
renew, expiry, and new lease receipts stop; visible present bytes remain readable.
A configured multi-source clock verification policy or explicit operator-confirmed
`CLOCK_CONFIRM` WAL transition is required to advance the floor. After a confirmed
long offline interval, leases are evaluated at confirmed current time; downtime
does not extend retention.

---

## 6. Inbox service

An inbox is a generic fixed-frame append/read facility. It replaces the name
`rendezvous` at the component boundary because it can also carry opaque wakeups,
repair announcements, capability rotations, and other application-defined
ciphertext. The daemon never knows which use applies.

### 6.1 Creation policies

Every inbox is explicitly created. There is no free implicit topic creation,
topic enumeration, mutable semantic head, or server-selected application policy.
Version 1 supports exactly two append policies:

| Policy | Append authority | Intended generic property |
| --- | --- | --- |
| `OPEN_APPEND` (`appendAuthMode=0`) | Possession of random physical topic plus generic admission | Multiwriter/public announcement bag; spam is client-filtered |
| `SIGNED_APPEND` (`appendAuthMode=1`) | Generic admission plus signature by one random inbox append key | Single capability domain; key is not an app/author key |

The client generates independent random create, renew, close, and optional append
keys. The self-certifying physical topic is:

```text
physicalTopic = BLAKE2b-256(
  "hiverelay.blind.inbox-topic.v1" || allocationEpoch || createPublicKey
)
```

Frame classes are exactly 4 KiB, 16 KiB, and 64 KiB. Frame retention classes are
R1, R7, R30, and R90. The create operation selects one retention class and one
inbox lease class. A frame expiry is the minimum of its stored epoch plus the
selected retention and the current inbox lease. Renewing an inbox does not
retroactively extend or resurrect old frames. Per-topic/global entry and byte
caps are generic daemon limits, not caller-defined policies.

Inbox renew uses the same non-stacking rule as cells:
`targetLeaseEpoch = max(oldLeaseEpoch, effectiveNowEpoch +
duration(requestedLeaseClass))`; target equal to old returns management-only
`RENEW_NOT_DUE` with no spend or revision change.

### 6.2 Operations

| ID | Operation | Required authority |
| --- | --- | --- |
| 1 | `CREATE` | create signature + admission |
| 2 | `RENEW` | renew signature + revision CAS + admission |
| 3 | `CLOSE` | close signature + revision CAS |
| 4 | `APPEND` | admission and, for `SIGNED_APPEND`, append signature |
| 5 | `READ` | random inbox ID; optional admission |
| 6 | `WATCH` | random inbox ID + required admission; bounded unary long poll on any request/response transport |

```text
InboxCreateV1 {
  version:          u8 = 1
  allocationEpoch:  u32
  physicalTopic:    32 bytes
  frameClassBits:   u8
  appendAuthMode:   u8 // 0 open-capability, 1 signature-required
  createPublicKey:  32 bytes
  appendPublicKey:  optional 32 bytes // required exactly for mode 1
  renewPublicKey:   32 bytes
  closePublicKey:   32 bytes
  retentionClass:   u8
  leaseClass:       u8
  clientNonce:      32 bytes
  createSignature:  64 bytes
  admission:        AdmissionV1
}

InboxManageV1 {
  version:          u8 = 1
  operation:        u8 // 1 renew, 2 close
  physicalTopic:    32 bytes
  expectedRevision: u64
  expectedLeaseEpoch:u32
  leaseClass:       u8 // NONE for close
  clientNonce:      32 bytes
  signature:        64 bytes
  admission:        optional AdmissionV1 // required for renew
}

InboxAppendV1 {
  version:          u8 = 1
  physicalTopic:    32 bytes
  frameClass:       u8
  frameHash:        32 bytes
  clientNonce:      32 bytes
  appendSignature:  optional 64 bytes // required exactly for auth mode 1
  admission:        AdmissionV1
  frame:            exact class bytes
}

InboxReadV1 {
  version:          u8 = 1
  physicalTopic:    32 bytes
  cursor:           opaque bounded bytes[0..128]
  limit:            u16
  clientNonce:      32 bytes
  admission:        optional AdmissionV1
}

InboxWatchV1 {
  version:          u8 = 1
  physicalTopic:    32 bytes
  afterRevision:    u64
  limit:            u16
  maxWaitMillis:    u16 // 1..30000
  clientNonce:      32 bytes
  admission:        AdmissionV1
}

InboxAppendAckV1 {
  version:          u8 = 1
  relayBinding:     RelayResultBindingV1
  topicCommitment:  BLAKE2b-256(physicalTopic)
  frameHash:        32 bytes
  appendRevision:   u64
  storedAtEpoch:    u32
  expiresAtEpoch:   u32
  requestNonce:     32 bytes
  requestCommitment:32 bytes
  result:           u8 = 1 // STORED
  signature:        relay Ed25519 signature
}

InboxReadResultV1 {
  version:          u8 = 1
  relayBinding:     RelayResultBindingV1
  requestNonce:     32 bytes
  requestCommitment:32 bytes
  snapshotRevision: u64
  entries:          bounded ordered array[0..64] of {
                      appendRevision: u64, frameHash: 32 bytes,
                      frameClass: u8, frame: exact class bytes
                    }
  entriesCommitment:BLAKE2b-256(canonical(entries))
  nextCursor:       optional opaque bytes, maximum 128
  signature:        relay Ed25519 signature over InboxReadSignaturePayloadV1
}
```

Create, append, renew, and close commitments bind every preceding non-signature,
non-admission field and the relay key under distinct
`hiverelay.blind.inbox-*.v1` domains. `frameHash` is over the exact randomized
fixed frame. Each relay replica receives a fresh independently encrypted frame.

Append assigns a monotonically increasing, relay-local `appendRevision`. It is an
availability cursor only, never application order. Same
`(physicalTopic, frameHash, exact bytes, request commitment)` is an idempotent retry;
same hash with different bytes is `CONFLICT`. Capacity failure never evicts a
non-expired frame: append returns retryable `BUSY` until expiry or owner close frees the
inbox.

An empty read cursor captures `snapshotRevision`; later pages exclude newer
appends. A relay-authenticated cursor binds physical topic, last position,
snapshot revision, and a maximum 15-minute expiry. Results contain at
most 64 frames and 4 MiB and are signed over the request nonce/commitment, snapshot
revision, entries commitment, and next-cursor hash. A signature is not a
completeness proof.

### 6.3 Watch and backpressure

`WATCH` is a bounded long poll, not SSE or a durable subscription. It waits only
until `appendRevision > afterRevision`, `maxWaitMillis` (at most 30 seconds),
abort, or shutdown, then returns one ordinary bounded `InboxReadResultV1`. It is
therefore available over direct HTTP, OHTTP, Protomux, split transports, and Tor
without a distinct streaming protocol.

The daemon enforces per-connection, per-topic, and global waiter caps before
registering a waiter. Every waiter owns one timer and cancellation hook and is
removed exactly once on response, timeout, abort, shutdown, or topic close. There
is no event queue: append wakes bounded waiters, each of which reads its bounded
page under the ordinary snapshot rules. Response transport backpressure has the
same byte/deadline cap as `READ`; a stalled response is aborted and the client
reconnects from its last verified revision. Watch never extends retention,
acknowledges application delivery, or changes canonical order.

A charged read/watch persists only a compact retry pin containing spend tag,
request commitment, topic commitment, snapshot and first/last append revisions,
entries commitment, next-cursor hash/bytes, and expiry. It is capped at 256 bytes
and pins the immutable referenced range for at most 15 minutes so an exact retry
can regenerate the same signed page without storing a multi-megabyte duplicate.
GC/rebalance cannot remove a pinned range. The longer spent-tag horizon remains
after page retry metadata expires.

Inbox state, frames, cursor keys, spends, and reproducible acknowledgements use
the shared WAL transaction rules in section 9.

---

## 7. Blind Core service

Blind Core composes upstream `blind-peer`/`blind-peering`; it MUST NOT fork their
replication wire or add an application namespace. The relay stores encrypted
Hypercore blocks under an opaque core key. It never receives the block-encryption
key, writer key, app author key, or Autobase/application metadata.

| ID | Operation | Effect |
| --- | --- | --- |
| 1 | `MIRROR` | Request/extend generic sponsorship for a witnessed core head |
| 2 | `PROVE` | Return selected upstream blocks/proofs and a nonce-bound acknowledgement |
| 3 | `OPEN_REPLICATION` | Hand the transport stream to the byte-for-byte upstream blind-peer protocol |

```text
CoreOpenReplicationV1 {
  version:          u8 = 1
  wireProfileHash:  32 bytes
  sessionClass:     u8 // C1/C2/C3
  controlChannelId: u64
  parentChannelBinding:32 bytes
  clientNonce:      32 bytes
  admission:        AdmissionV1
}

CoreOpenReplicationResultV1 {
  version:          u8 = 1
  relayBinding:     RelayResultBindingV1
  wireProfileHash:  32 bytes
  sessionClass:     u8
  controlChannelId: u64
  parentChannelBinding:32 bytes
  streamId:         u64
  maxSessionBytes:  u64
  idleMillis:       u32
  lifetimeMillis:   u32
  openedAtEpoch:    u32
  requestNonce:     32 bytes
  requestCommitment:32 bytes
  signature:        64 bytes
}
```

CORE session classes are exact: C1 is 16 MiB/30-second idle/10-minute lifetime;
C2 is 64 MiB/60 seconds/30 minutes; C3 is 256 MiB/120 seconds/60 minutes.
`wireProfileHash` must equal the CORE protocol profile hash in the signed
descriptor and pins the upstream wire/dependency/vectors.

The exact native transport artifact/profile hash is frozen in the descriptor. With
exporter ID 1, both peers derive the 32-byte session exporter from that hash and
the exact 64-byte final parent Noise handshake hash, then derive
`parentChannelBinding` from the exporter and client-random nonzero
`controlChannelId` encoded as u64be. The ID is unique within that session and is
not an implementation Protomux object ID. OPEN
rejects a zero/mismatched/foreign-channel binding before spend. Its canonical
request commitment covers relay key, wire profile, class, control ID, binding, and nonce; its
result repeats them, applies the fixed class limits, and signs every preceding
field under `hiverelay.blind.core-open-result.v1`. The coordinator atomically
persists spend, request commitment, binding, stream ID, limits, and terminal state
before child allocation. Admission operation is `core-open-replication`, lease
class NONE, and resource/cost class is the exact C1/C2/C3 session class. A
transport without the authenticated exporter returns `TRANSPORT_UNSUPPORTED`
before spend.

The retry record also stores the master spec's binding-free logical retry key.
Exact commitment on the same live channel reattaches; the same logical key with
only a different channel ID/binding is `RETRY_TERMINAL` before generic replay
classification; any other changed commitment is `SPEND_REPLAY`.

OPEN is a unary control exchange that assigns one bounded child adapter stream;
it does not define CORE kind-4 dispatch bodies. After spend/result/parent-channel
binding are fsynced, `hiverelay/blind-core-upstream/1` carries upstream
blind-peer bytes unchanged inside the child. The adapter only counts bytes,
idle/lifetime, backpressure, half-close, abort, and close. HTTP/OHTTP return
`TRANSPORT_UNSUPPORTED` before spend. Lost-result reattach is allowed only on the
same authenticated parent to the same live child; otherwise `RETRY_TERMINAL` and
no replacement. Upstream interop captures and every class/close/restart boundary
are release gates.

`MIRROR` binds core public key, fork, length, signed-head hash, lease class,
request nonce, and admission. The shared WAL first commits the spend,
sponsorship floor/expiry, idempotency record, and `mirror-accepted` acknowledgement.
Adapter activation is a recoverable state:

```text
ACCEPTED -> ACTIVATING -> ACTIVE -> EXPIRED
                    `-> RETRY_PENDING
```

`mirror-accepted` means sponsorship was durably accepted, not that bytes are
already retrievable. Health exposes aggregate core-role readiness; per-core status
is learned only through prove/serve. Restart resumes accepted activations.

Any holder of the opaque key may sponsor more availability; no public v1 core-drop
exists. Growth above the latest admitted signed length pauses until a new admitted
extension. Prove requests contain 1–16 sorted distinct indices and return at most
4 MiB. The client verifies the Hypercore signed head, fork/length floor, Merkle
proofs, block decryption, and application bytes.

Core sponsorship computes the same `max(oldLeaseEpoch, now + duration)` target. A
request may still raise the admitted signed head/length when target equals old;
the coordinator charges only if at least one admitted resource dimension advances
and records the exact resulting head, length, and lease. Otherwise it returns
`RENEW_NOT_DUE` before spend or mutation.

Until the repository's Hypercore 10/Corestore 6 stack is proven compatible with
the selected upstream blind-peer generation, this role runs in a daemon-owned
store/child process. Dependency compatibility, close behavior, disk accounting,
and wire interop are release gates.

---

## 8. Forward service and transport adapters

### 8.1 No open proxy

Forwarding is authorized only by a signed, app-free route in the current route
catalog. A request cannot supply a hostname, IP, URL, onion name, or arbitrary
next-hop key.

```text
BlindForwardOpenV1 {
  version:                u8 = 1
  routeId:                16 bytes
  nextDescriptorSequence: u64
  nextDescriptorHash:     32 bytes
  requestedWireClass:     u8
  circuitClass:           u8
  circuitNonce:           32 bytes
  hopAdmission:           AdmissionV1
  innerHandshake:         bounded opaque bytes[32] // exact Curve25519 Noise flight 1
}

BlindForwardOpenResultV1 {
  version:                u8 = 1
  relayBinding:           RelayResultBindingV1
  routeId:                16 bytes
  nextDescriptorSequence: u64
  nextDescriptorHash:     32 bytes
  circuitNonce:           32 bytes
  grantedWireClass:       u8 // exactly requestedWireClass in v1
  circuitClass:           u8
  streamId:               u64 // random nonzero on this authenticated channel
  grantedInitialWindow:   u32
  maxDataBytes:           u32 // exact wireClass bytes; flight3 exception
  maxCircuitBytes:        u64
  idleMillis:             u32
  lifetimeMillis:         u32
  openedAtEpoch:          u32
  requestCommitment:      32 bytes
  nextHopAccept:          BlindForwardHopAcceptV1
  signature:              64 bytes
}

BlindForwardHopOpenV1 {
  version:                  u8 = 1
  route:                    BlindTransportRouteV1
  previousDescriptorSequence:u64
  previousDescriptorHash:  32 bytes
  circuitNonce:             32 bytes
  requestedWireClass:       u8
  circuitClass:             u8
  grantedInitialWindow:     u32
  maxDataBytes:             u32
  maxCircuitBytes:          u64
  idleMillis:               u32
  lifetimeMillis:           u32
  clientRequestCommitment:  32 bytes
  handshakeFlight1:         32 bytes
  forwarderSignature:       64 bytes
}

BlindForwardHopAcceptV1 {
  version:                  u8 = 1
  previousRelayKey:         32 bytes
  previousDescriptorSequence:u64
  previousDescriptorHash:  32 bytes
  nextRelayKey:             32 bytes
  nextDescriptorSequence:   u64
  nextDescriptorHash:       32 bytes
  nextRelayBinding:         RelayResultBindingV1
  routeId:                  16 bytes
  circuitNonce:             32 bytes
  nextStreamId:             u64
  grantedWireClass:         u8
  circuitClass:             u8
  grantedInitialWindow:     u32
  maxDataBytes:             u32
  maxCircuitBytes:          u64
  idleMillis:               u32
  lifetimeMillis:           u32
  openedAtEpoch:            u32
  hopOpenCommitment:        32 bytes
  handshakeFlight2:         96 bytes
  nextSignature:            64 bytes
}

BlindForwardDataV1 {
  version:          u8 = 1
  circuitNonce:     32 bytes
  offset:           u64
  bytes:            bounded opaque bytes[1..maxDataBytes]
}

BlindForwardWindowV1 {
  version:          u8 = 1
  circuitNonce:     32 bytes
  consumedThrough:  u64
  creditIncrement:  u32 // 1..1 MiB; total credit remains capped
}

BlindForwardCloseV1 {
  version:          u8 = 1
  circuitNonce:     32 bytes
  closeKind:        u8 // 1 FIN(send side), 2 ABORT(both sides)
  finalSendOffset:  u64
  reasonCode:       u8 // generic bounded enum, no app text
}
```

The route binds previous endpoint, next relay key plus descriptor sequence/hash,
next endpoint, profile, separate envelope/wire class bitsets,
`maxCanonicalDispatchBytes`, ingress `maxEncapsulatedRequestBytes`, streaming
`maxOpenBytes/maxCircuitBytes`, stream limit, issued/expiry epochs, and signature.
OHTTP and streaming-only fields are zero when inapplicable; a required zero is
invalid, not unlimited. The daemon checks the catalog hash and both descriptors
before reserving resources. Unknown, expired, wrong-role, app-specific, class-
confused, or oversized routes fail before any network connection.

FORWARD classes are frozen app-neutral tuples: F1 is a 64-KiB window, 16-MiB
aggregate cap, 30-second idle, and 10-minute lifetime; F2 is 256 KiB/64 MiB/60
seconds/30 minutes; F3 is 1 MiB/256 MiB/120 seconds/60 minutes. The caller selects
the smallest fitting class; arbitrary numeric combinations are impossible.

The open-result signature domain is
`hiverelay.blind.forward-open-result.v1` and covers every preceding field. The
OPEN commitment binds previous key, route, next descriptor sequence/hash, wire and
circuit classes, circuit nonce, and handshake hash. The caller request has
`streamId=0`; its result assigns the caller stream ID.

`nextRelayBinding` repeats the next relay key and descriptor sequence/hash, binds
the destination store and durability continuity/profile, and carries the required
profile-2 witness. `hopOpenCommitment` is that witness's request commitment. The
next-hop purpose-3 recipe-2 signature covers the complete binding and witness, so
neither can be substituted by the forwarder.

Before dialing, the coordinator persists the exact signed HopOpen and spend. On
the authenticated `hiverelay/blind-forward-hop/1` adjacent channel, the forwarder
sends `u32be length || HopOpen`; the next hop verifies link/signature/route/both
descriptor bindings/bounds, initializes the correct Noise prologue, consumes the
exact 32-byte flight1, persists HANDSHAKE state, and returns
`u32be length || HopAccept` with exact 96-byte flight2. The forwarder verifies and
persists the accept, embeds it in OpenResult, and exposes the caller stream only
after fsync. The client's first DATA offset zero is exact 64-byte flight3; later
DATA is exact negotiated Noise ciphertext. Adjacent DATA/WINDOW/CLOSE reuse the
canonical FORWARD bodies with a persisted one-to-one caller↔`nextStreamId` map.
Replay is indexed by previous key+circuit nonce and complete HopOpen commitment:
exact retry returns the same accept, changed reuse conflicts. Subsequent frames use
kind 4, zero request ID, the assigned stream ID, and per-sender monotonic sequence.

A DATA offset MUST equal the next expected byte offset; no relay reorders or
buffers gaps. A sender may have at most the receiver-granted number of unconsumed
bytes outstanding. WINDOW advances only after bytes are written to the next-hop
bounded queue and prior buffers are released; it never raises outstanding credit
above 1 MiB. At zero credit the adapter stops reading upstream and relies on
transport backpressure. Per-circuit buffers are at most the granted window plus
one `maxDataBytes` frame.

Each direction has independent offsets, dispatch sequence, FIN, and credit. Both
FINs close normally after buffered bytes drain. ABORT, malformed frame, admitted
quota/lifetime/idle expiry, next-hop loss, or daemon shutdown closes both
directions and releases socket, buffers, waiter, route/admission state, and circuit
table entry exactly once. Keepalives do not reset admitted lifetime. No FORWARD
result asserts end-to-end delivery, non-collusion, or privacy.

Every hop performs independent admission before allocating a destination socket,
stream buffer, or circuit. The WAL atomically commits its `FORWARD_RESERVED`
spend/exact retry state before dialing. Entry, exit, and final storage operations
use distinct tokens, spend tags, nonces, and commitments. Completion commits the
bounded result status; exact retry resumes/returns that state and a different
request using the spend tag is replay. Hop admission never replaces final storage
admission, and failure never falls back to an open or direct proxy.

### 8.2 Padded unary envelope and stream chunks

Private unary adapters carry one complete canonical dispatch frame; they never
invent a transport-specific operation schema. Non-bHTTP adapters place the frame
inside this plaintext before end-to-end split-path encryption:

```text
BlindOuterEnvelopeV1 {
  version:       u8 = 1
  outerClass:    u8
  innerLength:   u32 // exact complete BlindDispatchFrameV1 bytes
  innerDispatch: bytes[innerLength]
  randomPadding: remaining bytes to exact outer class
}
```

Outer plaintext classes are universal and exact:

| Class ID | Total plaintext bytes |
| ---: | ---: |
| 1 | 4 KiB |
| 2 | 16 KiB |
| 3 | 64 KiB |
| 4 | 256 KiB |
| 5 | 1 MiB |
| 6 | 8 MiB |

`envelopeClassBits` advertises these IDs; `wireClassBits` is the separate Noise
record namespace. For this envelope the class covers the
complete plaintext, not Noise/TLS overhead. `innerLength` must be at least the canonical dispatch
header, fit exactly before the remainder, and the dispatch length prefix must
consume exactly `innerLength`; mismatch, nested trailing bytes, wrong class for
the observed plaintext length, or non-exact total is `BAD_ENCODING`. Padding comes
from a CSPRNG, is never compressed, and is ignored only after transport
authentication and all length checks. For split-native paths the complete
envelope is inside the innermost client-to-storage Noise session before it enters
the exit→storage FORWARD circuit. A separate client-to-exit control Noise session
hides that exit circuit from the entry; neither hop Noise nor the control session
alone may carry operation plaintext.

OHTTP is not this proprietary envelope. The OHTTP adapter MUST implement RFC 9458
using RFC 9292 known-length binary HTTP as the HPKE plaintext. Its bHTTP request
has method `POST`, scheme `https`, authority exactly the selected signed gateway
authority, path exactly the selected fixed family route, and the ordered header
list `content-type` then `accept`, both with value
`application/vnd.hiverelay.blind-v1`. It has no authority override, query,
informational response, trailer, `Date`, cookie, authorization, Origin, referrer,
Fetch Metadata, priority, ambient field, or compression. A correlated response has
status 200, only `content-type` with that value, and one complete response/error
dispatch as content. Let `base` be the canonical bHTTP
encoding with zero padding; the encoder selects the smallest shared class that
fits and appends exactly
`classBytes - byteLength(base)` RFC 9292 zero bytes. The complete bHTTP plaintext
is therefore exactly the class; HPKE adds only the fixed overhead of the advertised
key configuration. Indeterminate framing, invalid mid-section truncation, nonzero
padding, ambient/app headers, compression, or path/family mismatch fails closed.
Byte-exact
vectors freeze control data, headers, paths, status/error mapping, and every class
boundary. Outbound encoders use the shortest legal QUIC-varint width and always
emit explicit header/content/zero-trailer lengths; they never truncate empty tail
sections. Inbound RFC 9292 parsing accepts and normalizes legal wider integers and
permitted empty-tail truncation before profile validation. Vectors cover 63/64,
16,383/16,384, 1,073,741,823/1,073,741,824, and all reachable class boundaries.
Every OHTTP POST on both client→ingress and ingress→gateway disables TLS early
data/0-RTT and waits for handshake confirmation. The gateway's bounded
per-config cache of exact encapsulated `enc` values is a denial-of-service guard
only; replay correctness remains the dispatch/admission/idempotency contract.

RFC 9458's relay resource maps to one fixed gateway. The client cannot place an
arbitrary target URL in the encapsulated request and the ingress is never an open
proxy. In version 1 the gateway role terminates OHTTP in blind-edge and passes the
exact decapsulated class-sized bHTTP plaintext over PRIVATE_IPC to its blind-daemon
target. Serving several storage gateways requires several fixed shared,
app-neutral ingress resources and signed route entries. A separate
gateway-to-storage hop is not inferred; it requires a later profile with an
explicit signed bounded next-hop allowlist and its own capture and abuse gate.

The canonical `application/ohttp-keys` collection and signed wrapper mapping are
exactly those in the master spec: entries sort by `configId`, each RFC 9458 key
configuration is prefixed by `u16be` length, one wrapper maps to one KEM plus one
KDF/AEAD pair, and one malformed/duplicate entry rejects the whole collection.
Cold clients obtain the gateway descriptor/config/mapping from their signed
release bundle or the ingress's one shared generic config resource; they never
contact the gateway directly before source separation exists. Refresh stays on
that path and requires the signed descriptor sequence plus witnessed auxiliary
hash.

Outer requests are `POST` with `message/ohttp-req`. Once the gateway successfully
decapsulates, every target success/error is returned as outer `200` with
`message/ohttp-res`; Blind errors remain inside protected bHTTP. Relay failures and
pre-decapsulation gateway failures are unprotected 4xx/5xx. They are forgeable by
the ingress and therefore never count as an app result, proof of non-processing,
downgrade decision, or trusted key material. Only a separately authenticated
signed collection can update keys.

After decapsulation, the only protected uncorrelated transport errors are exact
two-byte `BlindOhttpTransportErrorV1 { version=1, code }` with non-overlapping
boundaries: status 400/code 1 MALFORMED_INNER before a valid dispatch exists;
status 503/code 2 TARGET_UNAVAILABLE after decoding but before handing the
dispatch to the target, and only with positive non-processing evidence; or status
504/code 3 TARGET_TIMEOUT after the target may have received the valid dispatch
but no valid correlated response arrived. Their only header is `content-type:
application/vnd.hiverelay.blind-transport-error-v1`; explicit trailer length is
zero, there is no Date/Retry-After/text/request ID, and canonical zero padding uses
the smallest shared class. A target success or target-generated Blind error with a
matching request ID uses status 200 plus the correlated dispatch; the gateway
never fabricates one for timeout or connection loss. Only protected code 2 can
authorize policy-controlled same-destination fresh-HPKE retry; code 3 is ambiguous
and requires reconciliation. Pre-decap errors remain unprotected/untrusted.
Golden vectors freeze every status, byte, class, and the
pre-decap/pre-dispatch/pre-target/post-target boundaries.

Non-bHTTP request and response envelopes likewise use the smallest mutually
advertised class that fits unless a named app-neutral privacy policy chooses a
larger class from the same universal set. All apps share the same ingress pool,
gateway route pool, HPKE suites/config set, class table, and selection policy.
Each request uses a fresh HPKE context. Eligible ingress-to-gateway H2/H3
connections are pooled across clients and apps and selected without downstream
IP/Origin affinity, caller-specific TLS credentials, caller priority/header, or a
dedicated per-client connection. A per-app or per-client gateway/key config or
stable pool affinity is nonconforming because it partitions the anonymity set.
Multi-client/two-app captures MUST reject gateway-visible connection grouping.
Connection, HPKE, and record overhead are reported separately and never folded
into class identity.

An ambiguous OHTTP timeout, connection loss, or response loss is not an automatic
retry signal. The client retains the exact logical intent as pending and follows
RFC 9458 section 6.5: it may automatically resubmit in a fresh HPKE context only
after a positive HTTP/2 or HTTP/3 signal that the request was not processed (for
example an applicable `REFUSED_STREAM`, `H3_REQUEST_REJECTED`, or qualifying
`GOAWAY`). Otherwise it reconciles with a separate CELL GET/PROVE, INBOX READ, or
CORE PROVE where applicable, or waits for an explicit user/policy resubmission.
Daemon idempotency still makes an explicitly repeated identical inner request
safe, but it cannot be used to bypass the OHTTP transport rule. No resend reuses
HPKE context or silently changes gateway/storage, locator, commitment, spend, or
privacy profile.

Long-lived split streams do not expose a plaintext chunk length to the entry.
`split-native-protomux-v1` implements two separate
`Noise_XX_25519_ChaChaPoly_BLAKE2b` machines: a client↔exit control session over
the entry circuit and a client↔storage blind session over an exit circuit carried
inside that control session. The sessions have fresh unrelated random initiator
static keys and independent transcript, nonce, stream, offset, credit, timeout,
and abort state. The signed next endpoint's `endpointKey` is the responder static.
Tag overhead is exactly 16 bytes. Transport plaintext is:

```text
BlindStreamChunkPlainV1 { // exact total = wireClass bytes - 16-byte tag
  version:       u8 = 1
  wireClass:     u8 // ciphertext: 1=4096, 2=16384, 3=65535 bytes
  flags:         u8 // bit 0 FIN; all other bits zero
  contentLength: u32
  content:       bytes[contentLength]
  randomPadding: remainder to (wireClass bytes - 16)
}
```

Maximum content is 4,073, 16,361, or 65,512 bytes. The largest ciphertext is
65,535—not 65,536—because the Noise Framework caps every message at 65,535 bytes.
The complete ciphertext is `BlindForwardDataV1.bytes`; offsets and credit count
ciphertext bytes.

Entry OPEN carries the exact 32-byte Curve25519 client↔exit flight 1. The verified
HopAccept embedded in OpenResult carries exact 96-byte flight2; first DATA at
offset zero carries exact 64-byte flight3. All three Noise XX handshake payloads
are zero length, the total buffered transcript is exactly 192 bytes, and handshake
time is at most 30 seconds. The selected class is accepted exactly—v1 rejects
rather than downgrades it. Its exact prologue is the master-spec exit domain plus
previous/next keys and descriptor sequence/hashes, route ID, circuit nonce,
requested wire class, and circuit class. Before
transport mode, early records, extra flights, transcript/static mismatch, timeout,
or fallback aborts. Client↔exit plaintext then concatenates into a bounded stream
of canonical exit-directed dispatch frames.

Inside that encrypted stream, a second OPEN with distinct route, circuit nonce,
admission, and fresh static carries the exact 32-byte client↔storage flight 1. It
uses the master-spec storage prologue, verified-accept/first-DATA framing, and identical 32/96/64-byte zero-payload,
192-byte transcript, exact-class, and 30-second rules. In transport mode the exit
sees only complete opaque storage-session records. The inner exit DATA dispatch
stream is allowed to cross outer control-record boundaries: specifically, a
65,535-byte storage record plus dispatch framing must be fragmented into at least
two client↔exit records. The exit reassembles at most one frame under the absolute
dispatch cap. Storage-session plaintext similarly reassembles one exact bounded
`BlindOuterEnvelopeV1` before dispatch. Stream IDs, offsets, windows, admission,
and byte/lifetime caps remain independent at both hops; zero inner credit
propagates backpressure without an unbounded outer queue.

The class is fixed at OPEN and bounded by the signed route. Envelope and dispatch
boundaries come from their canonical lengths. Inner FIN permanently half-closes
that Noise plaintext direction; later bytes fail closed. FORWARD FIN mirrors the
half-close, while ABORT owns teardown and cascades without fallback. Byte-exact vectors cover both prologues and XX
transcripts, static-key nonlinkability, early data, nonce/sequence, nested
fragmentation/reassembly, every boundary, tag failure, FIN, credit propagation,
abort/retry, and role-local captures. Another split adapter must first define and
vector an equally exact nested overhead and knowledge partition.

### 8.3 Common adapter interface

Every adapter implements the following logical interface; language and runtime are
not prescribed. Server/listener implementations are compiled only into
`blind-edge`; daemon imports no HTTP/TLS/Protomux/onion listener adapter:

```text
TransportAdapter {
  id
  supportedProfiles
  request(endpoint, canonicalRequest, limits, signal) -> canonicalResponse
  open(endpoint, canonicalOpen, limits, signal) -> boundedDuplex
  start(listenerHandles, signal)
  drain(deadline)
  close()
}
```

It MUST:

- pass canonical blind messages unchanged end to end;
- enforce descriptor/route/outer-class limits before allocation or dialing;
- expose bounded read/write queues and propagate half-close, abort, timeout, and
  backpressure;
- pool eligible connections without sharing application cookies or credentials;
- provide only the fixed `LocalDispatchV1` metadata to the daemon;
- never perform a privacy-weakening retry under the same operation; and
- report adjacent-role/profile counters without client, locator, route, or app
  labels.

### 8.4 Required adapters

| Adapter/profile | Required behavior | Claim ceiling before its gate |
| --- | --- | --- |
| Direct HTTPS/Protomux, `direct-blind-v1` | Authenticated endpoint; raw streaming; Protomux protocol name `hiverelay/blind/1` | Storage/payload blindness only; source, Origin, timing, and interest remain visible |
| OHTTP, `split-web-ohttp-v1` | Fresh HPKE context per request, pooled H2/H3, independently operated generic ingress, signed shared key config, fixed outer classes | Storage source separation under ingress/gateway non-collusion; no read-interest claim |
| Protomux split, `split-native-protomux-v1` | Entry forwards an end-to-end Noise stream only to a signed exit route; exit forwards only to signed storage; bounded Protomux channels | Candidate native source separation after role-local capture and non-collusion assumptions |
| MASQUE, `split-native-masque-v1` | Persistent two-hop H3/CONNECT-UDP circuit carrying end-to-end Noise/QUIC blind messages; no per-cell circuit | Candidate native source separation after route, leak, and performance gates |
| Tor native, `tor-native-full-v1` | Full v3 onion endpoint to the edge's onion listener/local socket; edge strips transport metadata and uses private IPC to daemon; native descriptors and service traffic stay inside Tor; stable isolation token per local session/persona | G2-W plus Tor threat-model source separation; no global-observer or read-interest claim |
| Tor Browser, `tor-browser-full-v1` | Full v3 onion endpoint with no clearnet fallback; capture ambient browser headers at storage | Source-address separation only until the opaque-origin Origin/referrer/Fetch-Metadata gate passes; neither G2-W nor G4-T from Tor alone |

The native Tor adapter encodes SOCKS5 username exact ASCII `<torS0X>0` and a
nonempty password that is unpadded base64url of 32 fresh random bytes per local
session/persona. It rejects empty/arbitrary usernames, cross-persona token reuse,
and clearnet/DNS fallback. Tor Browser credentials remain browser-controlled and
are never represented as an app isolation token.

The Protomux split and MASQUE profiles are alternatives with the same knowledge
partition: entry sees client and exit, exit sees entry and storage, storage sees
exit and generic blind operations. The entry MUST NOT know the storage endpoint;
the exit/storage MUST NOT receive the original client address. Adjacent roles
SHOULD use distinct relay identities/operators. Different keys are evidence, not
proof of independence.

Ordinary browser Fetch cannot create CONNECT/MASQUE. Browser streaming through
WebTransport/WebSocket is experimental and receives a separate profile after its
own gate. OHTTP ingress app opacity additionally requires cross-browser proof that
an opaque-origin client leaks no stable app discriminator; until then only the
storage role is app-blind.

Strict Tor mode has no clearnet DNS, direct descriptor fetch, UDP/HyperDHT race,
or automatic fallback. The onion endpoint uses a local Unix socket where
available. An operator need not run a public Tor network relay. Tor unavailability
fails closed. Tor does not remove browser-generated `Origin`, referrer, or Fetch
Metadata: Tor Browser and native onion modes remain distinct evidence/claim
profiles, and every supported Tor Browser must pass the ambient-header classifier
before its storage path can advertise G2-W or G4-T.

---

## 9. Storage, virtual buckets, and atomicity

### 9.1 Virtual buckets and partitions

At store initialization the daemon generates a random persistent 32-byte
`K_partition`, distinct from identity, receipt, descriptor, transport, cursor,
and admission keys. It is never advertised or shared with another relay. There
are exactly 65,536 relay-local virtual buckets:

```text
digest = HMAC-SHA-256(K_partition, serviceTag || primaryLocator)
virtualBucket = digest[0] * 256 + digest[1] // unsigned u16 big-endian
```

`serviceTag` is the fixed ABI family byte for `CELL`, `INBOX`, or `CORE`.
`primaryLocator` is respectively the random cell slot, physical inbox topic, or
opaque core key. Keying prevents an identical portable locator from landing in a
correlatable bucket number at different relays. Forward retry and descriptor/
admission control records remain in the coordinator's bounded control keyspace;
they do not create a caller-selectable partition namespace. No app, author,
record type, plaintext hash, origin, or client identity is an input.

`K_partition` is included in the encrypted operator backup/recovery contract.
Losing it makes deterministic index recovery impossible. Rotation requires a
complete fenced rebalance and is never coupled to relay identity rotation.

A local `BucketMapV1` maps virtual-bucket ranges to physical shard workers/volumes
and has a monotonically increasing `mapGeneration`. Clients never address a
partition; the external endpoint remains stable. Partitions own segments, indexes,
checkpoints, staging, tombstones, retry pins, and byte accounting, while one
relay-wide coordinator owns the WAL, spend uniqueness, idempotency, epoch floor,
and bucket map. Descriptors expose only coarse aggregate capacity, never the map
or per-bucket traffic.

Version 1 permits one active writer daemon per blind relay identity. Multiple
disks/partitions are supported; active-active multi-host writers are not. A future
distributed transaction backend must pass the same atomic/crash vectors before it
can preserve the protocol profile.

### 9.2 Online rebalance

Rebalance moves complete virtual buckets, never a semantic subset:

```text
STABLE(source, generation)
  -> COPYING(source, target, snapshotRevision)
  -> CATCHING_UP(source, target, walRevision)
  -> FENCED(target, generation + 1)
  -> STABLE(target, generation + 1)
```

Every transaction captures the selected bucket's `(mapGeneration,
ownerFenceToken)`. The source remains the sole writer through COPY/CATCH_UP while the target copies
a verified snapshot and replays ordered per-bucket WAL deltas. The coordinator
then fences the source, blocks new reservations, and drains or boundedly aborts
staged transactions through a recorded final per-bucket WAL LSN. The target
verifies through that LSN; one ordered commit then fsyncs the new generation/fence
token before exposing the target as writer. A staged transaction whose saved
generation/token changed never publishes to the old owner: it reroutes before
staging where possible, otherwise deletes/releases its unspent reservation and
returns retryable `BUSY`. Reads may consult both
copies but return one state revision. No phase has two unfenced writers.

Crash recovery selects the last fsynced map generation and idempotently resumes or
discards the copy. The source is deleted only after a later verified checkpoint.
Rebalance has bounded concurrency/IO and pauses under foreground-latency, disk-
pressure, clock-unsafe, or integrity-failure conditions. Crash/concurrency tests
race reservations, body staging, and WAL commit against every copy, delta, fence,
final-LSN, fsync, map commit, restart, and reclaim transition.

### 9.3 WAL/admission atomicity

The ordered create/append/mirror transaction is:

1. Decode and validate fixed prefixes, declared body length/hash, caps, signatures,
   clock, coarse capacity, and admission shape without allocating staging or
   changing state.
2. Call `admission.prepare()` as a side-effect-free verifier before body disk I/O. It returns
   `{ spendTag, requestCommitment, costClass, walCommitRecord }`.
3. Acquire spend and object locks in canonical byte order. Detect exact committed
   retry, conflict, and spend replay, or append/fsync `INGRESS_RESERVED` keyed by
   spend+locator+commitment with declared bytes, 15-minute deadline, and exactly
   two attempt credits. It consumes the token for only this commitment and counts
   against global/per-profile staging quota after local fsync in profile 1; profile
   2 additionally waits for the pinned journal to cover that exact sequence/hash
   and a local `EXTERNALLY_WITNESSED` marker. Until its applicable commit point it
   is hidden and authorizes no body work.
4. Before body bytes, fsync an attempt-credit decrement. Profile 2 obtains its
   covering external floor and fsyncs its witnessed marker; profile 1 proceeds on
   local fsync. Stream the exact body into
   a capped temporary object while hashing under rate/deadline/abort limits. A
   complete wrong length/hash commits terminal spend state through the same
   profile-specific sequence; an interrupted first attempt may
   use the single remaining exact-retry credit. Exhaustion/expiry follows that
   sequence too, bounding one valid token to two declared-body disk/hash attempts.
   Profile 2 preserves that bound across live-volume loss; profile 1 permanently
   retires the identity after such loss. A match fsyncs the object.
5. Reacquire locks, revalidate reservation and map generation, atomically publish
   the body file within its partition, fsync the directory, and append one
   checksummed final WAL commit containing the object delta/reference,
   prepared spend, request commitment, retry result, receipt fields, bucket/map
   revision, deterministic result/binding, visibility transition, and epoch-floor
   transition; group fsync is allowed. Profile 1 becomes locally durable/visible
   and may sign after this fsync. Profile 2 remains
   `LOCAL_COMMITTED_PENDING_FLOOR`, hidden from every read/proof/checkpoint/
   rebalance view.
6. For profile 2, submit the exact committed WAL sequence/hash and unsigned result
   commitment to the store-pinned external
   control journal and obtain a covering `BlindExternalAckFloorV1`.
7. For profile 2, obtain the matching `BlindExternalCommitWitnessV1`, append/fsync
   an `EXTERNALLY_WITNESSED` marker binding it/floor, then make the mutation visible
   and release the deterministic signed result. A group receipt waits for both the
   group WAL fsync and its covering external floor/witness.

A crash before `INGRESS_RESERVED` leaves an unspent token. Profile 1 recovers only
from the same intact locally locked store and replays its complete prefix; any gap,
clone, relocation, or ambiguity permanently retires the identity. Profile 2 first
externally witnesses any exact locally pending control transition, then restores
one consumed/resumable bounded reservation, remaining credits, and at most one
orphan. A pending profile-2 local transition authorizes no body work or outcome.
Invalid/reused admission cannot trigger body staging/fsync. A crash after step 5
replays one mutation, one spend, and the same result. There is no separate
authoritative spent database. A profile-2 crash after step 5 restores hidden
pending state and must re-witness the identical WAL sequence/hash/result before
step 7; uncharged reads cannot observe it. Reuse of a spend tag with another commitment is
always replay; reuse of a commitment with inconsistent fields is conflict.

Renew/drop/control mutations have no staged blob but use the same lock, WAL, and
result rules. A charged read commits its spend and exact snapshot/result identity
before sending bytes. Uncharged reads are side-effect-free. WAL frames have length,
type, sequence, transaction ID, bucket/map revision, payload hash, and checksum;
recovery truncates only an incomplete torn tail and fails closed on an interior
checksum or sequence break.

The implemented draft local frame is `BlindWalFrameV2`, byte-for-byte: ASCII
`HRWL` at offsets 0..3; version `2` at 4; nonzero record type at 5; big-endian
`totalLength` at 6; sequence at 10; 32-byte nonzero transaction ID at 18;
virtual bucket at 50; map generation at 52; 32-byte writer-fence hash at 60;
payload length at 92; predecessor WAL hash at 96; the exact nonzero
`durabilityContinuityHash` at 128; payload BLAKE2b-256 at 160; payload at 192;
and a final 32-byte checksum. `totalLength = 224 + payloadLength`. Sequence one
uses a zero predecessor; later frames use
`BLAKE2b-256("hiverelay.blind.wal-frame-hash.v1" || previousCompleteFrame)`.
The checksum is
`BLAKE2b-256("hiverelay.blind.wal-frame-checksum.v1" ||
frame[0..totalLength-32])`. Recovery compares continuity, map generation, and
fence to the already validated store session before applying payload bytes. The
old unpublished version-1 layout is rejected rather than accepted as a weak
continuity alias.

Checkpoints are written to a new file, fsynced, atomically renamed, directory
fsynced, and committed by WAL sequence. Startup loads the newest committed
checkpoint and replays forward without scanning ciphertext bodies. Compaction
cannot remove tombstones, spends, retry records, or cursor/admission keys before
their declared horizons.

### 9.4 Charged unary retry pins

Every charged unary operation commits its spend before response bytes can be
lost. The coordinator therefore stores a compact `ChargedUnaryRetryV1`, never a
duplicate response body:

```text
ChargedUnaryRetryV1 {
  version:          u8 = 1
  spendTag:         32 bytes
  requestCommitment:32 bytes
  familyId:         u8
  operationId:      u8
  locatorCommitment:32 bytes
  sourceRevision:   u64
  sourceCommitment: 32 bytes
  resultCommitment: 32 bytes
  reconstruction:   bounded canonical bytes[0..96]
  retryExpiresMinute:u64
  retryState:       u8 // 1 replayable, 2 visibility-revoked, 3 terminal
}
```

The record is at most 256 bytes. It pins the immutable cell/blob or ordered batch
state, inbox WAL range, or exact core fork/head/block/Merkle state required to
reconstruct the same bounded result and signature. `CELL.GET/PROVE/BATCH_GET`,
charged inbox `READ/WATCH`, and `CORE.PROVE` all use this contract. A core adapter
that cannot deterministically pin and regenerate its proof must make prove
uncharged or unsupported. Every regenerated result is checked against
`resultCommitment` before release. Pin expiry is at most 15 minutes. After it, the longer spent-tag
record remains authoritative, so retry cannot charge again even if the response
can no longer be regenerated.

Every exact-retry record binds the exact `relayPublicKey`, `storeId`,
`durabilityContinuityHash`, endpoint/request/admission material, and the historical
commit-time descriptor sequence/hash and `durabilityProfileHash` carried by its
result. Before retry, the client verifies that the current linked descriptor still
has the same relay key/store/continuity and advertises the required operation; it
then verifies the returned deterministic result against its historical commit
descriptor/profile. A routine linked descriptor or dynamic-profile refresh on the
same tuple does not create a fresh replica. Recoverable role-activation caches are
updated to that current linked descriptor rather than pinning a stale sequence.
Operator history, URL, or dual-signed key rotation is never retry/write authority.
Any changed relay key, store ID, or continuity binding—even for the same operator
or endpoint—is a fresh replica attempt with fresh admission, nonce, locator, and
result binding.

Policy safety overrides response replay. A later operator `SUPPRESS`, owner inbox
`CLOSE`, terminal cell drop/GC, or equivalent core suppression immediately makes
the public retry indistinguishable from ordinary absence and releases byte-serving
eligibility; it never replays bytes merely because an older charged result was
prepared. Replay takes the resource lock and checks the one authoritative current
visibility/state record before following a regeneration reference. Suppress,
drop, close, and GC therefore update only that authoritative record in O(1); they
do not scan or rewrite retry records. Old pins/records age out asynchronously, and
an optional reverse index is bounded and only a reclamation optimization. The
spend remains consumed and retry returns a deterministic generic terminal outcome.
Public `GET/PROVE/READ/WATCH` cannot distinguish never-created, expired,
closed/dropped, suppressed, or reclaimed state.

`FORWARD.OPEN` persists the assigned circuit nonce, stream ID/channel binding,
limits, and terminal state with its spend. An exact retry on the still-live
authenticated channel returns the same signed open result and circuit; it never
dials a second circuit. If the channel/circuit already terminated, the retry
returns its deterministic generic terminal code and never spends or dials again.
Forward retry state contains no buffered application bytes.

### 9.5 Store format, upgrade, backup, and clean restore

The store root is the following MACed/checksummed manifest and its separate
`storeFormatHash`; it is internal and is never served to clients:

```text
BlindLocalCheckpointV1 {
  magic:                 exact ASCII "HRBCKP01"
  checkpointVersion:     u16 = 1
  relayPublicKey:        32 bytes
  storeId:               32 bytes
  durabilityProfileId:   u8
  durabilityContinuityHash:32 bytes
  durabilityProfileHash: 32 bytes
  formatMajor:           u16
  formatMinor:           u16
  storeFormatHash:       32 bytes
  specHash:              32 bytes
  abiHash:               32 bytes
  mapGeneration:         u64 nonzero
  bucketMapHash:         32 bytes
  writerEpoch:           u64 nonzero
  writerFenceTokenHash:  32 bytes
  checkpointRevision:    u64 nonzero
  previousCheckpointHash:optional 32 bytes
  coveredWalSequence:    u64 nonzero
  coveredWalHash:        32 bytes
  epochFloor:            u32
  descriptorSequenceFloor:u64
  descriptorHashFloor:   32 bytes
  snapshotByteLength:    u64 nonzero
  snapshotHash:          32 bytes
}

BlindStoreManifestV1 {
  magic:                 exact ASCII "HRBLIND1"
  manifestVersion:       u16 = 1
  storeId:               32 random nonzero bytes
  relayPublicKey:        32 bytes
  durabilityProfileId:   u8
  durabilityContinuityHash:32 bytes
  durabilityProfileHash: 32 bytes
  formatMajor:           u16
  formatMinor:           u16
  storeFormatHash:       32 bytes
  specHash:              32 bytes
  abiHash:               32 bytes
  mapGeneration:         u64
  bucketMapHash:         32 bytes
  checkpointWalSequence: u64
  checkpointHash:        32 bytes
  epochFloor:            u32
  writerEpoch:           u64
  writerFenceTokenHash:  32 bytes
  externalLeaseRevision: u64 // zero for profile 1
  externalJournalId:     32 bytes // zero for profile 1; nonzero for 2
  externalWitnessPublicKey:32 bytes // zero for profile 1
  lastAckWalSequence:    u64 // zero for profile 1
  lastAckWalHash:        32 bytes // zero for profile 1
  externalCheckpointRevision:u64 // zero for profile 1
  externalCheckpointHash:32 bytes // zero for profile 1
  descriptorSequenceFloor:u64
  descriptorHashFloor:   32 bytes
  migrationState:        u8 // 0 stable, 1 prepared, 2 copying, 3 verifying, 4 switching
  sourceFormatMajor:     u16
  targetFormatMajor:     u16
  migrationCursorHash:   32 bytes
  previousManifestHash:  optional 32 bytes
  manifestRevision:      u64
  mac:                   32 bytes
}
```

The checkpoint file is canonical and hashes under
`hiverelay.blind.local-checkpoint-hash.v1` with an exact u64 length prefix. Its
separate canonical `BlindControlStateSnapshotV1` file must match the declared
length/hash and repeat the relay/store/continuity/WAL tuple. The manifest repeats
the covered WAL sequence and checkpoint-header hash. Missing bytes, a WAL-head
hash substituted for the checkpoint hash, or any tuple mismatch fails validation
before cleanup, truncation, repair, or listeners.

`controlSnapshotHash = BLAKE2b-256("hiverelay.blind.control-snapshot.v1" ||
len64(canonicalSnapshotBytes) || canonicalSnapshotBytes)`. Every checkpoint
`snapshotHash` equals that value. The checked-in
`store/control-state-snapshot-v1.bin` vector freezes the canonical bytes and hash
preimage and is included in `storeVectorSetHash`.

The generated
`packages/blind-protocol/hiverelay-blind-store-format-authority-v1.draft.cenc`
is the executable store-format authority. It starts with `HRBSFA01`, authority
version 1 and format `1.0`, then contains the exact complete INTERNAL_STORE
catalog bytes followed by the strictly sorted printable-ASCII rule entries in the
master. `storeFormatHash` hashes the exact complete authority artifact with the
length-delimited `hiverelay.blind.store-format-hash.v1` recipe; hashing only the
schema catalog, its hash, or `storeVectorSetHash` is nonconforming. Generation and
`--check` must reproduce every byte.

The daemon verifies those exact artifact bytes against the embedded generated
catalog and frozen source rules before opening storage. It requires the verified
version/format/hash to equal the signed durability tuple and requires the signed
build profile to name the same `storeFormatHash`. The verifier-minted authority is
then passed into `BlindCellStorageEngine`, while `runtime-binding.v1` MAC-binds the
same format tuple to relay/store/continuity/profile/map/fence identity. Stale
artifacts, stale signed pins, split build/durability pins, forged authority
objects, and preexisting root-binding mismatches fail before mutation. This is an
executable draft binding only; it does not authorize removal of the `.draft`
marker while Core/global recovery, genesis, manifest-runtime integration, or any
other store-format publication blocker remains.

The only canonical control paths in format 1 are
`control/writer.lock.v1`, `control/wal.v2`, `control/manifest-a.v1`,
`control/manifest-b.v1`, content-addressed
`control/checkpoint-<hash32>.v1`, and content-addressed
`control/snapshot-<hash32>.v1`. Manifest temporaries are
`control/.manifest-[ab].v1.<nonce16>.tmp`; checkpoint/snapshot temporaries insert
the same dot prefix and append `.<nonce16>.tmp` to the complete final basename.
Hashes are 64 lowercase hex characters and nonces are 32. No writer-lock or WAL
temporary name exists.

WAL publication is complete-frame append, WAL fsync, anchor advance, then state
apply/visibility/signature/acknowledgement. Snapshot publication completes
exclusive-temp write and fsync, pre-install streaming canonical/hash/binding/
semantic verification, atomic OS rename-no-replace install, directory fsync, and
same-inode final verification before the same sequence begins for its
checkpoint header. Only after both verify may the manifest CAS advance. Existing
immutable finals must be byte-identical and are never replaced; the unused temp
is unlinked and the directory fsynced again. Each manifest slot uses exclusive-temp write/fsync,
rename-replace, directory fsync, and reopen/MAC/exact-byte verification, advancing
the inactive/opposite slot first and the other second.

Startup holds the canonical writer lock and validates before mutation. It never
selects a temporary or unreferenced immutable final. It MAC-checks both slots:
zero valid fails, one valid needs repair, equal revisions must be byte-identical,
and unequal revisions must be exact adjacent predecessor/successor records. The
selected manifest's checkpoint, revision-1 predecessor chain, snapshot, WAL
anchor, and every binding/hash validate before repair, temp cleanup, torn-tail
truncation, or listeners. Validation-only startup deletes nothing.

Format 1 retains all complete WAL frames and all immutable checkpoint/snapshot
finals. WAL pruning/segment replacement, checkpoint/snapshot garbage collection,
checkpoint crash-orphan temp reclamation, crash-resumable empty-root/revision-1
genesis publication, and online/offline format migration are explicitly
unsupported. An unknown format major, missing exact reader, WAL v1, provisional
layout, MAC/checksum failure, empty unanchored root, or build/store/profile/
continuity mismatch therefore fails before listeners. A descriptor must not
claim a writable durability implementation while any of these required lifecycle
paths remains necessary but unsupported.

Both profiles release results only after body, directory, and local-WAL fsync.
Profile 1 `LOCAL_FSYNC_IDENTITY_RESET_V1` permits one writer on one continuously
mounted live filesystem under an exclusive OS/filesystem lock. The same identity
may restart only from that exact intact store after complete manifest/WAL/body/
spend/result/visibility replay. A backup restore, clone, relocation, missing key,
control gap or fork, ambiguous lock, or attempted new store ID permanently retires
the old `(relayPublicKey,storeId)`; recovery starts an unrelated relay key and
random store ID. A body copy may seed client-authorized repair under fresh
bindings, but never same-identity continuity. Every external journal, witness,
lease, floor, checkpoint, topology, and restore-evidence field is its exact
zero/absent value;
`acknowledgedRpoBand`, `targetRtoBand`, and `restoreDrillAgeBand` are zero and
`redundancyClass` is at most 1.

Profile 2 `CONTROL_RPO0_3_NODE_V1` adds the pinned three-voter external journal,
lease, floor, checkpoint, topology, and per-result witness needed for zero-RPO
released control history and fenced same-identity restore/failover. In both
profiles, `acknowledgedRpoBand` describes only opaque body/block backup exposure;
profile-2 released control RPO is exactly zero or mutation readiness is clear.

The encrypted backup unit is one checkpoint plus required WAL tail, all blobs/core
state, tombstones, spends/reservations/retry pins, bucket map/accounting, cursor/
store keys, epoch floor, and `K_partition`. Its content manifest hashes every
chunk, names the covered WAL sequence/format reader, and resides outside the live
failure domain. Relay identity and release signing keys use separate threshold
custody. A backup is counted successful only after automated verification; a
durability band is advertised only after a clean-machine restore drill meets it.

Backup bytes are never stored off-host in plaintext. The portable encrypted
archive uses these exact schemas:

```text
BlindBackupEncryptionProfileV1 {
  version:               u8 = 1
  algorithmId:           u16 = 1 // XCHACHA20_POLY1305_IETF
  keyDerivationId:       u16 = 1 // HKDF_SHA256
  recoveryKeyId:         32 random nonzero bytes
  backupSalt:            32 random nonzero bytes
}

BlindBackupChunkManifestV1 {
  version:               u8 = 1
  backupId:              32 random nonzero bytes
  encryptionProfile:     BlindBackupEncryptionProfileV1
  encryptionManifestHash:32 bytes
  entries:               sorted array[1..16777216] of {
                           path: portable relative ASCII bytes[1..512],
                           fileOffset: u64,
                           plaintextByteLength: u32[1..4194304],
                           ciphertextByteLength:u32[17..4194320],
                           nonce: 24 bytes,
                           ciphertextHash: 32 bytes
                         }
  totalPlaintextByteLength:u64
  totalCiphertextByteLength:u64
}
```

A path is lowercase relative ASCII components separated only by `/`; each matches
`[a-z0-9][a-z0-9._-]{0,127}`. Absolute/empty paths, empty components, `.`, `..`,
slashes at either end, backslash, colon, percent, control/non-ASCII/uppercase
bytes, case/normalization aliases, duplicates, links, sparse ambiguity, and
non-regular files fail. Entries sort by raw `(path,fileOffset)`, cover each file
contiguously from zero, and satisfy `ciphertextByteLength =
plaintextByteLength + 16` and both checked totals.

The 32-byte recovery master key is held separately from every online, relay,
witness, store, partition, and release key. Nonces are unique per backup and a
`(recoveryKeyId,backupSalt)` pair is never reused. `canonicalEncryptionPlan` is
the canonical chunk manifest through `encryptionProfile` followed by each ordered
entry only through `nonce`, excluding the encryption-manifest hash, ciphertext
hashes, and totals. Encryption is exact:

```text
backupEncryptionProfileHash = BLAKE2b-256(
  "hiverelay.blind.backup-encryption-profile.v1" ||
  len64(canonical(BlindBackupEncryptionProfileV1)) ||
  canonical(BlindBackupEncryptionProfileV1)
)
encryptionManifestHash = BLAKE2b-256(
  "hiverelay.blind.backup-encryption-manifest.v1" ||
  len64(canonicalEncryptionPlan) || canonicalEncryptionPlan
)
backupPrk = HKDF-SHA256-Extract(backupSalt, recoveryMasterKey)
chunkKey[i] = HKDF-SHA256-Expand(
  backupPrk,
  "hiverelay.blind.backup-chunk-key.v1" || backupId ||
  encryptionManifestHash || u64be(i),
  32
)
chunkAad[i] =
  "hiverelay.blind.backup-chunk-aad.v1" || backupId ||
  encryptionManifestHash || u64be(i) ||
  len64(canonical entry[i] fields path through nonce) ||
  canonical entry[i] fields path through nonce
ciphertextHash[i] = BLAKE2b-256(
  "hiverelay.blind.backup-ciphertext.v1" ||
  len64(storedCiphertextAndTag[i]) || storedCiphertextAndTag[i]
)
```

Restore streams and verifies the exact chunk-manifest length/hash, path/coverage,
and ciphertext hashes before AEAD authentication. Plaintext is released only
after its tag verifies and is extracted into a new empty directory through
directory-fd/`openat` no-follow operations; every object must remain below that
root, be a restore-owned regular file, and not pre-exist. The public backup store
contains only canonical manifests and ciphertext+tags. Substitution, traversal,
key/nonce/AAD reuse, known-plaintext, and sentinel scans are release gates.
The witness-signed backup manifest, clean-restore evidence, and journaled retention
transition are profile-2 protocol evidence and carry its nonzero journal/
continuity binding. A profile-1 operator may use the same encrypted portable
container privately, but it cannot advertise backup/RTO bands, reproduce an old
relay-bound result, or use the archive for same-identity READY.

Format-authority version 1 rejects every format upgrade and non-STABLE migration
state. The following never-rewrite-the-sole-copy sequence is a required future
authority design, not executable permission in the current artifact:

```text
STABLE(v) -> PREPARED(v->v+1) -> COPYING -> VERIFYING
          -> FENCED_SWITCH(final LSN + directory fsync) -> STABLE(v+1)
```

The target is a separate store. It copies a verified checkpoint, tails the one
active writer, fences at a final LSN, verifies every record/blob/spend/accounting
and map entry, then atomically commits the switch. The source stays immutable
through rollback horizon. Before switch rollback discards target; after switch an
old binary needs an explicit compatible reader or tested reverse shadow migration.

If a later authority closes those blockers, its times and capabilities come only from signed
`BlindReleaseSupportHorizonV1`. In `FENCED_BLUE_GREEN`, new components start
without public ownership or a writer lease, shadow-copy/tail/verify, and wait while
the old descriptor drains. Old daemon commits the terminal LSN, clears readiness,
releases the external writer lease and closes IPC; only a higher-epoch CAS permits
new daemon READY and endpoint transfer. Any temporarily retained old ABI is an
adapter in the new edge, proven by the predecessor's compatibility vectors and
removed exactly at `oldAbiServeThroughUnixMillis`; old daemon is never retained as
a second writer. Post-fence rollback is another fenced reverse-shadow migration
and is refused after `rollbackThroughUnixMillis`.

`IN_PLACE_FORMAT_COMPATIBLE` permits no simultaneous process generation. It
requires identical store format or the named bidirectional reader/writer vectors;
old edge drains, old daemon checkpoints/releases lease, both stop, then new daemon
acquires a higher epoch and new edge opens. Rollback repeats the sequence. Startup
refuses current operation after `fullSupportThroughUnixMillis` absent a newly
signed activated release. Kill/fork tests cover every horizon, final-LSN, lease,
IPC, endpoint, descriptor and reverse-migration boundary.

Restore is `EMPTY -> RESTORING -> VERIFYING -> REPLAYING_WAL -> SCRUBBING ->
FENCING_OLD_WRITER -> READY|RECOVERY_GAP_READ_ONLY`; all mutation/storage readiness bits stay
clear and no receipt is signed before READY. Under profile 1, this workflow may
return the same identity to READY only when it is restart/replay of the exact
continuously live mounted store under its exclusive lock. Any backup candidate,
copy, relocation, continuity ambiguity, missing partition/store key, or replay gap
is never a same-identity restore: the old tuple remains retired and the recovered
body bytes can only seed a fresh unrelated identity. Profile 1 never acquires an
external lease or emits an external floor/witness.

Under profile 2, continuity requires one external linearizable lease under stable
key `(relayPublicKey, storeId)`, whose conditionally updated value is
`(writerEpoch, freshWriterFenceToken, holderInstanceId,
leaseRevision, expiresAtLeaseClockMillis)`. Epoch/token are values, never lookup-key
components. The authoritative TTL is at most 30 seconds; renew by 10 seconds before
expiry and map authenticated remaining TTL minus measured RTT and a two-second
uncertainty margin onto a conservative local monotonic deadline. Clear readiness at
least 5 seconds before expiry without a committed exact-value CAS. Check cached
epoch/token/revision/deadline before WAL commit and again before result release; a
pause across the margin emits nothing. The manifest and WAL header persist epoch, domain-separated token hash,
and lease revision. The restored writer chooses an epoch above both verified local
and external floors and waits for conditional revocation or authoritative expiry
plus the stop margin before READY. Ambiguous/unreachable/lost-history lease state
fails closed; without provable exclusive fencing it uses a new relay identity.
Before any signed mutation/charged-operation result is released, the independent
linearizable control journal must durably cover its WAL sequence/hash in a signed
`BlindExternalAckFloorV1`; descriptor publication has the same rule. Same-identity
restore reproduces that complete control and descriptor floor exactly. Store
genesis pins `externalJournalId` and `externalWitnessPublicKey` in both manifest
slots and the signed durability profile before opening listeners; every floor must
match those values. Restore configuration cannot replace them, and v1 changes
either binding only by creating a new relay/store identity.

The journal ID is nonzero in manifest, floor, and descriptor. The witness private
key exists only in the external journal failure domain. Its public key is rejected
if it equals the relay, release/reproducer, endpoint/admission, or any accepted
visible capability key; the release key is likewise distinct from the runtime
relay key. Equality/key-reuse vectors fail startup or the pre-mutation request
gate. Key distinctness is not claimed as proof of organizational independence.

External floors use exact Ed25519 verification over the master-spec domain and
canonical bytes. Revision 1 alone omits its predecessor; each later revision is
exactly prior+1 and hashes the complete prior signed floor with the frozen
`hiverelay.blind.external-ack-floor-hash.v1` length-delimited BLAKE2b preimage.
Non-canonical/small-order keys, non-canonical signatures, changed fields/domains,
missing/extra predecessors, skips, and same-revision forks fail the INTERNAL_STORE
vectors; no other 32/64-byte signature scheme is compatible.

Every journal append is linearly conditioned on the exact live external lease
`(writerEpoch, writerFenceToken, holderInstanceId, externalLeaseRevision)`. The
journal authenticates the raw tuple internally, checks the unexpired current lease
and matching WAL header, and signs the floor's epoch, domain-separated token hash,
and lease revision atomically with the append. Any stale/delayed old-writer tuple
fails without advancing history; fencing tests race it through every lease and
replacement transition.

Production durability profile 2 uses the master-spec
`LINEARIZABLE_3_NODE_QUORUM_V1`: one lease/control consensus history, three voters
in three declared failure domains, and no floor until a majority has fsynced it.
Minorities never acknowledge; quorum loss stops admitted transitions/mutation
readiness but preserves uncharged reads of already witnessed visible state. A
single-process/host/volume or mock journal cannot satisfy the profile. Node/disk
loss, majority/minority partitions, leader failover, corrupt replacement,
snapshot restore, and signing-service loss must preserve one prefix and zero
acknowledged gaps.

The signed durability profile hashes a fresh
`BlindExternalJournalTopologyV1` with exactly three node keys and distinct declared
failure domains, quorum two, stable shared failure-group ID, and role-conflict
declarations. The evidence is sequence-linked, expires within four epochs, and is
public evidence only—not the control endpoint or proof of ownership independence.
Missing/stale/forked topology clears mutation/privacy/resilience qualification;
clients collapse relays sharing the failure-group ID and treat every journal node
as storage/redeemer knowledge for collusion analysis.

```text
BlindExternalJournalTopologyV1 {
  version:               u8 = 1
  relayPublicKey:        32 bytes
  storeId:               32 bytes
  externalJournalId:     32 random nonzero bytes
  durabilityContinuityHash:32 bytes
  topologySequence:      u64
  previousTopologyHash:  optional 32 bytes
  replicationClass:      u8 = 1
  commitQuorum:          u8 = 2
  sharedFailureGroupId:  32 random nonzero bytes
  nodes:                 sorted array[3..3] of {
                           nodePublicKey: 32-byte Ed25519 public key,
                           operatorGroupId: 32 random nonzero bytes,
                           failureDomainId: 32 random nonzero bytes,
                           roleConflictBits: u16
                         }
  issuedEpoch:           u32
  expiresEpoch:          u32
  witnessPublicKey:      32-byte Ed25519 public key
  signature:             64-byte Ed25519 signature
}
```

Profile 2 and its evidence mirrors retain every complete topology object and
predecessor needed by a retained descriptor/result for at least 1,460 epochs and
one year, subject to the 4,096-object online chain cap. The selected
`DESCRIBE.GET`/evidence path fetches one by exact topology hash without a direct-
URL downgrade. A client accepting a persistent profile-2 result stores the exact
descriptor, durability profile, topology, and witness bytes (or verified
content-addressed copies). Historical verification uses that commit-time topology
and ignores only its later expiry; current selection still requires fresh evidence.
Missing archive bytes make the old topology claim unverifiable and never permit
substitution of a newer topology or silent reclassification as profile 1.

Profile-2 body-recovery claims are backed by a public canonical bundle rather than
inferred from coarse bands:

```text
BlindRestoreEvidenceIndexV1 {
  version:               u8 = 1
  relayPublicKey:        32 bytes
  storeId:               32 bytes
  externalJournalId:     32 random nonzero bytes
  durabilityContinuityHash:32 bytes
  descriptorSequence:    u64
  backupManifestHash:    32 bytes
  cleanRestoreEvidenceHash:32 bytes
  retentionTransitionHash:32 bytes
  backupEncryptionProfileHash:32 bytes
  restoreDrillCompletedUnixMillis:u64
  restoreSupportExpiresUnixMillis:u64
  issuedExternalUnixMillis:u64
  issuedEpoch:           u32
  expiresEpoch:          u32
  witnessPublicKey:      32-byte Ed25519 public key
  signature:             64-byte Ed25519 signature
}

BlindRestoreEvidenceBundleV1 { // canonical size <= 131072
  version:               u8 = 1
  index:                 BlindRestoreEvidenceIndexV1
  backupManifestBytes:   bounded canonical bytes[1..65535]
  cleanRestoreEvidenceBytes:bounded canonical bytes[1..8192]
  retentionTransitionBytes:bounded canonical bytes[1..8192]
}

restoreEvidenceHash = BLAKE2b-256(
  "hiverelay.blind.restore-evidence-bundle-hash.v1" ||
  len64(canonicalCompleteBundle) || canonicalCompleteBundle
)
```

`restoreEvidenceUrl` is an evidence mirror, never a control endpoint. Its exact
fetched canonical bytes must decode one bundle and hash to the descriptor field.
The index uses purpose-3 recipe 2 domain
`hiverelay.blind.restore-evidence-index.v1` over every field before `signature`.
Its relay/store/journal/continuity/witness fields equal the enclosing descriptor
and topology, and its descriptor sequence equals that descriptor. It satisfies
`issuedEpoch < expiresEpoch <= issuedEpoch + 4` and
`issuedExternalUnixMillis < restoreSupportExpiresUnixMillis`.

The three embedded byte strings decode canonically as the exact backup manifest,
clean-restore evidence, and current retention transition. Their complete hashes,
cross-references, keys, signatures, floors, candidate commitment, encryption-
profile hash, and support expiry must agree with the index. The transition is the
latest REGISTER or EXTEND, never RETIRE. Clean-evidence completion equals
`restoreDrillCompletedUnixMillis`; `restoreDrillAgeBand` is the universal band
containing `issuedExternalUnixMillis - restoreDrillCompletedUnixMillis`. Zero,
underflow, wrong/older band, expired support, missing bytes, or any mismatch clears
body RPO/RTO/restore qualification and mutation readiness for a profile claiming
it, without changing the separately witnessed profile-2 control-RPO0 fact.

Fetches use the already selected privacy path, a release cache, or an explicitly
separate evidence workflow; failure never causes direct DNS/network fallback.
Relays and mirrors retain every bundle used by a retained descriptor for the same
1,460-epoch/one-year window as topology evidence. Runtime and release tests cover
valid selected-path/cache retrieval, every embedded/hash/signature/reference/age/
expiry mutation, missing archive dependencies, privacy-path failure, 30/90/365-day
historical retrieval, and proof that an unverifiable nonzero recovery claim clears
qualification/readiness before new writes are selected.

External compaction uses only canonical `BlindControlStateSnapshotV1` plus
witness-signed `BlindExternalControlCheckpointV1`. Entry-kind codecs/order,
snapshot/checkpoint hashes, signature/predecessor chains, base-floor equality,
manifest anchoring, and streaming bounds are exactly the master/store registry.
Every 30/90/365-day supported backup registers its checkpoint/base-floor/snapshot/
WAL hashes and support expiry through canonical `BlindBackupChunkManifestV1`,
`BlindBackupManifestV1`, `BlindCleanRestoreEvidenceV1`, and a journaled
`BlindBackupRetentionTransitionV1`. Exact chunk coverage/order/hashes, backup/
evidence signatures and commitments, transition REGISTER/EXTEND/RETIRE CAS chain,
replacement rule, and key separation are those in the master/store registry.
Pruning keeps the complete base floor, latest two checkpoints, and every
non-retired backup anchor, and occurs only after a registered clean restore, no
older references, witnessed RETIRE transitions, and the seven-day safety interval
on the external quorum clock. Local files/config never authorize pruning.
Restore verifies the pinned checkpoint/snapshot then every later contiguous floor;
a missing/forked/pruned dependency is `RECOVERY_GAP_READ_ONLY`.

Profile-2 backup expiry/pruning uses the authenticated monotonic external
lease-clock floor. Rollback or a forward jump beyond the frozen five-minute
envelope enters `JOURNAL_CLOCK_UNSAFE`. It immediately rejects writer-lease
acquire, renew, and revoke; conditional journal/floor append; mutation admission;
and signed mutation/charged-result release. It clears profile-2 mutation readiness,
lets an existing writer stop at its already cached conservative monotonic deadline,
never guesses or extends a lease, and pauses backup retirement/pruning until a
quorum `CLOCK_CONFIRM` backed by at least two authenticated time sources. Store
genesis creates floor/snapshot/checkpoint 1 and
persists nonzero checkpoint revision/hash before listeners. Checkpoint age over 24
hours or refresh failure clears mutation readiness but preserves witnessed
uncharged reads. Genesis/jump/rollback/partition/expiry-boundary crashes are
mandatory vectors.

READY keeps checkpoint age at most 24 hours and bounds hidden pending control work
to 4,096 transitions/64 MiB; crossing either returns `BUSY` before another spend.
Journal storage growth, checkpoint/compaction time, floor batch depth/latency,
quorum outage, backpressure, uncharged-read continuity, and failover RTO are release
benchmarks.

The floor rule covers every spend-bearing control transition, not just final
results: reservation, staging-quota acquisition, attempt-credit decrement,
terminal invalid-body/expiry, idempotency-state change, and immutable control
mutation. A transition cannot authorize the next resource action or release its
lock/outcome before its external floor and local witnessed marker. In particular,
the daemon accepts no body byte until reservation and first-credit floors are both
durable; loss of the journal fails new admitted work closed.

Recovery queries the pinned journal before exposing local state. If the local WAL
has a contiguous, fully hashable pending-floor tail beyond the journal, it submits
the exact sequence/hash pairs idempotently and exposes them only after writing
covering `EXTERNALLY_WITNESSED` markers. A journal floor ahead of reproducible
local WAL/body state, a same-sequence hash fork, missing referenced bytes, unknown
witness binding, or refusal of that exact tail enters terminal
`RECOVERY_GAP_READ_ONLY`. Valid pending entries are never silently truncated,
renumbered, or re-encoded.
Losing `K_partition` or store MAC key makes that store unrecoverable
and requires a new store/relay identity. Crash tests kill every migration/restore
step, corrupt each artifact, simulate each lost key, restore to a clean machine,
and partition a still-running old host during the fence drill, then compare visible bytes, receipts, spends, leases, bucket ownership, and
accounting. Measured acknowledged-write RPO and READY RTO must fit the signed
coarse `DurabilityProfileV1`; 30/90/365-day retained backups are rehearsed. Missing
control state forbids same-identity startup. Any actual acknowledged body/block
loss enters terminal `RECOVERY_GAP_READ_ONLY`; repair occurs on other identities,
and this identity never becomes writable again in v1. Suspension tests cover every
precheck/fsync/external-floor/sign/send boundary.

---

## 10. Descriptor, identity, and parameter lifecycle

### 10.1 Descriptor

`BlindServiceDescriptorV1` is canonical binary, at most 16 KiB, and signed under
domain `hiverelay.blind.descriptor.v1`. It contains:

```text
DurabilityProfileV1 {
  profileId:        u8 // 1 LOCAL_FSYNC_IDENTITY_RESET_V1,
                       // 2 CONTROL_RPO0_3_NODE_V1
  storeFormatMajor: u16
  storeFormatMinor: u16
  storeFormatHash:  32 bytes
  externalJournalId:32 bytes // zero for profile 1; random nonzero for 2
  externalWitnessPublicKey:32 bytes // zero for 1; Ed25519 for 2
  externalJournalReplicationClass:u8 // 0 for 1; 1 three-node quorum for 2
  externalJournalFailureGroupId:32 bytes // zero for 1; stable nonzero for 2
  externalCheckpointAgeBand:u8
  externalJournalTopologyUrl:optional canonical HTTPS URL bytes[1..512] // absent for 1
  externalJournalTopologyHash:32 bytes // zero for 1
  restoreEvidenceUrl:optional canonical HTTPS URL bytes[1..512] // absent for 1; evidence mirror
  restoreEvidenceHash:32 bytes // zero for 1; current bundle hash for 2
  acknowledgedRpoBand:u8 // 0 undeclared, 1 <=15m, 2 <=1h, 3 <=6h
  targetRtoBand:    u8 // 0 undeclared, 1 <=1h, 2 <=4h, 3 <=24h
  redundancyClass: u8 // 0 single, 1 local redundant, 2 verified off-host backup, 3 warm standby
  restoreDrillAgeBand:u8
}

DurabilityContinuityBindingV1 {
  version:          u8 = 1
  profileId:        u8
  externalJournalId:32 bytes
  externalWitnessPublicKey:32 bytes
  externalJournalReplicationClass:u8
  externalJournalFailureGroupId:32 bytes
}

BlindServiceDescriptorV1 {
  version:          u8 = 1
  relayPublicKey:   32 bytes
  storeId:          32 random nonzero bytes
  descriptorSequence:u64
  previousDescriptorHash:optional 32 bytes
  identitySequence: u64
  previousRelayKey: optional 32 bytes
  identityTransition:optional RelayIdentityTransitionV1
  build:            BuildProfileV1
  protocols:        sorted array[1..16] of ProtocolProfileV1
  endpoints:        sorted array[1..16] of TransportEndpointV1
  cellSizeClassBits:u8
  leaseClassBits:   u8
  maxBatchCount:    u16 // <= 64
  maxResponseBytes: u32 // <= 4 MiB
  maxSponsoredCoreLength:u64
  enabledOperationBits:u32 // operation ordinals; bits 22..31 zero
  admissionProfiles:sorted array[1..8] of AdmissionProfileV1
  durability:       DurabilityProfileV1
  durabilityContinuityHash:32 bytes
  durabilityProfileHash:32 bytes
  storeLifecycleState:u8 // 1 ACTIVE, 2 DRAINING, 3 RETIRED
  drainStartedEpoch:optional u32
  capacityBand:     u8
  issuedEpoch:      u32
  expiresEpoch:     u32 // issued < expiry <= issued + 4
  descriptorNonce:  32 bytes
  signature:        64 bytes
}
```

The two durability hashes have different change boundaries:

```text
durabilityProfileHash = BLAKE2b-256(
  "hiverelay.blind.durability-profile-hash.v1" ||
  len64(canonicalDurabilityProfileV1) || canonicalDurabilityProfileV1
)
durabilityContinuityHash = BLAKE2b-256(
  "hiverelay.blind.durability-continuity-hash.v1" ||
  len64(canonical(DurabilityContinuityBindingV1)) ||
  canonical(DurabilityContinuityBindingV1)
)
```

For one `(relayPublicKey,storeId)`, the continuity hash and all of its fields are
immutable from genesis. Profile 1 binds the exact zero external tuple; profile 2
binds an exact nonzero journal ID, witness key, replication class, and failure-
group ID. Changing tier or any continuity field requires a fresh random store ID
and unrelated relay key. Format minor/hash, checkpoint and restore age, topology
and restore-evidence URL/hash, body RPO/RTO, and redundancy are dynamic profile
evidence: they may change only through a newly linked descriptor and matching linked manifest;
profile 2 obtains the covering external floor before publication. Old results keep
their exact historical descriptor/profile/topology bytes and hash. Genesis pins
the continuity hash; every later manifest and WAL/checkpoint header repeats it.

Profile 1 is local fsync with identity reset after control-store loss, has every
external field zero/absent—including absent topology/restore-evidence URLs and
zero hashes—and keeps `acknowledgedRpoBand`, `targetRtoBand`, and
`restoreDrillAgeBand` zero because v1 makes no same-identity recovery claim.
Profile 2 is the external zero-RPO control quorum required for witnessed release
and same-identity restore/failover. `acknowledgedRpoBand` in either profile describes
body/block backup only. Profile 2 needs a current nonzero floor/checkpoint, age at
most band 4, fresh topology, current verifiable restore-evidence URL/hash for every
nonzero body-recovery claim, and verified three-node replication class 1 to expose
mutation readiness. Universal age IDs are exactly 0 undeclared, 1 <=15m, 2 <=1h,
3 <=6h, 4 <=24h, 5 <=7d, 6 <=30d, and 7 >30d. Unknown values fail.
Protocol/transport profile hashes reproduce the master spec's canonical artifact
hashes; each endpoint carries its exact `transportProfileHash` and disables on
artifact/vector/dependency mismatch.

`ProtocolProfileV1` contains protocol ID, major, minor, feature bits, and the exact
protocol-specific schema/vector/dependency `profileHash` (CORE uses it to pin the
upstream blind-peer wire).
`TransportEndpointV1` contains endpoint ID, transport ID, generic role/profile
bits, canonical URL, optional endpoint key, envelope/wire classes, maximum streams, and
optional signed auxiliary URL/hash. `AdmissionProfileV1` contains the admission
profile and scheme IDs, conformance class, role bits, optional evidence-mirror URL,
and parameter hash. Exact field order and caps live in the ABI registry.

Validity is at most four six-hour epochs. Canonical endpoint URLs have no query,
fragment, userinfo, or application label. An onion endpoint contains one v3 onion
host and no clearnet alternate. Auxiliary key/route documents are signed, hashed,
bounded, validity-overlapping, and cannot add a role absent from the descriptor.
`buildArtifactUrl`, `buildManifestUrl`, `releaseEvidenceBundleUrl`, and
`runtimeBoundaryEvidenceUrl` are mandatory deterministic
content-addressed activation inputs, while optional admission/auxiliary URLs are
mirrors. A bundled exact copy satisfies retrieval. A client fetches any URL only
through its already selected privacy transport or an explicitly separate evidence
workflow; inability in Tor/OHTTP mode disables the role and never triggers DNS,
direct fetch, or downgrade. Admission parameters remain available through
`DESCRIBE.ADMISSION_PARAMETERS` on the selected edge path.

The universal discovery topic is
`BLAKE2b-256("hiverelay.blind.service.v1")`. DHT announcements are signed bounded
pointers to the same descriptor hash, not full descriptors. Bootstrap directories,
bundled keys, peers, and user-entered endpoints are non-exclusive discovery hints.

### 10.2 Descriptor and identity lifecycle

1. `INIT`: generate/import the dedicated blind identity with restrictive
   permissions; descriptor and identity sequences are zero and no unsigned blind
   advertisement exists.
2. `ACTIVE`: descriptors, health, receipts, and proofs use this key. Every routine
   same-key refresh advances `descriptorSequence` exactly once, links the complete
   prior descriptor hash, retains `identitySequence`, and omits previous key/
   transition. Routine refreshes issue at most once per six-hour epoch and overlap
   their predecessor by at least one epoch. Backups are operator-controlled and
   never mounted into application containers.
3. `ROTATING`: the old and new keys sign the same bounded
   `RelayIdentityTransitionV1`, binding adjacent keys, `oldSequence`, exactly
   `oldSequence + 1`, validity, reason, and nonce. The new descriptor advances both
   sequences as specified by the master, embeds that transition, and links the
   complete signed previous descriptor hash. Both descriptors overlap for at most
   four epochs.
4. `RETIRED`: the old private key is removed from the daemon; clients retain the
   signed transition and reject rollback. Emergency uncompensated loss creates a
   new relay identity and does not pretend continuity.

A planned rotation first acquires the store-global lifecycle fence and records one
fixed `drainStartedEpoch`. It stops new reservations and drains or deterministically
aborts every admitted allocation, append, mirror, open, renewal, watch, forwarding
circuit, and charged read/proof before any can stage or publish. It then freezes
and privately signs the complete canonical DRAINING descriptor, computes its signed
hash, and commits the exact bytes/hash, lifecycle transition, and reduced bitmap to
the local WAL and manifest. Profile 1 uses that linked local commit; profile 2 must
also obtain a covering external floor carrying the exact descriptor sequence/hash.
Only after the applicable floor and local marker/manifest fsync may the already-
signed bytes be published. Recovery reproduces those persisted bytes exactly,
resumes the highest lifecycle fence, never republishes ACTIVE, and never releases a
pre-fence result under the DRAINING binding.

DRAINING enables exactly operation ordinals 0, 1, 2, 4, 6, 7, 8, 11, 13, and 16:
DESCRIBE.GET/CHALLENGE/ADMISSION_PARAMETERS; uncharged side-effect-free CELL.GET/
PROVE/BATCH_GET, INBOX.READ, CORE.PROVE; and valid owner CELL.DROP/INBOX.CLOSE.
Therefore both the descriptor `enabledOperationBits` and the maximum challenge
ready bitmap are exactly `0x000129d7` (bits 22..31 zero), further intersected only
with the challenged request for health output. A PROVE/BATCH_GET/READ/CORE.PROVE
carrying admission, INBOX.WATCH, every new/renew/create/append/mirror/open/forward
operation, and every other mutation is rejected before token parsing or spend.
After DRAINING publication, only owner DROP/CLOSE may commit new control mutation
or carry that descriptor binding. Profile-2 journal outage preserves readiness for
permitted uncharged reads but clears DROP/CLOSE readiness until the witness path is
healthy. Clients remove the relay from new-write selection and repair elsewhere.

The store cannot enter RETIRED while any lease, frame, core sponsorship,
reservation, pending/witness transition, retry pin, or GC grace remains, which may
take the full 90-day horizon. Drain/retire commits are locally fsynced for profile 1
and quorum-witnessed for profile 2. Only after publishing the exact RETIRED
descriptor with zero readiness through the same floor procedure may the operator
release the writer lock/profile-2 lease and dual-sign a transition to a fresh key,
random store ID, and (for profile 2) fresh journal binding. ACTIVE omits drain epoch;
DRAINING and RETIRED retain the same original nonfuture epoch; RETIRED is terminal.
Profile-1 gap/loss instead starts an unrelated key/store at sequence zero with no
continuity transition.

Descriptor sequence zero alone omits `previousDescriptorHash`; every later
descriptor links sequence minus one. Previous relay key/transition appear only on
the descriptor that actually rotates the identity key. Same-sequence different
hash is equivocation; lower sequence is rollback. `DESCRIBE.GET` fetches named
history only over the selected path. The daemon retains every linked descriptor
from the last 1,460 epochs, capped at 4,096 links (routine issuance is at most one
per epoch); clients follow the same bounded cycle-free chain and test 30/90/365-day
offline recovery. Missing/deeper history is unwitnessed, not trusted. Expired
history is evidence only. Strict profiles additionally require a release-bundled
or two-witness descriptor/config/catalog hash and reject targeted auxiliary-set
equivocation.

### 10.3 Admission parameters

Admission adapters implement only:

```text
AdmissionV1 {
  profileId:       u16
  schemeId:        u16
  parameterHash:   32 bytes
  token:           bounded bytes[1..4096]
}

AdmissionParametersV1 {
  version:          u8 = 1
  relayPublicKey:   32 bytes
  profileId:        u16
  schemeId:         u16
  conformanceClass: u8
  roleBits:         u16
  verifierKey:      bounded bytes[0..4096]
  resourceCosts:    sorted array[1..512] of {
                      familyId: u8, operationId: u8, resourceClass: u8,
                      leaseClass: u8, costUnits: u64
                    }
  tokenMaxBytes:    u16 // <= 4096
  issuanceUrl:      optional canonical URL bytes[1..512]
  issuerRelayKey:   optional 32 bytes
  validFromEpoch:   u32
  expiresEpoch:     u32
  nonce:            32 bytes
  signature:        64 bytes
}

prepare(admission, familyId, operationId, resourceClass, leaseClass,
        requestCommitment, signal)
  -> { spendTag, requestCommitment, costClass, walCommitRecord }
```

`prepare` is side-effect-free. The transaction coordinator is the sole redeemer.
The request's `(profileId, schemeId, parameterHash)` MUST exactly select one
current descriptor profile and fetched signed parameter object. Cost lookup uses
the pair `(familyId, operationId)` because operation IDs collide between families;
no implementation may price by operation ID or display name alone.

Rows sort by raw `(familyId,operationId,resourceClass,leaseClass)`, reject duplicate
tuples, and cover exactly every tuple each enabled registry rule can produce with
no unreachable row. Generator expansion proves unique coverage and the 512-row/
16-KiB cap; CORE mirror rule 9 emits at most resource classes 1..45 for a `u64`
length. Missing, mismatched, or cheaper-neighbor lookup returns `SPEND_INVALID`
before expensive work.

The parameter signature domain is
`hiverelay.blind.admission-parameters.v1`, and:

```text
parameterHash = BLAKE2b-256(
  "hiverelay.blind.admission-parameters-hash.v1" ||
  canonicalCompleteSignedParameters
)
```

Parameter state is `PENDING -> ISSUING -> REDEEM_ONLY -> EXPIRED`, with at least
one descriptor overlap epoch between successive sets. Issuance stops before
redemption, and redemption remains accepted through the maximum token lifetime.
The same parameter ID with different bytes is forbidden. Emergency revocation is
signed, descriptor-bound, and reported as a privacy/availability incident; it
never deletes spent records or makes a previously committed write disappear.

Open conformance requires at least one app-free proof-of-work or anonymously
obtainable byte-duration credit. Private bearer admission may exist but cannot
support the permissionless plug-and-play claim. Tokens and cost classes contain no
app/namespace/client identity and are bound to the exact request commitment.

---

## 11. Client-only responsibilities

The blind client, not the daemon, MUST own:

- application encoding, author/member keys, signatures, validation, ordering,
  merge, edits, deletes, moderation, and semantic indexes;
- randomized encryption, padding, chunking, read capabilities, one-time create
  keys, renew/drop keys, and encrypted capability chains;
- separately randomized per-relay replicas for the unlinkable cells profile;
- inbox plaintext format, decryption, signature checking, deduplication, fork
  retention, and polling/watch resume policy;
- Hypercore writer and block-encryption keys plus signed-head verification;
- descriptor verification, privacy profile selection, role/operator diversity,
  explicit downgrade decisions, receipt/proof verification, witnessed floors,
  availability quorum, challenge cadence, and repair;
- durable offline outbox/idempotency state and crash-safe advancement of local
  capability chains; and
- truthful user presentation of the actual path and claim ceiling.

The daemon sees only generic operation IDs, opaque locators/core keys, fixed
classes, coarse leases, adjacent transport role, timing, and volume. This is the
declared residual leakage, not hidden semantics.

---

## 12. Observability and resource safety

Allowed log/metric dimensions are fixed: component, generic operation, protocol
version/hash, transport profile, size/frame/lease/cost class, coarse capacity band,
result code, latency bucket, queue band, and lifecycle state.

Forbidden fields include payloads, locators, topics/inbox IDs, core keys, public
management keys, request/admission tokens, route IDs, IPs, origins, headers,
application strings, exact disk paths, or user-selected labels. Error objects are
mapped to stable codes before logging; stack traces are development-only and
scanned before release. Request bodies are excluded from tracing and crash dumps.

Every queue has a descriptor/configured item and byte cap. Slow producers are
paused; slow consumers are disconnected with a resumable error. Admission happens
before expensive allocation. Per-connection, per-role, global, and disk
high-water caps fail closed with `BUSY` rather than evicting live leased data.

After cheap shape/signature/admission checks, scheduling uses bounded weighted-fair
queues per generic role/profile and opaque resource bucket. At least 5% of WAL/
coordinator/disk headroom is reserved for clock/fence/recovery, valid renew/drop/
close, descriptor/config/admission refresh, and bounded health. Shed order is new
watch/forward/bulk proof/batch, then new allocation/append/mirror; lifecycle-
critical authenticated control is last. Health polling has a separate cap and
coarse jittered BUSY response.

Shared OHTTP/Tor/split paths never use adjacent IP/connection as end-user fairness.
Their nontrivial read/proof egress requires an anonymous one-use fair credit before
large work; per-IP fallback is direct-profile-only and disclosed. Saturation/noisy-
neighbor gates prove one ingress/topic cannot starve honest unlinkable clients and
that existing leases/control/config remain live at every high-water mark.

Minimum scale gates on the reference 2-vCPU/4-GiB SSD relay are:

- one million indexed 16-KiB cells restart to ready within 30 seconds without
  scanning blobs;
- steady RSS below 1.5 GiB excluding page cache;
- local 16-KiB GET p99 below 50 ms at 100 clients;
- profile-1 acknowledged 16-KiB PUT p99 below 150 ms through final local fsync and
  result release, with forced-crash prefix replay and no external-witness label;
- profile-2 acknowledged 16-KiB PUT p99 below 250 ms through local fsync, the
  independently failed external quorum, and final witnessed release—not a mock,
  same-host journal, or local-commit result;
- no unbounded watch, forward, core, admission, GC, or repair queue; and
- a seven-day expiry/rebalance/restart soak with zero unrecoverable WAL/index
  drift and accounting error below 1%.

Every result is reported separately by durability profile. Both reports pin CPU,
RAM, SSD/filesystem/mount, OS, runtime, WAL/checkpoint/fsync/group-commit policy,
cache state, seed, concurrency, and raw samples. Profile 1 additionally pins the
exclusive lock/local fsync sequence and tests exact-intact-store restart plus
forced loss/clone/relocation as new-identity recovery; it publishes no same-
identity restore/failover RTO. Profile 2 additionally pins journal/lease software,
voters/failure domains, per-link RTT/loss/jitter, consensus/fsync policy, floor
transitions and actual quorum round trips, batch depth, checkpoint/compaction age,
and pending bytes. Quorum outage and slow followers prove bounded BUSY, zero new
admitted body bytes, mutation-readiness clearing, witnessed uncharged-read
continuity, no fork, and measured throughput/p99/p999/storage growth/failover RTO.

Backup gates report plaintext-to-ciphertext throughput, peak memory, ciphertext
expansion, decrypt/authenticate/scrub throughput, clean-room READY time, and every
path/key/nonce/AAD/ciphertext corruption case. Profile 2 additionally measures
30/90/365-day exact-hash topology and restore-evidence bundle retrieval, verifies
every embedded manifest/evidence/transition cross-reference and age band, and
rejects pruned predecessors, expired support, or substitution by newer valid
evidence. Combining profile percentiles or labelling a profile-1/local commit as
externally witnessed fails the report.

Private-transport benchmarks use identical payload seeds/endpoints and report
network latency separately. No profile opens a connection or circuit per cell.

---

## 13. Cross-application conformance fixtures

Two unrelated applications are mandatory fixtures; neither gets relay code or
configuration.

### 13.1 Fixture A — signed field notebook

This fixture creates small signed text observations, multi-device forks, edits,
encrypted checkpoints, and an open announcement inbox. It uses all cell classes up
to 64 KiB, inbox read/watch, multiple relay replicas, proofs, renew/drop, offline
retry, and client-side merge.

Sentinels include unique app name, author names, record-type strings, logical IDs,
and graph-like links. They appear only inside ciphertext and client state.

### 13.2 Fixture B — binary tile stream

This fixture publishes chunked binary map/sensor tiles, a signed chunk manifest,
a signed-append inbox, and an encrypted transport Hypercore. It uses 256-KiB and
1-MiB cells, Blind Core mirror/prove, forward routes, expiry, replacement, and
range reconstruction in the client.

Its distinct app, producer, media/type, coordinate, and index sentinels likewise
appear only inside ciphertext and client state.

### 13.3 Required combined evidence

Both fixtures MUST:

1. use the same descriptor, spec/ABI/vector hashes, endpoints, media type, operation IDs,
   classes, admission mechanism, route pool, edge+daemon component digests,
   launch topology, private-IPC tuple, and generic configuration;
2. run concurrently and after either fixture is introduced post-startup, with no
   restart, plugin, namespace, domain allowlist, key, or metric change;
3. pass Node and Bare vectors; cell/inbox browser vectors also pass supported
   Chromium, Firefox, and Safari/iOS;
4. produce decoded network captures containing no app/author/type/semantic field;
5. produce recursive scans of WAL, checkpoints, partitions, blob filenames, core
   store, logs, metrics, cursor/admission state, and crash diagnostics with zero
   fixture sentinel matches;
6. survive response loss, duplicate/concurrent spend, torn WAL, restart, partition
   rebalance, exhausted watch-waiter cap, killed forward hop, and role shutdown; and
7. demonstrate that adding a third opaque byte producer needs client code only.

A classifier report records residual size, lease, timing, volume, and access
leakage. Absence of sentinel strings alone is not an anonymity proof.

---

## 14. Delivery phases and hard gates

| Phase | Deliverable | Gate to advance |
| --- | --- | --- |
| 0 | Freeze the canonical spec plus registry, IDs, domains, limits, errors, vectors, and source/hash rules | Independent registry review; same vectors pass Node/Bare; deliberate schema drift fails startup |
| 1 | Disjoint blind-edge and blind-daemon shells, PRIVATE_IPC, identities/config/lifecycle, `DESCRIBE` | Signed launch topology and process capability tests prove the sole bounded initializer exited exactly, edge-only public listeners, daemon-only store/signing/two unequal private sockets, unequal users/mounts, exact unary/stream/readiness frames, endpoint ACK before bind and expiry-close, and no app/legacy access; abort/close leak tests pass |
| 2 | WAL coordinator, virtual buckets, cells, open admission, receipts/proofs | Full crash matrix, double-spend concurrency, clock unsafe, tombstone horizon, million-cell restart/latency gates |
| 3 | Inbox create policies, fixed frames, snapshot read, bounded long-poll watch, expiry | Omission/reorder/flood, cursor, retention, waiter-cap/abort, restart, and 90-day-class cold-start simulations pass |
| 4 | Blind Core isolated adapter | Upstream wire interop, dependency boundary, encrypted-block proof, sponsorship/restart, disk/accounting gates pass |
| 5 | Direct HTTP/Protomux plus Protomux split forwarder | Identical canonical transcript; entry/exit/storage capture proves stated knowledge split; no open-proxy vector passes |
| 6 | RFC 9458 OHTTP ingress/gateway | RFC 9292 bHTTP/class vectors, key rotation, fixed relay-resource mapping, shared key/route pool, two-fixture storage-wire app-opacity capture, performance gate pass |
| 7 | MASQUE adapter | Two-hop route substitution/leak, churn, backpressure, no direct retry, and throughput/latency gates pass |
| 8 | Full Tor onion adapters | Bootstrap/update/error/retry packet capture shows zero clearnet DNS/TCP/UDP and zero downgrade; native/browser claims remain distinct; Tor Browser storage header captures gate G2-W; controlled/public performance recorded |
| 9 | Rebalance, soak, deterministic two-component packaging, evidence retrieval and upgrade proof | Seven-day soak; two fixtures plus late third producer; descriptor→manifest/evidence retrieval; topology/support horizon; initializer completion and six-report recursive proof; fenced blue/green and format-compatible kill/rollback vectors pass |
| 10 | Final replacement-product cutover | Mode is exactly `BLIND_APPLICATION_SUBSTRATE_V1`; fetched signed topology/isolation/support evidence binds both components and the completed bounded initializer with derived zero forbidden bits, both unequal IPC paths and readiness-before-bind pass, and every legacy-route probe passes. Any compatibility image comes from full separate source/artifact/manifest/boundary, has pinned genesis/fresh no-store head/non-extendable chain, and enforces write/read deadlines under monotonic time; clean default retains exactly edge+daemon after initializer exit |

No later transport blocks release of an earlier truthful profile. Conversely, a
compiled adapter is not advertised until its own gate passes. The release verifier
derives claims from evidence and descriptor profile, never feature presence alone.

---

## 15. HiveRelay repository file map

The reviewed HiveRelay repository currently has workspaces for Core, Services,
Client, and Verifier. The strict substrate requires new workspaces because placing
it under `packages/services/builtin` would expose the unrestricted in-process
service context and collapse the membrane.

### 15.1 Add

```text
docs/protocol/BLIND-APP-AGNOSTIC-HIVERELAY-MASTER-SPEC.md
docs/protocol/BLIND-SUBSTRATE-IMPLEMENTATION-SPEC.md

packages/blind-protocol/
  hiverelay-blind-abi-v1.cenc sole canonical ABI/hash input
  registry.js                 generated schema/ID/domain/limit bindings
  codec.js                    bounded canonical encoding
  commitments.js              domain-separated request/signature preimages
  errors.js                   stable errors and HTTP mapping
  descriptor.js               descriptor, pointer, route, health codecs
  vector-manifest-v1.cenc     canonical vector-set/hash input
  vectors/                    byte-exact positive/negative fixture bytes

packages/blind-ipc/
  hiverelay-blind-private-ipc-v1.cenc sole PRIVATE_IPC schema/hash input
  registry.js                 generated local frame/transport/class/error bindings
  codec.js                    u32 framing plus bounded unary/stream codecs
  vectors/                    byte-exact split/coalesce/truncate/sequence fixtures

packages/blind-client/
  cells.js
  inbox.js
  core.js
  admission.js
  discovery.js
  selection.js
  receipts.js
  repair.js
  runtime/{browser,bare,node,pear}.js

packages/blind-edge/
  cli.js                      sole public entrypoint; no legacy mode flag
  bootstrap-config.js         TLS/listener/route/IPC handles only
  lifecycle.js                public drain and IPC cancellation
  http.js                     five fixed POST routes and descriptor GET
  protomux.js                 canonical public stream framing
  onion.js                    Tor local-socket listener
  metadata.js                 ambient header/source/trace stripping
  ipc.js                      PRIVATE_IPC client; no inner dispatch parser
  observability/{logger,metrics}.js

packages/blind-daemon/
  cli.js                      private engine entrypoint only
  daemon.js
  bootstrap-config.js
  lifecycle.js
  ipc.js                      two authenticated private Unix servers
  identity.js
  identity-history.js
  build-profile.js
  descriptor.js
  health.js
  transaction/{coordinator,wal,checkpoint,recovery}.js
  storage/{partition-key,buckets,partitions,rebalance,staging,gc}.js
  cells/{engine,receipt,proof}.js
  inbox/{engine,cursor,watch}.js
  core/{adapter,sidecar,accounting}.js
  admission/{interface,pow,privacypass,cashu}.js
  forward/{engine,routes}.js
  observability/{logger,metrics}.js
  release/{product-isolation-evidence,artifact-inventory,import-graph}.js

packages/private-transport/
  interface.js
  profiles.js
  policy.js
  outer-envelope.js
  stream-chunks.js
  direct/{client-http,client-protomux,edge-http,edge-protomux}.js
  ohttp/{bhttp,client,ingress,gateway,key-config}.js
  protomux-split/{client,entry,exit}.js
  masque/{client,entry,exit}.js
  tor/{client,onion-service}.js

packaging/hiverelay-blind-edge.service
packaging/hiverelay-blind-daemon.service
packaging/blind-launch-topology.cenc

packages/legacy-compat/ // complete frozen historical runtime; separate source/artifact
  package.json
  bin.js
  core/
  services/

packages/legacy-compat-release/ // release tooling only; never blind dependency
  build-manifest.js
  sunset-genesis.js
  sunset-head.js
  sunset-evidence.js
  authority-transition.js
  runtime-boundary-evidence.js

test/fixtures/blind-protocol/
test/fixtures/blind-apps/field-notebook/
test/fixtures/blind-apps/binary-tile-stream/
test/unit/blind-*.test.js
test/integration/blind-substrate-*.test.js
test/integration/blind-transport-*.test.js

scripts/verify-blind-source-consistency.mjs
scripts/launch-blind-topology.mjs
scripts/generate-blind-build-profile.mjs
scripts/verify-blind-membrane.mjs
scripts/verify-blind-release.mjs
scripts/verify-blind-product-isolation.mjs
scripts/probe-forbidden-legacy-routes.mjs
scripts/scan-blind-state.mjs
scripts/bench-blind-substrate.mjs
scripts/test-blind-crash-matrix.mjs
scripts/test-blind-rebalance.mjs
scripts/test-tor-no-clearnet-leak.mjs
```

### 15.2 Modify

| Existing file/area | Required change |
| --- | --- |
| Root `package.json` and lockfile | Add blind-protocol, blind-ipc, blind-client, blind-edge, blind-daemon, transport, and separately packaged legacy-compat workspaces plus strict test/verify/bench/release scripts; pin upstream blind-peer generations. Root `npm start` invokes only the signed-topology launcher; component `npm start` commands enter only their own new edge/daemon binaries, never old RelayNode |
| `packages/blind-edge/{cli,bootstrap-config,lifecycle,http,protomux,onion,metadata,ipc}.js` | New public product component; own only fixed listeners/TLS/CORS/metadata stripping/private-IPC client and never import old Core/Services |
| `packages/blind-daemon/{cli,bootstrap-config,lifecycle,ipc}.js` | New private product component; own canonical dispatch/store/signing and never open a public listener/import old Core/Services |
| `packages/core/config/default.js`, `config/loader.js` | Remain compatibility-source inputs only; they are not modified into or imported by either blind component |
| `packages/core/core/relay-node/index.js`, `api.js`, `api-route-mounts.js` | Remain the frozen legacy-compat runtime entrypoint/surface. They MUST NOT become a blind edge, contain a product-mode branch, or enter the blind artifact/import graph |
| `packages/core/core/capability-doc.js`, `network-discovery.js`, `relay-record.js` | Legacy compatibility only. New descriptor/discovery implementations live wholly under blind-daemon/edge and share only public WIRE bytes |
| `packages/core/core/services/{registry,service-catalog,protocol}.js` | Freeze/copy into the complete legacy-compat source/artifact only; neither blind component is an RPC service |
| `packages/core/transports/tor/index.js`, `core/protocol/{forward-relay,relay-circuit}.js` | Treat as legacy/reference source only. Port reviewed algorithms into new blind-edge/private-transport files with independent import closure; do not share these runtime files across products |
| `packages/client/index.js` | Publish the blind client from its new workspace as the application-serving surface; legacy APIs remain only in a separately versioned compatibility package and are never aliases |
| `packages/verifier` | Verify spec/public/private-IPC/store/evidence registries/vectors, two-component artifact/manifest/topology/support/retrieval/isolation reports, descriptor/route/profile binding, compatibility build/genesis/head/time/boundary/sunset/authority chain, and no unsigned strict claim |
| `Dockerfile`, `docker-compose.yml`, `docker-entrypoint.sh`, service units | Produce one deterministic distribution with exactly two selectively built component images/binaries; default Compose/systemd runs the exact signed, networkless, capability-bounded daemon-image volume initializer to completion, then starts edge+daemon under signed topology. Migration compose may reference the separately built compatibility image/service but it is not a third component |
| Release, image-smoke, fleet, and package scripts | Produce exact mode/topology/support/isolation/retrieval evidence; build compatibility from its full frozen source with a distinct canonical manifest, runtime boundary, pinned genesis/fresh head/sunset chain, channel and enforced deadlines |

### 15.3 Do not extend for the strict path

- `packages/core/core/plugin-loader.js` or the unrestricted ServiceProvider
  context;
- `packages/services/builtin/outboxlog`, `shard-store`, `repairticket`, or any
  semantic service;
- app registry/catalog, author directory, identity, schema, AI, moderation, or
  index APIs; or
- existing JSON service RPC for cells, frames, core blocks, or forwarding.

Those components are absent from the final blind artifact. They may remain only in
a separately built compatibility artifact while its signed write/read sunset is
valid; no bridge is imported, mounted, or advertised as `hiverelay-blind/1`.

---

## 16. Definition of done

The component is complete only when all of the following are authoritative current
evidence, not plans:

1. The executable registry, vectors, descriptor, build profile/manifest, exact
   `productMode=1`, private-IPC tuple, signed launch topology/support horizon/
   isolation evidence, deterministic evidence retrieval, and every spec/ABI/
   vector/component/artifact hash agree; every drift/substitution fails closed.
2. A clean default distribution first completes exactly the signed bounded
   initializer with matching artifact/argv/UID/GID/capability/network/rootfs/
   no-new-privilege/PID/mount/target/time/exit evidence, then runs exactly the
   signed blind edge plus dedicated
   daemon components under unequal unprivileged users. Edge authenticates both
   unequal socket paths, obtains the current endpoint-bound ACK before bind, and
   closes by ACK expiry on refresh failure; edge alone owns public
   TLS/routes and daemon alone owns private IPC/store/signing, with no access to
   application stores/config/keys and no
   packaged/imported/listening/running legacy/plugin/semantic component. It
   advertises no strict role when isolation or signing is unavailable. Negative
   probes prove all retired routes absent.
3. Cells, inbox, core, admission, evidence, discovery, and authorized forwarding
   pass their complete state, crash, replay, resource, and lifecycle matrices.
4. Virtual-bucket rebalance proves single authority at every crash point and the
   seven-day multi-partition soak has no WAL/index/accounting drift.
5. Both unrelated fixtures and a late third opaque producer run against the same
   unchanged daemon/config/descriptor and recursive scans find no semantic data.
6. Every advertised transport passes its separate route, role-visibility,
   downgrade, leak, backpressure, and performance gates.
7. Browser, Node, Bare, and Pear-supported surfaces verify the same canonical
   vectors and results.
8. Public documentation states residual size/lease/timing/volume/access leakage,
   role-separation assumptions, and the absence of semantic, global-observer,
   read-interest, and active-public-reader secrecy claims unless separately proven.
9. Any still-published compatibility product has a distinct artifact, process,
   identity, listener, descriptor, store and release channel; its full frozen
   source and canonical build manifest reproduce; runtime-boundary comparisons are
   disjoint; pinned genesis/current head/sunset/authority chain and monotonic time
   floor validate; expired writes/reads are actually rejected; and it cannot join
   blind discovery or enter the blind artifact/import graph.
10. Both signed upgrade modes pass every fence/lease/socket/store crash point. No
    old ABI or rollback is served beyond its exact horizon, no old daemon remains a
    second writer, and in-place rollback occurs only with the named bidirectional
    format vectors.

Until then, the descriptor and product language identify each implemented subset
and its measured claim ceiling; they do not call the whole deployment blind or
anonymous.
