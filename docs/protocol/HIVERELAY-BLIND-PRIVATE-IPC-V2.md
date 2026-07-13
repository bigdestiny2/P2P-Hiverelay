# HiveRelay blind private IPC v2

Status: additive executable contract for staged HTTPS `CELL.PUT`; it is not a
runtime-release authorization.

This document freezes the private edge-to-daemon format needed to carry one
complete public outer envelope without letting a large upload bypass the daemon's
canonical dispatch, response-fit, admission, storage, or durability checks. The
authority metadata intentionally sets `runtimeReleaseReady:false` and
`authorizesRelease:false`. Runtime, TLS, storage, restart, retrieval, signed
descriptor, and multi-relay evidence remain separate gates.

## 1. Compatibility and authority boundary

Private IPC v1 remains byte-for-byte frozen. Its seven schema rows, registry,
aliases, vector manifest, vectors, authority JSON, codecs, and v1 hash domains do
not change. V1 continues to serve its existing unary/read paths, but v1 staged
`CELL.PUT` is forbidden. A sender never retries a rejected v2 open as v1.

The byte at offset 4, immediately after `totalLength:u32be`, is the record
version. A v1 verifier accepts only v1 authority/records. A v2 verifier accepts
only v2 authority/records. Unknown versions close the private connection. No
frame may be dual-interpreted and no fallback or downgrade exists.

The separate v2 authority is:

```text
packages/blind-ipc/hiverelay-blind-private-ipc-v2.cenc
packages/blind-ipc/vector-manifest-v2.cenc
packages/blind-ipc/vectors/v2/**
packages/blind-ipc/hiverelay-blind-private-ipc-authority-v2.json
```

The v2 registry uses magic `hiverelay-blind-private-ipc-v2`, format version 2,
retains the exact v1 rows with IDs 1 through 7, and adds:

8. `LocalTransportBindingV2`
9. `LocalStagedCellPutOpenV2`
10. `LocalStagedCellPutFrameV2`
11. `LocalReadyProbeV2`
12. `LocalReadyAckV2`

The registry imports public constants from the generated WIRE authority. In
particular, the `CELL.PUT` write bit is computed with
`operationBit(FAMILY.CELL, OPERATION.CELL.PUT)`; it is not copied as a private
numeric constant. `STORAGE` comes from the generated endpoint-role registry.

## 2. Exact records

All multi-byte integers are unsigned big-endian. `totalLength` is the exact byte
count after its four-byte prefix. The incremental declared-record readers return
`null` until their bounded header or discriminant is available. They reject an
impossible declaration, a contradictory body/context length, or a non-v2 version
before body allocation.

### 2.1 Transport binding

`LocalTransportBindingV2` is exactly 162 bytes and has no length prefix:

```text
offset  bytes  field
0       1      version = 2
1       1      authorityKind
2       32     edgeProcessNonce, nonzero
34      32     localChannelNonce, nonzero
66      32     transportProfileHash, nonzero
98      32     publicSessionBindingHash, nonzero
130     32     openBindingHash, nonzero
```

`edgeProcessNonce` is generated from the operating-system CSPRNG once after the
edge process starts, and again after any process fork. It is stable only until
that process exits, is never persisted or restored, and is never reused by a
later process. `localChannelNonce` is fresh operating-system CSPRNG output for
every open attempt, including retries, and is never reused. Production code has
no caller-supplied, raw, deterministic, or test nonce authority seam.

Authority kinds are closed:

1. `TLS_EXPORTER_BY_PEERCRED_EDGE`
2. `NOISE_TRANSCRIPT_BY_PEERCRED_EDGE`

The current HTTPS open accepts only kind 1. Kind 2 records the native-Noise
mapping for a later operation-specific open; it is not accepted by the HTTPS
staged-open codec.

### 2.2 Staged open

`LocalStagedCellPutOpenV2` is exactly 200 bytes: a 38-byte header including the
prefix followed by one exact 162-byte transport binding.

```text
offset  bytes  field
0       4      totalLength = 196
4       1      version = 2
5       1      requestKind = STAGED_CELL_PUT_OUTER_ENVELOPE_V1
6       1      resultKind = CELL_PUT_OUTER_RESULT_ENVELOPE_V1
7       1      authorityKind = TLS_EXPORTER_BY_PEERCRED_EDGE
8       1      transportId = HTTPS_DIRECT
9       2      transportSupportBit = DIRECT_HTTP
11      1      endpointId, 1..255
12      1      outerClass, syntactically 1..6; initial CELL.PUT policy 3..6
13      1      ipcChannelClass = LOCAL_64K
14      8      acceptedMonotonicMillis
22      8      openDeadlineMonotonicMillis
30      4      requestEnvelopeBytes = OUTER_CLASS[outerClass]
34      4      contextLength = 162
38      162    context = LocalTransportBindingV2
```

The open deadline is strictly after acceptance and no more than 15,000 ms later.
All public outer classes use the one local `LOCAL_64K` frame class and fragment
when necessary. This mapping avoids allocating an 8-MiB private frame while still
carrying the exact full public envelope.

The initial staged `CELL.PUT` runtime authorizes outer classes 3 through 6 only.
Classes 1 and 2 are rejected before open binding, write readiness, replay
consumption, ingress construction, or body work. V2 result sizing is the fixed
generated worst case: a 16,384-byte result body and 16,435-byte complete result
envelope. No caller- or runtime-supplied predicted-result input or authority
exists in V2.

### 2.3 Staged frames

`LocalStagedCellPutFrameV2` has a 20-byte header including its prefix and is at
most 65,535 bytes. Content is at most 65,515 bytes.

```text
offset  bytes  field
0       4      totalLength = 16 + bodyLength
4       1      version = 2
5       1      direction // 1 request, 2 result
6       1      frameKind // 1 CONTENT, 2 ABORT
7       8      sequence // first zero, exact +1 per direction
15      1      flags // FIN bit only
16      4      bodyLength
20      n      bytes[bodyLength]
```

`CONTENT` carries 1 through 65,515 bytes; zero bytes are legal only with FIN.
`ABORT` has zero flags and exactly one byte containing a registered generic v1
abort code. It has no diagnostic text or free-form payload.

Request frames start at sequence zero and end with FIN after exactly
`OUTER_CLASS[outerClass]` bytes. After successfully writing that FIN, the edge
must send no more request bytes and must write-half-close the authenticated local
IPC socket while keeping its response/read half open until a terminal result,
abort, or deadline. The daemon must observe peer EOF after FIN on that same
native-peer-credential-authenticated stream. Only after that daemon-observed EOF
may result frames start at their own sequence zero. A non-aborted result ends with
FIN after the same exact outer-class byte count. ABORT is terminal.

The pure frame verifier proves byte and FIN ordering only and never mints EOF
authority. Runtime EOF authority is a module-private brand created only by the
daemon's native stream observer; a caller boolean, callback, or structural record
cannot substitute.

FIN alone is not request-completion authority. EOF before FIN, request data after
FIN, or FIN without daemon-observed EOF before the deadline produces only a
generic local abort/close, no public error, and no commit. Result emission before
daemon-observed EOF is a runtime conformance failure. If the edge closes its
response half early, ordinary caller-cancellation semantics apply: a pre-publish
boundary cancellation discards staging, while a post-boundary cancellation
cannot interrupt the atomic commit and merely suppresses the result.

## 3. Public dispatch invariants

The edge sends the complete `BlindOuterEnvelopeV1`; it does not strip the outer
header or forward only dispatch content. Before any commit-capable action, the
daemon reassembles and canonically decodes that envelope and requires:

- the selected exact public outer class;
- `frameKind=REQUEST`, `family=CELL`, and `operation=CELL.PUT`;
- nonzero request ID, zero flags, zero stream ID, and zero sequence; and
- one canonical `PutCellV1` request body under the generated operation cap.

The result is one same-class public outer envelope containing the correlated
request ID and either `frameKind=RESPONSE` or `frameKind=ERROR`, exact
`CELL.PUT`, zero flags, zero stream ID, and zero sequence. Any other kind, family,
operation, class, correlation, flag, stream, or sequence is rejected.
`RESPONSE` carries exactly one canonical closed-schema `BlindReceiptV1` body;
`ERROR` carries exactly one canonical closed-schema `BlindErrorV1` body. A body
that fails its mapped codec, has trailing bytes, or does not re-encode byte for
byte is rejected as a private-IPC contract error before commit-capable work.
The verifier snapshots the complete outer envelope once before decoding and
returns a frozen frame record whose request ID and canonical body are owned
copies. Later mutation of caller-owned input cannot invalidate verified fields.

The staged exchange is not successful merely because its request bytes reached
the daemon. Success becomes committable only after the daemon has authenticated
the open, decoded the request, proved the correlated result fits, and completed
the operation-specific precommit barrier.

## 4. Transport binding and threat model

Peer credentials on the signed Unix-socket topology authenticate which edge
process made the transport-binding attestation. TLS exporter or Noise transcript
material binds that authenticated edge's attestation to its public session. It is
not independent cryptographic proof against a malicious edge that already owns
the authorized peer credential. Claims stronger than that are forbidden.

For HTTPS, the edge obtains exactly 32 bytes from the real TLS socket with:

```text
TLSSocket.exportKeyingMaterial(
  32,
  "EXPORTER-HiveRelay-Blind-Staged-Cell-Put-v2",
  tlsExporterContextHash
)
```

No random bytes, request nonce, caller-provided hash, raw test value, or
self-minted substitute may stand in for this exporter. Production code exposes
no raw/random/test authority constructor. The pure v2 contract validates only
the canonical open and transport-binding relationship. It does not observe peer
credentials, accept a caller boolean claiming that they were observed, or mint
runtime authority. The daemon runtime must first obtain the native socket peer
credentials itself, then combine that observation with the non-authoritative
binding validation and mint its own process-private authority handle. Decoded
context, open bytes, or the validation record are never authority.

The context hash is BLAKE2b-256 over the exact ASCII domain
`hiverelay.blind.tls-exporter-context.v2`, the launch-topology hash, canonical
open fields excluding the context, and both nonces. The public-session binding is
BLAKE2b-256 over domain `hiverelay.blind.public-session-binding.v2`, authority
kind, transport-profile hash, exporter-context hash, and the exact 32-byte
exporter. The open binding is BLAKE2b-256 over domain
`hiverelay.blind.local-staged-open-binding.v2`, topology, canonical open fields,
authority kind, both nonces, transport-profile hash, and public-session binding.

The replay tuple is
`(edgeProcessNonce, localChannelNonce, publicSessionBindingHash)`, domain-hashed
under `hiverelay.blind.local-staged-replay-tuple.v2`. The daemon atomically
consumes it before the first request-body pull, outer-envelope reassembly,
admission preflight, staging, publish, WAL, spend, or signing. Once consumed, it
remains occupied through the original open deadline even when readiness expires,
the body is malformed, the caller aborts, or the operation returns no result.
Replay, collision, or expiry is terminal; there is no release operation.

Replay authority comes only from a dedicated module-private, fsync-backed journal
opened for the exact private-IPC format, signed launch-topology hash, relay/store
identity, durability-continuity/profile/store-format tuple, capacity 4,096, and a
15,000-ms maximum accepted-record TTL. A fresh entry expires at its exact
validated open deadline, which must be no more than 15,000 ms after acceptance;
no accepted record may encode or configure a longer TTL. Its opened authority
and one-use consume receipt are unforgeable process-private brands; a structural
object, frozen fields, or caller boolean cannot substitute. A consume receipt is
minted only after the complete record is durably appended. Live entries are never
evicted: the 4,097th live tuple returns bounded `BUSY` without consuming another
tuple.

Journal open/recovery requires the exclusive writer lock, canonical owner-only
paths, no-follow/inode/mode/link checks, authenticated header and records, a
contiguous hash chain, and mandatory full startup quarantine. Any ambiguity,
integrity failure, short/uncertain write, fsync failure, lock loss, identity
mismatch, or clock regression poisons V2 writes only. Every daemon start enforces
a full 15,000-ms monotonic V2-write quarantine after successful recovery; this
quarantine plus recovered-live retention is the restart/rollback fence, not a
separately incremented durable boot generation. All read/unary/v1 services remain
available. Because restart cannot safely reconstruct the remaining monotonic open
TTL, every recovered live tuple remains occupied for at least 15,000 ms from
successful recovery. That conservative retention may outlive the original open
deadline and is a recovery fence, not an accepted-record TTL above 15,000 ms. A
topology change requires a fenced stop and the same full quarantine interval
before a new topology-bound journal may authorize writes unless a later atomic
migration preserves every live entry.

The normative anti-poisoning order is:

1. native peer credentials and connection quota;
2. exact v2 open, transport profile, topology, endpoint, deadline, and initial
   class-3-through-6 policy;
3. non-authoritative open-binding validation;
4. branded live readiness anchored to a persisted descriptor floor at sequence
   one or greater;
5. counter-only reservation of the complete bounded IPC memory charge;
6. durable replay consumption and one-use daemon authority minting; and
7. only then the first request-body pull and ingress construction.

Binding failure, readiness failure, descriptor rollback/fork, memory `BUSY`, or
pre-consume expiry therefore cannot poison a valid tuple. The pure contract
implements the binding-validation subset only.

## 5. Write-specific readiness

`LocalReadyProbeV2` is exactly 95 bytes:

```text
u32 totalLength=91 || u8 version=2 || u8 controlKind=PROBE ||
u8 endpointId || edgeProcessNonce[32] || launchTopologyHash[32] ||
u32 edgeFeatureBits || u32 requestedWriteOperationBits ||
u64 acceptedMonotonicMillis || u64 absoluteDeadlineMonotonicMillis
```

Its deadline is exactly acceptance plus 2,000 ms. Initial requested write bits
are exactly the generated `CELL.PUT` bit. Feature bits are exactly:

```text
0x01 STAGED_CELL_PUT
0x02 FULL_OUTER_ENVELOPE
0x04 PEERCRED_EDGE_AUTHORITY
0x08 TLS_EXPORTER_BINDING
0x10 PRECOMMIT_OUTER_CLASS_AUTHORITY
0x20 OUTER_RESULT_ENVELOPE
```

The required mask is `0x3f`.

`LocalReadyAckV2` is exactly 133 bytes:

```text
u32 totalLength=129 || u8 version=2 || u8 controlKind=ACK ||
u8 endpointId || edgeProcessNonce[32] || launchTopologyHash[32] ||
u64 descriptorSequence || descriptorHash[32] || u16 readyRoleBits ||
u32 readyOperationBits || u32 readyWriteOperationBits ||
u32 readyIpcFeatureBits || u64 expiresMonotonicMillis
```

`readyWriteOperationBits` is separate from the broad ready-operation bitmap. It
must be exactly the generated `CELL.PUT` bit, must be a subset of
`readyOperationBits`, and both must be subsets of the current signed descriptor's
enabled-operation bits. `readyRoleBits` must include generated `STORAGE` and be a
descriptor subset. Endpoint, nonce, topology, descriptor sequence/hash, and
expiry must match a fresh descriptor snapshot. Missing write readiness, any
missing or unknown feature, a stale/forked descriptor tuple, a subset mismatch,
or expiry keeps public writes disabled. A decision before
`acceptedMonotonicMillis` is not yet valid. Probe deadline, ACK expiry, and
descriptor expiry are exclusive upper bounds: equality is already expired.

Sequence zero is a valid public descriptor genesis but never authorizes private
IPC v2 writes. Initial V2 activation requires an explicitly signed and already
persisted successor descriptor at sequence one or greater. The readiness
projection is a daemon-private brand derived from the current verified descriptor
and its MAC-verified manifest/checkpoint floor under the active store session;
`selfVerified` booleans or callback-shaped objects are not authority. The floor is
restored before readiness after every restart. Rollback or an equal-sequence
different-hash fork clears only V2 write readiness while read service stays live.
During the 15-second replay-journal startup quarantine, the daemon withholds the
branded V2 write-readiness authority and suppresses or refuses `LocalReadyAckV2`.
It never encodes an ACK with `readyWriteOperationBits=0`; such an ACK is invalid
under the closed codec. Read/unary/v1 service remains live while no V2 write ACK
exists.

## 6. Precommit result fit and ordering

Before open binding, the daemon uses only the generated fixed worst case. It does
not authenticate or accept any predicted-result input:

```text
required = 6-byte outer header + 45-byte dispatch framing +
           fixed 16,384-byte generated maximum result body
         = 16,435 bytes
```

Class 2 is 16,384 bytes and therefore cannot hold the fixed 16,435-byte result.
Class 3 is the initial minimum, and only classes 3 through 6 are authorized.

The barrier order is:

1. complete the anti-poisoning open/readiness/memory/replay order in section 4;
2. after replay, decode an owned bounded request prefix and permit only a
   deterministic, side-effect-free, branded admission preflight over that owned
   prefix; it may not contact an issuer, consume a spend, mutate replay/admission
   state, append WAL, reserve durable quota, publish, or sign;
3. stream only into bounded reversible ephemeral staging while hashing; no
   `INGRESS_RESERVED`, `ATTEMPT_CONSUMED`, terminal-spend, or other legacy
   reservation WAL record may be emitted by the v2 path;
4. require the exact selected outer bytes and request FIN, then require the edge
   to write-half-close only its request direction while retaining a readable
   response half, require daemon-observed EOF on that same authenticated stream,
   and only then perform canonical `REQUEST CELL.PUT` revalidation, exact body
   length/hash validation, and fsync of the matching staging object;
5. under canonical spend/object/WAL locks, revalidate caller cancellation,
   deadline, descriptor lifecycle, admission, capacity, idempotency, map/fence,
   writer state, and the branded preflight immediately before entering the
   publish-and-commit unit; a rejected revalidation may now emit its exact
   canonical same-class correlated `ERROR` without durable mutation;
6. on success, enter a non-cancellable unit that publishes the immutable body as
   a recoverable pre-WAL orphan if necessary, then appends/fsyncs/applies exactly
   one additive `PUT_ATOMIC_COMMITTED` record that atomically consumes the spend
   and creates the cell/idempotency result; and
7. only after that commit, sign and emit the exact same-class correlated
   `RESPONSE` envelope.

Legacy reservation/attempt WAL kinds remain decodable and recovery-compatible;
private IPC v2 never emits them. The final caller cancellation, deadline,
descriptor-lifecycle, map, and writer-fence check occurs under the canonical
locks immediately before entering the non-cancellable publish-and-commit unit.
Cancellation observed at that boundary discards the ephemeral stage and consumes
no spend. Once `publishOpaque` begins, caller cancellation is ignored through
immutable publication and `PUT_ATOMIC_COMMITTED` append/fsync/apply. The WAL
prewrite fence rechecks only internal writer and commit invariants and must not
consult the caller signal. After the unit completes, the adapter rechecks caller
cancellation and may suppress signing/result release. Response loss or
post-commit signing failure is recovered by a new transport tuple carrying the
same exact idempotent request, never by rolling back the spend.

A public canonical error discovered from the owned prefix is retained until the
complete outer envelope, FIN, edge write-half-close, authenticated daemon-observed
EOF, and body validation all succeed. Invalid, truncated, overlong, wrong-hash,
post-FIN, replayed-sequence, premature-EOF, missing-EOF, or private-authority
failures suppress that error and close or send only a registered generic local
abort. Before complete request authority there is no public error oracle. After a
commit begins, an internal/signing/encoding failure closes the exchange and
cannot emit an alternative error claiming that no commit occurred.

An oversized or unrepresentable result therefore fails before externally visible
mutation, never after a committed operation.

## 7. Reproduction and remaining gates

The generator accepts no arguments other than optional `--check`, builds twice,
compares every byte, enforces the exact `vectors/v2` inventory, and emits the
canonical public vector-manifest format. Its accepted and negative vectors freeze
lengths, enum/bit rejection, v1/v2 no-fallback, split/coalesce/state sequencing,
readiness matrices, class and transport mapping, replay fields, public dispatch
kind/family/operation/correlation/invariants, and the class-2 precommit negative.

```text
node packages/blind-ipc/generate-private-ipc-v2.mjs
node packages/blind-ipc/generate-private-ipc-v2.mjs --check
```

These artifacts prove the contract and fixtures only. The production assembler
owns the branded replay journal and its mandatory startup quarantine, but the
packaged production entrypoint remains DESCRIBE-only until a reviewed admission
adapter/profile authority enables CELL explicitly. Public write readiness also
requires the persisted sequence-1 descriptor floor, post-EOF
`PUT_ATOMIC_COMMITTED` storage and crash recovery, reviewed edge/daemon
integration, real local TLS exporter evidence, browser/client integration,
independent assurance, and staged multi-relay evidence. The quarantine plus
recovered-live retention is the complete restart fence; no separate durable boot
generation is required. Until the remaining gates pass, the v2 authority does
not authorize deployment.
