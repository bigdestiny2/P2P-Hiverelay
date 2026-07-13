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
12      1      outerClass, 1..6
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
`OUTER_CLASS[outerClass]` bytes. Only then may result frames start at their own
sequence zero. A non-aborted result ends with FIN after the same exact outer-class
byte count. ABORT is terminal. A gap, replay, result-before-request-FIN, wrong
aggregate length, or frame after FIN/ABORT closes the exchange.

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
no raw/random/test authority constructor. A successful peercred-first
verification returns an opaque branded handle; decoded context or open bytes are
never authority.

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
consumes it before request-body allocation, reassembly, admission, publish, WAL,
spend, or signing. Replay, collision, or expiry is terminal.

Verification order is peer credentials, exact shape, transport profile,
topology, endpoint, deadline, replay consumption, and open binding. Only the
resulting opaque handle may enter outer-envelope decode.

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
or expiry keeps public writes disabled.

## 6. Precommit result fit and ordering

The daemon computes the exact required result-envelope bytes before any publish,
WAL append, admission spend, or signature:

```text
required = 6-byte outer header + 45-byte dispatch framing +
           authenticated predicted result-body bytes
```

An operation-specific authenticated prediction may accept a smaller result. For
example, a 104-byte predicted receipt fits class 2. A caller without such a
prediction uses the generated maximum `CELL.PUT` result body of 16,384 bytes.
That worst case requires `6 + 45 + 16,384 = 16,435` bytes, so class 2 (16,384)
must be rejected and class 3 is the minimum worst-case class.

The barrier order is:

1. authenticated open and replay consume;
2. exact full outer-envelope reassembly and canonical `REQUEST CELL.PUT` decode;
3. same-class correlated result prediction and fit;
4. admission validation and storage/coordinator precommit;
5. only then publish, WAL, spend, and sign; and
6. emit the exact same-class correlated `RESPONSE` or `ERROR` envelope.

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

These artifacts prove the contract and fixtures only. Public write readiness
still requires reviewed edge/daemon runtime integration, real local TLS exporter
evidence, signed descriptor propagation, precommit storage/recovery/retrieval
tests, browser/client integration, independent assurance, and staged multi-relay
evidence. Until those gates pass, the v2 authority does not authorize deployment.
