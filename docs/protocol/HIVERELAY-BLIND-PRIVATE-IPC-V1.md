# HiveRelay blind private IPC v1

Status: frozen binary authority for the local `blind-edge` to `blind-daemon`
boundary.

This authority is private product IPC. It is not public relay WIRE, an
application protocol, a client capability format, a daemon store format, or a
general RPC surface. Only the isolated edge and daemon runtime components may
import it. Release/build verifiers may inspect its artifacts without packaging
them into either runtime.

The normative architecture and behavioral requirements remain in
`BLIND-APP-AGNOSTIC-HIVERELAY-MASTER-SPEC.md` and
`BLIND-SUBSTRATE-IMPLEMENTATION-SPEC.md`. This file freezes the artifact
boundary, dependency, framing inventory, and hash construction needed to
reproduce one exact private IPC authority.

## 1. Final authority files

```text
packages/blind-ipc/hiverelay-blind-private-ipc-v1.cenc
packages/blind-ipc/vector-manifest-v1.cenc
packages/blind-ipc/vectors/fixtures/*.bin
packages/blind-ipc/vectors/framing/*.bin
packages/blind-ipc/hiverelay-blind-private-ipc-authority-v1.json
```

Any transitional `.draft` registry or manifest alias is byte-identical to the
corresponding final file. It is not another authority or hash input.

## 2. Scope and imported WIRE dependency

The registry contains exactly these seven category-5 schemas, with contiguous
category-local IDs 1 through 7:

1. `LocalDispatchV1`
2. `LocalUnaryResponseV1`
3. `LocalStreamOpenV1`
4. `LocalStreamFrameV1`
5. `LocalAuthenticatedChannelV1`
6. `LocalStreamAttachContextV1`
7. `LocalStreamControlV1`

The readiness probe and acknowledgement are closed variants of the first two
schemas; they do not create extra schema types or public operations.

The registry imports exactly the final public WIRE `abiHash` and the WIRE
bindings for `FAMILY`, `TRANSPORT_ID`, `TRANSPORT_SUPPORT`, `OUTER_CLASS`, and
`STREAM_WIRE_CLASS`. It copies no numeric value by hand. A change to any imported
WIRE binding changes the private registry and its format hash. The final WIRE
specification, ABI, vectors, and hashes do not import this private authority.

No EVIDENCE, CLIENT_EXAMPLE, INTERNAL_STORE, application, semantic-service, or
legacy-relay schema may appear in the registry, vector manifest, edge import
graph, or daemon public framing.

## 3. Registry encoding

The registry uses compact-encoding version 1. `uint` is the canonical
compact-encoding unsigned integer, `string` is its canonical UTF-8 string, and
`fixed32` is exactly 32 bytes. Lists encode `uint count` followed by that many
entries. Unknown fields, overlong or noncanonical integers, invalid UTF-8,
truncation, trailing bytes, unbounded counts, duplicate IDs/names, wrong order,
or an alternate imported WIRE hash fail closed.

```text
PrivateIpcRegistryV1 =
  string magic = "hiverelay-blind-private-ipc-v1" ||
  uint formatVersion = 1 ||
  fixed32 wireAbiHash ||
  list<Schema> schemas ||
  list<BindingTable> importedWireBindings ||
  list<BindingTable> localBindings

Schema = uint schemaId || string schemaName || list<string> fields
BindingTable = string name || list<BindingEntry> entries
BindingEntry = string name || uint id || uint value
```

Schema IDs are numeric order. Enum and class entries are numeric-ID order with
raw name bytes as the tie breaker. Named limits are raw-name order. Local
bindings freeze every response/control/error/kind/mode/class/phase/size/limit/
timing/open-combination row consumed by the executable codecs.

## 4. Frame families

Every unary request, unary response, stream-open item, and stream frame begins
with `u32be totalLength`, the exact bytes following the prefix. Complete header
sizes including that prefix are 32 or 64 bytes for `LocalDispatchV1`, 11 bytes
for `LocalUnaryResponseV1`, 33 or 65 bytes for `LocalStreamOpenV1`, and 21 bytes
for `LocalStreamFrameV1`.

The executable codecs enforce the master specification's exact variants:

- external unary requests and responses carry one exact public outer class;
- readiness uses only its fixed 65-byte probe and 120-byte acknowledgement;
- local broker errors contain no diagnostic body or text;
- stream opens use only the five closed kind/mode/class/context/adjacency rows;
- authenticated-channel and attach contexts are fixed-size and nonzero-bound;
- stream content, raw Core, ciphertext, control, and abort frames use their
  exact class, phase, flag, size, direction, and sequence policies; and
- stream control uses only its seven fixed discriminated layouts.

Split/coalesced frames are parsed only after their declared bounded length is
available. A connection never accepts a short, overlong, trailing, multi-frame,
unknown, or contradictory item as one canonical frame.

## 5. Vector manifest and hashes

The final manifest uses the public canonical vector-manifest construction:

```text
u32be entryCount || repeated(
  u16be pathLength || UTF8_NFC(relativePath) ||
  u64be vectorLength || BLAKE2b-256(vectorBytes)
)
```

Paths are slash-separated relative paths, strictly sorted by raw UTF-8 bytes,
and contain no empty, dot, dot-dot, backslash, absolute, or duplicate component.
Every listed fixture file must exist with the exact length and hash; unlisted
fixture files fail generation and verification.

The manifest binds 35 complete canonical schema fixtures and 44 executable
framing scenarios. A framing scenario is a test-only vector container; it is
never transmitted and does not add an eighth PRIVATE_IPC schema:

```text
PrivateIpcFramingVectorV1 =
  u8 version = 1 ||
  u8 parser // 1 request, 2 response, 3 stream-open, 4 stream-frames ||
  u8 outcome // 1 accept, 2 reject ||
  u8 expectedItemCount // nonzero only for accept ||
  u16be chunkCount[1..64] ||
  repeated(u32be chunkLength[1..8388672] || bytes[chunkLength])
```

The scenarios bind prefix and every field split, split-plus-coalesced stream
records, valid stream multi-frame parsing, unary/open multi-item rejection,
prefix/header/body truncation, trailing bytes, overlong declarations, unknown
versions, reserved flags, length contradictions, sequence gap/replay, post-FIN,
post-ABORT, and the one permitted correctly sequenced ABORT after FIN. A verifier
must feed the recorded chunks in order, must not decode an item before its exact
declared bytes exist, must reject buffered bytes at EOF, and must obtain exactly
`expectedItemCount` canonical items only for an accept scenario.

Let `len64(x)` be unsigned big-endian byte length. The authority hashes are:

```text
privateIpcFormatHash = BLAKE2b-256(
  "hiverelay.blind.private-ipc-format-hash.v1" ||
  len64(registryBytes) || registryBytes
)

privateIpcVectorSetHash = BLAKE2b-256(
  "hiverelay.blind.private-ipc-vector-set-hash.v1" ||
  len64(vectorManifestBytes) || vectorManifestBytes
)
```

The authority metadata records those hashes, the exact imported public WIRE
`abiHash`, and exact schema/vector counts. Metadata, build paths, timestamps,
release blockers, and implementation status do not enter registry or manifest
bytes.

## 6. Publication boundary

Publishing this authority proves only the local binary contract and its
executable codecs. It does not prove the production daemon storage engines,
recovery, admission redemption, external witness, online rebalance, privacy
transports, deployment topology, release image, or relay fleet. Those gates stay
independent and fail closed.
