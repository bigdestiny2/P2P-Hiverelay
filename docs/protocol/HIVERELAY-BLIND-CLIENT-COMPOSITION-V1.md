# HiveRelay Blind Client Composition v1

Status: final generic client-composition binary authority.

This document is the canonical specification input embedded byte-for-byte in the
client-composition format artifact. It defines only six client-owned records used
to compose opaque application state. A relay stores or transports their encrypted
or otherwise opaque containing bytes and MUST NOT decode these records.

## 1. Closed authority and ownership boundary

The authority owns exactly these schema names, in raw-ASCII order:

```text
BlindCoreReadCapV1
CellBlobV1
OpaqueChainCheckpointV1
OpaqueChainFrameV1
ReadCellCapV1
WriteCellCapV1
```

They are category 3 (`CLIENT_EXAMPLE`) rows 1 through 6 respectively. The exact
canonical declarations and composition dependencies are the six entries in
`hiverelay-blind-client-composition-schema-catalog-v1.cenc`, generated with the
stable master schema meta-grammar. Category 1 relay WIRE, product evidence,
category 4 relay persistence, and category 5 private IPC are outside this
authority. No schema, name, declaration, fixture, or byte catalog from those
categories may appear in its catalog or vector set.

The authority does not claim application semantics, application-author identity,
relay honesty, daemon readiness, persistence recovery, or private-IPC readiness.
An application profile may import this exact authority and then add its own
signed payload rules. It MUST bind the complete two-hash tuple below rather than
copying a declaration or relying on a JavaScript object shape.

## 2. Canonical primitives

Fields are encoded in declaration order with no alignment or implicit values.
`u8`, `u32`, and `u64` are fixed-width unsigned big-endian integers. Fixed byte
strings have no length prefix. A bounded byte string is the canonical shortest
compact-uint length followed by exactly that many bytes. Arrays use the same
canonical shortest compact-uint count followed by exactly that many elements.
Compact uint values `0..252` use one byte; marker `0xfd` is followed by a
little-endian `u16`, `0xfe` by a little-endian `u32`, and `0xff` by a
little-endian `u64`; an overlong form and a value above JavaScript's exact safe
integer range fail closed. An optional is one byte `0` for absent or `1` followed
by its value; every other tag fails closed. Unknown versions, truncation, trailing
bytes, out-of-range values, and non-canonical encodings fail with `BAD_ENCODING`.

All fields called keys, commitments, hashes, slots, chain IDs, or frame hashes
that the executable codec marks nonzero MUST contain at least one nonzero byte.
Sorting is lexicographic unsigned-byte order and is strict: equal adjacent keys
are duplicates and fail closed.

## 3. Exact schema semantics

`ReadCellCapV1` is version 1, then 32-byte relay public key, 32-byte storage slot,
32-byte cell key, size class `1..5`, and optional 32-byte expected blob hash. The
three mandatory byte strings and a present expected hash are nonzero.

`WriteCellCapV1` is one canonical `ReadCellCapV1`, allocation epoch `u32`, then
three 32-byte create, renew, and drop private keys. Each private key is nonzero and
the three values are pairwise distinct.

`CellBlobV1` is contextual. A decoder MUST be selected by an already authenticated
size class. Its exact total lengths are class 1 = 4096, class 2 = 16384, class 3 =
65536, class 4 = 262144, and class 5 = 1048576 bytes. It contains version 1, a
12-byte nonce, and exactly `classLength - 13` sealed bytes. No class discriminator
is serialized in the blob. Decoding with the wrong class, a short blob, or a long
blob fails closed. Cryptographic nonce uniqueness and AEAD verification are the
responsibility of the composing encryption profile; this binary codec only fixes
the envelope bytes.

`OpaqueChainCheckpointV1` is version 1; a `1..1024` array of frontier entries
`(chainId[32], sequence:u64, frameHash[32])`; two nonzero 32-byte commitments;
and a `1..16` array of `ReadCellCapV1`. Frontier entries are strictly sorted by
chain ID. Snapshot capabilities are strictly sorted by `(relayPublicKey,
storageSlot)`. Frontier chain IDs and frame hashes and both commitments are
nonzero.

`OpaqueChainFrameV1` is version 1; nonzero chain ID; sequence `u64`; optional
previous frame hash; nonzero 32-byte transport verification key; `0..256` opaque
payloads each `0..262144` bytes; `0..16` `ReadCellCapV1` values; optional
`OpaqueChainCheckpointV1`; and a 64-byte transport signature. The previous hash
is absent exactly when sequence is zero and present otherwise. Next capabilities
are strictly sorted by `(relayPublicKey, storageSlot)`. At least one payload or a
checkpoint is required. Signature verification, sequence increment across two
frames, and complete chain continuity are higher-level composition checks; this
codec fixes the signed record bytes and its local invariants.

`BlindCoreReadCapV1` is version 1; nonzero 32-byte core public key; nonzero
32-byte block-encryption key; witnessed fork and length as `u64`; and a
`1..4096` byte witnessed signed head. The relay never receives the encryption key
or this complete capability.

## 4. Format artifact and hash

`hiverelay-blind-client-composition-format-v1.cenc` is exactly:

```text
ASCII("HRBCCF01")                         // 8 bytes
authorityVersion:u16be = 1
formatMajor:u16be = 1
formatMinor:u16be = 0
specLength:u64be
schemaCatalogLength:u64be
specBytes[specLength]                     // this exact UTF-8 file
schemaCatalogBytes[schemaCatalogLength]   // exact six-entry category-3 catalog
```

Both lengths are nonzero and at most 1 MiB. `specBytes` use LF only, no BOM or
NUL, strict UTF-8, and exactly one final LF. The catalog decodes canonically to
exactly the six names and local IDs in section 1. Trailing bytes fail closed.

```text
clientCompositionFormatHash = BLAKE2b-256(
  ASCII("hiverelay.blind.client-composition-format-hash.v1") ||
  U64BE(len(completeFormatArtifact)) || completeFormatArtifact
)
```

## 5. Vector manifest and semantic commitments

The final vector manifest uses the generic strict vector-manifest framing: a
`u32be` entry count, followed by raw-UTF-8-path-sorted rows of path length
`u16be`, canonical relative path bytes, vector length `u64be`, and BLAKE2b-256 of
the complete vector bytes. Duplicate, absolute, dot-component, backslash,
non-canonical UTF-8, unsorted, truncated, or trailing-byte manifests fail closed.

The closed path inventory is:

```text
negative/blind-core-read-cap-zero-core-public-key.bin
negative/cell-blob-v1-class-1-truncated.bin
negative/opaque-chain-checkpoint-unsorted-frontier.bin
negative/opaque-chain-frame-sequence-one-without-predecessor.bin
negative/read-cell-cap-zero-relay-public-key.bin
negative/write-cell-cap-duplicate-private-keys.bin
positive/blind-core-read-cap-v1.bin
positive/cell-blob-v1-class-1.bin
positive/cell-blob-v1-class-2.bin
positive/cell-blob-v1-class-3.bin
positive/cell-blob-v1-class-4.bin
positive/cell-blob-v1-class-5.bin
positive/opaque-chain-checkpoint-v1.bin
positive/opaque-chain-frame-v1-genesis.bin
positive/opaque-chain-frame-v1-successor.bin
positive/read-cell-cap-v1.bin
positive/write-cell-cap-v1.bin
registry/client-composition-schema-catalog-v1.cenc
```

Every positive vector MUST decode with its named codec and re-encode byte-for-byte.
The five blob vectors MUST decode only with their stated contextual class. Every
negative vector MUST fail canonical decoding with `BAD_ENCODING` for the condition
named by its path. The registry vector MUST equal the catalog embedded in the
format artifact. Missing, extra, substituted, or semantically misclassified
vectors fail complete authority verification.

```text
clientCompositionVectorSetHash = BLAKE2b-256(
  ASCII("hiverelay.blind.client-composition-vector-set-hash.v1") ||
  U64BE(len(completeVectorManifest)) || completeVectorManifest
)
```

The final identity of this authority is the pair
`(clientCompositionFormatHash, clientCompositionVectorSetHash)` published in the
generated metadata artifact. Neither value is a relay WIRE tuple component.
