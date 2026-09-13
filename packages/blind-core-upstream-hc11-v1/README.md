# Private HC11 CORE upstream, profile v1

This private source package implements real Hypercore MIRROR acquisition and deterministic offline PROVE materialization for the existing `BlindCoreRuntimeAdapter` interface. It is a prerequisite component for R01, not production selection. `STATUS.productionReady`, `defaultSelected`, `openReplication` and `clientVerificationComposed` are false. No frozen public schema, checkpoint binding, default selector or advertised operation bit changes.

The exact dependency closure pins Hypercore 11.34.1, Corestore 7.11.1, hypercore-crypto 3.7.0, compact-encoding 3.3.0 and flat-tree 1.13.0. `package-lock.json` retains the transitive entries from the assignment's exact root lock; a private offline `npm ci` successfully installs that 77-package closure. Current qualification is Node 22.22.0 on macOS arm64. Bare/Pear 3.4, Linux/other OS, independent-host, native OPEN and live-network qualification are pending.

## Contract and use

Construct `RealCoreUpstreamV1({root, connect, readCorpus, limits})` after the caller has selected this exact **private** profile. `root` is a disjoint, canonical absolute scratch directory for temporary native Corestores. It is not the blind WAL/body root or a client writer store. `connect({corePublicKey, signal, maxWireBytes})` returns an exclusively owned duplex stream carrying the peer's unmodified Hypercore replication protocol. The adapter creates its own key-only, non-writable relay session and its own initiating protocol stream. The connector is an application-owned transport provider, never a verifier or source of trusted proof truth. Register no app writer/read keys on that relay session. The caller must not reuse the returned stream elsewhere.

`readCorpus({request,maxBytes,signal})` is a storage-owned read-only lookup of persisted corpus bytes for the exact requested key/fork/length/private head digest. It must authorize storage/owner access and enforce the byte bound before returning data. It must support whichever active/retained sources the surrounding storage coordinator selects. The adapter independently validates the returned format and real Hypercore signatures; lookup does not become activation authority. There is no authoritative in-memory corpus cache.

Methods:

- `activateMirror({request,requestCommitment,previousGeneration,signal})`: returns `{verified:true,corpus,corpusByteLength,corpusHash}` only after finite full-range acquisition, exact authenticated head and prefix checks, corpus verification and actual resource cleanup. The surrounding accepted storage engine must have committed admission first and remains responsible for activation CAS, lease, corpus staging, retries and retirement. Invalid supported-format/head/corpus candidates return `{verified:false}`; unavailability/abort rejects. No statement that MIRROR acknowledgement alone proves retrieval.
- `estimateProofBytes({request,signal})`: validates the persisted corpus and returns the exact serialized sample length.
- `serveProof({generation,blockIndices,corpus,signal})`: validates the supplied immutable corpus and deterministically slices the requested 1..16 sorted distinct block frames. It performs no network acquisition.
- `verifyProofBundle({request,proof,signal})`: an explicitly asynchronous private verifier using actual upstream cryptography, including exact sample/head checks. It is not wired into the existing synchronous public client hook.
- `close({timeoutMillis})`: aborts owned work and returns true only once every charged job released resources. False means a pending provider, native close or failed cleanup remains charged; callers must not claim teardown or instantiate replacement capacity on that basis. The instance remains closed to new work. A cleanup failure fences the instance and keeps its charge; operator recovery is a later integration concern.

The adapter rejects u64 values outside JavaScript's safe integer range before opening attacker-selected core state. Its current format supports only Hypercore manifest v1, one Ed25519 signer/quorum one, BLAKE2b, without patch/prologue/linked/userData fields. Other valid Hypercore manifests are unsupported and fail closed. This restriction is explicit private-profile scope, not a claim to qualify every existing consumer/core format.

## Versioned bytes

`format-contract.json` and `vectors.json` are generated from the new package. `PROFILE_DIGEST` is BLAKE2b-256 of UTF-8 `JSON.stringify(FORMAT_CONTRACT)` in its declared property order. Do not change any of these byte semantics without creating/reviewing a private profile successor and regenerating vectors. No unversioned public `signedHeadHash` interpretation is adopted.

HeadIdentityV1 is:

```
ASCII("hiverelay.private.hc11.head-identity.v1\0") ||
u8(1) || corePublicKey32 || fork_u64be || length_u64be || treeHash32
```

Its BLAKE2b-256 digest is the request's head digest **only when this private profile is explicitly selected**. The identity is authenticated by the retained canonical upstream signed-head proof. It does not hash an unauthenticated claimed root or accept a caller-provided verification boolean. Same-fork extension recomputes the candidate's prefix tree root and this identity at the previous length/fork; thus a retained hash-only floor remains useful after old body expiry. Higher forks require the exact new signed head; storage still orders/activates them.

CorpusV1 contains magic `HRHC11C1`, profile digest, head identity, one u32be-length-delimited signed-head frame, u32be count equal to the head length and a u32be-length-delimited upstream proof for every ciphertext block in order. ProofBundleV1 uses magic `HRHC11P1` and 1..16 selected ascending frames. Both retain the exact upstream `wire.data` payloads with request zero and no extra hash/seek fields. All proof frames require the same exact signed head, upgrade start zero and no additional upgrade nodes.

The decoder bounds counts and lengths against remaining bytes before allocating arrays or calling upstream decoding. It also requires the exact block path into a signed full root and the exact other full-root list, with no leftover nodes. This matters because pinned `verifyFullyRemote` can verify a valid upgrade while leaving an unrelated block root unused; the real-library adversarial regression demonstrates that behavior and the private rejection. Canonical re-encoding catches overlong compact integers and unknown/trailing data. Every retained block proof is cryptographically validated, even when the current request selects another block.

## Bounds and ownership

Defaults: 256 blocks; 64 KiB ciphertext/block; 4 MiB encoded corpus; 4 MiB minus 256 sample bytes; two concurrent jobs; 10-second job deadline; 16 MiB aggregate incoming plus outgoing wire bytes. Supported configurable maxima are in `limitsOf` and the format contract: 4096 blocks, 1 MiB ciphertext/block, 64 MiB corpus, eight jobs, 60-second job deadline and 128 MiB wire budget. Exact encoded corpus/proof bytes include duplicated proof/header overhead.

The finite download must resolve `true`; upstream cancellation resolves `false`. Abort/timeouts destroy registered streams/ranges. Late connector and corpus-reader promises remain charged until they settle and any late resource is actually closed. A final signal check after cleanup prevents success minted during cancellation. Input buffers are copied synchronously after slot admission, before yielding. Temporary native stores are removed only after native closure. Tests exercise cancellation at that removal boundary.

`reservedCorpusBytes` is a logical maximum corpus-output reservation, **not a bound on total RSS or total native disk usage**. Native Hypercore/storage metadata, pre-decode transport allocations, RocksDB caches, copies during verification and acquisition-plus-body-staging duplication are additional. Wire metering sees bytes before forwarding chunks into the local protocol but cannot prove that every upstream internal allocation was bounded before it occurred. A source can advertise a larger signed head; it is rejected, but metadata may already have arrived. Connector-owned buffers also require their own lower-level limits. These preallocation, total memory/disk, process isolation and G04 custody gates remain open. A process crash may leave acquisition scratch directories; this component does not delete arbitrary old directories or claim production crash recovery.

Privacy: only ciphertext blocks/proofs leave the acquisition store, never Corestore directories, userData, encryption key or writer secret. The relay still observes opaque key/discovery/manifest signer metadata, lengths, timing and transport peers. It cannot certify that an arbitrary client's bytes were encrypted; random per-device encrypted transport-core construction remains a client requirement. This is no anonymity or independent-operator claim.

## Verification and remaining integration

Run `npm test` in this directory for standalone component tests, `npm run check:vectors` for exact generated bytes, and `npm run test:integration` in this monorepo for the unchanged real storage/runtime harness. Fixture encryption/signing seeds in vectors are deterministic public test material only. Tests use disposable disk stores and genuine upstream replication streams; no DHT or production peer is contacted. Fresh-process offline replay uses no network connection.

The storage harness proves admission-before-acquisition, genuine corpus persistence, signed charged proof, reverse candidate completion, retained old-corpus replay and restart through the actual unchanged engine. It also records the unresolved runtime path explicitly: estimation currently selects the active corpus before a paid older proof retry reaches its storage-owned pin. The expected refusal test is a follow-on integration gate, not a claim that this path works. The public `coreProofVerifier` hook is synchronous and cannot receive this async method directly. G04 body capture/pruning/hydration, all-family coordinator routing, production selection and the complete runtime/device/fleet matrix remain mandatory later gates.

Installation/rollback: source-only private addition; no store migration or production selector is applied. Reverting/removing this package before selection returns to the unchanged unavailable upstream. Any later selector/profile activation needs its own forward migration and rollback proof. An earlier public profile must never silently interpret this private head digest or corpus. Independent review of the exact commit is required before integration.
