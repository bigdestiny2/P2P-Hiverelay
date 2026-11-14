# Private Node async HC11 proof client v1

This private source-workspace package composes the accepted actual Hypercore
11.34.1/Corestore 7.11.1 verifier with the existing signed CORE.PROVE result
verifier. It is explicitly selected for the private HC11 profile v1. It is not a
published package, default client, new public protocol interpretation, durable
attempt implementation, or fleet qualification. Existing public client files,
schemas, default selectors and accepted source bindings remain unchanged.

The verifier opens native temporary Corestores and therefore this composition is
Node-only. Current tests use Node 22.22.0 on macOS arm64. Bare, Pear 3.4, browser,
mobile, Linux and separate-host qualification remain open. No replacement
cryptography is used to claim portability. The upstream package's exact private
lock and root workspace lock must both be installed; this package uses their
source-workspace imports and does not claim independent npm installation.

## Interface

```js
import { NodeCoreProofClientV1 } from './index.js'
import { PROFILE_DIGEST } from '../blind-core-upstream-hc11-v1/format.js'

const client = new NodeCoreProofClientV1({
  root: '/canonical/private/dedicated-proof-scratch',
  profileDigest: Buffer.from(PROFILE_DIGEST),
  transport, // Existing transport.request interface; optional for verifyResult.
  timeoutMillis: 10000
})
// created is the existing createCoreProveRequest result for this private head.
const verified = await client.prove({
  endpoint, // Existing authenticated VerifiedEndpoint for CORE.PROVE.
  requestBytes: created.requestBytes,
  requestCommitment: created.requestCommitment,
  signal
})
const authenticatedResultBytes = verified.snapshotBytes()
const closed = await client.close({ timeoutMillis: 1000 })
```

`verifyResult` accepts the same request/endpoint fields and an additional
`resultBytes`, without sending a transport request. Both methods return the
existing branded `VerifiedOperationResult` only after all checks succeed. They
reject absent/non-successful responses, malformed data, mismatched proof or
signed result, cancellation and timeout. They do not synthesize an accepted
response, persist an intent state, decide retry policy or interpret plaintext.
The private head digest must already represent the caller's exact trusted
key/fork/length/head selection. Signature/Merkle proof verification authenticates
the sampled ciphertext under that head; client decryption/application semantics
and transport-core encryption-key custody remain separate responsibilities.

An optional `externalWitnessVerifier` retains the existing synchronous witness
policy contract when an endpoint requires it. Its signature and binding are
still checked by the frozen result verifier; an asynchronous/truthy return is
not accepted. Caller-supplied CORE proof verifiers/upstreams are rejected.

## Verification and ownership

Admission has one slot. The client makes owned copies of bounded canonical full
request bytes (including admission), request commitment and supplied result
bytes before yielding. It validates the request's exact private head/sample
bounds and reproduces the frozen request commitment before transport. Returned
transport bytes are copied immediately when received. Request and result byte
ceilings are the unchanged 16 KiB and 4 MiB CORE.PROVE limits; native proof limits
come from the accepted private upstream. Logical byte limits do not bound native
cache/RSS/disk overhead.

The internally constructed real verifier authenticates every proof frame's
key, fork, length, private head hash, exact requested sample and ciphertext.
Only strict `true` after its awaited verification and cleanup enables a local
single-use closure inside the existing signed result verifier. That closure is
never returned, cached, caller-supplied or reused. It matches the full canonical
request and full canonical result bytes plus every qualified endpoint namespace,
destination and durability field. The old verifier independently checks the
relay signature, binding, commitment, nonce, head and required witness. A failed
check produces no branded result. A repeated response undergoes real native
verification again; it does not reuse an authorization token.

Cancellation and a monotonic deadline are checked around asynchronous boundaries
and immediately before return, including when synchronous work delays timer
delivery. An uncooperative transport remains charged until its promise settles.
If native verification returns cancellation before physical cleanup, the native
adapter's retained job keeps the client's sole slot unavailable. Cleanup failure
fences the client and retains capacity. `close()` aborts admission and returns
false if transport/native cleanup has not settled within its deadline. False is
not permission to instantiate replacement capacity, remove arbitrary scratch
directories or claim clean shutdown. Crash/abandoned-scratch recovery needs a
separate operator policy; the existing native adapter limitations still apply.

## Qualification and remaining work

Tests acquire proofs from actual independently stored encrypted Hypercores over
their protocol streams, close the source writer, then exercise this client's
actual `prove`/`verifyResult` flow. Relay signatures are genuine; the transport
and authenticated endpoint issuer are explicit local test fixtures. The tests
do not claim deployed descriptor qualification or a real HTTP/DHT fleet path.
Controls cover valid/tampered/mismatched/missing results; real pending verification
and repeated proofs; owned mutable inputs including admission; namespace drift;
pre-abort and deadline; uncooperative late transport; held native cleanup; cleanup
failure; and a completed real verifier whose delivery crosses the deadline.
Delay/failure instrumentation wraps real native operations without substituting
a cryptographic verdict.

Run `node --test packages/blind-core-proof-client-node-v1/test/client.test.mjs`
from the workspace. The package remains unselected. The existing public
`DurableAttempt` still has its synchronous verifier/replay path: versioned async
durable persistence/replay is a required follow-on, not silently routed here.
Whole publication/source binding, exact immutable images, full checkpoint
capture/prune/hydration, all runtime/device rows and full 0.27 remain required
before fleet rollout. Private relay remains off by default.

There is no store/schema migration. Before any future selection, rollback is to
remove this additive package; existing sources and selectors remain unchanged.
Later production selection must separately qualify profile compatibility,
durable intent handling, decryption, custody, retry and recovery behavior.
