# HiveRelay Operation Journal v1 — private named consumer

`@hiverelay/blind-intent-journal-consumer@0.0.0-i01.1` is an additive named
consumer of the accepted Node, Bare and packaged Pear intent backends. It uses
the existing client intent codec/sealer/state machine without changing any
frozen client export, wire hash, backend framing or public artifact. It is a
source-workspace private consumer; an independently installable locked package
and production application adoption are later qualification gates.

Supply one actual exclusive-lifetime NodeIntentBackend, BareIntentBackend or
PearIntentBackend, the recovered caller sealer, explicit bounded retention
policy, and caller-authenticated recovery floors. Do not use this wrapper with
a shared multi-tab IndexedDB backend or call its underlying backend directly:
its native census relies on the accepted exclusive OS writer lease.

```js
const journal = new DurableIntentJournal({
  backend: new NodeIntentBackend(canonicalPrivateDirectory),
  sealer: createAesGcmIntentSealer(runtime, recoveredCallerKey),
  policy: { maxRecords: 256, maxTotalBytes: 16 * 1024 * 1024 },
  recoveryFloors: authenticatedRecoveryManifest.intentRevisionFloors
})
await journal.ready()
// journal.create, journal.read and journal.update await recovery first.
await journal.close()
```

Recovery first scans the exclusive store in bounded pages and counts committed
record bytes (ciphertext plus the unchanged 84-byte header). It retains at most
4096 key/revision/size entries, no plaintext capabilities. Existing storage
exceeding policy is refused without mutation. It then checks every supplied
external revision floor, authenticates every retained intent using the recovered
key, and only after all authenticate converts SENT/ACKNOWLEDGED to
PENDING_UNKNOWN. Logical ID, nonce, commitment and operation bytes are unchanged.
It does not send network requests or issue automatic new logical operations.

The wrapper enforces retained record and byte capacity at every CAS, before a
native write, with eight admitted operations and ciphertext copied before
yielding. A native unknown commit fences queued/future operations until close
and recovery. At capacity, reads and shrinking/equal-sized updates still work.
All records, including terminal records, are retained indefinitely within the
finite cap. New/growing work fails at capacity; no unresolved operation is
deleted. Reclamation requires a separately reviewed export/reconciliation and
retirement successor. Provision additional temporary disk for the native
backend's one `.pending` record (at most maxCiphertextBytes + 84) and filesystem
metadata; logical payload limits do not quantify filesystem overhead.

The caller must authenticate and preserve the sealing key and recovery manifest
separately. This package validates supplied floors, not their external signature
or provenance. An empty array is appropriate only for a caller-authorized fresh
journal or a separately qualified no-external-acknowledgment case. A whole-store
rollback cannot be detected without retained external authority. Do not silently
replace a lost key or pass empty floors to force an old backup to open. Recovery
manifest signature/key custody, complete external acknowledged-operation census,
and reconciliation after backup rollback remain application integration gates.

The local common vectors run real Node 22.22.0, Bare 1.31.0 and the accepted
packaged pear-runtime 1.3.1 / bare-sidecar 0.5.2 with observed Bare 1.29.4 on
macOS arm64. They prove cross-runtime encrypted recovery and zero network sends,
wrong-key refusal without writes, bounded census/retention, uncertain-write
fencing and caller-floor rejection. Three additional live-process SIGKILL vectors
kill the exact Node, Bare or packaged Pear worker after a durable SENT receipt;
a different runtime then recovers the same operation without sending. These
application-boundary kills are separate from the accepted backend commit-phase
crash vectors and do not establish physical power-loss behavior. The Pear component is the frozen Pear 3.0
cohort; it does not establish Pear 3.4, all supported OS/device rows, physical
power-loss durability, actual application lifecycle, or independent acceptance.

For migration, stop admission, drain and close the prior exclusive holder, make
a complete consistent backup, preserve the separate key and authenticated
floors, and open one new holder on the same format. Rollback follows the same
drain/exclusive-open procedure using a qualified accepted backend and consumer
that preserves PENDING_UNKNOWN. Older apps that do not understand the journal
must leave it untouched; deleting records or generating replacement logical IDs
is not rollback.
