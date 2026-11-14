# Private captured body validation V1

This component checks the physical opaque bodies named by an original private
full-WAL capture while its exact native store lease remains held. It adds no
public export or default runtime selection. It is a prerequisite for checkpoint
publication and reconstruction, not authority to perform either operation.

`validateCapturedBodies({ role, capture, root, lease, limits, signal })` accepts
one CELL, INBOX or CORE capture from the versioned checkpoint storage engines.
The corresponding engine-owned capture reader revalidates the full WAL and
retained lease. Caller-created descriptions and copied tokens are rejected.

Body ownership is derived from the captured semantic state:

- CELL: every present cell and every present entry of a live charged read. A
  charged read must join the cell's exact immutable hash and size. Duplicate
  references share one physical read but each counts toward the reference limit.
- INBOX: every retained frame. The preceding accepted semantic capture checks
  the relationship between charged page retries and retained frames.
- CORE: every active generation floor and every unexpired paid proof's original
  source generation. Replaced generations with a live paid proof remain required.
  Historical generations whose owners all retired require no deleted corpus.

The validator opens no mutable engine. It neither creates, removes nor repairs a
body. All body paths are derived from validated bucket and object identifiers.
It rejects noncanonical or linked parent paths, nonprivate ownership or modes,
nonregular files and multiply linked files. Each final file is opened read-only
with `O_NOFOLLOW`; named/open inode identities and declared lengths must agree.
BLAKE2b-256 is streamed over every byte and checked against the captured hash.
Metadata is compared before and after hashing, after handle close, and when the
result is consumed. Parent identities, WAL capture and native ownership are
rechecked. The actual file handle closes before a result can be returned, including
read failure, cancellation and lease loss.

The result is an in-process WeakMap-branded token. Its reader requires the same
root and lease, revalidates retained metadata/WAL/ownership and returns deep copies
of reference and coverage evidence. It returns no payload. Reopening a root or
serializing a token does not recreate authority.

## Resource limits

Defaults are 65,536 unique bodies, 262,144 owner references, 64 MiB per body,
256 MiB total body bytes and a 64 KiB read chunk. Positive integer overrides are
bounded to 65,536 bodies, 1,048,576 references, 64 MiB per body, 64 GiB total and
1 MiB chunks. Unknown fields fail. Reference collection completes before any body
open. Bodies are read sequentially with one file handle and one bounded chunk.
The preceding capture has its own bounded observed WAL and retained row limits.

These are per-call work bounds, not a shared production admission or RSS limit.
Copying semantic capture state also consumes bounded memory. Cancellation cannot
interrupt a pending kernel read or the capture reader's own validation; resources
remain owned until the awaited operation and close complete.

## Verification and authority boundary

Tests use actual persistent CELL, INBOX and CORE engines, native store leases,
full-WAL captures and real filesystem bytes. CORE fixture payloads and prepared
admissions are synthetic; these tests do not qualify Hypercore cryptography or a
production token issuer. They cover retained/replaced/retired owners, paid reads,
missing/truncated/modified bodies, unsafe links and permissions, reference and
byte limits, parent replacement, cancellation, lease loss, read failure and late
body/WAL mutation. Frozen checkpoint source bindings remain unchanged.

This component is qualified locally on Node 22.22.0, macOS arm64. Other runtime,
OS and architecture evidence is separate. It does not establish a snapshot of all
three roots, shared blind/Hypercore installation custody, prune eligibility,
compacted hydration, rollback freshness, an independent witness, public consumer
support or release/fleet readiness. The retained lease excludes cooperating
writers. A privileged adversary changing files or the filesystem outside that
ownership protocol is not prevented by these sequential checks. The publisher
must coordinate every participating role and revalidate before its own durable
boundary; it cannot treat these descriptive tokens as publication authority.

## Migration and rollback

There is no on-disk format or manifest change. Existing versioned captures and
all frozen format files remain byte-identical. Removing these additions before
selection is a source-only rollback with no data conversion. Never remove or
repair a failed body merely because this read-only validation rejects it.
