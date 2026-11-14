# Serving selected retained local snapshots

This optional compatibility path serves selected public files already present
in a guarded storage generation. It is disabled by default. It is intended for
legacy recovered entries whose storage bound is still unknown and which cannot
produce the modern finite storage commitment required by the normal gateway.

A successful read verifies the returned bytes against the selected signed
Hypercore heads. It does not establish a complete copy of the drive, change the
entry's storage bound, make the entry a modern anchor, or authorize a custody
acknowledgement. Unknown obligations continue to block fresh storage admission.

## Selecting authority

An operator must prepare a stopped-state capability from the exact existing
generation and independently select its raw SHA-256 digest. The capability uses
the closed `HiveRelayRetainedLocalReadCapabilityV1` schema and binds:

- The verified installation, generation authority and envelope.
- Canonical storage paths and their actual device/inode identities.
- The qualification provenance and complete registry witness.
- Each selected app's exact raw registry row and metadata/blob core descriptors.
- Exact signed head versions, forks, lengths, byte lengths and tree hashes.

The capability and its separate digest file must live outside mutable storage.
Both files must be regular, single-link files that the running relay cannot
write directly. Protect the authority directory with an actual read-only mount
for production. The loader checks effective direct-write refusal; permission
bits alone do not prove that an owning account cannot later change permissions
or replace a path. In particular, `0444` does not protect a file from root.
The parsed selection is private and immutable for the running controller;
protection of the external selection across later launches remains an operator
requirement. Symlinked paths, partial
declarations, mutable authority, mismatched hashes and replay onto another
storage generation are refused.

The digest file contains `sha256:` followed by the 64 lowercase hexadecimal
digest characters and one newline. The capability uses the exact canonical
encoding produced by the selected operator tool. Do not hand-edit either file.
The operator's selection is a hash-pinned authorization; data authenticity comes
from the independent Hypercore signature and Merkle proof checks.

Declare both files explicitly at launch:

```text
--retained-read-capability /protected/retained-local.json
--retained-read-capability-sha256-file /protected/retained-local.sha256
```

The equivalent environment variables are
`HIVERELAY_RETAINED_READ_CAPABILITY` and
`HIVERELAY_RETAINED_READ_CAPABILITY_SHA256_FILE`. Persisted configuration and
management updates cannot enable this path. A declaration does not issue a
capability or choose a snapshot automatically.

The stopped issuance and deployment procedure must preserve the full registry,
all existing content and holes, identities, services and storage accounting.
Opening the native database for inspection can change database housekeeping
files. Any later startup must therefore bind the inspected **post-issuance**
manifest, rather than reusing a pre-inspection filesystem manifest. A restored
generation requires selection against its actual restored identity.

## Request behavior

Successful responses include:

```text
X-Hive-Read-Scope: retained-local-snapshot
```

File GET, bounded single byte ranges, HEAD and a directory's `index.html` are
supported. HEAD reports verified file metadata under ordinary HTTP semantics;
it does not prove that every body block is locally available. Deployment
acceptance requires an actual GET and content-hash comparison.

Directory listings and verification bundles return an explicit unsupported
response for retained snapshots. Their normal modern-proof routes are unchanged.
Existing denylist, privacy, policy, approved-origin, rate, egress and response
controls continue to apply. This capability cannot make a private or encrypted
entry public, register an origin, or bypass a takedown.

The reader borrows an already-open lifecycle-owned public drive. It does not
open arbitrary cores in response to a URL or request missing blocks from peers.
Every returned metadata or body block must be locally present and pass a signed
proof check. A missing block, changed row, revoked owner, changed core head,
truncation, fork or retirement makes the selection unavailable. Version 1 also
refuses a same-fork append; serving a changed head requires a new selection.
Cleared blocks cannot be served from a stale snapshot cache.

The version 1 retained response ceiling is 64 MiB. Larger files require bounded
single-range requests. Per-request proof and verified-byte budgets also apply,
so unusual metadata or block layouts may be refused even below that ceiling.
`RETAINED_LOCAL_UNAVAILABLE` identifies unavailable selected data;
`RETAINED_LOCAL_LIMIT` identifies a bounded-work limit. Neither error enables a
network fallback.

## Operational acceptance

Qualify the exact source and capability tooling before use. Preserve the
predecessor and an independently verified backup. Keep writers stopped through
issuance and selection, then launch with the protected authority bindings.
Verify exact retained content, all enabled services, identity, unchanged storage
obligations and health on both the first start and a cold restart. Synthetic
tests and a successful HEAD request are insufficient production acceptance.

If a selected head or registry row changes, stop using that selection and prepare
a new independently reviewed one from the resulting state. Never manufacture
finite bounds or copy legacy `anchored` flags into modern proof fields to make
a read pass.
