# Exact source and partial publication receipts

The artifact stage requires the full admitted Git commit SHA. It archives that
commit into a fresh private directory and compares every extracted file and
executable mode with the committed tree. Dirty tracked files and untracked
checkout files do not enter the archive. Links, special files and archive
attributes that omit or rewrite reviewed files are rejected.

All four public npm packages are packed from this archive with lifecycle scripts
disabled. Every packed file must match a blob in its committed package directory.
The publisher prepares and checks all four tarballs before publishing any. It
publishes those same tarball bytes to `next`; an occupied version must have the
same SHA-512 integrity and SHA-1 shasum before the staging tag can be repaired.

After publication, immutable registry metadata is retried only for an explicit
npm E404, at most 12 reads with a 30-second command timeout and delays starting at
2 seconds and capped at 15 seconds. Authentication errors, transport ambiguity,
malformed metadata and mismatched hashes fail immediately. The tarballs, source receipt
and a flushed per-package progress log survive an incomplete run. A successful
publish acknowledgment is recorded before readback. A process or host failure
between publication and acknowledgment can still leave an unrecorded remote
version; a retry must reconcile that version against the same packed hashes.

The OCI build likewise consumes a fresh verified archive, while its revision
label identifies the admitted SHA. The workflow preserves source and npm attempt
receipts under a run/attempt-specific artifact, including after later failure.
Those diagnostic receipts do not authorize stable labels or fleet promotion.

This binding covers committed application inputs. It does not qualify generated
native dependencies, the image toolchain or actual registry signatures and
provenance. The final complete source still needs public artifact inspection,
real installed-consumer and image tests, signature/provenance verification,
appliance qualification and all 0.27 production gates before fleet rollout.

Local tests use actual Git archives and npm packing with simulated registry
operations. No public version or live fleet change is produced by those tests.
Reverting this change affects future packaging only; immutable remote versions
from a partial live run must still be reconciled, never overwritten.
