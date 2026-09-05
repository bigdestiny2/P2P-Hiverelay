# Node encrypted intent backend — private qualification slice I01

`NodeIntentBackend` implements the existing `EncryptedIntentStore` backend
contract: `read(key)` returns `{ revision: bigint, ciphertext: Uint8Array | null }`
and `compareAndSwap(key, expectedRevision, ciphertext)` returns a boolean. Use it
with the caller's authenticated intent sealer. The backend receives no encryption
key or decoded intent and cannot verify whether caller-supplied bytes are encrypted.
It persists opaque ciphertext plus the random intent ID, revision and structural
checksum. The sealer authenticates the ciphertext's key/revision binding.

```js
import { NodeIntentBackend } from '@hiverelay/blind-intent-store-node'

const backend = new NodeIntentBackend('/canonical/private/intent-directory')
await backend.ready()
// Pass backend to the existing EncryptedIntentStore together with your sealer.
// Keep that sealer and its key in the caller, outside this directory.
await backend.close()
```

This package is private and separately installable with `npm ci --prefix
packages/blind-intent-store-node --workspaces=false`. Its own lockfile pins the
explicit `fd-lock@2.2.0` dependency closure. It does not extend the frozen client
or browser exports, register a root workspace, enable a production profile, or
claim Bare, browser, network-filesystem or Windows support. Node 22 on Linux and
macOS are the qualification targets.

## Ownership and commit semantics

One open backend holds one exclusive OS file lock for its entire lifetime. A
second process/session fails with `INTENT_STORE_LOCKED` until the first closes
or exits. The stable `.writer-lock` inode is never replaced or removed. There
is no PID file, stale-lock timeout or lock stealing. Call `close()` to drain all
admitted operations and release the lease. New operations are rejected as soon
as close starts. A close failure remains visible to the caller. The backend
attempts to release the writer lease even if closing the directory handle fails;
only a fulfilled `close()` proves that all admitted work and handles drained.

The root is a canonical absolute path with no symlink ancestors. Its existing
parent must be trusted; the backend creates only the final directory. Root mode
is exactly `0700`; regular files are exactly `0600`, owned by the current UID and
single-link. Ancestors must be owned by root or the current UID; writable
ancestors require the sticky bit. Resolve platform aliases such as macOS `/var`
before providing the path. Root and lock inode identities are checked throughout
operations. Record opens reject symlinks and special files without blocking.
This custody model trusts processes running as the same UID and the host
administrator; it does not provide isolation from a malicious peer with those
privileges or rollback protection against a whole-directory backup replacement.

Keys are exactly `intent:` followed by 64 lowercase hexadecimal characters.
Missing records alone return revision `0n` and null ciphertext. Committed records
have positive u64 revisions and a bounded length, embedded key and SHA-256
checksum. Wrong framing, truncation, checksum failure and unsafe custody throw;
they never become an empty intent. The checksum detects structural corruption,
and is not a replacement for the caller's authenticated encryption.

A successful CAS reads the current record under the writer lease, checks the
exact revision, writes the next complete record to `.pending`, synchronizes that
file, atomically renames it over the committed record, and synchronizes the
directory before returning `true`. Initialization also synchronizes the lock and
the root's parent directory, including recovery from an interrupted mkdir.
Revision conflict returns `false` without changing any record. Revision overflow
is rejected. Only the reserved unpublished `.pending` slot is discarded during
reopen; committed data is never silently repaired or promoted from that slot.

Errors during publication/synchronization throw `INTENT_STORE_COMMIT_UNKNOWN`
and latch the session. Ready/read/queued/future operations then fail until close
and reopen. An unknown outcome may recover either the prior or next complete
revision; it is never a durable-send license. Reconcile through the existing
encrypted intent state machine and preserve logical ID, nonce, commitment and
exact operation bytes. `SENT` becomes `PENDING_UNKNOWN` in caller recovery, not by
creating a replacement logical operation. Successful fsync semantics depend on
the filesystem and storage device; SIGKILL tests exercise process crashes, not
physical power-loss guarantees.

## Bounded work and enumeration

At most eight operations are admitted, including the active one. Excess work
rejects with `INTENT_STORE_BUSY` before retaining a ciphertext copy. Admitted
ciphertext is copied synchronously so subsequent caller mutation cannot change
the write. The maximum ciphertext is `8 MiB + 292` bytes, covering the existing
intent's maximum operation/result payload, header and AES-GCM sealing overhead.

`keysPage({ cursor: null, limit: 64 })` starts an unordered, session-scoped scan
and returns `{ keys, cursor }`. Pass the returned cursor until it becomes null,
or call `closeScan(cursor)`. Each call reads at most `limit` directory entries
with `opendir` buffer size one; the limit is within 1..256. A page can have no
keys but a continuation cursor when it visits the lock entry. There are at most
four open scans. No scan materializes or sorts the whole directory.

CAS rejects with `INTENT_STORE_BUSY` while any scan is open, so enumeration has a
stable key inventory under this backend's exclusive lease. Reads remain allowed.
Exhaust or close scans before updating intents; cursors expire on close/restart.
Unexpected directory entries or unsafe record metadata fail the scan. Read each
record through `EncryptedIntentStore` to verify its framing and authentication.

The optional `onCommitPhase` callback exposes five private qualification phases
used by process-kill tests. It grants no commit authority. Throwing from it makes
the CAS unknown and fences the session, even after directory synchronization.

## Adoption and rollback

This slice adds a new format in a dedicated directory; it does not migrate any
existing store or change the current client default. Adopt it only after review,
with one caller-owned authenticated sealer and a fresh private directory. Retain
that sealer's key using the application's existing custody procedure. A previous
application build has no reader for this directory, and must not start another
backend against it while the new process owns its lease.

Before a backup, stop admission and await `close()`. Preserve complete committed
records and the separate caller key; restore into a private directory only while
all writers are stopped. Reopen verifies record structure, and the caller must
authenticate and reconcile each intent before sending. A backup restore does not
establish freshness or protect against rollback to older valid ciphertext.

To roll back application adoption, drain and close this backend, then retain its
directory for reconciliation with the same sealer. Never erase or recreate an
uncertain intent to make an older application proceed: an already sent operation
may have committed remotely. Returning to an earlier application version is safe
only once its pending operations have been reconciled or it can leave this new
store untouched. No automatic downgrade, data deletion or format conversion is
provided by this qualification slice.
