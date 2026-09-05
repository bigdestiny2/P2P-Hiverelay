# Private Bare durable intent backend

`@hiverelay/blind-intent-store-bare` is an additive, private I02 component based on
accepted I01 commit `45616fdfceea43feedf251e4f3572e565d6353fd`. It supplies opaque
`read`, exact-revision `compareAndSwap`, bounded `keysPage`/`closeScan`, `ready`, and
`close` for the existing `EncryptedIntentStore`. It does not implement encryption,
transport, retry policy, total-store quota, deletion, or retention.

The retained qualification targets are **Bare v1.31.0 on macOS arm64 and Linux x64**. The runtime
adapter selects only an explicitly qualified target and verifies its platform,
architecture and exact Bare version. This is not full I02, a Pear SDK release, or production
enablement. Other architectures, packaged/embedded Pear, mobile devices,
network filesystems and physical power-loss behavior remain unqualified.

## Installation and native flags

This package has its own package-lock.json. Install it independently; do not change
the root workspace lock or register a browser/client export:

```sh
npm ci --prefix packages/blind-intent-store-bare --workspaces=false --ignore-scripts
npm test --prefix packages/blind-intent-store-bare --workspaces=false
```

`bare-fs` 4.8.1 does not expose `O_EXCL`, `O_NOFOLLOW`, `O_DIRECTORY`, or
`O_NONBLOCK`; its `wx` spelling cannot supply the missing exclusive bit. The tiny
`native/flags.c` program obtains those values from the target compiler's
`<fcntl.h>`. `node native/build.mjs [evidence-directory]` compiles and executes the
probe on that target and writes `native/flags-<platform>-<arch>.cjs`, with
source/binary hashes and compiler provenance. It never guesses numeric values,
substitutes zero, or trusts another target's artifact. Existing artifact bytes are
preserved; a rebuild with different compiler/probe identity fails and retains its
candidate in the supplied evidence directory. Evidence filenames also include the
target, so collecting Linux proof does not overwrite macOS proof.

The macOS arm64 artifact is byte-identical to its accepted predecessor. The
Linux x64 artifact was compiled with Ubuntu GCC 13.3.0 from the same flags.c. `native/targets.cjs` uses explicit static imports; generating a new
artifact does not enable it. Replay all tests and obtain independent review before
adding another target to that selector. Neither Linux arm64 nor any additional
Bare/Pear version is selected.

There is no new runtime native addon. Existing pinned libraries own native I/O:
`bare-fs` 4.8.1, `bare-buffer` 3.6.1, `bare-crypto` 1.15.3,
`bare-path` 3.1.2, `bare-posix` 1.0.1, `fd-lock` 2.2.0 and overridden
`fs-native-extensions` 1.5.1. The POSIX binding supplies real `getuid()`.
`fd-lock` supplies macOS flock and Linux OFD locking on the stable empty
`.writer-lock` inode. The closure and native prebuild digests are retained in lane
evidence. This guarantee applies to standalone installation with this lock. A
consumer install does not automatically honor a dependency package's lock or its
root-only overrides; packaging must bind and qualify the actual loaded closure. Bare's Number-valued stat identities and sizes must be safe integers;
unrepresentable values are rejected. Short writes are completed with checked,
positive progress and exact offsets before file synchronization.

## Caller integration and durable outcomes

Supply a canonical absolute directory with trusted, non-symlink ancestors. The
backend creates only the final directory with mode 0700. Records, the permanent
writer-lock file and temporary slot require the current UID, mode 0600 and a single
hard link. It pins directory and writer-lock identities and rejects aliases,
special files, substitutions and corrupt committed records.

```js
import { BareIntentBackend } from '@hiverelay/blind-intent-store-bare'

const backend = new BareIntentBackend(canonicalPrivateDirectory)
await backend.ready()
// Caller owns EncryptedIntentStore, authenticated sealer and its separate key.
const store = new EncryptedIntentStore({ backend, sealer })
// ... use the caller's intent state machine ...
await backend.close()
```

A CAS compares the exact u64 revision; conflict returns false. Success returns true
only after a complete record write, file fsync, identity verification, atomic rename,
directory fsync, final identity verification and record close. Any uncertain commit
returns `INTENT_STORE_COMMIT_UNKNOWN`, latches failure and fences queued operations
and subsequent readiness. It grants no send license. Close, reopen and authenticate
and reconcile the same logical intent before deciding what to do next. Recovery
only removes the bounded unpublished `.pending` slot under the exclusive lease;
it never promotes it or treats corrupt committed data as absence.

`HRINDB01` framing is byte-identical to I01: an 84-byte header containing the magic,
big-endian u64 revision, u32 ciphertext length, 32-byte key and SHA-256 checksum,
followed by opaque ciphertext. The checksum is not authentication or rollback
protection. The caller-owned authenticated sealer binds intent ID and revision;
current-UID actors and the host administrator remain trusted, and whole-directory
rollback needs caller freshness/reconciliation controls.

Admission permits eight retained operations, ciphertext up to 8 MiB + 292 bytes,
up to four scans, and at most 256 directory reads per page. Enumeration uses a
one-entry native directory buffer. Internal entries may yield an empty page with a
continuation cursor. Mutations reject while a cursor is live; exhaust or explicitly
close each scan. `close()` stops admission, drains admitted work, closes scans and
the directory, then releases the writer lease. Cleanup continues if a scan close
fails. A possibly completed native file close is never retried on a reused descriptor.
The fd-lock dependency does not surface native lock-descriptor close errors; close
is not a fresh durability proof.

## Qualification, migration and rollback

Tests run actual Bare processes, with Node as the orchestrator and interoperability
peer. They verify compiler-derived flags against Node native constants and real
exclusive/no-follow/directory/nonblocking opens, real file/directory fsync, short and
failed writes, unsafe stats, error fencing, close ownership, exact common vectors,
u64 exhaustion, cross-process leases, five SIGKILL commit boundaries, input and scan
bounds, custody and corruption refusal, and caller AES-GCM SENT-to-unknown recovery
through Bare/Bare, Bare/Node and Node/Bare. The harness probes the native executable
behind the Node `bare` launcher and kills that actual lease holder. It requires
structured child receipts as well as exit status. It stages eleven byte-identical
accepted Node/client/protocol source files under ignored `test/.baseline`, recording
their hashes, so dependencies never mutate the accepted package or root workspace.

After independent review, use a dedicated private directory and preserve the caller
key separately. Node/Bare migration can reuse the exact records only with all writers
stopped, admission drained, the current holder closed, and a verified backup.
Start one backend, authenticate stored intents and reconcile uncertain operations
with the same logical ID, nonce, commitment and operation bytes. Do not replace the
stable writer-lock inode to bypass contention.

Rollback follows the same drain/close and exclusive reopen protocol. Retain all
records and the caller key; do not delete uncertain intents, synthesize new logical
IDs, downgrade the framing, or silently drop unresolved operations. Earlier clients
must leave this private directory untouched unless they implement the same contract.

Before claiming Pear support, package the exact native dependency closure with the
actual application, select its canonical storage directory through the app's verified
Pear storage API, wire application teardown to awaited backend close, and rerun these
contracts on that embedded runtime and supported devices. A global Bare binary,
compiler success, or local process restart does not prove packaged Pear behavior,
untested Linux distributions, controller-cache durability, physical power loss, or fleet production
readiness. Production flags and frozen public artifacts remain unchanged.

Linux x64 qualification uses Ubuntu 24.04.4, glibc 2.39, Node 22.23.2 and Bare
1.31.0 (libuv 1.52.1 / V8 14.8.178.31) in a pinned Docker image on this macOS
arm64 host with x64 translation. Native Linux tmpfs and a dedicated persistent
ext4 volume exercise the shared integration suite, including five process-kill
boundaries and cross-runtime recovery. Separate container lifetimes preserve and
reopen encrypted SENT intents and opaque CAS records. Loaded native libraries,
runtime payload integrity, system libraries and exact image identity are retained
in lane evidence. This is functional qualification on that environment; it is not
native x64-hardware performance evidence or physical-power-loss qualification.
