# Private actual HC11 installation participant v1

This is a Node source-workspace prerequisite for common installation authority.
It owns an actual Corestore, verifies its guarded HC11 activation and keeps
native custody while a private prepared token is live. It does not publish the
common `HRBPA001` journal, acknowledge shared readiness, issue prune authority,
expose a Corestore/writer, or select any public/default runtime. Existing files,
39+13 frozen bindings, protocols, selectors and old capability claims remain
unchanged. Full 0.27 and its release gates remain required before fleet rollout.

The dependency selection is the accepted private HC11 upstream package's exact
77-package lock: Corestore 7.11.1, Hypercore 11.34.1 and hypercore-storage 3.2.0.
Imports resolve through that source package, and absence of its private native
graph refuses root graph fallback. The existing envelope and native FDLock come
from the unchanged root workspace graph. Both locks must be installed; this is
not an independently npm-installable package. Current qualification is Node
22.22.0/macOS arm64 only. Linux, Bare, Pear 3.4, browser, mobile and independent
host/device qualification are open. No substitute cryptography is provided.

## Explicit private interface

```js
import {
  Hc11InstallationParticipantV1, readPreparedHc11Participant
} from './index.js'
import { PROFILE_DIGEST } from '../blind-core-upstream-hc11-v1/format.js'

const participant = new Hc11InstallationParticipantV1({
  root: canonicalEnvelopeRoot,
  rootId: externallyAssignedHc11RootId,
  profileDigest: Buffer.from(PROFILE_DIGEST),
  envelope: externallyPinnedEnvelopeConfiguration,
  timeoutMillis: 10000
})
const prepared = await participant.prepare({ signal })
const observation = await readPreparedHc11Participant(prepared, { signal })
// observation is passive evidence pending a future common coordinator commit.
const closed = await participant.close({ timeoutMillis: 1000 })
```

The envelope configuration has exactly `mode`, `expectedInstallationId`,
`expectedAuthorityKeySha256`, `expectedManifestSha256` and `participant`, using
the existing offline ceremony's externally retained pins. Runtime code never
creates a ceremony or trusts newly synthesized pins. `rootId` is a nonzero
installation-assigned bytes32 identifier, not a filesystem path or inferred
storeId. This prerequisite captures that supplied identity; the future common
coordinator must bind it to authenticated external topology before commit.

`prepare()` reads and authenticates the existing envelope before native open.
It reserves the canonical root within this process, opens the immutable
installation-id inode with O_RDWR/O_NOFOLLOW, acquires actual native FDLock,
and revalidates all directory, authority file and lease identities. This inode
also excludes the existing cooperating device-rebind path. The pinned native
lock uses macOS flock/Linux OFD locks; only macOS is tested here. Kernel/native
lock behavior, not an existence-only lock file, enforces cross-process custody.
The native database owns its separate Corestore/RocksDB lifetime too.

The owned store runs the unchanged `prepareCorestoreGenerationOpen` and
`guardCorestoreGenerationReady` flow. The existing guard performs actual native
ready, one sentinel append/read, and authenticated original trigger publication.
Its historical per-envelope receipt is private inside this owner; it is not a
new common ready acknowledgment. Independently, this component rereads the
actual sentinel and checks exact key, fork=0, length=1, canonical activation
block bytes, signed trigger, pinned envelope, CORESTORE marker and db/IDENTITY.
Checks repeat after asynchronous reads and native session close, including
retained file inode identity. Native directories/metadata never become a blind
WAL tuple. Legacy import and signed device-rebind profiles refuse before native
open: their patched migration and rollback compositions require separate proof.

The WeakMap-branded token is created only after those checks. It exposes no
fields, callback, writer, store, signing key or internal prepared binding.
`readPreparedHc11Participant` revalidates actual native state/custody each time
and returns fresh copies of:

- `evidence`: exact frozen `Hc11Evidence` fields. Envelope/database/block hashes
  retain the existing SHA-256 byte recipes. `triggerReceiptHash` is SHA-256 of
  the exact canonical MAC-authenticated original `hc11-trigger.v1.json` file,
  matching the existing receipt's `triggerRecordSha256`; it is not a mutable
  status projection or newly generated trigger.
- `installationId`: the actual envelope's authenticated bytes32 ID.
- `triggerBytes`: those original signed trigger file bytes, copied intact.
- `sharedAuthorityComposed:false` and `commonReadyAcknowledged:false`.

The common coordinator must compare exact external installation/root/topology
identity, preserve the original trigger bytes and authenticate ancestry. A
prepared token, copied evidence or `status()` cannot grant that authority.
A token from a closed, quarantined or changed owner cannot be read. Reopening
requires a new owner/token and preserves the existing trigger bytes. No global
registration function, injected Corestore, semantic verifier or success
callback can mint a token. Native methods are only wrapped in isolated tests
for delay/failure; their real results are not replaced.

## Cancellation, uncertainty and custody

Only one operation runs at a time per participant. Abort/deadline can reject
the caller before a non-cooperative native operation settles, but that work
and OS custody remain retained. Monotonic deadline checks surround native
boundaries and final return, including delayed timer delivery. Any admitted
verification failure quarantines the owner; restoring files cannot clear the
quarantine or make an old token readable. Native readiness failure may leave
legitimate already-written native/sentinel/trigger bytes for later inspection;
this component does not erase them or claim no mutation after native opening.

`close()` cancels admission, waits for actual outstanding work and closes the
owned Corestore before releasing the native installation lock. It returns
false on deadline or native close failure; false never authorizes replacement
capacity. A late close can later complete. A native close failure stays fenced
and charged until an external recovery/process-lifetime policy handles it.
No force-close, arbitrary scratch cleanup, fresh-authority reconstruction,
old-writer bypass fence or copied-installation stale-floor detector is supplied.
Verified reader availability after common quarantine must be composed with the
common coordinator; this prerequisite makes no all-family reader claim.

## Provisional B/C composition boundary

The conductor agreed this interface direction; it is not implemented here.
Lane B owns a private prepared checkpoint token after exact snapshot/header/
linked manifest publication and body/semantic/lease validation. Its fixed
`readPreparedCheckpointParticipant` revalidates and returns typed BlindEvidence,
never prune authority. C will consume those source-owned tokens and this actual
HC11 token in `commitParticipants`, publish authenticated canonical HRBPA001
and return its private committed-participants token. B's coverage finalizer
must consume C's fixed reader plus its exact prepared token/ancestry/lease
before minting any prune authority. No injected semantic callback substitutes
for either fixed source reader.

C must first establish an already durable baseline/prior Participants record
(revision >=1), with actual original first-trigger raw bytes and authenticated
existing floor/full-WAL history. A snapshot references that ancestor; the later
covering record is appended only after snapshot/header/manifests, avoiding a
hash cycle. Empty blind coverage does not erase irreversible history. Complete
externally pinned topology/floor, all-role custody, shared write/cached-positive
quarantine and conservative crash recovery are mandatory before common commit.
This component implements none of that journal or blind-root bridge and does
not claim full G04, durable intent composition, capture/prune/hydration, every-
append high-water coverage, device restore, publication/images or fleet proof.

Tests use disposable actual fresh envelopes/native databases, genuine signed
activation bytes and cross-process lock checks. They cover reopen, altered
signed files/database identity, same-byte inode replacement, native sentinel
append/fork, directory rebind, cancellation, late native completion and close
failure. Fixture identities and keys are disposable and never production data.

There is no existing source/schema migration. Before future selection, rollback
removes this additive private package. Never remove an actual activated envelope
or original trigger to claim rollback; later operational migration/recovery
needs its own qualification and authorization.
