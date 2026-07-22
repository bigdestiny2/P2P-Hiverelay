# Optional HiveRelay Bare/Pear v3 engineering lane

> **Status: proposed, non-production engineering only.** The separately named
> `hiverelay-bare` artifact, its Pear v3 wrapper, native packages, release
> records, data adapter, and cross-platform runner evidence do not exist in a
> production-ready form yet. This document defines the gate they must satisfy;
> it is not an installation or availability claim.

Pear v3 makes a native application or binary responsible for its embedded
runtime, packaging, storage, update behavior, and recovery. It does not turn a
remote application link into a worker entrypoint. For HiveRelay, that makes a
v3/Bare build an optional distribution lane, not a replacement for the proven
service and appliance estate.

## Distribution boundary

The proposed product is named `hiverelay-bare`. It MUST have:

- a distinct package and release identity;
- one unambiguous executable or application artifact per supported host;
- a new, non-critical canary relay identity and fresh canary storage;
- an externally supervised process with health and last-known-good gates; and
- an AppRelease v2 candidate record that remains non-promotable until its
  native, data, signing, availability, and observation evidence passes.

The existing Node/npm, systemd, Docker, raw-fleet, Umbrel, and StartOS paths
remain the primary operator and recovery paths. A failure in the optional v3
lane MUST be recoverable through those paths without relying on the same Pear
deployment, runtime, publisher, or relay set.

The current `packages/core/pear-entry.js` depends on an ambient Pear global and
Pear-managed application storage. It is retained source evidence for the old
application model, not the v3 entrypoint described here.

## Runtime boundary

The native wrapper owns process lifecycle, configuration, explicit data paths,
update presentation, and supervision. It may start a bundled Bare worker only
from a resolved local path. The following is an architecture sketch, not a
shipped entrypoint:

```js
const path = require('node:path')
const PearRuntime = require('pear-runtime')
const pkg = require('./package.json')

const localWorker = './worker.js'
const runtimeDir = path.resolve(process.env.HIVERELAY_RUNTIME_DIR)
const storageDir = path.resolve(process.env.HIVERELAY_STORAGE_DIR)

const runtime = new PearRuntime({
  dir: runtimeDir,
  storage: storageDir,
  name: pkg.productName,
  version: pkg.version,
  upgrade: pkg.upgrade,
  updates: false
})

const worker = PearRuntime.run(
  require.resolve(localWorker),
  process.argv.slice(2)
)
```

The irreducible boundary is `PearRuntime.run(require.resolve(localWorker))`:
`PearRuntime.run()` MUST receive a bundled local worker entrypoint. A catalogue,
deployment, upgrade, or arbitrary remote link MUST NOT be passed to it. Updates
remain disabled until the health, controlled-restart, and recovery gates below
are implemented and independently verified.

Runtime, worker, Corestore, and Hyperswarm ownership must be explicit. Graceful
shutdown is complete only after the wrapper:

1. stops accepting new relay work and reports a draining health state;
2. asks the worker to close and waits for its bounded acknowledgement;
3. closes the embedded runtime and updater;
4. closes each application-owned Corestore and Hyperswarm exactly once; and
5. reports the final health result to the external supervisor before exit.

The external supervisor, not the embedded updater alone, owns restart policy,
health deadlines, failed-update quarantine, and selection of a last-known-good
artifact. No automatic health rollback is claimed until a real supervisor test
proves it.

## Storage, identity, and migration

Runtime bookkeeping and relay state use explicit, separately configured roots.
The wrapper MUST reject an empty, relative, or ambiguous path and MUST NOT
silently fall back to a new default when an expected relay root is missing.

The first engineering canary uses a new non-critical identity. Reusing an
existing operator identity or pointing the artifact at an existing production
root is forbidden without a separately reviewed, product-specific data adapter.
That adapter follows exactly eight phases:

| Phase | Required result |
|---|---|
| `discover` | Locate supported old and target roots without opening one Corestore in two processes. |
| `fingerprint` | Record public identities, schema/core counts, selected digests, and record counts; never log seeds or private keys. |
| `preflight` | Require the old process closed, acquire exclusive locks, check capacity and permissions, and block divergent populated roots. |
| `preserve` | Create a recoverable snapshot or immutable copy before mutation. |
| `migrate` | Preserve writer/operator identity and directory semantics; do not delete the source. |
| `validate` | Reopen through the new build and prove identity, schema, counts, and a relay-specific read/write smoke. |
| `commitMarker` | Atomically record adapter version, source/target fingerprints, timestamp, and validation digest. |
| `rollback` | Close the new runtime, retain diagnostics, restore or reselect the old root, and prove it remains usable. |

Identity rotation and legacy-data deletion are forbidden by default. Neither a
new storage directory nor a successful process boot is migration evidence.

## Frozen engineering toolchain

The first cohort is tested against these exact archived sources:

| Component | Version | Source commit |
|---|---:|---|
| Pear | `3.0.0` | `5113c8569d9b01881eae2b17de14a0a2935aa515` |
| `pear-runtime` | `1.3.1` | `70898fd9d9bb2dc7eb4cb4acb1cf349c89d1a1fc` |
| `pear-build` | `1.1.0` | `9204b07bac08e8c9cdeb00d1eff92efd760ef692` |
| `pear-install` | `1.2.0` | `5f4c1659d1d1f42099333064c763282edeca6898` |

Future version changes require a new signed record and repeat evidence; they do
not inherit this cohort's results.

## Build output and target matrix

The staged deployment has one root package and host-specific artifacts:

```text
/
├── package.json
└── by-arch/
    └── <host>/
        └── app/
            └── <one unambiguous artifact>
```

The AppRelease tree inventory covers `/package.json` and every file or contained
symlink under `/by-arch`. It binds normalized paths, modes, byte sizes, file
digests, artifact subtree digests, and the complete BLAKE2b-256 tree digest.
Sampling a block or observing a joined swarm is not complete-artifact evidence.

The contract contains every desktop host exactly once:

| Host | Evidence state before a claim |
|---|---|
| `darwin-arm64` | unavailable or built-unproven until a native runner verifies the exact artifact digest |
| `darwin-x64` | unavailable or built-unproven until a native runner verifies the exact artifact digest |
| `linux-arm64` | unavailable or built-unproven until a native runner verifies the exact artifact digest |
| `linux-x64` | unavailable or built-unproven until a native runner verifies the exact artifact digest |
| `win32-arm64` | unavailable or built-unproven until a native runner verifies the exact artifact digest |
| `win32-x64` | unavailable or built-unproven until a native runner verifies the exact artifact digest |

Only a target with matching artifact, platform-signing where applicable, and
native-runner evidence may be presented as available. Local success on one host
does not promote another architecture.

## Release flow and authority gates

The engineering flow is:

1. **Build** the wrapper and local worker into the exact host artifacts.
2. **Verify** the package, inventory, digests, signatures, storage behavior,
   shutdown, and native runner results in an isolated candidate lane.
3. **Stage** the verified tree to a non-production deployment link.
4. **Provision** release authority for the exact staged checkout.
5. **Multisig/deploy** the exact candidate without rebuilding it.

Stage, provision, multisig, real signing, and deployment are human-authority
gates. This repository documentation grants none of them. A test key, local
drive, fixture link, or candidate record MUST NOT be presented as a production
release.

## Installation and update lifecycle

First install is a separate operation from update, repair, reinstall, and
uninstall. The current installer refuses to overwrite an existing target, so
the safe contract is:

| Operation | Required behavior |
|---|---|
| First install | Resolve one verified host artifact, show its identity, destination, size, permissions, and digest, then install to an empty target. |
| Repeat install | Refuse the existing target without deleting or replacing it. |
| Update | Unsupported until app-owned update, health validation, controlled restart, and recovery are proven. |
| Repair | Unsupported until exact file reconciliation and identity preservation are proven. |
| Reinstall | Unsupported; it is not another install call. |
| Uninstall | Unsupported until explicit state-retention and deletion policy exists. |

No one-command install, unattended overwrite, automatic data deletion, or
automatic rollback claim is valid for `hiverelay-bare` today.

## Availability and canary gate

A locally built artifact is not an availability result. Before any production
availability claim, evidence MUST show:

- full cold retrieval of `/package.json`, the tree inventory, and every
  promoted host artifact from fresh reader storage with the publisher offline;
- at least three complete replicas controlled by three independently identified
  operators, with matching tree and artifact digests;
- timestamps, regions, repair results, capacity headroom, and observation
  evidence for those replicas;
- an externally supervised canary observed for at least `86400` seconds; and
- a rehearsed last-known-good recovery that preserves the Node/systemd, Docker,
  raw-fleet, Umbrel, and StartOS paths.

Partial downloads, timed-out prefetches, duplicate endpoints owned by one
operator, sample-block proofs, or a publisher-online read do not satisfy this
gate.

## Current conclusion

`hiverelay-bare` remains a proposed optional canary. Operators should continue
to use the documented Node/systemd, Docker, raw-fleet, Umbrel, or StartOS path
appropriate to their environment. Production adoption requires implementation,
independent review, native proof for promoted hosts, complete multi-operator
retrieval evidence, the observation window, and a separate operator lease.
