# Private Pear intent worker consumer

This private component runs one fixed packaged local worker through
`pear-runtime` 1.3.1 / `bare-sidecar` 0.5.2. The normative Pear 3 cohort is
recorded in `cohort.json`. It supports the observed Bare 1.29.4 sidecar on
macOS arm64 and Linux x64 only. It does not install or invoke global Pear,
create an updater/Corestore/swarm, or select an entrypoint from caller input.
The runtime's instance updater lifecycle is outside this static local-worker
component; no internally created updater store is relied on or left open.

```js
const { PearIntentBackend } = require('@hiverelay/blind-intent-pear-consumer')
const backend = new PearIntentBackend(absolutePrivateAppDirectory)
await backend.ready()
// Pass backend to the existing EncryptedIntentStore and keep its sealing key
// in the caller's separate key custody. Worker RPC carries opaque ciphertext.
await backend.close()
```

The caller owns the private application directory and its parent, retains the
sealing key separately, and decides when all application intent work is done.
No storage path or key is taken from a catalogue, URL, global Pear installation
or environment default. The worker imports byte-identical copies of the
private Bare backend and uses its unchanged framing, writer custody, CAS,
revision, sync and corruption rules. `scripts/stage.mjs` regenerates these
copies and the source digest manifest from the surrounding accepted source.

The host admits at most eight operations before copying ciphertext, including
while startup is pending. The backend retains its four-scan and 256-row limits.
The local JSON pipe represents ciphertext as hex, so a maximum-size record
uses twice its ciphertext length on the pipe; each frame is bounded to twice
the backend ciphertext limit plus 64 KiB. These are component admission bounds,
not application memory/capacity qualification. Operations and shutdown have a
bounded deadline (30 seconds by default); any expired deadline or unexpected
worker exit is unknown and requires reopen/reconciliation.

`close()` stops admission, waits for admitted operations, requests and awaits
the real backend drain/close, then separately awaits process exit and pipe
closure. Only the combination creates `backend.lifecycle`. Killing/destroying
a sidecar cannot produce a graceful-close receipt. Fatal cleanup uses the
specific ChildProcess handle exposed by this pinned sidecar implementation;
it does not target a retained/reused PID. Test-only commit-phase pauses allow
ordinary process-kill vectors and are bounded by the operation deadline.

`backend.runtime` records the actual embedded version, executable digest and
SHA256 digests of files in the actual Bare addon loader registry. This is
local component evidence; it is not platform signing, public availability or
release acceptance. The default `node_modules` closure is established by this
package's own exact lock, with lifecycle scripts disabled in qualification.
In a source checkout, run `npm ci --ignore-scripts --workspaces=false`, then
`npm test` from this directory. The test command regenerates exact source
fixtures, including their private protocol resolver, before running vectors.
Packed-consumer qualification installs the packed files in an isolated tree,
copies the exact own lock (npm excludes package-lock.json from packs), and
replays the source integration suite with `PEAR_CONSUMER_PACKAGE` pointing to
that installed tree. Development scripts and fixtures are not package exports.

Migration retains the complete private intent directory, writer inode and
caller sealing key; stop all old workers first. Node and supported Bare/Pear
backends alternate ownership using the same opaque record format. Never copy
only selected records during active writes, erase unknown outcomes, or replace
a missing sealing key with a fresh key while reusing existing encrypted state.
Rollback closes this worker and reopens with a separately qualified backend
against the same preserved directory and key. No live-store migration is run.

Full I02 remains gated by remaining OS/device/Pear application integration,
capacity, caller lifecycle and key-custody proof. Tests on macOS or Linux do not
establish physical power-loss durability, native Linux hardware behavior when
translated in Docker, Bare threads, mobile, Windows, Darwin x64, Linux arm64,
OS installation, soak, production enablement or independent acceptance.
