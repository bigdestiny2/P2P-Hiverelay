# Alternative Designs Deep Review - 2026-06-29

## Scope

This reviews the two actual adversarial-review alternative specs supplied after
the earlier release-scope reconstruction:

- `/Users/localllm/Projects/SPEC-RELAYKERNEL-v1.md`
- `/Users/localllm/Projects/SPEC-HIVEMESH-v1.md`

This note supersedes the speculative parts of
`docs/RELEASE_SCOPE_ALTERNATIVES_2026-06-29.md`. That earlier note correctly
identified "narrow release, broad ecosystem" as the likely direction, but it did
not have the real Alt A / Alt B documents.

## Executive Verdict

**Do not implement either spec literally as the next HiveRelay/Blindspark
release.** Both specs are deliberate break-glass redesigns, not safe patch
plans. They are not wire-compatible with HiveRelay, both require conformance
suites that do not exist yet, and RelayKernel as written drops the current
browser/appliance HTTP gateway contract that PearBrowser and Blindspark rely on.

The best path is:

1. **Next release:** ship a narrowed Blindspark/Core Availability release from
   the current codebase, with services and module claims de-emphasized.
2. **Parallel extraction:** start a RelayKernel-compatible profile/spec
   implementation as a sidecar or package, not a replacement.
3. **Later end-state:** promote custody/witness into HiveMesh-style T2/T3 only
   after RelayKernel conformance exists and the payment/witness/vault-directory
   problems have working evidence.

In short: **RelayKernel is the right immediate design direction; HiveMesh is the
right long-term custody architecture.** The optimal release should borrow
RelayKernel's small promise and conformance discipline, not its hard cut-over.

## What RelayKernel Proposes

RelayKernel is Alt A: a minimal relay binary with exactly five protocol
channels:

- `rk-seed`: signed leases for durable Hypercore/Hyperdrive seeding.
- `rk-proof`: per-block proof-of-retrievability.
- `rk-circuit`: NAT traversal.
- `rk-meta`: identity, capabilities, signed directory.
- `rk-accounting`: signed OS-grounded storage/bandwidth receipts.

Everything else becomes a layer-2 app: custody, anchoring, publishing, billing,
AI, ZK, VRF, poker, arbitration, and witnesses.

### Strong Parts

- **Scope control is excellent.** The relay has three jobs: seed, circuit,
  prove retrievability. This is the cleanest answer to the "HiveRelay became a
  platform inside a daemon" critique.
- **Conformance-first is the right protocol posture.** A checked-in binary
  vector suite is the strongest proposal in either spec. Without it, open
  protocol remains mostly narrative.
- **OS-grounded accounting is correct.** Defining signed storage receipts
  against on-disk usage avoids repeating Hypercore API drift failures.
- **Opt-in directory is a real privacy improvement.** It fixes the global
  enumerable-relay problem without giving up discovery for operators who want
  to be found.
- **Layer-2 release cadences are sane.** A custody bug should not force a relay
  release, and a relay patch should not invalidate custody flows.
- **Proof honesty is good.** It labels T1 proof as proof-of-retrievability, not
  proof-of-replication.

### Release Blockers

- **It is not wire-compatible.** The spec says migration is a cut-over. That
  makes it unsuitable as the immediate Blindspark release path.
- **It omits the current HTTP gateway contract.** The current release depends on
  `GET /.well-known/hiverelay.json`, `GET /catalog.json`, and
  `GET /v1/hyper/:driveKey/*path`. RelayKernel's core channel list has no
  browser gateway. If RelayKernel replaces HiveRelay as written, PearBrowser
  and the Umbrel appliance lose a critical public surface unless a separate
  `rk-gateway` or compatibility wrapper is specified.
- **"Exactly five channels, no others" conflicts with layer-2 registration.**
  Section 2.2 says RelayKernel exposes exactly five protomux channels, while
  section 5 says layer-2 apps register their own channels advertised in
  `rk-meta`. That can be reconciled if the relay only brokers app channel
  discovery and the app owns the actual protomux handler, but the process and
  isolation model must be nailed down.
- **The 2,000-line target is probably unrealistic.** Hypercore storage,
  Hyperswarm transport, circuit limits, proof verification, accounting,
  leases, nonce replay windows, and conformance adapters will exceed that unless
  the "line count" excludes dependency glue and distribution code. Treat it as
  a pressure, not a contract.
- **Role prefixes need cryptographic domain separation.** Prefixes like `rk1`
  and `rkp` are encoding labels, not independent Ed25519 key spaces. If the
  same raw key material is reused across roles, signatures can verify unless
  every signed payload includes role/channel/domain bytes. The spec should
  require per-role key derivation or explicit signature domains.
- **Proof verification is underspecified for cross-implementation parity.**
  The Merkle path, `sigRoot`, and recent `core.head` verification rules need
  concrete Hypercore version semantics in the conformance vectors.

### Best Use

RelayKernel should become the **extraction target**:

- a "kernel mode" profile inside current HiveRelay first,
- then a separate `relaykernel` reference implementation,
- with conformance vectors before any compatibility claim.

It should not be the next public appliance release.

## What HiveMesh Proposes

HiveMesh is Alt B: a three-role network with tier-specific binaries and keys:

- **T1 Seed Relay:** public availability, circuit relay, HTTP gateway, anchor
  proofs, T1 directory, Lightning pin leases.
- **T2 Custody Vault:** atomic blind custody only, no gateway, no circuit, no
  content DHT participation, `proveHeld` commit-reveal.
- **T3 Witness:** tombstone signing, bandwidth co-signing, witness directory,
  paid from escrow and slashed for false tombstones.

HiveMesh explicitly says the Umbrel/StartOS appliance is T1-only.

### Strong Parts

- **It makes blind custody structurally true.** T2 has no gateway, no circuit,
  no DHT content announcement, and no public directory by default.
- **It preserves HiveRelay's actual invention.** Atomic blind custody, witness
  tombstones, and stronger custody proof are not thrown away; they move into
  the roles where their trust model belongs.
- **Publisher-selected witnesses fix a real capture risk.** A vault cannot pick
  its own witness quorum because the signed intent names the T3 set.
- **Allowlist validation is the right custody validator.** The old denylist can
  always miss `caption`-style smuggling. Fixed per-message field allowlists are
  much cleaner.
- **Tier-scoped reputation is a strong Sybil-resistance improvement.** T1/T2/T3
  scores cannot be inflated by the wrong key type.
- **The spec is honest about proof strength.** T1 is retrievability; T2
  `proveHeld` is stronger but still window-dependent.
- **It acknowledges "A first, then B."** The migration section says
  RelayKernel conformance should become the foundation for HiveMesh T1.

### Release Blockers

- **It is even less shippable than RelayKernel today.** It needs three
  binaries, three directories, three conformance suites, escrow, slashing,
  cross-tier client SDK logic, and migration tooling.
- **T2 discovery is unresolved.** T2 is intentionally not discoverable, but the
  spec also admits a paid curated vault directory is necessary infrastructure.
  That directory is outside v1 scope, so a new publisher has no complete,
  product-grade way to choose vaults.
- **T3 economics are underdesigned.** Lightning hold invoices, escrow
  distribution, OP_RETURN fallback, and witness redemption are not small
  details. The open questions include the actual fallback redemption script.
- **Slashing is mostly reputation-level, not enforceable collateral.** The spec
  says witnesses are slashed for false tombstones, but the described mechanism
  is reputation marks and directory gossip. If "slashable" implies monetary
  penalty, collateral custody and dispute resolution are missing.
- **"No answer means not serving" needs tighter semantics.** A failed T2
  `proveHeld` challenge may mean not serving, offline, censored, partitioned,
  overloaded, or under attack. For expiry tombstones that may be enough, but
  for false-tombstone slashing it needs observation diversity, retry policy,
  and clock/window rules in vectors.
- **Key-type enforcement alone does not prevent one process/operator from
  running all roles.** The spec notes cross-tier Sybil as a client heuristic.
  That is honest, but it means the structural security claim is "role
  separation by protocol," not "operator separation by construction."
- **The custom T2 storage layout is a major implementation fork.** A
  Hypercore-compatible block/tree layout owned by HiveMesh may be good for
  accounting, but it also increases maintenance cost and cross-version risk.

### Best Use

HiveMesh should be the **custody end-state**, not the next release:

- Harvest T1/T2/T3 role language for docs now.
- Implement custody allowlists in current or extracted custody modules.
- Delay paid witnesses until escrow, slashing, and vault discovery are
  specified enough to test.

## Cross-Spec Findings

### Finding 1: Both Specs Are Correct To Strip The Appliance

Both alternatives reject the current "everything in the relay" posture. That
critique is sound. Blindspark should not ship as a service marketplace, payment
network, AI provider, poker substrate, package registry, and custody network in
one public story.

### Finding 2: RelayKernel Is The Necessary First Cut

HiveMesh itself endorses "A first, then B": extract the relay as RelayKernel,
then split custody/witness into T2/T3. That is the right sequence. Jumping
straight to HiveMesh means solving conformance, vault discovery, witness
economics, and migration all at once.

### Finding 3: Current Browser HTTP Surfaces Must Survive

The current ecosystem needs:

- `GET /.well-known/hiverelay.json`
- `GET /catalog.json`
- `GET /v1/hyper/:driveKey/*path`

RelayKernel as written does not carry these as first-class release surfaces.
For a real Blindspark release, keep them. Options:

- Keep them in HiveRelay/Blindspark while RelayKernel develops in parallel.
- Add a thin `rk-http-gateway` layer-2 app and make it part of the Blindspark
  appliance profile.
- Treat HTTP as distribution packaging, not core protocol, but still require
  release evidence for it.

Do not release a home-server appliance that only speaks protomux unless
PearBrowser and other consumers have already migrated.

### Finding 4: Conformance Is Non-Negotiable

Both specs rely on conformance suites as the thing that turns design into
protocol. The current repo has many tests, but not a frozen protocol vector
suite. Before claiming RelayKernel or HiveMesh compatibility, ship:

- binary fixtures for every message type,
- expected parse objects,
- expected reject codes,
- semantic state-machine vectors,
- version negotiation vectors,
- adapters for current JS implementation.

Implementation note: the checked-in vector suite now includes
`seed-protocol-binary-v1`, which pins HiveRelay seed-request/accept/deny/unseed
compact-encoding frames, decoded objects, and malformed-frame reject codes
against the current JS implementation. This is a first seed-channel fixture,
not a full RelayKernel conformance claim.

Implementation note: the vector suite now also includes
`seed-protocol-handshake-v1`, pinning seed-channel version negotiation before
pending seed requests replay. Same-major future minor versions are accepted,
major mismatches close, and malformed or oversized handshakes close.

Implementation note: the checked-in vector suite now also includes
`circuit-protocol-binary-v1`, pinning reserve/connect/status/data/ready/close
compact-encoding frames plus malformed-frame reject codes for the current
HiveRelay circuit compatibility channel.

Implementation note: capability documents now carry a signed
`directory_privacy` posture. RelayKernel-profile docs advertise
`relaykernel-private` unless a future explicit directory opt-in is added, while
the existing signed-directory service is marked as `global-directory-opt-in`.

Implementation note: capability documents now also advertise
`circuit-limits-profile-v1` with signed `protocol_profile.circuit_limits`
metadata, binding the current circuit relay's hard caps and security checks to
the RelayKernel circuit-limits vector without changing the Blindspark transport.

Implementation note: the vector suite now includes
`capability-doc-signature-v1`, pinning signed capability-doc canonicalization,
the RelayKernel-compatible meta claims, downgrade-sensitive signature-domain
advertisements, directory privacy, opt-in freshness-window verdicts, and a
tamper case that must fail signature verification.

### Finding 5: Prefixes Must Be Domain-Separated

Both specs use prefixed Ed25519 keys. Good for UX and routing, but insufficient
unless signatures include:

- protocol name,
- role prefix,
- channel name,
- message type,
- version,
- canonical payload.

Otherwise raw key reuse can blur roles. The specs should say "MUST use
domain-separated signatures" everywhere, not only "the prefix is checked."

Implementation note: current hiverelay seed-request verification now accepts a
preferred `hiverelay.seed-request.v3` domain-separated preimage before falling
back to legacy v2/v1 layouts for compatibility. Capability documents advertise
this with the signed `seed-signature-domain-v3` feature and
`protocol_profile.signature_domains.seed_request`.

Implementation note: publisher-signed HTTP and `hiverelay-publish` seed ingress
now also support an opt-in `hiverelay.seed-request.replay-v1` signature profile
that signs `issuedAt` plus a 16-byte `requestNonce`; relays reject duplicate
publisher nonce submissions locally without changing the legacy Protomux
seed-request frame.

Implementation note: `relaykernel-meta-profile-v1-opt-in-directory` now also
pins reserved app-capability namespaces, and
`relaykernel-meta-profile-v1-reserved-namespace-reject` pins the negative case.
Layer-2 apps may advertise `custody-v1`/`publish-v1` style capabilities, but
the profile rejects apps that claim RelayKernel/HiveRelay/HiveMesh-looking names
or channels such as `rk-wallet`, `seed-request-v1`, `hiverelay-forward`, or
`t2-witness`. This gives us the role-separation benefit without changing the
live service registry yet.

### Finding 6: Proof Claims Need Front-Page Honesty

This is one of the strongest improvements. The next release should immediately
rename/describe current `proveSeeded` as proof-of-retrievability unless and
until a stronger T2 `proveHeld` path exists.

Implementation note: current hiverelay now exposes an opt-in
`retrievability-proof-v1` domain-separated proof signature profile through the
HTTP proof route, SDK sampling driver, service manifest, and signed capability
document while keeping legacy proof bytes as the default compatibility path.

Implementation note: `proveSeeded` sampling now uses libsodium-backed uniform
random block selection instead of `Math.random()`, with focused client coverage
for distinct in-range samples and head clamping. This keeps the current API but
makes adversarial proof-of-retrievability probes harder to predict.

Implementation note: the client also now uses libsodium-backed random suffixes
for fresh local drive/share-bundle names, removing the remaining `Math.random()`
identifier source from `packages/client/index.js` without changing public APIs.

Implementation note: relay-side proof challenge validation is now centralized
before keypair, registry, or storage work. The provider rejects malformed
`coreKey`, `nonce`, unsupported signature profiles, and unsafe/non-`uint32`
block indices as cheap protocol-edge failures, with HTTP coverage pinning
oversized indices to `400 BAD_INDEX`.

### Finding 7: OS-Grounded Accounting Should Move Into Current HiveRelay

Both specs independently make OS disk usage the signed accounting source. That
is a concrete improvement we can adopt without a wire-protocol rewrite:

- signed storage receipt uses OS-measured storage,
- disk guard trips from OS-measured usage,
- Hypercore API counters stay dashboard-only.

### Finding 8: Allowlist Custody Validation Is Worth Pulling Forward

Even before HiveMesh, custody message validators should move from denylist to
per-message allowlists. This is a small change with a large security payoff.

Implementation note: custody normalization now applies the per-type allowlist
before the recursive secret-field scan in both core and client signer copies.
`caption` and `dataKey` are pinned as `unknown custody field` rejections in
`custody-allowlist-v2-strict`, while the secret scan remains as
defense-in-depth for nested content inside otherwise allowed containers.

## Comparison Matrix

| Dimension | Current HiveRelay | RelayKernel | HiveMesh |
| --- | --- | --- | --- |
| Next-release viability | High if narrowed | Low as replacement, high as profile target | Low |
| Wire compatibility | Current | None | None |
| Browser gateway | Present | Missing/unspecified | T1 includes gateway |
| Custody model | In broad relay process | Layer-2 app | Dedicated T2/T3 roles |
| Proof honesty | Mixed naming | Strong PoR honesty | Strong T1/T2 distinction |
| Accounting | Improved, but still mixed surfaces | OS-grounded by spec | OS-grounded by spec |
| Directory privacy | Global-ish current surfaces | Per-app + opt-in global | T1/T3 dirs, T2 out-of-band |
| Release complexity | Already too wide | Manageable after extraction | Very high |
| Review/store posture | Needs narrowing | Excellent if HTTP gateway added | T1 excellent, full mesh not appliance-ready |
| Long-term architecture | Powerful but bundled | Best kernel baseline | Best custody end-state |

## Recommended Release Strategy

### 1. Ship Blindspark Core Availability First

The next release should remain the current codebase, but with the public
promise narrowed:

- availability seeding,
- circuit relay,
- browser HTTP gateway,
- catalog/capability surfaces,
- review-mode appliance UI,
- storage and served-byte accounting,
- proof-of-retrievability,
- release evidence.

Do not market AI, poker, custody, payments, registry, global search, or
services as part of the appliance guarantee.

### 2. Define A "RelayKernel Profile" Inside Current HiveRelay

Before a new repo, define a mode/profile that approximates RelayKernel without
breaking consumers:

- services profile-locked off,
- custody profile-locked off,
- no legacy global directory inside the profile,
- OS-grounded accounting receipts,
- proof docs say PoR, not PoRep,
- stable public HTTP compatibility kept,
- conformance-vector work begins against seed/proof/circuit/meta/accounting.

This gives us a release-safe bridge from broad HiveRelay to RelayKernel.

### 3. Build RelayKernel In Parallel, Not In Place

Create RelayKernel as a reference implementation only after the profile and
vectors are credible. Migration should be:

1. HiveRelay exposes a compatibility adapter.
2. RelayKernel passes the vector suite.
3. New publishers can target RelayKernel.
4. Existing leases expire or are translated.
5. Blindspark decides whether to package HiveRelay-core or RelayKernel.

### 4. Treat HiveMesh As Custody v2

Adopt now:

- T1/T2/T3 vocabulary in architecture docs.
- T2 no-gateway/no-DHT principle for blind custody.
- T3 witness separation as an explicit future product.
- custody allowlists.
- publisher-selected witness quorum.

Implementation note: custody status summaries now accept an optional
publisher-selected witness policy and surface an `expiryWitnessQuorum` verdict
computed from already-valid witness tombstones. This keeps default Blindspark
status output unchanged while making the HiveMesh 5-of-7 witness policy testable
from the current client/core custody code.

Do not adopt yet:

- paid T3 witness network,
- OP_RETURN fallback,
- slashing claims,
- curated vault directory promises,
- three-binary migration as a release blocker.

## Concrete Decision Gates

### Gate A: Next Blindspark Release

Ready when:

- GHCR image digest and smokes pass.
- Umbrel package smoke passes against that exact digest.
- Browser surfaces still work.
- `proveSeeded` docs say PoR honestly.
- module/service features are optional or beta in public copy.
- fleet/store/StartOS claims have sidecar evidence or are not claimed.

### Gate B: RelayKernel Profile

Ready when:

- current HiveRelay can run with non-kernel modules locked off by the profile.
- OS-grounded storage receipts exist.
- legacy signed-directory behavior stays opt-in outside the profile.
- seed/proof/circuit/meta/accounting contracts are documented.
- first conformance fixtures exist and run against the current implementation.

### Gate C: RelayKernel Replacement

Ready when:

- the standalone implementation passes 100% of vectors.
- HTTP gateway compatibility is solved.
- compatibility client translates old seed flows.
- migration runbook exists.
- a non-production fleet can run mixed HiveRelay + RelayKernel nodes.

### Gate D: HiveMesh Custody

Ready when:

- T2 vault discovery has a real answer.
- T3 witness payment and fallback redemption are specified and tested.
- false-tombstone slashing semantics are testable.
- cross-tier Sybil warnings are implemented in SDK.
- T2/T3 conformance vectors pass.

## Open Questions For Us

1. Is Blindspark's next public product name **Core Availability** or
   **T1 Seed Relay**?
2. Should current `p2p-hiveservices` stay published in lockstep during the
   narrowed release, or should service packages begin independent versioning?
3. Do we add an `rk-http-gateway` spec now, or keep HTTP as a Blindspark
   compatibility surface outside RelayKernel?
4. Should custody allowlists be backported before the next release, or staged
   as the first RelayKernel-profile hardening task?
5. Is `proveSeeded` naming acceptable if docs say PoR, or should the public API
   grow an alias like `proveRetrievable`?

## Decision

Use **RelayKernel as the extraction blueprint**, **HiveMesh as the custody
end-state**, and **current HiveRelay as the release vehicle**.

The optimal near-term release is not a cut-over. It is a disciplined narrowing:
ship Blindspark as a verifiable T1/core-availability appliance, keep current
browser contracts alive, and stop spending the relay's trust budget on modules
that should have their own specs, binaries, and evidence.
