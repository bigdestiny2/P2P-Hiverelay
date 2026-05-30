# Phase 3 — PVSS Blind Custody, End-to-End (Execution Plan)

**Status:** Ready for execution · **Drafted:** 2026-05-30 · **Owner:** localllm

## Goal

An app developer (the *dealer*, e.g. Drop) can, in a few client-SDK calls:

1. **Split** a secret t-of-n across guardian pubkeys (already shipped: `secret-sharing.js`),
2. Hand the encrypted content **and** publicly-verifiable encrypted shares to a quorum of relays for **blind** custody,
3. Have each relay **cryptographically verify** the specific share it holds (against the published Feldman commitments) before anchoring a receipt,
4. Later **reconstruct** the secret client-side from any t guardian decryptions —

…with the relay never able to open the content *or* the shares it custodies.

This closes the gap identified after the prover moved into the client: the PVSS primitive ships and the relay can verify a transcript, but **nothing ties split → custody → verify → reconstruct together**, and **the relay never receives the share it would verify**.

## Decisions (locked)

| # | Decision | Choice | Rationale |
|---|----------|--------|-----------|
| D1 | How the client authors+signs v2 custody intents/commits (can't reach core's v2 signing through the frozen `p2p-hiverelay@0.7.2` pin) | **Self-contain a Bare-safe `packages/client/custody.js`**, pinned by a cross-impl test against core's verifier | Matches the prover precedent (`secret-sharing.js`). Repinning core to 0.8.x would drag the Hyperbee-backed `core/registry` into the client's **Bare** runtime — that fossil pin is load-bearing, not an oversight. |
| D2 | How each custodying relay receives the encrypted share + commitments it must verify (today the seed request carries only the one-way `commitmentRoot` hash) | **Deliver over the replication data plane**: a sibling hypercore (`shareBundleKey`) the relay replicates and reads | Satisfies all three constraints: **no new HTTP**, **no 0.7.2 dependency**, **no seed-request wire-encoding collision**. On-brand for a replication network; blind invariant preserved (shares are guardian-encrypted). |

### Sub-decisions (defaults applied; flag if you disagree)

- **SD1 — share→relay index assignment:** the signed v2 intent carries `shareAssignments` (`[{ relayPubkey, shareIndex }]`). Order-independent, auditable, signed. Relay finds its own pubkey → its index.
- **SD2 — verify-fail policy:** if a relay's assigned share fails `verifyEncryptedShare`, the relay **does not emit an anchored receipt** for that intent and emits a `custody:share-verify-failed` event. The dealer sees the missing receipt and re-deals / re-selects. (Anchoring an unverifiable share defeats the purpose.)
- **SD3 — intent transport:** the *intent/commit* control messages stay on the **existing** custody REST channel (already shipped, tiny, publisher-authed). Only the bulky **share data** moves to P2P. Moving the control plane to P2P is explicitly **out of scope** for Phase 3 (future work).

## Invariants / guardrails (do not violate)

- **Blind by construction:** the relay never sees the secret, never runs `split`, never reconstructs. It holds opaque ciphertext + guardian-encrypted shares it cannot open. It only *verifies*.
- **Bare-safe everywhere in `packages/client/`:** `sodium` + `b4a` only. No node `crypto`, no `Buffer`. (Drop runs on Bare.)
- **Package boundary is real:** the client pins frozen `p2p-hiverelay@0.7.2`. **Nothing new in Phase 3 may require the client to import custody-signing / pvss / seed-request-builder / a changed protocol encoding from core.** The client gets its signing from the self-contained `custody.js` and its crypto from `secret-sharing.js`.
- **Cross-impl agreement, not shared code:** client `custody.js` ⇄ core `custody-signing.js` interop is pinned **by test** (client signs → core verifies, byte-for-byte), exactly like the prover ⇄ verifier.
- **Version-gating:** all new intent fields are v2-only and additive; v1 entries stay byte-identical (preserves existing fleet signatures). Domain tags unchanged.
- **No commit / no deploy without explicit ask.** Local-only until told otherwise.

---

## Workstreams & tasks

Legend: ⬚ = file to create, ✎ = file to edit. Each task lists a Definition of Done (DoD).

### WS-A — Client custody-author module (self-contained, Bare-safe)

> Gives the dealer the ability to *author + sign* the publisher-signed custody family without touching frozen core.

- **A1 ⬚ `packages/client/custody.js`** — port the **publisher-signed path only**: `createCustodyIntent` (v2, with `shareScheme`/`shareThreshold`/`commitmentRoot`/`shareBundleKey`/`shareAssignments`), `createCustodyCommit`, the canonical `custodySignablePayload` + `signableFieldsFor` + version-gating + domain tags + `signCustodyEntry` + `hashHex`, and the `FORBIDDEN_KEYS` guard. Bare-safe: sodium ed25519 (`crypto_sign_*`) + b4a; **no** node crypto/Buffer. Mirror core/custody-signing.js byte-for-byte on the signable payload.
  - **DoD:** module exports `createCustodyIntent`, `createCustodyCommit`, `signCustodyEntry`, `hashHex`, `FORBIDDEN_KEYS`, version constants; lint clean.
- **A2 ✎ `packages/core/core/custody-signing.js`** — extend v2 `SHARE_FIELDS_BY_TYPE['custody-intent']` with `shareBundleKey` (hex hypercore key, 64-hex) + `shareAssignments` (array). Add validators (`shareBundleKey` shape; each assignment `{ relayPubkey: 64-hex, shareIndex: int ≥1 }`, indices distinct, count ≤ `shareThreshold`-related bound). Update `validateCustodyTransition` so receipts' `shareIndex` must match the intent's `shareAssignments` for that relay.
  - **DoD:** new fields normalized + validated; v1 path untouched; existing Phase-2 v2 tests updated to the new schema and green.
- **A3 ⬚ `test/unit/client-custody-crossimpl.test.js`** — cross-impl: client `custody.js` signs an intent + commit → core `verifyCustodyEntry` + `validateCustodyTransition` accept **byte-for-byte**; a tampered field is rejected; v1 (no PVSS) still byte-identical to core.
  - **DoD:** new test green; pins A1⇄A2 agreement.
- **A4 ✎ `packages/client/package.json`** — add `"./custody.js"` export + `files` entry.
  - **DoD:** resolvable as `p2p-hiverelay-client/custody.js`.

### WS-B — Share-bundle delivery + relay verify (P2P data plane)

> Gets the verifiable share material to the relay over replication and slots the verify into receipt creation.

- **B1 ⬚ share-bundle writer (client)** — helper (in `custody.js` or a small `share-bundle.js`) that writes `{ scheme, threshold, commitmentRoot, commitments[], encryptedShares[] }` to a fresh hypercore via the client's existing corestore, returns `shareBundleKey`. Public data only — no secret material.
  - **DoD:** bundle round-trips; `commitmentRootOf(commitments) === commitmentRoot`.
- **B2 ✎ relay: replicate + read the bundle** — when a PVSS intent (`shareScheme` + `shareBundleKey` present) is recorded, the relay replicates `shareBundleKey` (it's already a swarm peer) and reads the bundle. Locate the intent-ingest point (custody-intent REST handler `api.js:~1310` → `seedingRegistry.publishCustodyIntent`) and/or the seed-accept path; kick off replication there.
  - **DoD:** relay obtains commitments + encryptedShares for a PVSS intent; tolerates absent/slow bundle (retry, no crash).
- **B3 ✎ `packages/core/core/relay-node/app-lifecycle.js` `_recordCustodyReceipt` (≈1104–1129)** — if intent is PVSS: verify `commitmentRootOf(commitments) === intent.commitmentRoot`; resolve this relay's `shareIndex` from `intent.shareAssignments`; call `verifyEncryptedShare(commitments, encryptedShares[shareIndex-1])` (pvss.js:246); on success populate receipt `shareIndex` / `shareCommitment` (= `shareCommitmentAt(commitments, index)`) / `shareVerified: true`; on failure apply **SD2** (no anchored receipt + emit event).
  - **DoD:** honest bundle → receipt with `shareVerified:true`; tampered share/proof → no anchored receipt + event; non-PVSS intents unchanged.
- **B4 ✎ registry/index.js receipt creation (≈758–762)** — thread the new receipt fields through `recordCustodyReceipt` → `createCustodyReceipt` so they're signed under v2.
  - **DoD:** signed receipt carries the three share fields; verifies in core.
- **B5 ⬚ relay verify tests** — unit: honest/tampered bundle drives `_recordCustodyReceipt` correctly; `commitmentRoot` mismatch rejected; missing assignment handled.
  - **DoD:** green.

### WS-C — Client orchestration (the DX payoff)

> Two methods that compose the prover + `custody.js` + existing REST custody calls into a one-call flow.

- **C1 ✎ `packages/client/index.js` — `async splitForCustody({ secret?, guardians, threshold, relays, appKey, opts })`**: `split()` → write share bundle (B1) → `createCustodyIntent` (A1) with `commitmentRoot`/`shareBundleKey`/`shareAssignments` (derived from `relays`) → `publishCustodyIntent` to each relay → poll `getCustodyStatus` until `shareVerified` receipts reach `threshold` → `createCustodyCommit` (A1) → `publishCustodyCommit`. Returns `{ intentId, commitmentRoot, key /* dealer-private */, receipts }`.
  - **DoD:** against a local relay, returns a committed PVSS custody with verified receipts; `key`/`secretPoint` never published.
- **C2 ✎ `packages/client/index.js` — `async reconstructFromCustody({ intentId, guardianSecretKeys, relays })`**: read share bundle (via `shareBundleKey` from custody status) → `decryptShare` per guardian → `verifyDecryptedShare` → `reconstruct` → `deriveKey`. Returns `{ key }`.
  - **DoD:** any t guardians recover the dealer key; a forged decryption is rejected.
- **C3 ⬚ `test/unit/custody-orchestration.test.js`** — full client-side round-trip with a stubbed relay/status; threshold + blindness assertions (encrypted shares can't stand in for decrypted).
  - **DoD:** green.

### WS-D — Drop integration + docs

- **D1 ⬚ `packages/client/README.md`** — quickstart (the package has none): install, `new HiveRelayClient(...)`, publish/open/get, and a PVSS blind-custody example (`splitForCustody`/`reconstructFromCustody`).
  - **DoD:** copy-pasteable example runs.
- **D2 ✎ `packages/client/index.js` header docstring** — fix stale import path `'p2p-hiverelay/client'` → `'p2p-hiverelay-client'`.
- **D3 — Drop wiring** — integrate the two methods into Drop's encrypt-key-handoff flow (encrypt note/clipboard with the dealer key; hand the key to blind custody; recover on another device via guardians). *Coordinate with Drop repo — likely a separate PR there.*
  - **DoD:** Drop can blind-custody + recover a key against the fleet.

### WS-E — Ship

- **E1 ✎ version bump + `CHANGELOG.md`** — bump core + client (+ peers) off current; client npm is stale at 0.8.14 vs 0.8.27 local. (No publish without ask.)
- **E2 — fleet deploy of WS-B** (relay changes) — **must precede** any client E2E against the fleet.
- **E3 — live E2E** — `splitForCustody` → fleet → `reconstructFromCustody` on a second client; confirm verified receipts + reconstruction; confirm relay cannot open share/content.
  - **DoD:** green E2E on real relays.

---

## Sequencing & dependencies

```
WS-A (client-only) ─┐
                    ├─→ WS-C ─→ WS-D ─→ (E1) ─→ E2 (deploy relay) ─→ E3 (E2E)
WS-B (core+relay) ──┘                              ▲
                                                   └ E2 also gates on WS-B
```

- **A ∥ B** can proceed in parallel (A is client-only; B is core+relay).
- **C** depends on **A** (signing) + **B** (bundle format + verify contract).
- **D** depends on **C**.
- **E2 (deploy)** gates on **B**; **E3 (E2E)** gates on **C + E2**.
- Tests gate each WS (run `npx brittle test/unit/**/*.test.js` + `npx standard` to green before advancing).

## Risks / watch-items

- **Canonicalization drift (A1⇄A2):** the only thing standing between "client signs" and "relay accepts" is byte-identical signable-payload construction. **A3 must exist before C1** is trusted.
- **Bundle availability timing:** a relay may receive the intent before the share bundle has replicated. B2 must retry; B3 must tolerate "bundle not yet present" without anchoring a bogus receipt.
- **`shareAssignments` ↔ quorum coupling:** dealer must assign indices to the *actual* relays it publishes to; mismatch → no verified receipt. C1 derives assignments from the `relays` arg.
- **Phase-2 test churn:** A2 changes the v2 intent schema → existing v2 vectors in `test/unit/custody-pvss.test.js` need updating (expected).
- **Bare-compat regression:** keep `custody.js` + `share-bundle.js` on sodium/b4a only; add to the Bare smoke path if one exists.

## Definition of done (Phase 3)

- [ ] `custody.js` self-contained + cross-impl test green (A1–A4)
- [ ] Relay verifies its custodied share over the P2P bundle; receipts carry `shareVerified` (B1–B5)
- [ ] `splitForCustody` / `reconstructFromCustody` work end-to-end client-side (C1–C3)
- [ ] Client README + Drop wiring (D1–D3)
- [ ] Full unit suite + lint green; live fleet E2E green (E1–E3)
- [ ] Blind invariant demonstrably intact (relay opens nothing)
