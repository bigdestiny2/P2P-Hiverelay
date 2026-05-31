# Reply to Ian — #1 root-caused + fixed (v0.9.2), PR #31, v0.9.x custody live

Ian — huge thanks for the #3 end-to-end confirmation, the #2 read, and the PR.
Closing the loop on all of it.

## #1 — found it. Two bugs, both fixed in v0.9.2 (on `main`, `b30226c`).

Your hypothesis (a) was right, and there was a second one stacked behind it that
only surfaced once (a) was cleared:

**1. Linkage (your (a)).** The sweep gates on `entry.custodyIntentId`, but
content seeded over the seed-request channel registers the appRegistry entry
with `custodyIntentId: null` — the binary `seedRequestEncoding` drops the custody
fields (the exact latent drop noted in the `_onSeedRequest` comment). The
intent / receipts / commit / source-retired all live in the `seedingRegistry`
(so `committed:true`, `sourceRetired:true`), but they were never linked to the
appRegistry **entry**, so the sweep had nothing to attest against. Fix: the
sweep now resolves the intent by `addressKey`
(`SeedingRegistry.getCustodyIntentIdByAddressKey`) when the entry lacks it, and
backfills `custodyIntentId` / `retainUntil` / `blindContentId` onto the entry
(persisted, so it survives restart and shows on `/api/anchors?detailed=1`).

**2. Nonce.** Once (1) was cleared, the sweep reached attestation and threw
`challengeNonce must be 64 hex characters`. `_runCustodyExpiryPass` →
`createCustodyNonServingProof` (and the periodic witness scan →
`createCustodyExpiryWitness`) never supplied a `challengeNonce`, and signing
requires one. So **v0.8.27's claim-path witness never actually emitted a proof
through the sweep** — the pure-function + registry-append tests covered the
`validateCustodyTransition` relaxation, but nothing drove the sweep's auto-attest
path. Fix: both self-generate a 64-hex nonce when the caller supplies none (a
relay-signed self-attestation only needs a unique nonce, not a challenger-issued
one; explicit challenge-response callers still pass their own).

Repro + regression: `test/integration/custody-sweep-linkage.test.js` — one
sweep pass backfills a live entry's `custodyIntentId` by addressKey **and**
attests an expired one (full committed chain, retain elapsed) →
`nonServingProofCount: 1`.

**Net for Drop:** re-run intent `278eb…e502` (or a fresh one) after the
foundation fleet picks up v0.9.2 — `nonServingProofCount` should go ≥ 1 within a
sweep tick of source-retired, no out-of-band orchestration needed.

## Your PR #31 — LGTM, merging into the v0.9.2 release.

Exactly the right observability call (your option (ii)), and your redaction
instinct is better than my first pass: I'd briefly exposed raw `retainUntil` /
`blindContentId` on `/api/anchors?detailed=1` for blind entries, then backed it
out in favor of your design — `custodyIntentId` preserved (already public via
`/api/custody/{id}/status`, only the linkage is new), `retainUntil` stays
redacted for blind. I deliberately kept v0.9.2 **out** of the `/api/anchors`
handler and `catalog()` so your PR applies cleanly on current `main` — no rebase
needed.

## v0.9.x custody — live.

- **v0.9.0** — publicly-verifiable blind *key* custody (PVSS over secp256k1):
  `splitForCustody` / `reconstructFromCustody`. Relay holds an opaque,
  guardian-encrypted share it verifies (DLEQ) but never decrypts; any t-of-n
  guardians reconstruct client-side.
- **v0.9.1** — made the dealer→relay path work end-to-end (the split now
  triggers the per-relay custody seed; public status surfaces `receipts[]`).
- **v0.9.2** — the sweep fix above.

Foundation fleet is on v0.9.1; v0.9.2 rolling out now. A real
`splitForCustody` → `reconstructFromCustody` round-trip is verified against a
production relay over the public DHT. Docs: `docs/PVSS-BLIND-CUSTODY.md`.

## Ops

- **utah (144.172.101.215)** HTTP is back — the listener had wedged; the v0.9.x
  rollout restarted it. `200` now.
- **Tags** — creating annotated tags on origin for `v0.8.27`, `v0.9.0`,
  `v0.9.1`, `v0.9.2` (was untagged — good catch).
- **milkyb 2/3 DHT discovery** — reads env-side (post-deploy announce lag from
  your machine); happy to compare notes if it persists, but the foundation
  evidence stands.

Thanks again — the precise repro + the PR made this a fast turnaround.
