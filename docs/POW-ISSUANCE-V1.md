# pow-issuance-v1 — PoW-issued one-use admission tokens for the blind relays

Status: implemented and drill-verified locally; fleet rollout is a separate
owner-gated step. Owner decisions: D1 (cells + INBOX-pointer discovery), D2
(PoW-issued one-use tokens); lane plan
`02-apps/peerit/docs/T2-BROWSER-WRITES-LANE-PLAN-2026-08-06.md`.
Spec anchor: master spec §14.1 `open-admission-v1` — "bounded request-bound
proof-of-work" is a named generic OPEN mode.

## 1. Scheme shape

```
client                issuer (operator-run, per relay)                relay daemon (redeemer)
  |  GET /challenge  →  fresh random challenge (HMAC-signed, TTL)        |
  |  mint PoW: sha256 leading-zero-bits ≥ difficulty                   |
  |  POST /redeem {challenge, nonce, recordCommitment, allowance?}     |
  |                  ←  one-use HMAC token (bound, expiring)           |
  |  CELL.PUT / INBOX.CREATE / INBOX.APPEND with admission.token  →  → |  verify locally in the
  |                                                                    |  sandboxed adapter script
```

One PoW mints one token with `allowance` ∈ 1..8 spend units (issuer default 2,
fleet policy caps at 2). Each unit is spent independently and is **one-use per
relay** (storage-owned spend markers, as for every admitted op). Both fleet
relays share the issuer key, so one token covers CELL.PUT + INBOX.APPEND **on
both relays** without re-minting.

**Request binding (no unbound units).** The token commits to the ordered list
of the `allowance` request commitments the minter intends:

```
recordCommitment = HMAC-SHA256(BIND, u8(allowance) ‖ c₀ ‖ … ‖ c_{a-1})
presentation     = token ‖ u8(spendIndex) ‖ sibling commitments (slot order, spendIndex omitted)
```

The adapter reconstructs the list with `c[spendIndex] = requestCommitment` of
the request being admitted and requires equality with the signed
`recordCommitment`. Every spend is bound to its canonical `requestCommitment`
(spec §14.1: "an intercepted token cannot authorize a different slot, blob,
lease, or operation"). The PoW is over `challengePayload ‖ recordCommitment ‖
nonce`, so work cannot be replayed across challenges or records.

**SHA-256-only, deliberately.** Every derivation uses SHA-256/HMAC-SHA256,
never blake2b: the production daemon admission contract is a sandboxed
synchronous import-free script (`production-entrypoint.js`) with no crypto
host APIs, and browser minters run under strict CSP. The sandbox adapter
(`pow-issuance-v1/sandbox-adapter.js`) carries a pure-JS SHA-256/HMAC
implementation of the same derivations; the test suites pin byte-parity with
`token-codec.js` (node:crypto).

## 2. Wire formats (all integers big-endian)

```
challengePayload = u8(1) ‖ challengeId:32 ‖ issuedAtUnix:u32 ‖ ttlSeconds:u32 ‖ difficultyBits:u8   (42 B)
challenge        = challengePayload ‖ HMAC-SHA256(K_challenge, challengePayload)                    (74 B, base64url)

tokenPayload     = u8(1) ‖ u8(schemeVersion=1) ‖ challengeId:32 ‖ recordCommitment:32
                   ‖ u8(allowance) ‖ u32(expiryEpoch)                                               (71 B)
token            = tokenPayload ‖ HMAC-SHA256(K_token, tokenPayload)                                  (103 B)

admission.token  = token ‖ u8(spendIndex) ‖ siblings:32×(allowance-1)              (104 + 32·(a-1) B)
PoW preimage     = POW ‖ challengePayload ‖ recordCommitment ‖ nonce:u64           (sha256, leading-zero-bits)
spendTag         = HMAC-SHA256(SPEND, token ‖ u8(spendIndex))                                       (32 B, deterministic)
```

Key schedule from one 32-byte fleet issuer master key:
`K_token = HMAC(master, KEY‖"token")`, `K_challenge = HMAC(master,
KEY‖"challenge")`. `issuerRelayKey` in `AdmissionParametersV1` =
`HMAC(COMMIT, master)` — a public commitment so clients pin issuer/key
identity across descriptor rotations without exposing the key. `verifierKey`
stays empty (the HMAC key is never published). Domain strings are the literal
ASCII constants in `pow-issuance-v1/token-codec.js`.

## 3. Issuer service (`pow-issuance-v1/issuer-service.js`, `issuer-cli.js`)

Plain `node:http`/`node:https`, no accounts, no database. `GET /challenge`
(default TTL 120 s, difficulty default 20 bits). `POST /redeem` verifies
challenge HMAC + TTL, enforces one-token-per-challenge (in-memory TTL set),
verifies the hashcash, and issues a token with `expiryEpoch = epochNow +
tokenTtlEpochs` (default 2, cap 4 — far inside the spec's 360-epoch credit
ceiling). TLS is enabled via `HIVERELAY_BLIND_POW_ISSUER_TLS_{KEY,CERT}` (the
fleet mode; the issuer shares the relay's public cert on its own port).
Disclosure (owner decision D2): issuer and relay are the same operator;
issuance↔redemption unlinkability is operator-trust at v1, identical boundary
to the relays today. The issuer never logs `recordCommitment`; it holds no
spend-tag database and has no callback into redemption, matching §14.1 role
separation. Upgrade path: blind credentials behind the same adapter contract.

Browser issuance is public and credential-free. Every issuer JSON success and
error carries `Access-Control-Allow-Origin: *`,
`Cross-Origin-Resource-Policy: cross-origin`, and `Cache-Control: no-store`;
the issuer never sends `Access-Control-Allow-Credentials`, `Vary`, or
`Set-Cookie`, and never reflects an origin. Known preflights are deliberately
route-bounded:

| Path | Status | `Access-Control-Allow-Methods` | `Access-Control-Allow-Headers` |
| --- | ---: | --- | --- |
| `/challenge` | 204 | `GET, OPTIONS` | absent |
| `/health` | 204 | `GET, OPTIONS` | absent |
| `/redeem` | 204 | `POST, OPTIONS` | `content-type` |

Each accepted preflight also sends `Access-Control-Max-Age: 600`,
`Cache-Control: no-store`, `Content-Length: 0`, and no body. Unknown `OPTIONS`
paths remain ordinary JSON 404 responses, advertise no methods or headers, and
cannot mint or consume a challenge.

## 4. Daemon integration (sandbox adapter script)

The production daemon loads its admission adapter as a sha256-pinned,
sandboxed, synchronous, import-free script (`HIVERELAY_BLIND_ADMISSION_ADAPTER_
SCRIPT_FILE/_SHA256`, `production-entrypoint.js`). pow-issuance-v1 ships in
that form — **no daemon image change is required**:

- `pow-issuance-v1/sandbox-adapter.js` — the combined resolver template:
  schemeId 9 = the deploy-side publisher pass-through (verbatim, unchanged
  from the live adapter script) + schemeId 1 = the pow-issuance-v1 verifier
  (pure-JS SHA-256/HMAC, binding root, spend tags, 95-byte WAL commit echo).
- `pow-issuance-v1/build-sandbox-adapter.mjs` — injects the fleet issuer key
  into the template, enforces the contract's forbidden-identifier scan, prints
  the exact sha256 to pin in `blind.env`. The key lives only inside the built
  artifact (root/daemon-owned, mode-restricted) — same protection class as the
  previous script.
- `production-entrypoint.js` preserves script-thrown `SPEND_INVALID` through
  the bridge (the previous pass-through never threw, so behavior for scheme 9
  is unchanged); any other script failure stays an opaque execution failure.
- `admission-adapter.js` (module form) is the reference implementation the
  drills pin against; it is not what the fleet daemon loads.

Profile: `AdmissionProfileV1 {profileId 8, schemeId 1, conformanceClass OPEN,
roleBits 49 (DISCOVERY|STORAGE|QUOTA_REDEEMER), parameterUrl, parameterHash}`
with signed `AdmissionParametersV1` carrying `issuanceUrl` + `issuerRelayKey`
and cost rows per the approved public-write bounds (CELL.PUT sizeClass 1–2 ×
leaseClass 1–2; INBOX CREATE/APPEND; READ stays admission-OPTIONAL/uncharged;
no RENEW/WATCH rows → not pow-admittable). schemeId note: the wire schema
keeps no scheme table; 9 is the deploy-side publisher scheme — this note
allocates **schemeId 1 = pow-issuance-v1** as the first production scheme.

## 5. Replay safety summary

Challenge: one token per challengeId (issuer TTL set). Token: HMAC + expiry
epoch + allowance cap. Spend: `spendTag` deterministic per (token, spendIndex)
→ storage one-use marker per relay, atomic with the mutation; descriptor-
refresh replay is deterministic (storage-owned). Binding: every spend
reconstructs the signed commitment root with the live `requestCommitment`.
Cross-relay: shared key, independent markers — one-use *per relay per
allowance unit*, exactly the D2 requirement. Byte-identical and same-request
retries are deterministic idempotent replays by design (storage replays the
stored mutation); spend-unit reuse across *different* requests is what is
rejected (`SPEND_INVALID`).

## 6. Readiness disclosure

INBOX public execution is assembled and drilled; `BLIND_INBOX_RUNTIME_BLOCKERS`
(5 items — final store-format authority publication, shared all-family WAL
dispatch, checkpoint-engine restore, provisional-append reconciliation,
per-connection watch scoping) remain open hardening gaps and stay disclosed in
`status().exclusions`. They do not block serving INBOX. The two static CELL
assembly-requirement blockers are reported statically by this tree even when
wired; functional readiness (`v2WritePathReady`, admission capture complete)
is the honest signal and is asserted by the drill.
