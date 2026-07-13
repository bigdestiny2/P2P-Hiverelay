# Public T1 HTTPS Gateway — Attack Plan (Peerit-independent)

**Date:** 2026-07-13  
**Branch:** `feat/vnext-gateway-merge`  
**Product:** `public-t1-gateway` only (D-5: separate public product, no privacy claim)  
**Out of scope:** Peerit OutboxLog, Peerit GA, blind Peerit canary (D-1)

---

## 1. Where we are

| Layer | Status | Notes |
| --- | --- | --- |
| Code train | **Done** | Gateway merged with vNext on `feat/vnext-gateway-merge` |
| Storage / physical enforcement | **Done (tests green)** | Cap provenance, lifecycle, registry enforcement |
| Unit + deploy-rehearsal tests | **Done** | 119 gateway unit + 1 deploy rehearsal + storage suites |
| Local canary preflight | **Done** | `mode=canary` pass; expected transitional warnings |
| Nginx template + example config | **Done** | `deploy/public-hive-gateway/*` |
| Canary runbook | **Done** | Staging-ready; fleet gated |
| Owner D-5 | **Decided** | Separate T1 product naming |
| Isolated **staging host** | **Not started** | Needs VPS + DNS + TLS + one app key |
| Live TLS probe preflight | **Not run** | Needs real host |
| 24h observation | **Not started** | After staging is up |
| Frozen T1 admission (non-transitional) | **Blocked** | Still `transitional-operator-allowlist-v1` |
| `--mode fleet` / live fleet canary | **Blocked** | Explicitly fails until frozen admission |
| Publish / GHCR / fleet promote | **Not authorized** | Human authority |

**Admission code today:**  
`packages/core/gateway/public-app-admission.js` → `transitional-operator-allowlist-v1`

**Independence from Peerit:**  
Gateway serves *public app Hyperdrive/bytes*. Peerit social writes use OutboxLog. Staging can use any one public app key (demo static site, pear-pos drive, etc.) — **not** Peerit outbox.

---

## 2. What “done” means for this track (three finish lines)

### Finish line A — Staging canary (this plan’s main target)

Ordinary browser opens:

```text
https://<app-label>.hive-canary.<your-domain>/<path>
```

for **exactly one** trusted public app, with:

- loopback gateway + management split  
- TLS via nginx  
- canary preflight **with live probe** + body SHA-256  
- custody off  
- 24h observation notes  

**Does not require:** frozen blind substrate, Peerit, fleet promotion.

### Finish line B — Software readiness for fleet (engineering, still no live promote)

- Non-transitional T1/T2/T3 admission predicate compiled in  
- Full branch test suite green on release commit  
- Spec single-source + mirrors  
- Signed release tag candidate  

**Still no** production fleet mutate without explicit go.

### Finish line C — Live fleet canary (later)

- `--mode fleet` evidence  
- one node, then observation, then stable  
- Human authority for DNS/fleet/credentials  

---

## 3. Workstreams (parallel where possible)

```text
WS-G1  Local software hardening     (no host required)
WS-G2  Staging host bring-up        (needs operator inputs)
WS-G3  Live proof + observation      (after G2)
WS-G4  Admission freeze design      (fleet prep; may touch substrate classifier)
WS-G5  Release packaging            (after A or with B)
```

Peerit never appears as a dependency in G1–G3.

---

## 4. Detailed plan

### Phase 0 — Freeze the working tree (½ day)

| # | Task | Owner | Exit |
| --- | --- | --- | --- |
| 0.1 | Keep gateway work on `feat/vnext-gateway-merge` (or cut `feat/public-t1-staging` from it) | eng | Named branch tip recorded |
| 0.2 | Do not merge unsafe main dirty / Peerit branches into this train | eng | Clean gateway tip |
| 0.3 | Pick **one** public app key for staging (not Peerit outbox) | owner | 64-hex key + expected `/index.html` (or path) SHA-256 |

**Blocker for 0.3:** need a real seedable public Hyperdrive/app.

---

### Phase 1 — Local software you can finish without a VPS (1–2 days)

| # | Task | Why | Exit |
| --- | --- | --- | --- |
| 1.1 | Re-run full public-hive-gateway unit + integration rehearsal on tip | Confidence | Pass log committed under `docs/vnext/evidence/` |
| 1.2 | Run `test:public-hive-gateway:live` if local harness allows; else document skip | Catch runtime gaps | Pass or explicit skip reason |
| 1.3 | Config validator CLI: refuse multi-app canary, refuse `custody.enabled: true`, require finite maxResponseBytes | Foot-gun prevention | Tests |
| 1.4 | Staging config template filled from example (placeholders only) | Faster host day | `deploy/public-hive-gateway/staging.example.json` |
| 1.5 | Operator one-pager: “first 60 minutes on a VPS” checklist | Reduce host thrash | Doc section in runbook |
| 1.6 | Canonical gateway spec already on this branch — confirm no second conflicting copy is cited in release notes | Spec authority | Single pointer in README snippet |
| 1.7 | Optional: full `npm test` / unit suite on merge tip — triage failures that block gateway | Branch health | Failure list with owners |

**Can start immediately. No Peerit. No DNS.**

---

### Phase 2 — Staging host (Finish line A) — 1–2 days after inputs

**You must supply:**

1. Staging domain suffix (e.g. `hive-canary.staging.example.com`)  
2. API hostname (e.g. `relay-api.staging.example.com`)  
3. VPS (prefer **isolated**, not production fleet stable node)  
4. One public app key + content hash  
5. TLS plan (Let’s Encrypt on-box recommended)

| # | Task | Exit |
| --- | --- | --- |
| 2.1 | Provision VPS, open 443 only; 9100/9200 loopback | Host ready |
| 2.2 | Install HiveRelay from branch tip / package built from tip | Service running |
| 2.3 | DNS A/AAAA for API + wildcard app host | Resolves to host |
| 2.4 | ACME certs for API + wildcard | Cert paths valid |
| 2.5 | Real config: one key, custody false, productProfile public-t1-gateway, finite budgets | File on disk |
| 2.6 | Seed/register the one public app | Registry allows serve |
| 2.7 | Render nginx from template; install include; reload | App host → :9200, API → :9100 |
| 2.8 | Canary preflight **with** `--probe-origin`, `--connect-address`, `--expected-sha256` | `status: pass` evidence JSON |
| 2.9 | Ops rehearsal contract evidence (rehearsal mode, not fleet) | Evidence JSON |
| 2.10 | Manual browser + curl isolation checks | Notes in evidence dir |

---

### Phase 3 — Observe & harden (Finish line A complete) — ≥24h

| # | Task | Exit |
| --- | --- | --- |
| 3.1 | 24h observation: errors, disk, latency, cert renewal path | Observation log |
| 3.2 | Chaos: restart relay, reload nginx, temporary probe fail | Recovery notes |
| 3.3 | Negative checks: second app key denied; custody path not mounted | Pass |
| 3.4 | Write `docs/vnext/public-t1-staging-canary-result-YYYY-MM-DD.json` | Committed evidence |
| 3.5 | Marketing language freeze: “staging public distribution canary” only | Agreed phrasing |

**Stop here for a demoable public HTTPS gateway.** Fleet is optional later.

---

### Phase 4 — Fleet software prep (Finish line B, still Peerit-free)

| # | Task | Dependency | Exit |
| --- | --- | --- | --- |
| 4.1 | Design frozen T1 admission (replace transitional allowlist) | Role classifier semantics | Design doc + tests |
| 4.2 | Fail-closed T2: custody/blind cannot open app gateway | Same | Negative suite |
| 4.3 | `--mode fleet` preflight passes against frozen profile **on staging clone** | 4.1–4.2 | Evidence |
| 4.4 | V-GW1 budgets: huge objects, slow readers, ranges, transforms | Code | Suite green |
| 4.5 | Full monorepo/gateway suite on release candidate commit | CI or local | Green or signed waiver list |
| 4.6 | Release prepare dry-run (versions, digests) — **no push** | Owner | Dry-run log |

Note: 4.1 may share a *classifier* with blind substrate docs, but **shipping fleet still does not require Peerit** or a public blind canary.

---

### Phase 5 — Live fleet canary (Finish line C) — explicit human go only

| # | Task | Authority |
| --- | --- | --- |
| 5.1 | Choose one fleet node / new canary host | owner |
| 5.2 | Signed release + channel pin | owner |
| 5.3 | `--mode fleet` evidence on that node | eng + owner |
| 5.4 | Observe; promote stable only after gate | owner |

Do **not** start Phase 5 until Finish line A is solid and 4.x admission freeze lands.

---

## 5. Recommended order for “as much as possible” this week

```text
Day 1     Phase 0 + Phase 1 (local hardening, evidence logs, staging template)
Day 1–2   Owner: domain + VPS + app key (unblock Phase 2)
Day 2–3   Phase 2 bring-up
Day 3–4   Phase 3 observation start
Parallel  Phase 4.1–4.2 design spikes (admission freeze) — no fleet touch
```

**Maximum without any host from you:** complete all of Phase 1 (and start Phase 4 design).

**Maximum with a staging VPS + domain + app key:** Finish line A (demoable public HTTPS for one app).

---

## 6. Explicit non-goals (keeps track independent)

- Peerit CSP, capacity 2k clients, second Outbox operator  
- Blind G2-S public canary / Peerit dual-read  
- OHTTP / G3  
- Umbrel/StartOS multi-app gateway for Phase 1  
- npm publish, fleet channel promote, production DNS changes without ask  

---

## 7. Immediate asks (to unstick Phase 2)

Reply with whatever you already have:

1. **Staging domain** (API host + `*.hive-canary…` wildcard)  
2. **VPS** (new isolated preferred — IP or provider)  
3. **One public app key** (64-hex) and path/hash to probe  
4. **TLS:** Let’s Encrypt on-box OK?  

Until then, execution can still run Phase 1 fully on `feat/vnext-gateway-merge`.

---

## 8. Success criteria (checkbox form)

### Finish line A — Staging canary

- [ ] One isolated host, 443 public only  
- [ ] One allowlisted public app  
- [ ] Live canary preflight pass with body digest  
- [ ] API vs app hostname isolation proven  
- [ ] 24h observation log  
- [ ] Evidence JSON committed  
- [ ] Claims limited to staging / canary  

### Finish line B — Fleet-ready software

- [ ] Non-transitional admission profile  
- [ ] T2 exclusion suite  
- [ ] Full suite on RC commit  
- [ ] Fleet preflight green on non-prod  

### Finish line C — Live fleet

- [ ] Explicit owner go  
- [ ] Signed release + fleet evidence  
- [ ] Observation + optional stable  

---

## 9. Code / doc anchors

| Item | Path |
| --- | --- |
| Working tree | `00-core/hr-vnext-gateway-merge` |
| Example config | `deploy/public-hive-gateway/hiverelay-config.example.json` |
| Nginx template | `deploy/public-hive-gateway/nginx.conf.template` |
| Runbook | `docs/PUBLIC-HIVE-GATEWAY-CANARY-RUNBOOK.md` |
| Spec | `docs/PUBLIC-HTTPS-HIVE-GATEWAY-SPEC.md` |
| Go-now notes | `docs/vnext/PUBLIC-T1-GATEWAY-GO-NOW-2026-07-13.md` |
| Merge evidence | `docs/vnext/vnext-gateway-merge-2026-07-13.json` |
| Admission | `packages/core/gateway/public-app-admission.js` |
