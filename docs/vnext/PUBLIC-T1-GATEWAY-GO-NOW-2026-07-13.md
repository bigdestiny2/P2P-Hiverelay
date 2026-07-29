# Public T1 HTTPS Gateway — Go Path (2026-07-13)

**Active ship track:** `public-t1-gateway` only.  
**Branch:** `feat/vnext-gateway-merge`  
**Owner decisions:** D-5 separate product; blind canary parked (D-1); no fleet privacy claims.

This is **not** a blind/privacy release. It is exact-byte public app distribution over HTTPS.

## What “going” means right now

| Posture | Allowed? | Meaning |
| --- | --- | --- |
| Local config + nginx render preflight | **Yes — green today** | `mode=canary` static checks pass |
| Isolated staging host (one trusted app) | **Yes — next ops step** | Operator VPS + DNS + TLS + one app key |
| Live fleet / `--mode fleet` | **No** | Needs frozen non-transitional T1 admission (`blind-substrate-public-v1`) |
| Marketing as private/blind | **No** | D-5: separate public product only |

## Verified today (local)

Worktree: `00-core/hr-vnext-gateway-merge` @ merge train tip.

1. **Canary preflight (config only)** — `status: pass`  
   - admission: `transitional-operator-allowlist-v1` (expected warning)  
   - finite policy present (`maxResponseBytes: 67108864`, etc.)  
   - custody disabled, physical enforcement required  
2. **Canary preflight + nginx template render** — `status: pass`  
   - nginx sha256 recorded in local evidence under `/tmp/hr-gateway-rehearsal/`  
3. **Expected canary warnings (do not “fix” these away):**  
   - transitional admission not fleet-ready  
   - no Public Suffix evidence → one app only  
   - shared proxy caching disabled in Phase 1  

Commands used:

```sh
cd /Users/localllm/Projects/pear-ecosystem/00-core/hr-vnext-gateway-merge
export HIVERELAY_API_KEY='…'   # never commit

node scripts/preflight-public-hive-gateway.mjs \
  --mode canary \
  --config deploy/public-hive-gateway/hiverelay-config.example.json \
  --evidence /tmp/hr-gateway-rehearsal/preflight-canary-config.json

# with nginx render (needs any cert/key paths; staging uses real Let's Encrypt)
node scripts/preflight-public-hive-gateway.mjs \
  --mode canary \
  --config deploy/public-hive-gateway/hiverelay-config.example.json \
  --nginx-template deploy/public-hive-gateway/nginx.conf.template \
  --certificate /path/to/fullchain.pem \
  --certificate-key /path/to/privkey.pem \
  --nginx-output /tmp/nginx-canary.conf \
  --evidence /tmp/hr-gateway-rehearsal/preflight-canary-nginx.json
```

## What you need to stand up staging (operator checklist)

Fill these before a real canary host:

1. **One staging VPS** (not production fleet canary/stable until frozen admission)  
2. **Two hostnames**  
   - management/API: e.g. `relay-api.staging.example` → loopback `:9100`  
   - app wildcard: e.g. `*.hive-canary.staging.example` → loopback `:9200`  
3. **Exactly one public app key** (64-hex) and its expected content path + SHA-256  
4. **TLS cert** covering the wildcard app host (and API host if separate)  
5. **Config** cloned from `deploy/public-hive-gateway/hiverelay-config.example.json`:  
   - `productProfile: "public-t1-gateway"`  
   - `custody.enabled: false`  
   - `hiveAppPublicKeys: [ "<one-key>" ]`  
   - `hiveAppPublicVersions` matches that one key  
   - finite gateway byte limits left enforced  
6. **Management token** in `HIVERELAY_API_KEY` (never in git)

Topology (from canary runbook):

```text
relay-api.…:443     nginx → 127.0.0.1:9100   (API/WSS only)
*.hive-canary.…:443 nginx → 127.0.0.1:9200   (app GET/HEAD only)
```

Never cross-proxy those ports.

## Staging bring-up sequence (after host exists)

Full detail: `docs/PUBLIC-HIVE-GATEWAY-CANARY-RUNBOOK.md`.

Short path:

1. Install relay from this branch/commit on the **staging** host only.  
2. Write real config (one app, custody off, loopback binds).  
3. Install rendered nginx include; open only 443 publicly.  
4. Seed the one public app / confirm local registry entry is `public` T1.  
5. Run:

```sh
node scripts/preflight-public-hive-gateway.mjs \
  --mode canary \
  --config /path/to/real-config.json \
  --nginx-template deploy/public-hive-gateway/nginx.conf.template \
  --certificate /etc/letsencrypt/live/.../fullchain.pem \
  --certificate-key /etc/letsencrypt/live/.../privkey.pem \
  --nginx-binary /usr/sbin/nginx \
  --nginx-config /etc/nginx/…include… \
  --probe-origin "https://<z32-or-key>.hive-canary.…" \
  --connect-address <node-public-ip> \
  --app-key <64-hex> \
  --path /index.html \
  --expected-sha256 <body-sha256> \
  --evidence ./public-gateway-canary-preflight.json
```

6. Run ops preflight in **rehearsal** mode with the operator contract example filled in.  
7. Observe ≥ **24h** before proposing any production fleet step.  
8. **Do not** pass canary evidence into fleet promotion tools.

## Explicitly out of scope for this track

- Blind cells, G2-S/G3 claims, Peerit blind migration (other agent / later)  
- `--mode fleet` while admission is transitional  
- Umbrel/StartOS multi-app gateway  
- Second untrusted app on the same suffix without PSL / separate domains  

## Code train location

| Item | Location |
| --- | --- |
| Combined code | `feat/vnext-gateway-merge` |
| Example config | `deploy/public-hive-gateway/hiverelay-config.example.json` |
| Nginx template | `deploy/public-hive-gateway/nginx.conf.template` |
| Runbook | `docs/PUBLIC-HIVE-GATEWAY-CANARY-RUNBOOK.md` |
| Spec | `docs/PUBLIC-HTTPS-HIVE-GATEWAY-SPEC.md` |
| Merge evidence | `docs/vnext/vnext-gateway-merge-2026-07-13.json` |

## Immediate next asks for the operator (you)

Reply with whatever you already have:

1. Staging hostname suffix you want (e.g. `hive-canary.<domain>`)  
2. The **one** public app key to allowlist  
3. Whether the host is a **new isolated box** vs a named fleet node (prefer new isolated for Phase 1)  
4. Whether certs will be Let’s Encrypt on-box or provided  

With those, the next conductor step is a **filled real config + command sheet** for that host (still no fleet promotion without you saying so).
