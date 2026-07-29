# Public T1 gateway — first 60 minutes on a staging VPS

Peerit-independent. One trusted public app only. Canary posture (not fleet).

## Before the clock starts (have these ready)

| Input | Example |
| --- | --- |
| Staging domain suffix | `hive-canary.staging.example.com` |
| API hostname | `relay-api.staging.example.com` |
| VPS with public IP | Ubuntu 22.04+, 2 GB RAM ok |
| One public app key (64 hex) | from your seeded Hyperdrive / public app |
| Expected body path + SHA-256 | e.g. `/index.html` + digest |
| This branch tip | `feat/vnext-gateway-merge` |

**Not Peerit Outbox.** Pick any *public* app/drive you control.

## Minute 0–10 — host baseline

```sh
# as root or sudo
apt-get update
apt-get install -y nginx certbot python3-certbot-nginx curl jq
# open 443/80 only; do not expose 9100/9200 publicly
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable
```

Install Node 20+ if needed. Clone or rsync this repo worktree to the host.

## Minute 10–20 — config

```sh
cd /path/to/hr-vnext-gateway-merge   # or installed package tree

cp deploy/public-hive-gateway/staging.example.json /etc/hiverelay/public-t1.json
# edit: hiveAppHostSuffix, hiveAppPublicKeys, hiveAppPublicVersions
# keep custody.enabled false and finite byte limits

export HIVERELAY_API_KEY='generate-a-long-random-secret'
# never commit the key

node scripts/validate-public-t1-staging-config.mjs \
  --config /etc/hiverelay/public-t1.json
# must print status: PASS
```

## Minute 20–35 — DNS + TLS

Create DNS:

- `A/AAAA relay-api.staging.example.com` → VPS  
- `A/AAAA *.hive-canary.staging.example.com` → VPS  

```sh
certbot certonly --nginx \
  -d relay-api.staging.example.com \
  -d '*.hive-canary.staging.example.com'
# paths typically under /etc/letsencrypt/live/...
```

## Minute 35–50 — run relay + nginx edge

Start HiveRelay with the staging config so API listens on `127.0.0.1:9100` and gateway on `127.0.0.1:9200`. Seed/register the one public app until the registry has an explicitly public, persistent, non-blind entry for that key.

Render nginx:

```sh
node scripts/preflight-public-hive-gateway.mjs \
  --mode canary \
  --config /etc/hiverelay/public-t1.json \
  --nginx-template deploy/public-hive-gateway/nginx.conf.template \
  --certificate /etc/letsencrypt/live/.../fullchain.pem \
  --certificate-key /etc/letsencrypt/live/.../privkey.pem \
  --nginx-output /etc/nginx/snippets/public-hive-gateway.conf \
  --evidence /var/tmp/public-t1-preflight-static.json
```

Include the snippet in the nginx site for both hostnames; reload nginx. Confirm:

- API vhost proxies only to `127.0.0.1:9100`  
- App wildcard proxies only to `127.0.0.1:9200`  

## Minute 50–60 — live proof

```sh
# compute expected body hash once you can fetch locally
curl -fsS "https://<app-host>/index.html" | shasum -a 256

node scripts/preflight-public-hive-gateway.mjs \
  --mode canary \
  --config /etc/hiverelay/public-t1.json \
  --nginx-template deploy/public-hive-gateway/nginx.conf.template \
  --certificate /etc/letsencrypt/live/.../fullchain.pem \
  --certificate-key /etc/letsencrypt/live/.../privkey.pem \
  --nginx-binary /usr/sbin/nginx \
  --probe-origin "https://<app-host>" \
  --connect-address <VPS_PUBLIC_IP> \
  --app-key <64-hex> \
  --path /index.html \
  --expected-sha256 <digest> \
  --evidence /var/tmp/public-t1-preflight-live.json
```

Expect `status: pass` and **warnings** about transitional admission + single-app PSL — those are normal for Phase 1 canary.

## Isolation smoke

```sh
curl -sI "https://relay-api.../" | head
curl -sI "https://<app-host>/index.html" | head
# app host must not expose management API; API host must not serve app bytes
```

## After the hour

- Leave canary running ≥ **24 hours**  
- Do **not** pass this evidence to `--mode fleet` promotion  
- File observation notes under `docs/vnext/evidence/` when you return offline  

## Full detail

See `docs/PUBLIC-HIVE-GATEWAY-CANARY-RUNBOOK.md` and  
`docs/vnext/PUBLIC-T1-GATEWAY-ATTACK-PLAN-2026-07-13.md`.
