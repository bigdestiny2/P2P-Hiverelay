# Public Hive gateway deploy assets

| File | Purpose |
| --- | --- |
| `hiverelay-config.example.json` | Canonical example (finite policy, one app, custody off) |
| `staging.example.json` | Copy for staging VPS — replace suffix + app key with real values |
| `nginx.conf.template` | Strict TLS edge template |
| `operator-readiness-contract.example.json` | Ops contract skeleton |
| `STAGING-FIRST-60-MIN.md` | First hour on a staging host |

**Spec authority:** `docs/PUBLIC-HTTPS-HIVE-GATEWAY-SPEC.md` on this branch is the active
public gateway contract. Do not cite older shorter copies on other worktrees.

**Validate before deploy:**

```sh
export HIVERELAY_API_KEY='…'
npm run gateway:validate-staging-config -- --config deploy/public-hive-gateway/staging.example.json
```

Peerit OutboxLog is out of scope for this product track.
