# Release Notes — v0.8.2

**Release date**: 2026-05-05

Operational release for npm publish. Folds the v0.8.0 atomic-custody work
and v0.8.1 hardening patch into a single npm-shipped version. No protocol
changes since v0.8.1.

## Summary

This release exists primarily so external consumers (`p2p-hiverelay-client`
in particular) can `npm install p2p-hiverelay@^0.8` and get the
trust-pipeline + custody-hardening combo as one coherent version.

## Added

### `--operator` and `--auto-heal` CLI flags

The deployment-time `--operator` flag is **important** for v0.8.0 onwards:

- Without a stable operator identifier, AutoHeal treats each pubkey as its
  own operator.
- The per-operator fairshare cap (which prevents sybil clusters from
  dominating a drive's quorum) doesn't activate until an operator is named.
- Set this to your org / deployment name, e.g. `--operator acme-corp`,
  `--operator foundation-prod`.

Both flags are wired through to the systemd unit emitted by the deploy
script.

```bash
p2p-hiverelay start \
  --region NA \
  --operator your-org-name \
  --auto-heal \
  --max-storage 50GB
```

## Fixed

### Deploy CLI path correction

The systemd-deploy script was pointing at a pre-monorepo `cli/index.js`
location that no longer exists post the v0.5.0 split. Now correctly
references `packages/core/cli/index.js`. Affects fresh installs only —
existing deployments using the old path continue working until they
re-deploy.

## Upgrading

```bash
npm install -g p2p-hiverelay@^0.8.2
```

If you maintain your own deployment script, audit any references to
`./cli/index.js` and update them to `./packages/core/cli/index.js`.

## What's next

v0.8.3 ships the bug-hunt patch for the issues uncovered by the first
operator running v0.8.2 in production.
