# Stable HiveRelay v0.24.3

This is the canonical documentation entry point for the current stable
HiveRelay operator/fleet baseline. Stable means the signed source and raw-fleet
channel named below; it does not mean every distribution surface has published
`0.24.3` artifacts.

## Version boundary

| Lane | Authority | Status |
|---|---|---|
| Stable | `v0.24.3` at `d0190577c5eccd10b7e4ae84baf2dc7b0f2b1c80` | Application-aware compatibility relay used by the stable and hold fleet channels |
| Canary | `v0.25.0-rc.9` | Release candidate only; not promoted to stable |
| Blind-substrate development | `1.0.0-rc.1` manifests on `main` | Isolated replacement work; not the stable product and not blind GA |

HiveRelay `v0.24.3` is the legacy application-aware relay. It includes the
ghost-outbox sweep and rate-limit/read-path fixes recorded in
[CHANGELOG.md](../CHANGELOG.md#0243--2026-07-08). It must not be described as
the isolated app-agnostic blind substrate being developed after it.

## Reproducible stable source

Use the signed release tag, not the tip of `main`:

```sh
git clone https://github.com/bigdestiny2/P2P-Hiverelay.git
cd P2P-Hiverelay
git checkout v0.24.3
git rev-parse HEAD
npm ci
npm test
```

The expected commit is:

```text
d0190577c5eccd10b7e4ae84baf2dc7b0f2b1c80
```

## Reproducible stable container

The stable OCI index was rechecked on 2026-08-06 and contains Linux amd64 and
arm64 manifests:

```text
ghcr.io/bigdestiny2/p2p-hiverelay:0.24.3@sha256:cb104aa65d7e8f57766ea7d60d64dbb6b081a0b9fc5b318c0fa75cb22c0d31c8
```

Pull it by immutable digest:

```sh
docker pull ghcr.io/bigdestiny2/p2p-hiverelay:0.24.3@sha256:cb104aa65d7e8f57766ea7d60d64dbb6b081a0b9fc5b318c0fa75cb22c0d31c8
```

Do not replace the digest with `latest`, `next`, a release-candidate tag, or a
bare mutable tag when stable artifact identity matters.

## Documentation map

- [Developer and API guide](./DEVELOPER.md) explicitly tracks `v0.24.3`.
- [Pear application integration](./PEAR-INTEGRATION.md) records the stable
  four-package source contract.
- [PearBrowser integration](./PEARBROWSER-INTEGRATION.md) records the stable
  browser/relay compatibility boundary.
- [Service contract](./SERVICE-CONTRACT.md) defines which relay behavior is
  generic infrastructure rather than an application-specific emergency patch.
- [Fleet management](../fleet/README.md) documents signed channel updates,
  health gating, containment, and rollback.

Documents under `docs/vnext/`, blind public-test material, `0.25.0-rc.*`
announcements, and `1.0.0-rc.1` package/appliance manifests are candidate or
development records. They are useful for the next train but are not stable
`v0.24.3` behavior or installation instructions.

## Distribution reality

The following was verified against the public registries on 2026-08-06:

- The GitHub release `v0.24.3` exists, is marked as a prerelease, and has no
  attached assets.
- No stable `v0.24.3` StartOS `.s9pk` is attached. GitHub's latest-release URL
  must not be used to select a stable StartOS package.
- Exact `0.24.3` versions of `p2p-hiverelay`, `p2p-hiverelay-client`,
  `p2p-hiveservices`, and `p2p-hiverelay-verifier` are not published on npm.
  npm `latest` is therefore not a `0.24.3` installation route.
- The immutable GHCR index above is available for Linux amd64 and arm64.
- `fleet/channels.json` keeps `stable` and `hold` on `v0.24.3`; `canary` is
  deliberately separate.

Those are distribution gaps, not reasons to relabel a candidate as stable.
Until a separately authorized release action changes them, the signed source
tag and immutable container are the stable artifacts.
