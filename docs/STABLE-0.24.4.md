# Stable HiveRelay v0.24.4

This is the canonical documentation entry point for the current stable
HiveRelay operator/fleet baseline. It succeeds
[Stable HiveRelay v0.24.3](./STABLE-0.24.3.md). Stable means the signed source
tag and published npm line named below; it does not mean every distribution
surface has published `0.24.4` artifacts.

## Version boundary

| Lane | Authority | Status |
|---|---|---|
| Stable | `v0.24.4` at `e5bb696f039b0aace885becaf0052441b6b7a8a5` | Application-aware compatibility relay; npm `latest` for all four packages |
| Stable fleet channel | `v0.24.3` at `d0190577c5eccd10b7e4ae84baf2dc7b0f2b1c80` | `fleet/channels.json` keeps `stable` and `hold` here until a separately authorized promotion |
| Release candidate | `v0.26.0-rc.1` | The 0.26.0 train; supersedes the whole `0.25.0-rc.1`…`rc.9` train (npm `next`) |
| Blind-substrate development | `1.0.0-rc.1` blind-* workspace packages | Isolated replacement work; deliberately on its own version line, not the stable product and not blind GA |

HiveRelay `v0.24.4` is the legacy application-aware relay. Its only code
change over `v0.24.3` is the `GET /api/poker/usage` fix that unblocked the
release gate, plus production dependency advisory bumps — see
[CHANGELOG.md](../CHANGELOG.md#0244--2026-08-06). It must not be described as
the isolated app-agnostic blind substrate being developed after it.

## Install from npm (stable route)

`v0.24.4` is the first 0.24.x release published to npm. All four lockstep
packages carry the `latest` dist-tag, so npm is a valid stable install route:

```sh
npm install -g p2p-hiverelay        # relay runtime + CLI
npm install p2p-hiverelay-client    # app/client SDK
npm install p2p-hiveservices        # optional service providers
npm install p2p-hiverelay-verifier  # verification helpers
```

The `next` dist-tag tracks the release-candidate lane (currently
`0.25.0-rc.9`, moving to `0.26.0-rc.1`); it is not stable scope.

## Reproducible stable source

Use the signed release tag, not the tip of `main`:

```sh
git clone https://github.com/bigdestiny2/P2P-Hiverelay.git
cd P2P-Hiverelay
git checkout v0.24.4
git rev-parse HEAD
npm ci
npm test
```

The expected commit is:

```text
e5bb696f039b0aace885becaf0052441b6b7a8a5
```

## Stable container

`v0.24.4` was an npm-only maintenance release: no `0.24.4` image tag exists on
GHCR. The newest digest-pinned stable container remains the `v0.24.3`
multi-arch OCI index (Linux amd64 and arm64), rechecked 2026-08-18:

```sh
docker pull ghcr.io/bigdestiny2/p2p-hiverelay:0.24.3@sha256:cb104aa65d7e8f57766ea7d60d64dbb6b081a0b9fc5b318c0fa75cb22c0d31c8
```

The only runtime difference from `0.24.4` is the poker-usage telemetry answer
and dependency advisory bumps recorded in the changelog. Do not replace the
digest with `latest`, `next`, a release-candidate tag, or a bare mutable tag
when stable artifact identity matters.

## Documentation map

- [Developer and API guide](./DEVELOPER.md) tracks the stable `0.24.4` line.
- [Pear application integration](./PEAR-INTEGRATION.md) records the stable
  four-package source contract.
- [PearBrowser integration](./PEARBROWSER-INTEGRATION.md) records the stable
  browser/relay compatibility boundary.
- [Service contract](./SERVICE-CONTRACT.md) defines which relay behavior is
  generic infrastructure rather than an application-specific emergency patch.
- [Fleet management](../fleet/README.md) documents signed channel updates,
  health gating, containment, and rollback.

Documents under `docs/vnext/`, blind public-test material, `0.26.0-rc.*`
announcements, and the `1.0.0-rc.1` blind-* workspace manifests are candidate
or development records. They are useful for the next train but are not stable
`v0.24.4` behavior or installation instructions.

## Distribution reality

The following was verified against the public registries on 2026-08-18:

- npm `latest` is `0.24.4` for `p2p-hiverelay`, `p2p-hiverelay-client`,
  `p2p-hiveservices`, and `p2p-hiverelay-verifier`; npm `next` is
  `0.25.0-rc.9` (the superseded rc train's last tag, moving to
  `0.26.0-rc.1`).
- The `v0.24.4` git tag exists; no GitHub release object or attached assets
  accompany it, so `releases/latest` must not be used as a stable selector.
- No stable `.s9pk` is attached to any release.
- No `0.24.4` GHCR image exists; the immutable `0.24.3` index above is the
  newest digest-pinned stable container.
- `fleet/channels.json` keeps `stable` and `hold` on `v0.24.3`; `canary`
  points at `v0.25.0-rc.9` until the `v0.26.0-rc.1` promotion.

Those are distribution boundaries, not reasons to relabel a candidate as
stable. Until a separately authorized release action changes them, the signed
source tag, the npm `latest` packages, and the immutable container above are
the stable artifacts.
