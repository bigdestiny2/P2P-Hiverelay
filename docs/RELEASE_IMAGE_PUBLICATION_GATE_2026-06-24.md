# Hiverelay Release Image Publication Gate - 2026-06-24

## Scope

This Level 2 slice classified the next edge after the fixed-source local image
smoke passed:

```text
hiverelay-publish-fixed-ghcr-image-and-capture-digest-pinned-release-smoke-evidence
```

The goal is to turn the green local image proof into public release evidence for
a digest-pinned GHCR image built from the fixed source.

## Current Evidence

- Local Docker is available when run outside the managed Codex sandbox:
  `docker version --format '{{.Client.Version}} {{.Server.Version}}'` returned
  `29.2.0 29.2.0`.
- The fixed local image still exists:
  `p2p-hiverelay:local-smoke-20260624`.
- Its image id is:
  `sha256:10f0966b853a4d6d46748d9833bf12f1cfcdefec091cd4646ca84243da96e4f7`.
- The local image is `linux/arm64`, about 274,620,496 bytes, and was already
  smoked green by `npm run release:smoke-image`.

This is not public release evidence because it is not a pushed multi-arch GHCR
reference of the form:

```text
ghcr.io/bigdestiny2/p2p-hiverelay:<semver>@sha256:<digest>
```

## Safe Preflight Results

The stable distribution preflight was run without secrets:

```sh
npm run release:check-distribution-env -- --channel both --prerelease false
```

Result: red, with the expected external release secrets missing:

```text
FLEET_SSH_PRIVATE_KEY
UMBREL_STORE_TOKEN
UMBREL_OFFICIAL_PR_TOKEN
UMBREL_OFFICIAL_FORK
STARTOS_DEVELOPER_KEY_PEM
STARTOS_REGISTRY_URL
```

The read-only GHCR manifest inspection command:

```sh
docker buildx imagetools inspect ghcr.io/bigdestiny2/p2p-hiverelay:0.20.0
```

did not return in roughly 90 seconds from this environment and was killed. Treat
registry access from this local session as unproven/stalled until a later agent
can retry with working network/registry access.

## Release Boundary

Do not manually overwrite `ghcr.io/bigdestiny2/p2p-hiverelay:0.20.0` from an
agent loop without explicit operator approval. The repo already declares the
official release path:

1. Run `.github/workflows/release-surfaces.yml` from the tagged source or a
   deliberate manual dispatch.
2. Let the workflow build and push the multi-arch GHCR image.
3. Capture `HIVERELAY_IMAGE_DIGEST`.
4. Run:

   ```sh
   npm run release:check-image-manifest -- \
     --image ghcr.io/bigdestiny2/p2p-hiverelay:<semver>@sha256:<digest> \
     --out release-image-manifest-evidence.json
   ```

5. Run:

   ```sh
   npm run release:smoke-image -- \
     ghcr.io/bigdestiny2/p2p-hiverelay:<semver>@sha256:<digest> \
     --evidence release-image-smoke-evidence.json
   ```

6. Only after those two evidence files are green should `release:prepare` update
   the pinned image digest in Umbrel, fleet, StartOS, README, and package
   surfaces.

## Next Edge

`hiverelay-release-image-authorized-publish-loop`: run the official
`release-surfaces.yml` workflow or an explicitly approved manual multi-arch
GHCR push from the fixed source, capture the pushed digest, then rerun
`release:check-image-manifest` and `release:smoke-image` against the exact
digest-pinned public image.
