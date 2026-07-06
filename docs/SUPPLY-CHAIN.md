# Supply-chain integrity

This document covers how HiveRelay artifacts are signed and verified, and the
**one-time operator key setup** the maintainer must complete for the
protections to actually engage. It closes audit findings HR-DIS-001 (image
attestation), HR-DIS-002 (digest pinning), and HR-DIS-003 (updater tag
verification).

There are three independent guards, each fail-closed:

| # | Guard | What it protects | Verified where |
|---|-------|------------------|----------------|
| HR-DIS-003 | **Signed release tags** | The pull-based fleet updater (`fleet/updater.sh`) | On every relay box, before `git checkout` |
| HR-DIS-002 | **Digest-pinned image** | The Umbrel `docker-compose.yml` app image | CI (`umbrel-app-validate.yml`), fail-closed |
| HR-DIS-001 | **cosign keyless signature** | The published GHCR container image | `docker-publish.yml` / `release-surfaces.yml` sign; consumers `cosign verify` |

---

## 1. Signed release tags (HR-DIS-003) — REQUIRED operator setup

`fleet/updater.sh` resolves a channel-named tag from a remote JSON file over
the network and checks it out **as root** on every box. Without verification, a
repo compromise, a stolen GitHub account, a CDN/`raw.githubusercontent.com`
MITM, or a CA MITM could move that tag and run arbitrary code fleet-wide.

The updater now refuses to check out any tag that is not an **annotated tag
signed by a key in a locally provisioned allowed-signers file**. It fails
closed: a missing allowed-signers file, a lightweight/unsigned tag, or a tag
signed by an untrusted key all abort the update and leave the box on its
current version.

### One-time setup (maintainer, once)

1. **Create an SSH signing key** dedicated to release tags (keep the private
   key offline / in a hardware key; only the public half is distributed):

   ```sh
   ssh-keygen -t ed25519 -C "hiverelay-release" -f ~/.ssh/hiverelay_release_signing
   ```

2. **Configure git to sign tags** with it on the release machine:

   ```sh
   git config --global gpg.format ssh
   git config --global user.signingkey ~/.ssh/hiverelay_release_signing.pub
   ```

   Then cut releases with a **signed annotated tag**:

   ```sh
   git tag -s v0.24.0 -m "v0.24.0"
   git push origin v0.24.0
   ```

   (GPG works too — the updater accepts either. SSH is the documented default.)

3. **Publish the allowed-signers file** to the repo and ship it to every box.
   Format is OpenSSH `allowed_signers`; the principal is the signer identity
   (e.g. an email) and the value is the *public* key:

   ```
   hiverelay-release ssh-ed25519 AAAA... hiverelay-release
   ```

### One-time setup (per relay box)

Install the allowed-signers file where the updater expects it:

```sh
sudo install -D -m 0644 allowed-signers /etc/hiverelay/allowed-signers
```

Override the path with `HIVERELAY_ALLOWED_SIGNERS` if needed. Audit a tag by
hand at any time:

```sh
hiverelay-updater --verify-only v0.24.0   # exit 0 = trusted, non-zero = refused
```

**Break-glass:** `HIVERELAY_REQUIRE_SIGNED_TAGS=0` disables the gate for an
emergency where signing is broken and you accept the risk. It logs a loud
warning and should never be a standing configuration.

---

## 2. Digest-pinned Umbrel image (HR-DIS-002)

`umbrel-app/docker-compose.yml` pins the app image by immutable digest
(`ghcr.io/bigdestiny2/p2p-hiverelay:<version>@sha256:<digest>`), not a floating
tag. Docker resolves and verifies the digest, so a moved or re-pushed tag can
never change what runs on an install.

- `npm run release:prepare -- <version> --image-digest sha256:<digest>`
  rewrites the pin to the freshly-built multi-arch manifest digest at release
  time.
- `.github/workflows/umbrel-app-validate.yml` **fails the build** if the ref
  ever regresses to a tag-only reference. No operator setup required — the gate
  is automatic.

---

## 3. cosign keyless image signing (HR-DIS-001)

The container-publish workflows sign the pushed multi-arch **manifest digest**
with [cosign](https://docs.sigstore.dev/) using **keyless (OIDC)** signing: the
GitHub Actions job mints a short-lived OIDC token, Fulcio issues an ephemeral
signing certificate, and the signature + certificate are stored in the Rekor
transparency log. **No long-lived signing key is stored anywhere** — nothing
for the operator to provision or rotate.

Signing happens in:

- `.github/workflows/docker-publish.yml` — `:latest` / `main-<sha>` images
- `.github/workflows/release-surfaces.yml` — release images

Both jobs declare `id-token: write` and sign `--recursive` over the digest.

### Verifying an image (consumers / operators)

Any consumer can verify an image was built by this repo's workflow before
running it:

```sh
cosign verify \
  --certificate-identity-regexp \
    'https://github.com/bigdestiny2/P2P-Hiverelay/\.github/workflows/.+@refs/(heads|tags)/.+' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/bigdestiny2/p2p-hiverelay@sha256:<digest>
```

Pin `--certificate-identity` to an exact workflow ref for the strictest check.

### Verification hook

`scripts/verify-image-signature.sh <image-ref>` wraps the `cosign verify`
invocation above with the repo's expected identity/issuer baked in, so CI, the
StartOS/Umbrel packaging steps, and operators can gate on a signed image with
one command. It exits non-zero (fail-closed) if the signature is missing or the
identity does not match.
