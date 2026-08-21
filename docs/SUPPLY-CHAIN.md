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

Release-image reuse does exactly that before it mutates a tag or adds another
signature:

```sh
cosign verify \
  --certificate-identity \
    'https://github.com/bigdestiny2/P2P-Hiverelay/.github/workflows/release-surfaces.yml@refs/tags/vX.Y.Z' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/bigdestiny2/p2p-hiverelay@sha256:<digest>
```

The reuse gate starts from one immutable, digest-bearing Actions artifact, not
the public multi-asset Release update. It binds the artifact's numeric REST id,
source run, archive URL, size, ZIP SHA-256, and exact evidence-file inventory,
then binds the embedded run id/attempt, tag ref, head SHA, accepted release
event, exact `.github/workflows/release-surfaces.yml` path, and the completed
`sync` job's successful pre-handoff checkpoint
steps. It then live-inspects both evidence-bound platform child configs for
that same source revision. Mutable GitHub Release evidence alone is never
sufficient authority for a retag.

### Verification hook

`scripts/verify-image-signature.sh <image-ref>` wraps the `cosign verify`
invocation above with the repo's expected identity/issuer baked in, so CI, the
StartOS/Umbrel packaging steps, and operators can gate on a signed image with
one command. It exits non-zero (fail-closed) if the signature is missing or the
identity does not match.

---

## 4. StartOS 0.4 package and closure authority

The StartOS 0.4 child workflow keeps signing secrets behind an authenticated
toolchain boundary. It does not execute Start9's setup composite. Checkout and
artifact-upload actions are pinned to full commit SHAs, and
`scripts/install-startos-cli.sh` downloads only the fixed StartOS CLI 1.1.0
asset over HTTPS. The script requires SHA-256
`70eff67b6e9a936acd8aaaf787b783819252ecedaa5c74d462e3b15ed4dd843a`
before chmod, PATH exposure, version execution, or developer-key exposure. The
lockfile-verified dependency install also completes before key exposure. The
SDK version, resolved tarball, and npm integrity are independently bound to the
source manifest and lockfile.

The GitHub Release package and deterministic sidecar form one immutable pair.
Every child builds from the exact tag with the authenticated CLI and locked
SDK; public Release bytes are never used as package or artifact authority. CI
accepts only exactly one non-empty `uploaded` record of each name with a valid
GitHub digest, and requires the newly built bytes to match. It rejects partial
pairs, duplicate names, zero-byte/`starter` records, and rebuild drift without
deleting or clobbering them. A successful child uploads only its fresh local
build and sidecar to the run/attempt-named, digest-bearing Actions artifact.

`release-evidence.json` certifies a `release-surfaces/pre-handoff-checkpoint`,
not a completed `sync` job, and remains
`checkpoint-passed-pending-sync-completion-and-startos-0.4-closure`. The child
authenticates the exact recorded parent run attempt and its terminal successful
`sync` job through the Actions API. It resolves the package image only from the
separate run/attempt-named image-authority artifact whose exact numeric id the
parent dispatches. Its parent path/event/tag/SHA, successful checkpoints, REST
record, two-file ZIP digest/inventory, and embedded attempt must agree. Mutable
Release JSON is compare-only. Before key exposure, the child verifies the
exact-tag keyless signature, raw index hash and amd64/arm64 membership, then
both child revision labels. API workflow paths are accepted only as the exact
workflow file, optionally qualified by the exact release tag; branch or other
ref suffixes fail closed. Reusable-image recovery instead requires
the exact attempt's enumerated image-sign, manifest, smoke, evidence-write,
and local-verification steps, while the separately authenticated artifact
proves its own completed upload; it can recover
from a later terminal `sync` failure without weakening that authority. The final parent job uses the exact image-authority
and child Actions artifacts as image/package authority, installs the
hash-authenticated CLI, independently inspects the package commitment and
structured manifest, and compares those artifact bytes with the current
Release pair. Only then does it publish `release-closure-evidence.json`,
re-download the entire published bundle, and run the live GitHub closure
verifier. The closure certificate records normalized image-authority REST
metadata. The live verifier re-fetches each Release asset by exact REST id and
digest, authenticates the exact parent and child run attempts/workflow paths,
and downloads and hashes both exact non-expired artifact ZIPs before comparing
their files to the Release checkpoint/pair; it also resolves the current GitHub tag to the
recorded source commit. A terminal inventory re-fetch requires the Release id
and exact `draft`/`prerelease` policy plus every required asset
id/state/size/digest/URL to remain unchanged after all downloads and artifact
checks; both exact Actions artifact records and the tag commit are revalidated
too. The bounded verifier mode used inside the still-running parent permits
that exact parent to remain in progress only when GitHub's repository,
workflow-ref, job, run, attempt, ref, and SHA context all match; stable/GA checks require the recorded
parent attempt to be completed successfully.
The stable blocker explicitly requires `prerelease=false`. JSON-only offline inspection is deliberately
non-authoritative; stable/GA blocker checks require `GH_TOKEN` and the live
mode. Each verifier subprocess has a 60-second ceiling and the parent closure
job is explicitly bounded.

The parent selects the child artifact by numeric REST id, verifies the downloaded
ZIP size and SHA-256 against that exact REST record, and rejects an expired or
missing attempt-named artifact so a later parent retry can dispatch a fresh child.
`start-cli 1.1.0` exposes the package commitment but no signer fingerprint.
The evidence records this limitation and restricts the proof to inspected
GitHub-sideload package bytes; it does not claim StartOS registry signer
identity. Publication is also non-atomic: earlier GHCR, npm, legacy StartOS,
the StartOS 0.4 Release pair, fleet, or Umbrel/ecosystem writes may precede closure. A child failure leaves
the parent red and blocks stable/GA completion, but does not imply rollback of
those external writes.

Reusable-image recovery verifies the signed index itself before any retag sink:
the raw index bytes must hash to the authenticated digest, and its exact
`linux/amd64` and `linux/arm64` child descriptors must match the evidence before
each child config is checked for the release revision label. Manual release
dispatches must use the exact tag as the workflow ref; branch-loaded dispatches
are rejected before release writes.

The public checkpoint update uses a non-atomic multi-asset GitHub Release
`--clobber`. A partial replacement can make those public files temporarily
incomplete, but it cannot become image-reuse authority or force a rebuild: the
retry restores the evidence-bound digest from the prior immutable Actions
artifact. Once public release state exists, a missing or expired authority
artifact—including after its explicit 90-day retention window—fails closed for
audited recovery rather than silently changing the index digest.
