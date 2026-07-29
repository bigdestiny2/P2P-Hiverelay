# Cutting a release (keyvault-signed, no gpg)

HiveRelay release tags are **SSH-signed** (git `gpg.format=ssh`) — no GnuPG
needed. The signing key lives in [keyvault](../../keyvault); you unlock the vault
once and `scripts/release.sh` does the rest: sign → self-verify against the
fleet's `allowed-signers` → push → GitHub prerelease → (optionally) promote the
canary channel.

This complements `scripts/prepare-release.mjs` (which bumps package versions +
lockfile + compose digest for a *new* version). When `package.json` is already at
the target version, `release.sh cut` is all you need.

## One-time setup

Unlock the vault (once per session; the agent then serves every command
prompt-free):

```bash
keyvault agent --daemonize      # prompts for the master password, then detaches
```

Generate + store the release signing key and register its public half:

```bash
scripts/release.sh setup
```

This generates an ed25519 key, stores the **private** half in the vault
(`hiverelay-release/tag-signing-key`; generated in a `0700` temp dir that is
removed immediately, so the private key never persists outside the vault), and
appends the **public** half to `fleet/allowed-signers` keyed by your
git `user.email`. Then:

```bash
git add fleet/allowed-signers && git commit -m "release: add signing key"
# ship it to every box (required from the NEXT release onward — see SUPPLY-CHAIN.md):
#   sudo install -D -m 0644 fleet/allowed-signers /etc/hiverelay/allowed-signers
```

## Cutting a release

With the agent unlocked:

```bash
scripts/release.sh cut v0.24.0                 # sign + push + GitHub prerelease
scripts/release.sh cut v0.24.0 --promote-canary # …and bump channels.json canary
scripts/release.sh cut v0.24.0 -y              # skip the confirm prompt
```

Or as a **single self-unlocking command** (injects the key — and `GH_TOKEN` if
you store one at `hiverelay-release/gh-token` — as env vars; prompts once if the
agent is down):

```bash
keyvault exec --scope hiverelay-release -- scripts/release.sh cut v0.24.0
```

`scripts/release.sh status` shows what's configured (vault state, key
availability, whether the signer principal is trusted by `allowed-signers`,
allowed-signers count, and package.json version). A locked vault is reported as
unknown/unavailable, never as proof that the signing key is absent; unlock it
before considering the one-time `setup` command.

## Guards the script enforces

- **Tag name == `package.json` version.** The fleet updater's health-gate
  compares `${tag#v}` to the running `/health` version (= `package.json`). A
  mismatch (e.g. an `-rc` tag while `package.json` says `0.24.0`) auto-rolls-back
  every box. `cut` refuses to sign a mismatched tag.
- **Prerelease by default.** A non-prerelease tag triggers the secret-gated
  npm/ecosystem-consumer release jobs. `cut` marks the GitHub release
  `--prerelease` unless you pass `--stable`.
- **Self-verify before push.** The signed tag is verified against
  `fleet/allowed-signers` locally; if your key isn't trusted there, the tag is
  deleted and nothing is pushed — you never publish a tag the fleet would reject.
- **Trusted principal before signing.** If `git config user.email` is not an
  allowed principal, `cut` fails before creating a tag. Set
  `HIVERELAY_RELEASE_SIGNER_EMAIL` to the principal shipped in
  `fleet/allowed-signers`; do not rotate a key merely to repair an email mismatch.
- **No key on disk.** The signing key is materialized only to a `0600` temp file
  that is removed on every exit path (success, error, or interrupt).

## Rotating the signing key

```bash
keyvault rm hiverelay-release/tag-signing-key   # drop the old one
scripts/release.sh setup                        # generate + store + register a new one
# commit fleet/allowed-signers (keep the old pubkey until every box is updated, if
# any un-rolled tag still needs verifying), then re-distribute to boxes.
```
