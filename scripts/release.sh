#!/usr/bin/env bash
#
# release.sh — keyvault-integrated, SSH-signed release cutter for HiveRelay.
#
# No gpg required: tags are signed with git's SSH signing (gpg.format=ssh),
# using a release signing key held in keyvault (../keyvault). Unlock the vault
# once (`keyvault agent --daemonize`, or run this under `keyvault exec`) and this
# script does the rest — sign, self-verify, push, GitHub prerelease, and
# (optionally) promote the fleet canary channel.
#
# Subcommands:
#   setup                 One-time: generate an ed25519 release key, store the
#                         PRIVATE half in keyvault, add the PUBLIC half to
#                         fleet/allowed-signers (what the fleet's verify_tag uses).
#   cut <vX.Y.Z> [<ref>]  Sign + verify + push the tag, create a GitHub prerelease.
#                         Optional: --promote-canary also bumps channels.json.
#   status                Show what's configured (vault key present? git version?
#                         signer email? allowed-signers populated?).
#
# One-command release (agent unlocked, or prompts once):
#   keyvault exec --scope hiverelay-release -- scripts/release.sh cut v0.24.0
#     (injects TAG_SIGNING_KEY [+ GH_TOKEN if stored] from the vault)
#   — or, with the agent already up —
#   scripts/release.sh cut v0.24.0
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ALLOWED_SIGNERS="$REPO_ROOT/fleet/allowed-signers"

# --- configurable (env overridable) ---------------------------------------
VAULT_SCOPE="${HIVERELAY_RELEASE_VAULT_SCOPE:-hiverelay-release}"
VAULT_KEY_NAME="${HIVERELAY_RELEASE_SIGNING_KEY_NAME:-tag-signing-key}"
# Env var that `keyvault exec --scope hiverelay-release` produces from the key
# named 'tag-signing-key' (namespace stripped, upper-snake): TAG_SIGNING_KEY.
KEY_ENV_VAR="TAG_SIGNING_KEY"
SIGNER_EMAIL="${HIVERELAY_RELEASE_SIGNER_EMAIL:-$(git -C "$REPO_ROOT" config user.email 2>/dev/null || true)}"
GITHUB_REPO="${HIVERELAY_GITHUB_REPO:-bigdestiny2/P2P-Hiverelay}"

log()  { printf '\033[36mrelease:\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[33mrelease: WARNING:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31mrelease: ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"; }

# Any secret material written to disk is tracked here and removed on EVERY exit
# path — success, error under `set -e`, or interrupt. A function-local trap would
# miss the errexit path and strand a private key in the temp dir.
KEYFILE=""; SETUP_TMP=""
cleanup() {
  [ -n "${KEYFILE:-}" ] && rm -f "$KEYFILE" 2>/dev/null || true
  [ -n "${SETUP_TMP:-}" ] && rm -rf "$SETUP_TMP" 2>/dev/null || true
  return 0
}
trap cleanup EXIT INT TERM

# Retrieve the release signing PRIVATE key material, in priority order.
# NEVER echoed. Emits the key to stdout for the caller to redirect to a 0600 file.
get_signing_key() {
  if [ -n "${!KEY_ENV_VAR:-}" ]; then printf '%s' "${!KEY_ENV_VAR}"; return 0; fi
  if [ -n "${SIGNING_KEY_FILE:-}" ]; then cat "$SIGNING_KEY_FILE"; return 0; fi
  if command -v keyvault >/dev/null 2>&1; then
    keyvault get "$VAULT_SCOPE/$VAULT_KEY_NAME" 2>/dev/null && return 0
    die "keyvault has no '$VAULT_SCOPE/$VAULT_KEY_NAME' — run: $0 setup  (and unlock the agent)"
  fi
  die "no signing key available: set $KEY_ENV_VAR (via 'keyvault exec --scope $VAULT_SCOPE'), install keyvault, or set SIGNING_KEY_FILE"
}

# ---------------------------------------------------------------------------
cmd_setup() {
  need ssh-keygen; need keyvault; need awk
  [ -n "$SIGNER_EMAIL" ] || die "no signer email — set HIVERELAY_RELEASE_SIGNER_EMAIL or 'git config user.email'"
  if keyvault get "$VAULT_SCOPE/$VAULT_KEY_NAME" >/dev/null 2>&1; then
    die "'$VAULT_SCOPE/$VAULT_KEY_NAME' already exists in the vault — refusing to overwrite (rotate deliberately with 'keyvault rm' first)"
  fi
  SETUP_TMP="$(mktemp -d)"; chmod 700 "$SETUP_TMP"
  log "generating ed25519 release signing key…"
  ssh-keygen -t ed25519 -N '' -C "hiverelay-release" -f "$SETUP_TMP/relkey" -q
  keyvault set "$VAULT_SCOPE/$VAULT_KEY_NAME" --tags release,signing < "$SETUP_TMP/relkey"
  local keypart; keypart="$(awk '{print $1, $2}' "$SETUP_TMP/relkey.pub")"
  local line="$SIGNER_EMAIL $keypart hiverelay-release"
  touch "$ALLOWED_SIGNERS"
  if grep -qF "$keypart" "$ALLOWED_SIGNERS" 2>/dev/null; then
    log "public key already in $ALLOWED_SIGNERS"
  else
    printf '%s\n' "$line" >> "$ALLOWED_SIGNERS"
    log "added public key to $ALLOWED_SIGNERS"
  fi
  log "PRIVATE key stored in vault '$VAULT_SCOPE/$VAULT_KEY_NAME' (generated in a 0700 temp dir, then removed — never persisted outside the vault)"
  cat >&2 <<EOF

  NEXT:
    1. git add fleet/allowed-signers && git commit -m 'release: add signing key to allowed-signers'
    2. Ship fleet/allowed-signers to every box → /etc/hiverelay/allowed-signers
       (only required from the NEXT release onward; the v0.24.0 hop still runs the
        pre-verify_tag updater — see docs/SUPPLY-CHAIN.md).
    3. Cut a release:  scripts/release.sh cut v0.24.0
EOF
}

# ---------------------------------------------------------------------------
cmd_cut() {
  need git; need node
  local version="" ref="HEAD" prerelease=1 promote_canary=0 assume_yes=0 notes=""
  version="${1:-}"; shift || true
  while [ $# -gt 0 ]; do
    case "$1" in
      --stable)          prerelease=0 ;;
      --promote-canary)  promote_canary=1 ;;
      -y|--yes)          assume_yes=1 ;;
      --notes)           notes="${2:-}"; shift ;;
      -*)                die "unknown flag: $1" ;;
      *)                 ref="$1" ;;
    esac
    shift
  done
  [ -n "$version" ] || die "usage: $0 cut <vX.Y.Z> [<ref>] [--stable] [--promote-canary] [-y]"
  [[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || die "version must look like v0.24.0 (got '$version')"
  [ -n "$SIGNER_EMAIL" ] || die "no signer email — set HIVERELAY_RELEASE_SIGNER_EMAIL or 'git config user.email'"

  # FOOTGUN GUARD: the fleet updater health-gate compares the tag (minus 'v') to
  # the running /health version, which is package.json's version. A mismatch
  # (e.g. an -rc suffix while package.json says 0.24.0) auto-rolls-back the box.
  local pkgver tagver
  pkgver="$(node -p "require('$REPO_ROOT/package.json').version" 2>/dev/null)" || true
  [ -n "$pkgver" ] || die "cannot read a version from $REPO_ROOT/package.json"
  tagver="${version#v}"
  if [ "$tagver" != "$pkgver" ]; then
    die "tag $version (=$tagver) != package.json version $pkgver. The fleet health-gate compares these; an -rc tag would auto-roll-back. Bump package.json to match, or tag exactly v$pkgver."
  fi
  # FOOTGUN GUARD 2: a non-prerelease tag triggers the secret-gated npm/ecosystem
  # release jobs. Prerelease (default) skips them. Require --stable to opt in.
  if [ "$prerelease" = 0 ]; then
    warn "cutting a STABLE (non-prerelease) release — release-surfaces.yml will run the npm/ecosystem-consumer jobs (needs NPM_TOKEN/ECOSYSTEM_CONSUMER_TOKEN)."
  fi

  git -C "$REPO_ROOT" rev-parse -q --verify "$ref^{commit}" >/dev/null || die "ref not found: $ref"
  if git -C "$REPO_ROOT" rev-parse -q --verify "refs/tags/$version" >/dev/null 2>&1; then
    die "tag $version already exists locally — delete it first (git tag -d $version) if re-cutting"
  fi
  local target_sha; target_sha="$(git -C "$REPO_ROOT" rev-parse --short "$ref^{commit}")"

  # Confirm BEFORE signing, so an abort — or a non-interactive stdin — can never
  # strand a signed local tag.
  if [ "$assume_yes" != 1 ]; then
    if [ ! -t 0 ]; then
      die "non-interactive (no TTY on stdin): re-run with -y to confirm — e.g. 'scripts/release.sh cut $version -y'"
    fi
    printf '\033[1mrelease: sign + push %s (%s) to %s as a %s release? [y/N] \033[0m' \
      "$version" "$target_sha" "$GITHUB_REPO" "$([ "$prerelease" = 1 ] && echo prerelease || echo STABLE)" >&2
    local reply=""; read -r reply || reply=""
    [[ "$reply" =~ ^[Yy]$ ]] || die "aborted by user (nothing signed)"
  fi

  # Materialize the signing key to a 0600 temp file (removed on ANY exit path by
  # the global cleanup trap — see KEYFILE above).
  KEYFILE="$(mktemp)"; chmod 600 "$KEYFILE"
  get_signing_key > "$KEYFILE"
  [ -s "$KEYFILE" ] || die "signing key is empty (vault miss or empty env var)"
  # Secret stores (keyvault included) strip the trailing newline, but OpenSSH
  # private keys REQUIRE it — without it ssh-keygen reports 'invalid format',
  # which git surfaces as the confusing 'Couldn't load public key … No such
  # file or directory'. Re-add exactly one newline if the key doesn't end in one.
  if [ -n "$(tail -c1 "$KEYFILE")" ]; then printf '\n' >> "$KEYFILE"; fi

  [ -z "$notes" ] && notes="$version"
  log "signing $version @ $target_sha (SSH, signer $SIGNER_EMAIL)…"
  git -C "$REPO_ROOT" -c gpg.format=ssh -c user.signingkey="$KEYFILE" -c user.email="$SIGNER_EMAIL" \
      tag -s "$version" "$ref" -m "$notes"

  # Self-verify against the shipped allowed-signers BEFORE pushing, so we never
  # publish a tag the fleet's verify_tag would reject — but only when the file
  # has at least one real (non-comment) signer line.
  local signer_lines=0
  if [ -r "$ALLOWED_SIGNERS" ]; then
    signer_lines="$(grep -cvE '^[[:space:]]*(#|$)' "$ALLOWED_SIGNERS" 2>/dev/null || true)"
  fi
  if [ "${signer_lines:-0}" -gt 0 ]; then
    if git -C "$REPO_ROOT" -c gpg.format=ssh -c "gpg.ssh.allowedSignersFile=$ALLOWED_SIGNERS" \
         verify-tag "$version" >/dev/null 2>&1; then
      log "self-verify OK — signature trusts against fleet/allowed-signers"
    else
      git -C "$REPO_ROOT" tag -d "$version" >/dev/null 2>&1 || true
      die "self-verify FAILED — this key's public half is not in fleet/allowed-signers. Run: $0 setup"
    fi
  else
    warn "fleet/allowed-signers is empty — skipping self-verify. The fleet's verify_tag will REJECT this tag until you populate + ship it (run: $0 setup)."
  fi

  log "pushing tag…"
  git -C "$REPO_ROOT" push origin "$version"

  if command -v gh >/dev/null 2>&1; then
    log "creating GitHub release ($([ "$prerelease" = 1 ] && echo prerelease || echo stable))…"
    # Build the invocation without an empty array — "${arr[@]}" on an empty array
    # is an 'unbound variable' under `set -u` in bash 3.2 (macOS default).
    if [ "$prerelease" = 1 ]; then
      gh release create "$version" --repo "$GITHUB_REPO" --prerelease --title "$version" --notes "$notes" \
        || warn "gh release create failed (tag is pushed; create the release manually)"
    else
      gh release create "$version" --repo "$GITHUB_REPO" --title "$version" --notes "$notes" \
        || warn "gh release create failed (tag is pushed; create the release manually)"
    fi
  else
    warn "gh not installed — tag pushed, but no GitHub release created. Install gh or create it in the UI."
  fi

  if [ "$promote_canary" = 1 ]; then
    log "promoting fleet canary channel → $version…"
    node -e '
      const fs=require("fs"), p=process.argv[1], v=process.argv[2];
      const j=JSON.parse(fs.readFileSync(p,"utf8")); j.canary=v;
      fs.writeFileSync(p, JSON.stringify(j,null,2)+"\n");
    ' "$REPO_ROOT/fleet/channels.json" "$version"
    git -C "$REPO_ROOT" add fleet/channels.json
    git -C "$REPO_ROOT" commit -m "fleet: promote canary → $version" >/dev/null
    git -C "$REPO_ROOT" push origin HEAD
    log "canary promoted — the canary tier pulls $version on its next updater tick (health-gated)."
  fi

  log "done: $version released$([ "$promote_canary" = 1 ] && echo ' + canary promoted')."
}

# ---------------------------------------------------------------------------
cmd_status() {
  printf 'git:            %s\n' "$(git --version 2>/dev/null || echo MISSING)"
  printf 'gpg:            %s\n' "$(command -v gpg >/dev/null 2>&1 && gpg --version | head -1 || echo 'absent (fine — SSH signing used)')"
  printf 'gh:             %s\n' "$(command -v gh >/dev/null 2>&1 && echo present || echo 'absent (release step skipped)')"
  printf 'keyvault:       %s\n' "$(command -v keyvault >/dev/null 2>&1 && (keyvault status 2>/dev/null | head -1 || echo installed) || echo absent)"
  printf 'signer email:   %s\n' "${SIGNER_EMAIL:-<unset>}"
  if command -v keyvault >/dev/null 2>&1 && keyvault get "$VAULT_SCOPE/$VAULT_KEY_NAME" >/dev/null 2>&1; then
    printf 'signing key:    present in vault (%s/%s)\n' "$VAULT_SCOPE" "$VAULT_KEY_NAME"
  else
    printf 'signing key:    NOT in vault — run: %s setup\n' "$0"
  fi
  local as_n=0; [ -r "$ALLOWED_SIGNERS" ] && as_n="$(grep -cvE '^[[:space:]]*(#|$)' "$ALLOWED_SIGNERS" 2>/dev/null || true)"
  printf 'allowed-signers:%s\n' "$([ "${as_n:-0}" -gt 0 ] && echo " ${as_n} signer(s)" || echo ' none — run: setup')"
  printf 'package.json:    v%s (a fleet tag MUST be exactly this)\n' "$(node -p "require('$REPO_ROOT/package.json').version" 2>/dev/null || echo '?')"
}

main() {
  local sub="${1:-}"; shift || true
  case "$sub" in
    setup)  cmd_setup "$@" ;;
    cut)    cmd_cut "$@" ;;
    status) cmd_status "$@" ;;
    ''|-h|--help|help)
      sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' ;;
    *) die "unknown subcommand '$sub' (try: setup | cut | status)" ;;
  esac
}
main "$@"
