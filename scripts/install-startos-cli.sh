#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: install-startos-cli.sh <install-dir> <github-path-file>" >&2
  exit 64
fi

install_dir="$1"
github_path_file="$2"
cli_url='https://github.com/Start9Labs/start-technologies/releases/download/start-cli%2Fv1.1.0/start-cli_x86_64-linux'
expected_sha='70eff67b6e9a936acd8aaaf787b783819252ecedaa5c74d462e3b15ed4dd843a'
cli_path="$install_dir/start-cli"

mkdir -p "$install_dir"
curl --fail --location \
  --proto '=https' \
  --proto-redir '=https' \
  --tlsv1.2 \
  --retry 3 \
  --retry-all-errors \
  --output "$cli_path" \
  "$cli_url"

# The downloaded file is deliberately neither executable nor on PATH until its
# bytes match the reviewed StartOS 1.1.0 release asset.
actual_sha="$(sha256sum "$cli_path" | cut -d ' ' -f 1)"
if [ "$actual_sha" != "$expected_sha" ]; then
  echo "start-cli checksum mismatch: got $actual_sha, expected $expected_sha for start-cli_x86_64-linux v1.1.0" >&2
  exit 1
fi

chmod 700 "$cli_path"
cli_version="$("$cli_path" --version)"
if [ "$cli_version" != 'start-cli 1.1.0' ]; then
  echo "start-cli version mismatch: got '$cli_version', expected 'start-cli 1.1.0'" >&2
  exit 1
fi

echo "$install_dir" >> "$github_path_file"
