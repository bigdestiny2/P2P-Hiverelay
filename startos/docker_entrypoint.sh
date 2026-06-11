#!/bin/sh
# Blindspark — StartOS container entrypoint.
#
# StartOS has no APP_SEED equivalent (Umbrel derives one from the user's
# device seed), so we persist our own on the data volume: first boot
# generates 32 random bytes, every later boot reuses them. That seed
# derives the dashboard's proxy-auth token AND keeps the relay identity
# stable across reinstalls — as long as the data volume survives, the
# node comes back as itself.
set -e

if [ ! -f /data/.app-seed ]; then
  head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > /data/.app-seed
  chmod 600 /data/.app-seed
fi
APP_SEED="$(cat /data/.app-seed)"
export APP_SEED

export HOME=/data
export HIVERELAY_API_HOST=0.0.0.0
export HIVERELAY_API_PORT=9100
# StartOS fronts the UI through its Tor/LAN proxy — same situation as
# Umbrel's app_proxy, same solution: embed the seed-derived bearer token
# in served HTML so the dashboard can authenticate (see v0.12.0 notes).
export HIVERELAY_UI_EXPOSE_TOKEN=1
# Sovereignty default: the operator reviews every incoming seed request
# until they explicitly switch modes from the dashboard.
export HIVERELAY_ACCEPT_MODE=review
export HIVERELAY_LOG_LEVEL=info

exec node /app/packages/core/cli/index.js start
