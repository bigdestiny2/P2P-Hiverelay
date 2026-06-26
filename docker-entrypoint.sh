#!/bin/sh
set -e
if [ "$(id -u)" = "0" ]; then
  if [ "$(stat -c %u /data 2>/dev/null)" != "999" ]; then
    chown -R hiverelay:hiverelay /data 2>/dev/null || true
  fi
  if [ "$(stat -c %u /config 2>/dev/null)" != "999" ]; then
    chown -R hiverelay:hiverelay /config 2>/dev/null || true
  fi
  exec gosu hiverelay "$@"
fi
exec "$@"
