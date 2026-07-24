# Rollback — HiveRelay Blind public-test sidecar (release 1.0.0-rc.1.public-test.1)

Scope: stop the sidecar Blind Edge listener and the public-test containers ONLY.
Retained: all named volumes (IPC runtime + daemon data roots), all images, all
networks of other projects, and the entire existing fleet. T1
(`fleet/public-hive-gateway-release.json`, sha256
bfcc12664be108cdb13b1ca83f088a87fdcb03efa598377aca1c1d34a0f36064,
`enabled:false`) is never touched by this bundle.

The public-test deployment runs as the dedicated compose project
`hiverelay-blind-public-test` (see `docker-compose.blind-public-test.yml`), so
rollback never collides with any pre-existing `hiverelay-blind` project.

## Exact rollback

From the repository root on the relay host:

```sh
release/blind-public-test/rollback/rollback-public-test.sh
```

The script is idempotent and performs exactly:

1. `docker compose -p hiverelay-blind-public-test -f docker-compose.blind-public-test.yml stop blind-edge blind-daemon blind-volume-init`
   — stops the sidecar Edge listener first (no new public TCP 443 traffic), then
   the daemon and the one-shot initializer.
2. `docker compose -p hiverelay-blind-public-test -f docker-compose.blind-public-test.yml rm -f blind-edge blind-daemon blind-volume-init`
   — removes only those three containers.
3. Verifies the named volumes `hiverelay-blind-public-test_blind-runtime` and
   `hiverelay-blind-public-test_blind-data` still exist (roots retained).
4. Prints remaining project containers (must be empty) and remaining listeners
   on host TCP 443 owned by this project (must be none).

Never run `docker compose down -v` for this project: `-v` would delete the
retained roots. Plain `down` is permitted only when roots must be kept AND the
project network should also be removed; the script deliberately does not do it.

Optional flags:

- `--project-name NAME` — override the compose project name.
- `--remove-images` — additionally remove the digest-pinned test images from the
  local daemon (never required for rollback correctness; volumes stay).
- `--verify-t1 PATH` — additionally assert the T1 gateway release file still
  matches sha256 bfcc12664be108cdb13b1ca83f088a87fdcb03efa598377aca1c1d34a0f36064
  with enabled:false.

## Blast radius

- Removed: 3 containers of project `hiverelay-blind-public-test`.
- Retained: both named volumes (roots), images, TLS secret files on disk,
  all other compose projects, the production fleet, T1 (disabled).
