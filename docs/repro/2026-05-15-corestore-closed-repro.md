# Reproduction: `The corestore is closed` 503 on /api/v1/seed

**Date:** 2026-05-15 07:11Z
**Caught by:** `scripts/publish-test-drive.js --roundrobin`
**Relays affected:** Utah-US (`37cf4bfbdf33…`), Singapore-2 (`6b11208ad547…`)
**Relays healthy:** Utah (`1e7d8b1ffe69…`), Singapore-1 (`17ba6ae38d69…`), Bern (`bc421fedea8a…`)
**Version on all relays:** v0.8.12

## Symptom

`POST /api/v1/seed` returns:

```json
{
  "error": "The corestore is closed",
  "retryable": true,
  "hint": "transient corestore/hypercore lifecycle state; retry the request"
}
```

Status: 503. Retry returns the same. The relay's `/health` returns
`ok:true, running:true` throughout — the relay process is alive and
seems healthy at the systemd / health-monitor level, but the corestore
underlying its hyperdrive layer is wedged.

This matches the class the contributor flagged in the message of 2026-05-15 09:56Z:
> every prod host we've connected to (1e7d, 17ba, bc42, 0da2, 6b11, 37cf)
> accumulates state corruption after hours/days of uptime, surfacing as:
>   - Mutex has been destroyed on publish-channel SUBMIT_INTENT
>   - The corestore is closed on /api/v1/seed
>   - SESSION_CLOSED: Cannot make sessions on a closing core in stderr

## Repro

From the repo root on the publisher machine (laptop or any host with a
node ≥20):

```sh
node scripts/publish-test-drive.js --roundrobin --size 2mb --hold-seconds 120 --watch 60
```

Expected output on a healthy fleet — `OK 200` on every target,
anchor appears within ~7s.

Expected output on a fleet with wedged relays — at least one
`FAIL 503` with `The corestore is closed`, while the healthy ones
still `OK 200` and anchor normally.

Captured run (2026-05-15 07:11Z):
```
→ utah        ... OK 200  alreadySeeded=false
→ utah-us     ... FAIL 503 {"error":"The corestore is closed","retryable":true,...}
→ singapore-1 ... OK 200  alreadySeeded=false
→ singapore-2 ... FAIL 503 {"error":"The corestore is closed","retryable":true,...}
→ bern        ... OK 200  alreadySeeded=false

✓ anchored on bern after 6.3s
✓ anchored on singapore-1 after 6.3s
✓ anchored on utah after 7.2s
anchored on 3/5 relays
```

## Pre-failure pattern (from log dumps)

Both wedged relays show repeated `stale-connections — threshold
exceeded` warnings with growing counts over hours:

**Utah-US (pid 4156873, alive since 2026-05-15 05:27:49Z):**
```
05:58:26 stalePct=89 (8/9)
06:24:57 stalePct=89 (8/9)
06:58:57 stalePct=89 (8/9)
```

**Singapore-2 (pid 459739, alive ~6h before repro):**
```
00:56:56 stalePct=83 (5/6)
01:17:26 stalePct=83 (5/6)
01:58:26 stalePct=89 (8/9)
02:58:26 stalePct=90 (9/10)   ← growing
03:42:56 stalePct=91 (10/11)  ← growing
03:42:56 REQUEST_CANCELLED — recoverable rejection — continuing
03:42:56 REQUEST_CANCELLED — recoverable rejection — continuing
03:57:26 stalePct=91 (10/11)
04:10:56 stalePct=82 (9/11)   ← self-heal pruned
```

The `REQUEST_CANCELLED` rejections + the destroy-stale-connections
cycle correlate with the stale-ref accumulation the contributor hypothesised: the
relay is destroying connections that still have in-flight ops attached
to closed cores.

## Full log dumps

- [`2026-05-15-utah-us-corestore-closed.log`](./2026-05-15-utah-us-corestore-closed.log)
- [`2026-05-15-singapore-2-corestore-closed.log`](./2026-05-15-singapore-2-corestore-closed.log)

(Last 200 non-status lines from each, captured just after the failed
POSTs and before the bounce.)

## Workaround

Bounce the wedged relay:

```sh
ssh root@<host> 'systemctl restart hiverelay'
```

After bounce, `POST /api/v1/seed` returns 200 normally. State accumulates
again over hours. Same shape as the pearbrowser bounce request from
2026-05-14.

## Permanent fix

Tracked under "Reliability v2" — the contributor owns the audit + structural fix.
See his 2026-05-15 09:56Z message for the analysis. Expected fix shape:
a cancellation contract (AbortSignal + in-flight promise set drained
by `stop()`) covering `_eagerReplicate`, `_indexLog`, `_onConnection`,
and any other fire-and-forget loops that can outlive the corestore
they captured.

This file + the publisher script are the verification harness for that fix:
after the PR lands, a round-robin publish should return `OK 200` on every
relay regardless of uptime, and re-run should keep working over multi-day
windows.
