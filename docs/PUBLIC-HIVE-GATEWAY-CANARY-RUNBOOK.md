# Public HTTPS Hive Gateway Canary Runbook

Status: **staging-rehearsal ready; live-fleet deployment is gated on the blind
substrate**

This runbook brings one explicitly trusted public app to an ordinary HTTPS
URL through one raw VPS/systemd relay. It does not authorize a fleet rollout.
Until the blind-substrate role predicate replaces the transitional operator
allowlist, use this sequence only on an isolated test host/domain. The intended
first production use is the canary channel after the release gate below passes.

There are two deliberately different operating postures:

- `--mode canary` is the staging-rehearsal posture. It permits exactly one app
  and reports the transitional blind-substrate admission profile as a warning.
  Its output is useful test evidence, but it is not promotion evidence.
- `--mode fleet` is the frozen production posture. It rejects admission whose
  compiled capability is not fleet-ready, requires the installed nginx include,
  the nginx binary that emits the active parsed `nginx -T` configuration, and
  an explicit node connect IP for live evidence. It is the only posture accepted
  by the release-bound evidence verifier and fleet rollout gate.

The normative design and threat model are in
[`PUBLIC-HTTPS-HIVE-GATEWAY-SPEC.md`](PUBLIC-HTTPS-HIVE-GATEWAY-SPEC.md).

## Release gate

Before a production canary, all of the following must be true:

- the blind substrate has frozen its public-availability (T1), custody (T2),
  and witness (T3) role/storage semantics;
- enabling T2 cannot mount, advertise, or reach the public app listener, and
  mixed-role configurations fail closed;
- the gateway admission profile is no longer
  `transitional-operator-allowlist-v1`;
- the rebased unit, compatibility, TLS integration, lifecycle, and soak suites
  pass against the release commit;
- a signed release tag and an automatic systemd rollback target exist; and
- the operator has approved one public app, its expected bytes, domain, and
  observation window.

`--mode fleet` enforces this boundary. It intentionally fails while the
transitional admission profile remains active. Do not bypass that failure.
The code and packaging may be hardened in staging now; the first fleet canary
still waits for the blind-substrate gate and a release tag containing the
frozen admission profile.

## Canary topology

Keep the management and app surfaces on different external hostnames and
different loopback listeners:

```text
relay-api.operator.example:443          nginx -> 127.0.0.1:9100 API/WSS
*.hive-canary.operator.example:443      nginx -> 127.0.0.1:9200 app GET/HEAD
                                                   |
                                      one allowlisted public app key
```

The wildcard app virtual host must never proxy to port `9100`. The API virtual
host must never accept the wildcard app name. Ports `9100` and `9200` stay
firewalled and bound to loopback; only nginx exposes `443`.

Use one app for the first canary. `*.hive-canary.operator.example` is not a
browser cookie boundary merely because it uses subdomains. After the substrate
gate, a production canary with exactly one admitted app may proceed without a
Public Suffix List entry because there is no untrusted sibling app. Exposing
two or more mutually untrusted apps requires either a real PSL entry for the
app suffix or a separate registrable domain for every app. Until then:

- do not expose a second mutually untrusted app on that suffix;
- keep the gateway and app authentication cookie-free; and
- do not claim complete sibling-origin isolation.

The nginx template suppresses `Set-Cookie`, but the selected app must also be
reviewed for cookie use.

## 1. Choose the canary values

Run commands from the release worktree on the canary node and substitute the
real values:

```bash
export HIVERELAY_CONFIG="$HOME/.hiverelay/config.json"
export HIVE_APP_KEY="<64-hex-public-app-key>"
export HIVE_APP_SUFFIX="hive-canary.operator.example"
export HIVE_TLS_CERT="/etc/letsencrypt/live/hiverelay-public-apps/fullchain.pem"
export HIVE_TLS_KEY="/etc/letsencrypt/live/hiverelay-public-apps/privkey.pem"
export HIVE_CERTIFICATE_ROOT="/etc/letsencrypt"
export HIVE_INSTALLED_NGINX="/etc/nginx/conf.d/hiverelay-public-apps.conf"
export HIVE_NGINX_BINARY="/usr/sbin/nginx"
export HIVE_SS_BINARY="/usr/sbin/ss"
export HIVE_OPS_CONTRACT="$HOME/.hiverelay/gateway-evidence/operator-contract.json"
export HIVE_CONNECT_ADDRESS="127.0.0.1"
export HIVE_EXPECTED_SHA256="<publisher-verified-sha256-of-index.html>"
export HIVE_RELEASE_TARGET="vX.Y.Z"
export HIVE_RELEASE_SHA="$(git rev-parse "${HIVE_RELEASE_TARGET}^{commit}")"

export HIVE_APP_LABEL="$(node --input-type=module -e \
  "import { encodeHiveAppKey } from './packages/core/gateway/hive-host.js'; \
   console.log(encodeHiveAppKey(Buffer.from(process.env.HIVE_APP_KEY, 'hex')))" )"
export HIVE_ORIGIN="https://${HIVE_APP_LABEL}.${HIVE_APP_SUFFIX}/"
```

The expected digest must come from the publisher or the trusted source drive,
not from downloading the same gateway response that it is meant to check.

## 2. Provision DNS and wildcard TLS

Create a wildcard A/AAAA record for `*.hive-canary.operator.example` pointing
only to the canary edge. Keep `relay-api.operator.example` as a separate exact
record and certificate. A low DNS TTL is useful during canary rollback, but
DNS is not the health check or the application identity.

ACME wildcard certificates require DNS-01. Use a provider plugin with
credentials limited to the `_acme-challenge` record or a narrowly delegated
challenge zone; keep its credential file mode `0600`. The provider-specific
flags vary. This Cloudflare-shaped example must be changed to the operator's
installed DNS plugin and credential option:

```bash
sudo certbot certonly \
  --cert-name hiverelay-public-apps \
  --dns-cloudflare \
  --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini \
  -d "*.${HIVE_APP_SUFFIX}"
```

Never copy a wildcard private key to another operator. A second independent
gateway obtains its own domain, ACME account, certificate, and private key.

### 2.1 Freeze the operator-readiness contract

Before treating DNS or a certificate lookup as evidence, copy
`deploy/public-hive-gateway/operator-readiness-contract.example.json` into the
private evidence directory and replace every placeholder. This contract is the
reviewed expectation, not a dump of whatever DNS or TLS happens to return.
Obtain the expected A/AAAA set from the authenticated provider inventory and
the release fields from the verified signed release manifest. Do not populate
either from the live observation that they are intended to check.

The contract is exact on all of the following:

- `deploymentProfile` is only `public-t1-gateway`; T2, unknown, or a generic
  relay profile cannot pass fleet readiness;
- the key-derived app hostname, asserted registrable domain, and separate exact
  management/API hostname;
- an explicit `dual-stack`, `ipv4-only`, or `ipv6-only` policy and the complete
  globally routable address set;
- the node-local probe address, which is either numeric loopback or one of that
  exact public address set;
- the leaf certificate SHA-256 fingerprint and public-key SPKI SHA-256; and
- the release tag, content hash, immutable drive version, and complete active
  `nginx -T` hash. The verified commit SHA is supplied separately to the
  preflight and evidence verifier so it cannot create a self-referential
  contract digest.

For fleet publication, store the reviewed contract at the fixed tagged path
`fleet/public-hive-gateway-operators/<relay>.json`. The matching cohort entry
sets `deploymentProfile` to `public-t1-gateway` and carries the SHA-256 of the
canonical normalized contract. The publisher and updater derive that digest;
an arbitrary private contract path cannot replace the signed file. The
`HIVE_OPS_CONTRACT` copy above is only for staging/rehearsal before those tagged
bytes exist.

The asserted registrable domain must be checked against the current Public
Suffix List and registrar/DNS account outside this command. A string in the
contract does not prove domain or organizational ownership. For the one-app
Phase 1 topology, `publicSuffixReady` remains `false` unless there is separate
evidence for a real PSL or separate-registrable-domain boundary.

The leaf identity can be inspected while drafting the contract with local
OpenSSL, but those discovered values become trusted expectations only after
review and inclusion in the release process:

```bash
openssl x509 -in "$HIVE_TLS_CERT" -noout -fingerprint -sha256
openssl x509 -in "$HIVE_TLS_CERT" -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256
```

The readiness checker requires the full chain to contain the leaf followed by
its issuing CA/intermediate, an exact single DNS SAN of
`*.${HIVE_APP_SUFFIX}`, a matching RSA-2048-or-stronger or reviewed EC private
key, no API-host coverage, no duplicate/broken chain link, no group/world key
permissions, no more than a 398-day leaf lifetime, and at least seven days of
remaining validity. Certbot `live/` symlinks are accepted only when the command
is given the explicit `--certificate-root /etc/letsencrypt` containment root;
the resolved key must remain a root-owned single-link file in fleet mode.

For direct wildcard DNS, the live gate queries both the admitted app hostname
and a different canonical 52-character app-label witness. Both answers must
exactly equal the contract's A/AAAA set, use no CNAME, contain only globally
routable unicast addresses, have empty HTTPS/SVCB answers, and have TTLs from
30 through 900 seconds. The reviewed set contains at most one IPv4 and one IPv6
address. Every
published address is then contacted directly on port 443 with the key-derived
SNI and normal Web-PKI hostname validation; all endpoints must serve the same
reviewed leaf fingerprint and SPKI, and the browser-like content probe must
bind the same TLS protocol, certificate validity, unsigned metadata provenance,
immutable drive version, and exact bytes. This prevents a hidden IPv6 endpoint,
mutable vendor CNAME, or DNS-rebinding answer from escaping the reviewed edge
set at the time of the check.

HTTPS (type 65) and SVCB (type 64) are collected for both names with the
built-in bounded wire resolver, not generic Node `resolve()` or `dig`. It
validates a random query ID and the exact name/type/class question, rejects
malformed counts, CNAME ambiguity, and nonzero RCODEs, and retries truncated
UDP over one exactly framed bounded TCP response. Transport errors, SERVFAIL,
REFUSED, and timeouts fail; only an exact NOERROR empty RRset is empty.

## 3. Configure the loopback data plane

Merge the following fields into the relay's existing config. Do not replace
unrelated relay settings. A complete shape is also available at
`deploy/public-hive-gateway/hiverelay-config.example.json`.

```json
{
  "productProfile": "public-t1-gateway",
  "enableAPI": true,
  "enableSeeding": true,
  "apiHost": "127.0.0.1",
  "apiPort": 9100,
  "gatewayHost": "127.0.0.1",
  "gatewayPort": 9200,
  "gatewayTrustProxy": true,
  "gatewayTrustedProxyAddresses": ["127.0.0.1", "::1", "::ffff:127.0.0.1"],
  "gatewayRequireForwardedSNI": true,
  "gatewayCompatibilityHosts": ["127.0.0.1", "localhost", "[::1]"],
  "gatewayMaxInFlight": 256,
  "gatewayMaxInFlightPerApp": 32,
  "gatewayMaxResponseBytes": 67108864,
  "gatewayMaxTransformBytes": 4194304,
  "gatewayEgressBytesPerWindow": 268435456,
  "gatewayEgressWindowMs": 60000,
  "gatewayMaxResponseLifetimeMs": 900000,
  "custody": { "enabled": false },
  "hiveAppHostSuffix": "hive-canary.operator.example",
  "hiveAppPublicKeys": ["<64-hex-public-app-key>"],
  "hiveAppPublicVersions": {
    "<64-hex-public-app-key>": 7
  }
}
```

`enableSeeding: true` currently also starts SeedingRegistry. Do not activate an
enabled Public-T1 manifest until the storage update either bounds that workload
registry or enforces an explicit registry-disabled profile while retaining
direct seeding for the single pre-pinned app. The same update must persist
`storageProvedDriveVersion`; the release pin may select bytes only after that
independent storage-admission proof matches.

`productProfile: public-t1-gateway` is the exact post-substrate fleet value.
An isolated pre-merge host may exercise the same edge only with ops
`--mode rehearsal`; a generic `relay-core` observation is never accepted as
fleet evidence or channel-publication readiness.

Set a non-empty `HIVERELAY_API_KEY` in the relay's root-readable environment
file even though the API is loopback-only. The approved app must already be
seeded from the intended public Hyperdrive. Missing or contradictory public
admission must reject; there is no custody/private fallback.

Phase 1 admits exactly one manifest-bound app per gateway node, even if the
operator already has a Public Suffix. Multi-app admission is deferred until the
release manifest and evidence bind and probe the complete admitted set. For
fleet evidence, `hiveAppPublicVersions` must contain exactly the same one key and
the manifest's non-negative immutable `driveVersion`; the live probe rejects a
different `X-Hive-Drive-Version`. Canary preflight warns when the pin is absent,
but production fleet preflight fails closed.

For this transitional canary, `custody.enabled` must be exactly `false`. Run
the public availability gateway on a dedicated node while the blind substrate
is still defining its frozen role predicate. This is a deployment preflight
boundary, not a claim that safe mixed-role segregation is impossible later.

The loopback trusted-proxy configuration is also an explicit trust assumption:
only the reviewed nginx edge may be able to connect to port `9200` or originate
trusted forwarded-SNI headers. Loopback does not protect the gateway from a
hostile local process or another tenant sharing the host/network namespace.
Keep this phase on a dedicated, operator-controlled node; do not treat the
configuration as a multi-tenant isolation boundary.

## 4. Render and validate the TLS edge

Create a private evidence directory, run the static canary preflight, and
render the reviewed nginx template:

```bash
install -d -m 0700 "$HOME/.hiverelay/gateway-evidence"

npm run gateway:preflight -- \
  --mode canary \
  --config "$HIVERELAY_CONFIG" \
  --nginx-template deploy/public-hive-gateway/nginx.conf.template \
  --certificate "$HIVE_TLS_CERT" \
  --certificate-key "$HIVE_TLS_KEY" \
  --release-target "$HIVE_RELEASE_TARGET" \
  --release-sha "$HIVE_RELEASE_SHA" \
  --nginx-output "$HOME/.hiverelay/gateway-evidence/nginx-canary.conf" \
  --evidence "$HOME/.hiverelay/gateway-evidence/preflight-static.json"
```

The command requires `HIVERELAY_API_KEY` in its environment but never prints
or persists it. Load it from the existing root-readable service environment;
do not put it in a command argument or repository file. The canary result
should pass with three expected warnings: transitional blind-substrate
admission, no Public Suffix evidence, and disabled Phase 1 caching. Any other
warning or any error stops the rollout.

Install the rendered file, validate nginx, restart the relay, then reload the
edge:

```bash
sudo install -m 0644 \
  "$HOME/.hiverelay/gateway-evidence/nginx-canary.conf" \
  /etc/nginx/conf.d/hiverelay-public-apps.conf
sudo nginx -t
sudo systemctl restart hiverelay
sudo systemctl reload nginx
```

Inspect the complete `nginx -T` output, not just the rendered file. The API
virtual host must use only its exact `relay-api.operator.example` name. A
separate default TLS server must return `421` for unrelated SNI, and the app
virtual host must return `421` when TLS SNI and HTTP Host differ. Otherwise a
malformed app hostname could fall through to whichever virtual host nginx
loads as the default and accidentally reach the API. Active-parser inspection
and live evidence both pin these rules; forwarded Host headers must also be
unable to change app selection.

The repository includes a disposable real-parser rehearsal. It renders the
installed include, runs `nginx -T` in Docker, accepts the reviewed two-vhost
configuration, and proves that commented directives and split/competing
IPv4/IPv6 defaults fail policy even when nginx accepts their syntax:

```bash
node scripts/test-public-hive-gateway-nginx-docker.mjs
```

It defaults to the reviewed immutable nginx image digest embedded in the
harness. Set `HIVERELAY_NGINX_TEST_IMAGE` only to another reviewed, pinned
digest when rehearsing an intentional nginx upgrade.

This audit run could not access the Docker socket and therefore makes no fresh
real-image/default-config claim. Before activation, rerun the harness with
renewed authority and retain the pinned image ID plus complete `nginx -T`
artifact. The checked-in stock-shaped fixture permits parent `gzip on` only
because the app, default-reject, and quarantine vhosts each pin
`gzip off; gunzip off;` themselves.

Verify with `ss -tlnp` that the two upstream ports remain loopback-only. Do not
put a CDN, shared proxy cache, or a second load balancer in front of the
canary. Phase 1 responses are `Cache-Control: no-store`; the edge has
`proxy_cache off`, compression off, request buffering off, and no upstream
failover so exact bytes and failures stay attributable.
The app also strips `Accept-Encoding` before proxying, and live evidence
rejects `Content-Encoding` on metadata/exact/range/HEAD/non-probed responses.
The app, default-reject, and quarantine vhosts disable request access logging
and send only critical errors to stderr. Do not add public-edge log files;
bounded aggregate metrics and signed probes are the Phase 1 audit surface.

## 5. Capture live evidence

Probe a known exact file through public TLS:

```bash
npm run gateway:preflight -- \
  --mode canary \
  --config "$HIVERELAY_CONFIG" \
  --nginx-config "$HIVE_INSTALLED_NGINX" \
  --nginx-binary "$HIVE_NGINX_BINARY" \
  --probe-origin "$HIVE_ORIGIN" \
  --connect-address "$HIVE_CONNECT_ADDRESS" \
  --app-key "$HIVE_APP_KEY" \
  --path /index.html \
  --expected-sha256 "$HIVE_EXPECTED_SHA256" \
  --release-target "$HIVE_RELEASE_TARGET" \
  --release-sha "$HIVE_RELEASE_SHA" \
  --evidence "$HOME/.hiverelay/gateway-evidence/preflight-live.json"
```

This is staging evidence. Do not pass a `--mode canary` artifact to
`gateway:verify-evidence` or use it for channel promotion; the verifier accepts
only the frozen `fleet` posture. After the substrate gate, the fleet updater
generates and refreshes the promotion-grade artifact with the exact verified
tag/SHA, the installed include, and the complete configuration emitted by the
active nginx parser.

The public-safe evidence records the response digest, byte length, immutable
drive version, TLS protocol, certificate fingerprint and expiry, and successful
metadata, exact-byte, single-range, HEAD, management-isolation,
forwarded-header, unapproved-app, canonical-identity, unrelated-default-SNI,
and SNI/Host-binding checks. Exact responses must advertise both their
`hive://<app-key>/<path>` canonical identity and the well-known gateway metadata
`describedby` relation. The standalone fleet verifier
rejects a symlink, oversized artifact, release drift, absent live probe, stale
TLS, malformed certificate/content hashes, or any check that is not `true`.
By default it also rejects evidence or probe observations older than 24 hours
or more than five minutes in the future, so a same-tag artifact cannot be
reused indefinitely and clock drift fails visibly.
The observed leaf certificate must have at least seven days of validity
remaining. Its exact SHA-256 fingerprint is part of the signed node contract;
a renewed or replaced certificate therefore requires a new reviewed, signed
release manifest and a coordinated certificate/tag rollout. Do not let an
unattended certificate reload silently drift from the active release contract.
It must contain no API keys, ACME credentials, private keys, client IPs, query
values, cookies, or response bodies.

After the substrate gate, configure the canary updater with an absolute
node-local evidence path so every successful tagged update and every
no-op/up-to-date tick refreshes a release-bound artifact before the updater
declares success. Put literal values in the systemd unit's required root-only
environment file. Do not write `export`, shell variable references, or command
substitutions: systemd reads this as environment data, not as a shell script.
`fleet/install-updater.sh` creates the file mode `0600` and preserves its
contents on every idempotent reinstall.

```bash
# /etc/hiverelay/hiverelay-updater.env
HIVERELAY_PUBLIC_GATEWAY_PROBE_CONFIG="/root/.hiverelay/config.json"
HIVERELAY_PUBLIC_GATEWAY_PROBE_NGINX_CONFIG="/etc/nginx/conf.d/hiverelay-public-apps.conf"
HIVERELAY_PUBLIC_GATEWAY_PROBE_NGINX_BINARY="/usr/sbin/nginx"
HIVERELAY_PUBLIC_GATEWAY_PROBE_EVIDENCE="/root/.hiverelay/gateway-evidence/preflight-live.json"
HIVERELAY_PUBLIC_GATEWAY_PROBE_PUBLIC_SUFFIX_READY="0"
HIVERELAY_PUBLIC_GATEWAY_OPS_CERTIFICATE="/etc/letsencrypt/live/hiverelay-public-apps/fullchain.pem"
HIVERELAY_PUBLIC_GATEWAY_OPS_CERTIFICATE_KEY="/etc/letsencrypt/live/hiverelay-public-apps/privkey.pem"
HIVERELAY_PUBLIC_GATEWAY_OPS_CERTIFICATE_ROOT="/etc/letsencrypt"
HIVERELAY_PUBLIC_GATEWAY_OPS_SS_BINARY="/usr/sbin/ss"
HIVERELAY_PUBLIC_GATEWAY_OPS_EVIDENCE="/root/.hiverelay/gateway-evidence/operator-readiness.json"
HIVERELAY_PUBLIC_GATEWAY_QUARANTINE_BACKUP="/etc/nginx/conf.d/hiverelay-public-apps.conf.pre-quarantine"
```

Install or refresh the unit without losing those values, then exercise the
same entry point and environment used by timer ticks:

```bash
sudo chmod 0600 /etc/hiverelay/hiverelay-updater.env
sudo bash fleet/install-updater.sh canary utah
sudo systemctl start hiverelay-updater.service
sudo journalctl -u hiverelay-updater.service -n 50 --no-pager
```

Replace `utah` with the exact node identity from `fleet/relays.json`. The
installer persists that mandatory `RELAY_NAME` beside the channel so deleting
probe environment cannot disguise a signed cohort node as an ordinary relay.

The installed command is a stable trust-checking launcher. It verifies that
the checked-out `fleet/updater.sh` exactly matches `HEAD` and that `HEAD` is a
trusted signed release tag before executing it, so updater fixes advance with
signed releases rather than remaining frozen in `/usr/local/bin`.

After verifying the target tag, the updater reads and normalizes the canonical
manifest from that exact commit. Cohort membership, admission profile, origin,
connect address, app key/path, expected content hash, immutable drive version,
certificate fingerprint, and active nginx hash all come from that signed
record. The retired mutable environment names for those values are ignored and
must not be reintroduced. The local environment only names the relay config,
installed nginx fragment and binary, content/ops evidence destinations,
certificate/key/root, reviewed `ss` binary, and optional test CA, timeout, or
quarantine backup. All required paths are absolute; a missing cohort path
fails closed. These paths cannot select the deployment profile or operator
contract digest.

Set `HIVERELAY_PUBLIC_GATEWAY_PROBE_CA` only for a private/test CA. Set
`HIVERELAY_PUBLIC_GATEWAY_PROBE_PUBLIC_SUFFIX_READY=1` only for a proven PSL or
separate-registrable-domain topology; one admitted app may retain `0` after the
substrate gate, but two or more apps fail closed with `0`.

The API key is read from the protected service environment and passed only as
a child-process environment value, never argv or evidence. A failed gateway
probe after a new checkout triggers the existing code rollback. A failure when
already on the target has no code change to roll back: the updater atomically
replaces stale evidence with an invalid tombstone and runs the narrow
quarantine helper. That helper replaces only the public-app nginx fragment
with a TLS default `421` response; the exact management/API virtual host and
HiveRelay service remain running. If either containment step fails, the updater
reports critical, incomplete containment for operator action. The verifier
used for retirement is first materialized from the exact current release SHA,
including its complete local module closure, so a target checkout cannot swap
the authority that judges containment. The updater accepts only stable,
owner-trusted, single-link helper/nginx executables whose lexical paths equal
their physical canonical paths under non-writable ancestor chains, and holds
its systemd-created root-only runtime-directory lock for the whole tick. The
launcher, updater, frozen verifier, and helper reject intermediate ancestor
symlinks rather than validating only their current resolved targets.

A node-local code rollback does not move the controller's canary channel back.
Until a new release is explicitly selected, that node will retry the rejected
tag on later updater ticks. Revert the faulty behavior in a new signed
descendant release and use the receipt-bound `recover-canary` transition in
section 7.4; reverse channel movement is intentionally unsupported.

Also retain these release-local results:

```bash
npm run audit:relaykernel-gateway
npm run test:public-hive-gateway:live
npm run test:public-hive-gateway:soak
sudo certbot renew --cert-name hiverelay-public-apps --dry-run
```

### 5.1 Capture operator DNS/TLS/socket readiness

After `preflight-live.json` passes, bind it to the independent edge checks:

```bash
npm run gateway:preflight-ops -- \
  --mode rehearsal \
  --contract "$HIVE_OPS_CONTRACT" \
  --config "$HIVERELAY_CONFIG" \
  --gateway-evidence "$HOME/.hiverelay/gateway-evidence/preflight-live.json" \
  --release-sha "$HIVE_RELEASE_SHA" \
  --certificate "$HIVE_TLS_CERT" \
  --certificate-key "$HIVE_TLS_KEY" \
  --certificate-root "$HIVE_CERTIFICATE_ROOT" \
  --dns-live \
  --ss-binary "$HIVE_SS_BINARY" \
  --evidence "$HOME/.hiverelay/gateway-evidence/preflight-ops.json"
```

This live command adds four things that the content probe alone cannot prove:

1. the on-disk fullchain, key, wildcard SAN, expiry, fingerprint, and SPKI are
   mutually consistent and equal the reviewed contract;
2. both wildcard DNS observations equal the complete reviewed IPv4/IPv6 set;
3. every DNS address completes normal HTTPS validation with that same leaf;
4. live `ss -H -lntup` output has exactly one numeric-loopback TCP socket for
   the API and app gateway ports, the reviewed IPv4/IPv6 TCP listeners on port
   443, and no UDP/QUIC listener on port 443.

Use `--dns-snapshot`, `--tls-snapshot`, and `--socket-snapshot` only for local
rehearsal fixtures. Their evidence is labelled `fixture` and cannot claim live
DNS, Web-PKI, or socket state. Fleet mode rejects every fixture and private CA,
requires `--dns-live` and `--ss-binary`, validates the base artifact in its
strict signed-release `fleet` posture, and requires the merged config's exact
compiled product profile to be `public-t1-gateway`. It therefore remains
intentionally closed before the blind-substrate merge.

Some hosts cannot reach their own public address because their provider lacks
NAT hairpin support. That is a deployment-topology failure for this combined
node-local command, not permission to replace the live TLS result with a fleet
fixture. Either provision a directly addressed VPS/network that supports the
check or later add an authenticated external T3 observation schema and combine
it with the node-local socket result. That schema does not exist yet.

The ops artifact deliberately states that it does **not** prove blind G2/G3,
Public Suffix/registrar ownership, operator organizational control, continuous
runtime enforcement, or an independent timestamp. It does prove that the
exact finite production policy was contract-bound and present in the observed
runtime config, and that the locally reviewed public-T1 DNS/TLS/socket edge
posture was observed at the recorded time. Runtime negative tests establish
the corresponding finite-limit behavior. Continuous DNS/certificate drift
detection still requires this command on every updater/observer tick after its
contract fields are part of the signed release.

Observe the staging canary for at least 24 hours before proposing a production
release. This rehearsal does not replace the signed-manifest-defined production
observation window in section 7. Require clean same-port restarts, bounded shutdown during
stalled clients, bounded memory/concurrency, no management route exposure, no
unexpected `Set-Cookie` or cacheable responses, and a fresh live probe after
restart. Treat only 2xx exact-content probes as healthy.

## 6. Quarantine and recover the public edge

Use the installed helper for a manual public-edge rollback. It retains the
certificate directives, atomically swaps the active app fragment for a default
TLS `421` vhost, validates the complete nginx configuration, and reloads nginx.
It never invokes `sudo` or `systemctl` itself and does not touch the management
virtual host:

```bash
sudo /usr/local/sbin/hiverelay-quarantine-public-gateway \
  /etc/nginx/conf.d/hiverelay-public-apps.conf \
  /etc/nginx/conf.d/hiverelay-public-apps.conf.pre-quarantine \
  /usr/sbin/nginx
```

The backup is the exact pre-quarantine fragment and is never overwritten. Once
the trusted nginx boundary is armed, any command failure or HUP/INT/TERM before
successful validation and reload attempts to stop nginx exactly once. On
validation, reload, or intermediate containment failure, the helper retains
the reject fragment when present and never restores the formerly open app
vhost automatically. After fixing the cause, explicitly
restore the reviewed backup and re-run the manifest-bound updater gate:

```bash
sudo mv /etc/nginx/conf.d/hiverelay-public-apps.conf \
  /etc/nginx/conf.d/hiverelay-public-apps.conf.quarantined
sudo mv /etc/nginx/conf.d/hiverelay-public-apps.conf.pre-quarantine \
  /etc/nginx/conf.d/hiverelay-public-apps.conf
sudo nginx -t
sudo nginx -s reload
sudo systemctl start hiverelay-updater.service
```

If `nginx -t` fails, do not reload. Move the invalid active fragment back to
`hiverelay-public-apps.conf.pre-quarantine`, move
`hiverelay-public-apps.conf.quarantined` back to the active path, then validate
again before leaving the host. A successful updater tick writes new verified
evidence. The invalid tombstone must never be treated as promotion evidence.

For a longer shutdown, also disable the internal listener by clearing
`hiveAppPublicKeys` and
`hiveAppHostSuffix` and setting `gatewayPort` to `null`; restart HiveRelay.
The separate API hostname and port remain untouched. Remove or retarget the
wildcard DNS record after the edge is closed, and let the existing fleet
updater restore the last healthy signed tag when the release itself caused the
failure.

Record the failed release/tag, old and new commits, probe error, rollback time,
post-rollback API health, and whether DNS was changed. Do not delete
certificates, private keys, or logs during incident triage.

## 7. Signed release, canary, and stable promotion

This section is the post-substrate production flow. Do not enable the checked-in
placeholder manifest or run these commands against the live fleet while the
admission profile is still transitional.

The first enabled manifest must not share a release with the updater/identity
bootstrap. Publish a prior signed release with the manifest missing or exactly
disabled, then reinstall the updater on every raw node with its exact
`fleet/relays.json` name and verify a timer tick. Existing updater code cannot
enforce a new target's cohort contract while it is performing the checkout;
the later enabled-manifest release is the first release this updater can gate
end to end.

That disabled bootstrap must already contain the exact quarantine helper,
verifier, quarantine-authority library, release-manifest library, and policy
library. Enabled publication requires those five files plus `fleet/updater.sh`
to be blob-identical in the target and trusted signed predecessor, with exact
tracked modes. Each updater freezes the five-file current authority and
requires the installed root helper to match its bytes before containment; an
old root-owned helper is not silently accepted.

### 7.1 Freeze the release manifest

Populate `fleet/public-hive-gateway-release.json` before cutting the tag. The
file is covered by the trusted signed annotated tag because rollout and
promotion read it from that exact commit, not from the mutable working tree.
Its closed schema binds the admission profile and observation policy plus the
exact expectation for every approved gateway-cohort node. A minimal shape is:

```json
{
  "schema": "hiverelay-public-gateway-release-v1",
  "enabled": true,
  "releaseTarget": "vX.Y.Z",
  "admissionProfile": "public-availability-v1",
  "observationWindowMs": 86400000,
  "maxProbeGapMs": 1800000,
  "cohort": [
    {
      "relay": "canary-1",
      "channel": "canary",
      "suffix": "hive-canary.operator.example",
      "origin": "https://<z32-app-key>.hive-canary.operator.example/",
      "connectAddress": "127.0.0.1",
      "appKey": "<64-lowercase-hex-app-key>",
      "path": "/index.html",
      "contentSha256": "<publisher-supplied-64-hex-sha256>",
      "driveVersion": "<immutable-decimal-drive-version>",
      "peerFingerprint256": "<colon-separated-certificate-sha256>",
      "nginxConfigSha256": "<64-hex-complete-active-nginx-T-sha256>"
    }
  ]
}
```

The real manifest contains exactly the gateway-enabled relays approved for this
release; ordinary non-gateway fleet relays do not need dummy entries. The
snippet is illustrative, not a complete production cohort. The observation
window is at least 24 hours. Use `maxProbeGapMs: 1800000` (30 minutes) for the
current fleet timer: its 15-minute interval plus up to five minutes of jitter
can exceed a 15-minute contract despite a healthy node.
`contentSha256` comes from the publisher or trusted source drive. Origin,
connect IP, app/path, drive version, certificate fingerprint, and nginx hash
are node-specific release inputs. Changing any one requires a new signed
release contract; it is not an operator-side wildcard. For a node-local check,
prefer `127.0.0.1` so the HTTPS request still exercises nginx/SNI/Host while
avoiding mutable public DNS routing; use another exact IP only when the reviewed
topology requires it.
The node's sole `hiveAppPublicKeys` entry and sole `hiveAppPublicVersions` pin
must equal this manifest app key and drive version. A Public Suffix assertion
does not authorize additional unmanifested apps in Phase 1.

Generic release preparation must not move a fleet channel for an enabled
public-gateway release. Prepare with `--channel none`, commit the reviewed
manifest and release surfaces, then cut the signed tag without the legacy
`--promote-canary` convenience flag:

```bash
npm run release:prepare -- "$HIVE_RELEASE_TARGET" \
  --image-digest "sha256:<multi-arch-image-digest>" \
  --channel none

scripts/release.sh cut "$HIVE_RELEASE_TARGET"
```

Publish only canary from a completely clean, attached `main` that exactly
matches `origin/main`. The publisher runs the signature-verifying promoter,
checks the remote for races, and defaults to validation-only without changing
the control worktree, refs, or remotes. Review that
result, then repeat the same arguments with explicit `--publish`; do not edit
`fleet/channels.json` by hand or rebuild between canary and stable:

```bash
export HIVE_ALLOWED_SIGNERS="$HOME/.config/hiverelay/allowed-signers"
export HIVE_GATEWAY_OPS_EVIDENCE_DIR="$HOME/.hiverelay/gateway-evidence/operator-readiness"

npm run fleet:publish-channel -- \
  --channel canary \
  --target "$HIVE_RELEASE_TARGET" \
  --allowed-signers "$HIVE_ALLOWED_SIGNERS" \
  --gateway-ops-evidence-dir "$HIVE_GATEWAY_OPS_EVIDENCE_DIR"

npm run fleet:publish-channel -- \
  --channel canary \
  --target "$HIVE_RELEASE_TARGET" \
  --allowed-signers "$HIVE_ALLOWED_SIGNERS" \
  --gateway-ops-evidence-dir "$HIVE_GATEWAY_OPS_EVIDENCE_DIR" \
  --publish
```

The publisher's internal promoter always reads the canonical
`fleet/public-hive-gateway-release.json` from the trusted signed tag. When that
tagged manifest is enabled, the public-gateway gate is automatic: omitting
`--require-public-gateway` cannot weaken it. Canary promotion validates the
complete manifest, its nonempty canary cohort, and the cohort's mapping into the
current full inventory. Publication then creates and locally verifies a signed
commit changing only `fleet/channels.json` and uses an atomic compare-and-swap
publication with exact branch/tag leases. Only the pinned release-tag object
and signed channel commit are sent; unrelated refs and unguarded force updates
are disabled. A
missing or explicitly disabled tagged manifest retains the legacy non-gateway
promotion path.

For every `public-t1-gateway` cohort entry, the directory contains one fresh
`<relay>.json` fleet artifact produced from that relay's signed operator
contract. The publisher reads the manifest and fixed contract path from the
exact tagged commit, derives the canonical digest, and rejects missing, stale,
fixture-derived, or drifted evidence. Refresh the artifact bytes before each
canary or stable validation; do not change the directory or signed operator
invariants between transitions. Legacy manifests omit this option.

Provision that `allowed_signers` trust root through the release-key ceremony;
do not derive it from the unverified target tag.

### 7.2 Accumulate pinned canary evidence

Provision a local `known_hosts` file from an authenticated inventory or host-key
ceremony; do not learn keys with `accept-new` during this check. Then run the
manifest-bound rollout command from the release repository:

```bash
export HIVE_FLEET_KNOWN_HOSTS="$HOME/.ssh/hiverelay-fleet-known-hosts"
export HIVE_GATEWAY_WINDOW_STATE="$HOME/.hiverelay/gateway-evidence/canary-window.json"
export HIVE_CANARY_EVIDENCE="$HOME/.hiverelay/gateway-evidence/canary-fleet-rollout-evidence.json"

npm run fleet:check-rollout -- \
  --target "$HIVE_RELEASE_TARGET" \
  --target-sha "$HIVE_RELEASE_SHA" \
  --channel canary \
  --known-hosts "$HIVE_FLEET_KNOWN_HOSTS" \
  --allowed-signers "$HIVE_ALLOWED_SIGNERS" \
  --gateway-evidence /root/.hiverelay/gateway-evidence/preflight-live.json \
  --gateway-manifest fleet/public-hive-gateway-release.json \
  --gateway-window-state "$HIVE_GATEWAY_WINDOW_STATE" \
  --evidence "$HIVE_CANARY_EVIDENCE"
```

That one-shot check returns status `2` while the manifest-defined window is still
observing. Use the fail-fast observer to repeat the same authoritative checker
at a safe cadence; any red result stops immediately and completion does not
publish stable:

```bash
npm run gateway:observe-rollout -- \
  --sample-interval-ms 60000 \
  -- \
  --target "$HIVE_RELEASE_TARGET" \
  --target-sha "$HIVE_RELEASE_SHA" \
  --channel canary \
  --known-hosts "$HIVE_FLEET_KNOWN_HOSTS" \
  --allowed-signers "$HIVE_ALLOWED_SIGNERS" \
  --gateway-evidence /root/.hiverelay/gateway-evidence/preflight-live.json \
  --gateway-manifest fleet/public-hive-gateway-release.json \
  --gateway-window-state "$HIVE_GATEWAY_WINDOW_STATE" \
  --evidence "$HIVE_CANARY_EVIDENCE"
```

The checker verifies the signed tag, reads the manifest from its exact commit,
restricts the check to the signed canary cohort, requires every cohort relay in
inventory with the same channel, uses strict pinned SSH host keys, and remotely
verifies each fresh artifact against its node entry. The supplied `known_hosts`
file is the exclusive SSH host-key authority; global OpenSSH host-key files are
disabled for this path. The remote verifier runs only when the tracked target
worktree is clean and `HEAD` equals the signed release SHA.

Each observation-state sample stores both the relay's probe time and the
controller's collection time. Both timelines must span the manifest-defined window, both
must stay within `maxProbeGapMs`, and the latest sample must still be fresh;
relay clock manipulation or an old completed state cannot manufacture current
24-hour continuity. A green sample exits with
status `2` and `observing` evidence until the manifest-defined observation window is
complete. Run it again after each updater
cycle has produced a fresh probe, at an interval no greater than the manifest's
`maxProbeGapMs`. Running the observer more often cannot manufacture newer relay
evidence between updater ticks. A failure or excessive gap resets continuity;
do not turn status `2` into success in automation. Only a completed window
returns success
and writes `verified` schema-v2 rollout evidence. Run the final check after a
fresh updater probe and promote promptly: stable promotion recomputes the state
and refuses rollout evidence or latest relay samples older than 30 minutes.

The authority boundary here is exact: the signed release manifest fixes the
cohort, duration, and maximum gap, but the accumulated observation-state file
is controller-retained local data. It is manifest-bound and each sample names
the fresh relay evidence collected through pinned SSH; the state itself is not
cryptographically signed or independently timestamped. This protects the
normal operator path from accidental reuse, gaps, and drift. It is not proof
against a controller/operator with publication authority fabricating history.
Independent T3 witness observations or an external timestamp attestation are
the future production-grade proof for that stronger claim. Do not describe the
current file as a signed observation state.

Required live checks include exact bytes, Range, HEAD, canonical links,
management and unavailable-app isolation, forwarded-Host isolation, unrelated
default-SNI rejection, and SNI/Host mismatch rejection. A default vhost or Host
binding regression therefore cannot be waived by an otherwise healthy relay.

### 7.3 Promote the same tag to stable

After the completed window, a fresh post-restart check, and recorded human
approval, validate stable publication from the same clean, current `main`.
Review the dry-run, then repeat the exact evidence arguments with explicit
`--publish`:

```bash
npm run fleet:publish-channel -- \
  --channel stable \
  --target "$HIVE_RELEASE_TARGET" \
  --allowed-signers "$HIVE_ALLOWED_SIGNERS" \
  --canary-evidence "$HIVE_CANARY_EVIDENCE" \
  --gateway-window-state "$HIVE_GATEWAY_WINDOW_STATE" \
  --relays "$PWD/fleet/relays.json" \
  --gateway-ops-evidence-dir "$HIVE_GATEWAY_OPS_EVIDENCE_DIR"

npm run fleet:publish-channel -- \
  --channel stable \
  --target "$HIVE_RELEASE_TARGET" \
  --allowed-signers "$HIVE_ALLOWED_SIGNERS" \
  --canary-evidence "$HIVE_CANARY_EVIDENCE" \
  --gateway-window-state "$HIVE_GATEWAY_WINDOW_STATE" \
  --relays "$PWD/fleet/relays.json" \
  --gateway-ops-evidence-dir "$HIVE_GATEWAY_OPS_EVIDENCE_DIR" \
  --publish
```

For an enabled canonical tagged manifest, the publisher automatically re-verifies
the trusted tag and package version, the tagged manifest, its cohort's mapping
into current inventory, completed observation state, and all-green canary
evidence before signing and publishing the stable-channel-only change. The explicit
`--require-public-gateway` option remains only for legacy releases that use a
noncanonical opt-in manifest; it is not the security switch for canonical
public-gateway releases.
Stable remains a separate human-authorized command; canary completion never
advances it automatically. Let the updater converge stable in stages and stop
on the first drift. The two-operator verifier establishes only technical
separation of asserted contract identities, domains, keys, and address sets.
An independent-operator claim additionally requires authenticated external
review of domain/account and organizational control.

### 7.4 Guarded one-command transitions

`gateway:deploy` is the recommended operator wrapper around the publisher and
observer. It does not add a deployment authority or bypass an existing gate.
It binds the exact tag SHA into the authorization phrase, keeps private
controller receipts, starts a fresh observation only when the session, state,
and evidence paths do not exist, and requires stable to consume the unchanged
completed session. The receipts are mode `0600` controller records, not T3
witness signatures.

Create a private deployment directory and select new filenames for this
release:

```bash
export HIVE_DEPLOY_DIR="$HOME/.hiverelay/gateway-evidence/deploy-${HIVE_RELEASE_TARGET}"
install -d -m 0700 "$HIVE_DEPLOY_DIR"
export HIVE_CANARY_RECEIPT="$HIVE_DEPLOY_DIR/canary.json"
export HIVE_OBSERVATION_SESSION="$HIVE_DEPLOY_DIR/observation-session.json"
export HIVE_GATEWAY_WINDOW_STATE="$HIVE_DEPLOY_DIR/canary-window.json"
export HIVE_CANARY_EVIDENCE="$HIVE_DEPLOY_DIR/canary-rollout.json"
export HIVE_STABLE_RECEIPT="$HIVE_DEPLOY_DIR/stable.json"
export HIVE_GATEWAY_OPS_EVIDENCE_DIR="$HIVE_DEPLOY_DIR/operator-readiness"
install -d -m 0700 "$HIVE_GATEWAY_OPS_EVIDENCE_DIR"
```

One explicitly authorized canary command performs its own validation-only pass
before the publisher's atomic compare-and-swap. The authorization is not a
secret; it is an exact operator acknowledgement of the tag and commit:

```bash
npm run gateway:deploy -- canary \
  --target "$HIVE_RELEASE_TARGET" \
  --target-sha "$HIVE_RELEASE_SHA" \
  --allowed-signers "$HIVE_ALLOWED_SIGNERS" \
  --relays "$PWD/fleet/relays.json" \
  --gateway-ops-evidence-dir "$HIVE_GATEWAY_OPS_EVIDENCE_DIR" \
  --publish \
  --authorize "publish-canary:${HIVE_RELEASE_TARGET}:${HIVE_RELEASE_SHA}" \
  --receipt "$HIVE_CANARY_RECEIPT"
```

Start the controller-retained observation from empty state. This command owns
status `2` sampling and cannot publish stable. If the controller process is
interrupted without a red result, repeat the exact command with `--resume`;
changed trust roots, paths, or checker arguments are rejected by the retained
session contract. A red result marks the session failed and requires new
session/state/evidence filenames.

```bash
npm run gateway:deploy -- observe \
  --target "$HIVE_RELEASE_TARGET" \
  --target-sha "$HIVE_RELEASE_SHA" \
  --allowed-signers "$HIVE_ALLOWED_SIGNERS" \
  --relays "$PWD/fleet/relays.json" \
  --canary-receipt "$HIVE_CANARY_RECEIPT" \
  --session "$HIVE_OBSERVATION_SESSION" \
  --known-hosts "$HIVE_FLEET_KNOWN_HOSTS" \
  --gateway-evidence /root/.hiverelay/gateway-evidence/preflight-live.json \
  --gateway-window-state "$HIVE_GATEWAY_WINDOW_STATE" \
  --evidence "$HIVE_CANARY_EVIDENCE"
```

After fresh evidence, the complete manifest-defined window, and recorded human
approval, stable remains one separate authorized transition:

```bash
npm run gateway:deploy -- stable \
  --target "$HIVE_RELEASE_TARGET" \
  --target-sha "$HIVE_RELEASE_SHA" \
  --allowed-signers "$HIVE_ALLOWED_SIGNERS" \
  --relays "$PWD/fleet/relays.json" \
  --gateway-ops-evidence-dir "$HIVE_GATEWAY_OPS_EVIDENCE_DIR" \
  --canary-receipt "$HIVE_CANARY_RECEIPT" \
  --session "$HIVE_OBSERVATION_SESSION" \
  --publish \
  --authorize "publish-stable:${HIVE_RELEASE_TARGET}:${HIVE_RELEASE_SHA}" \
  --receipt "$HIVE_STABLE_RECEIPT"
```

If the release causes a canary rollback or repeated quarantine, create and sign
a new release tag whose commit descends from the failed canary commit. Validate
the receipt-bound forward recovery to obtain the exact authorization phrase,
then publish it. The wrapper refuses recovery after stable already points at
the failed release, and compare-and-swaps only while canary still names the
failed receipt-bound tag and SHA:

```bash
npm run gateway:deploy -- recover-canary \
  --target "$HIVE_RECOVERY_TARGET" \
  --target-sha "$HIVE_RECOVERY_SHA" \
  --allowed-signers "$HIVE_ALLOWED_SIGNERS" \
  --relays "$PWD/fleet/relays.json" \
  --gateway-ops-evidence-dir "$HIVE_GATEWAY_OPS_EVIDENCE_DIR" \
  --canary-receipt "$HIVE_CANARY_RECEIPT"

# Repeat with --publish, --receipt <new-private-path>, and the exact
# recover-canary:<failed-tag>:<failed-sha>->... authorization printed by
# the validation result.
```

The canary receipt binds the absolute ops directory and the signed invariants
(relay/operator/domain/suffix, canonical contract digest, certificate SPKI,
and address set), not the rotating artifact timestamp or file hash. Stable
therefore accepts freshly regenerated artifacts from the same directory after
the 24-hour window but rejects an operator, contract, key, address, or path
swap. `abort-canary` is retired and fails before publisher invocation. Recovery
uses the normal target manifest/operator gates and binds the failed receipt,
trust-root bytes, evidence directory, and normalized operator contracts into
its authorization token and private transition receipt.

Before a real release, rehearse the same signed-tag, local bare-remote,
publisher, updater rollback/quarantine, observation, and explicit stable flow
without touching live refs or hosts:

```bash
npm run gateway:rehearse-deploy
```

The disposable test time-compresses controller timestamps to exercise the real
stable validator. Its artifacts are deleted and are never production evidence;
the live canary still has to accumulate the full wall-clock window through the
authoritative observer.

## Packaging boundary

The public gateway remains disabled on Umbrel and StartOS for this phase. Do
not add port `9200`, wildcard domains/certificates, trusted-proxy settings, or
`hiveAppPublicKeys` to those packages. Their platform proxies, persistence,
update/rollback flows, and store-review threat models need a separate design
and real-device test pass. Only the raw VPS/systemd channel is in scope for the
first canary and stable rollout.
