# Public HTTPS Hive Gateway Specification

Status: **isolated Phase 1 canary implementation under hardening; live-fleet
deployment gated on the blind substrate**

This document specifies browser-compatible HTTPS access to public HiveRelay
applications without making one company, domain, gateway, directory, or TLS
key the identity of the application.

The Phase 1 transport, exact-byte serving, strict TLS-edge template, preflight,
and local multi-gateway TLS harness are implemented in an isolated worktree.
They may be tested on an operator-controlled staging host with one explicitly
trusted public app. Integration into the release branch and live fleet remains
blocked until the blind-substrate update owns and tests the public/custody role
boundary. See
[`PUBLIC-HIVE-GATEWAY-CANARY-RUNBOOK.md`](PUBLIC-HIVE-GATEWAY-CANARY-RUNBOOK.md)
for the deployment sequence and rollback contract.

## Current deployment boundary

| Surface | Current state |
| --- | --- |
| Isolated unit, TLS integration, lifecycle, and soak testing | Active |
| Operator-controlled staging hostname (`canary` posture) | Allowed for exactly one trusted public app; evidence is not promotion-grade |
| Raw VPS/systemd live-fleet canary | Blocked until the blind-substrate release gates pass |
| Raw VPS/systemd stable promotion | Blocked until canary evidence and explicit approval |
| Umbrel and StartOS | Public app gateway disabled; packaging is out of Phase 1 scope |

The preflight names these postures explicitly. `canary` mode is for isolated
staging and tolerates the transitional admission profile only as a visible
warning. `fleet` mode is the production posture: it fails until admission is a
frozen, non-transitional substrate profile and is the only mode accepted by the
release-bound evidence verifier.

## 1. Design objective

Provide ordinary browsers with URLs for public P2P applications while keeping
the following HiveRelay property:

> The application key is canonical. Every HTTPS name and gateway is a
> replaceable compatibility entrance.

The desired address forms are:

```text
hive://<app-key>/<path>                                  canonical P2P identity
https://<z32-app-key>.hive.<gateway-domain>/<path>       gateway-specific HTTPS
https://app.publisher.example/<path>                     publisher-owned HTTPS
```

The provisional `hive:` spelling is not frozen by this spec. The ecosystem may
retain `hyper:`, use a Pear-native scheme, or register another scheme later.
The HTTPS design depends only on a canonical 32-byte app/drive key.

## 2. Non-goals

This design does not create:

- a mandatory global `hive` domain or central control plane;
- a global account database required to publish or resolve an app;
- public HTTP access to blind, local-first, custody, shard, or private data;
- one wildcard TLS private key shared across independent relay operators;
- a trusted central gateway selector or load balancer;
- an arbitrary TCP/UDP or local-network proxy (Holesail owns that function);
- a claim that ordinary browser HTTPS verifies Hypercore provenance;
- default request/response body capture;
- gateway-side mutation of bytes in verifiable serving mode; or
- gateway, DNS, OAuth, or Web-PKI identity as a replacement for P2P identity.

## 3. Placement in the blind-substrate architecture

The blind-substrate split is a security boundary, not a deployment preset.

| Role | Storage/exposure purpose | HTTPS gateway relationship |
| --- | --- | --- |
| T1 availability relay | Public application availability, retrieval proof, circuit transport | MAY run the public HTTPS gateway as a layer-2/distribution component |
| T2 custody vault | Blind, time-bounded custody; no public content announcement or gateway | MUST NOT mount app-hosting routes, advertise gateway names, terminate app HTTPS, or participate in public gateway discovery |
| T3 witness | Independent observation and signed witness statements | MUST NOT serve app content; MAY verify gateway or expiry evidence as a client |

The RelayKernel-compatible core remains responsible for seeding, retrieval
proofs, circuits, signed metadata, and accounting. Host routing, DNS bindings,
TLS, HTTP policy, and browser response shaping live in a separate gateway
layer. The Blindspark appliance may package both T1 and the gateway, but the
protocol architecture must not make the gateway part of T2.

### 3.1 Fail-closed tier rule

The gateway serves an app only when all of the following are true:

1. the resolved app key is valid and canonical;
2. the local registry has a seeded entry for that exact key;
3. the entry is explicitly `public` and T1/availability-class;
4. the entry is not blind, custody, temporary, atomic-handoff, or shard data;
5. the publisher policy permits HTTP code/content serving;
6. any custom-domain lease is valid for the app, gateway, domain, and time; and
7. AppLifecycle grants a live read lease for its owned drive; a startup
   placeholder never causes the HTTP gateway to open a second drive;
8. the persisted storage-admission proof names the exact immutable version
   (`storageProvedDriveVersion`), independently of the release content pin; and
9. the requested version/fork constraints, when present, match both authorities.

Missing, unknown, transitional, or contradictory tier metadata is rejected.
There is no compatibility fallback from an unknown tier to `public`.

## 4. Trust model

### 4.1 What HTTPS proves

For an ordinary browser, Web PKI proves that the responding server is
authorized for the DNS name. It does not prove that the server returned the
expected Hyperdrive bytes, current fork, or publisher-approved policy.

Consequently:

- native HiveRelay/Pear clients verify Hypercore data directly;
- proof-aware clients may verify proof-carrying HTTP responses;
- a browser extension or previously trusted loader may verify signed bundles;
- an unmodified browser on first visit still trusts its HTTPS origin; and
- publisher-owned domains explicitly authorize their selected web gateways.

The system must describe this distinction honestly. `httpsVerified` and
`contentVerified` are separate verdicts.

### 4.2 Gateway capabilities and limits

A public gateway can observe the browser IP, hostname, path, timing, and public
response bytes. It can censor, delay, replay stale content, or return incorrect
bytes to a client that does not verify provenance. It cannot forge a valid
publisher signature, Hypercore proof, or gateway lease.

Private data therefore stays on native encrypted P2P paths. HTTPS is a T1
public-distribution surface, not a privacy upgrade.

### 4.3 Replaceability

The same app key may be served by unrelated gateway operators. Removing one
gateway changes reachability through that operator's domain, not the canonical
app identity. Publisher domains may rotate their authorized gateway set
without republishing the app.

## 5. URL and origin model

### 5.1 Gateway subdomain form

The primary gateway form is:

```text
https://<z32-app-key>.hive.<gateway-domain>/<path>
```

Requirements:

- the 32-byte app key is encoded using one frozen, lowercase z-base-32 profile;
- decoding must produce exactly 32 bytes and canonical re-encoding must match;
- the app key occupies one DNS label (52 z-base-32 characters);
- every app receives a distinct browser origin;
- the gateway rejects unknown sibling labels and malformed Host values;
- ports, trailing dots, Unicode confusables, duplicate separators, and
  Host values are normalized under one tested algorithm; and
- forwarded host headers never select an app in Phase 1, even when client-IP
  forwarding is trusted from an explicitly configured proxy.

A wildcard certificate is scoped to one operator's domain, for example
`*.hive.relay-a.example`. Independent operators never share that private key.

This model follows the origin-isolating subdomain gateway pattern used by
IPFS, while retaining Hyperdrive keys and HiveRelay proofs.

Browser origins isolate DOM access, local storage, service workers, and most
web platform state, but cookies may be scoped to a parent domain. A gateway
suffix may claim cookie isolation only when it is registered as a Public
Suffix. Until then, the gateway and its authentication remain cookie-free,
responses request origin-keyed agent clusters, and documentation must not claim
that sibling apps cannot influence parent-domain cookies.

PSL registration is not a false prerequisite for a one-app production canary:
after the blind-substrate gate, one explicitly admitted app has no untrusted
sibling and may run with `publicSuffixReady=false`. A fleet node that admits
two or more mutually untrusted apps must prove a PSL boundary or give every app
a separate registrable domain; otherwise fleet preflight and evidence
verification fail closed.

### 5.2 Existing path form

The compatibility route remains:

```text
GET /v1/hyper/:appKey/*path
```

It is useful for APIs and existing PearBrowser consumers but must not be the
preferred application-hosting form because all apps share the gateway origin.
Path mode may retain compatibility byte rewriting. It must advertise that the
response is transformed and therefore is not exact-byte/verifiable mode.

### 5.3 Publisher-owned domain form

A publisher may bind a normal domain to an app key:

```text
https://app.publisher.example/
```

The minimum binding is a DNS TXT record:

```dns
_hive.app.publisher.example. TXT \
  "v=hr1;key=<z32-app-key>;policy=<hex-policy-hash>"
```

Hive-aware clients validate the record and the corresponding publisher-signed
binding. Ordinary browsers use normal DNS and Web PKI and do not interpret the
TXT record.

Publishers may use A/AAAA records, CNAME, or HTTPS/SVCB service bindings to
direct the hostname to one or more authorized gateway operators. Each gateway
must present a certificate valid for the publisher hostname.

### 5.4 Canonical links

Gateway responses should expose both identities:

```http
Link: <hive://<app-key>/<path>>; rel="canonical"
Link: </.well-known/hiverelay-app.json>; rel="describedby"
```

HTML applications may additionally include a canonical link, but correctness
cannot depend on publishers remembering to add one.

## 6. Exact-byte public serving

Subdomain mode exists partly to remove the current need to rewrite absolute
HTML asset paths. In exact-byte mode:

- HTML, JavaScript, CSS, WASM, and other files are returned exactly as stored;
- absolute `/assets/...` paths naturally stay inside the app-specific origin;
- no HTML injection, base-tag insertion, path replacement, or script wrapping
  is permitted;
- range responses refer to the original stored bytes;
- content encoding must not change the represented payload unless the proof
  contract explicitly covers decoding; and
- errors and directory listings are gateway-generated documents and clearly
  marked as such.

Exact responses emit `Vary: Host`, but operators must also ensure reverse
proxy/CDN cache keys include the original Host. A cache keyed only by path can
serve one app's `/index.html` under another app's hostname.

The hardened Phase 1 canary takes the stricter position: application responses
emit `Cache-Control: no-store`, nginx uses `proxy_cache off`, and no CDN or
shared cache sits in front. Host-aware immutable caching remains deferred until
versioned URLs, proof binding, purge behavior, and cross-app cache isolation
have conformance coverage.

Suggested response metadata:

```http
X-Hive-App-Key: <hex-app-key>
X-Hive-Gateway-Key: <hex-gateway-key>
X-Hive-Drive-Fork: <uint>
X-Hive-Drive-Length: <uint>
X-Hive-Byte-Mode: exact
ETag: "hr1-<app-key-prefix>-<fork>-<length>-<path-digest>"
```

Headers are informative until verified through a signed envelope. They must
not be described as cryptographic proof by themselves.

## 7. Signed contracts

Every JSON contract below uses deterministic canonicalization, explicit
versioning, field allowlists, bounded strings/arrays, and a domain-separated
signature. Unknown fields are rejected for the signed version.

### 7.1 Gateway advertisement

A gateway operator advertises a replaceable public entrance:

```json
{
  "type": "hiverelay-gateway-advertisement-v1",
  "relayPubkey": "<hex>",
  "gatewayPubkey": "<hex>",
  "baseDomain": "hive.relay-a.example",
  "urlTemplate": "https://{z32AppKey}.hive.relay-a.example/",
  "modes": ["subdomain-exact-v1", "path-compat-v1"],
  "privacyTiers": ["public"],
  "region": "<bounded-label>",
  "operator": "<bounded-operator-id>",
  "issuedAt": 0,
  "expiresAt": 0,
  "signature": "<hex>"
}
```

The relay identity delegates to a role-separated gateway key. The gateway key
must not reuse raw signing material from relay, custody, witness, payment, or
publisher roles. The delegation and advertisement use different signature
domains.

Advertisements may travel through signed T1 directories, publisher manifests,
direct DHT metadata, or manual configuration. No single directory is required.

### 7.2 Publisher domain binding

```json
{
  "type": "hiverelay-domain-binding-v1",
  "domain": "app.publisher.example",
  "appKey": "<hex>",
  "policyHash": "<hex>",
  "issuedAt": 0,
  "expiresAt": 0,
  "publisherPubkey": "<hex>",
  "signature": "<hex>"
}
```

The binding proves publisher intent. DNS proves control of the web name. A
gateway requires both when serving a custom hostname.

### 7.3 Gateway lease

```json
{
  "type": "hiverelay-gateway-lease-v1",
  "domain": "app.publisher.example",
  "appKey": "<hex>",
  "gatewayPubkey": "<hex>",
  "policyHash": "<hex>",
  "certificateSpkiHash": "<optional-hex>",
  "notBefore": 0,
  "expiresAt": 0,
  "publisherPubkey": "<hex>",
  "signature": "<hex>"
}
```

The lease authorizes one gateway key, not an operator name or arbitrary fleet.
It may bind the intended TLS SPKI so a certificate request cannot silently
substitute another key. A gateway may enforce stricter local policy but may not
weaken the publisher policy named by `policyHash`.

### 7.4 Public gateway policy

The first policy version is deliberately small and declarative:

```yaml
version: hiverelay-public-gateway-policy-v1
privacyTier: public
byteMode: exact
methods: [GET, HEAD]
maxRequestHeaderBytes: 16384
maxResponseBytes: 67108864
maxTransformBytes: 4194304
oversizedFullOrHeadStatus: 413
oversizedRangeStatus: 416
unsupportedRangeStatus: 416
multiRangeStatus: 416
unsupportedProofAcceptStatus: 406
egressBytesPerClientAppWindow: 268435456
egressWindowMs: 60000
maxResponseLifetimeMs: 900000
cors: same-origin
securityHeaders: strict
cache:
  mutableMaxAge: 60
  immutableMaxAge: 31536000
rateLimit:
  capacity: 120
  windowSeconds: 60
```

The cache values above describe the later signed-policy target. They are not
enabled by the Phase 1 canary, which remains `no-store` end to end.

The finite values are exact for the `public-t1-gateway` production profile,
not operator-selected examples. A full response or HEAD representation larger
than 64 MiB is rejected with `413`; an oversized, unsupported, or multi-range
request is rejected with `416`; and the deferred proof media type is rejected
with `406` until proof envelopes ship. Egress is capped at 256 MiB for each
client-and-app key in a 60-second window, and a response may live for no more
than 15 minutes. The signed operator contract, persisted runtime config,
preflight artifact, and ops artifact must all carry these same integers and
status codes. Artifacts prove their observed configuration and release binding;
runtime negative tests prove the corresponding rejection behavior. Neither is
an independent timestamp or proof against a malicious operator.

V1 does not contain arbitrary expressions, embedded JavaScript, external HTTP
callbacks, dynamic upstream URLs, OAuth secrets, or response-body transforms.
Later policy actions require separate threat review.

## 8. Discovery and gateway selection

Resolution starts from one or more trust roots supplied by the caller:

- the canonical app key;
- a publisher-signed app manifest;
- a publisher-owned DNS binding;
- a manually configured gateway/operator set; or
- an opt-in signed T1 directory.

A resolver:

1. validates advertisements, bindings, leases, freshness, and role domains;
2. fetches signed relay capabilities;
3. requires the public gateway feature/profile;
4. verifies the relay claims to seed the requested app;
5. obtains a fresh anchor or retrievability proof when the requested assurance
   level requires it;
6. excludes incompatible privacy, policy, fork, or version states;
7. ranks by independent operator, region, health, latency, capacity, and cost;
8. returns multiple candidates and its evidence, not one opaque "best" URL.

DNS round-robin alone is availability routing, not evidence-based selection.
Hive-aware clients should select and fail over themselves. Ordinary browsers
may use DNS multi-answer/HTTPS records and accept weaker selection semantics.

## 9. Proof-carrying HTTP profile

Exact-byte mode prepares for a trustless retrieval profile:

```http
Accept: application/vnd.hiverelay.proof+binary;version=1
```

The response envelope should bind:

- app/drive key;
- drive fork and signed length;
- file path and entry metadata;
- returned byte range;
- underlying blob/core block indices;
- Hypercore Merkle proof material;
- request nonce when relay attribution/freshness is required;
- gateway and relay identities; and
- the exact response-byte digest.

The verifier produces separate verdicts:

```json
{
  "httpsVerified": true,
  "contentVerified": true,
  "relayAttributed": true,
  "freshnessVerified": true,
  "limitation": null
}
```

The first implementation targets the HiveRelay SDK, verifier package,
PearBrowser, CLI, and browser extensions. It must not claim that a vanilla
browser automatically verifies this envelope.

## 10. TLS and certificate operation

### 10.1 Operator domain

Each gateway operator obtains and rotates its own wildcard certificate for its
own base domain. ACME wildcard issuance uses DNS-01 through provider credentials
limited to `_acme-challenge` or a narrowly delegated challenge zone; HTTP-01
cannot issue a wildcard certificate. The certificate and private key remain on
that operator's edge and are never copied to another gateway.

The operator may terminate TLS in nginx, Caddy, another reviewed proxy, or a
future dedicated gateway process. HiveRelay receives a validated Host and the
terminated SNI only through an explicitly configured loopback trusted-proxy
boundary. The API/control-plane hostname and certificate are separate from the
wildcard app hostname.

Phase 1 therefore assumes a dedicated, operator-controlled node where only the
reviewed TLS edge can reach the gateway loopback listener or originate trusted
forwarded-SNI headers. Loopback is not a security boundary against a hostile
local process, root compromise, or an untrusted tenant in the same host/network
namespace. A shared-host deployment needs a separately reviewed isolation and
credential boundary before it can inherit this profile.

### 10.2 Publisher domain

Each authorized gateway generates its own TLS private key and obtains an exact
certificate for the publisher hostname. Certificates and keys are never copied
between unrelated gateway operators.

Initial support is manual. Automated ACME support follows only after gateway
leases and challenge authorization have conformance vectors.

Potential automation:

- HTTP-01 challenge tokens replicated to every active endpoint only under a
  valid publisher lease and bounded ACME order;
- DNS-01 through a narrowly delegated `_acme-challenge` zone;
- short-lived leases and certificates;
- optional SPKI binding in the gateway lease; and
- certificate-transparency monitoring as operator telemetry.

DNS and Web PKI remain compatibility infrastructure controlled by the domain
owner and browser trust stores. This is acceptable because they are not the
canonical P2P identity and no particular HiveRelay domain is mandatory.

## 11. Privacy-preserving traffic policy and observability

The useful ngrok idea is a programmable edge; the centralized capture and
control plane are not required.

Adoptable features:

- bounded method/path admission;
- per-app, peer/capability, or IP rate limits;
- strict security headers and same-origin defaults;
- static redirects and URL rewrites that do not alter stored response bytes;
- webhook signature verification into a signed Hypercore outbox;
- circuit breaking based on local health/proof evidence;
- local metrics and publisher-encrypted event export; and
- explicit, temporary developer capture for public applications.

Observability defaults:

- metadata only;
- bounded cardinality and retention;
- authorization/cookie/query-value redaction;
- no per-shard, custody ID, private key, capability, or tunnel-key labels;
- no body capture for non-public tiers under any flag;
- no global log collector required; and
- request replay disabled by default and limited to explicitly captured public
  requests, with safe methods preferred.

## 12. Integration map

| Existing component | Current/target integration |
| --- | --- |
| `packages/core/gateway/hyper-gateway.js` | Phase 1 has host-resolved exact-byte serving and per-response immutable checkouts; the target adds a common proof-aware resolved context |
| `packages/core/core/relay-node/gateway-server.js` | Phase 1 mounts loopback host routing behind a transitional key allowlist; the frozen T1 predicate replaces it while management routes stay outside app origins |
| `packages/core/gateway/server.js` | Standalone gateway profile and operator-domain configuration |
| App/seeding registry | Resolve exact public availability entry; never adapt custody/shard entries into gateway entries |
| PolicyGuard/privacy model | Replace permissive defaults with explicit public/T1 admission for new host routes |
| Capability document | Advertise gateway profile, byte modes, base domain, gateway key delegation, and limitations |
| Signed directory/meta profile | Carry bounded, expiring gateway advertisements as opt-in T1 metadata |
| Anchor/retrievability proof | Admission and ranking evidence; do not rename retrievability as replication proof |
| Client SDK | Resolve advertisements, select a diverse gateway set, construct HTTPS URLs, and verify proof envelopes |
| Verifier package | Verify gateway advertisements, bindings, leases, policies, and proof-carrying responses |
| PearBrowser | Prefer native P2P; use verified HTTPS as fast-start/fallback; isolate each app origin |
| Holesail transport | Optional reachability for relay/operator services; not the public app naming or trust layer |
| nginx/reverse-proxy packaging | A strict no-cache template, default TLS reject vhost, preflight, and real-nginx syntax rehearsal are present; production adds DNS-01 renewal and whole-config exact-API-vhost evidence |
| Raw VPS/systemd fleet | Strict CLI/env configuration, per-target content and operator-readiness gates, canonical signed operator-contract digests, health-gated rollback/quarantine, and signed canary/stable channel promotion are present; live use remains substrate-gated |
| Umbrel/StartOS | Gateway remains disabled until platform proxy, certificate persistence, update/rollback, and real-device isolation have a separate reviewed design |

### 12.1 Required internal refactor

The serving engine should accept a resolved immutable context rather than
parsing every external route itself:

```js
servePublicApp(req, res, {
  appKey,
  path,
  byteMode: 'exact',
  expectedFork: null,
  expectedLength: null,
  gatewayPolicy,
  domainBinding: null
})
```

Path compatibility, subdomain routing, and custom-domain routing become thin
adapters that validate external input and construct this context. This keeps
DNS/Host parsing out of the storage engine and makes tier enforcement common
to every route.

### 12.2 Management-plane isolation

An app hostname must never route to:

- `/api/manage/*`;
- setup/wizard endpoints;
- dashboard/operator WebSockets;
- raw service management;
- seed/unseed mutation routes;
- custody/shard routes; or
- ACME management APIs.

The gateway should use a distinct public listener where practical. If a shared
listener remains for compatibility, host routing happens before management
dispatch and app hosts receive only the public content surface plus bounded
well-known metadata.

### 12.3 Experimental Phase 1 configuration

The isolated implementation is disabled unless both a distinct data-plane port and
an app-host suffix are configured. Until the blind substrate owns the frozen
T1 predicate, each app must also be selected through the relay operator's
local key allowlist; registry compatibility defaults are never sufficient:

```json
{
  "productProfile": "public-t1-gateway",
  "enableAPI": true,
  "enableSeeding": true,
  "apiPort": 9100,
  "apiHost": "127.0.0.1",
  "gatewayPort": 9200,
  "gatewayHost": "127.0.0.1",
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
  "hiveAppHostSuffix": "hive.relay.example",
  "hiveAppPublicKeys": ["<64-hex-app-key>"],
  "hiveAppPublicVersions": {
    "<64-hex-app-key>": 7
  }
}
```

The exact production value is `productProfile: public-t1-gateway`. Before the
blind substrate compiles that profile, isolated staging may use only the
explicit rehearsal posture; a generic relay profile cannot produce fleet or
publication-grade readiness evidence.

The TLS proxy sends wildcard app hosts only to port `9200`, preserves the
original Host, never routes them to port `9100`, strips client-supplied
`Forwarded` and `X-Forwarded-Host`, overwrites client-IP forwarding, and binds
the forwarded TLS SNI to the Host. `X-Forwarded-Host` is intentionally not an
app-routing input in Phase 1.

The installed proxy must also contain a default TLS vhost that returns `421`
for unrelated SNI. Live fleet evidence makes a pinned-IP request with unrelated
SNI and separately sends an approved SNI with a mismatched HTTP Host; both must
return `421`. These `defaultSniRejection` and `sniHostBinding` checks, plus
`forwardedHostIsolation`, are required promotion evidence rather than optional
operator observations.

Phase 1 fleet posture is deliberately one app per gateway node. The sole
allowlisted key must have exactly one matching immutable drive-version pin, and
the live response version must equal it. Public Suffix readiness does not open
multi-app admission yet: that waits for a release/evidence schema that binds and
probes every admitted app rather than one representative origin.

The canary proxy does not cache, transform, or retain per-request app logs:

```nginx
proxy_set_header Host $host;
proxy_set_header Accept-Encoding "";
proxy_cache off;
gzip off;
gunzip off;
access_log off;
error_log stderr crit;
```

The whole active nginx configuration is authoritative, not only this server
fragment. Preflight rejects any TLS sibling that can shadow the app suffix or
bind an unreviewed socket, every `stream` context, QUIC/HTTP3, and inherited or
optional body transforms such as Brotli, Zstandard, gunzip, static gzip,
SSI, substitution/addition filters, image/XSLT filters, and charset conversion.
Stock parent `gzip on` is tolerated only because the app vhost, normal TLS
default, and frozen quarantine default each explicitly pin `gzip off` and
`gunzip off`; removing any override fails structural inspection. Browser-like
metadata/exact/range/HEAD/non-probed requests advertise common encodings,
nginx strips `Accept-Encoding` before the loopback hop, and evidence rejects
any `Content-Encoding` response. App, default-reject, and quarantine access
logging is off, and all three limit errors to critical stderr events;
aggregate metrics and signed probes are the Phase 1 observability surface.

This configuration is experimental until the readiness gates pass and the
transitional admission predicate is replaced with the frozen substrate role
predicate.

### 12.4 Release, evidence, and promotion contract

A production public-gateway release is described by
`fleet/public-hive-gateway-release.json` in the exact commit named by a trusted,
signed annotated release tag. The manifest is not accepted from the mutable
working tree: rollout and promotion read its bytes from the verified tag and
record their SHA-256. In that sense the release signature covers the manifest,
its cohort, and every expected node binding.

An enabled manifest contains a non-transitional admission profile, a release
target, a minimum 24-hour observation window, a maximum permitted probe gap,
and one closed-schema entry per approved gateway-cohort node. Ordinary fleet
relays that do not run the public gateway are outside this exact cohort. Each
entry binds:

- relay name and canary/stable channel;
- app suffix and exact HTTPS origin;
- the exact IP address to which the probe connection is pinned (`127.0.0.1` is
  preferred for node-local nginx checks);
- app key and exact request path;
- a publisher-supplied expected content SHA-256;
- immutable drive version;
- expected TLS peer-certificate SHA-256 fingerprint; and
- SHA-256 of the complete active configuration emitted by `nginx -T`. The
  installed public-gateway include must appear exactly once at nginx's parser
  marker and match its on-disk bytes, so an equivalent-looking dead file or
  commented copy cannot satisfy evidence; and
- for `deploymentProfile: public-t1-gateway`, the SHA-256 of one canonical
  `fleet/public-hive-gateway-operators/<relay>.json` contract. That contract
  binds the operator/domain assertions, exact DNS address set, TLS leaf
  fingerprint and SPKI, release/config/nginx assertions, and every field in
  the finite production policy above. Legacy entries that omit both fields
  remain parseable only for historical/read compatibility; no newly enabled
  manifest, deployment, channel promotion, or publication may contain one.

The manifest's observation window cannot be shorter than 24 hours, and its
maximum probe gap cannot exceed 30 minutes. A node artifact is accepted only
when fresh `fleet` evidence matches every signed value and all content,
canonical-identity, management-isolation, forwarded-Host, unavailable-app,
default-SNI, and SNI/Host checks are true.

The release pipeline is intentionally staged:

Before the first enabled target, a signed disabled bootstrap release must
contain the exact five-file quarantine authority (helper, verifier, and its
three local libraries). Enabled publication additionally requires the target
and signed predecessor to contain blob-identical copies of those five files
plus `fleet/updater.sh`, with exact tracked modes. On-node containment compares
the installed helper byte-for-byte with the frozen current-release helper
before executing it. This is an enforced compatibility gate, not a rollout
instruction operators may skip.

1. Generic release preparation uses `--channel none`; an enabled public-gateway
   manifest may not move canary or stable as a release side effect.
2. The dedicated promoter verifies the trusted tag and moves only the canary
   channel. An enabled canonical manifest in that tag automatically forces
   gateway validation, including a nonempty all-`public-t1-gateway` cohort,
   canonical operator-contract digests for every relay, and its exact mapping
   into current inventory; omission of an operator flag cannot select a weaker
   path. The legacy tag-cutter convenience promotion is not used.
3. Each updater derives its target only from an allowed-signer-verified Git
   control commit changing exactly `fleet/channels.json`. Durable atomic state
   rejects replay and both control-head and release-target
   downgrade/divergence. Each opted-in updater then probes the exact node
   binding after update and again on every no-op/up-to-date tick, so an old
   green artifact cannot persist just because the checkout did not change.
4. Fleet rollout verification uses a trusted `allowed_signers` root, pinned
   `known_hosts`, the signed manifest, per-node evidence, and a persistent
   observation-state file. It refuses `accept-new`, disables global OpenSSH
   host-key trust so the supplied pin file is exclusive, and refuses to execute
   the remote verifier from a dirty tracked target worktree. Observation state
   records relay probe time and independent controller collection time; both
   timelines must span the signed-manifest-defined window with bounded gaps, and the latest
   collection must remain fresh.
5. Stable changes only through the dedicated promoter. An enabled canonical
   tagged manifest automatically requires the public-gateway gate, even when a
   caller omits `--require-public-gateway`. The promoter re-verifies the tag,
   manifest, the signed cohort's mapping into current inventory, all-green
   canary evidence, and completed observation state before atomically changing
   only `fleet/channels.json`'s stable target.
   The final rollout evidence and latest per-relay samples must also be no more
   than 30 minutes old.
6. A `public-t1-gateway` publication additionally requires fresh fleet-mode
   operator-readiness evidence for every signed cohort relay. The publisher
   derives the canonical contract digest from each passing artifact and fails
   closed on a missing, mismatched, stale, fixture-derived, or release-drifted
   artifact. The updater repeats the same exact A/AAAA plus empty CNAME and
   HTTPS/SVCB DNS posture, every-address TLS/content binding, loopback TCP and
   no-UDP-443 listener posture, finite-config, and contract checks on each
   update and no-op tick.

None of these tools deploys the live fleet merely because a tag exists, and
none removes the blind-substrate readiness gate.

## 13. Threat model

| Threat | Required mitigation |
| --- | --- |
| One gateway disappears | Return multiple independently operated candidates; canonical app key remains valid |
| Gateway advertises another app | Bind host key, registry key, lease, proof, and response envelope to the same app key |
| Gateway serves modified bytes | Exact-byte mode plus proof-aware client verification; do not overclaim vanilla-browser integrity |
| Gateway serves stale fork/version | Signed version constraints, freshness policy, immutable URLs, proof comparison across relays |
| Cross-app DOM/storage/CORS attack | One app key per subdomain origin; never host apps through shared path origin by default |
| Cross-app parent-domain cookie attack | Use a Public Suffix boundary (or separate registrable domains) before claiming cookie isolation; keep gateway/auth responses cookie-free regardless |
| HTML rewrite breaks verification | No transformations in subdomain exact-byte mode |
| Host-header/DNS-rebinding attack | Canonical Host parser, explicit base-domain allowlist, trusted-proxy configuration, no localhost auth inheritance |
| Gateway reaches management API | Separate listener or pre-dispatch host isolation; app host has read-only content routes |
| T2 data leaks through gateway | Structural role separation plus explicit T1/public registry admission; fail closed on missing tier |
| Shared wildcard key compromises fleet | Per-operator wildcard keys; per-gateway exact keys for publisher domains |
| Malicious directory controls selection | Multiple discovery sources, signed advertisements, direct proof checks, caller-visible selection evidence |
| Policy downgrade | Publisher-signed policy hash in binding and lease; gateway may only tighten |
| Central traffic surveillance | Native P2P preferred; app request logging disabled; bounded aggregate metrics and signed probes; no required global ingress or observability service |
| Domain or CA compromise | Cannot be eliminated for vanilla HTTPS; keep key identity canonical, support multiple names/gateways, expose proof verification to aware clients |

## 14. Conformance and test plan

No compatibility claim is made without checked-in vectors and negative cases.

### 14.1 Contract vectors

- app-key z-base-32 canonical encoding and DNS label cases;
- gateway-key delegation and advertisement signatures;
- domain binding and gateway lease signatures;
- policy canonicalization and hash;
- expiry, wrong-role, wrong-domain, wrong-app, wrong-gateway, and unknown-field
  rejects;
- URL template parsing and canonical output; and
- proof-envelope binary/JSON encoding and verification.

### 14.2 Gateway unit tests

- valid subdomain maps to exact seeded public app;
- malformed or non-canonical host rejected;
- unrelated gateway base domain rejected;
- public app roots and absolute assets load without HTML rewriting;
- two app keys have distinct DOM/storage/service-worker/CORS origins;
- parent-domain cookie isolation is claimed only when the app-host suffix is a
  tested Public Suffix boundary (or apps use separate registrable domains);
- path compatibility remains unchanged;
- unknown, local-first, p2p-only, blind, custody, temporary, shard, and T2
  entries all reject;
- app host cannot reach management, wizard, seed, custody, or service routes;
- trusted-proxy client-IP behavior and unconditional forwarded-Host distrust
  are pinned;
- unrelated TLS SNI reaches only the default `421` vhost, and approved SNI with
  a different HTTP Host also returns `421`;
- Range/HEAD/cache/error behavior remains bounded, including exact `413`,
  `416`, and `406` negative results at the signed finite thresholds;
- the 64 MiB response cap, 4 MiB transform cap, 256 MiB per-client-and-app
  egress window, 60-second window, and 15-minute response lifetime cannot be
  omitted, set to `null`, weakened by environment/CLI input, or drift between
  config, contract, and evidence; and
- start/stop/restart drains listeners and in-flight streams.

### 14.3 Integration tests

- two unrelated gateways serve the same app key with exact identical bytes;
- one gateway fails and an aware client selects another;
- wrong bytes fail proof verification;
- stale fork/version is detected;
- publisher domain binding selects only leased gateways;
- independent TLS keys serve the same publisher domain in a test PKI;
- capability and advertisement expiry remove a candidate;
- browser origin-isolation fixture covers storage, service worker, and CORS;
- a separate cookie fixture runs only against the production Public Suffix (or
  separate-registrable-domain) topology; and
- blind-substrate tests assert that enabling T2 never mounts or advertises the
  gateway, including mixed-role configuration rejection where required.

### 14.4 Distribution evidence

- reverse-proxy configuration validates Host and keeps internal ports loopback;
- DNS-01 wildcard/operator certificate and renewal smoke;
- raw systemd canary evidence, pinned-SSH fleet verification, signed per-node
  release-manifest/operator-contract matching, fresh live DNS and every-address
  TLS/SPKI checks, numeric-loopback upstream listener checks, and health-gated
  rollback;
- proof that Umbrel/StartOS packages do not enable or advertise the gateway;
- public artifact scanner excludes private keys, ACME account material, API
  keys, tunnel keys, publisher metadata, and captured traffic; and
- fleet smoke verifies at least two independent gateway identities before any
  multi-gateway availability claim.

## 15. Execution phases

### Phase 0: substrate readiness and spec freeze

- finish the blind-substrate update;
- freeze T1/T2/T3 role identifiers and registry/storage-class semantics;
- freeze canonical signing helpers and role-domain separation;
- confirm gateway compatibility routes remain supported;
- settle gateway package/process ownership; and
- land this spec's contract fixtures before production integration.

### Phase 1: operator-domain subdomain gateway

- refactor exact-byte serving from route parsing;
- add canonical Host-to-app-key routing;
- enforce explicit T1/public admission;
- add per-app origin/security behavior;
- expose bounded app well-known metadata;
- configure external wildcard TLS; and
- preserve the existing path gateway unchanged.

Deliverable:

```text
https://<z32-app-key>.hive.<operator-domain>/
```

### Phase 2: signed discovery and client resolution

- gateway key delegation;
- expiring gateway advertisements;
- capability profile additions;
- multi-source discovery;
- proof-aware diverse selection; and
- PearBrowser/SDK fallback behavior.

### Phase 3: signed policy and custom domains

- public gateway policy v1;
- domain binding and gateway lease;
- manual publisher-domain TLS;
- DNS TXT and HTTPS/SVCB guidance; and
- independent gateway certificate/key support.

### Phase 4: proof-carrying retrieval

- exact response proof envelope;
- verifier and SDK support;
- immutable version URLs/cache behavior;
- PearBrowser/extension verification; and
- honest UI verdicts separating HTTPS, content, attribution, and freshness.

### Phase 5: ACME automation and programmable public edge

- lease-authorized HTTP-01 or delegated DNS-01 flows;
- rate limits, safe static routing/redirects, webhook verification;
- evidence-driven circuit breaking;
- privacy-preserving inspection/export; and
- conformance and fleet rollout gates.

### Isolated Phase 1 canary status

The `feat/public-https-hive-gateway` worktree currently implements:

- canonical 32-byte key to 52-character z-base-32 host labels;
- strict Host parsing without trusting `X-Forwarded-Host`;
- duplicate Host and malformed intended-app-host rejection;
- a dedicated data-plane listener requirement;
- exact-byte app serving with HTML Range and HEAD support;
- canonical `hive://` and well-known `Link` response metadata without making
  the HTTPS gateway the app identity;
- explicit transformed-byte metadata on legacy rewritten HTML;
- a replaceable transitional public-availability predicate gated by a local
  operator app-key allowlist, so legacy registry hydration defaults deny;
- app-origin CORS separation from legacy wildcard gateway CORS;
- bounded generated `/.well-known/hiverelay-app.json` metadata;
- per-request immutable drive checkouts with drive-version response metadata;
- an operator-configured immutable version pin for the sole Phase-1 public app,
  enforced by fleet preflight and the live version probe;
- `no-store`, Host-varying, cookie-free app responses and origin-keyed
  agent-cluster headers;
- bounded request/per-app concurrency, listener timeouts, controlled shutdown,
  exact finite response/transform/egress/lifetime limits, cache ownership, and
  single-flight drive opening;
- a strict nginx template with an unmatched-SNI reject vhost,
  config/template/live-probe preflight, and public-safe evidence schema;
- strict raw DNS HTTPS/SVCB queries for both app and wildcard-witness names,
  with random IDs, exact question validation, bounded UDP, TC-to-exact-TCP
  retry, and hard failure on malformed/RCODE/timeout/CNAME ambiguity;
- independent test certificates, replicated Hyperdrive storage, two-gateway
  exact-byte parity, Range/HEAD behavior, forwarding isolation, SNI/Host and
  unapproved-app rejection, failover, paused-stream shutdown, three same-port
  restarts, and soak coverage;
- strict deployment CLI/environment inputs, target-only fleet probe rollback
  gating, a signed per-node release-manifest contract, persistent 24-hour
  observation state, pinned-host fleet checks, and an atomic signed-tag
  canary/stable promotion command; and
- focused codec, routing, privacy/custody, lifecycle, and compatibility tests.

It intentionally does not yet implement the frozen T1 role predicate, Public
Suffix registration/validation, signed gateway identities/advertisements,
custom domains, production ACME orchestration, proof envelopes, or enabled
Umbrel/StartOS packaging. The blind-substrate integration replaces the
transitional admission predicate before merge or live-fleet deployment.
Production activation also waits for the storage slice to persist
`storageProvedDriveVersion` and to bound SeedingRegistry or explicitly disable
that workload registry for Public-T1 while retaining direct single-app
seeding. A release drive pin is content authority, never permission to fetch
unproved storage.

## 16. Readiness gates

Release-branch integration and live-fleet deployment start only when all gates
are satisfied. Isolated implementation and staging tests may precede the gates
but remain opt-in, unreleased, limited to one explicitly trusted public app,
and keep their substrate admission predicate replaceable.

| Gate | Requirement |
| --- | --- |
| G1 role boundary | T1/T2/T3 or successor role semantics are frozen and T2 no-gateway behavior is tested |
| G2 storage classification | Public availability entries are distinguishable from every blind/custody/shard class without heuristics |
| G3 signing foundation | Canonicalization, role-domain keys, delegation, expiry, and replay rules are stable |
| G4 gateway compatibility | Existing catalog, capability, and `/v1/hyper` consumers have passing compatibility evidence |
| G5 major update green | Blind-substrate unit/integration/conformance suites pass before gateway code is rebased onto it |
| G6 ownership | A clean implementation branch/worktree is selected so unrelated in-progress changes are preserved |
| G7 operator prerequisites | At least two operators can provide distinct domains/keys for multi-gateway integration testing |
| G8 release evidence | Signed tag embeds the exact per-node gateway manifest/operator-contract digests and the canary completes its manifest-defined observation window with bounded gaps |
| G9 operator readiness | Every `public-t1-gateway` cohort relay has fresh fleet-mode DNS/TLS/socket/config evidence deriving the signed canonical operator-contract digest; the evidence makes no independent timestamp or operator-control claim |
| G10 storage admission | Every RelayNode HTTP route uses an AppLifecycle lease and the persisted `storageProvedDriveVersion`; absent/mismatch is unavailable without update, checkout, or block pull |
| G11 bounded registry | Public-T1 consumes the bounded SeedingRegistry slice or proves the registry workload disabled while direct pre-pinned app seeding remains |
| G12 proxy runtime | A renewed-authority run captures the pinned production image's real default `nginx -T`; this run could not access Docker and makes no live-image claim |

Known low-severity evidence gap: the frozen quarantine verifier structurally
requires `gzip off`, `gunzip off`, and a closed directive posture, but its live
TLS 421 containment probe does not separately assert that `Content-Encoding`
is absent. Preserve the five-file frozen authority for this review and add that
wire assertion in the next versioned quarantine-authority renewal before using
the renewed evidence for activation.

Passing G1-G6 permits the isolated implementation to become a production
canary candidate, subject to the dedicated-node/loopback trust assumption. A
successful canary, recorded approval, health-gated rollback evidence, and G8
are still required before stable promotion. G7 is required before making
decentralized multi-gateway availability claims.

## 17. Open decisions

1. Is the canonical user-facing scheme `hive:`, `hyper:`, or Pear-native?
2. Does the gateway ship as `p2p-hiverelay` layer-2 code, a separate package,
   or a sidecar process?
3. Is z-base-32 the final app-key DNS encoding, and what textual prefix is used
   outside DNS?
4. Which exact registry fields constitute explicit T1/public admission after
   the blind-substrate update?
5. Does the gateway use a derived role key or a separately generated/persisted
   key delegated by relay identity?
6. What proof format maps Hyperdrive file ranges to Hypercore/Hyperblobs proof
   material without buffering large responses?
7. Are publisher domain bindings stored only in DNS/app manifests, or also in
   an optional signed T1 log?
8. Which component coordinates ACME without becoming a required certificate
   control plane?
9. What minimum independent-operator evidence is required before describing a
   hostname as decentralized or highly available?

## 18. Standards and prior art

- ACME: <https://www.rfc-editor.org/rfc/rfc8555.html>
- DNS SVCB and HTTPS records: <https://www.rfc-editor.org/rfc/rfc9460.html>
- Let's Encrypt challenge operation and delegation:
  <https://letsencrypt.org/docs/challenge-types/>
- IPFS gateway origin isolation and trustless-gateway precedent:
  <https://docs.ipfs.tech/concepts/ipfs-gateway/>
- ngrok traffic-policy phases and actions, used only as ergonomics prior art:
  <https://ngrok.com/docs/traffic-policy/how-it-works>

## 19. Decision summary

Public HTTPS Hive URLs are feasible and valuable, but they belong on the
public availability edge, not inside blind custody. The first implementation
is an operator-owned, key-derived subdomain gateway serving exact public bytes.
The long-term design adds publisher domains, independently authorized gateways,
signed policies, and proof-carrying responses without creating a mandatory
central HiveRelay domain, directory, certificate key, or traffic collector.
