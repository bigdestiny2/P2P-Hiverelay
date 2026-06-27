# HiveRelay Detailed Architecture Diagram

Last updated: 2026-06-27

This document maps the current HiveRelay implementation as a detailed runtime
architecture reference. It complements the graph-first overview in
[HIVERELAY-ARCHITECTURE-GRAPH.md](HIVERELAY-ARCHITECTURE-GRAPH.md), the product
mental model in [HIVERELAY_OVERVIEW.md](HIVERELAY_OVERVIEW.md), and the protocol
contracts in [PROTOCOL-SPEC.md](PROTOCOL-SPEC.md).

HiveRelay is an always-on Hyperswarm peer for Pear and Hypercore applications.
It keeps public Hyperdrives available, accepts signed seed and custody requests,
serves browser/mobile gateway reads, runs optional service plugins, and emits
evidence that operators, clients, and package reviewers can verify.

## 1. System Overview

```mermaid
flowchart LR
  subgraph Actors["Actors And Clients"]
    Publisher["Publisher SDK\np2p-hiverelay-client\ncreates drives and signs requests"]
    PearApp["Pear or Bare app\nHypercore + Hyperdrive + Hyperswarm"]
    Browser["Browser or mobile client\nHTTP gateway + WebSocket ingress"]
    Operator["Operator\nCLI, dashboard, fleet scripts"]
    Verifier["Verifier\nstorage, relay, custody, release evidence"]
    Reviewer["Store reviewer\nUmbrel, StartOS, GHCR"]
  end

  subgraph Ingress["Discovery And Ingress"]
    DHT["HyperDHT / Hyperswarm\npeer discovery, Noise transport"]
    HTTP["Relay HTTP API\nhealth, status, catalog, management"]
    Gateway["Gateway reads\n/v1/hyper/:key/*path\nRange-aware streaming"]
    WSGateway["WebSocket ingress\n/ws, dashboard feed,\nreplication bridge, DHT bridge"]
    SignedSurfaces["Signed surfaces\ncatalogBeeKey, indexRoom,\nrelay records, signed directory"]
  end

  subgraph Kernel["Core3 Relay Kernel"]
    RelayNode["RelayNode\npackages/core/core/relay-node/index.js\nboot orchestrator"]
    Seeder["Seeder\nHypercore and Hyperdrive replication"]
    AppRegistry["AppRegistry\nseeded apps, catalog entries,\nlatest-version selection"]
    ManifestStore["ManifestStore\nauthor seeding manifests\nsignature verification"]
    Registry["SeedingRegistry\nseed state, custody state,\nredacted catalog"]
    GatewayServer["GatewayServer\nstreaming public app content"]
    RelayAPI["RelayAPI\noperator API and dashboard routes"]
    AutoHeal["AutoHeal + SelfHeal\nreplica recruitment,\nanchor proof verification"]
    Accounting["Accounting\nstored bytes, served bytes,\nusage receipts, eviction"]
    Discovery["Discovery and federation\nnetwork discovery, bootstrap cache,\noptional federation"]
    Guardrails["Runtime guardrails\naccess control, policy guard,\nswarm firewall, alert manager"]
  end

  subgraph Channels["P2P Protocol Channels"]
    SeedProtocol["hiverelay-seed\nseed and unseed requests"]
    PublishProtocol["hiverelay-publish\ncustody and seed submissions"]
    CustodyProtocol["hiverelay-custody\nrelay-to-relay custody push"]
    AnchorProtocol["hiverelay-anchor\nanchor proof request/response"]
    ProofProtocol["hiverelay-proof\nstorage and relay challenges"]
    CircuitProtocol["hiverelay-circuit\nreservation and opaque forwarding"]
    ForwardProtocol["hiverelay-forward\nbounded forward relay"]
    ServicesProtocol["hiverelay-services\nplugin RPC and events"]
    MetaProtocol["hiverelay-meta\nregistry metadata and signed directory"]
  end

  subgraph Services["Optional Services Layer"]
    ServiceConfig["services.json\npersisted opt-in service config"]
    PluginLoader["PluginLoader\nloads builtin and configured plugins"]
    ServiceRegistry["ServiceRegistry\nprovider catalog and dispatch"]
    ServiceRouter["Router\nservice method routing and policy"]
    Identity["identity\nsign, verify, resolve"]
    Storage["storage\ncore and drive helpers"]
    Schema["schema\nschema registration and validation"]
    VRF["vrf\nsortition and beacon randomness"]
    AI["ai\nQVAC, Ollama, HTTP inference hooks"]
    ZK["zk\ncommitments and proof helpers"]
    SLA["sla / arbitration\nevidence-backed disputes"]
    Poker["poker / SignedLog\nsealed actions, table events"]
  end

  subgraph Persistence["Persistence And State"]
    Corestore["Corestore\nroot Hypercore storage"]
    Hyperdrive["Hyperdrive\npublished apps and hosted content"]
    Hyperbee["Hyperbee\ncatalogs, app registry, services"]
    JSONState["JSON sidecars\nservices.json, config snapshots,\nmanifest backups"]
    Evidence["Evidence artifacts\nrelease, fleet, store, smoke,\nusage, custody, anchor proofs"]
  end

  subgraph Distribution["Distribution And Fleet"]
    GitHub["GitHub source and releases"]
    GHCR["GHCR image\nmulti-arch OCI digest"]
    Fleet["Raw VPS fleet\nchannels.json, updater, health gates"]
    Umbrel["Umbrel package\napp_proxy + persistent data"]
    StartOS["StartOS package\ns9pk + registry evidence"]
  end

  Publisher --> DHT
  Publisher --> SeedProtocol
  Publisher --> PublishProtocol
  PearApp --> DHT
  PearApp --> SeedProtocol
  Browser --> HTTP
  Browser --> Gateway
  Browser --> WSGateway
  Operator --> HTTP
  Operator --> RelayAPI
  Verifier --> ProofProtocol
  Verifier --> Evidence
  Reviewer --> Umbrel
  Reviewer --> StartOS

  DHT --> RelayNode
  HTTP --> RelayAPI
  Gateway --> GatewayServer
  WSGateway --> RelayAPI
  SignedSurfaces --> AppRegistry
  SignedSurfaces --> Discovery

  RelayNode --> Seeder
  RelayNode --> AppRegistry
  RelayNode --> ManifestStore
  RelayNode --> Registry
  RelayNode --> GatewayServer
  RelayNode --> RelayAPI
  RelayNode --> AutoHeal
  RelayNode --> Accounting
  RelayNode --> Discovery
  RelayNode --> Guardrails

  SeedProtocol --> Registry
  PublishProtocol --> Registry
  CustodyProtocol --> Registry
  AnchorProtocol --> AutoHeal
  ProofProtocol --> Accounting
  CircuitProtocol --> RelayNode
  ForwardProtocol --> RelayNode
  ServicesProtocol --> ServiceRegistry
  MetaProtocol --> SignedSurfaces

  ServiceConfig --> PluginLoader
  PluginLoader --> ServiceRegistry
  ServiceRegistry --> ServiceRouter
  ServiceRouter --> Identity
  ServiceRouter --> Storage
  ServiceRouter --> Schema
  ServiceRouter --> VRF
  ServiceRouter --> AI
  ServiceRouter --> ZK
  ServiceRouter --> SLA
  ServiceRouter --> Poker
  RelayAPI --> ServiceConfig
  ServicesProtocol --> ServiceRouter

  Seeder --> Corestore
  AppRegistry --> Hyperbee
  Registry --> Hyperbee
  GatewayServer --> Hyperdrive
  ManifestStore --> JSONState
  Accounting --> Evidence
  AutoHeal --> Evidence
  Corestore --> Hyperdrive
  Corestore --> Hyperbee

  GitHub --> GHCR
  GHCR --> Fleet
  GHCR --> Umbrel
  GHCR --> StartOS
  Fleet --> RelayNode
  Umbrel --> RelayNode
  StartOS --> RelayNode
```

The important split is between durable public availability and temporary blind
custody. Public apps flow through the catalog and gateway. Blind custody entries
flow through redacted catalogs, signed receipts, quorum commits, and proof
channels without exposing plaintext or decryption keys to the relay.

## 2. Runtime Boot Sequence

```mermaid
sequenceDiagram
  autonumber
  participant CLI as CLI
  participant Config as Config loader
  participant Relay as RelayNode
  participant Store as Corestore
  participant Swarm as Hyperswarm
  participant Registry as AppRegistry + SeedingRegistry
  participant Protocols as Protomux channels
  participant API as RelayAPI + GatewayServer
  participant Services as Optional service plugins
  participant Heal as AutoHeal + monitors

  CLI->>Config: parse flags, env, config file, operating mode
  Config-->>CLI: merged config<br/>storage, API, custody, services, transports
  CLI->>Relay: new RelayNode(config)
  Relay->>Store: open Corestore at configured storage path
  Store-->>Relay: root store ready
  Relay->>Swarm: create Hyperswarm and join relay topics
  Swarm-->>Relay: peer connection streams
  Relay->>Registry: open app registry, seeding registry, manifests
  Registry-->>Relay: persisted apps, manifests, custody state
  Relay->>Protocols: attach seed, publish, custody, anchor,<br/>proof, service, circuit, forward channels
  Protocols-->>Relay: per-peer channel handlers ready
  Relay->>API: start HTTP API, dashboard, gateway,<br/>WebSocket bridges when enabled
  API-->>CLI: health, status, catalog, management surfaces
  Relay->>Services: load services.json and configured plugins when enabled
  Services-->>Relay: service catalog and method router
  Relay->>Heal: start health, disk, accounting,<br/>self-heal, auto-heal, alerts
  Heal-->>Relay: bounded telemetry and repair events
```

Boot rules:

- Corestore, Hyperswarm, registry state, and protocol channel setup are core
  relay dependencies.
- The HTTP API is enabled by default for operator and gateway surfaces unless a
  mode or config disables it.
- Optional services are disabled by default. Enabling poker expands the runtime
  bundle to the poker service plus its supporting VRF, arbitration, and ZK
  services.
- Federation, Tor, Holesail, DHT-over-WebSocket, and service plugins are
  opt-in or mode-dependent extension points.
- Runtime state is bounded and redacted before it reaches dashboard feeds or
  unauthenticated read endpoints.

## 3. Persistent Availability Flow

```mermaid
sequenceDiagram
  autonumber
  participant Dev as Developer or app
  participant SDK as HiveRelayClient
  participant DHT as Hyperswarm DHT
  participant Relay as RelayNode
  participant Policy as PolicyGuard + AccessControl
  participant Seed as SeedProtocol
  participant Seeder as Seeder
  participant Registry as AppRegistry
  participant Gateway as HTTP Gateway
  participant User as Browser or Pear client
  participant Heal as AutoHeal

  Dev->>SDK: create or open Hyperdrive
  SDK->>SDK: write app files, manifest, capability docs
  SDK->>DHT: announce app discovery key
  SDK->>Seed: signed SEED_REQUEST<br/>app key, version, policy, storage class
  Seed->>Relay: deliver request over Protomux
  Relay->>Policy: validate accept mode, privacy tier,<br/>capacity, app identity, signatures
  Policy-->>Relay: accept or reject
  Relay-->>SDK: SEED_ACCEPT or SEED_DENY
  SDK->>Relay: Hypercore replication stream
  Relay->>Seeder: replicate drive blocks into Corestore
  Seeder->>Registry: upsert app, version, pin, catalog entry
  Registry-->>Gateway: catalog-visible public app state
  User->>Gateway: GET /catalog.json or /v1/hyper/:key/path
  Gateway->>Seeder: stream Merkle-verified blocks with Range support
  Gateway-->>User: app content
  Heal->>Registry: inspect archive tier and replica diversity
  Heal->>Relay: recruit or repair replicas when thresholds drift
```

Persistent availability is the normal app-hosting path. The relay can serve
public content over HTTP, but the content itself still originates from Hypercore
data structures. For private or `p2p-only` content, the relay may store and
replicate opaque encrypted blocks while keeping gateway access blocked or
redacted according to policy.

## 4. Atomic Blind Custody Flow

```mermaid
sequenceDiagram
  autonumber
  participant Publisher as Publisher
  participant Submit as PublishProtocol or signed API
  participant Relay as RelayNode
  participant Registry as SeedingRegistry
  participant Peers as Custody peers
  participant Verifier as Verifier
  participant Witness as Witness relay

  Publisher->>Submit: custody-intent<br/>ciphertext root, retention window,<br/>required replicas, signature
  Submit->>Relay: SUBMIT intent
  Relay->>Registry: validate schema, signature,<br/>privacy allowlist and plaintext denylist
  Registry-->>Relay: durable intent entry
  Relay-->>Publisher: custody-receipt<br/>signed by anchoring relay
  Relay->>Peers: hiverelay-custody PUSH entry
  Peers-->>Relay: ACK entryHash
  Publisher->>Submit: custody-commit<br/>receiptRoot over quorum receipts
  Submit->>Registry: append commit after quorum validation
  Publisher->>Submit: source-retired<br/>retire publisher authority for future state
  Submit->>Registry: append source retirement
  Verifier->>Relay: possession challenge
  Relay-->>Verifier: custody-proof<br/>nonce-bound possession evidence
  Registry->>Relay: retainUntil reached
  Relay->>Relay: unseed and stop active serving
  Relay-->>Registry: custody-non-serving-proof
  Witness->>Relay: probe expired entry
  Witness-->>Registry: custody-expiry-witness tombstone
```

Custody messages are durable through registry replication and fast through the
relay-to-relay custody channel. The custody channel is a latency optimization;
the safety property comes from signed entries, deterministic receipt roots,
retirement semantics, possession proofs, and expiry witnesses.

## 5. HTTP API And Gateway Surface

```mermaid
flowchart TD
  Client["Browser, SDK, operator, reviewer"] --> HTTP["HTTP server\napi.js + route modules"]

  HTTP --> Public["Public read surfaces"]
  HTTP --> Gateway["Gateway surfaces"]
  HTTP --> Manage["Management surfaces"]
  HTTP --> Realtime["Realtime surfaces"]

  Public --> Health["/health\n/api/health\nliveness, readiness"]
  Public --> Status["/status\n/api/status\nbounded relay state"]
  Public --> Catalog["/catalog.json\n/api/catalog\npublic or redacted app catalog"]
  Public --> Capability["/.well-known/hiverelay.json\ncapability document"]

  Gateway --> Hyper["/v1/hyper/:key/*path\nstreamed Hyperdrive file reads"]
  Gateway --> Range["Range requests\npartial content, bounded reads"]
  Gateway --> DHTWS["/ws/dht\nDHT-over-WebSocket bridge"]
  Gateway --> ReplWS["/ws/replicate\nHypercore-over-WebSocket replication"]

  Manage --> Config["/api/manage/config\nsafe config updates"]
  Manage --> Services["/api/manage/services/config\nservice enablement and plugins"]
  Manage --> Custody["/api/manage/custody\ncustody status and actions"]
  Manage --> Federation["/api/manage/federation\nfederation state"]
  Manage --> Lifecycle["/api/manage/lifecycle\nstart, stop, restart actions"]
  Manage --> Alerts["/api/manage/alerts\noperator alerts"]
  Manage --> Unseed["/api/manage/unseed\nseed removal actions"]

  Realtime --> Dash["/dashboard\nHTML dashboard"]
  Realtime --> Feed["/ws\noperator event feed"]
  Realtime --> PokerFeed["poker WebSocket feed\nwhen poker service is enabled"]

  Auth["Auth and guardrails\nbearer token, app proxy auth,\nCORS, rate limits, redaction"]
  Auth --> Manage
  Auth --> Realtime
  Auth --> Gateway
```

Route implementation is split by responsibility under
`packages/core/core/relay-node/api-*.js`. The top-level dispatcher composes
small route modules for health, status, catalog, service configuration, custody,
federation, peer state, dashboard feeds, safe config updates, and lifecycle
actions.

## 6. P2P Protocol Channel Matrix

| Channel | Direction | Main implementation | Purpose | Persistence path |
|---|---|---|---|---|
| `hiverelay-seed` | Publisher to relay | `packages/core/core/protocol/seed-request.js` | Request seed or unseed of Hypercore/Hyperdrive content | App registry and seeding registry |
| `hiverelay-publish` | Publisher to relay | `packages/core/core/protocol/publish-channel.js` | Submit signed custody, source-retired, commit, and seed messages without HTTPS dependency | Registry entries and custody state |
| `hiverelay-custody` | Relay to relay | `packages/core/core/protocol/custody-channel.js` | Push custody entries between connected relays for low-latency convergence | Registry log remains durable source |
| `hiverelay-anchor` | Relay to relay or verifier to relay | `packages/core/core/protocol/anchor-channel.js` | Request and return signed anchor proofs for replica verification | Anchor proof evidence |
| `hiverelay-proof` | Verifier to relay | `packages/core/core/protocol/proof-of-storage.js`, `proof-of-relay.js` | Challenge storage or relay behavior with nonce-bound responses | Proof evidence and accounting |
| `hiverelay-circuit` | Peer to relay to peer | `packages/core/core/protocol/relay-circuit.js` | Reserve relay slots and forward opaque encrypted data when direct connectivity fails | Ephemeral reservation state |
| `hiverelay-forward` | Peer to relay | `packages/core/core/protocol/forward-relay.js` | Bounded forward-open, data, status, and close messages | Ephemeral forwarding state |
| `hiverelay-services` | Peer to service host | `packages/core/core/services/protocol.js` | Service catalog, request/response RPC, exact-topic subscriptions, events | Service provider state |
| `hiverelay-meta` | Relay to relay | `packages/core/core/services/signed-directory.js` and relay metadata helpers | Exchange signed directory and registry metadata | Signed directory and catalog surfaces |

All of these ride over Hyperswarm streams and Protomux channels. Hypercore
replication itself stays on the standard Hypercore replication stream, so app
data integrity continues to be Merkle-tree based even when the request that
started replication came from a HiveRelay-specific channel.

## 7. Services Layer

```mermaid
flowchart LR
  Operator["Operator or API client"] --> API["/api/manage/services/config"]
  API --> Config["storage/services.json\natomic write where supported"]
  Config --> Boot["RelayNode service boot"]
  Boot --> Loader["PluginLoader"]
  Loader --> Builtins["Builtin providers\nidentity, storage, schema,\nvrf, ai, zk, sla,\narbitration, poker"]
  Loader --> External["Configured plugin modules"]
  Builtins --> Registry["ServiceRegistry"]
  External --> Registry
  Registry --> Router["Router\nmethod dispatch + role policy"]
  Router --> Protocol["ServiceProtocol\nJSON length-prefixed over Protomux"]
  Protocol --> Peers["Remote peers and clients"]
  Router --> HTTP["Service read and management API"]

  PokerToggle["enable poker"] --> PokerBundle["poker + vrf + arbitration + zk"]
  PokerBundle --> Config

  Guard["Guards\nmax message size, exact topics,\nmethod restrictions, peer role defaults"]
  Guard --> Protocol
  Guard --> Router
```

Service messages are JSON frames with bounded length. The protocol supports
catalog exchange, request/response RPC, errors, subscriptions, unsubscriptions,
events, app catalog snapshots, and app catalog deltas. Remote subscriptions are
exact-topic only, wildcard metacharacters are rejected, and peers are capped by
topic count.

Restricted service methods such as identity signing and AI model registration
are not generally exposed to anonymous peers. The default peer role is
anonymous unless the operator config or a pairing/delegation flow grants a
stronger role.

## 8. Storage And Persistence Map

```mermaid
flowchart TD
  Root["Configured storage root\n./storage or operator path"] --> Corestore["Corestore\nHypercore block storage"]
  Root --> Sidecars["JSON sidecars and snapshots"]
  Root --> Logs["Evidence and operational logs"]

  Corestore --> Drives["Hyperdrive data\npublished apps, public content,\nopaque encrypted blocks"]
  Corestore --> Bees["Hyperbee state\napp registry, catalog,\nservice/provider state"]
  Corestore --> RegistryLog["Registry logs\nseed, custody, anchor,\nusage, signed directory"]

  Sidecars --> ServicesJson["services.json\nservice enablement and plugins"]
  Sidecars --> ManifestBackup["manifest store fallback\nauthor-published seeding manifests"]
  Sidecars --> ConfigSnapshots["safe config and dashboard snapshots"]
  Sidecars --> LegacyJson["legacy registry JSON fallback\nfor migration and recovery"]

  Logs --> FleetEvidence["release and fleet evidence"]
  Logs --> UsageEvidence["usage receipts and served accounting"]
  Logs --> CustodyEvidence["custody receipts, commits,\nnon-serving proofs, witnesses"]
  Logs --> HealthEvidence["health, disk, alerts,\nself-heal and auto-heal events"]

  Drives --> Gateway["Gateway reads"]
  Bees --> Catalog["/catalog.json and signed catalog surfaces"]
  RegistryLog --> Verifiers["Verifier and AutoHeal proof checks"]
```

Important persistence properties:

- App registry state is backed by Hyperbee when Corestore is available and has
  migration/fallback paths for JSON state.
- ManifestStore verifies author signatures, keeps newest author manifests, and
  uses atomic tmp-file plus rename writes where the platform supports it.
- Service configuration persists at `<storage>/services.json`, so API toggles
  survive process restarts and fleet updates.
- Custody and registry data are stored as signed entries. HTTP and dashboard
  views are derived projections, not the root of trust.
- Eviction and accounting operate on bounded state so a relay can enforce
  capacity without losing the ability to explain what happened.

## 9. Fleet And Release Topology

```mermaid
flowchart TB
  Source["origin/main\nversioned source tree"] --> Tests["release checks\nnpm audit, lint, tests,\nworkspace audits"]
  Tests --> Tag["GitHub tag or release"]
  Tag --> Image["GHCR image build\nlinux/amd64 + linux/arm64"]
  Image --> ImageEvidence["image manifest evidence\nOCI digests and platform checks"]
  Image --> Smoke["release image smoke\nhealth, dashboard, setup,\nwallet, services"]
  Smoke --> Prepare["release:prepare\nversions, channels, package surfaces"]

  Prepare --> Channels["fleet/channels.json\nstable and canary targets"]
  Channels --> VPS["Raw VPS relays\nsystemd service + updater timer"]
  VPS --> HealthGate["health gate\nupgrade, verify, rollback if needed"]
  HealthGate --> FleetEvidence["fleet rollout evidence\nversion, SHA, host health"]

  Prepare --> Umbrel["Umbrel app package\napp_proxy + persistent /data"]
  Umbrel --> UmbrelEvidence["Umbrel smoke and reviewer evidence"]

  Prepare --> StartOS["StartOS s9pk package\nregistry metadata and digest"]
  StartOS --> StartOSEvidence["StartOS verify and registry evidence"]

  ImageEvidence --> Final["release-evidence.json\nhash-linked sidecars"]
  Smoke --> Final
  FleetEvidence --> Final
  UmbrelEvidence --> Final
  StartOSEvidence --> Final
```

The release surface intentionally fans out from one source/version into three
deployment forms:

- Raw VPS relays consume `fleet/channels.json` through the systemd updater path.
- Umbrel consumes the GHCR image through app package metadata and app proxy
  configuration.
- StartOS consumes the same image digest through the `.s9pk` packaging and
  registry evidence path.

## 10. Operating Modes

| Mode | Primary behavior | Typical API surface | Notes |
|---|---|---|---|
| `relay-core` | General relay with seeding, gateway, dashboard, custody-capable core | Health, catalog, gateway, dashboard, management | Default production mental model |
| `custody-relay` | Emphasizes blind custody, receipts, commits, expiry witnesses | Custody status, proof, redacted catalog | Requires strict plaintext-deny validation |
| `homehive` | Home-server style relay for Umbrel/StartOS users | Dashboard, setup wizard, services config | Persistent local storage and app proxy matter most |
| `seed-only` | Replicate and keep content available without broad gateway behavior | Seed requests, health, limited status | Useful for private or fleet helper nodes |
| `relay-only` | Forwarding and relay transport without app hosting emphasis | Circuit/forward relay, health | Used for connectivity/NAT assistance |
| `gateway` | HTTP gateway first, with catalog and public Hyperdrive reads | `/catalog.json`, `/v1/hyper`, WebSocket ingress | Browser/mobile friendliness path |
| `private` or `stealth` | Reduced public surfaces and tighter discovery | Authenticated management only | Useful for controlled fleets |
| `hybrid` | Mixed seeding, gateway, services, custody, and federation | Most surfaces enabled by policy | Powerful but needs clear operator configuration |

Modes are presets over config, not separate binaries. The same RelayNode boot
path constructs the needed transports, protocol channels, registries, and API
routes based on merged config.

## 11. Client SDK Shape

```mermaid
flowchart LR
  App["App developer code"] --> Client["HiveRelayClient\npackages/client/index.js"]
  Client --> Store["Corestore\nlocal app storage"]
  Client --> Drive["Hyperdrive\npublish and update files"]
  Client --> Swarm["Hyperswarm\nrelay discovery and replication"]
  Client --> Seed["Seed request protocol\nsigned seed/unseed"]
  Client --> Custody["Custody helpers\nintent, receipt, commit,\nsecret sharing helpers"]
  Client --> Services["Service RPC client\ncatalog, request/response,\nsubscriptions"]
  Client --> Resilience["Resilience\nretry queue, pending seeds,\nquorum and fork checks"]
  Client --> RelayRecords["Relay records\ncapabilities, gateway URLs,\nhealth, proof surfaces"]

  Swarm --> Relay["RelayNode peers"]
  Seed --> Relay
  Custody --> Relay
  Services --> Relay
  Drive --> Relay
```

The client SDK is deliberately close to the Hypercore stack. It creates or opens
drives, discovers relay peers through Hyperswarm, signs protocol messages,
replicates with accepting relays, and tracks relay state so app code does not
need to know which transport path succeeded.

## 12. Live Consumer Integration Paths

These are the current ecosystem consumers that must keep pulling the newest
HiveRelay line by default. The local guard is
`npm run audit:ecosystem-consumers`, which checks package manifests and nearest
lockfiles for direct `p2p-hiverelay*` drift.

| Consumer | HiveRelay surface | Current default |
|---|---|---|
| PearBrowser desktop | Bundled `p2p-hiverelay`, client, and verifier packages; HTTP catalog/gateway bridge | Local `file:` workspace links to the `0.20.2` packages |
| PearBrowser mobile | HTTP catalog, capability-doc, and gateway contracts over HTTPS relay transport | Wire-contract consumer; not a direct package pin |
| PearPaste | Encrypted availability through split core/client packages and custody-safe relay paths | Local `file:` links to core/client `0.20.2` |
| anonGPT native | Relay/onion AI app importing current core services subpaths | Local `file:` link to core `0.20.2` |
| POS, Tickets, p2pbuilders, Opengit bridge, hiverelay-test | Direct app/site/experiment consumers | Local `file:` links checked with lockfile metadata |

## 13. Module Inventory

| Subsystem | Key files |
|---|---|
| CLI and process entry | `packages/core/cli/index.js` |
| Relay boot orchestrator | `packages/core/core/relay-node/index.js` |
| HTTP API dispatch | `packages/core/core/relay-node/api.js`, `api-dispatch.js`, `api-request.js`, `api-response.js` |
| Health and status | `api-health.js`, `api-status-read.js`, `api-overview.js`, `health-monitor.js`, `disk-monitor.js` |
| Gateway | `gateway-server.js`, `api-catalog-read.js`, `api-gateway-stats.js` |
| Dashboard and WebSocket feeds | `api-dashboard-routes.js`, `api-dashboard-html.js`, `ws-feed.js`, `ws-feed-poker.js` |
| Seed and app registry | `seeder.js`, `app-registry.js`, `api-seed-publish.js`, `api-catalog-management.js` |
| Custody | `api-custody-status.js`, `api-custody-management.js`, `protocol/custody-channel.js`, `protocol/publish-channel.js` |
| Proofs and anchors | `api-anchor-status.js`, `api-fork-proofs.js`, `protocol/anchor-channel.js`, `protocol/proof-of-storage.js`, `protocol/proof-of-relay.js` |
| Relay transport | `relay.js`, `bare-relay.js`, `relay-tunnel.js`, `distributed-drive-bridge.js`, `protocol/relay-circuit.js`, `protocol/forward-relay.js` |
| Services | `core/services/protocol.js`, `core/services/registry.js`, `core/services/provider.js`, `api-service-config.js`, `api-service-management.js`, `api-service-read.js` |
| Policy and auth | `access-control.js`, `swarm-firewall.js`, `api-auth-helpers.js`, `api-auth-failures.js`, `api-cors.js`, `api-rate-limit.js` |
| Accounting and eviction | `storage-accounting.js`, `served-accounting.js`, `eviction.js`, `api-usage-telemetry.js`, `api-eviction-purge.js` |
| Repair and operations | `auto-heal.js`, `self-heal.js`, `alert-manager.js`, `api-alert-management.js`, `api-lifecycle-actions.js` |
| Client SDK | `packages/client/index.js`, `custody.js`, `pairing.js`, `secret-sharing.js` |
| Services package | `packages/services/builtin/*`, including poker provider code |
| Release and fleet | `fleet/`, `scripts/`, `umbrel-app/`, `startos/`, release evidence docs |

## 14. Trust Boundaries

```mermaid
flowchart TD
  RemotePeer["Untrusted remote peer\nHyperswarm stream"] --> ProtoGuard["Protocol decode guards\ncompact-encoding or bounded JSON"]
  ProtoGuard --> SignatureGuard["Signature and schema validation"]
  SignatureGuard --> PolicyGuard["Policy guard\nprivacy tier, accept mode,\ncapacity, role"]
  PolicyGuard --> CoreState["Core relay state\nregistry, seeder, services"]

  HTTPClient["Untrusted HTTP client"] --> HTTPGuard["HTTP guards\nCORS, auth, rate limit,\nbody caps, route allowlists"]
  HTTPGuard --> Projection["Bounded projections\ncatalog, status, dashboard"]
  Projection --> CoreState

  ServicePeer["Service peer"] --> ServiceGuard["Service guards\nrole checks, restricted methods,\nexact topic subscriptions"]
  ServiceGuard --> ServiceState["Service provider state"]
  ServiceState --> CoreState

  Operator["Operator"] --> ManagementAuth["Bearer/app-proxy auth\nmanagement route checks"]
  ManagementAuth --> ConfigState["Config state\nservices.json, safe config,\nlifecycle actions"]
  ConfigState --> CoreState

  CoreState --> Evidence["Signed evidence\nreceipts, proofs, release,\nfleet and usage artifacts"]
```

Boundary summary:

- Remote P2P streams are untrusted until decoded, bounded, schema-checked, and
  signature-verified.
- HTTP management routes are privileged. Public read routes expose bounded,
  redacted projections.
- Service plugins are opt-in and run behind router policy; anonymous peers do
  not automatically receive privileged methods.
- Blind custody rejects plaintext-looking fields before signed custody entries
  become accepted state.
- Dashboard and fleet outputs are operational projections. Signed protocol
  entries and release evidence are the audit roots.

## 15. End-To-End Mental Model

```mermaid
flowchart LR
  Create["Create app or custody payload"] --> Sign["Sign request\nseed, publish, custody"]
  Sign --> Discover["Discover relays\nDHT, relay records, gateway URLs"]
  Discover --> Negotiate["Negotiate acceptance\npolicy, capacity, privacy tier"]
  Negotiate --> Replicate["Replicate or store\nHypercore blocks or ciphertext"]
  Replicate --> Index["Index relay state\nregistry, catalog, signed surfaces"]
  Index --> Serve["Serve or prove\nHTTP gateway, P2P replication,\nproof channels"]
  Serve --> Repair["Repair and account\nAutoHeal, SelfHeal,\nusage, eviction"]
  Repair --> Release["Operate fleet\nchannels, package surfaces,\nevidence"]
```

HiveRelay is not a single server API wrapped around storage. It is a peer that
speaks the same replication language as the apps it hosts, plus a set of signed
coordination channels that make relay promises auditable. The HTTP gateway,
dashboard, package surfaces, and fleet updater are all operational views on top
of that peer-first substrate.
