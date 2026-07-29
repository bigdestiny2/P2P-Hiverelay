# Namespace — App-Neutral OutboxLog

**Status:** shipped in v0.24.1 (`feat(outboxlog): opaque-id takedown primitive + app-neutral namespace (#163)`, env wiring #172) · **Code:** `packages/services/builtin/outboxlog/` (`outbox-log.js`, `index.js`, `http-adapter.js`, `blind-seal.js`)

> Namespaces make the relay-hosted OutboxLog **app-neutral**: every signed record carries a namespace label, and the operator registers which namespaces (apps) the relay admits — with per-namespace caps and an optional blind mode where the relay stores only sealed ciphertext. Any app (Peerit, Poked, …) is admitted by configuration, no relay fork — the Service Contract commitment that app releases never require relay updates.

## 1. What it is

The OutboxLog is a relay-hosted, single-writer, append-only signed log — one "outbox" per app writer key. Before namespaces, the service was coupled to one app. Now:

- A **namespace registry** (operator-owned) admits named namespaces, each with its own capability profile.
- Every record is labeled (`_ns`) and every outbox group binds to exactly one namespace — a group can never straddle two.
- A **blind namespace** forbids plaintext application fields: data rows store
  only sealed ciphertext (blind sealing in `blind-seal.js`). Three exact signed
  control shapes are admitted without a sealed body: global `head`, atomic
  `commit` authorization, and `lane-head {id,version,updatedAt}`. Unknown or
  additional fields on those shapes are rejected.
- An **opaque-id takedown** primitive lets the operator mark individual records do-not-serve without learning anything about their content.

It also fixed a fleet footgun: ENV-provisioned boxes had no way to register a namespace, so *every* append was refused `unknown namespace` — the `HIVERELAY_OUTBOXLOG_NAMESPACE` env var now seeds the registry (persisted config still wins).

## 2. Data model

```mermaid
classDiagram
  class NamespaceEntry {
    +name : string
    +blind : bool
    +caps.maxOutboxes : int
    +caps.maxEntriesPerOutbox : int
    +caps.maxValueBytes : int
    +caps.bytesPerDay : int
  }
  class OutboxRecord {
    +_ns : string
    +_k : string
    +_dk : string
    +_sig : string
    +type
    +data
  }
  NamespaceEntry "1" --> "many" OutboxRecord : admits
```

Namespace names match `/^[a-z0-9][a-z0-9._-]{0,63}$/`; all four caps are enforced (see §7 for the `bytesPerDay` windowing choice and restart boundary).

- Default namespace: `'outbox'`.
- Signed payload: `` `pear.app.${driveKey}:${ns}:${canonicalOutboxRecord(type, data)}` `` — the namespace is inside the signature domain, so a record cannot be replayed across namespaces.
- Registry semantics: when explicitly configured, the registry admits **exactly** what was asked — no hard-injected house namespace. Persisted namespaces are re-validated on load; `configureNamespaces` refuses to drop a persisted namespace.

## 3. Flows

### 3.1 Register and configure

```mermaid
flowchart LR
  Env["HIVERELAY_OUTBOXLOG_NAMESPACE<br/>(env, first-boot default)"] --> L["config/loader.js<br/>applyOutboxlogNamespaceEnv"]
  Cfg["config.outboxlog.namespace(s)<br/>(persisted config wins)"] --> L
  L --> Reg["createOutboxNamespaceRegistry()"]
  Reg --> Eng["OutboxLog engine"]
  Eng --> RPC["service manifest<br/>outboxlog.namespaces (RPC-only)"]
```

Env is a **default only**: once a namespace config is persisted, env changes no longer override it.

### 3.2 Create + append (the validation pipeline)

```mermaid
sequenceDiagram
  participant W as Writer (app)
  participant E as OutboxLog engine
  participant R as Namespace registry

  W->>E: sync.create(appId, {namespace})
  E->>R: namespaceInfoForCreate()
  alt unregistered
    R-->>W: 400 unknown namespace
  else at outbox cap
    R-->>W: 503 namespace outbox capacity
  else ok
    E->>E: bindGroupNamespace (permanent binding)
  end

  W->>E: append record {_ns, _k, _dk, _sig, type, data}
  E->>R: namespaceInfoForAppend — missing _ns 400, unknown 400, policy check
  E->>E: verifyOutboxRecordSignature<br/>domain includes driveKey + ns
  alt blind namespace
    E->>E: hasBlindForbiddenField? → reject plaintext
  end
  E->>E: caps: maxValueBytes, maxEntriesPerOutbox, bytesPerDay
  E->>E: append to group log (single writer)
```

Rebinding a group to a different namespace → `400 namespace mismatch`. Signature verification looks up rules from the registry — a record in an unregistered namespace fails verification even if well-formed.

### 3.3 Read / resolve

- `namespaces()` snapshot (engine) → RPC method `OutboxLogApp.namespaces()`; the service manifest advertises the `outboxlog.namespaces` capability with exact method names for P2P RPC parity.
- **No HTTP route lists namespaces** — the surface is RPC-only by design. HTTP exposes only `POST /api/sync/create` (which takes `{namespace}`); appends carry `_ns` inside the signed record.

### 3.4 Blind namespaces and takedown

```mermaid
flowchart TD
  W["Writer seals record client-side<br/>(blind-seal.js)"] --> S["relay stores sealed ciphertext<br/>plaintext fields rejected"]
  S --> R["readers with the key unwrap locally"]
  Op["Operator takedown (admin key)"] -->|opaque record id| T["DO-NOT-SERVE tombstone<br/>content never inspected"]
  S --> T
```

The operator's takedown is gated by the admin key and references records by opaque id only — moderation without content exposure, matching the blind-custody posture of the rest of the stack.

## 4. Security and capability model

- **Writer authentication**: per-record ed25519 signatures, `_k` must equal `appId`, namespace inside the signature domain.
- **Operator allowlist**: unregistered namespaces reject at create, append, and verify time.
- **Blind mode**: `BLIND_FORBIDDEN_FIELDS` hard-blocks plaintext fields on blind
  namespaces. `head`, `commit`, and `lane-head` use exact field allowlists so
  atomic control metadata works without becoming a plaintext smuggling channel.
- **Caps**: enforced per namespace — `maxOutboxes`, `maxEntriesPerOutbox`, `maxValueBytes`, `bytesPerDay` (each resolved as min of namespace cap and global fallback).
- **Takedown**: admin-key-only, opaque-id, do-not-serve.

## 5. Config surface

```json
{
  "outboxlog": {
    "namespace": "outbox",
    "namespaces": {
      "outbox": { "blind": false },
      "peerit": { "blind": true, "caps": { "maxOutboxes": 10000, "maxEntriesPerOutbox": 5000, "maxValueBytes": 8192, "bytesPerDay": 67108864 } },
      "poked":  { "blind": true }
    }
  }
}
```

- `config.outboxlog.namespace` / `config.outboxlog.namespaces` map; fed into the engine at `OutboxLogApp.start()`.
- `HIVERELAY_OUTBOXLOG_NAMESPACE` (env) seeds the default on first boot only.
- Reconfiguration must not drop a persisted namespace (fail-closed).

## 6. How it plugs in

```mermaid
flowchart LR
  Apps["Apps (Peerit, Poked, …)"] -->|signed records, _ns| OL["OutboxLog service"]
  OL --> Store["relay storage (append-only group logs)"]
  OL --> Notify["Notify service Mode-2<br/>(co-resident composition)"]
  OL --> RPC["Service RPC manifest<br/>outboxlog.namespaces"]
  OL --> Wake["Outbox wake/head hints<br/>(Nym lane / Tor read plane control)"]
```

- **Service Contract**: app releases never require relay updates — admission is config, not code.
- **Notify Mode-2** composes with the co-resident outboxlog. Global
  `notify-feed-head` remains available; sender-owned virtual mailboxes use
  `notify-outbox-lane`, which observes only `lane-head!<opaque tag>` and emits a
  payload-free wake.
- **Privacy transports**: encrypted wake/head hints are exactly the bounded control messages the Tor/Nym privacy lanes carry; the log bodies themselves stay on native paths (or Tor bulk).

## 7. Honest limits

1. `caps.bytesPerDay` **is enforced** — as a **rolling 24h** ingest window per namespace (not calendar-day; the spec previously left the windowing open). Every accepted append charges its full serialized record bytes — the same measure as `maxValueBytes`, in-place updates included (it is an ingest-rate cap, not a storage cap) — against `min(namespace cap, global maxBytesPerDay fallback)`; over budget rejects appends with `503 namespace at daily byte capacity`. The global fallback is uncapped by default, so only configured caps bite. The window survives restart exactly: journaled appends carry a `ts` and re-charge on replay, and checkpoints persist the pruned charge list (`byteWindows` in the state snapshot). Three explicit boundaries: (a) journal appends written before this enforcement carry no `ts` and do **not** re-charge — the window under-counts by that legacy volume for up to 24h after upgrade, then self-heals; (b) expiry is wall-clock (`Date.now()`) — a backward clock jump delays expiry (conservative), a forward jump frees budget early; (c) tracking is lazy — a cap added later via `configureNamespaces` observes traffic from that point on.
2. Namespace enumeration is RPC-only; there is no public HTTP discovery of admitted namespaces (deliberate).
3. Do not conflate with the ENS/petname "naming" roadmap (`PEAR-NAMING-IPFS-RELEASE-ROADMAP`) — that is a different concept from this shipped feature.
4. A group permanently binds to its first namespace; there is no migration — choose names carefully.

Related: `docs/SERVICES.md` (OutboxLog section), `blind-seal.js`, `docs/tor-transport.md`, and the Nym × HiveRelay spec (wake-hint lane) in the research vault.
