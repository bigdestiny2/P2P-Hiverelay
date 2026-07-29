# HiveRelay Application Privacy SDK v1

Status: proposed application SDK contract; not a public protocol authority and
not release evidence.

This specification defines the proposed developer-facing composition layer
above the frozen HiveRelay blind substrate. It makes workload placement,
transport privacy, durability, downgrade behavior, cost, recovery, and
non-blind service disclosure explicit without adding application semantics to
a relay.

The intended product surface is Pear Deploy: deployment intent fixes the
minimum route policies and required evidence for a release, while this SDK
performs fresh, operation-bound qualification and execution at runtime. Pear
Deploy is the compiler, infrastructure, and evidence plane; it is not an
application-data proxy, capability vault, or substitute for runtime privacy
checks.

The implementation target is `@hiverelay/blind-client`. The existing
`p2p-hiverelay-client` package remains a legacy Hyperdrive/service compatibility
surface and may expose a thin `/blind` re-export during migration. It MUST NOT
silently reinterpret its current app-aware methods as strict blind operations.

Examples below describe a target API, not the package's current exported
surface. In particular, a pure `/policy` helper, a registry constant, or an
availability boolean is not an executable privacy path. `BlindClient`, durable
journal/vault backends, and each transport adapter remain unavailable until the
corresponding package export, runtime implementation, conformance tests, and
evidence exist.

## 1. Design rule

Privacy is not one ascending mode that every byte should traverse. The SDK MUST
resolve these dimensions independently:

1. workload semantics and the correct substrate primitive;
2. representation privacy and replica correlation;
3. network transport and adjacent-role visibility;
4. metadata shaping;
5. identity exposure;
6. read-interest exposure;
7. durability evidence and repair policy; and
8. downgrade or external-service disclosure.

Presets make common choices easy. Every draft, prepared plan, result, and UI
status exposes the orthogonal decisions so a preset can never hide a tradeoff.
The SDK reports representation, transport, read-interest, and durability claims
separately. An aggregate label MUST NOT imply the strongest component when any
other component has a lower or unverified ceiling.

## 2. Package boundary

The target package surface is:

```text
@hiverelay/blind-client
  /policy                 pure, non-executable draft planner
  /cells                  immutable opaque records
  /inbox                  bounded rendezvous
  /core                   native encrypted streams
  /journal                durable logical intents and ambiguous results
  /vault                  capabilities and encrypted recovery state
  /selection              relay and operator-diversity policy
  /transports/direct
  /transports/ohttp
  /transports/native
  /transports/tor
  /runtime/browser
  /runtime/node
  /runtime/bare
  /testing                conformance fixtures
```

The existing byte-oriented Cells, Inbox, Core, qualification, intent, attempt,
selection, and durability modules remain the security foundation. The new layer
coordinates them; it does not copy their codecs or relax their endpoint pins.

The existing `p2p-hiverelay-client/privacy-policy.js` is useful prior art for
orthogonal axes and fail-closed path selection, but its legacy path vocabulary
does not model workload representation, OHTTP, primitive-specific durability,
operation-bound qualification, or external semantic disclosure. It remains
unchanged. A future compatibility subpath may re-export this contract only after
version, package-closure, and cross-runtime gates pass; the legacy resolver is
not silently treated as an `AppPrivacyIntentV1` compiler.

`/policy` has no network authority. Its output MUST NOT be accepted by
`execute()`, a transport adapter, or an intent sender. Only
`BlindClient.prepare()` (and the `BlindClient.plan()` convenience form that
calls it) may combine a draft with fresh qualification and return an opaque
executable plan.

Until an adapter and its capture/conformance evidence exist, it is unselectable.
A registry constant, relay advertisement, configuration flag, or caller-supplied
boolean alone never makes a path deployable or an axis satisfied.

## 3. Workload routing

The SDK uses these closed workload and primitive classes:

| Workload | Default primitive | Permitted primitives | Intended use | Important limit |
| --- | --- | --- | --- | --- |
| `records` | `cell` | `cell` | Signed immutable records, random access, browser state | No cross-cell transaction or semantic query |
| `rendezvous` | `inbox` | `inbox` | Wake-up hints, bounded discovery, invitations | Not history, authority, or completeness |
| `history` | `core` natively; `cell` plus checkpoints in ordinary browsers | `core`, `cell` | Append streams, bulk history, larger media manifests | Core needs an authenticated stream transport |
| `live` | `p2p-direct` | `p2p-direct` | Calls, games, cursors, live collaboration | Not durable; source/path metadata is visible |
| `semantic` | `local-compute` when possible; otherwise `external` | `local-compute`, `external` | Search, ranking, AI, transcoding, consensus | External execution is outside the blind substrate trust boundary |

The closed primitive IDs are `cell`, `inbox`, `core`, `p2p-direct`,
`local-compute`, and `external`. An application MAY override a representation
only within the permitted set above. Any other pair is blocked with
`WORKLOAD_PRIMITIVE_UNSUPPORTED`; it MUST NOT fall through to a generic storage
or transport planner. In particular, records cannot be relabeled as P2P or
external work, ordinary-browser Core cannot be enabled by a boolean, and
semantic work cannot be presented as encrypted Cell/Inbox/Core input.

`operation` remains the application workload verb. A separate canonical
`wireOperation` binds executable substrate work. Records `put|get` map to
`CELL.PUT|GET`; rendezvous verbs map to their exact Inbox operations; native
history `put` maps to `CORE.MIRROR` and history `get` maps to
`CORE.OPEN_REPLICATION`. Core proof challenges are durability/qualification
work, not a relabelled application read. P2P and semantic routes have no blind
wire operation. A planner must never emit a generic `put` as a Core wire verb.

`local-compute` means application-owned code operating on locally available
plaintext under the application's own process/origin boundary. It performs no
relay request, needs no external-service disclosure, and makes no claim about
the privacy of later synchronization. `external` always requires the disclosure
and consent contract in section 11.

Large media SHOULD use direct P2P or Blind Core for the body and Cells for signed
manifests, thumbnails, keys, and checkpoints. An ordinary browser MAY use
chunked Cells, but the plan MUST expose the resulting transaction count and
blind-envelope and adapter/fleet amplification before execution. If no
app-owned signed manifest is supplied, the result is
`CHUNK_MANIFEST_REQUIRED`, never an executable single-Cell plan.

Legacy BlindShard/PVSS custody is not a generic SDK primitive or an automatic
durability upgrade. It multiplies ciphertext/share placement, roster and proof
work, and repair coordination while retaining publisher/custody linkage and
giving public readers threshold-share fetch behavior. A product that genuinely
needs threshold custody must select a separately versioned experimental custody
profile with its own operator-set assumptions, cost model, recovery semantics,
and disclosure; ordinary records use independent Cell replicas instead.

## 4. Privacy presets and custom constraints

The required fixed presets are:

| Preset | Browser | Native | Downgrade | Intended behavior |
| --- | --- | --- | --- | --- |
| `fast` | `direct-blind-v1` | `direct-blind-v1` | none | Lowest latency; storage sees adjacent source and access pattern |
| `private` | `split-web-ohttp-v1` | `split-native-protomux-v1` | explicit prompt only | Normal source-separated path under non-collusion assumptions |
| `high-privacy` | Tor Browser full-onion path | `tor-native-full-v1` | deny | Background-preferred and fail-closed; no clearnet race |

Fixed presets are immutable closed values. `privacy.fast()`,
`privacy.private()`, and `privacy.highPrivacy()` accept no field overrides;
attempting one is `PRESET_IMMUTABLE`. Applications needing different behavior
use `privacy.custom()`, optionally naming a preset as a base whose resolved
fields are copied into a new custom intent. A custom intent does not modify or
extend a canonical transport profile or wire registry.

`custom` accepts constraints over:

```js
{
  base: undefined | 'fast' | 'private' | 'high-privacy',
  transport: 'direct' | 'source-separated' | 'tor',
  metadataShaping: 'none' | 'padded' | 'bucketed-experimental',
  identityExposure: 'stable' | 'session' | 'anonymous-reply',
  readInterest: 'observable' | 'bucketed-experimental',
  downgradePolicy: 'deny' | 'prompt',
  backgroundPreferred: boolean
}
```

Every pure-draft axis has an explicit prospective resolution record:

```js
{
  requested,
  planned,
  state: 'qualification-required' |
    'adapter-qualification-required' |
    'connector-qualification-required' |
    'session-preparation-required' |
    'application-policy-required' |
    'known-visible' |
    'unsupported' |
    'not-applicable',
  requiredEvidence: ['closed-evidence-id'],
  assumptions: [],
  claimCeiling
}
```

Every state ending in `-required` has a non-empty `requiredEvidence` set. The
pure scaffold exports the closed `EVIDENCE_REQUIREMENT` IDs for signed profile,
verified endpoint, fresh health, adapter/conformance capture, class or stream
shaping, application identity boundary, Inbox anonymous reply, universal read
buckets, P2P session preparation, role separation, no-direct-race,
no-clearnet, browser opaque origin, external endpoint/connector, and
disclosure authorization evidence. Unknown evidence IDs fail closed when a
prepared plan or Pear Deploy release predicate resolves them; an empty set can
never make a required state satisfied.

The SDK MUST NOT report an axis as satisfied merely because the caller requested
it. Satisfaction requires the primitive or compatible runtime adapter, signed
endpoint and transport profile, fresh qualification, and the evidence named by
that axis. `unsupported` is blocked. `unverified` cannot become `ready`; it is
`queueable` only when a conforming adapter/path may later obtain the missing
evidence, otherwise it is blocked. In particular,
`bucketed-experimental`, `anonymous-reply`, role non-collusion, Tor no-clearnet,
and Tor Browser opaque-origin claims each need their own evidence and cannot be
inferred from transport selection.

`not-applicable` is permitted only when the closed workload/primitive pair has
no such surface, such as network transport for `local-compute`. It is not a way
to erase a caller-requested constraint from a networked operation. Pure drafts
have no `actual` field and never copy `requested` into `satisfied`. Only a
prepared plan may add `actual`, `evidenceRefs`, and the final
`satisfied | unsupported | unverified | not-applicable` state.

Plans and results expose at least:

```js
{
  privacyResolution: {
    transport,
    metadataShaping,
    identityExposure,
    readInterest
  },
  claims: {
    representation,
    transport,
    readInterest,
    durability
  }
}
```

Representation is a primitive claim rather than a caller-selectable privacy
axis, so it lives under `claims.representation`; it MUST NOT be duplicated as a
second, independently satisfiable axis. A prepared plan may add `actual`,
`evidenceRefs`, and final satisfaction state to each `privacyResolution` member
without renaming this shape.

`prompt` grants permission to present a fallback proposal, not to take it. When
the requested path is temporarily unavailable, the preparation result remains
`queueable` under the requested policy and MAY attach
`DOWNGRADE_CONSENT_REQUIRED` with one suggested lower profile; an
interactive-only caller MAY instead request a blocked result. It never executes
the proposal. After visible consent, the future qualified-client
`authorizeDowngrade()` operation issues an opaque,
expiring, single-use local authorization bound to the draft ID,
requested-policy hash, workload/primitive, suggested actual profile, disclosure
hash if any, and user-visible prompt version. `prepare()` additionally binds the
resulting ready plan to the exact endpoint/path. A generic boolean, stored
preference, consent for another draft, or application restart is not
authorization. `high-privacy` always uses `deny` and cannot mint a downgrade
authorization.

`authorizeDowngrade()` is not exported by the pure `/policy` module. A pure
draft rejects caller-supplied downgrade or disclosure authorizations; the
future `BlindClient` qualification boundary owns their creation and use.

OHTTP and Tor do not hide which locator storage serves. Read-interest privacy is
`observable` unless a separately qualified universal bucket/PIR profile is in
use.

## 5. Public API

The ergonomic target separates pure drafting from evidence-qualified
preparation:

```js
import { BlindClient } from '@hiverelay/blind-client'
import { RUNTIME, draftWorkload, privacy } from '@hiverelay/blind-client/policy'

const app = await BlindClient.open({
  storage,
  bootstrap,
  // Each value is an evidence-bearing adapter, not an availability boolean.
  transports: { direct, ohttp, native, tor, p2p },
  privacy: privacy.private(),
  durability: {
    cell: {
      replicaTarget: 3,
      acknowledgementTarget: 2,
      readbackTarget: 2,
      fetchTarget: 1,
      independentOperatorGroups: 2
    },
    inbox: {
      stripeCountLog2: 3,
      replicaTargetPerStripe: 3,
      appendAcknowledgementTargetPerStripe: 2,
      readbackTargetPerStripe: 2,
      independentOperatorGroups: 2
    },
    core: {
      mirrorTarget: 3,
      proofTarget: 1,
      recentlyServedTarget: 2,
      independentOperatorGroups: 2
    }
  }
})

const draft = draftWorkload({
  workload: { kind: 'records', byteLength: encoded.byteLength },
  runtime: RUNTIME.BROWSER,
  privacy: privacy.private(),
  costBudget: { maxBlindEnvelopeAmplification: 32 }
})

if (draft.status === 'draft') {
  const prepared = await app.prepare(draft, encoded, { signal })
  if (prepared.status === 'ready') {
    const result = await app.execute(prepared.plan, encoded, { signal })
  } else if (prepared.status === 'queueable') {
    await app.enqueue(draft, encoded, { signal })
  }
}
```

`app.plan(input, encoded, options)` is a convenience for
`draftWorkload(input)` followed by `app.prepare(draft, encoded, options)`. It is
asynchronous and returns the same evidence-qualified `ready`, `queueable`, or
`blocked` preparation result. A `/policy` draft is never called a ready plan.
`enqueue()` is valid only for locally durable mutation workloads; it journals
the signed logical intent and does not perform network I/O.

Convenience scopes make the same planner explicit:

```js
const records = app.cells({ privacy: privacy.private() })
const rendezvous = app.inbox({ privacy: privacy.private(), stripeCountLog2: 3 })
const history = app.core({ privacy: privacy.fast() })
const live = app.p2p({ privacy: privacy.fast() })

const localSearch = app.localCompute('search', {
  purpose: 'full-text search',
  executor: localIndex.search
})

const search = app.external('search', {
  endpoint,
  networkPrivacy: privacy.private(),
  disclosure: {
    serviceId: 'search-provider-v1',
    purpose: 'full-text search',
    operatorSees: ['query', 'result selection', 'timing'],
    authority: 'advisory',
    retention: 'provider policy',
    endpointEvidence
  },
  disclosureAuthorization
})
```

Labels such as `search` or a local collection name remain local encrypted state.
They MUST NOT enter a relay request, capability, receipt, log, metric, descriptor,
or admission token.

## 6. Draft and prepared-plan contract

| Producer | Possible status | May perform network I/O | Executable output |
| --- | --- | --- | --- |
| `draftWorkload()` from `/policy` | `draft`, `queueable`, `blocked` | No | Never |
| `BlindClient.prepare()` / `BlindClient.plan()` | `ready`, `queueable`, `blocked` | Qualification only; no application mutation send | Only the opaque `plan` inside `ready` |
| `BlindClient.execute()` | Operation result, `queueable`, `PENDING_UNKNOWN`, or error | Yes, under the exact prepared plan | Not applicable |

### 6.1 Pure policy draft

`draftWorkload()` is deterministic, side-effect free, and performs no network
I/O. Its result is one of:

- `draft`: the closed workload/primitive pair and requested policy are
  internally valid and may be passed to `prepare()`;
- `queueable`: the policy is valid but the supplied deployment-inventory hint
  lacks a candidate path, or a proposed weaker path still needs explicit
  consent; a mutation may be journaled locally without sending; or
- `blocked`: the request is invalid, incompatible, unsupported, over a hard
  budget, or missing a mandatory disclosure descriptor or manifest authority.

A draft contains desired constraints, primitive-specific durability, exact
blind-envelope estimates where derivable, unresolved axes, and candidate
transport profiles. It contains no `VerifiedEndpoint`, no fresh-health claim,
no admission/capacity claim, and no execution authority.
Inventory booleans are prospective compilation hints only: they are not a
capability snapshot, path-health result, or proof that any adapter is qualified.
Changing an inventory hint may change `draft` to `queueable`, but MUST NOT erase
the deterministic candidate primitive, `wireOperation`, intended transport,
axis requirements, representation sizing, cost result, claims, assumptions,
warnings, durability, or disclosure metadata. This lets `explain` and offline UI
show what is missing without pretending that absence invalidated the policy.

A pure `queueable` draft reports only a prospective action:

```js
{
  prospectiveQueue: {
    state: 'not-journaled',
    action: 'journal-mutation-intent' | 'wait-for-path',
    intentCanBeJournaled: boolean,
    localVisible: false
  }
}
```

Only `enqueue()` or the journal may later report `local-queued`. Reads and
watches wait for a path and cannot be journaled as mutations.

### 6.2 Evidence-qualified preparation

`BlindClient.prepare()` may perform qualification I/O and local durable
preparation. It resolves the draft against installed adapters, fresh signed
descriptors/health, path-role separation, admission, capacity, consent, and
cost evidence. Its result is `ready`, `queueable`, or `blocked`. `ready` is
reserved for an opaque plan that pins:

```text
workload
primitive
runtime
requested privacy intent
resolved requested/planned/actual/satisfied state for every axis
canonical transport profile
family and operation
qualified endpoint/path roles, adjacent keys, and transport-profile hash
primitive-specific durability and evidence targets
cell/frame/session class where applicable
payload/request commitment and destination identity
exact blind-envelope costs and separately qualified adapter/fleet estimates
cost and latency budgets
downgrade/disclosure authorization identifiers and hashes
separate representation, transport, read-interest, and durability claims
expiry/revalidation boundary
```

A prepared plan snapshots binary evidence rather than recursively freezing
caller-owned byte views. It is non-forgeable, operation-specific, bounded in
lifetime, and cannot be reconstructed from JSON or a pure draft.

Required state/reason codes include:

```text
PRIVACY_PATH_UNAVAILABLE
PRIVACY_AXIS_UNSUPPORTED
PRIVACY_EVIDENCE_UNVERIFIED
DOWNGRADE_CONSENT_REQUIRED
DOWNGRADE_AUTHORIZATION_MISMATCH
TRANSPORT_UNSUPPORTED
CORE_STREAM_UNAVAILABLE
P2P_PATH_UNAVAILABLE
WORKLOAD_PRIVACY_CONFLICT
WORKLOAD_PRIMITIVE_UNSUPPORTED
WORKLOAD_PRIMITIVE_CONFLICT
WORKLOAD_DURABILITY_CONFLICT
WORKLOAD_DISCLOSURE_CONFLICT
SEMANTIC_SERVICE_DISCLOSURE_REQUIRED
SEMANTIC_SERVICE_CONSENT_REQUIRED
EXTERNAL_SERVICE_UNAVAILABLE
LOCAL_COMPUTE_UNAVAILABLE
COST_BUDGET_EXCEEDED
COST_EVIDENCE_UNAVAILABLE
CHUNK_MANIFEST_REQUIRED
RENDEZVOUS_FRAME_TOO_LARGE
OFFLINE_QUALIFICATION_PENDING
```

The SDK MUST revalidate endpoint health, signed profile pins, admission,
capacity, cost ceiling, and local consent immediately before execution. A plan
cannot be replayed against another endpoint, operation, profile, class, or
destination. If revalidation becomes temporarily unavailable without disproving
the policy, a mutation returns to `queueable`; it never races or silently chooses
a weaker route.

## 7. Operation lifecycle

Every mutation follows:

```text
POLICY_DRAFT
  -> DRAFT_LOCAL
  -> IDENTITY_COMMITTED
  -> INNER_EVENT_SIGNED
  -> INTENT_JOURNALED
  -> LOCAL_VISIBLE
  -> QUEUEABLE_OFFLINE <-> PREPARING_PATH
  -> TARGET_PREPARED
  -> SENT
  -> ACKNOWLEDGED | PENDING_UNKNOWN
  -> READBACK_VERIFIED
  -> REPAIR_SCHEDULED | POLICY_COMPLETE
```

The logical event is locally durable and visible before network publication. A
`QUEUEABLE_OFFLINE` intent retains the exact requested policy and retry
conditions. Waking, reconnecting, or discovering a direct relay does not weaken
that policy. Qualification may move it to `TARGET_PREPARED` only after all axes,
consent, costs, and primitive-specific durability targets can be bound.

`TARGET_PREPARED` means the exact destination, operation, profile, class,
request commitment, fresh replica capability material, and authorization hashes
have been persisted before the first possible send. Changing any of those fields
creates a new attempt. A different replica also uses a fresh slot, keys, nonce,
wrapper, ciphertext, capability set, and request identity; it remains part of
the same app-level logical event only through the journal's explicit replica
relationship.

A timeout after possible delivery becomes `PENDING_UNKNOWN`. The SDK reconciles
the exact request identity and MUST NOT create another logical event or silently
change destination/profile. A downgrade authorization or external disclosure
authorization is journaled by opaque identifier and binding hash, never by an
unbound `true` flag.

Every asynchronous API accepts `AbortSignal` and a bounded deadline. Abort before
the commit boundary cancels. Abort after a possibly committed send records an
ambiguous state and preserves reconciliation data.

## 8. Capability vault and recovery

The SDK supplies an encrypted vault interface:

```js
{
  read(key),
  compareAndSwap(key, expectedVersion, encryptedValue),
  list(prefix),
  remove(key, expectedVersion),
  close()
}
```

Browser implementations use an origin-isolated IndexedDB backend with multi-tab
compare-and-swap. Native implementations use an encrypted local store with
explicit fsync. Application identity keys never become storage-management keys.

The capability taxonomy distinguishes canonical client-composition values from
opaque SDK vault handles:

| Capability or authority | Scope | Conversion rule |
| --- | --- | --- |
| `ReadCellCapV1` | Read and decrypt one exact relay-bound Cell replica | Cannot renew, drop, create, append, or reveal identity authority |
| `WriteCellCapV1` | Aggregate client-side Cell record containing the read cap plus independent create, renew, and drop private authority | MUST NOT be derived from a read cap or exported where read-only authority was requested |
| `CellCreateAuthority` | Create the one prepared replica/request | Single-purpose; cannot be used as renew or drop authority |
| `CellRenewAuthority` | Renew the bound Cell replica | Cannot read, create, or drop |
| `CellDropAuthority` | Drop the bound Cell replica | Cannot read, create, or renew |
| `InboxReadCap` | Read/watch one random physical Inbox topic within its bounded shape | Cannot append or manage lifecycle |
| `InboxAppendCap` | Append within the bound authorization mode, frame classes, and retention policy | Cannot read, renew, or close |
| `InboxWriteCap` | Aggregate client-side Inbox management record containing read plus create, optional append, renew, and close authority | Least-authority views are explicit handles, never inferred key conversion |
| `InboxCreateAuthority` | Create the prepared Inbox replica | Cannot append, read, renew, or close |
| `InboxRenewAuthority` | Renew the bound Inbox replica | Cannot append, read, create, or close |
| `InboxCloseAuthority` | Close the bound Inbox replica | Cannot append, read, create, or renew |
| `BlindCoreReadCapV1` | Read/decrypt a witnessed Core history under its fork/head bounds | Does not grant relay admission, mirroring, or application writer authority |

Names ending in `V1` above refer to existing canonical client-composition
schemas. Other names are proposed opaque SDK handles over separately stored key
material; this specification does not add them to the public relay wire. Core
mirroring/admission authority, P2P session keys, application signing identity,
and external-service credentials are separate authority classes and MUST NOT be
treated as convertible storage capabilities.

The SDK provides:

```text
exportRecoveryBundle
importRecoveryBundle
inspectCapability
rotateReplica
renew
drop
challenge
repair
```

Recovery exports are encrypted, versioned, authenticated, bounded, and include
the exact protocol/profile pins needed to reject a downgrade. Export policy may
select read-only, append-only, lifecycle-management, or full recovery authority;
it MUST NOT silently widen the requested set. Export UI states plainly that loss
of read material loses data access, while loss of create/append/renew/drop/close
material loses the corresponding publication or lifecycle control.

## 9. Durability and UI evidence

One receipt is one acknowledged remote operation, not a quorum. Durability is
primitive-specific:

| Primitive | Meaningful durability evidence | Claims that are forbidden |
| --- | --- | --- |
| Cell | Locally journaled intent; distinct relay-bound acknowledgements; exact GET/PROVE readback; qualified continuity roots/operator groups; lease state | One receipt is not replication; replica count alone is not operator independence |
| Inbox | Create/manage receipt per replica; append acknowledgement per bounded stripe/replica; read/watch snapshot evidence; lease and retention horizon | Inbox append/read/watch is not durable history, global ordering, authority, or completeness |
| Core | Mirrored signed head/fork/length; relay acknowledgement; challenged block/proof readback; independent mirror/operator evidence; lease state | Opening a replication stream or observing a peer is not durable mirroring |
| Direct P2P | Session establishment and peer acknowledgement only | No offline or storage durability; pair with Cell/Core if required |
| Local compute | Application-defined local persistence of inputs/results | No network replication claim |
| External service | Provider-specific, explicitly non-blind receipt and retention statement | Never counted as Blind Cell/Inbox/Core durability |

Replica, acknowledgement, readback, operator-diversity, stripe, session, mirror,
lease, and retention fields therefore live in a tagged per-primitive durability
schema. Generic Cell defaults MUST NOT be copied onto Inbox, Core, P2P, local
compute, or external plans. Evidence targets must be jointly satisfiable; for
example, operator-diversity evidence counted only over readback-verified replicas
cannot exceed the readback target used to complete the policy.

SDK results and events expose exact evidence:

```js
{
  localState,
  intentState,
  durability: {
    primitive,
    acknowledgedReplicas,
    readbackVerifiedReplicas,
    qualifiedIndependentOperatorGroups,
    externallyWitnessedReplicas,
    repairPending,
    leaseRenewalDeadline,
    retentionHorizon,
    coreHead
  },
  requestedPrivacy,
  actualTransportProfile,
  privacyResolution,
  downgradeAuthorizationId,
  claims: {
    representation,
    transport,
    readInterest,
    durability
  },
  assumptions
}
```

Allowed derived labels are `local-queued`, `remote-stored`,
`remote-readback-verified`, `replicated`, and `resilient-multi-operator`. The UI
MUST display the primitive and evidence behind the label and MUST NOT collapse
them into `online`, `safe`, or `secure`. `queueable` describes current execution
state, not achieved remote durability.

## 10. Cost, padding, batching, and chunking

Cost reporting separates cryptographically exact blind framing from
adapter/network modelling:

```js
{
  usefulBytes,
  opaqueBytes,
  blindEnvelope: {
    requestOuterBytes,
    responseOuterBytes,
    roundTripBytesPerDestination,
    destinationCount,
    totalOuterBytes,
    usefulByteAmplification,
    exact: true
  },
  adapter: {
    profile,
    clientEgressBytes,
    hopBytes,
    encapsulationBytes,
    handshakeBytesAmortized,
    retryAllowanceBytes,
    evidence: 'captured' | 'bounded-model' | 'unknown'
  },
  fleet: {
    totalBytes,
    linkCount,
    evidence: 'captured' | 'bounded-model' | 'unknown'
  }
}
```

For the current v1 same-class profile, `blindEnvelope` values are derived from
the frozen outer classes, not `payload + estimated headers`. They are exact
outer-envelope bytes, not exact HTTP, OHTTP, Noise, Tor, TLS, handshake, retry,
or whole-fleet bytes. Adapter and fleet costs differ by profile and path and MUST
come from that adapter's bounded model or capture evidence. Unknown values remain
`unknown`; they MUST NOT be filled with direct-transport values or multiplied by
replicas and called fleet cost.

An exact Cell estimate additionally requires an explicit useful-byte/Cell-class
basis and an operation-specific destination count. PUT uses `replicaTarget`;
foreground GET uses `fetchTarget`; post-write durability readback remains the
separate `readbackTarget`. Without the size basis, a draft exposes
`estimateStatus: size-basis-required` and no `blindEnvelope`; any hard envelope
ceiling then blocks with `COST_EVIDENCE_UNAVAILABLE`.

Inbox planning similarly selects the minimum universal 4/16/64-KiB opaque frame
class from an explicit positive byte-length basis. Application framing and
encryption must fit inside that selected frame. A value above 65,536 bytes is
`RENDEZVOUS_FRAME_TOO_LARGE` before transport selection; it never becomes a
draft append. Inbox outer-envelope, fanout, and fleet costs remain unknown until
the corresponding adapter model or capture supplies them.

A caller may set `maxBlindEnvelopeAmplification`, `maxAdapterBytes`,
`maxFleetBytes`, `maxForegroundBytes`, or `maxInteractiveLatencyMs`. A hard
adapter/fleet/latency ceiling requires evidence with matching coverage; otherwise
the result is `COST_EVIDENCE_UNAVAILABLE`, not `ready`. The SDK blocks rather
than overruns a hard ceiling. It reports costs per primitive and operation:
Cell PUT/GET/PROVE, Inbox create/append/read/watch, Core mirror/prove/session,
P2P session, and external-service request are not interchangeable estimates.

The SDK SHOULD recommend batching when a small event would sparsely occupy a
4-KiB Cell. It MUST NOT automatically combine events with different authors,
authorization, atomicity, visibility, retention, or privacy policy. The app owns
the batching codec and flush policy.

Objects larger than the maximum Cell payload require an app-owned signed chunk
manifest. Without one, drafting is blocked with `CHUNK_MANIFEST_REQUIRED`. With
one, the prepared plan pins the manifest commitment, exact chunk count/classes,
per-chunk destinations and operations, total blind-envelope costs, available
adapter/fleet bounds, and completion rule. Partial chunks remain incomplete
state; the SDK never reports the logical object complete until the manifest and
every required chunk validate. The SDK never invents an application chunk codec
or signs a manifest on the application's behalf.

## 11. External semantic services

Search, ranking, recommendation, transcoding, remote AI, fraud evaluation,
consensus, and server-authoritative game transitions are not blind merely because
their input is encrypted in transit.

The application first chooses `local-compute` or `external`. Local compute uses
an application-owned executor and reports only the local representation and
process/origin assumptions; it does not manufacture a transport plan or an
external disclosure.

An external-service pure draft requires a separate network intent and a
secret-free semantic-disclosure descriptor, but no consent handle:

```js
{
  workload: { kind: 'semantic', execution: 'external' },
  runtime: 'browser',
  privacy: privacy.private(),
  externalDisclosure: {
    serviceId,
    purpose,
    operatorSees: [...],
    authority: 'advisory' | 'authoritative',
    retention,
    endpointEvidence: 'sha256:<64-hex>',
    networkTransport: 'source-separated'
  }
}
```

The pure draft canonicalizes `operatorSees`, retains only the content-addressed
endpoint-evidence digest, and returns
`consentRequired: true, consentStatus: qualification-required`. It rejects a
caller-shaped `userConsent`, `disclosureAuthorization`, or raw evidence bytes.
This allows Pear Deploy to compile the route without serializing a user's
runtime consent.

The future high-level `app.external()` call supplies the separately minted
`disclosureAuthorization` to `prepare()`, never to `draftWorkload()`.

`disclosureAuthorization` is an opaque local authorization bound to the service
identity and endpoint-evidence hash, purpose, exact `operatorSees` set,
authority, retention statement, requested network-policy hash, visible prompt
version, scope/expiry, and application persona. A boolean `userConsent`, an
authorization for a different service/purpose, or consent to transport downgrade
is insufficient. Missing, expired, widened, or mismatched authorization is
`SEMANTIC_SERVICE_CONSENT_REQUIRED` or
`SEMANTIC_SERVICE_DISCLOSURE_REQUIRED`; it cannot produce `ready`.
`authorizeDisclosure()` is the only SDK operation that mints this handle after
the application presents the exact disclosure through a visible consent UI.

Disclosure does not replace transport privacy. `prepare()` still resolves
`networkPrivacy` to an actual direct, OHTTP/split, or Tor profile and verifies
its evidence. A high-privacy external request without Tor is queueable or
blocked exactly like a blind-storage request; it does not become direct because
the operator can see plaintext. The prepared plan's `transportProfile` remains
the actual network profile. Semantic visibility is reported separately as:

```js
{
  claims: {
    transport,
    semanticDisclosure: {
      claimCeiling: 'explicitly non-blind semantic service',
      operatorSees,
      authority,
      retention
    }
  }
}
```

The SDK keeps external credentials, telemetry, retry policy, consent, cost, and
failure state separate from blind storage. Results that alter canonical
application state are independently validated and signed under the application
protocol. Provider acknowledgements and retention statements never count as
Blind Cell/Inbox/Core durability.

Local search, local moderation, and on-device inference need no external
disclosure and SHOULD be preferred when they meet the product requirement.

## 12. Runtime defaults

### Ordinary browser

- Records and history use Cells; rendezvous uses Inbox.
- `private` selects OHTTP only after the adapter, opaque-origin capture, and
  signed profile evidence are ready.
- Blind Core is unavailable without a production stream bridge.
- Missing/offline OHTTP yields `queueable` or `blocked`, never a direct race.
- Direct fallback requires a bound downgrade authorization and a newly prepared
  plan.

### Pear/Bare/Node

- Records use Cells; long append history and bulk replication prefer Core.
- `private` selects split Noise/Protomux only after that adapter, its distinct
  path roles, and capture/collusion evidence pass. An active release that
  reserves Core/Forward stream operations reports them unavailable.
- `high-privacy` selects full-onion Tor only after its adapter and operator-side
  evidence pass; it starts no clearnet DNS, DHT, QUIC, UDP, or fallback race.
- Live interaction uses direct P2P and pairs with Cells/Core for durability.
- Missing private/Tor paths leave durable mutations queueable under their exact
  requested policy.

### Tor Browser

- Full-onion access fails closed.
- Source-address separation does not by itself prove Origin/app separation.
- The transport axis reports source-address separation, while the application
  identity/origin axis remains `unverified`; the SDK reports the lower separate
  claim ceilings and cannot return a fully satisfied high-privacy plan until the
  opaque-origin gate passes.

No bullet above asserts that an adapter currently ships. Runtime defaults become
selectable only through the release and evidence rule in section 2.

## 13. Pear Deploy integration and developer experience

### 13.1 Contract boundary and present status

Pear Deploy is the intended high-level developer experience after the substrate,
transport adapters, and representative applications pass their conformance
gates. Its existing record kernel is useful authority machinery, but the
`pear.deploy.json` compiler, controller, HiveRelay provider adapter, and privacy
route integration are not yet shipped. This section is a target integration
contract, not evidence that those components exist.

During this design audit, the legacy application-bridge validator skipped all
15 discovered applications and reported success with zero evaluated apps; one
draft contract also used v2 `contentFlow` vocabulary against a v1
`publishFlow` validator. Neither result is promotion evidence. The integration
must make zero evaluated applications a failure and converge on one pinned
contract version before a privacy route can satisfy a release gate.

Three namespaces that all contain a word such as `private` MUST remain distinct:

| Namespace | Example | What it means | What it does not prove |
| --- | --- | --- | --- |
| Deployment profile | Pear Deploy `private@1` | Defaults and release gates for an application deployment | That Blind Cells, Core, OHTTP, or Tor are mature or usable |
| Data classification | `application-encrypted` | Bytes must be authenticated and encrypted before a distributed surface | Source-address, read-interest, identity, or durability privacy |
| SDK route policy | `privacy.private()` | Minimum per-operation transport and metadata constraints | A fresh endpoint, available adapter, consent, admission, or executable plan |

Selecting a deployment profile MUST NOT manufacture a route-policy result. A
route policy MUST NOT change a data classification. Passing both gates MUST NOT
be summarized as one undifferentiated `private: true` claim.

Pear Deploy owns release intent, deterministic compilation, provider leases,
binding sets, and release evidence. The application owns plaintext, schemas,
signing identities, storage capabilities, consent handles, logical events, and
runtime operations. No compiler artifact, provider snapshot, lock, deployment
record, binding set, proof, catalog entry, or controller log may contain bearer
capabilities, application keys, payloads, locators, or consent handles.

The dependency direction is one way: the SDK publishes closed policy schemas,
canonicalization/vectors, a pure planner, and conformance fixtures; a separate
first-party Pear Deploy compiler/provider integration consumes them. The SDK
MUST NOT import Pear Deploy, deploy infrastructure, mutate providers, sign a
release, or report deployment readiness.

### 13.2 Proposed intent extension

Until the route vocabulary is promoted into a frozen Pear Deploy contract, it
belongs in the schema-referenced `extensions` namespace of the provider-neutral,
secret-free `pear.deploy.json`. The compiler MUST reject this extension unless
it recognizes the exact schema and SDK-policy contract digest.

An illustrative intent is:

```json
{
  "$schema": "https://schemas.pear.dev/deploy/intent.v1alpha1.json",
  "apiVersion": "pear.deploy/v1alpha1",
  "kind": "DeploymentIntent",
  "project": "private-collaboration",
  "profile": "private",
  "data": {
    "mode": "stateful",
    "privacy": "mixed"
  },
  "bindings": {
    "network": { "required": true },
    "identity": { "required": true },
    "availability": { "required": true, "provider": "auto" },
    "privateStorage": { "required": true },
    "compute": { "required": false }
  },
  "extensions": {
    "pear.application-privacy/v1alpha1": {
      "$schema": "https://schemas.pear.dev/deploy/application-privacy.v1alpha1.json",
      "policyContract": "hiverelay.application-privacy/v1",
      "routes": {
        "records.timeline": {
          "workload": { "kind": "records", "maxByteLength": 4063 },
          "operations": ["put", "get"],
          "privacy": { "preset": "private" },
          "durability": {
            "replicaTarget": 3,
            "acknowledgementTarget": 2,
            "readbackTarget": 2,
            "independentOperatorGroups": 2
          },
          "runtimeFallback": "prompt",
          "failureMode": "block-release",
          "costBudget": { "maxBlindEnvelopeAmplification": 32 }
        },
        "rendezvous.invites": {
          "workload": { "kind": "rendezvous", "maxByteLength": 512 },
          "operations": ["create", "append", "read", "close"],
          "privacy": { "preset": "private" },
          "runtimeFallback": "prompt",
          "failureMode": "block-release"
        },
        "history.messages": {
          "workload": { "kind": "history" },
          "operations": ["put", "get"],
          "primitiveByRuntime": { "browser": "cell", "bare": "core", "node": "core" },
          "privacy": { "preset": "private" },
          "runtimeFallback": "prompt",
          "failureMode": "block-release"
        },
        "live.presence": {
          "workload": { "kind": "live" },
          "operations": ["session"],
          "privacy": { "preset": "fast" },
          "runtimeFallback": "deny",
          "failureMode": "block-release"
        },
        "semantic.search": {
          "workload": { "kind": "semantic", "execution": "external" },
          "operations": ["execute"],
          "required": false,
          "privacy": { "preset": "private" },
          "serviceBinding": "compute",
          "localExecutor": "search/local-index-v1",
          "bridgeClass": "search-query",
          "externalDisclosure": {
            "serviceId": "search-provider-v1",
            "purpose": "full-text search",
            "operatorSees": ["query", "result selection", "timing"],
            "authority": "advisory",
            "retention": "provider policy",
            "endpointEvidence": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "networkTransport": "source-separated"
          },
          "runtimeFallback": "local-only",
          "failureMode": "disable-feature"
        }
      }
    }
  }
}
```

The example omits the unrelated required Pear Deploy fields for readability.
It is not valid against the current unfinished compiler. Production intent MUST
still contain every required source, surface, artifact, environment,
availability, name, release, telemetry, and secret declaration. The all-zero
endpoint-evidence digest is an obvious documentation placeholder; production
compilation requires the real content digest and qualification requires the
matching evidence object.

`operations` is a required, non-empty, duplicate-free subset of the closed
operation set for its workload. The compiler emits a distinct route expansion
for every `(route, runtime, operation)` tuple and binds each runtime handle to
only those operations. It MUST NOT rely on the pure planner's convenience
default because PUT/GET, MIRROR/OPEN_REPLICATION, and Inbox verbs have different
wire operations, evidence, and cost. `required: false` marks the semantic route
as optional, and `localExecutor` identifies the reviewed local implementation
used by `local-only`; neither field permits an undeclared fallback.

The compiler maps `browser` to `RUNTIME.BROWSER`, `bare`, `node`, and Pear
native surfaces to `RUNTIME.NATIVE`, and a Tor Browser surface to
`RUNTIME.TOR_BROWSER`. It supplies a declared `maxByteLength` to the pure
planner as the worst-case `byteLength`; runtime preparation repeats planning
with the exact operation length. The example's amplification ceiling
intentionally fails against the current symmetric v1 Cell envelope and becomes
satisfiable only through the qualified compact class-1 mutation profile (or a
later more efficient protocol). This is a fail-closed efficiency requirement,
not a claim that the compact profile ships today. Before that profile can make
the compiler green, a later policy-contract revision MUST add an orthogonal,
signed `envelopeProfile` axis, prospective profile-specific estimates, and
conformance tuples for compact+direct, compact+OHTTP, compact+split-native, and
compact+Tor where each composition is actually supported. Network transport
privacy and blind-envelope framing MUST NOT be represented as one competing
selector. The v1 `/policy` surface knows only the symmetric envelope and
therefore MUST keep this route blocked today.

The recognized extension payload is the canonical, secret-free
`AppPrivacyIntentV1`. The compiler extracts it to a content-addressed generated
artifact so the same bytes can be consumed by conformance tools without making
a second human-authored deployment intent. Route names are stable
application-local identifiers and are not relay namespaces. The intent
expresses minimum semantics, not endpoint choices:

- it MAY name a closed workload, permitted primitive per runtime, SDK privacy
  preset or complete custom axes, a required closed `operations` list,
  primitive-specific durability, hard cost ceilings, and fallback policy;
- `runtimeFallback` is `deny`, `prompt`, or, for a semantic route with a local
  implementation, `local-only`; `failureMode` is `block-release` or
  `disable-feature`, and the latter is valid only for an explicitly optional
  route. `deny` and `prompt` MUST equal the selected privacy intent's
  `downgradePolicy`; a fixed-preset conflict is rejected rather than silently
  rewritten. `local-only` requires a reviewed `localExecutor` and is not a
  network privacy downgrade;
- an environment overlay cannot weaken production intent unless that exact
  weaker revision is compiled, reviewed, locked, and signed;
- an external semantic route MUST name a bridge class, service binding, and
  complete secret-free disclosure descriptor, while exact disclosure consent
  remains a runtime, persona-bound authorization; and
- it MUST NOT contain relay endpoints, raw provider descriptors, capabilities,
  credentials, app payloads, or consent booleans.

### 13.3 Deterministic compiler output

The Pear Deploy compiler calls only the pure `/policy` surface. It expands every
route across declared runtime surfaces and declared operations, validates the closed
workload/primitive/privacy matrix, computes exact Cell envelope bounds where
possible, and emits `application-privacy-plan.json` alongside the normal
compiled artifacts. Compilation performs no discovery, qualification, consent,
or application mutation and therefore never emits `ready`.

The generated plan contains:

```text
schema and policy-contract digests
source-intent, deployment-profile, and environment digests
SDK package/version/source-closure digest
stable route name and route-intent digest
runtime/workload/primitive/operation expansion
requested axes and honest draft resolution states
per-primitive durability and cost requirements
required adapter, transport-profile, and conformance classes
external bridge-policy references
compile verdict, reason codes, assumptions, and claim ceilings
```

The compiler adds the plan digest to `compiled-intent.json`, derives
provider-neutral requirements into `relay-needs.json`, derives allowed external
disclosures into deny-by-default `bridge-policy.json`, and pins the exact policy
compiler and route digests in `pear.lock`. The lock also pins the provider
snapshot, adapter versions, signed capability digests, evidence-policy digest,
and conformance bundle digests used for deployment planning. It contains no
bearer authority.

Each route compiles to versioned logical binding requirements such as
`blind-cell`, `blind-inbox`, `blind-core`, `network/direct`, or
`external-service`; concrete provider assignments exist only in a later
`BindingSet`. Multidimensional SDK axes MUST NOT be flattened into Pear Deploy's
legacy scalar `privacyTier`.

Identical fully expanded intent, environment, policy implementation, frozen
provider snapshot, evidence inputs, and evaluation time MUST produce
byte-identical route plans, locks, explanations, and provider action templates.
Unknown axes, profiles, primitives, adapters, evidence predicates, or cost
models fail closed; the compiler does not invent favorable defaults.

### 13.4 Control plane versus runtime data plane

The Pear Deploy HiveRelay provider adapter and the SDK transport adapters have
different authority and MUST remain separate:

| Component | May do | Must not do |
| --- | --- | --- |
| Pear Deploy compiler | Validate and expand route intent; emit requirements and locks | Perform I/O, choose a live route, mint consent, or call `execute()` |
| Pear Deploy controller/provider adapter | Discover signed capabilities, obtain quotes, provision leases/infrastructure, reconcile exact effects, gather release evidence | Read app plaintext or vaults, mint app storage capabilities, send app logical events, or turn a deployment check into an executable operation |
| SDK `prepare()` | Qualify a fresh operation-specific endpoint/path, bind payload/request commitment, costs, consent, capabilities, and expiry | Mutate provider infrastructure or rely on deployment-time health as current operation evidence |
| SDK `execute()` | Send the exact prepared app operation and preserve ambiguous-result semantics | Select a new endpoint/profile, weaken policy, or repair Pear Deploy bindings |

Deployment qualification proves that an environment has evidence-backed
coverage for a declared route class. It cannot pre-authorize future payloads.
At runtime the SDK consumes the signed deployment policy and current binding-set
projection as constraints and discovery inputs, then independently performs
fresh endpoint and operation qualification. A deployment-time pass may make a
runtime path likely to prepare; it never makes a future plan ready.

Qualification uses synthetic, non-secret fixture operations and negative
captures against staged infrastructure. An opaque `prepare()` plan is
short-lived, non-serializable, and never stored in `application-privacy-plan`,
`pear.lock`, a build artifact, a binding set, or release evidence.

Binding-set repair may replace a provider only when the new set meets or exceeds
every signed route and deployment constraint. The application sees the new
signed binding-set revision through discovery; an already prepared operation
does not silently migrate to it.

### 13.5 Ship gates and evidence

`pear deploy ship` MUST refuse a release that advertises a required route until
all applicable gates pass:

1. the exact route extension and `/policy` implementation pass `compiler-v1`
   determinism, closed-schema, and cross-runtime vector tests;
2. every required SDK adapter/profile/runtime tuple has a versioned conformance
   manifest, source-closure digest, executable artifact digest, valid evidence
   window, and negative-path capture coverage;
3. the provider adapter passes the applicable `provider-v1` discovery,
   verification, effect-reconciliation, observation, renewal, and revocation
   gates without claiming app-data authority;
4. representative applications pass route-level integration tests for offline
   queueing, restart, ambiguous results, replica repair, capability leakage,
   disclosure consent, denied fallback, and hard cost ceilings;
5. private and high-privacy captures prove absence of forbidden direct races;
   high privacy additionally proves no clearnet DNS, DHT, QUIC, UDP, HTTP, or
   fallback traffic for the exercised route;
6. independent probes verify the exact deployed adapter and provider-profile
   coverage from clean browser/native clients;
7. `release-proof.json` binds every required predicate to the deployment,
   binding set, policy digest, producer, subject, evidence digest, observation
   time, expiry, strength, and limitations; and
8. compatibility and application-wave validators evaluate at least one intended
   subject under the exact pinned schema; zero evaluated subjects, skipped
   generations, or version/field drift are failures rather than green evidence.

Suggested release-proof predicates are
`privacy-route-policy-compiled`, `privacy-adapter-conformant`,
`privacy-negative-path-pass`, `privacy-provider-profile-qualified`, and
`privacy-app-route-conformant`. A release proof reports deploy-time coverage
only. Its limitations MUST say that per-operation readiness, non-collusion,
traffic-analysis resistance outside the tested capture, service retention, and
future provider health remain runtime or external assumptions.

Evidence is emitted in two separate classes. `AppPrivacyConformanceV1` binds
the source/build/tree digest, exact SDK and adapter artifact digests, runtime
matrix, route-intent digests, test/capture digests, verdicts, and limitations.
Target qualification observations bind an exact staged endpoint, signed
transport-profile and capability-snapshot digests, operation fixture, producer,
observation time, expiry, and limitations. Raw traces and private topology are
metadata-sensitive sidecars; `release-proof.json` contains their digests and
typed verdicts, not the raw material.

Missing optional-route evidence disables that route in the generated runtime
policy. Missing required-route evidence blocks `ship`; it is not a warning.
Preview may use a weaker policy only when the preview environment contains an
explicit, separately compiled override and the UI identifies every difference.
Production intent is never weakened automatically to make a deploy green.

A pure `draft` outcome proves only internal policy validity and cannot satisfy a
promotion predicate. A `blocked` required route fails promotion. A `queueable`
result can prove only that the app's offline/background behavior was exercised;
it never proves target-path availability. Promotion still requires fresh staged
qualification and every other predicate declared by the route.

### 13.6 Target developer flow

The target flow is one intent file and one release path:

```sh
pear deploy check --environment production
pear deploy explain privacy --route history.messages
pear deploy preview
pear deploy ship --environment production
```

`check` is deterministic and non-mutating. Its privacy table shows, per route
and runtime, the chosen primitive, requested axes, expected claim ceilings,
exact envelope cost where available, unresolved evidence, fallback behavior,
and whether the route is required. `explain` shows why candidates were accepted
or rejected. `preview` provisions only the isolated preview policy. `ship`
executes the idempotent provider action plan, verifies the result, and requests
the existing project-controlled release signatures.

The compiler also generates a typed, content-digest-pinned route manifest for
the app build. The target SDK experience is:

```js
import { BlindClient } from '@hiverelay/blind-client'
import deployment from 'pear-deploy:runtime'

const app = await BlindClient.open({
  policy: deployment.applicationPrivacy,
  bindings: deployment.bindings,
  adapters,
  storage,
  vault
})

const timeline = app.route('records.timeline')
const result = await timeline.put(encoded, { signal })
```

The virtual import and `app.route()` are target APIs, not current exports. A
generated handle fixes the signed route constraints but still returns the SDK's
normal `ready`, `queueable`, `blocked`, or ambiguous operation states. It never
contains a hidden direct client or a deployment-time executable plan. An app may
use the lower-level SDK directly, but production claim lint SHOULD fail when its
effective policy is weaker than the signed deployment route.

Compatibility generation is one-way and conservative. A v1 bridge policy is
emitted only for disclosure, opt-in, and exclusion semantics it can represent;
legacy relay-needs v1/v2 files describe only their actual availability roles.
If an SDK axis, failure mode, consent rule, or claim ceiling cannot be represented
without loss, the compiler omits or rejects that projection rather than calling
it `private`, `p2p-only`, or equivalent.

### 13.7 Delivery order

The integration is promoted in this order:

1. freeze and test the pure SDK policy contract and route-plan vectors;
2. stand up each concrete transport/storage adapter and publish narrowly scoped
   evidence without making it selectable early;
3. exercise the adapters through representative browser, native, offline,
   high-loss, and multi-operator applications;
4. add the namespaced route extension and deterministic compiler output to Pear
   Deploy;
5. implement the non-app-data HiveRelay provider adapter and evidence predicates;
6. generate runtime route handles and bind them to signed deployment artifacts;
7. enable `ship` gates route by route only when compiler, provider, verifier,
   adapter, and app conformance all pass; and
8. promote the extension to a stable Pear Deploy contract only after at least
   two independent implementations reproduce its vectors.

This order allows the one-command experience to be built early without letting
its ergonomics outrun the privacy evidence.

## 14. Conformance

Release requires, at minimum:

1. every closed workload/primitive/runtime/preset combination resolves to
   `draft`, `queueable`, or a stable blocked code, and invalid primitive
   overrides never reach generic planning;
2. only an opaque evidence-qualified prepared plan can become `ready` or enter
   `execute()`; a pure draft, JSON reconstruction, registry value, advertisement,
   or availability boolean cannot;
3. every requested custom axis records requested, planned state, required
   evidence, assumptions, and claim ceiling in a draft, while only a qualified
   prepared plan may add actual/satisfaction/evidence fields;
4. fixed preset mutation is rejected and high-privacy downgrade authorization
   cannot be minted;
5. a queueable intent performs no network I/O and retains the exact requested
   policy across wake, restart, discovery, and reconnect;
6. family, operation, endpoint/path roles, transport, privacy profile,
   destination, class, payload/request commitment, and request identity cannot
   mutate within an attempt;
7. high-privacy capture produces no clearnet DNS, DHT, QUIC, UDP, HTTP, or
   fallback race;
8. private paths never race direct, and every fallback is a new plan with an
   exact, unexpired, single-use consent binding;
9. external disclosure consent is bound to service/purpose/visibility/retention
   and remains independent of network transport and downgrade consent;
10. response loss, restart, reload, and multi-tab races do not duplicate a
    logical event;
11. Cell read/write/create/renew/drop, Inbox read/append/create/renew/close,
    Core read/mirror, P2P session, app identity, and external credentials cannot
    substitute for one another and never appear in logs, metrics, crash output,
    or public state;
12. known app/schema/author sentinels are absent from every relay-visible surface;
13. Node, Bare, and browser accept and reject identical canonical vectors;
14. per-primitive durability labels rise only with the stated receipts,
    readbacks, signed heads, witnesses, leases, retention, and operator-group
    evidence;
15. unrelated and previously unknown apps use the unchanged relay ABI;
16. representation, direct, OHTTP, split-native, Tor, browser-origin,
    read-interest, and durability claims each have separate evidence and claim
    ceilings;
17. exact blind-envelope estimates match encoded envelope bytes for every class
    and operation, while adapter/fleet estimates match their declared capture or
    bounded-model coverage and never masquerade as exact envelope bytes;
18. oversized Cell inputs block with `CHUNK_MANIFEST_REQUIRED` until an
    app-signed manifest is supplied, after which all chunks and costs are pinned;
19. local compute produces no external disclosure or transport claim, while
    external compute cannot become ready without complete disclosure and bound
    consent; and
20. package exports, Node/Bare/browser tests, generated browser closure, and
    release evidence cover every advertised API and adapter.

The workload vectors additionally cover every Inbox frame cliff and oversize
rejection, every application-to-wire operation mapping, and equality of all
deterministic plan fields across available versus unavailable inventory hints.

## 15. Migration

1. Preserve `p2p-hiverelay-client` for existing app-aware consumers.
2. Promote the strict protocol/client packages from the accepted vNext source
   and publish them only after their release gates pass.
3. Ship `/policy` first only as the non-executable draft surface, with its
   closed matrix, immutable presets, axis resolution schema, and cost labels.
4. Ship `BlindClient.prepare()/plan()`, `/journal`, and `/vault` only after
   opaque ready-plan, queueing, consent-binding, capability, and restart tests
   pass.
5. Ship concrete adapters incrementally; unavailable or unevidenced adapters
   remain unselectable rather than caller-set `true`.
6. Add `p2p-hiverelay-client/blind` only as a thin version-pinned re-export.
7. Migrate applications primitive by primitive: Cells, durability, Inbox/Core,
   then stronger transports and explicitly disclosed external services.
8. Add the Pear Deploy route extension first as a namespaced experimental
   contract; compile only pure drafts until provider, adapter, verifier, and app
   conformance gates are independently green.
9. Generate runtime route handles and enable production `ship` only for the
   exact route/runtime/profile tuples covered by the signed evidence bundle.
10. Retire legacy OutboxLog, BlindShard, Notify, and semantic relay paths through
   the separately signed compatibility cutoff.

No SDK change authorizes deployment, publication, DNS, fleet mutation, or a
privacy claim without the corresponding independent evidence.
