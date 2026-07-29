# @hiverelay/blind-client

Application-agnostic client composition for HiveRelay's blind substrate.
It creates fixed-size encrypted cells and relay-bound transport capabilities;
application schemas and identities remain opaque bytes owned by the caller.

The public WIRE and client-composition binary authorities are final independent
inputs. The checked browser-control artifact binds both exact tuples (WIRE
specification/ABI/vector hashes plus client-composition format/vector hashes),
its frozen source closure, and its artifact bytes. The same artifact bytes have
been reproduced on macOS and a clean Linux container and exercised in real
Chromium. The static status remains fail-closed: only
`verifyBlindClientBrowserArtifactReleaseEvidenceV1()` can make this slice
release-ready, after matching both canonical evidence records to the exact
artifact, manifest, source-closure, toolchain, and authority tuple. This does
not make daemon storage, recovery, fleet, or an application profile
release-ready.

The browser control artifact exports `decodeBlindExternalProfileValueV1(name,
bytes)` as its only executable external-profile schema selector. It accepts a
closed six-name inventory bound to the final WIRE/client-composition tuple,
snapshots caller bytes, rejects shared memory and noncanonical encodings, and
never accepts a caller codec, registry, schema, or callback.

The package deliberately has no Peerit, namespace, app registry, author, search,
moderation, or relay-plugin concept. Runtime adapters provide only cryptographic
primitives.

The default export is the small lurker/read/composition surface. Authenticated
descriptor continuity, health qualification, permissionless relay selection,
signed-result verification, encrypted publication intents, ambiguous-write retry,
and durability tracking are loaded explicitly from
`@hiverelay/blind-client/control`.

Ordinary transport accepts only an opaque `VerifiedEndpoint` qualified from a
canonical signed descriptor and fresh signed health result for the exact
endpoint/one-hot-transport/family/operation/privacy tuple. There is no public
raw-endpoint bypass.
Initial discovery uses the separate `BlindDescriptorBootstrapHttpClient`, which
can only fetch a hash-named `DESCRIBE.GET` and returns only a signature-checked
`VerifiedDescriptor`. A trusted descriptor can then issue a DESCRIBE-only control
endpoint for the fresh health challenge; that endpoint cannot authorize storage,
inbox, core, or forwarding operations.
Descriptor trust records are keyed by `(genesis relay key, store ID)`, never by a
relay-chosen store ID alone; every non-genesis continuation must supply the
persisted continuity root, preventing one candidate from collision-quarantining
another operator.
`BlindRelayQualifier` composes the hash-pinned descriptor fetch, persisted chain
acceptance, DESCRIBE-only health request, signed health verification, and exact
operation endpoint issuance into one bounded app-agnostic attempt. Discovery
sources remain replaceable inputs and gain no membership authority.
The opaque health handle carries a local monotonic observation time and cannot
authorize a new operation endpoint after ten minutes, even while the signed
coarse epoch remains current.
Applications sign and journal their own event before publication; zero relays
means queued delivery, one compatible unregistered relay is one remote replica,
and additional readback/operator evidence raises only the durability label.

## Draft workload and privacy planning

`@hiverelay/blind-client/policy` is a pure, side-effect-free planning surface.
It keeps workload placement separate from network privacy, durability, cost,
and semantic-service disclosure:

This policy export is not added to the executable v1 browser-control bundle.
That bundle remains byte-frozen; its manifest and browser evidence are refreshed
only to bind the already-current bundle and exact source closure. The policy SDK
is part of the unpublished private `1.0.0-rc.1` replacement workspace and is
not an npm publication claim.

```js
import {
  RUNTIME,
  WORKLOAD,
  draftWorkloadPlan,
  privacy
} from '@hiverelay/blind-client/policy'

const draft = draftWorkloadPlan({
  workload: { kind: WORKLOAD.RECORDS, byteLength: encoded.byteLength },
  runtime: RUNTIME.BROWSER,
  privacy: privacy.private(),
  inventory: { ohttp: true },
  costBudget: { maxBlindEnvelopeAmplification: 32 }
})
```

A `draft` is never executable. Inventory booleans are deployment hints, not
endpoint or privacy evidence. The future high-level client must qualify the
exact endpoint, operation, signed transport-profile hash, fresh health,
adapter, and capture evidence before it can issue a `ready` plan. Missing
background paths return `queueable`; incompatible workloads, privacy axes,
costs, or disclosures return `blocked` with a stable code.

Fixed presets are immutable. `custom` supplies every constraint axis directly
or inherits a fixed base before overriding it. Pure drafts report requested,
planned, required-evidence, assumptions, and claim-ceiling fields; they never
claim evidence-dependent `actual` or `satisfied` state. OHTTP, split-native,
and Tor remain unavailable for execution until concrete adapters and their
conformance evidence ship.

The intended production developer experience is a Pear Deploy integration.
`pear.deploy.json` will declare named application routes and minimum policies;
the Deploy compiler will call this pure policy surface, pin its deterministic
route plan and conformance inputs, and block `ship` when a required adapter or
application test is unevidenced. Deploy-time coverage never becomes an
executable app operation: the future `BlindClient.prepare()` must still bind
fresh endpoint, consent, capability, cost, and request evidence at runtime.
The proposed contract is specified in
`docs/protocol/HIVERELAY-APPLICATION-PRIVACY-SDK-V1.md` section 13.
