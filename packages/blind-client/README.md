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
