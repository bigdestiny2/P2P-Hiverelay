# Blind FORWARD route-scope implementation candidate

Status: draft-only CR-5/V-6 implementation candidate. This change does not
freeze or regenerate protocol, ABI, vector, browser, package, or release
authorities and does not enable FORWARD in production assembly. The draft
registry carries the explicit
`FORWARD_ROUTE_SCOPE_AUTHORITY_REGENERATION_PENDING` release blocker until the
governing schemas and generated authorities are deliberately reconciled.

## Enforced shape

The candidate implements an append-only `BlindForwardRouteScopeV1` containing
one to four relay-signed `BlindForwardRouteHopV1` entries. Each signature binds
the complete prior prefix through the scope hash. The daemon obtains the full
prefix from authenticated adjacent-hop transport context, verifies every hash,
signature, descriptor binding, expiry, index, and distinct relay key, then
appends the current relay before admission, reservation, persistence, or dial.

A direct parent must use an all-zero `parentRouteScopeHash`. A forwarded parent
must use the exact immutable inherited hash. The next relay must not equal the
current relay or any prior relay. The request commitment, retry record, HopOpen,
HopAccept, OpenResult, and persistent record bind the accepted scope hash and
relay count.

After validation and before admission, the daemon atomically claims the circuit
nonce under the authenticated parent, request commitment, and accepted scope
hash. Exact concurrent retries share the owner's result; a different binding
fails before spend or allocation. Rejected unrecorded claims notify their
current waiters once and are removed, so invalid admissions cannot exhaust the
bounded retry inventory.

## Immutable root constraints

`maxRelayCount` and `expiresEpoch` are signed into the genesis hash. The selected
V1 schemas carry no separate monotonic effective-limit or effective-expiry
field in either a hop or authenticated parent context. Consequently, reducing
either value on a continuation would change the genesis hash and invalidate all
earlier signatures, while applying a local-only reduction would be lost at the
next hop and could be widened again.

This candidate therefore allows a signed root/profile value from two through
four and requires every continuation route to carry the exact root relay limit
and expiry. It rejects widening and lossy local reduction. Supporting monotonic
reduction would require a schema revision, such as signed per-hop effective
limit and expiry fields.

## Client boundary

The low-level client commits `parentRouteScopeHash` before it asks an admission
provider for a token. A direct open uses the all-zero parent hash; a forwarding
caller supplies the exact inherited hash obtained from its authenticated parent
context. The hash is carried in the canonical request and exposed to the
admission provider, so neither admission nor retry identity can be reused under
a different route prefix.

This helper does not turn an untrusted hash into authenticated route context.
The daemon still derives the parent origin independently, and result acceptance
still requires the caller's `nextHopVerifier` to validate the descriptor and
route proof represented by the returned scope hash and relay count. Frozen
browser, ABI, vector, and runtime authorities remain unchanged.

## Evidence boundary

The adversarial suite exercises real `ForwardStreamService` and adjacent
HopOpen verification paths in one process. It covers root and continuation
acceptance, zero/root reset, count mismatch, altered root, over-depth, A-B-A and
A-B-C-A cycles, omitted/reordered/bit-flipped prefixes, invalid signatures,
expiry, descriptor mismatch, same nonce under another scope, and shutdown
racing a valid continuation. Every pre-admission negative asserts zero spend,
allocation, persistence, adjacent dial, live session, buffer, and route count.

Separate OS processes, production transport adapters, signed catalog inputs,
cross-runtime vectors, and final authority regeneration remain required before
V-6 or PG-2 can pass.
