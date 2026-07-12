# Blind FORWARD route-scope design candidate

Status: design candidate for CR-5 and V-6. This is not a frozen protocol
authority, does not enable multi-hop FORWARD, and does not authorize generation
of spec, ABI, vector, browser, package, or release hashes.

## Security property

An honest relay must reject a FORWARD continuation when the caller:

- resets the route budget on a transport already created by FORWARD;
- exceeds the signed route's relay-count bound;
- repeats any relay key in the route;
- changes or truncates the inherited route proof;
- retries one circuit nonce with a different route scope.

A caller-supplied remainingHops value cannot provide this property: opaque
traffic can carry a fresh nested OPEN whose counter starts over. The budget must
therefore be carried in authenticated transport context and extended only by
relays.

The property is scoped to one authenticated circuit and honest enforcement
relays. It does not claim to link a user who exits, reconnects through the public
Internet, and starts an independent circuit. A malicious relay can also violate
its own enforcement. Neither case may be described as globally bounded routing.

## Selected candidate

Use an append-only route-scope proof with an absolute maximum of four relay
entries. A signed route/profile may select a smaller maxRelayCount, but the
caller cannot select or increase it.

~~~text
BlindForwardRouteHopV1 {
  hopIndex:           u8                 // exact 0,1,2,3 sequence
  relayPublicKey:     fixed32
  descriptorSequence:u64
  descriptorHash:    fixed32
  previousScopeHash: fixed32             // zero only at hop 0
  scopeHash:          fixed32
  relaySignature:     fixed64
}

BlindForwardRouteScopeV1 {
  version:              u8 = 1
  rootRouteId:          fixed16
  rootCircuitNonce:     fixed32
  rootRequestCommitment:fixed32
  maxRelayCount:        u8[2..4]
  expiresEpoch:         u32
  hops:                 ordered-array[1..4](BlindForwardRouteHopV1)
}
~~~

For hop i:

~~~text
scopeGenesisHash =
  BLAKE2b-256(
    "hiverelay.blind.forward-scope-genesis.v1" ||
    rootRouteId ||
    rootCircuitNonce ||
    rootRequestCommitment ||
    maxRelayCount ||
    expiresEpoch
  )

scopeHash[i] =
  BLAKE2b-256(
    "hiverelay.blind.forward-scope-hop.v1" ||
    (i == 0 ? scopeGenesisHash : scopeHash[i - 1]) ||
    hopIndex ||
    relayPublicKey ||
    descriptorSequence ||
    descriptorHash
  )
~~~

relaySignature signs scopeHash under a dedicated registry domain. Every receiver
verifies the complete prefix, contiguous indexes, descriptor bindings, expiry,
and distinct relay keys. Carrying every prefix signature prevents a later relay
from silently removing an earlier honest hop.

## Authenticated transport context

Every transport adapter capable of carrying FORWARD must expose an internal,
immutable parent context:

~~~text
ForwardParentContextV1 {
  origin: direct | forwarded
  inheritedScopeHash: fixed32 | null
  inheritedRelayCount: u8
}
~~~

This context is created by the verified adjacent-hop accept path, not parsed
from opaque DATA and not supplied by the caller. An adapter that cannot preserve
it may support only a root/single-transition profile; it must reject multi-hop
continuation.

BlindForwardOpenV1 adds parentRouteScopeHash: fixed32. It must be all-zero only
on a direct parent. On a forwarded parent it must equal the immutable context
hash. A fresh zero/root value on a forwarded parent is a reset attempt and fails
before admission, reservation, persistence, or dialing.

BlindForwardHopOpenV1 carries the full extended BlindForwardRouteScopeV1.
BlindForwardHopAcceptV1 and BlindForwardOpenResultV1 echo the accepted scopeHash
and relay count. BlindTransportRouteV1 carries the signed maxRelayCount; an OPEN
may only reduce the route/profile limit, never increase it.

## Relay algorithm

The enforcement order is:

1. Authenticate the parent and obtain its immutable route context.
2. Require exact root/inherited scope agreement.
3. Verify the complete route-scope signature chain and expiry.
4. Require hops.length < maxRelayCount.
5. Require the current relay to be the last proven hop and the authorized next
   relay to be absent from all prior hops.
6. Extend and sign the route scope.
7. Only then verify admission, reserve capacity, persist the retry record, and
   dial the catalog-authorized adjacent endpoint.

The nonce/retry record and terminal record bind the exact accepted scope hash.
A retry with the same circuit nonce and another scope is terminal conflict.
Scope rejection consumes no spend, opens no socket, advances no WAL, and leaves
no route count, ticket, session, or buffered reservation.

## V-6 evidence matrix

The gate uses real adjacent relay processes and authenticated parent contexts:

| Case | Required result |
| --- | --- |
| Root route within profile bound | Accept and bind the exact scope hash |
| Valid continuation within bound | Accept one append-only scope extension |
| Caller resets a counter or root ID | Reject before admission or dial |
| Fresh nested OPEN uses zero scope on a forwarded parent | Reject as route reset |
| Continuation exceeds maxRelayCount | Reject as over-depth |
| A -> B -> A | Reject repeated relay A |
| A -> B -> C -> A | Reject repeated relay A |
| Prefix omitted, reordered, or bit-flipped | Reject signature/hash chain |
| Expired scope or descriptor mismatch | Reject before admission or dial |
| Same circuit nonce with a different scope | Reject terminally |
| Shutdown races a valid continuation | One terminal record and zero leaked resources |

Each negative must assert zero adjacent sockets, zero admission-spend commit,
zero ambiguous retry state, zero live sessions/tickets/buffers, and exactly one
terminal outcome where a retry record already existed.

## Integration order

1. Review this threat model and route-scope shape.
2. Add the two schemas and domain entry to the sole draft registry.
3. Generate both specification excerpts and executable bindings from that
   registry.
4. Implement parent-context propagation for every admitted transport.
5. Add the V-6 multi-process matrix.
6. Keep FORWARD disabled until V-1, V-2, V-6, and applicable V-7 gates pass.
7. Regenerate RC authorities and downstream browser/Peerit artifacts only after
   all pre-freeze controls and D-6/D-7 are closed.
