# `@hiverelay/blind-protocol`

This workspace implements the frozen transport-neutral public WIRE framing and
hash inputs for `hiverelay-blind/1`.

The v1 public WIRE authority is final: `hiverelay-blind-abi-v1.cenc`,
`vector-manifest-v1.cenc`, and `HIVERELAY-BLIND-WIRE-V1.md` bind the complete
71-schema, 22-operation, 20-error, and 39-domain v1 public format ("complete"
is a claim about the v1 authority only). Transitional `.draft` ABI/manifest
names are byte-identical aliases.

The workspace now also ships successor WIRE/ABI authorities alongside the
frozen v1: `wire-v2.js` (`abiFormatVersion: 2`, protocol 1.1,
`hiverelay-blind-abi-v2.cenc`) and `wire-v3.js` (`abiFormatVersion: 3`,
protocol 1.2, `hiverelay-blind-abi-v3.cenc`, including the forward-HTTPS
successor transports), each with its own generated registry, vector manifest,
and release gates. The client-composition catalogs have matching v2/v3
formats and authority records
(`hiverelay-blind-client-composition-authority-v2.json` / `-v3.json`).
Freezing v1 did not freeze the protocol: later trains extend it through these
independently hashed, independently gated versioned authorities.

`ABI_STATUS.releaseReady` and `assertReleaseReady()` cover this public WIRE
authority only. They do not assert that daemon persistence, private IPC, product
images, transports, fleets, or application profiles are production-ready; those
surfaces retain independent artifacts and gates.

The package subpath `@hiverelay/blind-protocol/client-composition-authority`
exposes the independently hashed final authority for the six generic client-side
capability/opaque-chain records that relays never decode. Its
`CLIENT_COMPOSITION_AUTHORITY_STATUS` and assertion are scoped to those six
formats and their 18-vector set only; they do not broaden the WIRE or product
readiness claim.

The canonical design is in `docs/protocol/`; this package is executable evidence,
not a second prose authority.
