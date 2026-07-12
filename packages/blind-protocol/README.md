# `@hiverelay/blind-protocol`

This workspace implements the frozen transport-neutral public WIRE framing and
hash inputs for `hiverelay-blind/1`.

The public WIRE authority is final: `hiverelay-blind-abi-v1.cenc`,
`vector-manifest-v1.cenc`, and `HIVERELAY-BLIND-WIRE-V1.md` bind the complete
71-schema, 22-operation, 20-error, and 39-domain public format. Transitional
`.draft` ABI/manifest names are byte-identical aliases.

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
