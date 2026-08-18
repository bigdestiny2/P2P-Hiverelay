# `@hiverelay/blind-client-public-browser`

Private, repository-local browser artifacts for HiveRelay public controls —
the **public browser artifact successor** for the 0.26.0 train. It succeeds
the frozen v1 `@hiverelay/blind-client` browser bundle for public-facing
browser operations. Like all blind-* workspaces it versions on the deliberate
`1.0.0-rc.x` line, independent of the four npm packages.

Two artifacts are exported (built from `src/`, generated into
`browser-artifacts/` with manifest, Chromium-evidence, and cross-host-evidence
records):

| Export | Artifact | Scope |
|---|---|---|
| `./blind-client-public-control-v1` | `blind-client-public-control-v1.mjs` | Full public browser control surface |
| `./blind-client-public-cell-get-v1` | `blind-client-public-cell-get-v1.mjs` | Limited artifact: public cell reads (CELL.GET) only |

What the full artifact covers:

- **PoW-issued one-use public-write admission (pow-issuance-v1) in the
  browser.** The admission-parameter APIs
  (`createAdmissionParametersRequest`, `VerifiedAdmissionParameters`,
  `trustedAdmissionProfile`) let a browser client obtain and verify admission
  parameters, complete PoW issuance itself, and spend one-use tokens on
  public writes. Scheme and replay safety: `docs/POW-ISSUANCE-V1.md`.
- **Compressed inbox-read signing.** Inbox reads are signed over the
  compressed payload; the Chromium evidence gates cover this path.
- **seq29 browser publishing + inbox discovery.** The browser publish/read
  lane with inbox-discovery reconcile that peerit is live on; the seq29
  browser-artifact gates assert it.

The cell-get artifact is the minimal public read surface for consumers that
must not carry the write/admission code.

Artifacts are release-gated the same way as the blind-client artifacts:
regenerate through `scripts/`, and the evidence records must match the exact
artifact bytes, manifest, and source closure. Do not hand-edit anything under
`browser-artifacts/`.
