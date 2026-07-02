# RelayKernel Gateway Compatibility

RelayKernel is the extraction target, but Blindspark and PearBrowser still rely
on HiveRelay's browser HTTP bootstrap surfaces. This matrix keeps that contract
explicit while RelayKernel develops in parallel.

Run the executable check:

```bash
npm run audit:relaykernel-gateway
```

The canonical route matrix is exported from
`packages/core/core/protocol/relaykernel-profile.js` as
`BLINDSPARK_HTTP_ROUTE_MATRIX`. The audit command reads the matrix and verifies
that each route is still present in the concrete route handlers.

The same matrix is also pinned as the profile-vector fixture
`test/fixtures/relaykernel-profile/relaykernel-http-route-matrix-v1-blindspark-compat.json`.
`node scripts/verify-profile-vectors.mjs` verifies the fixture against the
exported route matrix and requires the full supported vector inventory exactly
once, so the compatibility floor is transplantable without depending only on
this repository's source-level audit. Pass explicit fixture files to the same
script for focused one-vector debugging without the full-inventory gate.

| Surface | Purpose | Required handlers |
|---|---|---|
| `GET /.well-known/hiverelay.json` | Capability metadata before clients speak Hypercore. | Node API and Bare HTTP server. |
| `GET /catalog.json` | Public app/content catalog for browser and mobile bootstrap. | Node API dispatcher, Node API catalog helper, dedicated data-plane gateway, and Bare HTTP server. |
| `GET /v1/hyper/:driveKey/*path` | Hyperdrive content gateway retained for PearBrowser while RelayKernel extracts. | Node API and dedicated data-plane gateway. |

Bare relays participate in the P2P mesh and expose the catalog/capability HTTP
surfaces. They do not claim the browser content gateway; `/v1/hyper/*` remains
the Node/API or dedicated data-plane gateway responsibility.

The profile vector inventory also carries
`relaykernel-profile-v1-app-module-boundary`. That vector keeps QVAC, poker,
custody, and service-plugin signals visible as outside-kernel modules. They can
exist in HiveRelay/Blindspark, but they are not part of the RelayKernel
compatibility floor.

This is deliberately not a full RelayKernel replacement claim. It is the
compatibility floor for the current HiveRelay/Blindspark release line.
