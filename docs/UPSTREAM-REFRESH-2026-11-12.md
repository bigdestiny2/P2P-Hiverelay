# Holepunch and Pear refresh — 2026-11-12

This local successor starts at `6e68bdb4ee3a4fbab21714abdabab8678b0c2e23`,
the previously tested 0.27.0-rc.1 candidate. It preserves the canonical checkout's
unfinished work. It is not a fleet rollout or an existing-installation migration.

## Public dependency cohort

| Component | Previous candidate | Updated candidate |
| --- | --- | --- |
| Hypercore | 11.37.0 | 11.40.3 |
| Corestore | 7.12.6 | 7.16.1 |
| hypercore-storage | 3.3.1 | 3.4.0 |
| HyperDHT | 6.34.0 | 6.36.0 |
| Protomux | 3.12.1 | 3.13.1 |
| compact-encoding, public core | 3.5.2 | 3.6.0 |
| Bare runtime | 1.33.4 | 1.37.1 |
| Autobee, experimental test dependency | 2.12.1 | 2.13.4 |

The cohort also refreshes compatible Bare helpers, native storage/network
dependencies, Hyperblobs and Paparam. Hyperdrive 13.3.4, Hyperbee 2.27.3,
Hyperswarm 4.17.2 and blind-relay 1.6.1 were already current. Exact versions and
integrity values are recorded in the lockfile.

Upstream changes include shared in-flight block reads, replication/clear/proof
corrections, reduced bitfield allocation, lower-RTT relay selection, corrected
purge behavior and rejection of nested Protomux batches. These are upstream
improvements; this refresh does not claim a measured throughput increase.

Local corrections accompany the upgrade:

- Boot recovery skips registry entries removed before replay or while waiting
  for seed admission. Explicit new admissions keep their existing behavior.
- Served-byte telemetry detaches monitors from closed cores, releasing retained
  objects while preserving cumulative upload counters and live observations.
  In the disposable churn regression, retained monitors fall from 33 to 1.
- Shutdown cancels in-flight public-IP and API-health HTTP probes through the
  lifecycle signal, allowing pending probe work to settle promptly.
- Holesail startup and shutdown retain the underlying asynchronous operation
  until it settles. Late readiness cannot revive a stopped transport, and
  failed destruction keeps the exact server available for a cleanup retry.
  An unsettled upstream startup remains owned and subject to the existing
  outer shutdown deadline; these tests do not prove public DHT availability.

The dependency audit also prompted supported updates to gRPC 1.14.7,
ip-address 10.7.6 and the official x402 core/EVM SDKs 2.30.0. The resulting
graph uses Zod 4.6.7 and brace-expansion 1.1.21 and reports zero known npm audit
vulnerabilities at observation time. The public gateway operator-address check
now requires globally routable IPv6, including correct classification of NAT64
translation space, while retaining its exclusions for mapped and tunnel forms.
Payment replay reservations use verified EIP-3009 or Permit2 nonce domains,
independent of JSON formatting, key order, unsigned metadata or signatures.
Pending reservations retain their exact owner; completed executions remain
reserved for the authorization's validity period. Local SDK tests use a stub
facilitator. This protection is process-local; persistent replay protection,
live domain-metadata configuration and onchain settlement remain unqualified.

Client unit tests use real local DHT test networks so cleanup does not depend
on public bootstrap availability. The cleanup timeout and retry ownership
contract remains explicitly tested. Local-network integration fixtures disable
optional external Holesail auto-discovery; separate stalled local HTTP tests
exercise actual request cancellation during shutdown.

## Compatibility boundaries

The 3.4.0 storage migration source is byte-identical to 3.3.1. The required local
migration patch retains its exact hash; both its installer and runtime assertion
check the dependency version and patched source. Packaging checks require the
renamed patch. Existing signed installation-authority receipts are not silently
rebound to the new cohort. Production data migration and rollback need their
own approved, rehearsed transition.

The private HC11 adapter, private native Bare/Pear intent profiles, and frozen
browser artifacts retain their separate locks and authorities. Their actual
resolved dependencies must be tested separately; falling back to the public
root dependency tree is not qualification.

Autobee remains development-only. Its compatibility test uses disposable
stores. Autobee 2.13 remapping cannot be read by earlier releases; a successful
fresh-store/cold-reopen test does not establish a downgrade path.

`distributed-drive` stays at 0.1.1: 1.0.1 changes construction, server/client
roles and Corestore-session ownership, requiring a separate bridge migration.
The independent blind wire's compact-encoding v2 and sodium-universal v4
contracts also remain pinned.

Bare 1.37.1 requires the newer upstream Apple platform floor: macOS 13 and
iOS 15. The private profiles retain their previously bound runtimes. Existing
tree damage caused by older Hypercore clear behavior is not repaired merely by
installing the corrected release.

## Research and validation

The canonical Brain's `research/holepunch-pear-refresh-2026-11-12/` contains
official registry snapshots, GitHub source histories, current release coverage,
and the detailed study. Its approved ecosystem-wide baseline is separate from
this local candidate and is not promoted by this change.

Pear's npm wrapper (3.0.0), published CLI release (3.6.0), and development source
(3.8.0-rc.0 at observation time) are distinct. App libraries are separately
versioned. Bare Kit 3 and the updated React Native integration require native
app migration; they are research findings, not relay-server dependencies.

Qualification records and remaining gates are maintained in the sibling
`hiverelay-refresh-20261112/` evidence directory. Run the normal unit and
integration dispatch, Bare smoke/Autobee checks, package/export and migration
installation checks, independent old/new interoperability, and lint before
accepting the candidate. No live connectivity, fleet soak or production data
migration is implied by those local checks.

Primary references:

- [P2P release overview](https://docs.pears.com/p2p/release-overview/)
- [Pear release overview](https://docs.pears.com/pear/release-overview/)
- [Bare release overview](https://docs.pears.com/bare/release-overview/)
- [Hypercore source changes](https://github.com/holepunchto/hypercore/compare/v11.37.0...v11.40.3)
- [HyperDHT source changes](https://github.com/holepunchto/hyperdht/compare/v6.34.0...v6.36.0)
