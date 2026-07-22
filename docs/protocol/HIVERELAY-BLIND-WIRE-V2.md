# HiveRelay Blind WIRE v2 additive authority

Status: canonical additive contract for WIRE protocol 1.1 and ABI format 2. WIRE v1 protocol 1.0, ABI format 1, schema IDs 1 through 73, their bytes, hashes, decoder, native streaming route kinds, and operation rows remain unchanged.

## Release profiles

Profile 1 is `LIMITED_PUBLIC_TEST_V1`, operation mask `0x0001ffff`, and remains the fail-closed default. The deprecated spelling `BASELINE_17` is accepted only while parsing configuration or CLI input; it is never emitted, signed, hashed, stored, or encoded on wire.

Profile 2 is `LIMITED_PUBLIC_TEST_FORWARD_ONE_HOP_V1`, operation mask `0x003dffff`, with no alias. Bit 17 (`CORE.OPEN_REPLICATION`) is clear in both profiles.

## Additive HTTPS FORWARD transport

Route kind 7 is `DIRECT_HTTPS_FORWARD_ONE_HOP`. It is a profile-2 transport variant for the existing FORWARD `OPEN`, `DATA`, `WINDOW`, and `CLOSE` operations and does not redefine those native operation rows. Each variant uses request schema 74 and result schema 75. The canonical request body and canonical success-or-error result body are each exactly 65,536 bytes, including header, inner body, and padding.

Schema 74 is `BlindForwardHttpsTurnRequestV1`: a closed discriminator wrapping only existing `BlindForwardOpenV1`, `BlindForwardDataV1`, `BlindForwardWindowV1`, or `BlindForwardCloseV1` request codecs.

Schema 75 is `BlindForwardHttpsTurnResultV1`: a closed success-or-error discriminator. Success `OPEN` uses `BlindForwardOpenResultV1`; success `DATA`, `WINDOW`, and `CLOSE` reuse their existing codecs bidirectionally. Error uses existing `BlindErrorV1`. There are no ACK schemas.

The request commitment binds all 65,536 request bytes. The result signature payload binds all 65,536 result bytes except its fixed 64-byte signature slot, including every padding byte. One request sequence may be outstanding per signed session. An exact byte-for-byte retry is idempotent; changed bytes at the same sequence are terminal.

## One-transition parent capability

The inline signed parent capability pins a nonzero catalog entry ID, exact target relay public key, exact target descriptor sequence and hash, exact source relay and descriptor, a route prefix containing exactly that source, maximum relay count 2, remaining transitions 1, F1, cumulative 16 MiB spend including retries, 64 KiB window, 30 second idle timeout, 10 minute lifetime, nonce, expiry, and a hash of the source Edge TLS exporter binding. Source and target keys must differ, excluding A-B-A. Nested OPEN, reset, forwarded parents, reissue, fallback, and caller-provided URL, host, IP, or dial address are forbidden.

The source Edge alone derives TLS exporter material and passes only a binding over peer-credential-authenticated private IPC. Browser-visible and on-wire structures never contain raw exporter material.

## Domains

- Request 17 `FORWARD_HTTPS_TURN`: `hiverelay.blind.forward-https-turn-request.v1`
- Result 112 `FORWARD_HTTPS_TURN_RESULT`: `hiverelay.blind.forward-https-turn-result.v1`
- Auxiliary 214 `FORWARD_HTTPS_PARENT_CAPABILITY`: `hiverelay.blind.forward-https-parent-capability.v1`

## Activation boundary

The profile and transport variant are defined but not activated. FORWARD descriptor, advertised, and readiness bits remain zero until exact-size server enforcement, TLS-bound capability minting and verification, bounded HTTPS adaptation, retry and terminal recovery, real multiprocess restart, over-budget, replay, reset, over-depth, and A-B-A evidence are independently accepted. This contract does not claim V-6 closure or multi-hop readiness.
