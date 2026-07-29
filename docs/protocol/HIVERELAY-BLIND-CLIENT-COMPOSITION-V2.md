# HiveRelay Blind client composition v2

Client composition v2 is an additive delta over the byte-frozen v1 composition authority. It binds the WIRE v2 ABI hash and appends client-internal schema IDs 7 `ForwardHttpsVerifiedEndpointV2` and 8 `ForwardHttpsSessionV2` without altering v1 schema IDs 1 through 6.

The verified endpoint is an opaque exact-FORWARD-operation handle derived from a hash-pinned signed descriptor and fresh signed health. It pins profile 2, route kind 7, the WIRE v2 ABI hash, nonzero catalog entry ID, exact relay public key, exact descriptor sequence and hash, and fixed request/result sizes of 65,536 bytes. It must use credential-free HTTPS with cookies, authorization, referrer, and redirects disabled. Caller URL, host, IP, dial address, and credentials are not representable.

The session requires a continuity-persistent IndexedDB backend, a signed parent-capability binding, no more than one outstanding sequence, exact-byte idempotent retry, terminal changed replay, signed result verification, and readback verification. Browser code never derives or receives raw TLS exporter material.

These contracts define the bounded public-test shape only. FORWARD descriptor, advertised, and readiness bits remain zero, and browser runtime readiness remains false until independent runtime and recovery acceptance.
