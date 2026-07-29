# HiveRelay Blind Client Composition v3

Composition v3 imports the exact WIRE v3 ABI and the frozen composition v2
format hash `e289e6a1658db9f63c79ae13b50a055e16eccc997ef4c752bf1c94090b91dcc2`.
It appends only IDs 9 (`ForwardHttpsVerifiedEndpointV3`) and 10
(`ForwardHttpsSessionV3`).

The verified endpoint is operation-exact, descriptor- and health-pinned,
credential-free, fixed-size, non-redirecting, and backed by persistent
IndexedDB continuity. No URL, hostname, IP, dial address, or credentials are
representable in the authority value.

Before fetch, the browser atomically persists the exact 65,536-byte origin
request and its commitment, session, sequence, previous target-result hash,
endpoint hash, and WIRE v3 hash. Transport loss and restart retry those exact
bytes. A verified TARGET_RESULT is committed atomically with its domain-217
chain hash, sequence advance, and outstanding-state clear. Source error or
ambiguity results never advance or clear the exact request. A crash before the
target-result transaction commits therefore leaves the request retryable.

The browser v3 artifact manifest is exactly 214 bytes with magic `HRBCBV03`.
It pins the frozen v2 artifact and manifest, WIRE v3, composition v3, the
artifact, and its complete source closure. All activation and release flags
remain zero or false.
