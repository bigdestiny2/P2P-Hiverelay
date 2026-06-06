# Local App Runtime Bridge

Status: upstream contract and policy guard for privacy-preserving Hyperdrive
apps.

This document is intentionally strict. HiveRelay may distribute app bytes,
replicate encrypted data, and carry opaque circuit-relay traffic. It must not
become a hosted inference gateway for private apps.

## Claim Boundary

For private AI apps such as anonGPT, the allowed path is:

```text
Hyperdrive app bytes
  -> same-device trusted runtime bridge
  -> direct Hyperswarm or opaque CircuitRelay transport
  -> seller service
  -> local receipt verification before trusted display
```

The disallowed path is:

```text
Hyperdrive app bytes
  -> remote HTTPS/WebSocket inference endpoint
  -> hosted prompt termination
```

The second path is easier to ship, but it breaks the privacy claim. Do not call
it private.

## Bridge Shape

The browser-facing API should be narrow:

```js
await window.hiverelay.services.call({
  service: 'ai',
  method: 'infer',
  sellerPubkey,
  input,
  options: { maxTokens: 160 },
  verifyReceipt: true
})
```

The bridge implementation runs locally in Pear/Bare or an equivalent trusted
same-device runtime. The web page never receives generic DHT, filesystem, shell,
wallet-secret, or model-runtime access.

## Mandatory Policy

The bridge must call `checkLocalRuntimeBridgeCall()` or equivalent before
dialing:

- Manifest must declare `hiverelay.services.call`.
- `ai.infer` apps must declare `privacy.storesPrompts=false`.
- `ai.infer` apps must declare `privacy.remoteHttpInference="forbidden"`.
- `ai.infer` calls must verify receipts locally.
- Direct P2P and opaque circuit relay routes are allowed.
- Remote HTTP, HTTPS, WebSocket, and relay-terminated inference routes are
  denied.
- Loopback HTTP may be enabled only as a development stand-in and must not be
  used for production privacy claims.

The pure policy helper lives at:

```text
packages/core/core/app-runtime-policy.js
```

## Relay Role

A public HiveRelay node can serve `/v1/hyper/<key>/...` for app bytes and can
bridge encrypted circuit traffic. It must not expose an inference API that
receives plaintext prompts for private apps.

If a private app cannot reach the local runtime bridge, it should fail closed
with a runtime-unavailable state. It should not silently fall back to a hosted
endpoint.

## What This Does Not Prove

Receipt verification proves an attributable signed commitment to input, output,
model identity, token counts, price, and payment evidence. It does not prove the
seller actually ran a specific model on a specific GPU.

CircuitRelay can improve connectivity and can hide the direct peer path from
some network observers. It is not a full anonymity system, and the seller still
sees the prompt because the seller performs inference.
