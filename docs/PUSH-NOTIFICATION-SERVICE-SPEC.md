# HiveRelay Push Notification Service Specification

**Version:** 0.1.0-draft
**Date:** 2026-07-02
**Status:** Service MVP implemented; production adapters pending
**Target package:** `p2p-hiveservices` service provider, surfaced by `p2p-hiverelay`

## Summary

HiveRelay push notifications are a relay-hosted wakeup service for P2P
applications. This is not "decentralized push": the final hop still goes
through APNs, FCM, Web Push, or a shared app runtime controlled by the device
OS. HiveRelay's job is to make that bridge p2p-native, consentful, encrypted,
observable, and operator-sustainable.

The relay does not become the app backend, message store, social graph, unread
counter, semantic filter engine, or source of truth. It holds only revocable
notification capabilities, OS push routing material, delivery policy, bounded
encrypted wakeup payloads, and bounded delivery-attempt events. Application
state remains in Hypercore, Hyperdrive, Autobase, app inboxes, or direct P2P
sessions.

The core rule is:

```
push wakes the app; p2p sync gives the app truth
```

Implementation note: the current `notify` provider in `p2p-hiveservices`
implements the signed capability model, durable JSON state under Node relay
storage, quota/replay/dedupe guards, redacted relay-signed delivery events,
watch registration, service discovery, capability-doc advertising, and the
lightweight HTTP facade listed below. `p2p-hiverelay-client/notify.js` ships
Bare-safe signing helpers and HTTP/service client wrappers for apps. It does
not yet ship production APNs/FCM/Web Push adapters or billing enforcement.

This service is valuable because mobile and web operating systems suspend P2P
apps. A relay can stay online for the user, watch authorized P2P surfaces, and
send a minimal wake signal through a provider so the device can wake, reconnect,
and sync from its real P2P state.

## Goals

- Let Pear, Bare, browser, and mobile apps use one HiveRelay-native push API.
- Keep relays replaceable service providers, not authorities.
- Make notification capabilities explicit, signed, bounded, expiring, and
  revocable.
- Split receive authority from send authority so an app vendor key alone cannot
  wake users.
- Require three consent layers: OS permission, HiveRelay device/app/channel
  capability, and app-level peer/content subscription.
- Bind provider tokens to a runtime/app/provider scope with explicit credential
  custody.
- Encrypt all app-defined notification payloads to the target device or app.
- Support direct wakeups, relay-watched inboxes, and presence fallback.
- Give operators a billable service surface with clear abuse controls.
- Keep v1 small enough to ship as an optional `notify` service.

## Non-goals

- No plaintext app messages on the relay.
- No durable app mailbox in the notification service.
- No centralized account system.
- No global notification registry.
- No guaranteed delivery claim beyond provider acceptance and best-effort retry.
- No arbitrary per-app compute in v1 watch rules.
- No relay-side app-specific filtering that requires decrypting app content.
- No app-wide wildcard notification authority in v1.
- No claim that HiveRelay can wake arbitrary standalone native apps without
  their provider credentials or a shared runtime boundary.

## Design Principles

1. **Wake signal, not data plane.** A notification may contain a short encrypted
   hint, but the recipient must fetch authoritative state from the app's P2P
   data model after wake.
2. **Capabilities over accounts.** Apps and users authorize relays with signed
   capability documents, not server-side accounts.
3. **Relay blindness by default.** The relay may see routing metadata, channel,
   urgency, TTL, and billing dimensions. App content stays ciphertext.
4. **Revocation is normal.** Users can revoke app, device, channel, sender, or
   relay capabilities without migrating app state.
5. **Multi-relay friendly.** Apps can register more than one relay for a device
   and use quorum/diversity selection for important notifications.
6. **Provider reality acknowledged.** APNs, FCM, and Web Push are centralized
   OS delivery rails with payload limits, throttling, credential scope, TTL
   behavior, and no display guarantee. HiveRelay wraps them as replaceable
   egress, not as trust roots.
7. **At-most-best-effort delivery.** Notifications may be dropped, duplicated,
   delayed, reordered, collapsed, or throttled. Correctness must survive all of
   those outcomes.

## Actors

| Actor | Role |
|---|---|
| User identity | Signs receive/send capabilities and revocations for apps, devices, senders, and relays. |
| App identity | Public key for a P2P application or app publisher. |
| Device identity | Per-install notification keypair controlled by the app runtime. |
| Relay identity | HiveRelay node key advertising the `notify` service. |
| Sender | Peer, app backend-like service, or relay watcher requesting a wakeup. |
| OS provider | APNs, FCM, or Web Push endpoint used only for final delivery. |

## Service Placement

`notify` is an optional service provider in `p2p-hiveservices` and is surfaced
through the existing HiveRelay service layer.

Suggested service manifest:

```js
{
  name: 'notify',
  version: '0.1.0',
  description: 'Encrypted P2P wakeup notifications for apps',
  capabilities: [
    'register-device',
    'bind-provider',
    'install-receive-cap',
    'install-send-cap',
    'revoke',
    'send',
    'watch',
    'unwatch',
    'status',
    'delivery-event'
  ]
}
```

Discovery surfaces:

- `GET /api/v1/services` includes `notify` when enabled.
- `hiverelay-services` catalog exchange includes `notify`.
- `/.well-known/hiverelay.json` adds feature `notify-v1`.
- Capability doc `protocol_profile.services.notify` advertises provider support,
  limits, supported OS providers, and privacy posture.

Example capability profile:

```json
{
  "features": ["notify-v1"],
  "protocol_profile": {
    "services": {
      "notify": {
        "version": "0.1.0",
        "providers": ["runtime", "apns", "fcm", "webpush"],
        "credential_modes": ["runtime-owned", "app-owned"],
        "modes": ["direct", "watch", "presence-fallback"],
        "payload": {
          "max_ciphertext_bytes": 3072,
          "plaintext_allowed": false,
          "privacy_profiles": ["generic", "local-template"]
        },
        "limits": {
          "max_ttl_seconds": 604800,
          "max_devices_per_user_app": 32,
          "max_watches_per_receive_cap": 128,
          "default_channel_per_hour": 30
        }
      }
    }
  }
}
```

## Provider and Runtime Boundary

HiveRelay supports two product modes. Implementations must declare which mode a
provider binding uses.

### `runtimePush`

Apps run inside a shared Hive/Pear runtime that owns the OS push entitlement,
bundle id, FCM project, or Web Push origin. The provider wakes the runtime; the
runtime dispatches the encrypted wake hint to the app locally.

This is the preferred v1 path because relays and apps do not need arbitrary
native-provider credential custody for every standalone app.

### `standalonePush`

A standalone native app binds its own APNs/FCM/Web Push credentials or delegates
that provider bridge to the relay. This is a larger operational and compliance
surface:

- Provider credentials are app-scoped secrets.
- A bad app can affect provider reputation or quotas.
- Operator onboarding must verify bundle/project/origin ownership.
- Terms, abuse contact, and credential rotation are required production gates.

Standalone push is allowed by the spec, but v1 should optimize for
`runtimePush` and add `standalonePush` only behind explicit operator policy.

## Consent Model

All three layers must be present before a relay sends a push:

| Layer | Who controls it | Required proof |
|---|---|---|
| OS permission | Device user and OS | Valid provider token or runtime binding. |
| HiveRelay capability | User/device identity | `ReceiveCap` plus matching `SendCap`. |
| App subscription | App/user state | App-defined peer, group, channel, or content subscription. |

The relay verifies the first two layers. The app verifies the third layer after
wake by syncing real P2P state. If the app subscription was revoked while the
sender was offline, the wake may still arrive, but the app must ignore any
stale or unauthorized state after sync.

## Key Material

### User key

Identity used to authorize app/device/relay notification capabilities. The spec
does not require a global identity system; it only requires a public key that
the app already treats as the user's authority.

Apps SHOULD use app-scoped user notification keys by default to reduce cross-app
correlation. A stable global user key is allowed only when the user explicitly
chooses that identity for the app.

### App key

Application public key or publisher key. The relay uses it to scope
capabilities and meter usage. The relay must not infer that two app keys belong
to the same publisher unless the apps explicitly disclose that relation.

### Device notification key

Per app install, per device:

```text
notifyDeviceKey = Ed25519 public key
notifyEncryptionKey = X25519 public key
```

The device signs registration requests with `notifyDeviceKey`. Payload
encryption targets `notifyEncryptionKey`. The OS token is never the primary
device identity.

### Relay key

The existing relay identity key signs capability docs, delivery events, and
provider-attempt proofs.

## Data Objects

All signed objects use domain-separated preimages. JSON examples are normative
for field names and semantics; the wire encoding can be JSON in v1 over the
existing service RPC, with compact-encoding as a later optimization.

### ProviderBinding

Created by the runtime or standalone app to bind an OS provider token to a
device notification key. The provider token is routing material, not identity.

```json
{
  "type": "hiverelay.notify.provider-binding.v1",
  "bindingId": "32-byte-hex",
  "audience": "32-byte-hex-relay-key",
  "app": "32-byte-hex-app-key",
  "device": "32-byte-hex-notify-device-key",
  "mode": "runtimePush",
  "provider": "apns",
  "platform": "ios",
  "scope": {
    "bundle": "app.bundle.id",
    "project": null,
    "origin": null
  },
  "credentialMode": "runtime-owned",
  "tokenHash": "32-byte-hex",
  "tokenCiphertext": "base64url",
  "generation": 7,
  "createdAt": 1782864000000,
  "expiresAt": 1814400000000,
  "nonce": "16-byte-hex",
  "signature": "device-or-runtime-signature"
}
```

Rules:

- `audience` must match the relay identity.
- `generation` must increase monotonically for the same `(app, device,
  provider, scope)` tuple. Stale generations are rejected.
- `tokenHash` is used for lookup and invalidation; `tokenCiphertext` is
  decrypted only by local provider egress code.
- Provider tokens and credentials must never appear in public APIs,
  service catalogs, logs, or operator telemetry.
- `runtimePush` bindings are preferred for v1. `standalonePush` bindings must
  pass explicit operator production gates.

### DeviceRegistration

Created by the device and submitted to one or more relays.

```json
{
  "type": "hiverelay.notify.device-registration.v1",
  "audience": "32-byte-hex-relay-key",
  "app": "32-byte-hex-app-key",
  "user": "32-byte-hex-app-scoped-user-key",
  "device": "32-byte-hex-notify-device-key",
  "encryptionKey": "32-byte-hex-x25519-key",
  "bindingId": "32-byte-hex",
  "createdAt": 1782864000000,
  "expiresAt": 1814400000000,
  "nonce": "16-byte-hex",
  "signature": "device-signature"
}
```

Relay storage requirements:

- Store registration keyed by `(app, user, device)`.
- Require a valid `ProviderBinding` before sends can be attempted.
- Accept rotation only when signed by the current device key or a user-signed
  recovery/replacement object.
- Do not expose the stable user key publicly; caller-scoped status may return
  only the caller's own registration state.

### ReceiveCap

User/device-signed authorization allowing one relay to wake one device for one
app under bounded policy. This is the receive side of notification authority.

```json
{
  "type": "hiverelay.notify.receive-cap.v1",
  "capId": "32-byte-hex",
  "audience": "32-byte-hex-relay-key",
  "user": "32-byte-hex-app-scoped-user-key",
  "app": "32-byte-hex-app-key",
  "device": "32-byte-hex-notify-device-key",
  "bindingId": "32-byte-hex",
  "tokenHash": "32-byte-hex",
  "channels": ["message", "mention", "invite"],
  "modes": ["direct", "presence-fallback"],
  "quota": {
    "perHour": 30,
    "burst": 5,
    "maxTtlSeconds": 86400,
    "maxUrgency": "normal"
  },
  "createdAt": 1782864000000,
  "expiresAt": 1785456000000,
  "nonce": "16-byte-hex",
  "signature": "user-or-device-signature"
}
```

Required checks:

- `audience` must match the receiving relay identity.
- `expiresAt` must be in the future and within relay maximums.
- `channels` must be non-empty and bounded.
- `device` and `bindingId` must reference local valid registration state.
- `tokenHash` must match the current provider binding generation.
- Signature must cover every field except `signature`.

### SendCap

Recipient-signed authorization allowing a specific sender or group wake key to
submit wake intents against a `ReceiveCap`. No wildcard sender caps ship in v1.

```json
{
  "type": "hiverelay.notify.send-cap.v1",
  "capId": "32-byte-hex",
  "receiveCap": "32-byte-hex-receive-cap-id",
  "audience": "32-byte-hex-relay-key",
  "app": "32-byte-hex-app-key",
  "device": "32-byte-hex-notify-device-key",
  "sender": "32-byte-hex-sender-or-group-wake-key",
  "channel": "message",
  "quota": {
    "perHour": 10,
    "burst": 3,
    "maxTtlSeconds": 3600,
    "maxUrgency": "normal"
  },
  "createdAt": 1782864000000,
  "expiresAt": 1785456000000,
  "nonce": "16-byte-hex",
  "signature": "user-signature"
}
```

The relay verifies `ReceiveCap`, `SendCap`, sender signature, expiry, revocation
state, replay window, and all quota buckets before attempting provider delivery.

### NotificationRevocation

```json
{
  "type": "hiverelay.notify.revocation.v1",
  "target": "32-byte-hex-cap-or-binding-id",
  "user": "32-byte-hex-app-scoped-user-key",
  "app": "32-byte-hex-app-key",
  "audience": "32-byte-hex-relay-key",
  "scope": "send-cap",
  "createdAt": 1782867600000,
  "nonce": "16-byte-hex",
  "signature": "user-or-device-signature"
}
```

Scopes:

| Scope | Effect |
|---|---|
| `receive-cap` | Revoke one receive capability. |
| `send-cap` | Revoke one sender capability. |
| `app` | Revoke all notification authority for `(user, app)`. |
| `device` | Revoke all capabilities for one device key. |
| `binding` | Mark one provider binding unusable. |
| `relay` | Revoke this relay as notifier for the user. |
| `channel` | Revoke one app channel. |

Relays must reject sends and watches that match an active revocation, even if
the original capability has not expired.

### NotificationIntent

Sender-signed request to wake one device through an installed `SendCap`.

```json
{
  "type": "hiverelay.notify.intent.v1",
  "intentId": "32-byte-hex",
  "receiveCap": "32-byte-hex-receive-cap-id",
  "sendCap": "32-byte-hex-send-cap-id",
  "app": "32-byte-hex-app-key",
  "receiver": "32-byte-hex-notify-device-key",
  "sender": "32-byte-hex-sender-or-group-wake-key",
  "channel": "message",
  "urgency": "normal",
  "ttlSeconds": 3600,
  "collapseKey": "opaque-hash",
  "dedupeKey": "event-or-feed-position-hash",
  "ref": {
    "kind": "hypercore",
    "key": "32-byte-hex-or-null",
    "seq": 123
  },
  "createdAt": 1782864000000,
  "payloadHash": "32-byte-hex",
  "payloadCiphertext": "base64url",
  "payloadEncoding": "hiverelay.notify.payload.box.v1",
  "privacyProfile": "generic",
  "signature": "sender-signature"
}
```

Relay checks:

- `ReceiveCap` exists, is unexpired, and authorizes `app`, `receiver`,
  `channel`, mode, urgency, and TTL.
- `SendCap` exists, is unexpired, binds to the `ReceiveCap`, and authorizes
  `sender` and `channel`.
- `sender` signature verifies over the intent.
- `ttlSeconds` is at or below receive, send, and relay limits.
- `payloadHash` matches `payloadCiphertext`.
- `payloadCiphertext` length is below advertised maximum.
- `collapseKey` and `dedupeKey` are bounded opaque values.
- `createdAt` is inside relay clock skew limits and `intentId` was not replayed.

### DeliveryEvent

Relay-signed delivery attempt record. A `DeliveryEvent` proves relay/provider
behavior, not device display and not user delivery. Device-signed wake or sync
acks are optional future events and are cut from v1.

```json
{
  "type": "hiverelay.notify.delivery-event.v1",
  "intentId": "32-byte-hex",
  "relay": "32-byte-hex-relay-key",
  "app": "32-byte-hex-app-key",
  "device": "32-byte-hex-notify-device-key",
  "provider": "apns",
  "status": "provider_attempted",
  "reason": "accepted_by_provider",
  "providerStatus": "redacted-provider-code",
  "attemptedAt": 1782864000500,
  "expiresAt": 1782867600000,
  "metering": {
    "billable": true,
    "attempts": 1,
    "payloadBytes": 512
  },
  "signature": "relay-signature"
}
```

Statuses:

| Status | Meaning |
|---|---|
| `accepted_by_relay` | Relay validated and queued the intent. |
| `rejected_by_relay` | Relay rejected before provider attempt. |
| `rate_limited` | Relay suppressed because a quota bucket was empty. |
| `expired` | Intent expired before delivery attempt. |
| `provider_attempted` | Relay attempted provider egress. |
| `accepted_by_provider` | Provider accepted the request. |
| `provider_rejected` | Provider rejected the request. |
| `token_invalid` | Provider reported token invalid or unregistered. |
| `abuse_hold` | Relay held the send for operator or automated abuse review. |
| `failed` | Provider unavailable or relay internal failure. |

Mandatory rejection reasons:

| Reason | Meaning |
|---|---|
| `receive_cap_missing` | No valid receive capability. |
| `send_cap_missing` | No valid sender capability. |
| `cap_expired` | Capability expired. |
| `cap_revoked` | Capability revoked. |
| `channel_denied` | Channel outside cap. |
| `urgency_denied` | Urgency exceeds cap. |
| `rate_limited` | Quota bucket empty. |
| `quota_exhausted` | App/operator paid quota exhausted. |
| `provider_token_invalid` | Provider token invalid. |
| `provider_rejected` | Provider rejected request. |
| `abuse_hold` | Abuse controls held request. |

## Payload Encryption

Notification payloads must be encrypted before reaching the relay.

Recommended v1 payload construction:

```text
shared = X25519(senderEphemeralSecret, notifyEncryptionKey)
key = BLAKE2b("hiverelay.notify.payload.box.v1" || shared || intentId)
ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(
  plaintext,
  aad = canonicalIntentHeaders,
  nonce = random24,
  key
)
payloadCiphertext = senderEphemeralPublicKey || nonce || ciphertext
```

Plaintext should be a small app-defined wake hint:

```json
{
  "reason": "message",
  "conversation": "32-byte-hash",
  "head": "optional-feed-length-or-block-hash"
}
```

The relay must not require or parse plaintext. For provider display fields,
v1 defaults to generic copy controlled by the app shell, for example "New
activity". Rich plaintext previews are out of scope for v1 because they break
the relay blindness promise.

Privacy profiles:

| Profile | V1 status | Provider-visible content |
|---|---|---|
| `generic` | Required | Generic title/body only, no app event content. |
| `local-template` | Optional | Generic provider payload plus local app template after wake/decrypt. |
| `notification-extension-decrypt` | Future | Platform-specific extension decrypts before display where available. |
| `plain-provider-payload` | Future explicit leaky mode | Provider sees title/body; not allowed by v1 defaults. |

## Delivery Modes

### Mode 1: Direct wakeup

The app or a sender submits `NotificationIntent` to the relay over
`notify.send`. The relay validates the receive cap, send cap, sender signature,
quota, revocation state, and provider binding, then pushes through the provider.

Use cases:

- Chat peer knows the recipient's notify relay from an app-level profile.
- App operator wants to wake users for app updates or invitations, only when it
  holds an explicit `SendCap`.
- A relay-side service sends a notification after a signed event.

### Mode 2: Watched inbox

The user gives a relay permission to watch an app-defined P2P surface and send
notifications when it advances.

Watch object:

```json
{
  "type": "hiverelay.notify.watch.v1",
  "watchId": "32-byte-hex",
  "receiveCap": "32-byte-hex-receive-cap-id",
  "sendCap": "32-byte-hex-send-cap-id",
  "app": "32-byte-hex-app-key",
  "audience": "32-byte-hex-relay-key",
  "source": {
    "kind": "hypercore-head",
    "key": "32-byte-hex-core-key",
    "start": 42
  },
  "channel": "message",
  "policy": {
    "minIntervalSeconds": 60,
    "collapseKey": "source-key-hash",
    "onlyWhenOffline": true
  },
  "createdAt": 1782864000000,
  "expiresAt": 1785456000000,
  "signature": "user-or-device-signature"
}
```

V1 watch source kinds:

| Source kind | Relay sees | Trigger |
|---|---|---|
| `hypercore-head` | Core key and length only | Head length increases. |
| `notify-feed-head` | Dedicated app notification feed key and length only | Head length increases. |

Relay-side watch rules in v1 are intentionally primitive. They can detect new
append-only activity but cannot run app code or decrypt app messages. The app
must make the watched surface safe for the relay to observe.

Watch mode still requires `SendCap`. The cap must name the app-defined source
or group wake key that is allowed to cause this channel. A relay noticing a feed
tick is never enough authority by itself.

V1 watch mode must not:

- Parse app records.
- Run mention filters.
- Compute unread counts.
- Hold app decryption keys.
- Call app webhooks.
- Persist anything beyond `{ watchId, source, lastSeq, capHash, policy }`.

### Mode 3: Presence fallback

The sender first attempts direct P2P delivery. If the recipient is not present
within an app-defined timeout, it submits `NotificationIntent`.

Presence fallback can use:

- App-specific presence feeds.
- Hyperswarm peer presence.
- Relay-known active WebSocket/session state.

The relay may suppress notifications when the device has an active session for
the same `(app, user, device)` tuple, but it must treat presence as advisory.

## P2P Protocol

Service RPC remains the easiest integration path, but the protocol name for
direct P2P use is:

```text
hiverelay.notify/1
```

Messages:

| Message | Direction | Purpose |
|---|---|---|
| `HELLO` | both | Exchange notify version, relay key, feature flags, and limits. |
| `BIND_PROVIDER` | client -> relay | Install or rotate a provider binding. |
| `REGISTER_DEVICE` | client -> relay | Register device notification key. |
| `INSTALL_RECEIVE_CAP` | client -> relay | Install receive capability. |
| `INSTALL_SEND_CAP` | client -> relay | Install sender capability. |
| `SUBMIT_INTENT` | sender -> relay | Submit wake intent. |
| `INSTALL_WATCH` | client -> relay | Install opaque watch. |
| `REVOKE_CAP` | client -> relay | Revoke cap, binding, channel, app, device, or relay. |
| `ACK` | relay -> client | Return accepted/rejected status and optional delivery event id. |

Domain-separated signature strings:

```text
hiverelay.notify.v1.provider-binding
hiverelay.notify.v1.device-registration
hiverelay.notify.v1.receive-cap
hiverelay.notify.v1.send-cap
hiverelay.notify.v1.intent
hiverelay.notify.v1.watch
hiverelay.notify.v1.revoke
hiverelay.notify.v1.delivery-event
```

## RPC Methods

### `notify.bind-provider(params)`

Input: `ProviderBinding`.

Output:

```json
{
  "ok": true,
  "bindingId": "32-byte-hex",
  "generation": 7,
  "expiresAt": 1814400000000
}
```

### `notify.register-device(params)`

Input: `DeviceRegistration`.

Output:

```json
{
  "ok": true,
  "device": "32-byte-hex-notify-device-key",
  "relay": "32-byte-hex-relay-key",
  "bindingId": "32-byte-hex",
  "expiresAt": 1814400000000
}
```

### `notify.install-receive-cap(params)`

Input: `ReceiveCap`.

Output:

```json
{
  "ok": true,
  "capId": "32-byte-hex",
  "limits": {
    "perHour": 30,
    "burst": 5
  }
}
```

### `notify.install-send-cap(params)`

Input: `SendCap`.

Output:

```json
{
  "ok": true,
  "capId": "32-byte-hex",
  "receiveCap": "32-byte-hex"
}
```

### `notify.revoke(params)`

Input: `NotificationRevocation`.

Output:

```json
{ "ok": true, "revoked": true }
```

### `notify.send(params)`

Input: `NotificationIntent`.

Output:

```json
{
  "ok": true,
  "intentId": "32-byte-hex",
  "status": "accepted_by_relay",
  "eventId": "32-byte-hex-or-null"
}
```

`notify.send` may return an immediate `DeliveryEvent` id when provider delivery
is synchronous, or the caller can fetch events with `notify.delivery-event`.

### `notify.watch(params)`

Input: `Watch` object.

Output:

```json
{
  "ok": true,
  "watchId": "32-byte-hex",
  "source": {
    "kind": "hypercore-head",
    "key": "32-byte-hex-core-key"
  }
}
```

### `notify.unwatch(params)`

Input:

```json
{
  "watchId": "32-byte-hex",
  "receiveCap": "32-byte-hex",
  "signature": "user-or-device-signature"
}
```

Output:

```json
{ "ok": true, "removed": true }
```

### `notify.status(params)`

Returns bounded, redacted state for the caller's own app/user/device tuple.

### `notify.delivery-event(params)`

Returns relay-signed delivery-attempt events for one intent, capped and
filtered by caller authorization. It must not claim display or user delivery.

## HTTP Surface

The primary v1 API should be service RPC. HTTP can be added for browser and
mobile clients behind the existing management/public auth model:

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /api/v1/notify/capabilities` | public | Redacted notify service profile. |
| `POST /api/v1/notify/provider` | signed binding | Install or rotate provider token binding. |
| `POST /api/v1/notify/device` | signed device request | Register device notification key. |
| `POST /api/v1/notify/receive-cap` | signed user/device request | Install receive capability. |
| `POST /api/v1/notify/send-cap` | signed user request | Install sender capability. |
| `POST /api/v1/notify/revoke` | signed user/device request | Revoke cap/binding/device/channel. |
| `POST /api/v1/notify/send` | signed intent | Request wakeup. |
| `POST /api/v1/notify/watch` | signed cap/watch | Install opaque watch. |
| `GET /api/v1/notify/status` | signed caller request | Caller-scoped redacted state, using query params as the signed object. |
| `POST /api/v1/notify/status` | signed caller request | Caller-scoped redacted state, using a JSON signed object. |

Operator diagnostics belong under management auth and must never expose provider
tokens or payload plaintext:

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /api/manage/notify` | management | Aggregate counts, queue depth, error classes, rate-limit state. |
| `POST /api/manage/notify/test` | management | Send a test notification to an operator-owned device. |
| `GET /api/manage/notify/production-gates` | management | Provider binding, consent, limits, and abuse-readiness checks. |

## Provider Bridges

Provider modules are egress adapters with a narrow interface:

```js
class PushProvider {
  async send (delivery) {
    return {
      status: 'accepted',
      providerStatus: 'redacted-provider-code',
      retryAfterMs: 0
    }
  }
}
```

Delivery input:

```js
{
  provider,
  credentialMode,
  providerTokenCiphertext,
  app,
  device,
  channel,
  urgency,
  ttlSeconds,
  collapseKey,
  payloadCiphertext,
  genericDisplay
}
```

Provider rules:

- APNs topics, FCM projects, and Web Push origins are scoped provider assets.
  A generic relay cannot wake arbitrary native apps unless a shared runtime owns
  the provider entitlement or the standalone app supplies verified credentials.
- `runtime-owned` credentials are operator/runtime config and are the preferred
  v1 path.
- `app-owned` credentials are allowed only when the operator explicitly enables
  `standalonePush` and the app passes production gates.
- Provider credentials must be treated like wallet/API secrets: encrypted at
  rest when possible and redacted everywhere.
- Provider-specific errors must be normalized before becoming delivery events
  or telemetry.
- Invalid provider tokens should mark the device registration stale but should
  not delete capabilities without an explicit revocation.
- Silent/background pushes must be treated as hints, not reliable background
  compute.
- Provider payloads must fit provider constraints; v1 avoids exact
  provider-limit promises and enforces a conservative relay-side ciphertext cap.

## Storage Model

Recommended local stores:

| Store | Key | Value |
|---|---|---|
| `notify/provider-bindings` | `bindingId` | Signed binding, encrypted provider token, generation, expiry. |
| `notify/devices` | `app/user/device` | Signed registration, binding pointer, expiry. |
| `notify/receive-caps` | `capId` | Signed receive capability and local enforcement state. |
| `notify/send-caps` | `capId` | Signed sender capability and local enforcement state. |
| `notify/revocations` | `scope/key` | Signed revocation, newest-wins. |
| `notify/watches` | `watchId` | Signed watch and last observed position. |
| `notify/dedupe` | `dedupeKey` | Expiring marker. |
| `notify/delivery-events` | `intentId/device` | Signed delivery event until retention expiry. |

The v0.1.0 provider persists these stores as a versioned JSON snapshot at
`<relay-storage>/notify-service-state.json` when the Node relay starts the
service with `config.storage`. Operators/tests can also pass a custom
`persistence` adapter with `load()` / `save(snapshot)` or an explicit
`persistencePath`. The snapshot includes signed capability records,
revocations, watches, bounded delivery events, replay/dedupe markers, and
rate-limit buckets; application data remains outside the service.

Retention defaults:

| Data | Default retention |
|---|---|
| Provider token | Until binding expiry, invalidation, or user revocation. |
| ReceiveCap | Until expiry plus 7 days audit grace. |
| SendCap | Until expiry plus 7 days audit grace. |
| Revocation | At least capability expiry plus 30 days. |
| DeliveryEvent | 7 days for free tier, configurable for paid tiers. |
| Dedupe key | Min of intent TTL and 24 hours. |
| Watch state | Until watch expiry or revocation. |

## Abuse Controls

Required v1 controls:

- Per receive-cap token bucket.
- Per send-cap token bucket.
- Per app token bucket.
- Per sender token bucket.
- Per device token bucket.
- Per channel token bucket.
- Per collapse group suppression window.
- Per relay global queue and provider budget.
- Per app paid quota or free-tier ceiling.
- Max payload size.
- Max TTL.
- Max watches per receive cap.
- Max devices per user/app.
- Collapse key suppression.
- Dedupe key suppression.
- Provider failure backoff.
- Signed sender capability required for all v1 sends.
- Abuse hold for apps/senders exceeding invalid-token, provider-reject, or
  complaint thresholds.

Recommended defaults:

| Limit | Default |
|---|---|
| Payload ciphertext | 3072 bytes |
| Intent TTL | 1 hour default, 7 days hard cap |
| Per receive cap | 30 per hour, burst 5 |
| Per send cap | 10 per hour, burst 3 |
| Per app | Operator configured |
| Per device | 120 per hour, burst 10 |
| Watches per receive cap | 128 |
| Devices per user/app | 32 |
| Queue retention | Min of TTL and 24 hours |

Muted, revoked, rate-limited, or duplicate notifications should produce
`rate_limited`, `cap_revoked`, or `provider_attempted` delivery events as
appropriate. Suppression is important for app debugging and billing disputes,
but delivery events must remain content-free.

## Privacy Boundaries

Relay may know:

- App key.
- App-scoped user key if the capability exposes it.
- Device notification key.
- OS provider class.
- Channel name.
- Urgency.
- TTL.
- Collapse/dedupe hashes.
- Sender or group wake key.
- Watch source key and coarse append activity.
- Provider delivery outcome.

Relay must not know:

- Plaintext message content.
- Plaintext sender display name.
- Plaintext conversation title.
- Contacts/social graph beyond what app capabilities reveal.
- OS provider tokens outside local encrypted storage.
- App-specific private keys.

To reduce metadata leakage:

- Apps should hash conversation/thread ids before using collapse keys.
- Apps should use coarse channel names.
- Apps should prefer app-scoped user keys over global user keys.
- Apps should rotate group wake keys when group membership changes.
- Relays should cap and redact operator telemetry.
- Multi-relay use should avoid always picking the same relay for every app.
- Watch mode should be opt-in because source keys and append timing are
  metadata.
- Delivery-event retention should default to minimum useful audit windows, with
  aggregate-only analytics by default.

## Threat Model

| Threat | Mitigation |
|---|---|
| Malicious relay sends unauthorized push | OS provider token is local, but app verifies wake hint after sync; caps are auditable; clients can revoke and move relays. |
| Malicious app spams user | Per-channel receive caps, per-sender send caps, user revocation, token buckets, operator app-level limits. |
| Sender forges intent | Recipient-issued `SendCap` must name sender or group wake key; relay rejects unrecognized signers. |
| Relay reads content | Payload encryption; generic display text in v1; no plaintext fields accepted. |
| Provider token leak | Encrypt at rest; redact telemetry; never return token through service status. |
| Notification timing leaks activity | Allow watch opt-in, batching, min intervals, collapse keys, and user-level mute windows. |
| Replay of old intent | Intent id, dedupe key, createdAt skew checks, TTL, expiring replay cache. |
| Watch source becomes possession oracle | Watch only registered authorized sources; rate limit failed watch attempts; return generic `not-authorized`. |
| Push provider outage | Retry within TTL, return failed delivery events, app still syncs on manual open. |
| Relay centralization | Multi-relay capabilities and portable device registrations. |
| Provider throttles silent/background wake | Treat push as a hint only; no correctness depends on background execution. |
| Wake arrives before data replication | App sync loop retries from P2P state; notification carries only optional `ref`. |
| Duplicate pushes across multiple relays | Sender uses same dedupe key; app ignores duplicate wake hints after sync. |
| Device token rotation | Monotonic provider-binding generation; stale generations rejected. |
| App uninstall/token invalidation | `token_invalid` event marks binding stale; caps remain until expiry/revocation. |
| Relay key rotation | New relay identity requires new caps or signed relay-key transition object. |
| Compromised send cap | User revokes that cap without rotating receive cap or provider binding. |
| Group chat fanout pressure | App issues group wake keys; relay does not manage group membership or contact lists. |

## Economics

Push is a natural service-operator revenue line because it needs uptime,
provider credentials, queueing, rate limits, observability, and abuse handling.
It is not as commodity as raw seeding and not as hardware-heavy as AI.
Pricing should not be message-count only; the expensive parts are active device
state, watched sources, priority handling, delivery-event retention, abuse
operations, and provider credential custody.

Suggested billable units:

| Unit | Notes |
|---|---|
| Registered device-month | Covers token storage, credential operations, and baseline monitoring. |
| Push attempt | Charged on provider attempt, not guaranteed display. |
| Watched source-month | Covers relay staying joined and tracking app surfaces. |
| High-priority attempt | Higher price because it consumes scarce provider/operator budget. |
| Delivery-event retention | Optional paid audit/debug feature. |
| Standalone provider custody | Premium tier because credentials, support, and abuse risk are higher. |

Phase 1 can be reputation/free beta. Phase 2 can settle per app over Lightning
using usage receipts aligned with existing HiveRelay accounting patterns.

Usage receipt dimensions:

```json
{
  "service": "notify",
  "app": "32-byte-hex-app-key",
  "period": "2026-07",
  "attempts": 12000,
  "accepted": 11800,
  "suppressed": 900,
  "watchedSources": 42,
  "deviceDays": 410,
  "standaloneBindings": 8,
  "payloadBytes": 6144000
}
```

## Production Gates

An app/provider binding is production-ready only when the relay can verify:

| Gate | Requirement |
|---|---|
| Provider binding | Token and credential scope verified for runtime/bundle/project/origin. |
| Test delivery | `notify test` succeeds against an operator or developer test device. |
| Consent UI | App has OS permission prompt plus HiveRelay app/channel/device controls. |
| Revoke path | User can revoke app, device, channel, relay, and sender caps. |
| Rate limits | Receive, send, app, device, channel, and provider budgets configured. |
| Abuse contact | App/operator abuse contact configured for standalone push. |
| Privacy profile | App declares `generic` or another explicit profile with disclosure. |
| Token churn | Invalid-token handling and binding rotation tested. |
| Observability | Dashboard shows aggregate sends, rejects, queue depth, quota pressure, and provider health. |

Suggested CLI/DX commands:

```text
hiverelay notify init
hiverelay notify bind-provider --mode runtimePush
hiverelay notify test --device <device-key>
hiverelay notify inspect --app <app-key>
hiverelay notify production-gates --app <app-key>
```

## Developer Experience

Client SDK target:

```js
const notify = await client.notify(relay)

const binding = await notify.bindProvider({
  mode: 'runtimePush',
  app,
  device: deviceKey,
  provider: 'apns',
  providerToken
})

const device = await notify.registerDevice({
  app,
  user,
  bindingId: binding.id,
  device: deviceKey,
  encryptionKey
})

const receiveCap = await notify.installReceiveCap({
  app,
  user,
  device: device.key,
  bindingId: binding.id,
  channels: ['message', 'mention'],
  quota: { perHour: 30 }
})

const sendCap = await notify.installSendCap({
  receiveCap: receiveCap.id,
  app,
  device: device.key,
  sender: aliceKey,
  channel: 'message',
  quota: { perHour: 10 }
})

await notify.send({
  receiveCap: receiveCap.id,
  sendCap: sendCap.id,
  receiver: device.key,
  sender: aliceKey,
  channel: 'message',
  collapseKey: hash(conversationKey),
  payload: await notify.encrypt(device, {
    reason: 'message',
    conversation: hash(conversationKey)
  })
})
```

App wake flow:

1. Device receives provider push.
2. App runtime wakes.
3. App decrypts wake hint locally.
4. App opens its Hypercore/Autobase/app inbox.
5. App syncs from peers/relays.
6. App renders only verified app state.

## V1 Implementation Plan

1. Add `notify` service provider skeleton in `p2p-hiveservices`.
2. Add service manifest, capability feature `notify-v1`, and redacted manage
   status.
3. Implement local stores for provider bindings, registrations, receive caps,
   send caps, revocations, dedupe, watches, and delivery events. The current
   Node relay provider persists these as a versioned JSON state file.
4. Implement signed provider binding, registration, receive cap, send cap, and
   revocation validation.
5. Implement encrypted direct `notify.send` with a fake provider adapter.
6. Add Web Push provider first for browser/dev testing.
7. Add runtime-owned APNs and FCM adapters behind operator config.
8. Add delivery events and usage counters.
9. Add SDK helpers for bind/register/install caps/send/encrypt.
10. Add watched `hypercore-head` or dedicated `notify-feed-head` mode only.
11. Add provider-backed integration tests with fake provider fixtures.
12. Add production gate checker and `notify test` CLI.
13. Add appliance dashboard controls for enabling providers and viewing
    redacted queue/usage health.

## V1 Cut Line

Ship in v1:

- Direct notification intents.
- Provider binding and token rotation.
- Device registration.
- Receive caps, send caps, and revocations.
- Encrypted payloads.
- Generic display text.
- Web Push dev provider plus runtime-owned APNs/FCM adapters.
- Bounded delivery events and usage counters.
- `hypercore-head` or dedicated `notify-feed-head` watch mode.
- Collapse/dedupe/rate limits.
- Production gate checker.

Do not ship in v1:

- Plaintext rich previews.
- App-defined relay-side JavaScript filters.
- Arbitrary watch predicates.
- App webhooks.
- Global directory of user notification relays.
- Cross-relay fanout protocol.
- Guaranteed delivery SLA.
- Provider-token sharing between relays.
- Notification analytics that expose contacts or conversation titles.
- App-wide wildcard notify authority.
- Standalone app-owned APNs/FCM credential custody without explicit operator
  policy and production gates.

## Open Questions

1. Should capabilities be appended to an app/user Hypercore for portable audit,
   or is local relay storage plus signed export enough for v1?
2. Should `runtimePush` be the only production-supported v1 path, with
   `standalonePush` kept experimental until credential custody has a separate
   audit?
3. How should group wake keys be rotated and discovered without making the
   relay a group-membership server?
4. Do we need a relay-to-relay handoff format for device/provider migration
   in v1, or can devices re-register with new relays?
5. Should watch mode require the watched source to already be seeded on the
   relay, or can `notify` join/watch sources that are not otherwise in the app
   registry?
6. Which provider bridge should be the first production target: Web Push for
   easiest development, or APNs because iOS is the hardest real constraint?
7. Should device-signed `app_wake_ack` and `app_sync_ack` events be a v2 feature
   for debugging, or would they create too much tracking surface?

## Adversarial Review Notes

This section records the design pressure applied by two internal review
personas. They are inspiration lenses, not claims of external review.

### P2P systems review

Applied conclusions:

- Define push as a lossy encrypted wake service, not a notification backend.
- Split authority into `ReceiveCap` and `SendCap`.
- Require sender proof for every intent; no wildcard sender caps in v1.
- Cut rich provider-visible previews from v1.
- Restrict watch mode to opaque append/head ticks.
- Treat APNs/FCM/Web Push as provider egress adapters, not p2p trust roots.
- Rename delivery records to `DeliveryEvent` and explicitly avoid display or
  user-delivery claims.
- Keep relay state bounded: caps, provider bindings, quota counters, dedupe
  windows, watch offsets, and short retention events.

Sharp objection preserved:

> If HiveRelay Core says "apps call our notify API and we push to their users,"
> it is a backend. If HiveRelay Core says "users issue encrypted, expiring wake
> capabilities to peers/apps, and relays provide a replaceable OS wake bridge,"
> it is p2p-native.

### Product and operator review

Applied conclusions:

- Be honest that this is p2p wake coordination over centralized OS push pipes.
- Define `runtimePush` vs `standalonePush` because provider credentials are
  scoped to app bundles, projects, and origins.
- Require OS permission, HiveRelay capability consent, and app subscription
  consent.
- Add production gates for provider binding, test delivery, revoke path, rate
  limits, abuse contact, privacy profile, token churn, and observability.
- Avoid delivery promises beyond relay/provider attempt statuses.
- Treat metadata leakage as a privacy budget.
- Price active devices, watched sources, priority, retention, and credential
  custody, not only message count.
- Add operator dashboard requirements for queue depth, provider health, rejects,
  invalid tokens, quota pressure, and abusive apps.

Sharp objection preserved:

> "Universal p2p push" is a trap phrase. The final hop is Apple, Google, a
> browser push service, or a shared runtime.
