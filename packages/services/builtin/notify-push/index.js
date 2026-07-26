/**
 * Push provider factory.
 *
 * NotifyService resolves `config.notify.push` through here in `start()`. The
 * descriptor is plain JSON because operator config is JSON-only, and the
 * credentials it names are read from the operator's config/env at runtime —
 * nothing in this repo ships or stores key material.
 *
 * Descriptor shapes:
 *
 *   { kind: 'apns',    credentials: { keyId, teamId, privateKey, bundleId, host? } }
 *   { kind: 'fcm',     credentials: { projectId, clientEmail, privateKey } }
 *   { kind: 'webpush', credentials: { subject, privateKey, publicKey? } }
 *   { kind: 'multi',   providers: { apns: {...}, fcm: {...}, webpush: {...} } }
 *
 * Plus, on any descriptor: `tokenEncoding: 'sealed' | 'plaintext'` (default
 * `sealed`; see token-codec.js).
 */

import { assertNodeCrypto } from './jwt.js'
import { createTokenOpener } from './token-codec.js'

export { sealDeviceToken, createTokenOpener, TOKEN_ENCODINGS } from './token-codec.js'

export const PUSH_PROVIDER_KINDS = Object.freeze(['apns', 'fcm', 'webpush', 'multi'])

export async function createPushProvider (descriptor, context = {}) {
  // Fail at boot, not at the first wake. A Bare relay configured with a push
  // descriptor cannot sign ES256 and must not come up claiming it can deliver.
  assertNodeCrypto()

  if (!descriptor || typeof descriptor !== 'object') {
    throw new Error('NOTIFY_PUSH_BAD_CONFIG: push descriptor must be an object')
  }
  const kind = descriptor.kind
  if (!PUSH_PROVIDER_KINDS.includes(kind)) {
    throw new Error('NOTIFY_PUSH_UNKNOWN_KIND: expected one of ' + PUSH_PROVIDER_KINDS.join(', ') + ', got ' + String(kind))
  }

  const openToken = descriptor.openToken || createTokenOpener(descriptor.tokenEncoding || 'sealed', context.keyPair || null)
  const shared = { openToken, now: context.now, transport: descriptor.transport, tokenTransport: descriptor.tokenTransport }

  if (kind === 'multi') return buildMulti(descriptor, shared, context)
  return buildOne(kind, descriptor, shared)
}

async function buildOne (kind, descriptor, shared) {
  const opts = { ...shared, credentials: descriptor.credentials || {} }
  if (kind === 'apns') {
    const { createApnsProvider } = await import('./apns.js')
    return createApnsProvider(opts)
  }
  if (kind === 'fcm') {
    const { createFcmProvider } = await import('./fcm.js')
    return createFcmProvider(opts)
  }
  const { createWebPushProvider } = await import('./webpush.js')
  return createWebPushProvider(opts)
}

/**
 * Routes on the binding's declared provider. A relay serving iOS, Android and
 * web devices holds one binding set spanning all three, and `delivery.provider`
 * is the only thing that says which egress a given device needs.
 */
async function buildMulti (descriptor, shared, context) {
  const configured = descriptor.providers || {}
  const kinds = Object.keys(configured).filter(k => configured[k])
  if (kinds.length === 0) {
    throw new Error('NOTIFY_PUSH_BAD_CONFIG: multi provider requires at least one entry in `providers`')
  }
  const routes = new Map()
  for (const kind of kinds) {
    if (!PUSH_PROVIDER_KINDS.includes(kind) || kind === 'multi') {
      throw new Error('NOTIFY_PUSH_UNKNOWN_KIND: `providers` key must be apns, fcm or webpush, got ' + kind)
    }
    const entry = configured[kind]
    const sub = typeof entry.send === 'function'
      ? entry
      : await createPushProvider({ ...entry, kind, tokenEncoding: entry.tokenEncoding || descriptor.tokenEncoding, openToken: shared.openToken }, context)
    routes.set(kind, sub)
  }

  return {
    kind: 'multi',
    live: true,
    routes,

    async send (delivery) {
      const route = routes.get(delivery.provider)
      if (!route) {
        // 'runtime' bindings and any provider this relay was not configured for
        // land here. Rejected, not `token_invalid` — the token is fine, the
        // relay just has no egress for it, and staling the binding would make
        // the device permanently unreachable even after the operator fixes it.
        return {
          status: 'provider_rejected',
          reason: 'provider_not_configured',
          providerStatus: String(delivery.provider || 'unknown')
        }
      }
      return route.send(delivery)
    }
  }
}
