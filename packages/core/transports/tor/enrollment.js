/**
 * Pairing-channel enrollment (`hiverelay.onion.authkey/1` → roster + receipt).
 *
 * The relay half of the restricted-discovery enrollment flow
 * (docs/TOR-ONION-TRANSPORT.md §4): a device that just completed the relay's
 * pairing flow presents its signed enrollment envelope; the relay verifies
 * it against its stable identity, adds the x25519 pubkey to the onion
 * client-auth roster (rebuild-in-place — tor exposes no runtime roster add),
 * persists via rosterFile, and returns the signed acceptance receipt binding
 * key ↔ onion address ↔ expiry.
 *
 * Rejections are unsigned ({ enrolled: false, reason }) — the relay signs
 * acceptances only, so it never acts as a rejection-signing oracle.
 */

import b4a from 'b4a'
import { verifyEnrollment, createReceipt } from './auth-keys.js'

/**
 * Restricted discovery gates descriptor decryption to enrolled clients —
 * rosterFile-backed or seeded with static keys (mirrors the capability
 * doc's auth-mode rule).
 */
export function restrictedDiscoveryActive (torTransport) {
  if (!torTransport) return false
  if (typeof torTransport.isRestrictedDiscoveryActive === 'function') {
    return torTransport.isRestrictedDiscoveryActive()
  }
  return !!(torTransport.rosterFile || (torTransport.clientAuthKeys && torTransport.clientAuthKeys.length > 0))
}

/**
 * Complete an enrollment that rode the pairing channel.
 * Returns { enrolled: true, receipt } or { enrolled: false, reason } —
 * never throws on protocol-level rejections.
 */
export async function completeOnionEnrollment ({ torTransport, relayKeyPair, devicePubkeyHex, envelope, deviceName = 'unknown' }) {
  if (!torTransport || !torTransport.running || !torTransport.onionAddress) {
    return { enrolled: false, reason: 'tor-disabled' }
  }
  if (!restrictedDiscoveryActive(torTransport)) {
    // Open service: every client can already decrypt the descriptor, so
    // there is nothing to enroll into. Clean no-op.
    return { enrolled: false, reason: 'open-discovery' }
  }
  if (!relayKeyPair || !relayKeyPair.publicKey || !relayKeyPair.secretKey) {
    return { enrolled: false, reason: 'no-relay-identity' }
  }

  const relayPubkey = b4a.toString(relayKeyPair.publicKey, 'hex')
  const check = verifyEnrollment(envelope, { expectedRelayPubkey: relayPubkey })
  if (!check.ok) return { enrolled: false, reason: check.reason }

  // The envelope must be signed by the identity that just paired —
  // otherwise any paired device could replay another client's envelope
  // and enroll keys under its name.
  if (String(check.envelope.clientIdentity).toLowerCase() !== String(devicePubkeyHex).toLowerCase()) {
    return { enrolled: false, reason: 'identity-mismatch' }
  }

  // Roster add rebuilds the service in place (same onion address) and
  // persists via rosterFile when configured.
  await torTransport.addAuthClient(check.envelope.onionAuthPubX25519, {
    name: deviceName,
    expiresAtMs: check.envelope.expiresAtMs
  })

  const receipt = createReceipt({
    relayPubkey,
    relaySecretKey: relayKeyPair.secretKey,
    status: 'accepted',
    onionAddress: torTransport.onionAddress,
    endpointKeyId: torTransport.endpointKeyId,
    clientIdentity: check.envelope.clientIdentity,
    onionAuthPubX25519: check.envelope.onionAuthPubX25519,
    enrolledAtMs: Date.now(),
    expiresAtMs: check.envelope.expiresAtMs
  })
  return { enrolled: true, receipt }
}
