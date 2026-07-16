// release-manifest.mjs — the signed release manifest for drive-boot code drives.
//
// This is the trust anchor for the self-updating appliance (docs/DRIVE-BOOT-APPLIANCE.md,
// §4.2). It is the drive-boot analogue of the SSH-signed annotated git tag the fleet
// updater verifies (fleet/updater.sh verify_tag) and a direct port of peerit's web
// release-signing discipline (peerit/js/release-verify.js + scripts/sign-release.mjs),
// adapted for a hyperdrive shipping RUNNABLE app code rather than a static web bundle.
//
// A drive-boot loader must NOT run a byte it hasn't checked against this manifest:
//   1. the manifest is signed by an OFFLINE Ed25519 release key (supplied out-of-band,
//      never in the origin's CI env) — so a compromised *online* seeding key cannot
//      forge a release the loader will execute;
//   2. the signed message covers the integrity-critical fields only — the per-file
//      SHA-256 map (what code runs), the driveKey (which drive), the release version,
//      and the runtime contract (Node major + packages-only flag) the code targets;
//   3. cosmetic fields (builtAt, note) are excluded so the signed message is
//      reproducible from the file set alone.
//
// Verification is fail-closed: any missing/typo'd field, wrong key, bad signature, or
// content-hash mismatch throws. The loader pins the release key (from the image /
// store manifest) and passes it as expectedKey.

import { createHash, createPrivateKey, createPublicKey, sign as edSign, verify as edVerify } from 'node:crypto'

export const RELEASE_ALG = 'Ed25519'
export const RELEASE_MSG_VERSION = 'blindspark-drive-boot-v1'

const HEX64 = /^[0-9a-f]{64}$/i
const HEX128 = /^[0-9a-f]{128}$/i
// DER wrappers to turn a raw 32-byte Ed25519 seed / public key into PKCS8 / SPKI,
// identical to peerit/scripts/sign-release.mjs so the two trust chains stay aligned.
const PKCS8_PREFIX = '302e020100300506032b657004220420'
const SPKI_PREFIX = '302a300506032b6570032100'

export function sha256Hex (buf) {
  return createHash('sha256').update(buf).digest('hex')
}

// Deterministic, key-sorted JSON so signer and loader hash identical bytes.
function stable (v) {
  if (v === null || typeof v !== 'object') return JSON.stringify(v === undefined ? null : v)
  if (Array.isArray(v)) return '[' + v.map(stable).join(',') + ']'
  return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + stable(v[k])).join(',') + '}'
}

// The exact string the offline key signs / the loader verifies.
export function driveReleaseSigningMessage (manifest) {
  const m = manifest || {}
  return RELEASE_MSG_VERSION + '\n' + stable({
    files: m.files || {},
    driveKey: String(m.driveKey || '').toLowerCase(),
    version: String(m.version || ''),
    runtime: m.runtime || {}
  })
}

// Derive the { privateKey, pubHex } from a 32-byte hex seed (matches crypto.js /
// sign-release.mjs: PKCS8-wrapped raw seed → last-32-bytes-of-SPKI public key).
export function pubKeyFromSeedHex (seedHex) {
  const seed = String(seedHex || '').trim().toLowerCase()
  if (!HEX64.test(seed)) throw new Error('drive-boot: release seed must be 32-byte (64 hex)')
  const priv = createPrivateKey({ key: Buffer.from(PKCS8_PREFIX + seed, 'hex'), format: 'der', type: 'pkcs8' })
  const pubHex = createPublicKey(priv).export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex')
  return { priv, pubHex }
}

// Sign a manifest with the offline seed → { alg, key, sig, msgVersion }.
export function signDriveManifest (manifest, seedHex) {
  const { priv, pubHex } = pubKeyFromSeedHex(seedHex)
  const sig = edSign(null, Buffer.from(driveReleaseSigningMessage(manifest), 'utf8'), priv).toString('hex')
  return { alg: RELEASE_ALG, key: pubHex, sig, msgVersion: RELEASE_MSG_VERSION }
}

// Verify a { alg, key, sig } signature over a manifest against a pinned key.
// Throws with a specific reason on any failure; returns { ok:true, key } on success.
export function verifyDriveManifest ({ manifest, signature, expectedKey } = {}) {
  if (!manifest || typeof manifest !== 'object') throw new Error('drive-boot: no manifest')
  const sig = signature || {}
  if (sig.alg !== RELEASE_ALG) throw new Error('drive-boot: unsupported signature algorithm')
  const key = String(sig.key || '').toLowerCase()
  if (!HEX64.test(key)) throw new Error('drive-boot: signing key is not a 32-byte hex Ed25519 key')
  if (expectedKey && key !== String(expectedKey).toLowerCase()) {
    throw new Error('drive-boot: signed by an unexpected key (not the pinned release key)')
  }
  if (!HEX128.test(String(sig.sig || ''))) throw new Error('drive-boot: signature is not 64-byte hex')
  const pub = createPublicKey({ key: Buffer.from(SPKI_PREFIX + key, 'hex'), format: 'der', type: 'spki' })
  const ok = edVerify(null, Buffer.from(driveReleaseSigningMessage(manifest), 'utf8'), pub, Buffer.from(sig.sig, 'hex'))
  if (!ok) throw new Error('drive-boot: signature did not verify against the manifest')
  return { ok: true, key }
}

// Given the drive's ACTUAL reconstructed contents (Map path→Buffer), confirm every
// file the manifest pins matches its sha256. This is the check that turns "the
// signature is valid" into "the code on disk is exactly the code that was signed."
// Throws on the first mismatch/missing file; returns { ok, count }.
export function verifyDriveContents (manifest, actualFiles) {
  const files = (manifest && manifest.files) || {}
  for (const [path, expected] of Object.entries(files)) {
    const buf = actualFiles.get(path)
    if (!buf) throw new Error('drive-boot: manifest file missing from drive: ' + path)
    const got = sha256Hex(buf)
    if (got !== String(expected).toLowerCase()) {
      throw new Error('drive-boot: hash mismatch for ' + path + ' (expected ' + expected + ', got ' + got + ')')
    }
  }
  return { ok: true, count: Object.keys(files).length }
}
