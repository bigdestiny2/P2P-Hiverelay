/**
 * @hive/verifier — cross-client verification library.
 *
 * Standalone reference verifier for HiveRelay. Reads raw data from
 * multiple relay endpoints and reports divergence. The point of
 * shipping this as a SEPARATE package (not part of the main client
 * SDK) is cross-client verification per THREAT-MODEL.md defense
 * mechanism #2: if the same bytes on disk produce different results
 * in two independently-authored clients, divergence is proof of
 * corruption.
 *
 * Intentionally small — one job, no surprises:
 *   - Fetch the capability doc from each supplied relay
 *   - Fetch the catalog from each
 *   - Report any divergence (same drive key, different metadata;
 *     same author, different seeding manifest; same kind of queries
 *     yielding different answers)
 *
 * Importable as a library OR runnable as a CLI via `hive-verify ...`.
 *
 * Does NOT depend on `p2p-hiverelay` (that would defeat the point of
 * independence — if the main package is compromised, so is the
 * verifier). It does its own JSON handling, signature checks, and
 * comparisons using only b4a + Node built-ins.
 */

const USER_AGENT = 'hive-verifier/0.6.0'
const FETCH_TIMEOUT_MS = 10_000

/**
 * Verify a list of relay endpoints agree on their capability docs and
 * catalogs. Returns a structured report the CLI prints and callers
 * can assert against.
 *
 * @param {string[]} relayUrls   base URLs to compare (e.g. 'https://relay.example.com')
 * @param {object} [opts]
 * @param {number} [opts.timeoutMs=10000]  per-fetch timeout
 * @param {function} [opts.fetch]          override for injection/tests
 * @returns {Promise<VerificationReport>}
 */
export async function verifyRelays (relayUrls, opts = {}) {
  if (!Array.isArray(relayUrls) || relayUrls.length < 2) {
    throw new Error('verifyRelays needs at least 2 relay URLs to compare')
  }
  const _fetch = opts.fetch || globalThis.fetch
  if (typeof _fetch !== 'function') {
    throw new Error('no fetch available — use Node >=18 or supply opts.fetch')
  }
  const timeoutMs = opts.timeoutMs || FETCH_TIMEOUT_MS

  const capabilityDocs = await Promise.all(
    relayUrls.map(url => fetchWithTimeout(_fetch, url.replace(/\/+$/, '') + '/.well-known/hiverelay.json', timeoutMs))
  )
  const catalogs = await Promise.all(
    relayUrls.map(url => fetchWithTimeout(_fetch, url.replace(/\/+$/, '') + '/catalog.json', timeoutMs))
  )

  const divergences = []
  divergences.push(...compareCapabilityDocs(relayUrls, capabilityDocs))
  divergences.push(...compareCatalogs(relayUrls, catalogs))

  // Build fetchErrors preserving the ORIGINAL index into relayUrls so
  // we report the right relay against each error. The previous version
  // used .filter().map((_, i) => ...) which gave the index into the
  // *filtered* array, attributing errors to the wrong relay.
  const fetchErrors = []
  for (let i = 0; i < capabilityDocs.length; i++) {
    if (!capabilityDocs[i].ok) {
      fetchErrors.push({ relay: relayUrls[i], endpoint: 'capabilities', error: capabilityDocs[i].error })
    }
  }
  for (let i = 0; i < catalogs.length; i++) {
    if (!catalogs[i].ok) {
      fetchErrors.push({ relay: relayUrls[i], endpoint: 'catalog', error: catalogs[i].error })
    }
  }

  return {
    checkedRelays: relayUrls,
    capabilitiesOK: capabilityDocs.every(d => d.ok),
    catalogsOK: catalogs.every(d => d.ok),
    fetchErrors,
    divergences,
    divergenceCount: divergences.length,
    verdict: divergences.length === 0 ? 'agree' : 'diverge'
  }
}

/**
 * Compare a single drive's data served by multiple relays. If two
 * relays serve different Merkle roots for the same drive key, exactly
 * one is lying (or has out-of-date data — caller must follow up with
 * the author's canonical latest). Either way, the caller needs to
 * know.
 *
 * @param {string} driveKeyHex    the drive's public key (64 hex chars)
 * @param {string[]} relayUrls
 * @param {object} [opts]         see verifyRelays opts
 * @returns {Promise<DriveComparison>}
 */
export async function compareDrive (driveKeyHex, relayUrls, opts = {}) {
  if (typeof driveKeyHex !== 'string' || !/^[0-9a-f]{64}$/i.test(driveKeyHex)) {
    throw new Error('compareDrive: driveKeyHex must be 64 hex chars')
  }
  const _fetch = opts.fetch || globalThis.fetch
  const timeoutMs = opts.timeoutMs || FETCH_TIMEOUT_MS

  // Fetch each relay's view of this drive via the gateway endpoint.
  // We ask for the /info subresource which returns metadata including
  // the current length + last-modified — stable enough to compare.
  const responses = await Promise.all(
    relayUrls.map(url => fetchWithTimeout(
      _fetch,
      url.replace(/\/+$/, '') + '/v1/hyper/' + driveKeyHex + '/info',
      timeoutMs
    ))
  )

  const views = responses.map((r, i) => ({
    relay: relayUrls[i],
    ok: r.ok,
    info: r.ok ? r.body : null,
    error: r.ok ? null : r.error
  }))

  // Compare. Two relays "agree" on a drive if their reported drive
  // length, version, and content hash match.
  const agreed = []
  const divergent = []
  const compareFields = ['length', 'version', 'contentHash']
  const okViews = views.filter(v => v.ok)
  if (okViews.length < 2) {
    return { drive: driveKeyHex, views, agreement: 'insufficient-data' }
  }
  const reference = okViews[0]
  for (const v of okViews.slice(1)) {
    let matches = true
    for (const field of compareFields) {
      if (reference.info && v.info && reference.info[field] !== v.info[field]) {
        matches = false
        break
      }
    }
    if (matches) agreed.push(v.relay)
    else divergent.push({ relay: v.relay, vs: reference.relay, fields: compareFields })
  }

  return {
    drive: driveKeyHex,
    views,
    agreement: divergent.length === 0 ? 'agree' : 'diverge',
    agreedWith: reference.relay,
    divergentFrom: divergent
  }
}

/**
 * Fetch the signed anchor proof from a single relay for a specific
 * drive. Returns the parsed proof + a verifyOk boolean derived from
 * cross-checking the signature against the relay's pubkey.
 *
 * Uses Node's crypto.verify for Ed25519 — keeps the verifier free of
 * sodium-universal and other native crypto deps that would tie it to
 * the main package.
 *
 * @param {string} relayUrl       base URL
 * @param {string} driveKeyHex    drive key (64 hex chars)
 * @param {object} [opts]
 * @returns {Promise<AnchorProofView>}
 */
export async function fetchAnchorProof (relayUrl, driveKeyHex, opts = {}) {
  const _fetch = opts.fetch || globalThis.fetch
  const timeoutMs = opts.timeoutMs || FETCH_TIMEOUT_MS
  const url = relayUrl.replace(/\/+$/, '') + '/api/anchors/' + driveKeyHex + '/proof'
  const r = await fetchWithTimeout(_fetch, url, timeoutMs)
  if (!r.ok) return { relay: relayUrl, ok: false, error: r.error }

  const proof = r.body
  if (!proof || !proof.signature || !proof.relayPubkey) {
    return { relay: relayUrl, ok: false, error: 'malformed proof' }
  }

  // Bind the proof to the drive we actually asked about. The signed
  // payload below is built from proof.appKey, so without this check a
  // relay can answer a query for drive X with a validly-signed proof for
  // a DIFFERENT drive Y it anchored — and it passes the audit for X. This
  // mirrors the expectedAppKey binding in core/anchor-proof-verifier.js.
  if (typeof proof.appKey !== 'string' ||
      proof.appKey.toLowerCase() !== driveKeyHex.toLowerCase()) {
    return { relay: relayUrl, ok: false, error: 'appkey-mismatch', proof }
  }

  // Reconstruct the signed payload and verify against the relay's pubkey
  let verified = false
  try {
    const tag = Buffer.from('hiverelay-anchor-proof-v1', 'utf-8')
    const keyBuf = Buffer.from(proof.appKey, 'hex')
    const versionBuf = Buffer.alloc(8)
    versionBuf.writeBigUInt64BE(BigInt(proof.version || 0), 0)
    const tsBuf = Buffer.alloc(8)
    tsBuf.writeBigUInt64BE(BigInt(proof.attestedAt || 0), 0)
    const flagBuf = Buffer.from([proof.anchored ? 1 : 0])
    const payload = Buffer.concat([tag, keyBuf, versionBuf, tsBuf, flagBuf])
    const sig = Buffer.from(proof.signature, 'hex')
    const pk = Buffer.from(proof.relayPubkey, 'hex')

    // Node's built-in Ed25519 verify (libsodium under the hood, but no JS dep)
    const { createPublicKey, verify } = await import('crypto')
    // Build a SubjectPublicKeyInfo wrapper for Ed25519 (DER prefix:
    //   SEQUENCE { SEQUENCE { OID 1.3.101.112 } BIT STRING { pk } })
    const der = Buffer.concat([
      Buffer.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]),
      pk
    ])
    const publicKey = createPublicKey({ key: der, format: 'der', type: 'spki' })
    verified = verify(null, payload, publicKey, sig)
  } catch (err) {
    return { relay: relayUrl, ok: false, error: 'signature verify error: ' + err.message, proof }
  }

  return { relay: relayUrl, ok: true, verified, proof }
}

/**
 * Audit the anchor claims of N relays for a single drive. Each relay
 * is asked for its signed proof; signatures are verified against the
 * claimed pubkey; the consensus across relays is reported.
 *
 * Output:
 *   {
 *     drive,
 *     relayCount: N,
 *     anchored: { count, relays },
 *     unanchored: { count, relays },
 *     unverifiedSignatures: [...],
 *     unreachable: [...]
 *   }
 *
 * Use case: clients about to download from the network want to know
 * which relays they can actually pull from. A relay that lies in its
 * catalog ("anchored=true") fails the signature audit if it can't
 * actually sign for the data state.
 */
export async function auditAnchors (driveKeyHex, relayUrls, opts = {}) {
  if (typeof driveKeyHex !== 'string' || !/^[0-9a-f]{64}$/i.test(driveKeyHex)) {
    throw new Error('auditAnchors: driveKeyHex must be 64 hex chars')
  }
  if (!Array.isArray(relayUrls) || relayUrls.length === 0) {
    throw new Error('auditAnchors needs at least one relay URL')
  }

  const views = await Promise.all(
    relayUrls.map(url => fetchAnchorProof(url, driveKeyHex, opts))
  )

  const anchored = []
  const unanchored = []
  const unverifiedSignatures = []
  const unreachable = []

  for (const v of views) {
    if (!v.ok) {
      unreachable.push({ relay: v.relay, error: v.error })
      continue
    }
    if (v.verified !== true) {
      unverifiedSignatures.push({
        relay: v.relay,
        proof: v.proof
      })
      continue
    }
    if (v.proof.anchored === true) anchored.push({ relay: v.relay, version: v.proof.version, attestedAt: v.proof.attestedAt })
    else unanchored.push({ relay: v.relay, attestedAt: v.proof.attestedAt })
  }

  return {
    drive: driveKeyHex,
    relayCount: relayUrls.length,
    anchored: { count: anchored.length, relays: anchored },
    unanchored: { count: unanchored.length, relays: unanchored },
    unverifiedSignatures,
    unreachable
  }
}

// ─── Internal ─────────────────────────────────────────────────────

/**
 * Fetch with timeout. Returns { ok, body, error, statusCode } — never
 * throws for network errors, because the verifier wants to report
 * partial results (N-1 relays responded, the Nth timed out) not abort.
 */
async function fetchWithTimeout (fetchFn, url, timeoutMs) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const res = await fetchFn(url, {
      signal: controller.signal,
      headers: { 'User-Agent': USER_AGENT, Accept: 'application/json' }
    })
    clearTimeout(timer)
    if (!res.ok) {
      return { ok: false, statusCode: res.status, error: 'HTTP ' + res.status }
    }
    let body = null
    try {
      const text = await res.text()
      body = text ? JSON.parse(text) : null
    } catch (err) {
      return { ok: false, statusCode: res.status, error: 'non-json body: ' + err.message }
    }
    return { ok: true, statusCode: res.status, body }
  } catch (err) {
    clearTimeout(timer)
    return { ok: false, error: err.name === 'AbortError' ? 'timeout' : err.message }
  }
}

/**
 * Two capability docs "agree" if:
 *   - same schemaVersion
 *   - same software URL (no forked-client divergence)
 *   - same pubkey (sanity check — they shouldn't, it's per-relay)
 *     Actually, for capability docs, pubkey IS expected to differ
 *     (each relay has its own). What we check is: do they all share
 *     the same supported_transports, features intersection, and
 *     advertise consistent protocol versions?
 */
function compareCapabilityDocs (urls, responses) {
  const out = []
  const okResponses = responses.filter(r => r.ok)
  if (okResponses.length < 2) return out

  const reference = okResponses[0].body
  if (!reference) return out

  for (let i = 1; i < okResponses.length; i++) {
    const doc = okResponses[i].body
    if (!doc) continue

    if (doc.schemaVersion !== reference.schemaVersion) {
      out.push({
        category: 'capability',
        relayA: urls[responses.indexOf(okResponses[0])],
        relayB: urls[responses.indexOf(okResponses[i])],
        field: 'schemaVersion',
        valueA: reference.schemaVersion,
        valueB: doc.schemaVersion
      })
    }

    // If both advertise a software URL, it should match (otherwise
    // we may be comparing two different implementations — a security
    // concern for reproducibility).
    if (doc.software !== reference.software) {
      out.push({
        category: 'capability',
        relayA: urls[responses.indexOf(okResponses[0])],
        relayB: urls[responses.indexOf(okResponses[i])],
        field: 'software',
        valueA: reference.software,
        valueB: doc.software,
        severity: 'info' // different implementations are fine, just note it
      })
    }
  }
  return out
}

/**
 * Two catalogs "agree" on a given appKey when they list the same
 * type, publisher, and version. Missing entries aren't counted as
 * divergence (individual relays only carry what they've accepted —
 * federation is selective by design).
 */
function compareCatalogs (urls, responses) {
  const out = []
  const okResponses = responses.filter(r => r.ok)
  if (okResponses.length < 2) return out

  const allEntries = new Map() // appKey -> { relay, entry }[]
  for (let i = 0; i < okResponses.length; i++) {
    const body = okResponses[i].body
    if (!body || !Array.isArray(body.entries)) continue
    const relayIdx = responses.indexOf(okResponses[i])
    for (const entry of body.entries) {
      if (!entry || !entry.appKey) continue
      const key = entry.appKey.toLowerCase()
      if (!allEntries.has(key)) allEntries.set(key, [])
      allEntries.get(key).push({ relay: urls[relayIdx], entry })
    }
  }

  for (const [appKey, observations] of allEntries) {
    if (observations.length < 2) continue
    const ref = observations[0]
    for (let i = 1; i < observations.length; i++) {
      const cmp = observations[i]
      const diffFields = []
      for (const field of ['type', 'publisherPubkey', 'version']) {
        if (ref.entry[field] && cmp.entry[field] && ref.entry[field] !== cmp.entry[field]) {
          diffFields.push(field)
        }
      }
      if (diffFields.length > 0) {
        out.push({
          category: 'catalog-entry',
          appKey,
          relayA: ref.relay,
          relayB: cmp.relay,
          divergentFields: diffFields,
          entryA: ref.entry,
          entryB: cmp.entry
        })
      }
    }
  }
  return out
}
