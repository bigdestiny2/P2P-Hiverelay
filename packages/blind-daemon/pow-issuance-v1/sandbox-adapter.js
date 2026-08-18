// pow-issuance-v1 sandbox admission adapter — self-contained synchronous script
// for the production admission adapter contract (production-entrypoint.js).
// Combined resolver: schemeId 9 = deploy-side publisher pass-through (verbatim,
// unchanged from the live adapter.js) + schemeId 1 = pow-issuance-v1 verifier.
//
// The fleet issuer key is injected at build time by build-sandbox-adapter.mjs
// into POW_ISSUER_KEY_HEX; the built artifact is pinned by sha256 in blind.env.
// Keep this file free of the contract's forbidden identifiers and fully
// synchronous; the unit tests pin byte-parity with token-codec.js.
({
  schema: 'hiverelay-admission-adapter-script-v1',
  createAdmissionAdapterResolver: function createAdmissionAdapterResolver (context) {
    'use strict'
    var POW_ISSUER_KEY_HEX = '__POW_ISSUER_KEY_HEX__'
    var SCHEME_ID_POW = 1
    var SCHEME_ID_PUBLISHER = 9
    var SCHEME_VERSION = 1
    var WIRE_VERSION = 1
    var MAX_ALLOWANCE = 8
    var TOKEN_PAYLOAD_BYTES = 71
    var TOKEN_BYTES = 103
    var WAL_RECORD_BYTES = 95
    var SIX_HOURS_MILLIS = 21600000

    function fail (message) {
      var error = new Error(message)
      error.code = 'SPEND_INVALID'
      throw error
    }

    function strToU8 (text) {
      var out = new Uint8Array(text.length)
      for (var i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff
      return out
    }

    var TOKEN_KEY_INFO = strToU8('hiverelay/pow-issuance-v1/key/token')
    var RECORD_BINDING_DOMAIN = strToU8('hiverelay/pow-issuance-v1/record-binding')
    var SPEND_TAG_DOMAIN = strToU8('hiverelay/pow-issuance-v1/spend-tag')

    var HEX_DIGITS = '0123456789abcdef'
    function u8ToHex (bytes) {
      var out = ''
      for (var i = 0; i < bytes.length; i++) {
        out += HEX_DIGITS.charAt(bytes[i] >> 4) + HEX_DIGITS.charAt(bytes[i] & 15)
      }
      return out
    }
    function hexToU8 (hex, length) {
      if (typeof hex !== 'string' || hex.length !== length * 2) fail('hex input has an unexpected length')
      var out = new Uint8Array(length)
      for (var i = 0; i < length; i++) {
        var hi = HEX_DIGITS.indexOf(hex.charAt(i * 2))
        var lo = HEX_DIGITS.indexOf(hex.charAt(i * 2 + 1))
        if (hi < 0 || lo < 0) fail('hex input is not lowercase hex')
        out[i] = (hi << 4) | lo
      }
      return out
    }
    function concatU8 (parts) {
      var total = 0
      for (var i = 0; i < parts.length; i++) total += parts[i].length
      var out = new Uint8Array(total)
      var offset = 0
      for (i = 0; i < parts.length; i++) {
        out.set(parts[i], offset)
        offset += parts[i].length
      }
      return out
    }
    function sameU8 (left, right) {
      if (!left || !right || left.length !== right.length) return false
      var diff = 0
      for (var i = 0; i < left.length; i++) diff |= left[i] ^ right[i]
      return diff === 0
    }

    var SHA256_K = new Uint32Array([
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ])
    function rotr (x, n) { return (x >>> n) | (x << (32 - n)) }
    function sha256 (message) {
      var paddedLength = (((message.length + 8) >> 6) + 1) << 6
      var padded = new Uint8Array(paddedLength)
      padded.set(message)
      padded[message.length] = 0x80
      var view = new DataView(padded.buffer)
      view.setUint32(paddedLength - 8, Math.floor((message.length * 8) / 0x100000000))
      view.setUint32(paddedLength - 4, (message.length * 8) >>> 0)
      var h0 = 0x6a09e667; var h1 = 0xbb67ae85; var h2 = 0x3c6ef372; var h3 = 0xa54ff53a
      var h4 = 0x510e527f; var h5 = 0x9b05688c; var h6 = 0x1f83d9ab; var h7 = 0x5be0cd19
      var w = new Uint32Array(64)
      for (var block = 0; block < paddedLength; block += 64) {
        for (var t = 0; t < 16; t++) w[t] = view.getUint32(block + t * 4)
        for (t = 16; t < 64; t++) {
          var s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3)
          var s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10)
          w[t] = (w[t - 16] + s0 + w[t - 7] + s1) | 0
        }
        var a = h0; var b = h1; var c = h2; var d = h3
        var e = h4; var f = h5; var g = h6; var h = h7
        for (t = 0; t < 64; t++) {
          var s1Big = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
          var ch = (e & f) ^ (~e & g)
          var temp1 = (h + s1Big + ch + SHA256_K[t] + w[t]) | 0
          var s0Big = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
          var maj = (a & b) ^ (a & c) ^ (b & c)
          var temp2 = (s0Big + maj) | 0
          h = g; g = f; f = e; e = (d + temp1) | 0
          d = c; c = b; b = a; a = (temp1 + temp2) | 0
        }
        h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0
        h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + h) | 0
      }
      var out = new Uint8Array(32)
      var outView = new DataView(out.buffer)
      outView.setUint32(0, h0); outView.setUint32(4, h1); outView.setUint32(8, h2); outView.setUint32(12, h3)
      outView.setUint32(16, h4); outView.setUint32(20, h5); outView.setUint32(24, h6); outView.setUint32(28, h7)
      return out
    }
    function hmacSha256 (key, data) {
      var k = key
      if (k.length > 64) k = sha256(k)
      var inner = new Uint8Array(64 + data.length)
      var outer = new Uint8Array(64 + 32)
      for (var i = 0; i < 64; i++) {
        var byte = i < k.length ? k[i] : 0
        inner[i] = byte ^ 0x36
        outer[i] = byte ^ 0x5c
      }
      inner.set(data, 64)
      outer.set(sha256(inner), 64)
      return sha256(outer)
    }

    function parseIssuerKey (hex) {
      if (typeof hex !== 'string' || !/^[0-9a-f]{64}$/.test(hex)) {
        throw new Error('pow-issuance-v1 issuer key is not one exact 32-byte lowercase hex value')
      }
      return hexToU8(hex, 32)
    }
    var ISSUER_KEY = parseIssuerKey(POW_ISSUER_KEY_HEX)
    var TOKEN_KEY = hmacSha256(ISSUER_KEY, TOKEN_KEY_INFO)
    ISSUER_KEY.fill(0)

    function taggedBytes (bytes) {
      var tagged = {}
      tagged.$hiverelayType = 'bytes'
      tagged.hex = u8ToHex(bytes)
      return Object.freeze(tagged)
    }
    function bytesOf (tagged, field, length) {
      if (!tagged || typeof tagged !== 'object' || tagged.$hiverelayType !== 'bytes' ||
          typeof tagged.hex !== 'string') {
        fail(field + ' must be bridge bytes')
      }
      return hexToU8(tagged.hex, length == null ? tagged.hex.length / 2 : length)
    }
    function u64StringOf (tagged, field) {
      if (!tagged || typeof tagged !== 'object' || tagged.$hiverelayType !== 'u64' ||
          typeof tagged.value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(tagged.value)) {
        fail(field + ' must be a bridge u64')
      }
      return tagged.value
    }
    function epochNow () {
      return Math.floor(Date.now() / SIX_HOURS_MILLIS)
    }

    function parseToken (token) {
      if (token.length !== TOKEN_BYTES) fail('pow-issuance-v1 token is malformed')
      var payload = token.subarray(0, TOKEN_PAYLOAD_BYTES)
      var signature = token.subarray(TOKEN_PAYLOAD_BYTES)
      if (!sameU8(signature, hmacSha256(TOKEN_KEY, payload))) {
        fail('pow-issuance-v1 token signature is invalid')
      }
      if (payload[0] !== WIRE_VERSION || payload[1] !== SCHEME_VERSION) {
        fail('pow-issuance-v1 token version is unsupported')
      }
      var allowance = payload[66]
      if (allowance < 1 || allowance > MAX_ALLOWANCE) {
        fail('pow-issuance-v1 token allowance is outside 1..8')
      }
      var view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength)
      return {
        challengeId: payload.slice(2, 34),
        recordCommitment: payload.slice(34, 66),
        allowance: allowance,
        expiryEpoch: view.getUint32(67)
      }
    }

    function recordBindingRoot (commitments) {
      var parts = [new Uint8Array([commitments.length])]
      for (var i = 0; i < commitments.length; i++) parts.push(commitments[i])
      return hmacSha256(RECORD_BINDING_DOMAIN, concatU8(parts))
    }

    function spendTagFor (token, spendIndex) {
      return hmacSha256(SPEND_TAG_DOMAIN, concatU8([token, new Uint8Array([spendIndex])]))
    }

    function walCommitRecord (input, fields, spendIndex) {
      var record = new Uint8Array(WAL_RECORD_BYTES)
      var view = new DataView(record.buffer)
      record[0] = 1
      view.setUint16(1, input.admission.profileId)
      view.setUint16(3, input.admission.schemeId)
      record[5] = spendIndex
      record[6] = fields.allowance
      view.setUint32(7, fields.expiryEpoch)
      record.set(fields.challengeId, 11)
      record.set(bytesOf(input.requestCommitment, 'requestCommitment', 32), 43)
      record[75] = input.familyId
      record[76] = input.operationId
      record[77] = input.costClass.resourceClass
      record[78] = input.costClass.leaseClass
      view.setBigUint64(79, BigInt(u64StringOf(input.costClass.costUnits, 'costUnits')))
      var descriptorSequence = input.descriptorSequence == null
        ? '0'
        : u64StringOf(input.descriptorSequence, 'descriptorSequence')
      view.setBigUint64(87, BigInt(descriptorSequence))
      return record
    }

    function verifyPowInput (input) {
      if (!input || typeof input !== 'object' || !input.admission) {
        fail('pow-issuance-v1 admission input is required')
      }
      if (input.admission.schemeId !== SCHEME_ID_POW) {
        fail('pow-issuance-v1 adapter received a foreign schemeId')
      }
      var presentation = bytesOf(input.admission.token, 'admission token')
      if (presentation.length < TOKEN_BYTES + 1 ||
          (presentation.length - TOKEN_BYTES - 1) % 32 !== 0) {
        fail('pow-issuance-v1 presentation is malformed')
      }
      var token = presentation.slice(0, TOKEN_BYTES)
      var spendIndex = presentation[TOKEN_BYTES]
      var siblingCount = (presentation.length - TOKEN_BYTES - 1) / 32
      var fields = parseToken(token)
      if (spendIndex >= fields.allowance || siblingCount !== fields.allowance - 1) {
        fail('pow-issuance-v1 presentation does not match its signed allowance')
      }
      var epoch = epochNow()
      if (epoch >= fields.expiryEpoch) {
        fail('pow-issuance-v1 token is expired')
      }
      var commitments = []
      var siblingAt = TOKEN_BYTES + 1
      for (var index = 0; index < fields.allowance; index++) {
        if (index === spendIndex) {
          commitments.push(bytesOf(input.requestCommitment, 'requestCommitment', 32))
        } else {
          commitments.push(presentation.slice(siblingAt, siblingAt + 32))
          siblingAt += 32
        }
      }
      if (!sameU8(recordBindingRoot(commitments), fields.recordCommitment)) {
        fail('pow-issuance-v1 token is not bound to this request commitment')
      }
      return { token: token, spendIndex: spendIndex, fields: fields }
    }

    function powProof (input) {
      var verified = verifyPowInput(input)
      return {
        spendTag: taggedBytes(spendTagFor(verified.token, verified.spendIndex)),
        requestCommitment: input.requestCommitment,
        costClass: Object.freeze({
          resourceClass: input.costClass.resourceClass,
          leaseClass: input.costClass.leaseClass,
          costUnits: input.costClass.costUnits
        }),
        walCommitRecord: taggedBytes(walCommitRecord(input, verified.fields, verified.spendIndex)),
        profileId: input.admission.profileId,
        schemeId: input.admission.schemeId,
        parameterHash: input.admission.parameterHash
      }
    }

    var powAdapter = Object.freeze({
      prepare: function prepare (input) { return powProof(input) },
      preparePreflight: function preparePreflight (input) {
        verifyPowInput(input)
        return Object.freeze({})
      },
      confirmAfterEof: function confirmAfterEof (input) { return powProof(input) }
    })

    // Deploy-side publisher scheme (schemeId 9), verbatim from the live adapter.js:
    // structural pass-through; the coordinator enforces profile currency, exact
    // cost tuple, and storage-owned one-use. Unchanged behavior.
    function publisherPrepared (input) {
      return {
        spendTag: input.admission.token,
        requestCommitment: input.requestCommitment,
        costClass: input.costClass,
        walCommitRecord: input.admission.token,
        profileId: input.admission.profileId,
        schemeId: input.admission.schemeId,
        parameterHash: input.admission.parameterHash
      }
    }

    return function resolveAdmissionAdapter (input) {
      if (!input || typeof input !== 'object') return null
      if (input.schemeId === SCHEME_ID_PUBLISHER) {
        return Object.freeze({
          prepare: publisherPrepared,
          preparePreflight: function preparePreflight () { return Object.freeze({}) },
          confirmAfterEof: publisherPrepared
        })
      }
      if (input.schemeId === SCHEME_ID_POW) return powAdapter
      return null
    }
  }
})
