#!/usr/bin/env node
import fs from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import { gzipSync } from 'node:zlib'
import { fileURLToPath, pathToFileURL } from 'node:url'
import b4a from 'b4a'
import { build } from 'esbuild'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'blind-client-browser-'))
const output = path.join(directory, 'bundle.mjs')
const controlOutput = path.join(directory, 'control.mjs')

try {
  const built = await build({
    stdin: {
      contents: "export * from './packages/blind-client/index.js'\nexport * from './packages/blind-client/runtime/browser.js'\nexport { default as __browserSodiumForTest } from './packages/blind-client/crypto-browser.js'\n",
      resolveDir: root,
      sourcefile: 'blind-client-browser-entry.mjs',
      loader: 'js'
    },
    bundle: true,
    platform: 'browser',
    format: 'esm',
    minify: true,
    metafile: true,
    outfile: output,
    logLevel: 'silent'
  })
  const forbidden = Object.keys(built.metafile.inputs).filter(input =>
    input.includes('sodium-native') || input.includes('bare-crypto') ||
    input.includes('node:crypto') || input.endsWith('.node'))
  if (forbidden.length > 0) throw new Error(`browser bundle contains native/runtime-only inputs: ${forbidden.join(', ')}`)
  const serverOnlyProtocolInputs = Object.keys(built.metafile.inputs).filter(input =>
    input.endsWith('packages/blind-protocol/index.js') ||
    input.endsWith('packages/blind-protocol/evidence-schemas.js') ||
    input.endsWith('packages/blind-protocol/durability-schemas.js') ||
    input.endsWith('packages/blind-protocol/client-internal-schemas.js') ||
    input.endsWith('packages/blind-protocol/client-composition-authority.js') ||
    input.endsWith('packages/blind-protocol/client-composition-runtime-vectors.js') ||
    input.endsWith('packages/blind-protocol/extended-schema-metadata.js') ||
    input.endsWith('packages/blind-protocol/master-schema-inventory.js') ||
    input.endsWith('packages/blind-protocol/registry.js') ||
    input.endsWith('packages/blind-protocol/schema-codecs.js') ||
    input.endsWith('packages/blind-protocol/schema-meta.js') ||
    input.endsWith('packages/blind-protocol/abi-registry.js'))
  if (serverOnlyProtocolInputs.length > 0) {
    throw new Error(`browser bundle contains server/evidence protocol inputs: ${serverOnlyProtocolInputs.join(', ')}`)
  }
  if (!Object.keys(built.metafile.inputs).some(input => input.includes('sodium-javascript'))) {
    throw new Error('browser bundle did not resolve sodium-universal to sodium-javascript')
  }
  const unusedSodiumInputs = Object.keys(built.metafile.inputs).filter(input =>
    input.endsWith('node_modules/sodium-javascript/index.js') ||
    /node_modules\/sodium-javascript\/crypto_(?:aead|auth|box|hash_sha256|kdf|kx|onetimeauth|secretbox|secretstream|shorthash|stream(?:_chacha20)?)\.js$/.test(input) ||
    /node_modules\/(?:chacha20-universal|sha256-universal|sha256-wasm|siphash24|xsalsa20)\//.test(input))
  if (unusedSodiumInputs.length > 0) {
    throw new Error(`browser bundle contains unused sodium algorithm inputs: ${unusedSodiumInputs.join(', ')}`)
  }

  const bundleBytes = await fs.readFile(output)
  const gzipBytes = gzipSync(bundleBytes).byteLength
  if (bundleBytes.byteLength > 300 * 1024 || gzipBytes > 80 * 1024) {
    throw new Error(`blind-client browser bundle exceeds its draft budget (${bundleBytes.byteLength} raw, ${gzipBytes} gzip)`)
  }

  const client = await import(`${pathToFileURL(output).href}?test=${Date.now()}`)
  const sodium = client.__browserSodiumForTest
  const expectedSodiumMethods = [
    'crypto_generichash',
    'crypto_sign_detached',
    'crypto_sign_seed_keypair',
    'crypto_sign_verify_detached',
    'randombytes_buf'
  ]
  if (Object.keys(sodium).sort().join(',') !== expectedSodiumMethods.join(',')) {
    throw new Error('browser sodium facade is not closed over its five required primitives')
  }
  const cryptoMessage = b4a.from('HIVERELAY_BROWSER_CRYPTO_FACADE_V1')
  const cryptoHash = b4a.alloc(32)
  sodium.crypto_generichash(cryptoHash, cryptoMessage)
  if (b4a.toString(cryptoHash, 'hex') !== '33de3b524927256cb40acca4cc13e34824a4a785e3c43d2325364ec917563991') {
    throw new Error('browser sodium facade changed the frozen BLAKE2b-256 vector')
  }
  const cryptoPublicKey = b4a.alloc(32)
  const cryptoSecretKey = b4a.alloc(64)
  const cryptoSignature = b4a.alloc(64)
  sodium.crypto_sign_seed_keypair(cryptoPublicKey, cryptoSecretKey, b4a.alloc(32, 0x42))
  sodium.crypto_sign_detached(cryptoSignature, cryptoMessage, cryptoSecretKey)
  if (b4a.toString(cryptoPublicKey, 'hex') !== '2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12' ||
      b4a.toString(cryptoSignature, 'hex') !== 'df7a0da34e3abd3d459938940688eff60e7b870049ff5f8c3b16e3eab6b6c329ebe9f319b882e20e2e903f20a47bc4462eb7ab712b2020f6d86b65c2131e3201' ||
      !sodium.crypto_sign_verify_detached(cryptoSignature, cryptoMessage, cryptoPublicKey)) {
    throw new Error('browser sodium facade changed the frozen Ed25519 vector')
  }
  const randomProbe = b4a.alloc(32)
  sodium.randombytes_buf(randomProbe)
  if (randomProbe.every(byte => byte === 0)) throw new Error('browser sodium facade RNG did not fill its output')
  const runtime = client.createBrowserCryptoRuntime(globalThis.crypto)
  const sentinel = b4a.from('BROWSER_BUNDLE_PRIVATE_SENTINEL_f8e1762c')
  const relayPublicKey = b4a.alloc(32, 0x31)
  const created = await client.createCellReplica({
    runtime,
    relayPublicKey,
    allocationEpoch: 300,
    sizeClass: 1,
    leaseClass: 1,
    structuredContent: sentinel,
    admission: {
      profileId: 1,
      schemeId: 1,
      parameterHash: b4a.alloc(32, 0x32),
      token: b4a.from([0x33])
    }
  })
  const opened = await client.openCell({ runtime, ...created.readCap, cellBlob: created.request.cellBlob })
  if (!b4a.equals(opened, sentinel)) throw new Error('browser bundle cell round-trip mismatch')
  if (b4a.toString(created.requestBytes, 'hex').includes(b4a.toString(sentinel, 'hex'))) {
    throw new Error('browser bundle leaked application sentinel into relay request bytes')
  }
  const inbox = await client.createInboxReplica({
    runtime,
    relayPublicKey,
    allocationEpoch: 301,
    frameClassBits: 1,
    retentionClass: 1,
    leaseClass: 1,
    admission: {
      profileId: 1,
      schemeId: 1,
      parameterHash: b4a.alloc(32, 0x34),
      token: b4a.from([0x35])
    }
  })
  const appended = await client.createAppendInboxRequest({
    runtime,
    writeCap: inbox.writeCap,
    frameClass: 1,
    frame: runtime.randomBytes(4096),
    admission: {
      profileId: 1,
      schemeId: 1,
      parameterHash: b4a.alloc(32, 0x36),
      token: b4a.from([0x37])
    }
  })
  if (appended.request.frame.byteLength !== 4096 || appended.request.appendSignature.byteLength !== 64) {
    throw new Error('browser bundle signed-inbox composition mismatch')
  }
  const coreMirror = await client.createCoreMirrorRequest({
    runtime,
    relayPublicKey,
    corePublicKey: b4a.alloc(32, 0x38),
    fork: 0n,
    length: 1n,
    signedHeadHash: b4a.alloc(32, 0x39),
    leaseClass: 1,
    admission: {
      profileId: 1,
      schemeId: 1,
      parameterHash: b4a.alloc(32, 0x3a),
      token: b4a.from([0x3b])
    }
  })
  const forwardOpen = await client.createForwardOpenRequest({
    runtime,
    previousRelayKey: relayPublicKey,
    routeId: b4a.alloc(16, 0x3c),
    nextDescriptorSequence: 1n,
    nextDescriptorHash: b4a.alloc(32, 0x3d),
    requestedWireClass: 1,
    circuitClass: 1,
    innerHandshake: b4a.alloc(32, 0x3e),
    expectedInnerHandshakeBytes: 32,
    admission: {
      profileId: 1,
      schemeId: 1,
      parameterHash: b4a.alloc(32, 0x3f),
      token: b4a.from([0x40])
    }
  })
  const circuit = new client.ForwardClientCircuit({
    streamId: 1n,
    circuitNonce: forwardOpen.circuitNonce,
    grantedWireClass: 1,
    circuitClass: 1
  })
  const forwardFrame = circuit.encodeData(b4a.alloc(64, 0x41))
  if (coreMirror.requestBytes.byteLength === 0 || forwardFrame.byteLength === 0) {
    throw new Error('browser bundle Core/Forward composition mismatch')
  }
  const controlBuilt = await build({
    entryPoints: [path.join(root, 'packages/blind-client/control.js')],
    bundle: true,
    platform: 'browser',
    format: 'esm',
    minify: true,
    metafile: true,
    outfile: controlOutput,
    logLevel: 'silent'
  })
  const controlForbidden = Object.keys(controlBuilt.metafile.inputs).filter(input =>
    input.includes('sodium-native') || input.includes('bare-crypto') ||
    input.includes('node:crypto') || input.endsWith('.node') ||
    input.endsWith('packages/blind-protocol/index.js') ||
    input.endsWith('packages/blind-protocol/evidence-schemas.js') ||
    input.endsWith('packages/blind-protocol/durability-schemas.js') ||
    input.endsWith('packages/blind-protocol/client-internal-schemas.js') ||
    input.endsWith('packages/blind-protocol/client-composition-authority.js') ||
    input.endsWith('packages/blind-protocol/client-composition-runtime-vectors.js') ||
    input.endsWith('packages/blind-protocol/extended-schema-metadata.js') ||
    input.endsWith('packages/blind-protocol/master-schema-inventory.js') ||
    input.endsWith('packages/blind-protocol/registry.js') ||
    input.endsWith('packages/blind-protocol/schema-codecs.js') ||
    input.endsWith('packages/blind-protocol/schema-meta.js') ||
    input.endsWith('packages/blind-protocol/abi-registry.js'))
  if (controlForbidden.length > 0) {
    throw new Error(`browser control bundle contains forbidden inputs: ${controlForbidden.join(', ')}`)
  }
  const controlBytes = await fs.readFile(controlOutput)
  const controlGzipBytes = gzipSync(controlBytes).byteLength
  if (controlBytes.byteLength > 320 * 1024 || controlGzipBytes > 90 * 1024) {
    throw new Error(`blind-client browser control bundle exceeds its lazy budget (${controlBytes.byteLength} raw, ${controlGzipBytes} gzip)`)
  }
  const control = await import(`${pathToFileURL(controlOutput).href}?test=${Date.now()}`)
  if (typeof control.DescriptorTrustStore !== 'function' || typeof control.DurableAttempt !== 'function' ||
      typeof control.decodeBlindExternalProfileValueV1 !== 'function') {
    throw new Error('lazy browser control bundle is missing authenticated control-plane exports')
  }
  const readCap = b4a.concat([
    b4a.from([1]),
    b4a.alloc(32, 0x51),
    b4a.alloc(32, 0x52),
    b4a.alloc(32, 0x53),
    b4a.from([1, 1]),
    b4a.alloc(32, 0x54)
  ])
  if (control.decodeBlindExternalProfileValueV1('ReadCellCapV1', readCap).sizeClass !== 1) {
    throw new Error('lazy browser control bundle external-profile decoder failed')
  }
  process.stdout.write(`${JSON.stringify({
    schema: 'HiveRelayBlindClientBrowserBundleTestV1',
    rawBytes: bundleBytes.byteLength,
    gzipBytes,
    cellBytes: created.request.cellBlob.byteLength,
    inboxFrameBytes: appended.request.frame.byteLength,
    coreMirrorBytes: coreMirror.requestBytes.byteLength,
    forwardFlightBytes: forwardFrame.byteLength,
    controlRawBytes: controlBytes.byteLength,
    controlGzipBytes,
    nativeInputs: 0,
    ok: true
  })}\n`)
} finally {
  await fs.rm(directory, { recursive: true, force: true })
}
