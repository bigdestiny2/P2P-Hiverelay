import test from 'brittle'
import { PassThrough } from 'streamx'
import { createRequire } from 'module'
import { execFileSync } from 'child_process'
import { closeSync, constants, mkdtempSync, openSync, realpathSync, readFileSync, writeFileSync } from 'fs'
import { rm } from 'fs/promises'
import { tmpdir } from 'os'
import { dirname, join } from 'path'

const coreRequire = createRequire(new URL('../../packages/core/package.json', import.meta.url))
const RPC = coreRequire('protomux-rpc')
const { tryLock, unlock } = coreRequire('fs-native-extensions')

test('distributed-drive RPC transport retains numeric error causes and remains usable afterward', async t => {
  const stream = new PassThrough()
  const rpc = new RPC(stream)
  t.teardown(() => { rpc.destroy(); stream.destroy() })
  for (const code of [0, 17, -1, 'ENOENT']) {
    rpc.respond('failure', () => { const error = new Error('synthetic failure'); error.code = code; throw error })
    try {
      await rpc.request('failure', Buffer.alloc(0), { timeout: 2000 })
      t.fail('request must report the remote error')
    } catch (error) {
      t.is(error.code, 'REQUEST_ERROR')
      t.is(error.cause?.code, String(code), 'wire cause preserves zero and non-string codes')
      t.is(error.cause?.message, 'synthetic failure')
    }
    rpc.respond('success', () => Buffer.from('still-open'))
    t.is((await rpc.request('success', Buffer.alloc(0), { timeout: 2000 })).toString(), 'still-open', 'error did not close the shared channel')
    rpc.unrespond('failure'); rpc.unrespond('success')
  }
})

test('native shared import lock excludes another writer and keeps 64-bit lock offsets distinct', async t => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'hiverelay-native-lock-')))
  const file = join(root, 'marker'); writeFileSync(file, 'disposable lock fixture', { mode: 0o600 })
  t.teardown(() => rm(root, { recursive: true, force: true }))
  const child = 'const fs=require(\'fs\');const native=require(process.argv[1]);const fd=fs.openSync(process.argv[2],process.argv[3]===\'shared\'?\'r\':\'r+\');try{const ok=native.tryLock(fd,Number(process.argv[4]),Number(process.argv[4])===0?0:5,{shared:process.argv[3]===\'shared\'});process.stdout.write(JSON.stringify(ok));if(ok)native.unlock(fd,Number(process.argv[4]),Number(process.argv[4])===0?0:5)}finally{fs.closeSync(fd)}'
  const attempt = (mode, offset) => JSON.parse(execFileSync(process.execPath, ['-e', child, coreRequire.resolve('fs-native-extensions'), file, mode, String(offset)], { encoding: 'utf8', timeout: 5000 }))
  const reader = openSync(file, constants.O_RDONLY)
  try {
    t.is(tryLock(reader, 0, 0, { shared: true }), true)
    t.is(attempt('shared', 0), true, 'another stopped-reader lock is compatible')
    t.is(attempt('exclusive', 0), false, 'read-only import lock excludes a different process writer')
    unlock(reader, 0, 0)
    t.is(attempt('exclusive', 0), true, 'unlock releases the actual native lock')
  } finally { closeSync(reader) }
  const writer = openSync(file, constants.O_RDWR)
  const high = 2 ** 32 + 17
  try {
    if (process.platform === 'darwin') {
      t.exception(() => tryLock(writer, high, 5), { code: 'EINVAL' }, 'Apple backend explicitly supports whole-file locks only')
      return
    }
    t.is(tryLock(writer, high, 5), true)
    t.is(attempt('exclusive', high), false, '64-bit matching range conflicts')
    t.is(attempt('exclusive', 17), true, 'large offset is not truncated into a low offset')
    unlock(writer, high, 5)
    t.is(attempt('exclusive', high), true)
  } finally { closeSync(writer) }
})

test('public sodium 5 guards retain signature, authenticated-body and secure-memory behavior', t => {
  for (const workspace of ['core', 'services', 'client']) {
    const owner = createRequire(new URL('../../packages/' + workspace + '/package.json', import.meta.url))
    const sodium = owner('sodium-native')
    const version = JSON.parse(readFileSync(join(dirname(owner.resolve('sodium-native')), 'package.json'))).version
    t.is(version, '5.2.1', workspace + ': actual public native owner')
    if (version !== '5.2.1') continue
    const publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
    const secretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
    sodium.crypto_sign_keypair(publicKey, secretKey)
    const message = Buffer.from('synthetic public Hypercore signing boundary')
    const signature = Buffer.alloc(sodium.crypto_sign_BYTES)
    sodium.crypto_sign_detached(signature, message, secretKey)
    const changed = Buffer.from(message); changed[0] ^= 1
    let valid = true; let rejected = true
    for (let i = 0; i < 128; i++) {
      valid = valid && sodium.crypto_sign_verify_detached(signature, message, publicKey) === true
      rejected = rejected && sodium.crypto_sign_verify_detached(signature, changed, publicKey) === false
    }
    t.is(valid, true, 'valid signatures remain accepted through repeated native calls')
    t.is(rejected, true, 'tampered signatures remain rejected through repeated native calls')
    t.exception(() => sodium.crypto_sign(Buffer.alloc(0), Buffer.alloc(0), secretKey), 'undersized signed-message output is refused')
    const key = Buffer.alloc(sodium.crypto_secretbox_KEYBYTES)
    const nonce = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES)
    sodium.randombytes_buf(key); sodium.randombytes_buf(nonce)
    const cipher = Buffer.alloc(message.length + sodium.crypto_secretbox_MACBYTES)
    sodium.crypto_secretbox_easy(cipher, message, nonce, key)
    const plain = Buffer.alloc(message.length)
    t.is(sodium.crypto_secretbox_open_easy(plain, cipher, nonce, key), true)
    t.alike(plain, message)
    cipher[0] ^= 1
    t.is(sodium.crypto_secretbox_open_easy(plain, cipher, nonce, key), false, 'altered authenticated body is refused')
    t.exception(() => sodium.crypto_secretbox_easy(Buffer.alloc(0), Buffer.alloc(0), nonce, key), 'undersized ciphertext is refused')
    const secure = sodium.sodium_malloc(32)
    t.is(secure.secure, true)
    sodium.sodium_free(secure)
    t.is(secure.byteLength, 0); t.is(secure.secure, false)
    sodium.sodium_free(secure)
    t.is(secure.secure, false, 'repeated free remains a no-op')
    for (const protect of ['sodium_mprotect_noaccess', 'sodium_mprotect_readonly', 'sodium_mprotect_readwrite']) {
      t.exception(() => sodium[protect](Buffer.alloc(32)), 'unowned memory cannot be protected')
      t.exception(() => sodium[protect](null), 'invalid memory input cannot crash native protection')
    }
  }
})
