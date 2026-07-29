#!/usr/bin/env node

import { execFile } from 'node:child_process'
import { X509Certificate } from 'node:crypto'
import { constants as fsConstants } from 'node:fs'
import { lstat, open, realpath } from 'node:fs/promises'
import https from 'node:https'
import path from 'node:path'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'
import {
  normalizePublicHiveGatewayOperatorContract,
  sha256PublicHiveGatewayOperatorContract
} from './lib/public-hive-gateway-release-manifest.mjs'
import {
  collectPublicHiveGatewayQuarantineDns,
  inspectPublicHiveGatewayQuarantineDns,
  inspectPublicHiveGatewayQuarantineNginx
} from './lib/public-hive-gateway-quarantine-authority.mjs'

const execFileAsync = promisify(execFile)
const scriptPath = fileURLToPath(import.meta.url)

if (path.resolve(process.argv[1] || '') === scriptPath) {
  try {
    const result = await verifyPublicHiveGatewayQuarantine(parseArgs(process.argv.slice(2)))
    process.stdout.write(`contained\t${result.hostname}\t${result.addresses.join(',')}\n`)
  } catch (err) {
    console.error(`public gateway quarantine verification: ${err?.message || String(err)}`)
    process.exitCode = 1
  }
}

export async function verifyPublicHiveGatewayQuarantine (args, injected = {}) {
  const contractBytes = await readStableBounded(args.contract, 256 * 1024, 'operator contract')
  let contract
  try {
    contract = normalizePublicHiveGatewayOperatorContract(JSON.parse(contractBytes.toString('utf8')))
  } catch (err) {
    throw new Error(`operator contract is invalid: ${err?.message || String(err)}`)
  }
  if (sha256PublicHiveGatewayOperatorContract(contract) !== args.expectedDigest) {
    throw new Error('quarantine operator contract digest does not match signed manifest')
  }
  const nginxRecord = await trustedExecutableRecord(args.nginxBinary, 'nginx binary')

  const failures = []
  const runNginx = injected.runNginx || (async () => execFileAsync(args.nginxBinary, ['-T'], {
    encoding: 'utf8',
    timeout: 10_000,
    maxBuffer: 8 * 1024 * 1024,
    env: { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C', LC_ALL: 'C' }
  }))
  try {
    const nginx = await runNginx()
    if (await trustedExecutableRecord(args.nginxBinary, 'nginx binary') !== nginxRecord) {
      throw new Error('nginx binary changed while collecting active configuration')
    }
    const inspected = inspectPublicHiveGatewayQuarantineNginx(`${nginx.stdout || ''}\n${nginx.stderr || ''}`, {
      suffix: contract.suffix
    })
    if (!inspected.ok) failures.push(`active quarantine nginx failed: ${inspected.errors.join('; ')}`)
  } catch (err) {
    failures.push(`active quarantine nginx could not be inspected: ${err?.message || String(err)}`)
  }

  let addresses = [...contract.expectedAddresses]
  try {
    const collectDns = injected.collectDns || collectPublicHiveGatewayQuarantineDns
    const dns = await withDeadline(
      collectDns(contract, injected.dnsOptions),
      injected.dnsTimeoutMs || 10_000,
      'live quarantine DNS collection exceeded its absolute deadline'
    )
    const inspectedDns = inspectPublicHiveGatewayQuarantineDns(dns, contract)
    addresses = inspectedDns.probeAddresses
    if (!inspectedDns.ok) failures.push(`live quarantine DNS failed: ${inspectedDns.errors.join('; ')}`)
  } catch (err) {
    failures.push(`live quarantine DNS could not be proven: ${err?.message || String(err)}`)
  }

  const ca = args.ca ? await readStableBounded(args.ca, 1024 * 1024, 'CA bundle') : undefined
  const probe = injected.probe || probe421
  for (let offset = 0; offset < addresses.length; offset += 4) {
    const batch = addresses.slice(offset, offset + 4)
    const results = await Promise.allSettled(batch.map(address => withDeadline(
      probe(address, contract, ca),
      injected.probeTimeoutMs || 10_000,
      `address ${address} quarantine probe exceeded its absolute deadline`
    )))
    for (let index = 0; index < results.length; index++) {
      if (results[index].status === 'rejected') {
        failures.push(`address ${batch[index]} quarantine probe failed: ${results[index].reason?.message || String(results[index].reason)}`)
      }
    }
  }
  if (failures.length > 0) throw new Error(failures.join('; '))
  return { hostname: contract.appHostname, addresses }
}

function probe421 (address, contract, ca) {
  return new Promise((resolve, reject) => {
    let settled = false
    const finish = (err) => {
      if (settled) return
      settled = true
      clearTimeout(absoluteDeadline)
      if (err) reject(err)
      else resolve()
    }
    const request = https.request({
      host: address,
      port: 443,
      servername: contract.appHostname,
      method: 'GET',
      path: '/',
      headers: { Host: contract.appHostname, Connection: 'close' },
      ca,
      rejectUnauthorized: true,
      minVersion: 'TLSv1.2',
      maxVersion: 'TLSv1.3',
      agent: false,
      timeout: 8000
    }, response => {
      const certificate = response.socket.getPeerCertificate(true)
      const protocol = response.socket.getProtocol()
      let bytes = 0
      response.on('data', chunk => {
        bytes += chunk.byteLength
        if (bytes > 64 * 1024) request.destroy(new Error('quarantine response exceeded 64 KiB'))
      })
      response.on('end', () => {
        try {
          if (response.statusCode !== 421) throw new Error(`returned ${response.statusCode}, not 421`)
          if (response.headers['alt-svc'] !== undefined) throw new Error('advertises Alt-Svc')
          if (protocol !== 'TLSv1.2' && protocol !== 'TLSv1.3') throw new Error('negotiated an unreviewed TLS version')
          if (!certificate?.raw) throw new Error('did not provide a peer certificate')
          const fingerprint = new X509Certificate(certificate.raw).fingerprint256.toUpperCase()
          if (fingerprint !== contract.certificateFingerprint256) throw new Error('certificate drifted')
          finish()
        } catch (err) {
          finish(err)
        }
      })
    })
    const absoluteDeadline = setTimeout(() => {
      request.destroy(new Error('quarantine probe exceeded its absolute deadline'))
    }, 8000)
    if (absoluteDeadline.unref) absoluteDeadline.unref()
    request.on('timeout', () => request.destroy(new Error('quarantine probe timed out')))
    request.on('error', finish)
    request.end()
  })
}

function withDeadline (promise, timeoutMs, message) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(message)), timeoutMs)
    Promise.resolve(promise).then(
      value => {
        clearTimeout(timer)
        resolve(value)
      },
      err => {
        clearTimeout(timer)
        reject(err)
      }
    )
  })
}

async function readStableBounded (filename, max, label) {
  requireAbsoluteSafePath(filename, label)
  const euid = typeof process.geteuid === 'function' ? process.geteuid() : 0
  await requireCanonicalLexicalPath(filename, label)
  await requireTrustedParentChain(filename, label, euid)
  let handle
  try {
    if (typeof fsConstants.O_NOFOLLOW !== 'number') throw new Error('platform lacks O_NOFOLLOW')
    handle = await open(filename, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW)
    const before = await handle.stat({ bigint: true })
    if (!before.isFile() || before.nlink !== 1n || before.size < 1n || before.size > BigInt(max) ||
        (before.mode & 0o022n) !== 0n || (before.uid !== 0n && before.uid !== BigInt(euid))) {
      throw new Error(`${label} must be a bounded single-link regular file`)
    }
    const bytes = Buffer.allocUnsafe(Number(before.size))
    let offset = 0
    while (offset < bytes.length) {
      const result = await handle.read(bytes, offset, bytes.length - offset, offset)
      if (result.bytesRead === 0) break
      offset += result.bytesRead
    }
    const after = await handle.stat({ bigint: true })
    if (offset !== bytes.length || !sameSnapshot(before, after)) throw new Error(`${label} changed while being read`)
    await requireCanonicalLexicalPath(filename, label)
    await requireTrustedParentChain(filename, label, euid)
    return bytes
  } catch (err) {
    if (String(err?.message || '').startsWith(label) || err?.message === 'platform lacks O_NOFOLLOW') throw err
    throw new Error(`${label} must be a readable non-symlink file`)
  } finally {
    await handle?.close().catch(() => {})
  }
}

async function trustedExecutableRecord (filename, label) {
  requireAbsoluteSafePath(filename, label)
  await requireCanonicalLexicalPath(filename, label)
  const stat = await lstat(filename)
  const euid = typeof process.geteuid === 'function' ? process.geteuid() : stat.uid
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 ||
      (stat.mode & 0o111) === 0 || (stat.mode & 0o022) !== 0 ||
      (stat.uid !== 0 && stat.uid !== euid) || stat.size < 1 || stat.size > 256 * 1024 * 1024) {
    throw new Error(`${label} must be an owner-trusted, single-link, non-writable executable file`)
  }
  await requireTrustedParentChain(filename, label, euid)
  await requireCanonicalLexicalPath(filename, label)
  const finalStat = await lstat(filename)
  if (executableSnapshot(finalStat) !== executableSnapshot(stat)) {
    throw new Error(`${label} changed while establishing executable trust`)
  }
  return executableSnapshot(stat)
}

async function requireTrustedParentChain (filename, label, euid) {
  let parent = path.dirname(filename)
  while (true) {
    const stat = await lstat(parent)
    const stickyRoot = stat.uid === 0 && (stat.mode & 0o1000) !== 0
    if (!stat.isDirectory() || stat.isSymbolicLink() ||
        (stat.uid !== 0 && stat.uid !== euid) || ((stat.mode & 0o022) !== 0 && !stickyRoot)) {
      throw new Error(`${label} parent chain is writable or owner-untrusted at ${parent}`)
    }
    if (parent === path.parse(parent).root) break
    parent = path.dirname(parent)
  }
}

async function requireCanonicalLexicalPath (filename, label) {
  const physicalParent = await realpath(path.dirname(filename))
  const canonical = path.join(physicalParent, path.basename(filename))
  if (filename !== canonical) {
    throw new Error(`${label} path must be canonical and contain no symlink ancestors`)
  }
}

function executableSnapshot (stat) {
  return [stat.dev, stat.ino, stat.mode, stat.nlink, stat.uid, stat.gid, stat.size, stat.mtimeMs, stat.ctimeMs].join('|')
}

function sameSnapshot (left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode &&
    left.nlink === right.nlink && left.uid === right.uid && left.gid === right.gid &&
    left.size === right.size && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs
}

function requireAbsoluteSafePath (value, label) {
  if (typeof value !== 'string' || !value.startsWith('/') || value.length > 4096 || /[\r\n\0]/.test(value)) {
    throw new Error(`${label} path is invalid`)
  }
}

function parseArgs (argv) {
  const out = {}
  const allowed = new Set(['contract', 'expected-digest', 'nginx-binary', 'ca'])
  if (argv.length % 2 !== 0) throw new Error('invalid quarantine verifier arguments')
  for (let i = 0; i < argv.length; i += 2) {
    const name = String(argv[i] || '').replace(/^--/, '')
    const value = argv[i + 1]
    if (!allowed.has(name) || !value || out[name] !== undefined) throw new Error('invalid quarantine verifier arguments')
    out[name] = value
  }
  if (!out.contract || !out['nginx-binary'] || !/^[a-f0-9]{64}$/.test(out['expected-digest'] || '')) {
    throw new Error('quarantine verifier requires contract, expected digest, and nginx binary')
  }
  return {
    contract: out.contract,
    expectedDigest: out['expected-digest'],
    nginxBinary: out['nginx-binary'],
    ca: out.ca
  }
}
