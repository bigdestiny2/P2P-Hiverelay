#!/usr/bin/env node

import { constants } from 'fs'
import { open, rename, unlink } from 'fs/promises'
import { createHash, randomBytes } from 'crypto'
import { execFile } from 'child_process'
import { isUtf8 } from 'buffer'
import { dirname, join, resolve } from 'path'
import { promisify } from 'util'
import defaults from '../packages/core/config/default.js'
import {
  inspectPublicHiveGatewayConfig,
  inspectActivePublicHiveGatewayNginx,
  inspectPublicHiveGatewayNginx,
  normalizePublicHiveGatewayConnectAddress,
  probePublicHiveGateway,
  renderPublicHiveGatewayNginx
} from './lib/public-hive-gateway-preflight.mjs'
import {
  PUBLIC_HIVE_GATEWAY_EVIDENCE_SCHEMA
} from './lib/public-hive-gateway-evidence.mjs'

const execFileAsync = promisify(execFile)
const MAX_ACTIVE_NGINX_BYTES = 8 * 1024 * 1024

const args = parseArgs(process.argv.slice(2))
if (args.help) {
  console.log(`Usage:
  node scripts/preflight-public-hive-gateway.mjs --config <config.json> [options]

Options:
  --mode <canary|fleet>              Fleet mode fails until frozen T1 admission lands
  --public-suffix-ready              Assert PSL/separate-registrable-domain isolation
  --nginx-template <path>            Render and validate the strict nginx template
  --nginx-config <path>              Bind the exact installed include in nginx -T
  --nginx-binary <absolute-path>     Run this nginx with -T and attest active config
  --certificate <absolute-path>      Wildcard certificate path inserted in nginx config
  --certificate-key <absolute-path>  Node-local wildcard private-key path
  --nginx-output <path>              Atomically write rendered nginx config
  --probe-origin <https-origin>      Run live TLS/content/isolation probes
  --connect-address <IP>             Pin probe TCP connections to this node address
  --app-key <64-hex>                 Expected app key for the live probe
  --path </path>                     Exact content probe path (default /index.html)
  --expected-sha256 <64-hex>         Optional expected body digest
  --ca <path>                        Optional private/test CA bundle
  --release-target <vX.Y.Z>          Bind evidence to an immutable release tag
  --release-sha <40-or-64-hex>       Bind evidence to that tag's verified commit
  --evidence <path>                  Atomically write public-safe JSON evidence

HIVERELAY_API_KEY must be present. Its value is never printed or persisted.`)
  process.exit(0)
}

const release = normalizeReleaseArgs(args)
const configPath = requiredPath(args.config, '--config')
const persisted = JSON.parse(await readBoundedRegularFile(configPath, 'gateway config'))
const publicT1Preset = persisted.productProfile === 'public-t1-gateway'
  ? { mode: 'public-t1-gateway', enableRelay: false, enableSeeding: true, enableAPI: true, enableServices: false, plugins: [], requirePhysicalEnforcement: true }
  : null
const config = { ...defaults, ...(publicT1Preset || {}), ...persisted }
const mode = args.mode || 'canary'
const connectAddress = args.connectAddress == null
  ? null
  : normalizePublicHiveGatewayConnectAddress(args.connectAddress)
if (args.connectAddress != null && !connectAddress) throw new Error('--connect-address must be an explicit IP address')
if (mode === 'fleet' && !args.probeOrigin) {
  throw new Error('--mode fleet evidence requires --probe-origin')
}
if (mode === 'fleet' && !connectAddress) {
  throw new Error('--mode fleet live evidence requires --connect-address')
}
if (mode === 'fleet' && !args.nginxConfig) {
  throw new Error('--mode fleet live evidence requires --nginx-config for the exact installed edge configuration')
}
if (mode === 'fleet' && !args.nginxBinary) {
  throw new Error('--mode fleet live evidence requires --nginx-binary to attest the active parsed edge configuration')
}
const staticResult = inspectPublicHiveGatewayConfig(config, {
  mode,
  apiKeyPresent: typeof process.env.HIVERELAY_API_KEY === 'string' && process.env.HIVERELAY_API_KEY.length > 0,
  publicSuffixReady: args.publicSuffixReady === true,
  explicitConfig: persisted
})

let nginx = null
if (args.nginxConfig) {
  const installedPath = requiredPath(args.nginxConfig, '--nginx-config')
  const installed = await readBoundedRegularFile(installedPath, 'installed nginx config', 256 * 1024)
  const installedInspection = inspectPublicHiveGatewayNginx(installed, {
    suffix: config.hiveAppHostSuffix,
    gatewayPort: config.gatewayPort
  })
  if (args.nginxBinary) {
    const active = await readActiveNginxConfiguration(args.nginxBinary)
    const activeInspection = inspectActivePublicHiveGatewayNginx(active.text, {
      suffix: config.hiveAppHostSuffix,
      gatewayPort: config.gatewayPort,
      installedConfig: installed,
      installedPath
    })
    nginx = {
      ok: installedInspection.ok && activeInspection.ok,
      errors: [...installedInspection.errors, ...activeInspection.errors],
      source: 'active',
      sha256: createHash('sha256').update(active.bytes).digest('hex')
    }
  } else {
    nginx = {
      ...installedInspection,
      source: 'installed',
      sha256: createHash('sha256').update(installed).digest('hex')
    }
  }
} else if (args.nginxTemplate) {
  const templatePath = requiredPath(args.nginxTemplate, '--nginx-template')
  const template = await readBoundedRegularFile(templatePath, 'nginx template')
  const rendered = renderPublicHiveGatewayNginx(template, {
    suffix: config.hiveAppHostSuffix,
    gatewayPort: config.gatewayPort,
    certificate: args.certificate,
    certificateKey: args.certificateKey
  })
  nginx = {
    ...inspectPublicHiveGatewayNginx(rendered, {
      suffix: config.hiveAppHostSuffix,
      gatewayPort: config.gatewayPort
    }),
    source: 'rendered',
    sha256: createHash('sha256').update(rendered).digest('hex')
  }
  if (args.nginxOutput && staticResult.ok && nginx.ok) await writeAtomic(resolve(args.nginxOutput), rendered)
}

let probe = null
let probeError = null
if (args.probeOrigin && staticResult.ok && (!nginx || nginx.ok)) {
  try {
    const ca = args.ca ? await readBoundedRegularFile(resolve(args.ca), 'CA bundle', 1024 * 1024, null) : undefined
    const probeAppKey = String(args.appKey || staticResult.normalized?.appKeys[0] || '').toLowerCase()
    probe = await probePublicHiveGateway({
      origin: args.probeOrigin,
      appKey: probeAppKey,
      suffix: config.hiveAppHostSuffix,
      connectAddress,
      path: args.path || '/index.html',
      expectedSha256: args.expectedSha256,
      expectedDriveVersion: staticResult.normalized?.appVersions?.[probeAppKey],
      ca
    })
  } catch (err) {
    probeError = err.message
  }
}

const ok = staticResult.ok && (!nginx || nginx.ok) && !probeError && (!args.probeOrigin || !!probe)
const evidence = {
  schema: PUBLIC_HIVE_GATEWAY_EVIDENCE_SCHEMA,
  status: ok ? 'pass' : 'fail',
  checkedAt: new Date().toISOString(),
  mode,
  admissionProfile: staticResult.normalized?.admissionProfile || null,
  release,
  config: {
    suffix: staticResult.normalized?.suffix || null,
    appKeyCount: staticResult.normalized?.appKeys.length || 0,
    apiHost: config.apiHost,
    apiPort: config.apiPort,
    gatewayHost: config.gatewayHost,
    gatewayPort: config.gatewayPort,
    connectAddress,
    publicSuffixReady: args.publicSuffixReady === true,
    custodyEnabled: config.custody?.enabled === true,
    physicalEnforcementRequired: staticResult.normalized?.physicalEnforcementRequired === true,
    finiteProductionPolicy: staticResult.normalized?.finiteProductionPolicy || null
  },
  static: {
    ok: staticResult.ok,
    errors: staticResult.errors,
    warnings: staticResult.warnings
  },
  nginx,
  probe,
  probeError
}

if (args.evidence) await writeAtomic(resolve(args.evidence), JSON.stringify(evidence, null, 2) + '\n')
console.log(JSON.stringify(evidence, null, 2))
if (!ok) process.exitCode = 1

function parseArgs (argv) {
  const out = {}
  const boolean = new Set(['help', 'public-suffix-ready'])
  const values = new Set([
    'config',
    'mode',
    'nginx-template',
    'nginx-config',
    'nginx-binary',
    'certificate',
    'certificate-key',
    'nginx-output',
    'probe-origin',
    'connect-address',
    'app-key',
    'path',
    'expected-sha256',
    'ca',
    'release-target',
    'release-sha',
    'evidence'
  ])
  const seen = new Set()
  for (let i = 0; i < argv.length; i++) {
    const raw = argv[i]
    if (raw === '-h') {
      if (seen.has('help')) throw new Error('Duplicate option: --help')
      seen.add('help')
      out.help = true
      continue
    }
    if (!raw.startsWith('--')) throw new Error(`Unexpected argument: ${raw}`)
    const rawName = raw.slice(2)
    if (!boolean.has(rawName) && !values.has(rawName)) throw new Error(`Unknown option: --${rawName}`)
    if (seen.has(rawName)) throw new Error(`Duplicate option: --${rawName}`)
    seen.add(rawName)
    const name = camel(rawName)
    if (boolean.has(rawName)) { out[name] = true; continue }
    const value = argv[++i]
    if (!value || value.startsWith('--')) throw new Error(`Missing value for ${raw}`)
    out[name] = value
  }
  if (out.nginxOutput && !out.nginxTemplate) throw new Error('--nginx-output requires --nginx-template')
  if (out.nginxConfig && out.nginxTemplate) throw new Error('--nginx-config and --nginx-template are mutually exclusive')
  if (out.nginxBinary && !out.nginxConfig) throw new Error('--nginx-binary requires --nginx-config')
  if ((out.certificate || out.certificateKey) && !out.nginxTemplate) {
    throw new Error('--certificate and --certificate-key require --nginx-template')
  }
  if (out.nginxTemplate && (!out.certificate || !out.certificateKey)) {
    throw new Error('--nginx-template requires --certificate and --certificate-key')
  }
  if (!out.probeOrigin && (out.appKey || out.path || out.expectedSha256 || out.ca || out.connectAddress)) {
    throw new Error('--app-key, --path, --expected-sha256, --ca, and --connect-address require --probe-origin')
  }
  if (Boolean(out.releaseTarget) !== Boolean(out.releaseSha)) {
    throw new Error('--release-target and --release-sha must be provided together')
  }
  return out
}

async function readActiveNginxConfiguration (binaryValue) {
  const binary = safeExecutablePath(binaryValue, '--nginx-binary')
  let result
  try {
    result = await execFileAsync(binary, ['-T'], {
      encoding: 'buffer',
      timeout: 10_000,
      maxBuffer: MAX_ACTIVE_NGINX_BYTES
    })
  } catch (err) {
    const detail = err?.killed ? 'timed out' : 'failed its configuration test'
    throw new Error(`active nginx ${detail}`)
  }
  const active = result.stdout
  if (!Buffer.isBuffer(active) || active.length === 0 || active.length > MAX_ACTIVE_NGINX_BYTES || !isUtf8(active)) {
    throw new Error('active nginx -T output must be a bounded non-empty configuration')
  }
  return { bytes: active, text: active.toString('utf8') }
}

function safeExecutablePath (value, label) {
  if (typeof value !== 'string' || !value.startsWith('/') || value.length > 4096 || /[\r\n\0]/.test(value)) {
    throw new Error(`${label} must be a bounded absolute path`)
  }
  return value
}

function camel (value) {
  return value.replace(/-([a-z])/g, (_, char) => char.toUpperCase())
}

function requiredPath (value, flag) {
  if (!value) throw new Error(`${flag} is required`)
  return resolve(value)
}

function normalizeReleaseArgs (args) {
  if (!args.releaseTarget) return null
  if (!/^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/.test(args.releaseTarget)) {
    throw new Error('--release-target must be a release tag like v1.2.3')
  }
  if (!/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/i.test(args.releaseSha)) {
    throw new Error('--release-sha must be 40 or 64 hex characters')
  }
  return { target: args.releaseTarget, sha: args.releaseSha.toLowerCase() }
}

async function readBoundedRegularFile (path, label, maxBytes = 1024 * 1024, encoding = 'utf8') {
  let handle
  try {
    handle = await openNoFollow(path)
    const before = await handle.stat({ bigint: true })
    assertBoundedRegularFile(before, maxBytes, label)

    const buffer = Buffer.allocUnsafe(maxBytes + 1)
    let length = 0
    while (length < buffer.length) {
      const result = await handle.read(buffer, length, buffer.length - length, length)
      if (result.bytesRead === 0) break
      length += result.bytesRead
    }
    if (length > maxBytes) throw new Error(`${label} must be a bounded regular file`)

    const after = await handle.stat({ bigint: true })
    if (!sameFileSnapshot(before, after) || BigInt(length) !== after.size) {
      throw new Error(`${label} changed while it was being read`)
    }
    await assertPathIdentity(path, after, label)

    const contents = buffer.subarray(0, length)
    if (encoding === 'utf8' && !isUtf8(contents)) throw new Error(`${label} must be valid UTF-8`)
    return encoding == null ? contents : contents.toString(encoding)
  } catch (err) {
    if (isNoFollowError(err)) throw new Error(`${label} must be a bounded regular file`)
    throw err
  } finally {
    await handle?.close()
  }
}

async function writeAtomic (path, contents) {
  const directory = dirname(path)
  const buffer = Buffer.isBuffer(contents) ? contents : Buffer.from(contents)
  let temp = null
  let handle = null
  let tempOwned = false
  let renamed = false
  let failure = null

  try {
    for (let attempt = 0; attempt < 8; attempt++) {
      temp = join(directory, `.hiverelay-gateway-${process.pid}-${randomBytes(16).toString('hex')}.tmp`)
      try {
        handle = await open(temp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | noFollowFlag(), 0o600)
        tempOwned = true
        break
      } catch (err) {
        if (err.code !== 'EEXIST') throw err
      }
    }
    if (!handle) throw new Error(`Unable to allocate an exclusive temporary file for ${path}`)

    await handle.writeFile(buffer)
    await handle.sync()
    const written = await handle.stat({ bigint: true })
    if (!written.isFile() || written.nlink !== 1n || written.size !== BigInt(buffer.length)) {
      throw new Error(`Atomic output verification failed for ${path}`)
    }

    await assertPathIdentity(temp, written, 'atomic output')
    await rename(temp, path)
    renamed = true
    await syncDirectory(directory)
  } catch (err) {
    failure = err
  }

  try {
    await handle?.close()
  } catch (err) {
    if (!failure) failure = err
  }
  if (tempOwned && temp && !renamed) {
    try {
      await unlink(temp)
    } catch (err) {
      if (err.code !== 'ENOENT' && !failure) failure = err
    }
  }
  if (failure) throw failure
}

function noFollowFlag () {
  if (typeof constants.O_NOFOLLOW !== 'number') throw new Error('This platform cannot safely open no-follow paths')
  return constants.O_NOFOLLOW
}

async function openNoFollow (path) {
  return open(path, constants.O_RDONLY | noFollowFlag())
}

function assertBoundedRegularFile (info, maxBytes, label) {
  if (!info.isFile() || info.size < 0n || info.size > BigInt(maxBytes)) {
    throw new Error(`${label} must be a bounded regular file`)
  }
}

function sameFileIdentity (left, right) {
  return left.dev === right.dev && left.ino === right.ino
}

function sameFileSnapshot (left, right) {
  return sameFileIdentity(left, right) &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
}

async function assertPathIdentity (path, expected, label) {
  let current
  try {
    current = await openNoFollow(path)
    const info = await current.stat({ bigint: true })
    if (!sameFileSnapshot(expected, info)) throw new Error(`${label} path changed while it was being inspected`)
  } catch (err) {
    if (isNoFollowError(err) || err.code === 'ENOENT') {
      throw new Error(`${label} path changed while it was being inspected`)
    }
    throw err
  } finally {
    await current?.close()
  }
}

function isNoFollowError (err) {
  return err?.code === 'ELOOP' || err?.code === 'EMLINK'
}

async function syncDirectory (directory) {
  let handle
  try {
    handle = await open(directory, constants.O_RDONLY | (constants.O_DIRECTORY || 0))
    await handle.sync()
  } catch (err) {
    if (!['EINVAL', 'ENOTSUP', 'EBADF', 'EISDIR'].includes(err.code)) throw err
  } finally {
    await handle?.close()
  }
}
