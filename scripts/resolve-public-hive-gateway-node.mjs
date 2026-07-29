#!/usr/bin/env node

import {
  PUBLIC_HIVE_GATEWAY_RELEASE_SCHEMA,
  normalizePublicHiveGatewayReleaseManifest
} from './lib/public-hive-gateway-release-manifest.mjs'

const MAX_MANIFEST_BYTES = 2 * 1024 * 1024

try {
  const args = parseArgs(process.argv.slice(2))
  const bytes = await readStdinBounded(MAX_MANIFEST_BYTES)
  const parsed = parseJson(bytes)

  if (parsed?.enabled === false) {
    requireDisabledControl(parsed)
    process.stdout.write('ordinary\tdisabled\n')
    process.exit(0)
  }

  const manifest = normalizePublicHiveGatewayReleaseManifest(parsed, {
    releaseTarget: args.releaseTarget,
    requirePublicT1: args.requirePublicT1 === true
  })
  const entries = manifest.cohort.filter(entry => entry.relay === args.relay)
  if (entries.length === 0) {
    process.stdout.write('ordinary\tnoncohort\n')
    process.exit(0)
  }
  if (entries.length !== 1) throw new Error(`manifest does not uniquely identify relay ${args.relay}`)

  const entry = entries[0]
  if (entry.channel !== args.channel) {
    throw new Error(`relay ${args.relay} is signed for channel ${entry.channel}, not ${args.channel}`)
  }

  // Every value was normalized by the closed manifest schema and excludes
  // control characters. A fixed tab-delimited record lets the shell consume
  // it as data without eval/source or dynamically generated option names.
  process.stdout.write([
    'cohort',
    manifest.admissionProfile,
    entry.origin,
    entry.connectAddress,
    entry.appKey,
    entry.path,
    entry.contentSha256,
    entry.driveVersion,
    entry.peerFingerprint256,
    entry.nginxConfigSha256,
    entry.deploymentProfile || 'legacy',
    entry.operatorContractSha256 || '-'
  ].join('\t') + '\n')
} catch (err) {
  console.error(`public gateway node contract: ${safeError(err)}`)
  process.exitCode = 1
}

function parseArgs (argv) {
  const out = {}
  const valueArgs = new Set(['release-target', 'relay', 'channel'])
  const booleanArgs = new Set(['require-public-t1'])
  const seen = new Set()
  for (let i = 0; i < argv.length; i++) {
    const raw = argv[i]
    if (!raw.startsWith('--')) throw new Error(`unexpected argument ${JSON.stringify(raw)}`)
    const name = raw.slice(2)
    if (!valueArgs.has(name) && !booleanArgs.has(name)) throw new Error(`unknown option --${name}`)
    if (seen.has(name)) throw new Error(`duplicate option --${name}`)
    seen.add(name)
    if (booleanArgs.has(name)) {
      out[camel(name)] = true
      continue
    }
    const value = argv[++i]
    if (!value || value.startsWith('--')) throw new Error(`missing value for --${name}`)
    out[camel(name)] = value
  }
  if (!/^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/.test(out.releaseTarget || '')) {
    throw new Error('--release-target must be a release tag like v1.2.3')
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(out.relay || '')) {
    throw new Error('--relay must be a canonical fleet relay name')
  }
  if (!/^[A-Za-z0-9._-]{1,32}$/.test(out.channel || '')) {
    throw new Error('--channel must be a canonical fleet channel name')
  }
  return out
}

async function readStdinBounded (maxBytes) {
  const chunks = []
  let length = 0
  for await (const chunk of process.stdin) {
    length += chunk.length
    if (length > maxBytes) throw new Error('manifest exceeds the input limit')
    chunks.push(chunk)
  }
  if (length === 0) throw new Error('manifest input is empty')
  return Buffer.concat(chunks, length)
}

function parseJson (bytes) {
  try {
    const value = JSON.parse(bytes.toString('utf8'))
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('not an object')
    return value
  } catch {
    throw new Error('manifest input must be valid JSON object')
  }
}

function requireDisabledControl (value) {
  const keys = Object.keys(value).sort()
  if (keys.length !== 2 || keys[0] !== 'enabled' || keys[1] !== 'schema' ||
      value.schema !== PUBLIC_HIVE_GATEWAY_RELEASE_SCHEMA || value.enabled !== false) {
    throw new Error('disabled manifest must contain exactly the canonical schema and enabled=false')
  }
}

function camel (value) {
  return value.replace(/-([a-z])/g, (_, char) => char.toUpperCase())
}

function safeError (err) {
  const value = err instanceof Error ? err.message : String(err)
  return value.replace(/[\r\n\0]/g, ' ').slice(0, 1000)
}
