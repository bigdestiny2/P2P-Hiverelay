#!/usr/bin/env node

import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(__dirname, '..')

const usage = `
Usage:
  node scripts/check-fleet-rollout.mjs --target vX.Y.Z [options]

Options:
  --target <tag>              Release tag expected on each relay
  --target-sha <sha>          Expected commit SHA (defaults to git rev-parse tag)
  --channel <name|both|all>   Relay channel to check (default: canary)
  --relays <path>             Fleet inventory JSON (default: fleet/relays.json)
  --channels <path>           Fleet channel targets JSON (default: fleet/channels.json)
  --ssh-command <path>        SSH executable/fixture command (default: ssh)
  --ssh-key <path>            SSH key to use for every relay
  --ssh-user <user>           SSH username (default: root)
  --remote-repo-dir <path>    Repo path on each relay (default: $HOME/hiverelay)
  --service <name>            systemd service name (default: hiverelay)
  --api <url>                 Relay health URL base (default: http://127.0.0.1:9100)
  --timeout-ms <ms>           Total rollout wait budget (default: 1800000)
  --interval-ms <ms>          Delay between polling rounds (default: 30000)
  --ssh-timeout-ms <ms>       Per-relay SSH timeout (default: 25000)
  --evidence <path>           Write per-relay rollout evidence JSON
  --dry-run                   Resolve relays/target but do not SSH
`

const FORBIDDEN_PUBLIC_VALUE_PATTERNS = [
  [/-----BEGIN [A-Z ]*(?:PRIVATE|SECRET) KEY-----/, 'private key block'],
  [/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b/, 'GitHub token'],
  [/\bgithub_pat_[A-Za-z0-9_]{20,}\b/, 'GitHub token'],
  [/\bAuthorization\s*:\s*/i, 'authorization header'],
  [/\bBearer\s+[A-Za-z0-9._~+/=-]{16,}\b/i, 'bearer token'],
  [/\bAPP_SEED=[^\s'"]+/i, 'APP_SEED'],
  [/\bHIVERELAY_API_KEY=[^\s'"]+/i, 'API key'],
  [/\bsk-[A-Za-z0-9_-]{20,}\b/, 'API key']
]
const MAX_FLEET_METADATA_BYTES = 2 * 1024 * 1024
const FLEET_ROLLOUT_TIMEOUT_MIN_MS = 10 * 60 * 1000
const FLEET_ROLLOUT_TIMEOUT_MAX_MS = 4 * 60 * 60 * 1000
const FLEET_ROLLOUT_INTERVAL_MIN_MS = 5 * 1000
const FLEET_ROLLOUT_INTERVAL_MAX_MS = 5 * 60 * 1000
const FLEET_ROLLOUT_SSH_TIMEOUT_MIN_MS = 5 * 1000
const FLEET_ROLLOUT_SSH_TIMEOUT_MAX_MS = 2 * 60 * 1000

const args = parseArgs(process.argv.slice(2))
const target = args.target || args._[0]
if (!target || args.help) {
  console.log(usage.trim())
  process.exit(args.help ? 0 : 1)
}
if (!/^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(target)) {
  die(`Invalid --target "${target}". Expected vX.Y.Z.`)
}

const channel = args.channel || process.env.HIVERELAY_FLEET_CHANNEL || 'canary'
const relaysPath = path.resolve(args.relays || path.join(repoRoot, 'fleet', 'relays.json'))
const channelsPath = path.resolve(args.channels || path.join(repoRoot, 'fleet', 'channels.json'))
const sshCommand = validateLocalCommand(args.sshCommand || process.env.HIVERELAY_FLEET_SSH_COMMAND || 'ssh')
const sshKey = validateLocalPath(args.sshKey || process.env.HIVERELAY_FLEET_SSH_KEY || '', 'ssh-key')
const sshUser = validateSshUser(args.sshUser || process.env.HIVERELAY_FLEET_SSH_USER || 'root')
const remoteRepoDir = validateRemotePath(args.remoteRepoDir || process.env.HIVERELAY_REMOTE_REPO_DIR || '', 'remote-repo-dir')
const service = validateServiceName(args.service || process.env.HIVERELAY_SERVICE || 'hiverelay')
const api = normalizeApiBase(args.api || process.env.HIVERELAY_API || 'http://127.0.0.1:9100')
const timeoutMs = numberArg(args.timeoutMs || process.env.HIVERELAY_FLEET_ROLLOUT_TIMEOUT_MS, 1800000, 'timeout-ms')
const intervalMs = numberArg(args.intervalMs || process.env.HIVERELAY_FLEET_ROLLOUT_INTERVAL_MS, 30000, 'interval-ms')
const sshTimeoutMs = numberArg(args.sshTimeoutMs || process.env.HIVERELAY_FLEET_SSH_TIMEOUT_MS, 25000, 'ssh-timeout-ms')
const evidenceFile = args.evidence || process.env.HIVERELAY_FLEET_ROLLOUT_EVIDENCE || ''
const dryRun = Boolean(args.dryRun)
const targetSha = args.targetSha || await resolveTargetSha(target)
const targetVersion = target.slice(1)
const relays = selectRelays(readInventory(relaysPath), channel)
const channelTargets = validateChannelTargets(readChannels(channelsPath), channel, target)
const inventorySha256 = sha256File(relaysPath, 'fleet inventory')
const channelsSha256 = sha256File(channelsPath, 'fleet channel config')
const inventoryPath = pathForEvidence(relaysPath)
const channelsEvidencePath = pathForEvidence(channelsPath)

if (!/^[a-f0-9]{40}$/i.test(targetSha)) die(`Invalid target SHA "${targetSha}".`)
if (!relays.length) die(`No relays matched channel "${channel}" in ${relaysPath}.`)

console.log(`Fleet rollout target: ${target} (${targetSha})`)
console.log(`Checking ${relays.length} relay(s) on channel ${channel}: ${relays.map((r) => r.name).join(', ')}`)

if (dryRun) {
  writeRolloutEvidence('dry-run', relays.map((relay) => ({ relay })))
  console.log('dry-run: not opening SSH connections')
  process.exit(0)
}

const deadline = Date.now() + timeoutMs
let lastResults = []
while (Date.now() < deadline) {
  lastResults = await Promise.all(relays.map((relay) => probeRelay(relay)))
  printResults(lastResults)
  if (lastResults.every((result) => result.updated && result.packageVersionMatches && result.healthy && result.runtimeVersionMatches)) {
    writeRolloutEvidence('verified', lastResults)
    console.log(`Fleet rollout verified: ${relays.length}/${relays.length} relay(s) on ${target}`)
    process.exit(0)
  }
  await sleep(Math.min(intervalMs, Math.max(0, deadline - Date.now())))
}

console.error(`Fleet rollout did not converge within ${timeoutMs}ms.`)
printResults(lastResults, { stderr: true })
writeRolloutEvidence('failed', lastResults, `timeout after ${timeoutMs}ms`)
process.exit(1)

function parseArgs (argv) {
  const out = { _: [] }
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--help' || arg === '-h') {
      out.help = true
      continue
    }
    if (!arg.startsWith('--')) {
      out._.push(arg)
      continue
    }
    const key = camel(arg.slice(2))
    if (key === 'dryRun') {
      out[key] = true
      continue
    }
    const value = argv[++i]
    if (!value || value.startsWith('--')) die(`Missing value for ${arg}`)
    out[key] = value
  }
  return out
}

function camel (value) {
  return value.replace(/-([a-z])/g, (_, c) => c.toUpperCase())
}

function numberArg (value, fallback, name) {
  if (value == null || value === '') return fallback
  const raw = String(value)
  if (!/^[1-9][0-9]*$/.test(raw)) die(`Invalid --${name} value. Expected a positive integer without whitespace or control characters.`)
  const n = Number(raw)
  if (!Number.isSafeInteger(n)) die(`Invalid --${name} value. Expected a safe positive integer.`)
  return n
}

function readInventory (file) {
  const json = JSON.parse(readFleetMetadataFile(file, 'fleet inventory', 'utf8'))
  if (!Array.isArray(json.relays)) die(`${file} is missing a relays array.`)
  return json.relays
}

function readChannels (file) {
  const json = JSON.parse(readFleetMetadataFile(file, 'fleet channel config', 'utf8'))
  if (!json || typeof json !== 'object' || Array.isArray(json)) die(`${file} must be a JSON object.`)
  return json
}

function validateChannelTargets (channels, requestedChannel, expectedTarget) {
  const required = requiredChannelNames(channels, requestedChannel)
  const out = {}
  for (const name of required) {
    const value = channels[name]
    if (typeof value !== 'string' || !value) die(`fleet channel ${name} is missing a release target in ${channelsPath}.`)
    const safeName = validatePublicLabel(name, 'fleet channel name', 32)
    const safeValue = validatePublicLabel(value, `fleet channel ${name} target`, 80)
    if (safeValue !== expectedTarget) {
      die(`fleet channel ${name} target is ${safeValue}; expected ${expectedTarget}. Run npm run release:prepare or update fleet/channels.json before checking rollout.`)
    }
    out[safeName] = safeValue
  }
  return out
}

function requiredChannelNames (channels, requestedChannel) {
  if (requestedChannel === 'both') return ['canary', 'stable']
  if (requestedChannel === 'all') {
    const names = Object.keys(channels)
      .filter((name) => !name.startsWith('_'))
      .sort()
    if (names.length === 0) die(`${channelsPath} does not define any fleet channels.`)
    return names
  }
  return [requestedChannel]
}

function selectRelays (allRelays, requestedChannel) {
  const allowed = new Set()
  let includeAll = false
  if (requestedChannel === 'all') {
    includeAll = true
  } else if (requestedChannel === 'both') {
    allowed.add('stable')
    allowed.add('canary')
  } else if (/^[A-Za-z0-9._-]{1,32}$/.test(requestedChannel)) {
    allowed.add(requestedChannel)
  } else {
    die(`Invalid --channel "${requestedChannel}".`)
  }
  const selected = []
  const selectedNames = new Set()
  for (const raw of allRelays) {
    const rawChannel = raw.channel || 'stable'
    if (!includeAll && !allowed.has(rawChannel)) continue
    const name = validatePublicLabel(raw.name || '(unnamed)', 'relay name', 80)
    const relayChannel = validatePublicLabel(rawChannel, 'relay channel', 32)
    const host = raw.tailnet || raw.publicIp
    if (!host) continue
    if (selectedNames.has(name)) {
      die(`Duplicate relay name "${name}" in selected fleet channel "${requestedChannel}". Relay names must be unique before rollout evidence is written.`)
    }
    selectedNames.add(name)
    selected.push({
      name,
      channel: relayChannel,
      host: validateSshHost(host, `relay host for ${name}`),
      sshKey: validateLocalPath(raw.sshKey || '', `ssh key for ${name}`)
    })
  }
  return selected
}

async function resolveTargetSha (tag) {
  const result = await runLocal('git', ['rev-parse', `${tag}^{commit}`], { cwd: repoRoot, timeoutMs: 10000 })
  if (result.code !== 0) die(`Could not resolve ${tag}^{commit}; fetch tags first.\n${result.stderr.trim()}`)
  return result.stdout.trim()
}

async function probeRelay (relay) {
  const observedAt = new Date().toISOString()
  const key = sshKey || normalizeInventoryKey(relay.sshKey)
  const sshArgs = [
    '-o', 'BatchMode=yes',
    '-o', 'StrictHostKeyChecking=accept-new',
    '-o', 'ConnectTimeout=10',
    '-o', 'ServerAliveInterval=5',
    '-o', 'ServerAliveCountMax=2'
  ]
  if (key) sshArgs.push('-i', expandHome(key))
  sshArgs.push(`${sshUser}@${relay.host}`, 'bash', '-s')

  const result = await runLocal(sshCommand, sshArgs, {
    input: remoteProbeScript(),
    timeoutMs: sshTimeoutMs
  })

  if (result.code !== 0) {
    return {
      relay,
      observedAt,
      ok: false,
      updated: false,
      healthy: false,
      error: result.timedOut ? 'ssh timed out' : safeProbeError(result.stderr || result.stdout || `ssh exited ${result.code}`)
    }
  }

  const line = result.stdout.trim().split(/\r?\n/).pop() || ''
  const [headSha, version, running, disk, healthVersion, health] = line.split('\t')
  const updated = headSha === targetSha
  const packageVersionMatches = version === target
  const healthy = running === 'true'
  const runtimeVersionMatches = healthVersion === targetVersion
  return {
    relay,
    observedAt,
    ok: true,
    updated,
    packageVersionMatches,
    healthy,
    runtimeVersionMatches,
    headSha,
    version,
    healthVersion,
    running,
    disk,
    health
  }
}

function normalizeInventoryKey (key) {
  if (!key || key === 'default') return ''
  return key
}

function expandHome (value) {
  if (value === '~') return process.env.HOME || value
  if (value.startsWith('~/')) return path.join(process.env.HOME || '', value.slice(2))
  return value
}

function remoteProbeScript () {
  const repoLine = remoteRepoDir
    ? `repo=${shellQuote(remoteRepoDir)}`
    : 'repo="$' + '{HIVERELAY_REMOTE_REPO_DIR:-$HOME/hiverelay}"'
  const serviceLine = `service=${shellQuote(service)}`
  const apiLine = `api=${shellQuote(api)}`
  return String.raw`set -euo pipefail
${repoLine}
${serviceLine}
${apiLine}
env_file="\${HIVERELAY_ENV_FILE:-/etc/hiverelay/hiverelay.env}"
cd -- "$repo"
head_sha="$(git rev-parse HEAD 2>/dev/null || true)"
version="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' package.json | head -n 1)"
[ -n "$version" ] && version="v$version"
read_api_key() {
  local key
  key="$(systemctl show "$service" -p Environment 2>/dev/null | awk 'BEGIN{RS=" "} /^HIVERELAY_API_KEY=/{sub(/^HIVERELAY_API_KEY=/,""); print; exit}' || true)"
  if [ -z "$key" ] && [ -r "$env_file" ]; then
    key="$(awk -F= '/^[[:space:]]*HIVERELAY_API_KEY[[:space:]]*=/ { sub(/^[^=]*=/,""); sub(/^[[:space:]]*/,""); print; exit }' "$env_file" 2>/dev/null || true)"
  fi
  key="\${key%\"}"
  key="\${key#\"}"
  key="\${key%\'}"
  key="\${key#\'}"
  if [ -n "$key" ]; then printf '%s\n' "$key"; fi
  return 0
}
curl_with_optional_key() {
  local key="$1"
  shift
  if [ -z "$key" ]; then
    curl "$@" || return $?
    return 0
  fi
  if printf '%s' "$key" | LC_ALL=C grep -q '[[:cntrl:]]'; then
    return 2
  fi
  local header_file status
  header_file="$(mktemp)"
  chmod 600 "$header_file" 2>/dev/null || true
  printf 'Authorization: Bearer %s\n' "$key" > "$header_file"
  status=0
  curl -H "@$header_file" "$@" || status=$?
  rm -f "$header_file"
  return "$status"
}
key="$(read_api_key)"
health="$(curl_with_optional_key "$key" -fsS --max-time 10 "$api/health" 2>/dev/null || true)"
if printf '%s' "$health" | grep -q '"running":true'; then running=true; else running=false; fi
health_version="$(printf '%s' "$health" | sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
disk="$(df -h / | awk 'NR==2{print $5}')"
printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$head_sha" "$version" "$running" "$disk" "$health_version" "$(printf '%s' "$health" | tr '\n\t' '  ' | cut -c1-180)"
`
}

function validateLocalCommand (value) {
  const text = String(value || '').trim()
  if (!text) die('Invalid --ssh-command value.')
  if (hasControlChars(text)) die('Invalid --ssh-command value: control characters are not allowed.')
  return text
}

function validateLocalPath (value, label) {
  const text = String(value || '').trim()
  if (!text || text === 'default') return text
  if (hasControlChars(text)) die(`Invalid --${label} value: control characters are not allowed.`)
  if (text.length > 1024) die(`Invalid --${label} value: path is too long.`)
  return text
}

function validateRemotePath (value, label) {
  const text = String(value || '').trim()
  if (!text) return ''
  if (hasControlChars(text)) die(`Invalid --${label} value: control characters are not allowed.`)
  if (text.length > 1024) die(`Invalid --${label} value: path is too long.`)
  return text
}

function validateSshUser (value) {
  const text = String(value || '').trim()
  if (!/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(text)) {
    die(`Invalid --ssh-user "${value}". Expected a local account name without SSH options.`)
  }
  return text
}

function validateServiceName (value) {
  const text = String(value || '').trim()
  if (!/^[A-Za-z0-9@_.:-]{1,128}$/.test(text) || text.startsWith('-')) {
    die(`Invalid --service "${value}". Expected a systemd service name without options.`)
  }
  return text
}

function normalizeApiBase (value) {
  const text = String(value || '').trim()
  assertPublicSafeString(text, 'fleet rollout API URL', '$.probes.api')
  let url
  try {
    url = new URL(text)
  } catch (_) {
    die(`Invalid --api "${value}". Expected an http(s) URL.`)
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    die(`Invalid --api "${value}". Expected an http(s) URL.`)
  }
  if (!url.hostname) die(`Invalid --api "${value}". Expected a hostname.`)
  if (!isLoopbackHostname(url.hostname)) {
    die(`Invalid --api "${value}". Expected a loopback URL because fleet rollout probes run on each relay over SSH.`)
  }
  if (url.search || url.hash) die(`Invalid --api "${value}". Expected a base URL without query strings or fragments.`)
  return text.replace(/\/+$/, '')
}

function isLoopbackHostname (hostname) {
  const host = String(hostname || '').toLowerCase()
  return host === 'localhost' ||
    host === '::1' ||
    host === '[::1]' ||
    host === '0:0:0:0:0:0:0:1' ||
    isLoopbackIpv4(host)
}

function isLoopbackIpv4 (host) {
  const parts = host.split('.')
  return parts.length === 4 &&
    parts[0] === '127' &&
    parts.slice(1).every((part) => /^[0-9]{1,3}$/.test(part) && Number(part) <= 255)
}

function validatePublicLabel (value, label, maxLength) {
  const text = String(value || '').trim()
  if (!text) die(`Invalid ${label}: empty values are not allowed.`)
  if (text.length > maxLength) die(`Invalid ${label}: value is too long.`)
  assertPublicSafeString(text, `fleet rollout ${label}`, '$')
  return text
}

function validateSshHost (value, label) {
  const text = String(value || '').trim()
  if (!text) die(`Invalid ${label}: empty host.`)
  if (text.length > 253) die(`Invalid ${label}: host is too long.`)
  if (
    text.startsWith('-') ||
    text.includes('@') ||
    /\s/.test(text) ||
    !/^[A-Za-z0-9._:[\]-]+$/.test(text)
  ) {
    die(`Invalid ${label}: expected a hostname, IP address, or tailnet name without SSH options.`)
  }
  assertPublicSafeString(text, 'fleet rollout relay host', '$')
  return text
}

function shellQuote (value) {
  return "'" + String(value).replace(/'/g, "'\\''") + "'"
}

function printResults (results, opts = {}) {
  const write = opts.stderr ? console.error : console.log
  write(formatRow(['relay', 'channel', 'pkg', 'live', 'head', 'target', 'health', 'disk', 'note']))
  for (const result of results) {
    const relay = result.relay
    const note = result.ok
      ? (
          result.updated && result.packageVersionMatches && result.healthy && result.runtimeVersionMatches
            ? 'ok'
            : !result.updated
                ? 'waiting-repo'
                : !result.packageVersionMatches
                    ? 'waiting-package-version'
                    : !result.runtimeVersionMatches
                        ? 'waiting-runtime-version'
                        : 'waiting-health'
        )
      : result.error
    write(formatRow([
      relay.name,
      relay.channel,
      result.version || '-',
      result.healthVersion || '-',
      shortSha(result.headSha),
      shortSha(targetSha),
      result.healthy ? 'green' : 'red',
      result.disk || '-',
      note
    ]))
  }
}

function writeRolloutEvidence (status, results, error = '') {
  if (!evidenceFile) return
  assertVerifiedProbeTiming(status)
  const generatedAt = new Date().toISOString()
  const relays = results.map((result) => {
    const relay = result.relay
    const note = rolloutNote(result)
    return {
      name: relay.name,
      channel: relay.channel,
      packageVersion: result.version || '',
      healthVersion: result.healthVersion || '',
      observedAt: result.observedAt || generatedAt,
      headSha: result.headSha || '',
      targetSha,
      updated: Boolean(result.updated),
      packageVersionMatches: Boolean(result.packageVersionMatches),
      healthy: Boolean(result.healthy),
      runtimeVersionMatches: Boolean(result.runtimeVersionMatches),
      disk: result.disk || '',
      note,
      error: result.error || ''
    }
  })
  const evidence = {
    schemaVersion: 1,
    generatedAt,
    status,
    target: {
      tag: target,
      version: targetVersion,
      sha: targetSha,
      channel
    },
    inventory: {
      path: inventoryPath,
      sha256: inventorySha256,
      relayNames: relays.map((relay) => relay.name)
    },
    channelConfig: {
      path: channelsEvidencePath,
      sha256: channelsSha256,
      targets: channelTargets
    },
    probes: {
      timeoutMs,
      intervalMs,
      sshTimeoutMs,
      service,
      api
    },
    summary: {
      total: relays.length,
      updated: relays.filter((relay) => relay.updated).length,
      packageVersionMatches: relays.filter((relay) => relay.packageVersionMatches).length,
      healthy: relays.filter((relay) => relay.healthy).length,
      runtimeVersionMatches: relays.filter((relay) => relay.runtimeVersionMatches).length
    },
    relays
  }
  if (error) evidence.error = error

  assertPublicSafeValues(evidence, 'fleet rollout evidence')
  assertFleetRolloutEvidenceSchema(evidence)
  fs.mkdirSync(path.dirname(path.resolve(evidenceFile)), { recursive: true })
  const tmp = `${evidenceFile}.tmp-${process.pid}`
  fs.writeFileSync(tmp, JSON.stringify(evidence, null, 2) + '\n')
  fs.renameSync(tmp, evidenceFile)
}

function assertVerifiedProbeTiming (status) {
  if (status !== 'verified') return
  requireIntegerRange('verified fleet rollout timeoutMs', timeoutMs, FLEET_ROLLOUT_TIMEOUT_MIN_MS, FLEET_ROLLOUT_TIMEOUT_MAX_MS)
  requireIntegerRange('verified fleet rollout intervalMs', intervalMs, FLEET_ROLLOUT_INTERVAL_MIN_MS, FLEET_ROLLOUT_INTERVAL_MAX_MS)
  requireIntegerRange('verified fleet rollout sshTimeoutMs', sshTimeoutMs, FLEET_ROLLOUT_SSH_TIMEOUT_MIN_MS, FLEET_ROLLOUT_SSH_TIMEOUT_MAX_MS)
}

function requireIntegerRange (label, value, min, max) {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    die(`${label} must be an integer between ${min} and ${max}`)
  }
}

function assertFleetRolloutEvidenceSchema (evidence) {
  requireOnlyKeys('fleet rollout evidence', evidence, [
    'schemaVersion',
    'generatedAt',
    'status',
    'target',
    'inventory',
    'channelConfig',
    'probes',
    'summary',
    'relays',
    'error'
  ])
  requireOnlyKeys('fleet rollout target', evidence.target, ['tag', 'version', 'sha', 'channel'])
  requireOnlyKeys('fleet rollout inventory', evidence.inventory, ['path', 'sha256', 'relayNames'])
  requireOnlyKeys('fleet rollout channel config', evidence.channelConfig, ['path', 'sha256', 'targets'])
  requireOnlyKeys('fleet rollout channel config targets', evidence.channelConfig.targets, Object.keys(channelTargets))
  requireOnlyKeys('fleet rollout probes', evidence.probes, ['timeoutMs', 'intervalMs', 'sshTimeoutMs', 'service', 'api'])
  requireOnlyKeys('fleet rollout summary', evidence.summary, [
    'total',
    'updated',
    'packageVersionMatches',
    'healthy',
    'runtimeVersionMatches'
  ])
  if (Array.isArray(evidence.relays)) {
    for (const relay of evidence.relays) {
      requireOnlyKeys(`fleet rollout relay ${relay?.name || '(unnamed)'}`, relay, [
        'name',
        'channel',
        'packageVersion',
        'healthVersion',
        'observedAt',
        'headSha',
        'targetSha',
        'updated',
        'packageVersionMatches',
        'healthy',
        'runtimeVersionMatches',
        'disk',
        'note',
        'error'
      ])
    }
  }
}

function requireOnlyKeys (label, value, allowed) {
  if (value == null || typeof value !== 'object' || Array.isArray(value)) {
    die(`${label} must be an object`)
  }
  const allowedSet = new Set(allowed)
  const extra = Object.keys(value).filter(key => !allowedSet.has(key))
  if (extra.length > 0) die(`${label} has unsupported fields: ${extra.join(', ')}`)
}

function pathForEvidence (file) {
  const rel = path.relative(repoRoot, path.resolve(file))
  if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) return path.basename(file)
  return rel
}

function sha256File (file, label) {
  return crypto.createHash('sha256').update(readFleetMetadataFile(file, label)).digest('hex')
}

function readFleetMetadataFile (file, label, encoding) {
  const stat = fs.lstatSync(file)
  if (stat.isSymbolicLink()) die(`${label} file must not be a symlink: ${file}`)
  if (!stat.isFile()) die(`${label} file must be a regular file: ${file}`)
  if (stat.size > MAX_FLEET_METADATA_BYTES) {
    die(`${label} file must be ${MAX_FLEET_METADATA_BYTES} bytes or smaller: ${file} is ${stat.size} bytes`)
  }
  return fs.readFileSync(file, encoding)
}

function assertPublicSafeValues (value, label) {
  visit(value, '$')

  function visit (node, at) {
    if (node == null) return
    if (typeof node === 'string') {
      assertPublicSafeString(node, label, at)
      return
    }
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i++) visit(node[i], `${at}[${i}]`)
      return
    }
    if (typeof node === 'object') {
      for (const [key, child] of Object.entries(node)) visit(child, `${at}.${key}`)
    }
  }
}

function assertPublicSafeString (value, label, at) {
  if (hasControlChars(value)) die(`${label} must not contain control characters at ${at}`)
  for (const [pattern, name] of FORBIDDEN_PUBLIC_VALUE_PATTERNS) {
    if (pattern.test(value)) die(`${label} must not contain ${name} at ${at}`)
  }
  try {
    const url = new URL(value)
    if (url.username || url.password) die(`${label} must not expose URL credentials at ${at}`)
  } catch (_) {}
}

function hasControlChars (value) {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if (code <= 31 || code === 127) return true
  }
  return false
}

function rolloutNote (result) {
  if (result.ok === undefined) return 'dry-run'
  if (!result.ok) return result.error || 'probe-failed'
  if (!result.updated) return 'waiting-repo'
  if (!result.packageVersionMatches) return 'waiting-package-version'
  if (!result.runtimeVersionMatches) return 'waiting-runtime-version'
  if (!result.healthy) return 'waiting-health'
  return 'ok'
}

function formatRow (cells) {
  const widths = [12, 9, 10, 10, 10, 10, 8, 6, 28]
  return cells.map((cell, i) => String(cell || '').slice(0, widths[i]).padEnd(widths[i])).join(' ')
}

function shortSha (sha) {
  return sha ? sha.slice(0, 8) : '-'
}

function oneLine (value) {
  return String(value).replace(/\s+/g, ' ').trim().slice(0, 180)
}

function safeProbeError (value) {
  return oneLine(redactSensitiveOutput(value))
}

function redactSensitiveOutput (value) {
  const redacted = String(value)
    .replace(/-----BEGIN [A-Z ]*(?:PRIVATE|SECRET) KEY-----[\s\S]*?-----END [A-Z ]*(?:PRIVATE|SECRET) KEY-----/g, '[redacted key block]')
    .replace(/\bAuthorization\s*:\s*[^\r\n]*/gi, '[redacted authorization header]')
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]{8,}\b/gi, '[redacted bearer token]')
    .replace(/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b/g, '[redacted GitHub token]')
    .replace(/\bgithub_pat_[A-Za-z0-9_]{20,}\b/g, '[redacted GitHub token]')
    .replace(/\bAPP_SEED=[^\s'"]+/gi, '[redacted APP_SEED]')
    .replace(/\bHIVERELAY_API_KEY=[^\s'"]+/gi, '[redacted HIVERELAY_API_KEY]')
    .replace(/\bsk-[A-Za-z0-9_-]{20,}\b/g, '[redacted API key]')
    .replace(/(\bhttps?:\/\/)([^/\s:@]+):([^@\s/]+)@/gi, '$1[redacted]@')
  return stripControlChars(redacted)
}

function stripControlChars (value) {
  let out = ''
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    out += code <= 31 || code === 127 ? ' ' : value[i]
  }
  return out
}

function runLocal (cmd, args, options = {}) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, {
      cwd: options.cwd || repoRoot,
      stdio: ['pipe', 'pipe', 'pipe']
    })
    let stdout = ''
    let stderr = ''
    let timedOut = false
    const timer = setTimeout(() => {
      timedOut = true
      child.kill('SIGKILL')
    }, options.timeoutMs || 30000)
    child.stdout.on('data', (chunk) => { stdout += chunk })
    child.stderr.on('data', (chunk) => { stderr += chunk })
    child.on('error', (err) => {
      clearTimeout(timer)
      resolve({ code: 127, stdout, stderr: err.message, timedOut })
    })
    child.on('close', (code) => {
      clearTimeout(timer)
      resolve({ code, stdout, stderr, timedOut })
    })
    if (options.input) child.stdin.end(options.input)
    else child.stdin.end()
  })
}

function sleep (ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function die (message) {
  console.error(message)
  process.exit(1)
}
