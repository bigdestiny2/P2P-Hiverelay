import { Resolver } from 'node:dns/promises'
import { randomInt } from 'node:crypto'
import { createSocket } from 'node:dgram'
import { BlockList, createConnection, isIP } from 'node:net'

const MAX_NGINX_INSPECTION_BYTES = 8 * 1024 * 1024
const MAX_DNS_WIRE_BYTES = 4096
const MAX_DNS_RESOURCE_RECORDS = 128
const MAX_DNS_ROUTING_RECORDS = 8
const MAX_DNS_SERVERS = 3
const DNS_ROUTING_TYPES = Object.freeze({ SVCB: 64, HTTPS: 65 })
const HIVE_Z32_ALPHABET = 'ybndrfg8ejkmcpqxot1uwisza345h769'
const NGINX_UPSTREAM_DIRECTIVES = new Set([
  'proxy_pass',
  'fastcgi_pass',
  'uwsgi_pass',
  'scgi_pass',
  'grpc_pass'
])
const NGINX_DEFAULT_DIRECTIVES = new Set([
  'listen',
  'server_name',
  'ssl_certificate',
  'ssl_certificate_key',
  'ssl_protocols',
  'ssl_session_tickets',
  'gzip',
  'gunzip',
  'access_log',
  'error_log',
  'return'
])
const NGINX_REVIEWED_MAIN_DIRECTIVES = new Set([
  'daemon',
  'env',
  'error_log',
  'lock_file',
  'master_process',
  'pcre_jit',
  'pid',
  'thread_pool',
  'timer_resolution',
  'user',
  'worker_cpu_affinity',
  'worker_priority',
  'worker_processes',
  'worker_rlimit_core',
  'worker_rlimit_nofile',
  'working_directory'
])
const NGINX_REVIEWED_HTTP_PARENT_DIRECTIVES = new Set([
  'access_log',
  'client_body_timeout',
  'client_header_timeout',
  'default_type',
  'error_log',
  'include',
  'keepalive_requests',
  'keepalive_timeout',
  'large_client_header_buffers',
  'limit_req_zone',
  'limit_conn_zone',
  'lingering_close',
  'lingering_time',
  'lingering_timeout',
  'log_format',
  'open_file_cache',
  'open_file_cache_errors',
  'open_file_cache_min_uses',
  'open_file_cache_valid',
  'read_ahead',
  'reset_timedout_connection',
  'send_timeout',
  'sendfile',
  'server_names_hash_bucket_size',
  'server_names_hash_max_size',
  'ssl_prefer_server_ciphers',
  'ssl_protocols',
  'tcp_nodelay',
  'tcp_nopush',
  'types_hash_bucket_size',
  'types_hash_max_size'
])
const NGINX_REVIEWED_EVENTS_DIRECTIVES = new Set([
  'accept_mutex',
  'accept_mutex_delay',
  'debug_connection',
  'multi_accept',
  'use',
  'worker_connections'
])

const FORBIDDEN_IPV4 = new BlockList()
for (const [network, prefix] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.88.99.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4]
]) FORBIDDEN_IPV4.addSubnet(network, prefix, 'ipv4')

const FORBIDDEN_IPV6 = new BlockList()
for (const [network, prefix] of [
  ['::', 128],
  ['::1', 128],
  ['::ffff:0:0', 96],
  ['64:ff9b::', 96],
  ['100::', 64],
  ['2001:db8::', 32],
  ['2001:10::', 28],
  ['2002::', 16],
  ['fc00::', 7],
  ['fe80::', 10],
  ['ff00::', 8]
]) FORBIDDEN_IPV6.addSubnet(network, prefix, 'ipv6')

export async function collectPublicHiveGatewayQuarantineDns (contract, opts = {}) {
  const resolver = opts.resolver || new Resolver()
  const resolveRouting = opts.resolveRoutingRecords || ((hostname, rrtype) =>
    resolvePublicHiveGatewayRoutingRecords(hostname, rrtype, {
      resolver,
      servers: opts.servers,
      timeoutMs: opts.timeoutMs
    }))
  const witnessHostname = witnessHostnameFor(contract)
  const app = await resolveDnsAnswer(resolver, contract.appHostname)
  const witness = await resolveDnsAnswer(resolver, witnessHostname)
  return {
    hostname: contract.appHostname,
    witnessHostname,
    app,
    witness,
    routing: {
      app: {
        https: await resolveRouting(contract.appHostname, 'HTTPS'),
        svcb: await resolveRouting(contract.appHostname, 'SVCB')
      },
      witness: {
        https: await resolveRouting(witnessHostname, 'HTTPS'),
        svcb: await resolveRouting(witnessHostname, 'SVCB')
      }
    }
  }
}

export async function resolvePublicHiveGatewayRoutingRecords (hostname, rrtype, opts = {}) {
  const name = normalizeDnsWireHostname(hostname)
  const typeName = String(rrtype || '').toUpperCase()
  const type = DNS_ROUTING_TYPES[typeName]
  if (!type) throw new Error('operator DNS routing RR type must be HTTPS or SVCB')
  const timeoutMs = opts.timeoutMs == null ? 5000 : Number(opts.timeoutMs)
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 50 || timeoutMs > 30000) {
    throw new Error('operator DNS routing timeout must be an integer from 50 to 30000 milliseconds')
  }
  const resolver = opts.resolver || new Resolver()
  const servers = normalizeDnsServers(opts.servers || resolver.getServers?.())
  const deadline = Date.now() + timeoutMs
  const failures = []
  for (let index = 0; index < servers.length; index++) {
    const remaining = deadline - Date.now()
    if (remaining <= 0) break
    const attemptBudget = Math.max(50, Math.floor(remaining / (servers.length - index)))
    const attemptDeadline = Math.min(deadline, Date.now() + attemptBudget)
    const id = randomInt(0, 65536)
    const query = encodeDnsRoutingQuery(id, name, type)
    try {
      const udp = await exchangeDnsUdp(query, servers[index], attemptDeadline)
      let parsed = parseDnsRoutingResponse(udp, { id, name, type, allowTruncated: true })
      if (parsed.truncated) {
        const tcp = await exchangeDnsTcp(query, servers[index], attemptDeadline)
        parsed = parseDnsRoutingResponse(tcp, { id, name, type, allowTruncated: false })
      }
      return parsed.records
    } catch (err) {
      failures.push(`server ${index + 1}: ${boundedDnsError(err)}`)
    }
  }
  throw new Error(`operator DNS ${typeName} resolution failed (${failures.join('; ') || 'absolute deadline exceeded'})`)
}

export function inspectPublicHiveGatewayQuarantineDns (snapshot, contract) {
  const errors = []
  const expected = contract.expectedAddresses.map(address => requirePublicAddress(address, 'signed expected address'))
  const expectedIpv4 = expected.filter(address => isIP(address) === 4).sort(compareAddresses)
  const expectedIpv6 = expected.filter(address => isIP(address) === 6).sort(compareAddresses)
  const observed = []

  for (const [label, answer] of [['app', snapshot?.app], ['wildcard witness', snapshot?.witness]]) {
    if (!answer || typeof answer !== 'object' || Array.isArray(answer)) {
      errors.push(`${label} DNS answer is invalid`)
      continue
    }
    const ipv4 = normalizeObservedAddresses(answer.ipv4, 4, `${label} A`, errors)
    const ipv6 = normalizeObservedAddresses(answer.ipv6, 6, `${label} AAAA`, errors)
    observed.push(...ipv4, ...ipv6)
    compareAddressSets(ipv4, expectedIpv4, `${label} A`, errors)
    compareAddressSets(ipv6, expectedIpv6, `${label} AAAA`, errors)
    if (!Array.isArray(answer.cnames) || answer.cnames.length !== 0) {
      errors.push(`${label} DNS must not contain CNAME indirection`)
    }
  }

  for (const label of ['app', 'witness']) {
    const routing = snapshot?.routing?.[label]
    if (!routing || !Array.isArray(routing.https) || !Array.isArray(routing.svcb) ||
        routing.https.length !== 0 || routing.svcb.length !== 0) {
      errors.push(`${label} DNS HTTPS and SVCB RRsets must be empty`)
    }
  }

  const probeAddresses = [...new Set([...expected, ...observed])].sort(compareAddresses)
  return { ok: errors.length === 0, errors, probeAddresses }
}

export function inspectPublicHiveGatewayQuarantineNginx (text, opts = {}) {
  const errors = []
  if (typeof text !== 'string' || Buffer.byteLength(text) < 1 ||
      Buffer.byteLength(text) > MAX_NGINX_INSPECTION_BYTES) {
    return { ok: false, errors: ['quarantine nginx dump must be a bounded non-empty string'] }
  }
  const suffix = normalizeHostSuffix(opts.suffix)
  if (!suffix) return { ok: false, errors: ['quarantine expected suffix is invalid'] }
  const parsed = parseNginxStatements(stripNginxComments(text))
  if (!parsed.ok) return { ok: false, errors: ['quarantine nginx structure could not be inspected safely'] }
  inspectReviewedNginxDirectivePosture(parsed.nodes, errors)
  if (findNginxBlocksWithContext(parsed.nodes, 'stream').length > 0) {
    errors.push('quarantine forbids nginx stream context and stream includes')
  }
  const serverRecords = findNginxBlocksWithContext(parsed.nodes, 'server')
  const foreignTlsServers = serverRecords.filter(record =>
    !isHttpServerContext(record) && directDirectives(record.block, 'listen').some(isPort443Listen))
  if (foreignTlsServers.length > 0) {
    errors.push('quarantine TLS port 443 server blocks must be in HTTP context')
  }
  const tlsBlocks = serverRecords
    .filter(isHttpServerContext)
    .map(record => record.block)
    .filter(block => directDirectives(block, 'listen').some(isPort443Listen))
  const defaults = tlsBlocks.filter(block => directDirectives(block, 'listen').some(isDefaultTls443Listen))
  if (defaults.length !== 1 || !isSafeDefaultServer(defaults[0])) {
    errors.push('quarantine requires exactly one safe TLS 421 default server')
  }
  for (const block of tlsBlocks) {
    if (directDirectives(block, 'listen').some(directive => directive.args.includes('quic'))) {
      errors.push('quarantine must not expose a QUIC listener')
    }
    if (block === defaults[0]) continue
    const names = directDirectives(block, 'server_name').flatMap(directive => directive.args)
    if (names.some(name => serverNameCanMatchHiveApp(name, suffix))) {
      errors.push('quarantine has a sibling TLS vhost capable of matching an app host')
    }
    if (!hasExactPublicTlsListeners(directDirectives(block, 'listen'), false)) {
      errors.push('quarantine sibling TLS vhosts must use only the shared wildcard 443 ssl listen tuples')
    }
    if (names.length === 0 || names.some(name => !isExplicitDisjointServerName(name, suffix))) {
      errors.push('quarantine sibling TLS vhosts require explicit server_name values disjoint from the app suffix')
    }
  }
  if (allDirectives({ children: parsed.nodes }, 'add_header').some(directive =>
    String(directive.args[0] || '').toLowerCase() === 'alt-svc' &&
    directive.args.slice(1).join(' ').toLowerCase().includes('h3'))) {
    errors.push('quarantine must not advertise HTTP/3')
  }
  return { ok: errors.length === 0, errors }
}

function inspectReviewedNginxDirectivePosture (nodes, errors) {
  const rejected = []
  const isReviewedTypesBlock = node => node.kind === 'block' &&
    node.name === 'types' &&
    node.children.every(child => child.kind === 'directive')
  const reviewedParentCompression = node => node.kind === 'directive' && (
    (node.name === 'gzip' && (sameArgs(node.args, ['on']) || sameArgs(node.args, ['off']))) ||
    (node.name === 'gunzip' && sameArgs(node.args, ['off'])))
  const inspectHttpChildren = children => {
    for (const node of children) {
      if (node.kind === 'directive') {
        if (!NGINX_REVIEWED_HTTP_PARENT_DIRECTIVES.has(node.name) && !reviewedParentCompression(node)) {
          rejected.push(node.name)
        }
      } else if (node.name !== 'server' && !isReviewedTypesBlock(node)) {
        rejected.push(`${node.name} {}`)
      }
    }
  }
  for (const node of nodes) {
    if (node.kind === 'directive') {
      if (!NGINX_REVIEWED_MAIN_DIRECTIVES.has(node.name) &&
          !NGINX_REVIEWED_HTTP_PARENT_DIRECTIVES.has(node.name) &&
          !reviewedParentCompression(node)) rejected.push(node.name)
      continue
    }
    if (node.name === 'events') {
      for (const child of node.children) {
        if (child.kind !== 'directive' || !NGINX_REVIEWED_EVENTS_DIRECTIVES.has(child.name)) {
          rejected.push(child.kind === 'block' ? `${child.name} {}` : child.name)
        }
      }
    } else if (node.name === 'http') {
      inspectHttpChildren(node.children)
    } else if (node.name !== 'server' && !isReviewedTypesBlock(node)) {
      rejected.push(`${node.name} {}`)
    }
  }
  if (rejected.length > 0) {
    errors.push(`quarantine rejects unreviewed inherited HTTP/module directives or blocks: ${[...new Set(rejected)].sort().slice(0, 8).join(', ')}`)
  }
}

function normalizeObservedAddresses (value, family, label, errors) {
  if (!Array.isArray(value) || value.length > 16) {
    errors.push(`${label} RRset must be a bounded array`)
    return []
  }
  const normalized = []
  for (const address of value) {
    try {
      const canonical = requirePublicAddress(address, `${label} address`)
      if (isIP(canonical) !== family) throw new Error(`${label} address has the wrong family`)
      normalized.push(canonical)
    } catch (err) {
      errors.push(err.message)
    }
  }
  if (new Set(normalized).size !== normalized.length) errors.push(`${label} RRset contains duplicates`)
  return [...new Set(normalized)].sort(compareAddresses)
}

async function resolveDnsAnswer (resolver, hostname) {
  const [ipv4, ipv6, cnames] = await Promise.all([
    resolveOptional(() => resolver.resolve4(hostname)),
    resolveOptional(() => resolver.resolve6(hostname)),
    resolveOptional(() => resolver.resolveCname(hostname))
  ])
  if (ipv4.length > 16 || ipv6.length > 16 || cnames.length > 8) {
    throw new Error('quarantine DNS response exceeds its RRset bound')
  }
  return { ipv4, ipv6, cnames }
}

async function resolveOptional (operation) {
  try {
    return await operation()
  } catch (err) {
    if (['ENODATA', 'ENOTFOUND', 'NOTFOUND'].includes(err?.code)) return []
    throw new Error(`quarantine DNS resolution failed: ${err?.code || err?.message || 'unknown error'}`)
  }
}

function normalizeDnsWireHostname (value) {
  if (typeof value !== 'string' || value !== value.trim() || value.length < 1 || value.length > 253) {
    throw new Error('operator DNS routing hostname is invalid')
  }
  const name = value.toLowerCase().replace(/\.$/, '')
  const labels = name.split('.')
  if (labels.some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
    throw new Error('operator DNS routing hostname is invalid')
  }
  return name
}

function normalizeDnsServers (values) {
  if (!Array.isArray(values) || values.length < 1 || values.length > MAX_DNS_SERVERS) {
    throw new Error(`operator DNS routing requires 1 to ${MAX_DNS_SERVERS} system resolver servers`)
  }
  const servers = values.map((value, index) => parseDnsServer(value, index))
  if (new Set(servers.map(server => `${server.family}|${server.address}|${server.port}`)).size !== servers.length) {
    throw new Error('operator DNS routing resolver server list contains duplicates')
  }
  return servers
}

function parseDnsServer (value, index) {
  const text = String(value || '')
  if (text !== text.trim() || text.length < 1 || text.length > 256 || /[\r\n\0]/.test(text)) {
    throw new Error(`operator DNS routing resolver server[${index}] is invalid`)
  }
  let address = text
  let port = 53
  if (isIP(address) === 0) {
    const bracketed = /^\[([^\]]+)](?::([0-9]{1,5}))?$/.exec(text)
    const ipv4Port = /^([^:]+):([0-9]{1,5})$/.exec(text)
    if (bracketed && isIP(bracketed[1]) === 6) {
      address = bracketed[1]
      if (bracketed[2]) port = Number(bracketed[2])
    } else if (ipv4Port && isIP(ipv4Port[1]) === 4) {
      address = ipv4Port[1]
      port = Number(ipv4Port[2])
    } else {
      throw new Error(`operator DNS routing resolver server[${index}] is invalid`)
    }
  }
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) {
    throw new Error(`operator DNS routing resolver server[${index}] port is invalid`)
  }
  return { address, port, family: isIP(address) }
}

function encodeDnsRoutingQuery (id, hostname, type) {
  const name = encodeDnsName(hostname)
  const query = Buffer.allocUnsafe(12 + name.length + 4)
  query.writeUInt16BE(id, 0)
  query.writeUInt16BE(0x0100, 2)
  query.writeUInt16BE(1, 4)
  query.fill(0, 6, 12)
  name.copy(query, 12)
  query.writeUInt16BE(type, 12 + name.length)
  query.writeUInt16BE(1, 14 + name.length)
  return query
}

function encodeDnsName (hostname) {
  const parts = []
  for (const label of hostname.split('.')) {
    const bytes = Buffer.from(label, 'ascii')
    if (bytes.length < 1 || bytes.length > 63) throw new Error('operator DNS routing label is invalid')
    parts.push(Buffer.from([bytes.length]), bytes)
  }
  parts.push(Buffer.from([0]))
  return Buffer.concat(parts)
}

function exchangeDnsUdp (query, server, deadline) {
  return new Promise((resolve, reject) => {
    const socket = createSocket(server.family === 6 ? 'udp6' : 'udp4')
    let settled = false
    let timer = null
    const finish = (err, value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      try { socket.close() } catch {}
      if (err) reject(err)
      else resolve(value)
    }
    const remaining = deadline - Date.now()
    if (remaining <= 0) return finish(new Error('UDP query exceeded its absolute deadline'))
    timer = setTimeout(() => finish(new Error('UDP query exceeded its absolute deadline')), remaining)
    socket.once('error', err => finish(new Error(`UDP transport failed: ${boundedDnsError(err)}`)))
    socket.once('message', message => {
      if (message.length < 12 || message.length > MAX_DNS_WIRE_BYTES) {
        return finish(new Error('UDP response is outside its wire-size bound'))
      }
      finish(null, message)
    })
    socket.connect(server.port, server.address, () => {
      socket.send(query, err => {
        if (err) finish(new Error(`UDP send failed: ${boundedDnsError(err)}`))
      })
    })
  })
}

function exchangeDnsTcp (query, server, deadline) {
  return new Promise((resolve, reject) => {
    const socket = createConnection({ host: server.address, port: server.port, family: server.family })
    let settled = false
    let received = Buffer.alloc(0)
    let expectedLength = null
    let timer = null
    const finish = (err, value) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      socket.destroy()
      if (err) reject(err)
      else resolve(value)
    }
    const remaining = deadline - Date.now()
    if (remaining <= 0) return finish(new Error('TCP retry exceeded its absolute deadline'))
    timer = setTimeout(() => finish(new Error('TCP retry exceeded its absolute deadline')), remaining)
    socket.setNoDelay(true)
    socket.once('error', err => finish(new Error(`TCP transport failed: ${boundedDnsError(err)}`)))
    socket.once('end', () => finish(new Error('TCP response ended before one complete DNS frame')))
    socket.on('data', chunk => {
      if (settled) return
      received = Buffer.concat([received, chunk])
      if (received.length > MAX_DNS_WIRE_BYTES + 2) {
        return finish(new Error('TCP response exceeds its wire-size bound'))
      }
      if (expectedLength === null && received.length >= 2) {
        expectedLength = received.readUInt16BE(0)
        if (expectedLength < 12 || expectedLength > MAX_DNS_WIRE_BYTES) {
          return finish(new Error('TCP response frame length is invalid'))
        }
      }
      if (expectedLength !== null && received.length >= expectedLength + 2) {
        if (received.length !== expectedLength + 2) {
          return finish(new Error('TCP response contains trailing data beyond one DNS frame'))
        }
        finish(null, received.subarray(2))
      }
    })
    socket.once('connect', () => {
      const frame = Buffer.allocUnsafe(query.length + 2)
      frame.writeUInt16BE(query.length, 0)
      query.copy(frame, 2)
      socket.write(frame, err => {
        if (err) finish(new Error(`TCP send failed: ${boundedDnsError(err)}`))
      })
    })
  })
}

function parseDnsRoutingResponse (message, expected) {
  if (!Buffer.isBuffer(message) || message.length < 12 || message.length > MAX_DNS_WIRE_BYTES) {
    throw new Error('DNS response is outside its wire-size bound')
  }
  const id = message.readUInt16BE(0)
  const flags = message.readUInt16BE(2)
  const qdcount = message.readUInt16BE(4)
  const ancount = message.readUInt16BE(6)
  const nscount = message.readUInt16BE(8)
  const arcount = message.readUInt16BE(10)
  if (id !== expected.id) throw new Error('DNS response query ID mismatch')
  if ((flags & 0x8000) === 0 || (flags & 0x7800) !== 0 || (flags & 0x0040) !== 0) {
    throw new Error('DNS response has invalid QR, opcode, or reserved flags')
  }
  if ((flags & 0x000f) !== 0) throw new Error(`DNS response returned RCODE ${flags & 0x000f}`)
  if (qdcount !== 1) throw new Error('DNS response must contain exactly one question')
  if (ancount + nscount + arcount > MAX_DNS_RESOURCE_RECORDS) {
    throw new Error('DNS response exceeds its resource-record bound')
  }
  const question = decodeDnsName(message, 12)
  if (question.nextOffset + 4 > message.length) throw new Error('DNS response question is truncated')
  const qtype = message.readUInt16BE(question.nextOffset)
  const qclass = message.readUInt16BE(question.nextOffset + 2)
  let offset = question.nextOffset + 4
  if (question.name !== expected.name || qtype !== expected.type || qclass !== 1) {
    throw new Error('DNS response question does not match the exact query')
  }
  if ((flags & 0x0200) !== 0) {
    if (!expected.allowTruncated) throw new Error('DNS TCP response remains truncated')
    return { truncated: true, records: [] }
  }

  const records = []
  for (let index = 0; index < ancount; index++) {
    const rr = decodeDnsResourceRecord(message, offset)
    offset = rr.nextOffset
    if (rr.type === 5) throw new Error('DNS routing response contains CNAME alias ambiguity')
    if (rr.type !== expected.type || rr.class !== 1 || rr.name !== expected.name) {
      throw new Error('DNS routing answer contains an unexpected owner, class, or RR type')
    }
    records.push(decodeSvcbRecord(message, rr, expected.type))
    if (records.length > MAX_DNS_ROUTING_RECORDS) throw new Error('DNS routing RRset exceeds its record bound')
  }
  for (let index = 0; index < nscount; index++) {
    const rr = decodeDnsResourceRecord(message, offset)
    offset = rr.nextOffset
    if (rr.type === 5) throw new Error('DNS routing response contains CNAME alias ambiguity')
  }
  for (let index = 0; index < arcount; index++) {
    const rr = decodeDnsResourceRecord(message, offset)
    offset = rr.nextOffset
    if (rr.type === 5) throw new Error('DNS routing response contains CNAME alias ambiguity')
    if (rr.type === 41 && (rr.ttl >>> 24) !== 0) throw new Error('DNS response contains a nonzero extended RCODE')
  }
  if (offset !== message.length) throw new Error('DNS response contains trailing or unparsed bytes')
  if (records.filter(record => record.priority === 0).length > 0 && records.length !== 1) {
    throw new Error('DNS routing RRset mixes AliasMode with other records')
  }
  return { truncated: false, records }
}

function decodeDnsResourceRecord (message, offset) {
  const owner = decodeDnsName(message, offset)
  if (owner.nextOffset + 10 > message.length) throw new Error('DNS resource record header is truncated')
  const type = message.readUInt16BE(owner.nextOffset)
  const rrclass = message.readUInt16BE(owner.nextOffset + 2)
  const ttl = message.readUInt32BE(owner.nextOffset + 4)
  const length = message.readUInt16BE(owner.nextOffset + 8)
  const rdataOffset = owner.nextOffset + 10
  const nextOffset = rdataOffset + length
  if (nextOffset > message.length) throw new Error('DNS resource record data is truncated')
  return { name: owner.name, type, class: rrclass, ttl, rdataOffset, rdataEnd: nextOffset, nextOffset }
}

function decodeSvcbRecord (message, rr, type) {
  if (rr.rdataEnd - rr.rdataOffset < 3) throw new Error('DNS HTTPS/SVCB record data is truncated')
  const priority = message.readUInt16BE(rr.rdataOffset)
  const target = decodeDnsName(message, rr.rdataOffset + 2, { allowCompression: false, limit: rr.rdataEnd })
  let offset = target.nextOffset
  let previousKey = -1
  const parameterKeys = []
  while (offset < rr.rdataEnd) {
    if (offset + 4 > rr.rdataEnd) throw new Error('DNS HTTPS/SVCB parameter header is truncated')
    const key = message.readUInt16BE(offset)
    const length = message.readUInt16BE(offset + 2)
    offset += 4
    if (key <= previousKey) throw new Error('DNS HTTPS/SVCB parameters are not strictly ordered')
    if (offset + length > rr.rdataEnd) throw new Error('DNS HTTPS/SVCB parameter value is truncated')
    parameterKeys.push(key)
    previousKey = key
    offset += length
  }
  if (priority === 0 && !target.name) throw new Error('DNS HTTPS/SVCB AliasMode target must not be root')
  return {
    type: type === DNS_ROUTING_TYPES.HTTPS ? 'HTTPS' : 'SVCB',
    priority,
    targetName: target.name || '.',
    ttl: rr.ttl,
    parameterKeys
  }
}

function decodeDnsName (message, offset, opts = {}, depth = 0, visited = new Set()) {
  const allowCompression = opts.allowCompression !== false
  const limit = opts.limit == null ? message.length : opts.limit
  if (!Number.isSafeInteger(offset) || offset < 0 || offset >= limit || depth > 16 || visited.has(offset)) {
    throw new Error('DNS name encoding is invalid or cyclic')
  }
  visited.add(offset)
  const labels = []
  let cursor = offset
  let nextOffset = null
  while (true) {
    if (cursor >= limit) throw new Error('DNS name is truncated')
    const length = message[cursor]
    if ((length & 0xc0) === 0xc0) {
      if (!allowCompression || cursor + 1 >= limit) throw new Error('DNS name uses forbidden or truncated compression')
      const pointer = ((length & 0x3f) << 8) | message[cursor + 1]
      if (pointer >= message.length) throw new Error('DNS name compression pointer is outside the message')
      if (nextOffset === null) nextOffset = cursor + 2
      const suffix = decodeDnsName(message, pointer, {}, depth + 1, visited)
      if (suffix.name) labels.push(...suffix.name.split('.'))
      break
    }
    if ((length & 0xc0) !== 0 || length > 63) throw new Error('DNS name label length is invalid')
    cursor++
    if (length === 0) {
      if (nextOffset === null) nextOffset = cursor
      break
    }
    if (cursor + length > limit) throw new Error('DNS name label is truncated')
    const label = message.subarray(cursor, cursor + length).toString('ascii')
    if (!/^[A-Za-z0-9_-]+$/.test(label)) throw new Error('DNS name contains an unsupported label')
    labels.push(label.toLowerCase())
    cursor += length
    if (labels.join('.').length > 253) throw new Error('DNS name exceeds its expansion bound')
  }
  return { name: labels.join('.'), nextOffset }
}

function boundedDnsError (err) {
  return String(err?.message || err || 'unknown error').replace(/[\r\n\0]/g, ' ').slice(0, 240)
}

function compareAddressSets (actual, expected, label, errors) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    errors.push(`${label} RRset does not exactly match signed expected addresses`)
  }
}

function requirePublicAddress (value, label) {
  const address = canonicalAddress(value, label)
  if ((isIP(address) === 4 && FORBIDDEN_IPV4.check(address, 'ipv4')) ||
      (isIP(address) === 6 && FORBIDDEN_IPV6.check(address, 'ipv6'))) {
    throw new Error(`${label} must be a globally routable unicast address`)
  }
  return address
}

function canonicalAddress (value, label) {
  if (typeof value !== 'string' || value !== value.trim() || isIP(value) === 0) {
    throw new Error(`${label} must be an IP address`)
  }
  const normalized = isIP(value) === 6
    ? new URL(`http://[${value}]/`).hostname.slice(1, -1)
    : value
  if (normalized !== value.toLowerCase()) throw new Error(`${label} must use canonical IP spelling`)
  return normalized
}

function compareAddresses (left, right) {
  return isIP(left) - isIP(right) || left.localeCompare(right)
}

function witnessHostnameFor (contract) {
  const witnessKey = contract.appKey === '0'.repeat(64) ? 'f'.repeat(64) : '0'.repeat(64)
  return `${encodeHiveAppKey(Buffer.from(witnessKey, 'hex'))}.${contract.suffix}`
}

function encodeHiveAppKey (bytes) {
  let output = ''
  let accumulator = 0
  let bits = 0
  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte
    bits += 8
    while (bits >= 5) {
      bits -= 5
      output += HIVE_Z32_ALPHABET[(accumulator >>> bits) & 31]
      accumulator &= bits === 0 ? 0 : (1 << bits) - 1
    }
  }
  if (bits > 0) output += HIVE_Z32_ALPHABET[(accumulator << (5 - bits)) & 31]
  return output
}

function normalizeHostSuffix (value) {
  if (typeof value !== 'string' || value !== value.trim().toLowerCase() || value.length > 200) return null
  const labels = value.replace(/\.$/, '').split('.')
  if (labels.length < 2 || labels.some(label =>
    !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) return null
  return labels.join('.')
}

function stripNginxComments (text) {
  let output = ''
  let quote = null
  let escaped = false
  for (let i = 0; i < text.length; i++) {
    const character = text[i]
    if (escaped) {
      output += character
      escaped = false
      continue
    }
    if (character === '\\') {
      output += character
      escaped = true
      continue
    }
    if (quote) {
      output += character
      if (character === quote) quote = null
      continue
    }
    if (character === '"' || character === "'") {
      quote = character
      output += character
      continue
    }
    if (character === '#') {
      while (i + 1 < text.length && text[i + 1] !== '\n') i++
      continue
    }
    output += character
  }
  return output
}

function parseNginxStatements (text) {
  const nodes = []
  const stack = [nodes]
  let tokens = []
  let token = ''
  let quote = null
  let ok = true
  const pushToken = () => {
    if (token.length > 0) tokens.push(token)
    token = ''
  }
  for (let i = 0; i < text.length; i++) {
    const character = text[i]
    if (quote) {
      token += character
      if (character === '\\' && i + 1 < text.length) token += text[++i]
      else if (character === quote) quote = null
      continue
    }
    if (character === '"' || character === "'") {
      quote = character
      token += character
      continue
    }
    if (character === '\\') {
      token += character
      if (i + 1 < text.length) token += text[++i]
      else ok = false
      continue
    }
    if (/\s/.test(character)) {
      pushToken()
      continue
    }
    if (character !== ';' && character !== '{' && character !== '}') {
      token += character
      continue
    }
    pushToken()
    if (character === ';') {
      if (tokens.length === 0) ok = false
      else stack.at(-1).push({ kind: 'directive', name: tokens[0], args: tokens.slice(1) })
      tokens = []
      continue
    }
    if (character === '{') {
      if (tokens.length === 0) {
        ok = false
      } else {
        const block = { kind: 'block', name: tokens[0], args: tokens.slice(1), children: [] }
        stack.at(-1).push(block)
        stack.push(block.children)
      }
      tokens = []
      continue
    }
    if (tokens.length > 0 || stack.length === 1) ok = false
    else stack.pop()
    tokens = []
  }
  pushToken()
  if (quote || tokens.length > 0 || stack.length !== 1) ok = false
  return { ok, nodes }
}

function findNginxBlocksWithContext (nodes, name, ancestors = []) {
  const matches = []
  for (const node of nodes) {
    if (node.kind !== 'block') continue
    if (node.name === name) matches.push({ block: node, ancestors })
    matches.push(...findNginxBlocksWithContext(node.children, name, [...ancestors, node]))
  }
  return matches
}

function isHttpServerContext (record) {
  return record.ancestors.length === 0 || record.ancestors.at(-1).name === 'http'
}

function directDirectives (block, name = null) {
  if (!block) return []
  return block.children.filter(node => node.kind === 'directive' && (name === null || node.name === name))
}

function allDirectives (block, name = null) {
  if (!block) return []
  const matches = []
  for (const node of block.children) {
    if (node.kind === 'directive' && (name === null || node.name === name)) matches.push(node)
    if (node.kind === 'block') matches.push(...allDirectives(node, name))
  }
  return matches
}

function sameArgs (actual, expected) {
  return actual.length === expected.length && actual.every((value, index) => value === expected[index])
}

function isPort443Listen (directive) {
  const endpoint = directive.args[0] || ''
  return endpoint === '443' || /:443$/.test(endpoint)
}

function isDefaultTls443Listen (directive) {
  return isPort443Listen(directive) && directive.args.includes('default_server')
}

function hasExactPublicTlsListeners (listens, defaultServer) {
  const option = defaultServer ? ['ssl', 'default_server'] : ['ssl']
  const expected = [['443', ...option], ['[::]:443', ...option]]
  return listens.length === expected.length && expected.every(args =>
    listens.some(directive => sameArgs(directive.args, args)))
}

function isSafeDefaultServer (block) {
  const directives = directDirectives(block)
  const names = directDirectives(block, 'server_name')
  const returns = directDirectives(block, 'return')
  const hasNestedBlock = block.children.some(node => node.kind === 'block')
  const upstreams = allDirectives(block).filter(directive => NGINX_UPSTREAM_DIRECTIVES.has(directive.name))
  return hasExactPublicTlsListeners(directDirectives(block, 'listen'), true) &&
    names.length === 1 && sameArgs(names[0].args, ['_']) &&
    returns.length === 1 && sameArgs(returns[0].args, ['421']) &&
    hasSingleDirective(block, 'ssl_certificate') &&
    hasSingleDirective(block, 'ssl_certificate_key') &&
    hasSingleDirective(block, 'ssl_protocols', ['TLSv1.2', 'TLSv1.3']) &&
    hasSingleDirective(block, 'ssl_session_tickets', ['off']) &&
    hasSingleDirective(block, 'gzip', ['off']) &&
    hasSingleDirective(block, 'gunzip', ['off']) &&
    hasSingleDirective(block, 'access_log', ['off']) &&
    hasSingleDirective(block, 'error_log', ['stderr', 'crit']) &&
    directives.every(directive => NGINX_DEFAULT_DIRECTIVES.has(directive.name)) &&
    !hasNestedBlock && upstreams.length === 0
}

function hasSingleDirective (block, name, args = null) {
  const directives = directDirectives(block, name)
  return directives.length === 1 && directives[0].args.length === (args?.length || 1) &&
    (args === null || sameArgs(directives[0].args, args))
}

function serverNameCanMatchHiveApp (rawName, suffix) {
  const name = unquote(rawName).toLowerCase().replace(/\.$/, '')
  if (!name || name === '_') return false
  if (name.startsWith('~')) return true
  if (name.startsWith('*.')) {
    const base = name.slice(2)
    return suffix === base || suffix.endsWith(`.${base}`)
  }
  if (name.startsWith('.')) {
    const base = name.slice(1)
    return suffix === base || suffix.endsWith(`.${base}`)
  }
  if (name.includes('*')) return true
  if (!name.endsWith(`.${suffix}`)) return false
  const label = name.slice(0, -(suffix.length + 1))
  return /^[ybndrfg8ejkmcpqxot1uwisza345h769]{52}$/.test(label)
}

function isExplicitDisjointServerName (rawName, suffix) {
  const name = unquote(rawName).toLowerCase().replace(/\.$/, '')
  if (!name || name === '_' || name.startsWith('~') || name.includes('*')) return false
  if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/.test(name)) return false
  return !serverNameCanMatchHiveApp(name, suffix)
}

function unquote (value) {
  let name = String(value || '').trim()
  if ((name.startsWith('"') && name.endsWith('"')) || (name.startsWith("'") && name.endsWith("'"))) {
    name = name.slice(1, -1)
  }
  return name
}
