import test from 'brittle'
import http from 'http'
import https from 'https'
import { createHash } from 'crypto'
import { execFile } from 'child_process'
import { promisify } from 'util'
import { mkdtemp, readFile, rm, writeFile } from 'fs/promises'
import { join } from 'path'
import { tmpdir } from 'os'
import Corestore from 'corestore'
import Hyperdrive from 'hyperdrive'
import b4a from 'b4a'
import { GatewayServer } from 'p2p-hiverelay/core/relay-node/gateway-server.js'
import { encodeHiveAppKey, resolveHiveAppHost } from 'p2p-hiverelay/gateway/hive-host.js'
import { probePublicHiveGateway } from '../../scripts/lib/public-hive-gateway-preflight.mjs'

const execFileAsync = promisify(execFile)
const SUFFIX_A = 'hive-a.test'
const SUFFIX_B = 'hive-b.test'
const SOAK_REQUESTS = boundedPositiveInteger(
  process.env.HIVERELAY_PUBLIC_GATEWAY_SOAK_REQUESTS,
  24,
  10_000
)

test('live public Hive gateway - TLS, replication, isolation, and failover', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'hiverelay-public-live-'))
  const sourceStore = new Corestore(join(root, 'source'))
  const replicaStore = new Corestore(join(root, 'replica'))
  let replicationA = null
  let replicationB = null

  t.teardown(async () => {
    if (replicationA) replicationA.destroy()
    if (replicationB) replicationB.destroy()
    try { await sourceStore.close() } catch {}
    try { await replicaStore.close() } catch {}
    await rm(root, { recursive: true, force: true })
  })

  await sourceStore.ready()
  await replicaStore.ready()

  const sourceDrive = new Hyperdrive(sourceStore.namespace('public-live-source'))
  await sourceDrive.ready()
  const html = b4a.from('\ufeff<!doctype html>\r\n<script src="/assets/app.js"></script>\r\n')
  const asset = b4a.from('console.log("public-hive-live")\n')
  const large = Buffer.alloc(16 * 1024 * 1024, 0x5a)
  await sourceDrive.put('/index.html', html)
  await sourceDrive.put('/assets/app.js', asset)
  await sourceDrive.put('/large.bin', large)

  const replicaDrive = new Hyperdrive(replicaStore, sourceDrive.key)
  await replicaDrive.ready()
  replicationA = sourceStore.replicate(true)
  replicationB = replicaStore.replicate(false)
  replicationA.pipe(replicationB).pipe(replicationA)
  await replicaDrive.update({ wait: true })
  t.ok(b4a.equals(await replicaDrive.get('/index.html'), html), 'second gateway pulled exact HTML over Corestore replication')
  t.ok(b4a.equals(await replicaDrive.get('/assets/app.js'), asset), 'second gateway pulled exact asset bytes')
  t.ok(b4a.equals(await replicaDrive.get('/large.bin'), large), 'second gateway pulled the large shutdown fixture')
  replicationA.destroy()
  replicationB.destroy()
  replicationA = null
  replicationB = null

  const appKey = b4a.toString(sourceDrive.key, 'hex')
  const appLabel = encodeHiveAppKey(sourceDrive.key)
  const appHostA = `${appLabel}.${SUFFIX_A}`
  const appHostB = `${appLabel}.${SUFFIX_B}`
  const publicMetadata = {
    blind: false,
    privacyTier: 'public',
    storageClass: 'persistent',
    availabilityClass: 'always-on'
  }

  const gatewayA = await startGateway(t, sourceStore, sourceDrive, appKey, publicMetadata, SUFFIX_A)
  const gatewayB = await startGateway(t, replicaStore, replicaDrive, appKey, publicMetadata, SUFFIX_B)
  const certificateA = await createWildcardCertificate(root, SUFFIX_A, 'edge-a')
  const certificateB = await createWildcardCertificate(root, SUFFIX_B, 'edge-b')
  const edgeA = await startTlsEdge(t, gatewayA.server.address().port, certificateA, SUFFIX_A)
  const edgeB = await startTlsEdge(t, gatewayB.server.address().port, certificateB, SUFFIX_B)

  const first = await tlsRequest(edgeA.port, appHostA, '/', certificateA.cert)
  t.is(first.statusCode, 200, 'TLS edge serves the app root')
  t.is(first.tlsProtocol, 'TLSv1.3', 'live edge negotiates modern TLS')
  t.ok(first.raw.equals(html), 'TLS response preserves exact stored HTML bytes')
  t.is(first.headers['x-hive-app-key'], appKey)
  t.is(first.headers['x-hive-byte-mode'], 'exact')
  t.ok(Number(first.headers['x-hive-drive-version']) > 0, 'exact response names its immutable drive version')
  t.is(first.headers.vary, 'Host')
  t.is(first.headers.link, `<hive://${appKey}/>; rel="canonical", </.well-known/hiverelay-app.json>; rel="describedby"`)
  t.is(first.headers['cache-control'], 'no-store, max-age=0', 'Phase 1 edge cannot retain revoked mutable URLs')
  t.absent(first.headers['access-control-allow-origin'], 'app origin does not inherit compatibility CORS')

  const expectedHtmlSha256 = createHash('sha256').update(html).digest('hex')
  const evidence = await probePublicHiveGateway({
    origin: `https://${appHostA}:${edgeA.port}/`,
    appKey,
    suffix: SUFFIX_A,
    connectAddress: '127.0.0.1',
    path: '/index.html',
    expectedSha256: expectedHtmlSha256,
    expectedDriveVersion: Number(first.headers['x-hive-drive-version']),
    ca: certificateA.cert
  })
  t.is(evidence.sha256, expectedHtmlSha256, 'deployment probe records the exact publisher hash')
  t.is(evidence.tlsProtocol, 'TLSv1.3', 'deployment probe records the negotiated TLS protocol')
  t.is(evidence.connectAddress, '127.0.0.1', 'deployment probe records its pinned node address')
  t.alike(evidence.checks, {
    metadata: true,
    exactBytes: true,
    range: true,
    head: true,
    canonicalIdentity: true,
    managementIsolation: true,
    forwardedHostIsolation: true,
    unavailableAppIsolation: true,
    defaultSniRejection: true,
    sniHostBinding: true
  }, 'deployment evidence covers the public gateway isolation contract')
  await t.exception(probePublicHiveGateway({
    origin: `https://${appHostA}:${edgeA.port}/`,
    appKey,
    suffix: SUFFIX_A,
    connectAddress: '127.0.0.1',
    path: '/index.html',
    expectedSha256: expectedHtmlSha256,
    expectedDriveVersion: Number(first.headers['x-hive-drive-version']) + 1,
    ca: certificateA.cert
  }), /drive version does not match the configured immutable pin/)

  const ranged = await tlsRequest(edgeA.port, appHostA, '/assets/app.js', certificateA.cert, {
    Range: 'bytes=0-10'
  })
  t.is(ranged.statusCode, 206, 'TLS path preserves range semantics')
  t.ok(ranged.raw.equals(asset.subarray(0, 11)), 'range is cut from original asset bytes')

  const head = await tlsRequest(edgeA.port, appHostA, '/index.html', certificateA.cert, {}, 'HEAD')
  t.is(head.statusCode, 200)
  t.is(head.headers['content-length'], String(html.byteLength))
  t.is(head.raw.byteLength, 0, 'HEAD is body-free through TLS termination')

  const forwardedSibling = `${'y'.repeat(52)}.${SUFFIX_A}`
  const forwarded = await tlsRequest(edgeA.port, appHostA, '/', certificateA.cert, {
    'X-Forwarded-Host': forwardedSibling,
    'X-Forwarded-For': '198.51.100.66',
    Forwarded: 'for=198.51.100.66;host=attacker.example'
  })
  t.is(forwarded.statusCode, 200)
  t.is(forwarded.headers['x-hive-app-key'], appKey, 'forwarded Host cannot select a sibling app')
  t.absent(gatewayA._rateLimits.has('198.51.100.66'), 'strict edge overwrites attacker-supplied forwarding identity')

  const management = await tlsRequest(edgeA.port, appHostA, '/api/manage/config', certificateA.cert)
  t.is(management.statusCode, 404, 'management-looking paths remain app content lookups')
  t.absent(management.raw.toString().includes('apiKey'), 'management state is not exposed')

  const unknownHost = `${'y'.repeat(52)}.${SUFFIX_A}`
  const unknown = await tlsRequest(edgeA.port, unknownHost, '/', certificateA.cert)
  t.is(unknown.statusCode, 403, 'unapproved canonical app host fails closed')
  t.is(unknown.body.error, 'App unavailable through public Hive gateway')

  const metadata = await tlsRequest(edgeA.port, appHostA, '/.well-known/hiverelay-app.json', certificateA.cert)
  t.is(metadata.statusCode, 200)
  t.is(metadata.body.appKey, appKey)
  t.is(metadata.body.gatewayHost, appHostA)
  t.is(metadata.body.signed, false, 'transport metadata does not overclaim provenance')

  const second = await tlsRequest(edgeB.port, appHostB, '/', certificateB.cert)
  t.ok(second.raw.equals(first.raw), 'independent replicated gateway serves identical bytes')
  t.unlike(second.peerFingerprint, first.peerFingerprint, 'independent operators use different TLS private keys')

  const sniMismatch = await tlsRequest(
    edgeA.port,
    appHostA,
    '/',
    certificateA.cert,
    {},
    'GET',
    unknownHost
  )
  t.is(sniMismatch.statusCode, 421, 'strict edge rejects TLS SNI and HTTP Host mismatch')

  for (let i = 0; i < SOAK_REQUESTS; i++) {
    const useA = i % 2 === 0
    const port = useA ? edgeA.port : edgeB.port
    const host = useA ? appHostA : appHostB
    const ca = useA ? certificateA.cert : certificateB.cert
    const path = i % 3 === 0 ? '/assets/app.js' : '/index.html'
    const expected = path === '/assets/app.js' ? asset : html
    const response = await tlsRequest(port, host, path, ca)
    if (response.statusCode !== 200 || !response.raw.equals(expected)) {
      throw new Error(`soak request ${i + 1}/${SOAK_REQUESTS} returned inconsistent content`)
    }
  }
  t.pass(`${SOAK_REQUESTS} alternating TLS requests stayed byte-identical across both gateways`)

  const gatewayAPort = gatewayA.server.address().port
  gatewayA.port = gatewayAPort
  const paused = pauseTlsResponse(edgeA.port, appHostA, '/large.bin', certificateA.cert)
  await paused.started
  const stopped = await Promise.race([
    gatewayA.stop().then(() => true),
    new Promise(resolve => setTimeout(() => resolve(false), 1000))
  ])
  paused.destroy()
  t.ok(stopped, 'gateway shutdown is bounded while a TLS client pauses a large response')

  const failedOver = await requestFirstHealthy([
    { port: edgeA.port, host: appHostA, ca: certificateA.cert },
    { port: edgeB.port, host: appHostB, ca: certificateB.cert }
  ], '/')
  t.is(failedOver.port, edgeB.port, 'client fails over when the first edge has no healthy upstream')
  t.ok(failedOver.response.raw.equals(html), 'failover keeps exact application bytes')

  for (let cycle = 1; cycle <= 3; cycle++) {
    await gatewayA.start()
    t.is(gatewayA.server.address().port, gatewayAPort, `restart ${cycle} rebinds the same loopback port`)
    const restarted = await tlsRequest(edgeA.port, appHostA, '/', certificateA.cert)
    t.is(restarted.statusCode, 200, `restart ${cycle} restores HTTPS retrieval`)
    t.ok(restarted.raw.equals(html), `restart ${cycle} preserves exact bytes`)
    await gatewayA.stop()
  }
  await edgeA.stop()
})

async function startGateway (t, store, drive, appKey, metadata, suffix) {
  const pinnedVersion = drive.version
  const node = {
    config: {
      gatewayPublicOnlyPrivacyTier: true,
      hiveAppPublicKeys: [appKey],
      hiveAppPublicVersions: { [appKey]: pinnedVersion }
    },
    store,
    seededApps: new Map([[appKey, {
      drive,
      ...metadata,
      storageProvedDriveVersion: pinnedVersion
    }]])
  }
  node.appLifecycle = {
    acquireDriveReadLease (key) {
      const seededDrive = node.seededApps.get(key)?.drive
      if (!seededDrive || seededDrive.closed || seededDrive.closing) return null
      return { drive: seededDrive, release () {} }
    }
  }
  const gateway = new GatewayServer(node, {
    gatewayPort: 0,
    gatewayHost: '127.0.0.1',
    hiveAppHostSuffix: suffix,
    hiveAppPublicKeys: [appKey],
    hiveAppPublicVersions: { [appKey]: pinnedVersion },
    trustProxy: true,
    trustedProxyAddresses: ['127.0.0.1'],
    requireForwardedSNI: true
  })
  await gateway.start()
  t.teardown(async () => {
    try { await gateway.stop() } catch {}
  })
  return gateway
}

async function startTlsEdge (t, upstreamPort, certificate, suffix) {
  const sockets = new Set()
  const server = https.createServer({
    key: certificate.key,
    cert: certificate.cert,
    minVersion: 'TLSv1.2'
  }, (req, res) => {
    const resolvedHost = resolveHiveAppHost(req.headers.host, suffix)
    const sni = String(req.socket.servername || '').toLowerCase()
    if (resolvedHost.kind !== 'app' || sni !== resolvedHost.host) {
      res.writeHead(421, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' })
      res.end('{"error":"Misdirected request"}\n')
      return
    }

    const headers = { ...req.headers, host: req.headers.host }
    delete headers.connection
    for (const name of Object.keys(headers)) {
      if (name === 'forwarded' || name.startsWith('x-forwarded-')) delete headers[name]
    }
    headers['x-forwarded-for'] = normalizeLoopbackAddress(req.socket.remoteAddress)
    headers['x-hive-forwarded-sni'] = sni
    const upstream = http.request({
      hostname: '127.0.0.1',
      port: upstreamPort,
      method: req.method,
      path: req.url,
      headers
    }, (upstreamResponse) => {
      upstreamResponse.on('error', () => {
        if (!res.destroyed) res.destroy()
      })
      res.writeHead(upstreamResponse.statusCode, upstreamResponse.headers)
      upstreamResponse.pipe(res)
    })
    upstream.on('error', () => {
      if (!res.headersSent) res.writeHead(502)
      res.end()
    })
    upstream.setTimeout(3000, () => upstream.destroy(new Error('upstream timeout')))
    req.pipe(upstream)
  })
  server.on('connection', socket => {
    sockets.add(socket)
    socket.on('close', () => sockets.delete(socket))
  })
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  let stopped = false
  const stop = async () => {
    if (stopped) return
    stopped = true
    for (const socket of sockets) socket.destroy()
    await new Promise(resolve => server.close(resolve))
  }
  t.teardown(stop)
  return { port: server.address().port, stop }
}

async function createWildcardCertificate (root, suffix, name) {
  const configPath = join(root, `${name}-openssl.cnf`)
  const keyPath = join(root, `${name}.key`)
  const certPath = join(root, `${name}.crt`)
  await writeFile(configPath, [
    '[req]',
    'prompt = no',
    'distinguished_name = dn',
    'x509_extensions = extensions',
    '[dn]',
    `CN = *.${suffix}`,
    '[extensions]',
    'basicConstraints = critical,CA:FALSE',
    'keyUsage = critical,digitalSignature,keyEncipherment',
    'extendedKeyUsage = serverAuth',
    `subjectAltName = DNS:*.${suffix}`,
    ''
  ].join('\n'))
  await execFileAsync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
    '-config', configPath,
    '-keyout', keyPath,
    '-out', certPath
  ])
  return {
    key: await readFile(keyPath),
    cert: await readFile(certPath)
  }
}

function tlsRequest (port, host, path, ca, headers = {}, method = 'GET', servername = host) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: host,
      port,
      path,
      method,
      ca,
      servername,
      family: 4,
      lookup: (_hostname, _opts, callback) => callback(null, '127.0.0.1', 4),
      headers: { Host: host, Connection: 'close', ...headers },
      agent: false,
      timeout: 3000
    }, (res) => {
      const chunks = []
      res.on('data', chunk => chunks.push(chunk))
      res.on('end', () => {
        const raw = Buffer.concat(chunks)
        let body = raw
        try { body = JSON.parse(raw.toString('utf8')) } catch {}
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          raw,
          body,
          tlsProtocol: res.socket.getProtocol(),
          peerFingerprint: res.socket.getPeerCertificate().fingerprint256
        })
      })
    })
    req.on('timeout', () => req.destroy(new Error('TLS request timed out')))
    req.on('error', reject)
    req.end()
  })
}

function pauseTlsResponse (port, host, path, ca) {
  let response = null
  let settled = false
  let resolveStarted
  let rejectStarted
  const started = new Promise((resolve, reject) => {
    resolveStarted = resolve
    rejectStarted = reject
  })
  const req = https.request({
    hostname: host,
    port,
    path,
    method: 'GET',
    ca,
    servername: host,
    family: 4,
    lookup: (_hostname, _opts, callback) => callback(null, '127.0.0.1', 4),
    headers: { Host: host, Connection: 'close' },
    agent: false,
    timeout: 3000
  }, res => {
    response = res
    res.on('error', () => {})
    res.once('data', () => {
      res.pause()
      settled = true
      resolveStarted()
    })
  })
  req.on('timeout', () => req.destroy(new Error('paused TLS response timed out')))
  req.on('error', err => {
    if (!settled) rejectStarted(err)
  })
  req.end()
  return {
    started,
    destroy () {
      response?.destroy()
      req.destroy()
    }
  }
}

async function requestFirstHealthy (candidates, path) {
  let lastError = null
  for (const candidate of candidates) {
    try {
      const response = await tlsRequest(candidate.port, candidate.host, path, candidate.ca)
      if (response.statusCode >= 200 && response.statusCode < 300) return { port: candidate.port, response }
    } catch (err) {
      lastError = err
    }
  }
  throw lastError || new Error('no healthy public Hive gateway')
}

function normalizeLoopbackAddress (value) {
  return value === '::ffff:127.0.0.1' ? '127.0.0.1' : String(value || '')
}

function boundedPositiveInteger (value, fallback, max) {
  if (value == null || value === '') return fallback
  if (!/^[1-9][0-9]*$/.test(value)) throw new Error('HIVERELAY_PUBLIC_GATEWAY_SOAK_REQUESTS must be a positive integer')
  const number = Number(value)
  if (!Number.isSafeInteger(number) || number > max) {
    throw new Error(`HIVERELAY_PUBLIC_GATEWAY_SOAK_REQUESTS must not exceed ${max}`)
  }
  return number
}
