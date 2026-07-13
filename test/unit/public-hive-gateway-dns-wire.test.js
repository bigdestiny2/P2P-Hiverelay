import test from 'brittle'
import { createSocket } from 'node:dgram'
import { createServer } from 'node:net'
import {
  resolvePublicHiveGatewayRoutingRecords
} from '../../scripts/lib/public-hive-gateway-quarantine-authority.mjs'

const HOSTNAME = `${'y'.repeat(52)}.hive-canary.operator.example`

test('public gateway DNS wire resolver retries truncated UDP over exact TCP framing', async (t) => {
  const fixture = await dnsServerFixture(t, { truncateHttps: true })
  const https = await resolvePublicHiveGatewayRoutingRecords(HOSTNAME, 'HTTPS', {
    servers: [`127.0.0.1:${fixture.port}`],
    timeoutMs: 1000
  })
  t.is(https.length, 1)
  t.is(https[0].type, 'HTTPS')
  t.is(https[0].priority, 1)
  t.is(fixture.tcpQueries(), 1, 'TC response is retried once with DNS TCP framing')

  const svcb = await resolvePublicHiveGatewayRoutingRecords(HOSTNAME, 'SVCB', {
    servers: [`127.0.0.1:${fixture.port}`],
    timeoutMs: 1000
  })
  t.alike(svcb, [], 'NOERROR with an exact empty answer is the only empty-RRset result')
})

test('public gateway DNS wire resolver never converts malformed RCODE or timeout into empty', async (t) => {
  const wrongId = await dnsServerFixture(t, { wrongId: true })
  await t.exception(async () => resolvePublicHiveGatewayRoutingRecords(HOSTNAME, 'HTTPS', {
    servers: [`127.0.0.1:${wrongId.port}`],
    timeoutMs: 300
  }), /query ID mismatch/)

  const refused = await dnsServerFixture(t, { rcode: 5 })
  await t.exception(async () => resolvePublicHiveGatewayRoutingRecords(HOSTNAME, 'HTTPS', {
    servers: [`127.0.0.1:${refused.port}`],
    timeoutMs: 300
  }), /RCODE 5/)

  const servfail = await dnsServerFixture(t, { rcode: 2 })
  await t.exception(async () => resolvePublicHiveGatewayRoutingRecords(HOSTNAME, 'HTTPS', {
    servers: [`127.0.0.1:${servfail.port}`],
    timeoutMs: 300
  }), /RCODE 2/)

  const dropped = await dnsServerFixture(t, { drop: true })
  await t.exception(async () => resolvePublicHiveGatewayRoutingRecords(HOSTNAME, 'HTTPS', {
    servers: [`127.0.0.1:${dropped.port}`],
    timeoutMs: 80
  }), /absolute deadline/)
})

test('public gateway DNS wire resolver rejects ambiguous or structurally loose answers', async (t) => {
  for (const [label, transform, expected] of [
    ['extra question', response => {
      response.writeUInt16BE(2, 4)
      return response
    }, /exactly one question/],
    ['wrong question type', response => {
      response.writeUInt16BE(64, questionEnd(response) - 4)
      return response
    }, /does not match the exact query/],
    ['resource record count overflow', response => {
      response.writeUInt16BE(129, 6)
      return response
    }, /resource-record bound/],
    ['CNAME ambiguity', response => {
      const answer = cnameAnswer()
      response.writeUInt16BE(1, 6)
      return Buffer.concat([response, answer])
    }, /CNAME alias ambiguity/],
    ['trailing bytes', response => Buffer.concat([response, Buffer.from([0])]), /trailing or unparsed bytes/],
    ['oversized response', response => Buffer.concat([response, Buffer.alloc(4097 - response.length)]), /wire-size bound/]
  ]) {
    const fixture = await dnsServerFixture(t, { transformUdp: transform })
    await t.exception(async () => resolvePublicHiveGatewayRoutingRecords(HOSTNAME, 'HTTPS', {
      servers: [`127.0.0.1:${fixture.port}`],
      timeoutMs: 300
    }), expected, label)
  }
})

async function dnsServerFixture (t, options) {
  let tcpQueries = 0
  const createTcp = () => createServer(socket => {
    let received = Buffer.alloc(0)
    socket.on('data', chunk => {
      received = Buffer.concat([received, chunk])
      if (received.length < 2) return
      const length = received.readUInt16BE(0)
      if (received.length !== length + 2) return
      tcpQueries++
      const query = received.subarray(2)
      const response = responseFor(query, { answer: true })
      const frame = Buffer.allocUnsafe(response.length + 2)
      frame.writeUInt16BE(response.length, 0)
      response.copy(frame, 2)
      socket.end(frame)
    })
  })
  let tcp = null
  let udp = null
  let port = null
  for (let attempt = 0; attempt < 16; attempt++) {
    udp = createSocket('udp4')
    await bindUdp(udp, 0)
    port = udp.address().port
    tcp = createTcp()
    try {
      await listenTcp(tcp, port)
      break
    } catch (err) {
      await closeUdp(udp)
      tcp = null
      udp = null
      port = null
      if (err?.code !== 'EADDRINUSE' || attempt === 15) throw err
    }
  }
  if (!tcp || !udp || !port) throw new Error('could not bind paired DNS fixture sockets')
  udp.on('message', (query, peer) => {
    if (options.drop) return
    const qtype = query.readUInt16BE(questionEnd(query) - 4)
    let response = responseFor(query, {
      truncated: options.truncateHttps === true && qtype === 65,
      answer: false,
      wrongId: options.wrongId,
      rcode: options.rcode
    })
    if (options.transformUdp) response = options.transformUdp(response, query)
    udp.send(response, peer.port, peer.address)
  })
  t.teardown(async () => {
    udp.close()
    await new Promise(resolve => tcp.close(resolve))
  })
  return { port, tcpQueries: () => tcpQueries }
}

function responseFor (query, options = {}) {
  const end = questionEnd(query)
  const qtype = query.readUInt16BE(end - 4)
  const question = query.subarray(12, end)
  const answer = options.answer ? routingAnswer(qtype) : Buffer.alloc(0)
  const response = Buffer.alloc(12)
  const queryId = query.readUInt16BE(0)
  response.writeUInt16BE(options.wrongId ? (queryId + 1) & 0xffff : queryId, 0)
  let flags = 0x8080 | (query.readUInt16BE(2) & 0x0100) | (options.rcode || 0)
  if (options.truncated) flags |= 0x0200
  response.writeUInt16BE(flags, 2)
  response.writeUInt16BE(1, 4)
  response.writeUInt16BE(options.answer ? 1 : 0, 6)
  response.writeUInt16BE(0, 8)
  response.writeUInt16BE(0, 10)
  return Buffer.concat([response, question, answer])
}

function routingAnswer (type) {
  const answer = Buffer.alloc(15)
  answer.writeUInt16BE(0xc00c, 0)
  answer.writeUInt16BE(type, 2)
  answer.writeUInt16BE(1, 4)
  answer.writeUInt32BE(300, 6)
  answer.writeUInt16BE(3, 10)
  answer.writeUInt16BE(1, 12)
  answer[14] = 0
  return answer
}

function cnameAnswer () {
  const answer = Buffer.alloc(14)
  answer.writeUInt16BE(0xc00c, 0)
  answer.writeUInt16BE(5, 2)
  answer.writeUInt16BE(1, 4)
  answer.writeUInt32BE(300, 6)
  answer.writeUInt16BE(2, 10)
  answer.writeUInt16BE(0xc00c, 12)
  return answer
}

function questionEnd (query) {
  let offset = 12
  while (offset < query.length) {
    const length = query[offset++]
    if (length === 0) break
    if (length > 63 || offset + length > query.length) throw new Error('invalid test DNS query')
    offset += length
  }
  if (offset + 4 !== query.length) throw new Error('invalid test DNS question')
  return offset + 4
}

function listenTcp (server, port = 0) {
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(port, '127.0.0.1', resolve)
  })
}

function bindUdp (socket, port) {
  return new Promise((resolve, reject) => {
    socket.once('error', reject)
    socket.bind(port, '127.0.0.1', resolve)
  })
}

function closeUdp (socket) {
  return new Promise(resolve => socket.close(resolve))
}
