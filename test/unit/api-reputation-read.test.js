import test from 'brittle'
import {
  MAX_REPUTATION_LEADERBOARD_ENTRIES,
  buildReputationLeaderboardPayload,
  buildReputationRecordPayload,
  sanitizeReputationRecord
} from 'p2p-hiverelay/core/relay-node/api-reputation-read.js'

function record (overrides = {}) {
  return {
    score: 12.345,
    totalChallenges: 4,
    passedChallenges: 3,
    failedChallenges: 1,
    avgLatencyMs: 25.7,
    totalBytesServed: 512.5,
    totalUptimeHours: 8.25,
    region: ' EU ',
    geoBonus: true,
    firstSeen: 10,
    lastActivity: 20,
    secretToken: 'do-not-leak',
    ...overrides
  }
}

test('api reputation read: missing reputation returns empty public payloads', (t) => {
  t.alike(buildReputationLeaderboardPayload().payload, [])
  const recordOut = buildReputationRecordPayload({ pubkey: 'a'.repeat(64) })
  t.is(recordOut.status, undefined)
  t.is(recordOut.payload, null)
  t.alike(recordOut.headers, { 'Cache-Control': 'public, max-age=30' })
})

test('api reputation read: invalid pubkey rejects before store lookup', (t) => {
  let called = false
  const out = buildReputationRecordPayload({
    pubkey: 'not-hex',
    reputation: {
      getRecord () {
        called = true
        return record()
      }
    }
  })

  t.is(out.status, 400)
  t.alike(out.payload, { error: 'Invalid pubkey' })
  t.absent(called, 'store lookup is skipped for invalid pubkey')
})

test('api reputation read: sanitizes direct records without raw store fields', (t) => {
  const pubkey = 'A'.repeat(64)
  const out = buildReputationRecordPayload({
    pubkey,
    reputation: {
      getRecord (key) {
        t.is(key, 'a'.repeat(64), 'lookup key is canonicalized')
        return record({
          passedChallenges: 9,
          failedChallenges: 9,
          region: 'NA',
          privateNote: 'hidden'
        })
      }
    }
  })

  t.alike(out.payload, {
    score: 12.35,
    totalChallenges: 4,
    passedChallenges: 4,
    failedChallenges: 0,
    avgLatencyMs: 25,
    totalBytesServed: 512.5,
    totalUptimeHours: 8.25,
    region: 'NA',
    geoBonus: true,
    firstSeen: 10,
    lastActivity: 20,
    pubkey: 'a'.repeat(64)
  })
  t.absent(JSON.stringify(out.payload).includes('secretToken'))
  t.absent(JSON.stringify(out.payload).includes('privateNote'))
  t.absent(JSON.stringify(out.payload).includes('do-not-leak'))
})

test('api reputation read: caps and sanitizes leaderboard rows', (t) => {
  t.is(MAX_REPUTATION_LEADERBOARD_ENTRIES, 100)
  let requestedLimit = null
  const rows = []
  for (let i = 0; i < 105; i++) {
    rows.push({
      relay: i === 0 ? ' relay-a ' : String(i % 10).repeat(64),
      score: 2.345,
      reliability: i === 0 ? 'bad' : '80%',
      avgLatencyMs: 31.9,
      uptimeHours: 6.8,
      bytesServed: 1024,
      totalChallenges: 10,
      passedChallenges: 8,
      failedChallenges: 2,
      region: i === 0 ? ' Mars ' : 'APAC',
      lastActivity: 200,
      firstSeen: 100,
      secretToken: 'do-not-leak'
    })
  }

  const out = buildReputationLeaderboardPayload({
    reputation: {
      getLeaderboard (limit) {
        requestedLimit = limit
        return rows
      }
    }
  })

  t.is(requestedLimit, MAX_REPUTATION_LEADERBOARD_ENTRIES)
  t.is(out.payload.length, MAX_REPUTATION_LEADERBOARD_ENTRIES)
  t.alike(out.payload[0], {
    relay: 'relay-a',
    score: 2.35,
    reliability: '80%',
    avgLatencyMs: 31,
    uptimeHours: 6,
    bytesServed: 1024,
    totalChallenges: 10,
    passedChallenges: 8,
    failedChallenges: 2,
    region: 'Mars',
    lastActivity: 200,
    firstSeen: 100
  })
  t.alike(out.headers, { 'Cache-Control': 'public, max-age=30' })
  t.absent(JSON.stringify(out.payload).includes('secretToken'))
  t.absent(JSON.stringify(out.payload).includes('do-not-leak'))
})

test('api reputation read: shared record sanitizer clamps malformed counters', (t) => {
  t.alike(sanitizeReputationRecord(record({
    score: Infinity,
    totalChallenges: 2,
    passedChallenges: 7,
    failedChallenges: 7,
    avgLatencyMs: -1,
    totalBytesServed: -1,
    totalUptimeHours: -1,
    region: 'bad\nregion',
    geoBonus: 'yes',
    firstSeen: -1,
    lastActivity: Number.NaN
  })), {
    score: 0,
    totalChallenges: 2,
    passedChallenges: 2,
    failedChallenges: 0,
    avgLatencyMs: 0,
    totalBytesServed: 0,
    totalUptimeHours: 0,
    region: null,
    geoBonus: false,
    firstSeen: null,
    lastActivity: null
  })
})
