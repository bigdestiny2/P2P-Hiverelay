// LogTailer — spawns `ssh -i <key> root@<host>` for each relay, where the
// SSH key on each relay is force-commanded to `tail -n 50 -F /var/log/
// hiverelay.log`. Each connection becomes a stream of log lines from that
// relay; the tailer multiplexes them into a single in-memory ring buffer
// + a fan-out to subscribed SSE clients.
//
// Why this shape:
//   - No relay-side code changes needed (works on v0.8.12 as-is).
//   - The SSH key is single-purpose (force-command in authorized_keys),
//     so even if Bern is compromised the blast radius is limited to
//     log read access on the other relays.
//   - Ring buffer means late-joining clients see recent history without
//     reading log files.

import { spawn } from 'child_process'
import { EventEmitter } from 'events'

const DEFAULT_KEY = '/root/.ssh/observatory_tail'
const LINE_RING_DEFAULT = 1000

export class LogTailer extends EventEmitter {
  constructor (opts = {}) {
    super()
    this.relays = opts.relays || []
    this.sshKey = opts.sshKey || DEFAULT_KEY
    this.ringSize = opts.ringSize || LINE_RING_DEFAULT
    this.ring = []  // [{ ts, relay, level, msg, raw }]
    this._procs = new Map()  // relay.id → child_process
    this._buffers = new Map() // relay.id → partial-line buffer
    this._restartTimers = new Map()
  }

  start () {
    for (const relay of this.relays) {
      this._connectRelay(relay)
    }
  }

  stop () {
    for (const t of this._restartTimers.values()) clearTimeout(t)
    this._restartTimers.clear()
    for (const [id, proc] of this._procs) {
      try { proc.kill('SIGTERM') } catch (_) {}
    }
    this._procs.clear()
    this._buffers.clear()
  }

  _connectRelay (relay) {
    // ssh -o BatchMode -i <key> root@<host>
    // The remote authorized_keys force-command runs `tail -n 50 -F`,
    // so we don't pass a command argument here.
    const host = relay.host === '127.0.0.1' ? '127.0.0.1' : relay.host
    const proc = spawn('ssh', [
      '-i', this.sshKey,
      '-o', 'BatchMode=yes',
      '-o', 'StrictHostKeyChecking=accept-new',
      '-o', 'ServerAliveInterval=15',
      '-o', 'ServerAliveCountMax=4',
      '-o', 'ConnectTimeout=8',
      `root@${host}`
    ], { stdio: ['ignore', 'pipe', 'pipe'] })

    this._procs.set(relay.id, proc)
    this._buffers.set(relay.id, '')

    proc.stdout.on('data', (chunk) => this._onData(relay, chunk))
    proc.stderr.on('data', (chunk) => {
      // SSH chatter; surface meaningful errors but don't drown the dashboard
      const text = chunk.toString().trim()
      if (text && !/Pseudo-terminal will not be allocated/i.test(text)) {
        this._push({
          ts: Date.now(),
          relay: relay.id,
          level: 'warn',
          msg: '[ssh-stderr] ' + text.slice(0, 300),
          raw: text
        })
      }
    })

    const onExit = (code, signal) => {
      this._procs.delete(relay.id)
      this._buffers.delete(relay.id)
      this._push({
        ts: Date.now(),
        relay: relay.id,
        level: 'warn',
        msg: `[ssh-exited] code=${code} signal=${signal} — reconnecting in 5s`,
        raw: null
      })
      // Backoff reconnect — 5s. Don't pile up reconnects if relay is down.
      const timer = setTimeout(() => this._connectRelay(relay), 5000)
      this._restartTimers.set(relay.id, timer)
    }
    proc.on('exit', onExit)
    proc.on('error', (err) => {
      this._push({
        ts: Date.now(),
        relay: relay.id,
        level: 'error',
        msg: `[ssh-error] ${err.message}`,
        raw: err.message
      })
    })
  }

  _onData (relay, chunk) {
    // SSH delivers raw bytes; split on newline, leave any partial line in
    // the per-relay buffer for the next chunk.
    let buf = this._buffers.get(relay.id) + chunk.toString('utf8')
    const lines = buf.split('\n')
    buf = lines.pop()  // last element is the partial / empty
    this._buffers.set(relay.id, buf)

    for (const line of lines) {
      // Strip ANSI carriage returns that hiverelay's TTY status writer
      // emits; the actual log content sits at the end of those.
      const cleaned = line.replace(/.*\r/g, '').trim()
      if (!cleaned) continue
      // Drop the [status] one-liners — they're cosmetic terminal output,
      // not real events, and they'd drown the stream.
      if (cleaned.startsWith('[status]') || /^\s*\[status\]/.test(cleaned)) continue
      this._push(this._parseLine(relay, cleaned))
    }
  }

  _parseLine (relay, line) {
    // Try JSON first (pino logs are JSON). Fall back to raw text.
    if (line.startsWith('{')) {
      try {
        const obj = JSON.parse(line)
        return {
          ts: typeof obj.time === 'string' ? Date.parse(obj.time) : (obj.time || Date.now()),
          relay: relay.id,
          level: obj.level || obj.lvl || 'info',
          msg: obj.msg || obj.message || '',
          fields: obj,
          raw: line
        }
      } catch (_) {
        // fall through
      }
    }
    return {
      ts: Date.now(),
      relay: relay.id,
      level: /error|fatal/i.test(line) ? 'error' : /warn/i.test(line) ? 'warn' : 'info',
      msg: line.length > 500 ? line.slice(0, 500) + '…' : line,
      raw: line
    }
  }

  _push (entry) {
    // Append to ring + emit. The 'line' event drives the SSE fan-out.
    this.ring.push(entry)
    if (this.ring.length > this.ringSize) this.ring.shift()
    this.emit('line', entry)
  }

  /** Return the latest N entries from the ring (most recent last). */
  recent (n = 200) {
    if (n >= this.ring.length) return [...this.ring]
    return this.ring.slice(-n)
  }
}
