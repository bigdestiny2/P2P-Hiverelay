#!/usr/bin/env node
// pow-issuance-v1 issuer entrypoint (operator-run, per fleet).
// Env:
//   HIVERELAY_BLIND_POW_ISSUER_KEY_FILE   32 raw bytes (preferred) — or —
//   HIVERELAY_BLIND_POW_ISSUER_KEY_HEX    64 hex chars
//   HIVERELAY_BLIND_POW_ISSUER_HOST       default 127.0.0.1
//   HIVERELAY_BLIND_POW_ISSUER_PORT       default 0 (ephemeral)
//   HIVERELAY_BLIND_POW_ISSUER_TLS_KEY / HIVERELAY_BLIND_POW_ISSUER_TLS_CERT
//                                         PEM files; when both are set the issuer
//                                         serves HTTPS (the fleet deployment mode)
//   HIVERELAY_BLIND_POW_DIFFICULTY_BITS   default 20 (1..32)
//   HIVERELAY_BLIND_POW_CHALLENGE_TTL_SECONDS default 120 (5..3600)
//   HIVERELAY_BLIND_POW_TOKEN_TTL_EPOCHS  default 2 (1..4)
//   HIVERELAY_BLIND_POW_MAX_ALLOWANCE     default 2 (1..8)
import fs from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import b4a from 'b4a'
import { createPowIssuanceV1Issuer } from './issuer-service.js'

function unsigned (environment, name, fallback, minimum, maximum) {
  const raw = environment[name]
  if (raw == null || raw === '') return fallback
  if (!/^(0|[1-9][0-9]*)$/.test(raw)) throw new Error(`${name} must be a canonical unsigned integer`)
  const value = Number(raw)
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} is outside ${minimum}..${maximum}`)
  }
  return value
}

export async function runPowIssuanceV1IssuerCli (options = {}) {
  const environment = options.environment || process.env
  let issuerKey = null
  const keyFile = environment.HIVERELAY_BLIND_POW_ISSUER_KEY_FILE
  const keyHex = environment.HIVERELAY_BLIND_POW_ISSUER_KEY_HEX
  try {
    if (typeof keyFile === 'string' && keyFile.length > 0) {
      const bytes = await fs.readFile(keyFile)
      if (bytes.byteLength !== 32) throw new Error('HIVERELAY_BLIND_POW_ISSUER_KEY_FILE must contain exactly 32 bytes')
      issuerKey = b4a.from(bytes)
    } else if (typeof keyHex === 'string' && /^[0-9a-fA-F]{64}$/.test(keyHex)) {
      issuerKey = b4a.from(keyHex, 'hex')
    } else {
      throw new Error('HIVERELAY_BLIND_POW_ISSUER_KEY_FILE or HIVERELAY_BLIND_POW_ISSUER_KEY_HEX is required')
    }
    const tlsKeyFile = environment.HIVERELAY_BLIND_POW_ISSUER_TLS_KEY
    const tlsCertFile = environment.HIVERELAY_BLIND_POW_ISSUER_TLS_CERT
    let tls = null
    if (tlsKeyFile || tlsCertFile) {
      if (!tlsKeyFile || !tlsCertFile) {
        throw new Error('HIVERELAY_BLIND_POW_ISSUER_TLS_KEY and HIVERELAY_BLIND_POW_ISSUER_TLS_CERT must be present together')
      }
      tls = { key: await fs.readFile(tlsKeyFile), cert: await fs.readFile(tlsCertFile) }
    }
    const issuer = createPowIssuanceV1Issuer({
      issuerKey,
      host: environment.HIVERELAY_BLIND_POW_ISSUER_HOST || '127.0.0.1',
      port: unsigned(environment, 'HIVERELAY_BLIND_POW_ISSUER_PORT', 0, 0, 65535),
      difficultyBits: unsigned(environment, 'HIVERELAY_BLIND_POW_DIFFICULTY_BITS', 20, 1, 32),
      challengeTtlSeconds: unsigned(environment, 'HIVERELAY_BLIND_POW_CHALLENGE_TTL_SECONDS', 120, 5, 3600),
      tokenTtlEpochs: unsigned(environment, 'HIVERELAY_BLIND_POW_TOKEN_TTL_EPOCHS', 2, 1, 4),
      maxAllowance: unsigned(environment, 'HIVERELAY_BLIND_POW_MAX_ALLOWANCE', 2, 1, 8),
      tls
    })
    const address = await issuer.start()
    process.stdout.write(
      `[pow-issuance-v1] issuer ready at http${tls ? 's' : ''}://${address.address}:${address.port} ` +
      `(difficulty=${issuer.difficultyBits} bits, challengeTtl=${issuer.challengeTtlSeconds}s, ` +
      `tokenTtl=${issuer.tokenTtlEpochs} epochs, maxAllowance=${issuer.maxAllowance})\n`)
    if (options.installSignalHandlers !== false) {
      let shutdownPromise = null
      const shutdown = signal => {
        if (shutdownPromise) return shutdownPromise
        shutdownPromise = issuer.close().catch(error => {
          process.exitCode = 1
          process.stderr.write(`[pow-issuance-v1] ${signal} shutdown failed: ${error.message}\n`)
        })
        return shutdownPromise
      }
      process.once('SIGINT', () => shutdown('SIGINT'))
      process.once('SIGTERM', () => shutdown('SIGTERM'))
    }
    return issuer
  } finally {
    if (issuerKey) issuerKey.fill(0)
  }
}

const entrypoint = process.argv[1] == null ? null : path.resolve(process.argv[1])
if (entrypoint === fileURLToPath(import.meta.url)) {
  try {
    await runPowIssuanceV1IssuerCli()
  } catch (error) {
    process.stderr.write(`[pow-issuance-v1] startup failed: ${error.message}\n`)
    process.exitCode = 1
  }
}
