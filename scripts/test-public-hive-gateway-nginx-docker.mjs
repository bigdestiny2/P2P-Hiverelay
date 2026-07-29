#!/usr/bin/env node

import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import path from 'node:path'
import {
  inspectActivePublicHiveGatewayNginx,
  renderPublicHiveGatewayNginx
} from './lib/public-hive-gateway-preflight.mjs'

const image = process.env.HIVERELAY_NGINX_TEST_IMAGE ||
  'nginx@sha256:54f2a904c251d5a34adf545a72d32515a15e08418dae0266e23be2e18c66fefa'
if (!/^[A-Za-z0-9][A-Za-z0-9./:@_-]{0,255}$/.test(image)) {
  throw new Error('HIVERELAY_NGINX_TEST_IMAGE must be a bounded Docker image reference')
}

run('docker', ['info', '--format', '{{.ServerVersion}}'], 'Docker daemon check')
run('docker', ['image', 'inspect', image, '--format', '{{.Id}}'], 'local nginx image check')

const directory = await mkdtemp(path.join(process.cwd(), '.hiverelay-nginx-proof-'))
try {
  if (!/^[A-Za-z0-9_./-]+$/.test(directory)) throw new Error('proof directory path is not nginx-safe')
  const certificate = path.join(directory, 'fullchain.pem')
  const certificateKey = path.join(directory, 'privkey.pem')
  const installedPath = path.join(directory, 'hiverelay-public-apps.conf')
  const mainPath = path.join(directory, 'nginx.conf')
  run('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', certificateKey,
    '-out', certificate,
    '-days', '1',
    '-subj', '/CN=hive-nginx-proof.invalid'
  ], 'disposable TLS certificate generation')

  const template = await readFile('deploy/public-hive-gateway/nginx.conf.template', 'utf8')
  const options = {
    suffix: 'hive-nginx-proof.invalid',
    gatewayPort: 9200,
    certificate,
    certificateKey
  }
  const rendered = renderPublicHiveGatewayNginx(template, options)
  await writeFile(mainPath, `worker_processes 1;
error_log stderr notice;
pid /tmp/hiverelay-nginx-proof.pid;

events { worker_connections 16; }

http {
  include ${installedPath};
}
`)

  await writeFile(installedPath, rendered)
  const positiveDump = runNginxDump(directory, mainPath)
  const positive = inspectActivePublicHiveGatewayNginx(positiveDump, {
    ...options,
    installedConfig: rendered,
    installedPath
  })
  assert.equal(positive.ok, true, positive.errors.join('\n'))

  const commentsOnly = rendered.split('\n').map(line => `# ${line}`).join('\n')
  await writeFile(installedPath, commentsOnly)
  const commentsDump = runNginxDump(directory, mainPath)
  const comments = inspectActivePublicHiveGatewayNginx(commentsDump, {
    ...options,
    installedConfig: commentsOnly,
    installedPath
  })
  assert.equal(comments.ok, false, 'commented directives must not satisfy the edge policy')
  assert.ok(comments.errors.some(value => value.includes('default 421 reject vhost')))

  const splitDefaults = rendered.replace('  listen 443 ssl default_server;', '  listen 443 ssl;') + `
server {
  listen 443 default_server;
  server_name competing.invalid;
  ssl_certificate ${certificate};
  ssl_certificate_key ${certificateKey};
  return 421;
}
`
  await writeFile(installedPath, splitDefaults)
  const competingDump = runNginxDump(directory, mainPath)
  const competing = inspectActivePublicHiveGatewayNginx(competingDump, {
    ...options,
    installedConfig: splitDefaults,
    installedPath
  })
  assert.equal(competing.ok, false, 'split/competing IPv4 and IPv6 defaults must fail closed')
  assert.ok(competing.errors.some(value => value.includes('no competing default')))

  console.log(JSON.stringify({
    status: 'pass',
    image,
    cases: ['rendered-installed-include', 'commented-directives', 'competing-default-vhosts']
  }))
} finally {
  await rm(directory, { recursive: true, force: true })
}

function runNginxDump (directory, mainPath) {
  const result = run('docker', [
    'run', '--rm',
    '--entrypoint', 'nginx',
    '--mount', `type=bind,source=${directory},target=${directory},readonly`,
    image,
    '-c', mainPath,
    '-T'
  ], 'nginx -T')
  assert.ok(result.stdout.startsWith('# configuration file '), 'nginx -T must emit its parsed file dump on stdout')
  return result.stdout
}

function run (command, args, label) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    maxBuffer: 12 * 1024 * 1024,
    timeout: 30_000
  })
  if (result.error || result.status !== 0) {
    const detail = String(result.stderr || result.error?.message || 'unknown failure').slice(-2000)
    throw new Error(`${label} failed: ${detail}`)
  }
  return result
}
