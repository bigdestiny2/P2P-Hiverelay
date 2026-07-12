import test from 'brittle'
import { spawnSync } from 'child_process'
import { createHash } from 'crypto'
import { chmod, lstat, mkdtemp, readFile, readdir, rm, symlink, writeFile } from 'fs/promises'
import { tmpdir } from 'os'
import path from 'path'
import {
  inspectPublicHiveGatewayAdmissionReadiness,
  inspectPublicHiveGatewayConfig,
  inspectPublicHiveGatewayNginx,
  renderPublicHiveGatewayNginx
} from '../../scripts/lib/public-hive-gateway-preflight.mjs'

const KEY = 'a'.repeat(64)
const KEY_LABEL = 'ikikikikikikikikikikikikikikikikikikikikikikikikikiy'
const CONFIG = {
  mode: 'public',
  productProfile: 'relay-core',
  enableAPI: true,
  enableSeeding: true,
  apiHost: '127.0.0.1',
  apiPort: 9100,
  gatewayHost: '127.0.0.1',
  gatewayPort: 9200,
  gatewayTrustProxy: true,
  gatewayTrustedProxyAddresses: ['127.0.0.1', '::1'],
  gatewayRequireForwardedSNI: true,
  gatewayCompatibilityHosts: ['127.0.0.1', 'localhost', '[::1]'],
  gatewayMaxInFlight: 256,
  gatewayMaxInFlightPerApp: 32,
  gatewayMaxResponseBytes: 67108864,
  gatewayMaxTransformBytes: 4194304,
  gatewayEgressBytesPerWindow: 268435456,
  gatewayEgressWindowMs: 60000,
  gatewayMaxResponseLifetimeMs: 900000,
  custody: { enabled: false },
  hiveAppHostSuffix: 'hive-canary.operator.example',
  hiveAppPublicKeys: [KEY],
  hiveAppPublicVersions: { [KEY]: 7 }
}

test('public gateway preflight - hardened single-app canary passes with explicit warnings', (t) => {
  const result = inspectPublicHiveGatewayConfig(CONFIG, {
    mode: 'canary',
    apiKeyPresent: true,
    publicSuffixReady: false
  })

  t.ok(result.ok)
  t.alike(result.errors, [])
  t.is(result.normalized.suffix, CONFIG.hiveAppHostSuffix)
  t.alike(result.normalized.appKeys, [KEY])
  t.alike(result.normalized.appVersions, { [KEY]: 7 })
  t.ok(result.warnings.some(value => value.includes('transitional-operator-allowlist-v1')))
  t.ok(result.warnings.some(value => value.includes('Public Suffix')))
})

test('public gateway preflight - one-app fleet posture waits for substrate but not PSL registration', (t) => {
  const result = inspectPublicHiveGatewayConfig(CONFIG, {
    mode: 'fleet',
    apiKeyPresent: true,
    publicSuffixReady: false
  })

  t.absent(result.ok)
  t.ok(result.errors.some(value => value.includes('transitional-operator-allowlist-v1')))
  t.absent(result.errors.some(value => value.includes('Public Suffix')),
    'one admitted production canary has no sibling app origin to isolate')
  t.ok(result.warnings.some(value => value.includes('Public Suffix')))
})

test('public gateway preflight - a production-looking profile name cannot open fleet admission', (t) => {
  const result = inspectPublicHiveGatewayAdmissionReadiness(Object.freeze({
    kind: 'public-hive-gateway-admission-capability',
    version: 1,
    profile: 'frozen-t1-production-v99',
    authority: 'local-operator-allowlist',
    fleetReady: false
  }), 'fleet')

  t.absent(result.ok)
  t.ok(result.errors.some(value => value.includes('not fleet-ready')))

  const forgedReady = inspectPublicHiveGatewayAdmissionReadiness({
    kind: 'public-hive-gateway-admission-capability',
    version: 1,
    profile: 'frozen-t1-production-v99',
    authority: 'local-operator-allowlist',
    fleetReady: true
  }, 'fleet')
  t.absent(forgedReady.ok)
})

test('public gateway preflight - multi-app Phase 1 remains closed even with a Public Suffix assertion', (t) => {
  for (const publicSuffixReady of [false, true]) {
    const result = inspectPublicHiveGatewayConfig({
      ...CONFIG,
      hiveAppPublicKeys: [KEY, 'b'.repeat(64)]
    }, {
      mode: 'fleet',
      apiKeyPresent: true,
      publicSuffixReady
    })

    t.absent(result.ok)
    t.ok(result.errors.some(value => value.includes('exactly one manifest-bound trusted app')),
      `multi-app fleet is closed when publicSuffixReady=${publicSuffixReady}`)
  }
})

test('public gateway preflight - fleet requires one matching immutable version pin while canary warns', (t) => {
  const withoutPin = { ...CONFIG, hiveAppPublicVersions: {} }
  const canary = inspectPublicHiveGatewayConfig(withoutPin, {
    mode: 'canary',
    apiKeyPresent: true,
    publicSuffixReady: false
  })
  t.ok(canary.ok)
  t.ok(canary.warnings.some(value => value.includes('exactly one immutable hiveAppPublicVersions pin')))

  const fleet = inspectPublicHiveGatewayConfig(withoutPin, {
    mode: 'fleet',
    apiKeyPresent: true,
    publicSuffixReady: false
  })
  t.absent(fleet.ok)
  t.ok(fleet.errors.some(value => value.includes('exactly one immutable hiveAppPublicVersions pin')))

  const wrongKey = inspectPublicHiveGatewayConfig({
    ...CONFIG,
    hiveAppPublicVersions: { ['b'.repeat(64)]: 7 }
  }, {
    mode: 'fleet',
    apiKeyPresent: true,
    publicSuffixReady: true
  })
  t.absent(wrongKey.ok)
  t.ok(wrongKey.errors.some(value => value.includes('outside hiveAppPublicKeys')))
})

test('public gateway preflight - unsafe topology and multi-app canary fail closed', (t) => {
  const result = inspectPublicHiveGatewayConfig({
    ...CONFIG,
    apiHost: '0.0.0.0',
    gatewayHost: '0.0.0.0',
    gatewayTrustProxy: false,
    gatewayRequireForwardedSNI: false,
    gatewayTrustedProxyAddresses: ['0.0.0.0'],
    gatewayCompatibilityHosts: ['relay.example'],
    custody: { enabled: true },
    hiveAppPublicKeys: [KEY, 'b'.repeat(64)]
  }, {
    mode: 'canary',
    apiKeyPresent: false
  })

  t.absent(result.ok)
  for (const term of [
    'gatewayHost to bind loopback',
    'exactly one manifest-bound trusted app',
    'apiHost must bind loopback',
    'gatewayTrustProxy must be true',
    'gatewayRequireForwardedSNI must be true',
    'gatewayTrustedProxyAddresses',
    'gatewayCompatibilityHosts',
    'custody.enabled must be false',
    'HIVERELAY_API_KEY'
  ]) {
    t.ok(result.errors.some(value => value.includes(term)), `failure names ${term}`)
  }
})

test('public gateway preflight - strict nginx template renders and validates', async (t) => {
  const template = await readFile('deploy/public-hive-gateway/nginx.conf.template', 'utf8')
  const rendered = renderPublicHiveGatewayNginx(template, {
    suffix: CONFIG.hiveAppHostSuffix,
    gatewayPort: CONFIG.gatewayPort,
    certificate: '/etc/letsencrypt/live/hive/fullchain.pem',
    certificateKey: '/etc/letsencrypt/live/hive/privkey.pem'
  })
  const result = inspectPublicHiveGatewayNginx(rendered, {
    suffix: CONFIG.hiveAppHostSuffix,
    gatewayPort: CONFIG.gatewayPort
  })

  t.ok(result.ok)
  t.alike(result.errors, [])
  t.ok(rendered.includes(`127.0.0.1:${CONFIG.gatewayPort}`))
  t.ok(rendered.includes('server_name "~^'), 'nginx regex with a {52} quantifier stays quoted')
  t.ok(rendered.includes('proxy_set_header Accept-Encoding "";'), 'browser encodings are stripped before the loopback upstream')
  t.absent(rendered.includes('__HIVE_'), 'all deployment placeholders resolved')
  t.exception(() => renderPublicHiveGatewayNginx(template, {
    suffix: CONFIG.hiveAppHostSuffix,
    gatewayPort: CONFIG.gatewayPort,
    certificate: '/safe/cert.pem; include /tmp/evil',
    certificateKey: '/safe/key.pem'
  }), /safe absolute path/)
  t.exception(() => renderPublicHiveGatewayNginx(template, {
    suffix: CONFIG.hiveAppHostSuffix,
    gatewayPort: CONFIG.gatewayPort,
    certificate: '/safe/{dynamic}.pem',
    certificateKey: '/safe/key.pem'
  }), /safe absolute path/)
})

test('public gateway preflight - permissive forwarding or caching proxy is rejected', (t) => {
  const unsafe = `
    server_name app.${CONFIG.hiveAppHostSuffix};
    proxy_pass http://127.0.0.1:${CONFIG.gatewayPort};
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_cache shared;
    gzip on;
  `
  const result = inspectPublicHiveGatewayNginx(unsafe, {
    suffix: CONFIG.hiveAppHostSuffix,
    gatewayPort: CONFIG.gatewayPort
  })

  t.absent(result.ok)
  t.ok(result.errors.some(value => value.includes('must not append')))
  t.ok(result.errors.some(value => value.includes('cache must be disabled')))
  t.ok(result.errors.some(value => value.includes('must not transform')))
  t.ok(result.errors.some(value => value.includes('attest the TLS SNI')))
  t.ok(result.errors.some(value => value.includes('default 421 reject vhost')))
  t.ok(result.errors.some(value => value.includes('discard request bodies')))
  t.ok(result.errors.some(value => value.includes('request-rate throttling must return 429')))
  t.ok(result.errors.some(value => value.includes('connection throttling must return 429')))
})

test('public gateway preflight - commented safety directives are not evidence', async (t) => {
  const template = await readFile('deploy/public-hive-gateway/nginx.conf.template', 'utf8')
  const rendered = renderPublicHiveGatewayNginx(template, {
    suffix: CONFIG.hiveAppHostSuffix,
    gatewayPort: CONFIG.gatewayPort,
    certificate: '/etc/hiverelay/public-gateway/fullchain.pem',
    certificateKey: '/etc/hiverelay/public-gateway/privkey.pem'
  })
  const commentsOnly = rendered.split('\n').map(line => `# ${line}`).join('\n')
  const result = inspectPublicHiveGatewayNginx(commentsOnly, {
    suffix: CONFIG.hiveAppHostSuffix,
    gatewayPort: CONFIG.gatewayPort
  })

  t.absent(result.ok)
  t.ok(result.errors.some(value => value.includes('default 421 reject vhost')))
  t.ok(result.errors.some(value => value.includes('loopback gateway port')))
  t.ok(result.errors.some(value => value.includes('attest the TLS SNI')))

  const duplicated = inspectPublicHiveGatewayNginx(`${rendered}\n${rendered}`, {
    suffix: CONFIG.hiveAppHostSuffix,
    gatewayPort: CONFIG.gatewayPort
  })
  t.absent(duplicated.ok)
  t.ok(duplicated.errors.some(value => value.includes('no competing default')))
  t.ok(duplicated.errors.some(value => value.includes('exactly one active quoted app-key server block')))
})

test('public gateway preflight - quoted claims and reordered competing listeners are not evidence', async (t) => {
  const template = await readFile('deploy/public-hive-gateway/nginx.conf.template', 'utf8')
  const rendered = renderPublicHiveGatewayNginx(template, {
    suffix: CONFIG.hiveAppHostSuffix,
    gatewayPort: CONFIG.gatewayPort,
    certificate: '/etc/hiverelay/public-gateway/fullchain.pem',
    certificateKey: '/etc/hiverelay/public-gateway/privkey.pem'
  })
  const quotedClaim = rendered.replace('proxy_cache off;', 'set $claim "proxy_cache off;";\n  proxy_cache on;')
  const quotedResult = inspectPublicHiveGatewayNginx(quotedClaim, {
    suffix: CONFIG.hiveAppHostSuffix,
    gatewayPort: CONFIG.gatewayPort
  })
  t.absent(quotedResult.ok)
  t.ok(quotedResult.errors.some(value => value.includes('cache must be disabled')))

  const competing = `${rendered}\nserver {
    listen 127.0.0.2:443 default_server;
    server_name competing.example;
    return 421;
  }\n`
  const competingResult = inspectPublicHiveGatewayNginx(competing, {
    suffix: CONFIG.hiveAppHostSuffix,
    gatewayPort: CONFIG.gatewayPort
  })
  t.absent(competingResult.ok)
  t.ok(competingResult.errors.some(value => value.includes('no competing default')))

  const duplicateHost = rendered.replace(
    'proxy_set_header Host $host;',
    'proxy_set_header Host $host;\n    proxy_set_header Host $http_host;'
  )
  const duplicateHostResult = inspectPublicHiveGatewayNginx(duplicateHost, {
    suffix: CONFIG.hiveAppHostSuffix,
    gatewayPort: CONFIG.gatewayPort
  })
  t.absent(duplicateHostResult.ok)
  t.ok(duplicateHostResult.errors.some(value => value.includes('duplicate or unreviewed overrides')))

  const defaultRedirect = rendered.replace(
    '  access_log off;\n  error_log stderr crit;\n  return 421;',
    '  access_log off;\n  error_log stderr crit;\n  error_page 421 = https://api.example;\n  return 421;'
  )
  const defaultRedirectResult = inspectPublicHiveGatewayNginx(defaultRedirect, {
    suffix: CONFIG.hiveAppHostSuffix,
    gatewayPort: CONFIG.gatewayPort
  })
  t.absent(defaultRedirectResult.ok)
  t.ok(defaultRedirectResult.errors.some(value => value.includes('default 421 reject vhost')))
})

test('public gateway preflight - every sibling TLS vhost shares the reviewed HTTP socket topology', async (t) => {
  const template = await readFile('deploy/public-hive-gateway/nginx.conf.template', 'utf8')
  const rendered = renderPublicHiveGatewayNginx(template, {
    suffix: CONFIG.hiveAppHostSuffix,
    gatewayPort: CONFIG.gatewayPort,
    certificate: '/etc/hiverelay/public-gateway/fullchain.pem',
    certificateKey: '/etc/hiverelay/public-gateway/privkey.pem'
  })
  const inspect = extra => inspectPublicHiveGatewayNginx(`${rendered}\n${extra}`, {
    suffix: CONFIG.hiveAppHostSuffix,
    gatewayPort: CONFIG.gatewayPort
  })
  const management = inspect(`server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name management.example;
    return 421;
  }`)
  t.ok(management.ok, 'an exact unrelated management name may share the reviewed wildcard sockets')

  for (const [name, fixture, expected] of [
    ['address-specific', `server {
      listen 192.0.2.10:443 ssl;
      server_name management.example;
      return 421;
    }`, 'shared wildcard'],
    ['socket-option', `server {
      listen 443 ssl reuseport;
      listen [::]:443 ssl;
      server_name management.example;
      return 421;
    }`, 'shared wildcard'],
    ['unnamed', `server {
      listen 443 ssl;
      listen [::]:443 ssl;
      return 421;
    }`, 'explicit server_name'],
    ['stream', `stream {
      server {
        listen 443;
        proxy_pass 127.0.0.1:9443;
      }
    }`, 'HTTP context'],
    ['stream-include-dump', `# configuration file /etc/nginx/nginx.conf:
      stream { include /etc/nginx/stream-enabled/*.conf; }
      # configuration file /etc/nginx/stream-enabled/tls.conf:
      server { listen 443; proxy_pass 127.0.0.1:9443; }
    `, 'stream context'],
    ['exact-app-host', `server {
      listen 443 ssl;
      listen [::]:443 ssl;
      server_name ${'y'.repeat(52)}.${CONFIG.hiveAppHostSuffix};
      return 421;
    }`, 'shadow'],
    ['wildcard-app-host', `server {
      listen 443 ssl;
      listen [::]:443 ssl;
      server_name *.${CONFIG.hiveAppHostSuffix};
      return 421;
    }`, 'shadow'],
    ['regex', `server {
      listen 443 ssl;
      listen [::]:443 ssl;
      server_name ~^management\\.;
      return 421;
    }`, 'shadow']
  ]) {
    const result = inspect(fixture)
    t.absent(result.ok, `${name} sibling is rejected`)
    t.ok(result.errors.some(value => value.includes(expected)), `${name} failure names ${expected}`)
  }
})

test('public gateway preflight - inherited and module directives use a closed posture', async (t) => {
  const template = await readFile('deploy/public-hive-gateway/nginx.conf.template', 'utf8')
  const rendered = renderPublicHiveGatewayNginx(template, {
    suffix: CONFIG.hiveAppHostSuffix,
    gatewayPort: CONFIG.gatewayPort,
    certificate: '/etc/hiverelay/public-gateway/fullchain.pem',
    certificateKey: '/etc/hiverelay/public-gateway/privkey.pem'
  })
  for (const directive of [
    'brotli on;',
    'zstd on;',
    'gzip_static on;',
    'ssi on;',
    'sub_filter before after;',
    'subs_filter before after;',
    'body_filter_by_lua_file /etc/nginx/filter.lua;',
    'pagespeed on;',
    'add_before_body /prefix;',
    'image_filter resize 100 100;',
    'xslt_stylesheet /etc/nginx/transform.xslt;',
    'charset utf-8;',
    'load_module modules/ngx_http_hostile_filter_module.so;'
  ]) {
    const result = inspectPublicHiveGatewayNginx(`${directive}\n${rendered}`, {
      suffix: CONFIG.hiveAppHostSuffix,
      gatewayPort: CONFIG.gatewayPort
    })
    t.absent(result.ok, directive)
    t.ok(result.errors.some(value => value.includes('unreviewed inherited HTTP/module')), directive)
  }

  const inherited = inspectPublicHiveGatewayNginx(`http {
    subs_filter before after;
  }
  ${rendered}`, {
    suffix: CONFIG.hiveAppHostSuffix,
    gatewayPort: CONFIG.gatewayPort
  })
  t.absent(inherited.ok)
  t.ok(inherited.errors.some(value => value.includes('subs_filter')))

  const unprobedPath = rendered.replace('  location / {', `  location = /not-probed {
    body_filter_by_lua_file /etc/nginx/filter.lua;
    return 200;
  }

  location / {`)
  const unprobed = inspectPublicHiveGatewayNginx(unprobedPath, {
    suffix: CONFIG.hiveAppHostSuffix,
    gatewayPort: CONFIG.gatewayPort
  })
  t.absent(unprobed.ok)
  t.ok(unprobed.errors.some(value => value.includes('outside the reviewed Phase 1 policy')),
    'a transform on a path outside the live probe is still rejected structurally')

  const missingIdentity = inspectPublicHiveGatewayNginx(
    rendered.replace('    proxy_set_header Accept-Encoding "";\n', ''),
    { suffix: CONFIG.hiveAppHostSuffix, gatewayPort: CONFIG.gatewayPort }
  )
  t.absent(missingIdentity.ok)
  t.ok(missingIdentity.errors.some(value => value.includes('identity transfer encoding upstream')))

  const duplicateIdentity = inspectPublicHiveGatewayNginx(
    rendered.replace(
      '    proxy_set_header Accept-Encoding "";',
      '    proxy_set_header Accept-Encoding "";\n    proxy_set_header Accept-Encoding gzip;'
    ),
    { suffix: CONFIG.hiveAppHostSuffix, gatewayPort: CONFIG.gatewayPort }
  )
  t.absent(duplicateIdentity.ok)
  t.ok(duplicateIdentity.errors.some(value => value.includes('duplicate or unreviewed overrides')))

  const inheritedEncoding = inspectPublicHiveGatewayNginx(
    `proxy_set_header Accept-Encoding gzip;\n${rendered}`,
    { suffix: CONFIG.hiveAppHostSuffix, gatewayPort: CONFIG.gatewayPort }
  )
  t.absent(inheritedEncoding.ok)
  t.ok(inheritedEncoding.errors.some(value => value.includes('unreviewed inherited HTTP/module')))

  const accessLogging = inspectPublicHiveGatewayNginx(
    rendered.replace('  access_log off;\n  error_log stderr crit;\n  server_tokens off;',
      '  access_log /var/log/nginx/hive-app-access.log;\n  error_log stderr crit;\n  server_tokens off;'),
    { suffix: CONFIG.hiveAppHostSuffix, gatewayPort: CONFIG.gatewayPort }
  )
  t.absent(accessLogging.ok)
  t.ok(accessLogging.errors.some(value => value.includes('disable durable request access logging')))

  const fileErrorLogging = inspectPublicHiveGatewayNginx(
    rendered.replace('  error_log stderr crit;\n  server_tokens off;',
      '  error_log /var/log/nginx/hive-app-error.log warn;\n  server_tokens off;'),
    { suffix: CONFIG.hiveAppHostSuffix, gatewayPort: CONFIG.gatewayPort }
  )
  t.absent(fileErrorLogging.ok)
  t.ok(fileErrorLogging.errors.some(value => value.includes('critical stderr events')))
})

test('public gateway preflight - stock-shaped parent gzip remains isolated by explicit server overrides', async (t) => {
  const template = await readFile('deploy/public-hive-gateway/nginx.conf.template', 'utf8')
  const rendered = renderPublicHiveGatewayNginx(template, {
    suffix: CONFIG.hiveAppHostSuffix,
    gatewayPort: CONFIG.gatewayPort,
    certificate: '/etc/hiverelay/public-gateway/fullchain.pem',
    certificateKey: '/etc/hiverelay/public-gateway/privkey.pem'
  })
  const active = `
    user www-data;
    worker_processes auto;
    pid /run/nginx.pid;
    error_log /var/log/nginx/error.log;
    include /etc/nginx/modules-enabled/*.conf;
    events { worker_connections 768; }
    http {
      sendfile on;
      tcp_nopush on;
      tcp_nodelay on;
      types_hash_max_size 2048;
      default_type application/octet-stream;
      ssl_protocols TLSv1.2 TLSv1.3;
      ssl_prefer_server_ciphers on;
      access_log /var/log/nginx/access.log;
      keepalive_timeout 65;
      gzip on;
      gunzip off;
      include /etc/nginx/mime.types;
      include /etc/nginx/conf.d/*.conf;
    }
    types {
      text/html html htm;
      application/javascript js;
      application/octet-stream bin exe dll;
    }
    ${rendered}
  `
  const result = inspectPublicHiveGatewayNginx(active, {
    suffix: CONFIG.hiveAppHostSuffix,
    gatewayPort: CONFIG.gatewayPort
  })

  t.ok(result.ok)
  t.alike(result.errors, [])

  const inheritedDefault = inspectPublicHiveGatewayNginx(
    rendered.replace(
      '  gzip off;\n  gunzip off;\n  access_log off;\n  error_log stderr crit;\n  return 421;',
      '  access_log off;\n  error_log stderr crit;\n  return 421;'
    ),
    { suffix: CONFIG.hiveAppHostSuffix, gatewayPort: CONFIG.gatewayPort }
  )
  t.absent(inheritedDefault.ok)
  t.ok(inheritedDefault.errors.some(value => value.includes('default 421 reject vhost')))

  const defaultFileLogging = inspectPublicHiveGatewayNginx(
    rendered.replace(
      '  access_log off;\n  error_log stderr crit;\n  return 421;',
      '  access_log off;\n  error_log /var/log/nginx/default-error.log warn;\n  return 421;'
    ),
    { suffix: CONFIG.hiveAppHostSuffix, gatewayPort: CONFIG.gatewayPort }
  )
  t.absent(defaultFileLogging.ok)
  t.ok(defaultFileLogging.errors.some(value => value.includes('default 421 reject vhost')))
})

test('public gateway preflight CLI - installed nginx input is inspected and hashed exactly', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-installed-nginx-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const template = await readFile('deploy/public-hive-gateway/nginx.conf.template', 'utf8')
  const installed = renderPublicHiveGatewayNginx(template, {
    suffix: CONFIG.hiveAppHostSuffix,
    gatewayPort: CONFIG.gatewayPort,
    certificate: '/etc/hiverelay/public-gateway/fullchain.pem',
    certificateKey: '/etc/hiverelay/public-gateway/privkey.pem'
  })
  const installedPath = path.join(dir, 'public-gateway.conf')
  await writeFile(installedPath, installed)

  const result = spawnSync(process.execPath, [
    'scripts/preflight-public-hive-gateway.mjs',
    '--config', 'deploy/public-hive-gateway/hiverelay-config.example.json',
    '--nginx-config', installedPath
  ], {
    encoding: 'utf8',
    env: { ...process.env, HIVERELAY_API_KEY: 'unit-test-present' }
  })
  t.is(result.status, 0, result.stderr)
  const evidence = JSON.parse(result.stdout)
  t.is(evidence.nginx.source, 'installed')
  t.is(evidence.nginx.sha256, createHash('sha256').update(installed).digest('hex'))
  t.ok(evidence.nginx.ok)
})

test('public gateway preflight CLI - active nginx parser output is the attested configuration', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-active-nginx-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const template = await readFile('deploy/public-hive-gateway/nginx.conf.template', 'utf8')
  const installed = renderPublicHiveGatewayNginx(template, {
    suffix: CONFIG.hiveAppHostSuffix,
    gatewayPort: CONFIG.gatewayPort,
    certificate: '/etc/hiverelay/public-gateway/fullchain.pem',
    certificateKey: '/etc/hiverelay/public-gateway/privkey.pem'
  })
  const installedPath = path.join(dir, 'public-gateway.conf')
  const activePath = path.join(dir, 'active.conf')
  const fakeNginx = path.join(dir, 'nginx')
  const active = `${'# bounded filler from another parsed file\n'.repeat(9000)}` +
    '# configuration file /etc/nginx/nginx.conf:\nevents {}\nhttp {}\n\n' +
    `# configuration file ${installedPath}:\n${installed}`
  await writeFile(installedPath, installed)
  await writeFile(activePath, active)
  await writeFile(fakeNginx, '#!/bin/sh\n[ "$1" = "-T" ] || exit 2\nexec /bin/cat "$HIVERELAY_TEST_ACTIVE_NGINX"\n')
  await chmod(fakeNginx, 0o755)

  const result = spawnSync(process.execPath, [
    'scripts/preflight-public-hive-gateway.mjs',
    '--config', 'deploy/public-hive-gateway/hiverelay-config.example.json',
    '--nginx-config', installedPath,
    '--nginx-binary', fakeNginx
  ], {
    encoding: 'utf8',
    env: {
      ...process.env,
      HIVERELAY_API_KEY: 'unit-test-present',
      HIVERELAY_TEST_ACTIVE_NGINX: activePath
    }
  })
  t.is(result.status, 0, result.stderr)
  const evidence = JSON.parse(result.stdout)
  t.is(evidence.nginx.source, 'active')
  t.is(evidence.nginx.sha256, createHash('sha256').update(active).digest('hex'))
  t.ok(evidence.nginx.ok)

  await writeFile(activePath, `# configuration file /etc/nginx/not-installed.conf:\n${installed}`)
  const missing = spawnSync(process.execPath, [
    'scripts/preflight-public-hive-gateway.mjs',
    '--config', 'deploy/public-hive-gateway/hiverelay-config.example.json',
    '--nginx-config', installedPath,
    '--nginx-binary', fakeNginx
  ], {
    encoding: 'utf8',
    env: {
      ...process.env,
      HIVERELAY_API_KEY: 'unit-test-present',
      HIVERELAY_TEST_ACTIVE_NGINX: activePath
    }
  })
  t.not(missing.status, 0)
  t.ok(JSON.parse(missing.stdout).nginx.errors.some(value => value.includes('identify the installed')))
})

test('public gateway preflight CLI - no-follow input rejects a config symlink', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-preflight-symlink-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const config = path.join(dir, 'config.json')
  const linkedConfig = path.join(dir, 'linked-config.json')
  await writeFile(config, JSON.stringify(CONFIG))
  await symlink(config, linkedConfig)

  const result = spawnSync(process.execPath, [
    'scripts/preflight-public-hive-gateway.mjs',
    '--config', linkedConfig
  ], {
    encoding: 'utf8',
    env: { ...process.env, HIVERELAY_API_KEY: 'unit-test-present' }
  })

  t.not(result.status, 0)
  t.ok(result.stderr.includes('gateway config must be a bounded regular file'))
})

test('public gateway preflight CLI - atomic output replaces but never follows a destination symlink', async (t) => {
  const dir = await mkdtemp(path.join(tmpdir(), 'hiverelay-preflight-atomic-'))
  t.teardown(() => rm(dir, { recursive: true, force: true }))
  const sentinel = path.join(dir, 'sentinel.txt')
  const evidencePath = path.join(dir, 'evidence.json')
  await writeFile(sentinel, 'do-not-overwrite\n')
  await symlink(sentinel, evidencePath)

  const result = spawnSync(process.execPath, [
    'scripts/preflight-public-hive-gateway.mjs',
    '--config', 'deploy/public-hive-gateway/hiverelay-config.example.json',
    '--evidence', evidencePath
  ], {
    encoding: 'utf8',
    env: { ...process.env, HIVERELAY_API_KEY: 'unit-test-present' }
  })

  t.is(result.status, 0, result.stderr)
  t.is(await readFile(sentinel, 'utf8'), 'do-not-overwrite\n')
  const evidenceInfo = await lstat(evidencePath)
  t.ok(evidenceInfo.isFile())
  t.absent(evidenceInfo.isSymbolicLink())
  t.is(evidenceInfo.mode & 0o077, 0, 'atomic output is not group/world accessible')
  t.alike(JSON.parse(await readFile(evidencePath, 'utf8')), JSON.parse(result.stdout))
  t.alike((await readdir(dir)).sort(), ['evidence.json', 'sentinel.txt'])
})

test('public gateway preflight CLI - deployment option mistakes fail closed', (t) => {
  const script = 'scripts/preflight-public-hive-gateway.mjs'
  const config = 'deploy/public-hive-gateway/hiverelay-config.example.json'
  const run = (...args) => spawnSync(process.execPath, [script, '--config', config, ...args], {
    encoding: 'utf8',
    env: { ...process.env, HIVERELAY_API_KEY: 'unit-test-present' }
  })

  const unknown = run('--probe-orign', 'https://example.test/')
  t.not(unknown.status, 0)
  t.ok(unknown.stderr.includes('Unknown option: --probe-orign'))

  const outputWithoutTemplate = run('--nginx-output', '/tmp/should-not-exist.conf')
  t.not(outputWithoutTemplate.status, 0)
  t.ok(outputWithoutTemplate.stderr.includes('--nginx-output requires --nginx-template'))

  const pathWithoutProbe = run('--path', '/index.html')
  t.not(pathWithoutProbe.status, 0)
  t.ok(pathWithoutProbe.stderr.includes('--path') && pathWithoutProbe.stderr.includes('--probe-origin'))

  const connectWithoutProbe = run('--connect-address', '127.0.0.1')
  t.not(connectWithoutProbe.status, 0)
  t.ok(connectWithoutProbe.stderr.includes('--connect-address') && connectWithoutProbe.stderr.includes('--probe-origin'))

  const invalidConnectAddress = run(
    '--probe-origin', `https://${KEY_LABEL}.${CONFIG.hiveAppHostSuffix}`,
    '--connect-address', 'localhost'
  )
  t.not(invalidConnectAddress.status, 0)
  t.ok(invalidConnectAddress.stderr.includes('--connect-address must be an explicit IP address'))

  const offlineFleetEvidence = run('--mode', 'fleet')
  t.not(offlineFleetEvidence.status, 0)
  t.ok(offlineFleetEvidence.stderr.includes('--mode fleet evidence requires --probe-origin'))

  const unattributedFleetProbe = run(
    '--mode', 'fleet',
    '--probe-origin', `https://${KEY_LABEL}.${CONFIG.hiveAppHostSuffix}`
  )
  t.not(unattributedFleetProbe.status, 0)
  t.ok(unattributedFleetProbe.stderr.includes('--mode fleet live evidence requires --connect-address'))

  const ambiguousNginx = run(
    '--nginx-template', '/tmp/template.conf',
    '--nginx-config', '/tmp/installed.conf',
    '--certificate', '/tmp/cert.pem',
    '--certificate-key', '/tmp/key.pem'
  )
  t.not(ambiguousNginx.status, 0)
  t.ok(ambiguousNginx.stderr.includes('mutually exclusive'))
})
