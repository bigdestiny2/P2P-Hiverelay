import test from 'brittle'
import { chmod, link, mkdir, mkdtemp, realpath, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { verifyPublicHiveGatewayQuarantine } from '../../scripts/verify-public-hive-gateway-quarantine.mjs'
import { createPublicT1OpsFixture } from '../fixtures/public-hive-gateway-ops.js'

test('public gateway quarantine verifier binds live DNS and probes every signed address', async (t) => {
  const f = await fixture(t)
  const probed = []
  const result = await verifyPublicHiveGatewayQuarantine(f.args, {
    runNginx: async () => ({ stdout: `http { gzip on; gunzip off; }\n${quarantineNginx()}`, stderr: '' }),
    collectDns: async () => exactDns(f.contract),
    probe: async address => { probed.push(address) }
  })

  t.is(result.hostname, f.appHostname)
  t.alike(result.addresses, f.contract.expectedAddresses)
  t.alike(probed, f.contract.expectedAddresses)
})

test('public gateway quarantine verifier fails DNS drift after probing the observed/signed union', async (t) => {
  const f = await fixture(t)
  const probed = []
  const dns = exactDns(f.contract)
  dns.app.ipv4.push('1.1.1.1')
  await t.exception(async () => verifyPublicHiveGatewayQuarantine(f.args, {
    runNginx: async () => ({ stdout: quarantineNginx(), stderr: '' }),
    collectDns: async () => dns,
    probe: async address => { probed.push(address) }
  }), /live quarantine DNS failed.*does not exactly match/)
  t.alike(probed, ['1.1.1.1', ...f.contract.expectedAddresses])

  const routing = exactDns(f.contract)
  routing.app.cnames.push('edge.example')
  routing.routing.app.https.push({ priority: 1, name: '.' })
  await t.exception(async () => verifyPublicHiveGatewayQuarantine(f.args, {
    runNginx: async () => ({ stdout: quarantineNginx(), stderr: '' }),
    collectDns: async () => routing,
    probe: async () => {}
  }), /must not contain CNAME.*HTTPS and SVCB RRsets must be empty/)
})

test('public gateway quarantine verifier rejects stream shadow and still exercises containment probes', async (t) => {
  const f = await fixture(t)
  const probed = []
  const stream = `${quarantineNginx()}\nstream { server { listen 443; proxy_pass 127.0.0.1:9443; } }\n`
  await t.exception(async () => verifyPublicHiveGatewayQuarantine(f.args, {
    runNginx: async () => ({ stdout: stream, stderr: '' }),
    collectDns: async () => exactDns(f.contract),
    probe: async address => { probed.push(address) }
  }), /must be in HTTP context/)
  t.alike(probed, f.contract.expectedAddresses)
})

test('public gateway quarantine verifier rejects inherited rewrites, modules, and non-probed routes', async (t) => {
  for (const [label, nginx, expected] of [
    [
      'inherited error rewrite',
      `http { error_page 421 =200 /leak; }\n${quarantineNginx()}`,
      /unreviewed inherited HTTP\/module.*error_page/
    ],
    [
      'inherited response filter',
      `http { body_filter_by_lua_file /etc/nginx/filter.lua; }\n${quarantineNginx()}`,
      /unreviewed inherited HTTP\/module.*body_filter_by_lua_file/
    ],
    [
      'non-probed default path',
      quarantineNginx().replace('    return 421;', '    location = /not-probed { return 200; }\n    return 421;'),
      /exactly one safe TLS 421 default server/
    ],
    [
      'durable default error log',
      quarantineNginx().replace('    error_log stderr crit;', '    error_log /var/log/nginx/quarantine-error.log warn;'),
      /exactly one safe TLS 421 default server/
    ]
  ]) {
    const f = await fixture(t)
    await t.exception(async () => verifyPublicHiveGatewayQuarantine(f.args, {
      runNginx: async () => ({ stdout: nginx, stderr: '' }),
      collectDns: async () => exactDns(f.contract),
      probe: async () => {}
    }), expected, label)
  }
})

test('public gateway quarantine verifier refuses linked contract and CA inputs', async (t) => {
  const f = await fixture(t)
  const linkedContract = path.join(f.root, 'contract-linked.json')
  await link(f.contractPath, linkedContract)
  await t.exception(async () => verifyPublicHiveGatewayQuarantine({ ...f.args, contract: linkedContract }),
    /single-link regular file/)
  await rm(linkedContract)

  const symlinkContract = path.join(f.root, 'contract-symlink.json')
  await symlink(f.contractPath, symlinkContract)
  await t.exception(async () => verifyPublicHiveGatewayQuarantine({ ...f.args, contract: symlinkContract }),
    /readable non-symlink file/)

  const ca = path.join(f.root, 'ca.pem')
  const linkedCa = path.join(f.root, 'ca-linked.pem')
  await writeFile(ca, 'fixture CA\n', { mode: 0o600 })
  await link(ca, linkedCa)
  await t.exception(async () => verifyPublicHiveGatewayQuarantine({ ...f.args, ca: linkedCa }, {
    runNginx: async () => ({ stdout: quarantineNginx(), stderr: '' }),
    collectDns: async () => exactDns(f.contract),
    probe: async () => {}
  }), /CA bundle must be a bounded single-link regular file/)
})

test('public gateway quarantine verifier has absolute DNS and per-probe deadlines', async (t) => {
  const dnsHang = await fixture(t)
  const afterDns = []
  await t.exception(async () => verifyPublicHiveGatewayQuarantine(dnsHang.args, {
    runNginx: async () => ({ stdout: quarantineNginx(), stderr: '' }),
    collectDns: async () => new Promise(() => {}),
    dnsTimeoutMs: 10,
    probe: async address => { afterDns.push(address) }
  }), /DNS collection exceeded its absolute deadline/)
  t.alike(afterDns, dnsHang.contract.expectedAddresses, 'signed addresses are still probed after DNS timeout')

  const probeHang = await fixture(t)
  await t.exception(async () => verifyPublicHiveGatewayQuarantine(probeHang.args, {
    runNginx: async () => ({ stdout: quarantineNginx(), stderr: '' }),
    collectDns: async () => exactDns(probeHang.contract),
    probe: async () => new Promise(() => {}),
    probeTimeoutMs: 10
  }), /probe exceeded its absolute deadline/)
})

test('public gateway quarantine verifier requires trusted nginx metadata and parents', async (t) => {
  const writable = await fixture(t)
  await chmod(writable.args.nginxBinary, 0o777)
  await t.exception(async () => verifyPublicHiveGatewayQuarantine(writable.args), /owner-trusted.*non-writable executable/)

  const linked = await fixture(t)
  const alias = path.join(linked.root, 'nginx-hardlink')
  await link(linked.args.nginxBinary, alias)
  await t.exception(async () => verifyPublicHiveGatewayQuarantine(linked.args), /single-link/)

  const unsafe = await fixture(t)
  const unsafeParent = path.join(unsafe.root, 'writable-bin')
  const unsafeBinary = path.join(unsafeParent, 'nginx')
  await mkdir(unsafeParent, { mode: 0o777 })
  await chmod(unsafeParent, 0o777)
  await writeFile(unsafeBinary, '#!/bin/sh\nexit 0\n', { mode: 0o700 })
  await t.exception(async () => verifyPublicHiveGatewayQuarantine({
    ...unsafe.args,
    nginxBinary: unsafeBinary
  }), /parent chain is writable/)

  const linkedAncestor = await fixture(t)
  const ancestor = path.join(linkedAncestor.root, 'nginx-ancestor-link')
  await symlink(linkedAncestor.root, ancestor)
  await t.exception(async () => verifyPublicHiveGatewayQuarantine({
    ...linkedAncestor.args,
    nginxBinary: path.join(ancestor, path.basename(linkedAncestor.args.nginxBinary))
  }), /path must be canonical and contain no symlink ancestors/)
})

async function fixture (t) {
  const root = await realpath(await mkdtemp(path.join(tmpdir(), 'hiverelay-quarantine-verifier-')))
  t.teardown(() => rm(root, { recursive: true, force: true }))
  const ops = createPublicT1OpsFixture()
  const contractPath = path.join(root, 'contract.json')
  const nginxBinary = path.join(root, 'nginx')
  await writeFile(contractPath, ops.contractBytes, { mode: 0o600 })
  await writeFile(nginxBinary, '#!/bin/sh\nexit 0\n', { mode: 0o700 })
  await chmod(nginxBinary, 0o700)
  return {
    root,
    contract: ops.contract,
    appHostname: ops.evidence.dns.observed.hostname,
    contractPath,
    args: {
      contract: contractPath,
      expectedDigest: ops.operatorContractSha256,
      nginxBinary
    }
  }
}

function exactDns (contract) {
  const ipv4 = contract.expectedAddresses.filter(address => !address.includes(':'))
  const ipv6 = contract.expectedAddresses.filter(address => address.includes(':'))
  const answer = () => ({ ipv4: [...ipv4], ipv6: [...ipv6], cnames: [] })
  return {
    app: answer(),
    witness: answer(),
    routing: {
      app: { https: [], svcb: [] },
      witness: { https: [], svcb: [] }
    }
  }
}

function quarantineNginx () {
  return `server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name _;
    ssl_certificate /etc/hiverelay/fullchain.pem;
    ssl_certificate_key /etc/hiverelay/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_tickets off;
    gzip off;
    gunzip off;
    access_log off;
    error_log stderr crit;
    return 421;
  }`
}
