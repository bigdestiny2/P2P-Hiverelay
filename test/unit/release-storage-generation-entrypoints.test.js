import test from 'brittle'
import { readFileSync } from 'fs'

const REQUIRED_ENV = [
  'HIVERELAY_REQUIRE_GENERATION_RECEIPT',
  'HIVERELAY_GENERATION_RECEIPT',
  'HIVERELAY_GENERATION_RECEIPT_SHA256_FILE'
]

test('RC9 Node, Pear, image, and service launchers require one external pinned receipt', (t) => {
  const cli = read('packages/core/cli/index.js')
  const pear = read('packages/core/pear-entry.js')
  const docker = read('Dockerfile')
  const service = read('hiverelay.service')

  for (const name of REQUIRED_ENV) t.ok(cli.includes(name), `Node CLI binds ${name}`)
  t.ok(cli.includes("participant: 'relay-node'"))
  t.ok(cli.includes('resolveCorestoreGenerationReceiptLaunch'))
  t.ok(pear.includes('required: true'))
  t.ok(pear.includes("participant: 'bare-relay'"))
  t.ok(pear.includes('generationLaunch.hiverelayGeneration'))
  for (const name of REQUIRED_ENV) t.ok(docker.includes(name), `Docker image pins ${name}`)
  t.ok(docker.includes('node", "/app/packages/core/cli/index.js"'), 'release image remains the non-blind relay entrypoint')
  for (const name of REQUIRED_ENV) t.ok(service.includes(name), `systemd service pins ${name}`)
  t.ok(service.includes('ReadOnlyPaths=/etc/hiverelay/storage-generation-receipt.v1.json'))
})

test('RC9 appliance launchers mount receipt material separately and fail closed', (t) => {
  const surfaces = [
    ['Umbrel', 'umbrel-app/docker-compose.yml'],
    ['Runtipi', 'runtipi-app/apps/blindspark/docker-compose.yml'],
    ['ZimaOS', 'zimaos-app/Apps/Blindspark/docker-compose.yml'],
    ['TrueNAS', 'truenas-app/templates/docker-compose.yaml'],
    ['StartOS 0.3', 'startos/docker_entrypoint.sh'],
    ['StartOS 0.4', 'startos-0.4/startos/main.ts']
  ]
  for (const [label, file] of surfaces) {
    const source = read(file)
    for (const name of REQUIRED_ENV) t.ok(source.includes(name), `${label} binds ${name}`)
  }
  for (const file of [
    'umbrel-app/docker-compose.yml',
    'runtipi-app/apps/blindspark/docker-compose.yml',
    'zimaos-app/Apps/Blindspark/docker-compose.yml'
  ]) {
    const source = read(file)
    t.ok(source.includes('storage-generation'))
    t.ok(source.includes('/config'))
    t.ok(source.includes('ro') || source.includes('read_only: true'))
  }
  t.ok(read('unraid-app/templates/blindspark.xml').includes('Target="/config"'))
  t.ok(read('unraid-app/templates/blindspark.xml').includes('Mode="ro"'))
  t.ok(read('truenas-app/questions.yaml').includes('variable: generation'))
  t.ok(read('truenas-app/questions.yaml').includes('default: true'))
  t.ok(read('startos/manifest.yaml').includes('generation: /config'))
  t.ok(read('startos-0.4/startos/main.ts').includes("mountpoint: '/config'"))
  t.ok(read('startos-0.4/startos/main.ts').includes('readonly: true'))
})

test('RC9 stays non-blind while public blind production remains non-overridably disabled', (t) => {
  const blind = read('packages/blind-daemon/production-runtime.js')
  const image = read('Dockerfile')
  t.ok(blind.includes('BLIND_STORAGE_GENERATION_UNSAFE'))
  t.ok(blind.includes('RC9 blind production is disabled'))
  t.ok(image.includes('/app/packages/core/cli/index.js'))
  t.absent(image.includes('/app/packages/blind-daemon/production-entrypoint.js'))
})

function read (file) {
  return readFileSync(file, 'utf8')
}
