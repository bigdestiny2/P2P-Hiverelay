import test from 'brittle'
import { readFile } from 'node:fs/promises'
import path from 'node:path'

const WORKFLOW = path.join(process.cwd(), '.github/workflows/startos-04-container-store-smoke.yml')
const RC7_DIGEST = 'sha256:1238939f290715aa1da20629d4f1c07e73f30f1b96a518f337a3c45e729177a8'
const RC7_REF = `ghcr.io/bigdestiny2/p2p-hiverelay:0.26.0-rc.7@${RC7_DIGEST}`
const CHECKOUT_ACTION_SHA = '3d3c42e5aac5ba805825da76410c181273ba90b1'

test('StartOS 0.4 PR smoke is secret-free, read-only, and scoped to real pack inputs', async (t) => {
  const workflow = await readFile(WORKFLOW, 'utf8')

  t.ok(workflow.includes('name: StartOS 0.4 container store smoke'))
  t.ok(workflow.includes('multi-platform-digest:'))
  t.ok(workflow.includes('runs-on: ubuntu-24.04'))
  t.ok(workflow.includes('timeout-minutes: 30'))
  t.ok(workflow.includes('permissions:\n  contents: read'))
  t.ok(workflow.includes(`uses: actions/checkout@${CHECKOUT_ACTION_SHA}`))
  t.ok(workflow.includes('persist-credentials: false'))
  t.ok(workflow.includes(`HIVERELAY_IMAGE_DIGEST: ${RC7_DIGEST}`))
  t.ok(workflow.includes(`HIVERELAY_STARTOS_04_IMAGE_REF: ${RC7_REF}`))
  t.is(workflow.includes('0.26.0-rc.6'), false)
  t.is(workflow.includes('secrets.'), false)
  t.is(workflow.includes('STARTOS_DEV_KEY'), false)
  t.is(workflow.includes('gh release'), false)
  t.is(workflow.includes('actions/upload-artifact'), false)
  t.is(workflow.includes('docker push'), false)

  for (const requiredPath of [
    "'package.json'",
    "'scripts/install-startos-cli.sh'",
    "'scripts/lib/release-evidence-contract.mjs'",
    "'scripts/lib/startos-04-release-evidence.mjs'",
    "'scripts/verify-startos-04-package-manifest.mjs'",
    "'startos-0.4/**'",
    "'test/unit/startos-04-container-store-smoke-workflow.test.js'",
    "'test/unit/startos-04-release-evidence.test.js'"
  ]) t.ok(workflow.includes(requiredPath), `smoke path filter includes ${requiredPath}`)
})

test('StartOS 0.4 PR smoke performs the two-phase verifier around a real Start CLI pack', async (t) => {
  const workflow = await readFile(WORKFLOW, 'utf8')

  t.ok(workflow.includes('source_sha="$(git rev-parse --verify HEAD)"'))
  t.ok(workflow.includes('[ "$source_sha" != "$GITHUB_SHA" ]'))
  t.ok(workflow.includes('HIVERELAY_SMOKE_SOURCE_TAG=$source_tag'))
  t.ok(workflow.includes('HIVERELAY_SMOKE_SOURCE_SHA=$source_sha'))
  t.ok(workflow.includes('HIVERELAY_STARTOS_04_PACKAGE_VERSION=$package_version'))
  t.ok(workflow.includes('Universal StartOS pack requires at least 8 GiB free'))
  t.ok(workflow.includes('squashfs-tools-ng=1.2.0-1'))
  t.ok(workflow.includes('squashfs-tools=1:4.6.1-1build1'))
  t.ok(workflow.includes('bash scripts/install-startos-cli.sh "$RUNNER_TEMP/startos-cli-1.1.0" "$GITHUB_PATH"'))
  t.ok(workflow.includes('working-directory: startos-0.4\n        run: npm ci'))
  t.ok(workflow.includes('make check-release-image ingredients'))
  t.ok(workflow.includes('IMAGE_TAG="$HIVERELAY_IMAGE_NAME:$' + '{HIVERELAY_RELEASE_TAG#v}"'))
  t.ok(workflow.includes('--manifest-kind authoring'))
  t.ok(workflow.includes('--image-ref "$HIVERELAY_STARTOS_04_IMAGE_REF"'))
  t.ok(workflow.includes('start-cli init-key'))
  t.ok(workflow.includes('install -m 0600 "$key_path" "$workspace_key"'))
  t.ok(workflow.includes('start-cli s9pk pack -o blindspark.s9pk'))
  t.ok(workflow.includes('start-cli s9pk inspect blindspark.s9pk manifest --format json'))
  t.ok(workflow.includes('--manifest-kind packed'))
  t.ok(workflow.includes('--release-sha "$HIVERELAY_SMOKE_SOURCE_SHA"'))
  t.is(workflow.includes('make universal'), false)

  const checkout = workflow.indexOf('- name: Checkout')
  const sourceIdentity = workflow.indexOf('- name: Resolve checked-out source identity')
  const containerStore = workflow.indexOf('- name: Enable Docker containerd image store')
  const dependencies = workflow.indexOf('- name: Install locked StartOS dependencies')
  const authoring = workflow.indexOf('- name: Build and verify fixture-bound authoring manifest')
  const ephemeralKey = workflow.indexOf('- name: Generate ephemeral StartOS developer key')
  const pack = workflow.indexOf('- name: Pack the preverified universal package')
  const packed = workflow.indexOf('- name: Inspect and verify packed manifest')
  const noMutation = workflow.indexOf('- name: Confirm no release mutation')
  t.ok(checkout >= 0 && checkout < sourceIdentity)
  t.ok(sourceIdentity < containerStore)
  t.ok(containerStore < dependencies)
  t.ok(dependencies < authoring)
  t.ok(authoring < ephemeralKey)
  t.ok(ephemeralKey < pack)
  t.ok(pack < packed)
  t.ok(packed < noMutation)
})
