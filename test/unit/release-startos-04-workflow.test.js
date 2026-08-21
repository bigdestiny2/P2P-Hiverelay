import test from 'brittle'
import { execFile } from 'node:child_process'
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

const WORKFLOW = path.join(process.cwd(), '.github/workflows/release-startos-0.4.yml')
const LEGACY_WORKFLOW = path.join(process.cwd(), '.github/workflows/release-surfaces.yml')
const MAKEFILE = path.join(process.cwd(), 'startos-0.4/Makefile')
const ASSETS_README = path.join(process.cwd(), 'startos-0.4/assets/README.md')
const RELEASE_ASSET = 'blindspark-startos-0.4.s9pk'
const RELEASE_EVIDENCE = 'startos-0.4-release-evidence.json'
const WORKSPACE_KEY = '.startos/build.key.pem'
const LEGACY_RELEASE_UPLOAD = 'gh release upload "$' + '{{ steps.rel.outputs.version }}" startos/blindspark.s9pk --clobber'
const SETUP_ACTION_SHA = '21507e89e717a303cb1064ac4c853d28b96d323b'
const START_CLI_SHA256 = '70eff67b6e9a936acd8aaaf787b783819252ecedaa5c74d462e3b15ed4dd843a'
const GITHUB_EXPRESSION = '$' + '{{'

test('StartOS 0.4 release workflow copies the generated ephemeral key', async (t) => {
  const fixture = await workflowFixture(t, 'generated-key')
  const result = await runConfigureKey(fixture, '')

  t.is(result.status, 0)
  t.is(await readFile(path.join(fixture.root, WORKSPACE_KEY), 'utf8'), 'ephemeral-key')
  t.is((await stat(path.join(fixture.root, WORKSPACE_KEY))).mode & 0o777, 0o600)
})

test('StartOS 0.4 release workflow keeps the configured developer key path', async (t) => {
  const fixture = await workflowFixture(t, 'unexpected-cli')
  const result = await runConfigureKey(fixture, 'configured-key')

  t.is(result.status, 0)
  t.is(await readFile(path.join(fixture.home, '.startos/developer.key.pem'), 'utf8'), 'configured-key')
  t.is(await readFile(path.join(fixture.root, WORKSPACE_KEY), 'utf8'), 'configured-key')
})

test('StartOS 0.4 release workflow fails closed when key generation writes no key', async (t) => {
  const fixture = await workflowFixture(t, 'missing-key')
  const result = await runConfigureKey(fixture, '')

  t.is(result.status, 1)
  t.ok(result.stderr.includes('StartOS developer key is missing or empty'))
})

test('StartOS 0.4 release build has the required inputs and deterministic universal output', async (t) => {
  const [workflow, makefile, assetsReadme] = await Promise.all([
    readFile(WORKFLOW, 'utf8'),
    readFile(MAKEFILE, 'utf8'),
    readFile(ASSETS_README, 'utf8')
  ])

  t.ok(makefile.includes('TARGETS := universal'))
  t.ok(makefile.includes('include node_modules/@start9labs/start-sdk/s9pk.mk'))
  t.ok(assetsReadme.includes('requires this directory as an `s9pk` build ingredient'))
  t.ok(workflow.includes('cp "$key_path" ../.startos/build.key.pem'))
  t.is(workflow.includes('.startos/build-key'), false)
  t.ok(workflow.includes('make universal REQUIRE_RELEASE_IMAGE_DIGEST=1 IMAGE_DIGEST="$HIVERELAY_IMAGE_DIGEST"'))
  t.ok(workflow.includes('start-cli s9pk inspect "$STARTOS_04_RELEASE_ASSET" commitment'))
  t.ok(workflow.includes('manifest --format json'))
  t.ok(workflow.includes('verify-startos-04-package-manifest.mjs'))
  t.ok(workflow.includes('--package-version "$HIVERELAY_STARTOS_04_PACKAGE_VERSION"'))
  t.is(workflow.includes('start-cli s9pk verify'), false)
  t.ok(workflow.includes('mv blindspark.s9pk "$STARTOS_04_RELEASE_ASSET"'))
  t.ok(workflow.indexOf('make universal') < workflow.indexOf('start-cli s9pk inspect'))
  t.ok(workflow.indexOf('mv blindspark.s9pk') < workflow.indexOf('start-cli s9pk inspect'))
})

test('StartOS release workflows preserve the legacy asset and publish 0.4 immutably', async (t) => {
  const [workflow, legacyWorkflow] = await Promise.all([
    readFile(WORKFLOW, 'utf8'),
    readFile(LEGACY_WORKFLOW, 'utf8')
  ])

  t.ok(workflow.includes(`STARTOS_04_RELEASE_ASSET: ${RELEASE_ASSET}`))
  t.ok(workflow.includes(`STARTOS_04_RELEASE_EVIDENCE: ${RELEASE_EVIDENCE}`))
  t.ok(workflow.includes('gh release upload "$tag" "$STARTOS_04_RELEASE_ASSET" --repo "$GITHUB_REPOSITORY"'))
  t.is(workflow.includes('gh release upload "$tag" "$STARTOS_04_RELEASE_ASSET" --clobber'), false)
  t.is(workflow.includes('gh release upload "$tag" blindspark.s9pk --clobber'), false)
  t.ok(workflow.includes('refusing to replace a published StartOS 0.4 package'))
  t.ok(workflow.includes('Verify published StartOS 0.4 handoff'))
  t.ok(legacyWorkflow.includes(LEGACY_RELEASE_UPLOAD))
  t.is(legacyWorkflow.includes(`gh release upload "$tag" "${RELEASE_ASSET}"`), false)
  t.is(legacyWorkflow.includes(`${RELEASE_ASSET}" --clobber`), false)
  t.ok(legacyWorkflow.includes(`--pattern '${RELEASE_ASSET}'`), 'parent closure verifies but never writes the 0.4 asset')
})

test('StartOS 0.4 dispatch is source ordered and exact-tag checked before keys', async (t) => {
  const [workflow, legacyWorkflow] = await Promise.all([
    readFile(WORKFLOW, 'utf8'),
    readFile(LEGACY_WORKFLOW, 'utf8')
  ])

  t.is(workflow.includes('release:\n    types: [published]'), false)
  t.ok(workflow.includes('release_surfaces_run_id:'))
  t.ok(workflow.includes('timeout-minutes: 60'))
  t.ok(workflow.includes('git rev-parse --verify "$tag_ref^{commit}"'))
  t.ok(workflow.includes('git checkout --detach "$tag_ref"'))
  t.ok(workflow.includes('if [ "$head_sha" != "$tag_sha" ]'))
  t.ok(workflow.includes('workflow_dispatch ref $GITHUB_REF does not match exact tag'))
  t.ok(workflow.includes('node scripts/resolve-startos-04-release.mjs'))
  t.ok(workflow.includes('Verify release-surfaces sync authority'))
  t.ok(workflow.includes('--json workflowName,jobs'))
  t.ok(workflow.includes('sync.status !== "completed" || sync.conclusion !== "success"'))
  t.is(workflow.includes('terminal Release surfaces run'), false, 'child must not wait for the parent that awaits it')
  t.ok(workflow.indexOf('Resolve exact release tag') < workflow.indexOf('Configure StartOS developer key'))
  t.ok(workflow.indexOf('Verify release-surfaces sync authority') < workflow.indexOf('Configure StartOS developer key'))

  t.ok(legacyWorkflow.includes('dispatch-startos-04:\n    needs: sync'))
  t.ok(legacyWorkflow.includes('permissions:\n  actions: read\n  contents: write'))
  t.ok(legacyWorkflow.includes(`if: ${GITHUB_EXPRESSION} needs.sync.result == 'success'`))
  t.ok(legacyWorkflow.includes('actions: write\n      contents: read'))
  t.ok(legacyWorkflow.includes('--ref "$RELEASE_TAG"'))
  t.ok(legacyWorkflow.includes('--raw-field "release_surfaces_run_id=$GITHUB_RUN_ID"'))
  t.ok(legacyWorkflow.includes('Dispatch and await source-bound StartOS 0.4 package release'))
  t.ok(legacyWorkflow.includes('Verify published StartOS 0.4 closure assets'))
  t.ok(legacyWorkflow.includes('verify-published-startos-04-release.mjs'))
  t.is(legacyWorkflow.includes('permissions:\n  actions: write'), false)
})

test('StartOS 0.4 toolchain and release image are pinned before signing', async (t) => {
  const [workflow, makefile] = await Promise.all([
    readFile(WORKFLOW, 'utf8'),
    readFile(MAKEFILE, 'utf8')
  ])

  t.ok(workflow.includes(`setup-build-env@${SETUP_ACTION_SHA}`))
  t.ok(workflow.includes(`expected_sha='${START_CLI_SHA256}'`))
  t.ok(workflow.includes("expected 'start-cli 1.1.0'"))
  t.ok(workflow.indexOf('Verify pinned StartOS CLI') < workflow.indexOf('Configure StartOS developer key'))
  t.ok(makefile.includes('REQUIRE_RELEASE_IMAGE_DIGEST ?= 0'))
  t.ok(makefile.includes('HIVERELAY_STARTOS_04_IMAGE_REF := $(IMAGE_TAG)'))
  t.ok(makefile.includes('universal: check-release-image'))
})

test('release-surfaces reuses one source-bound image digest across equivalent reruns', async (t) => {
  const workflow = await readFile(LEGACY_WORKFLOW, 'utf8')

  t.ok(workflow.includes('Resolve reusable source-bound release image'))
  t.ok(workflow.includes('resolve-reusable-release-image.mjs'))
  t.ok(workflow.includes(`if: ${GITHUB_EXPRESSION} steps.prior_image.outputs.reuse != 'true' }}`))
  t.ok(workflow.includes('Restore release image tags to reusable digest'))
  t.ok(workflow.includes('actual_digest="sha256:$(sha256sum "$raw_manifest"'))
  t.ok(workflow.includes('.workflowName == "Release surfaces" and'))
  t.ok(workflow.includes('([.jobs[] | select(.name == "sync")] | length) == 1'))
  t.ok(workflow.includes('.status == "completed" and .conclusion == "success"'))
})

test('StartOS 0.4 reruns recover evidence without rebuilding an existing package', async (t) => {
  const workflow = await readFile(WORKFLOW, 'utf8')

  t.ok(workflow.includes('Inspect existing immutable release assets'))
  t.ok(workflow.includes('needs_build=false'))
  t.ok(workflow.includes('needs_evidence=true'))
  t.ok(workflow.includes(`if: ${GITHUB_EXPRESSION} steps.existing.outputs.needs_build == 'true' }}`))
  t.ok(workflow.includes(`if: ${GITHUB_EXPRESSION} steps.existing.outputs.needs_evidence == 'true' }}`))
  t.ok(workflow.includes('exists without $STARTOS_04_RELEASE_ASSET; refusing an orphaned handoff'))
})

async function workflowFixture (t, startCliMode) {
  const root = await mkdtemp(path.join(tmpdir(), 'hiverelay-startos-04-workflow-'))
  t.teardown(async () => {
    await rm(root, { recursive: true, force: true })
  })

  const home = path.join(root, 'home')
  const work = path.join(root, 'startos-0.4')
  const bin = path.join(root, 'bin')
  await Promise.all([mkdir(home), mkdir(work), mkdir(bin)])

  const startCli = path.join(bin, 'start-cli')
  await writeFile(startCli, startCliStub(startCliMode))
  await chmod(startCli, 0o755)

  return { bin, home, root, work }
}

function startCliStub (mode) {
  if (mode === 'generated-key') {
    return '#!/bin/sh\nset -eu\n[ "$1" = "init-key" ]\nmkdir -p "$HOME/.startos"\nprintf %s ephemeral-key > "$HOME/.startos/id.key.pem"\n'
  }
  if (mode === 'missing-key') return '#!/bin/sh\nexit 0\n'
  return '#!/bin/sh\nexit 97\n'
}

async function runConfigureKey (fixture, secret) {
  const script = await configureKeyScript()
  return new Promise((resolve) => {
    execFile('/bin/bash', ['-c', script], {
      cwd: fixture.work,
      env: {
        HOME: fixture.home,
        PATH: `${fixture.bin}:${process.env.PATH || ''}`,
        STARTOS_DEV_KEY: secret
      },
      timeout: 10000
    }, (err, stdout, stderr) => {
      resolve({
        status: err && typeof err.code === 'number' ? err.code : 0,
        stdout,
        stderr
      })
    })
  })
}

async function configureKeyScript () {
  const workflow = await readFile(WORKFLOW, 'utf8')
  const stepStart = workflow.indexOf('      - name: Configure StartOS developer key')
  const nextStep = workflow.indexOf('\n      - name:', stepStart + 1)
  const step = workflow.slice(stepStart, nextStep)
  const marker = '        run: |\n'
  const runStart = step.indexOf(marker)
  if (stepStart < 0 || nextStep < 0 || runStart < 0) throw new Error('Configure StartOS developer key run block is missing')

  const indented = step.slice(runStart + marker.length).trimEnd()
  if (indented.split('\n').some(line => !line.startsWith('          '))) {
    throw new Error('Configure StartOS developer key run block has unexpected indentation')
  }
  return indented.replace(/^ {10}/gm, '') + '\n'
}
