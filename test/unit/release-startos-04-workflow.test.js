import test from 'brittle'
import { execFile } from 'node:child_process'
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'

const WORKFLOW = path.join(process.cwd(), '.github/workflows/release-startos-0.4.yml')
const LEGACY_WORKFLOW = path.join(process.cwd(), '.github/workflows/release-surfaces.yml')
const MAKEFILE = path.join(process.cwd(), 'startos-0.4/Makefile')
const START_CLI_INSTALLER = path.join(process.cwd(), 'scripts/install-startos-cli.sh')
const ASSETS_README = path.join(process.cwd(), 'startos-0.4/assets/README.md')
const RELEASE_ASSET = 'blindspark-startos-0.4.s9pk'
const RELEASE_EVIDENCE = 'startos-0.4-release-evidence.json'
const WORKSPACE_KEY = '.startos/build.key.pem'
const LEGACY_RELEASE_UPLOAD = 'gh release upload "$' + '{{ steps.rel.outputs.version }}" startos/blindspark.s9pk --clobber'
const CHECKOUT_ACTION_SHA = '3d3c42e5aac5ba805825da76410c181273ba90b1'
const SETUP_NODE_ACTION_SHA = '249970729cb0ef3589644e2896645e5dc5ba9c38'
const BUILDX_ACTION_SHA = '37fe631027851001ddb9b187196cc803df7f5f0e'
const LOGIN_ACTION_SHA = 'dbcb813823bdd20940b903addbd779551569679f'
const COSIGN_INSTALLER_ACTION_SHA = '6f9f17788090df1f26f669e9d70d6ae9567deba6'
const START_CLI_URL = 'https://github.com/Start9Labs/start-technologies/releases/download/start-cli%2Fv1.1.0/start-cli_x86_64-linux'
const START_CLI_SHA256 = '70eff67b6e9a936acd8aaaf787b783819252ecedaa5c74d462e3b15ed4dd843a'
const UPLOAD_ARTIFACT_ACTION_SHA = '043fb46d1a93c77aae656e7c1c64a875d1fc6a0a'
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
  t.ok(workflow.includes('gh release upload "$tag" "$package" "$evidence"'))
  t.is(workflow.includes('gh release upload "$tag" "$STARTOS_04_RELEASE_ASSET" --clobber'), false)
  t.is(workflow.includes('gh release upload "$tag" blindspark.s9pk --clobber'), false)
  t.ok(workflow.includes('No asset will be deleted or clobbered'))
  t.ok(workflow.includes('Package-only evidence recovery is forbidden'))
  t.ok(workflow.includes('state" != "uploaded"'))
  t.ok(workflow.includes('digest" =~ ^sha256:'))
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
  t.ok(workflow.includes('release_surfaces_run_attempt:'))
  t.ok(workflow.includes('release_image_authority_artifact_id:'))
  t.ok(workflow.includes('timeout-minutes: 60'))
  t.ok(workflow.includes('git rev-parse --verify "$tag_ref^{commit}"'))
  t.ok(workflow.includes('git checkout --detach "$tag_ref"'))
  t.ok(workflow.includes('if [ "$head_sha" != "$tag_sha" ]'))
  t.ok(workflow.includes('workflow_dispatch ref $GITHUB_REF does not match exact tag'))
  t.ok(workflow.includes('node scripts/resolve-startos-04-release.mjs'))
  t.ok(workflow.includes('Resolve immutable release image authority'))
  t.ok(workflow.includes('verify-startos-04-parent-run.mjs'))
  t.ok(workflow.includes('--attempt "$EXPECTED_RELEASE_SURFACES_RUN_ATTEMPT"'))
  t.ok(workflow.includes('--json databaseId,attempt,url,workflowName,headSha,headBranch,event,status,conclusion,jobs'))
  t.ok(workflow.includes('select-startos-04-release-image-authority.mjs'))
  t.ok(workflow.includes('actions/runs/$EXPECTED_RELEASE_SURFACES_RUN_ID/artifacts?per_page=100&name=$authority_name'))
  t.ok(workflow.includes('actions/artifacts/$HIVERELAY_STARTOS_IMAGE_AUTHORITY_ID/zip'))
  t.ok(workflow.includes('zip_digest="sha256:$(sha256sum "$authority_zip"'))
  t.ok(workflow.includes('StartOS image-authority ZIP must contain exactly the two flat evidence files'))
  t.ok(workflow.includes('--release-surfaces-run-attempt "$EXPECTED_RELEASE_SURFACES_RUN_ATTEMPT"'))
  t.ok(workflow.includes('Public release-evidence.json differs from immutable image authority'))
  t.ok(workflow.includes('cat "$binding_env" >> "$GITHUB_ENV"'))
  t.ok(workflow.includes(`sigstore/cosign-installer@${COSIGN_INSTALLER_ACTION_SHA} # v4.1.2`))
  t.ok(workflow.includes('--certificate-identity "https://github.com/bigdestiny2/P2P-Hiverelay/.github/workflows/release-surfaces.yml@refs/tags/$HIVERELAY_RELEASE_TAG"'))
  t.ok(workflow.includes('verify-startos-04-image-index.mjs'))
  t.is(workflow.includes('terminal Release surfaces run'), false, 'child must not wait for the parent that awaits it')
  t.ok(workflow.indexOf('Resolve exact release tag') < workflow.indexOf('Configure StartOS developer key'))
  t.ok(workflow.indexOf('Resolve immutable release image authority') < workflow.indexOf('Configure StartOS developer key'))
  t.ok(workflow.indexOf('cosign verify --recursive') < workflow.indexOf('Configure StartOS developer key'))
  t.ok(workflow.indexOf('verify-startos-04-image-index.mjs') < workflow.indexOf('Configure StartOS developer key'))
  t.ok(workflow.indexOf('verify_child amd64') < workflow.indexOf('Configure StartOS developer key'))

  t.ok(legacyWorkflow.includes('dispatch-startos-04:\n    needs: sync'))
  t.ok(legacyWorkflow.includes('permissions:\n  actions: read\n  contents: write'))
  t.ok(legacyWorkflow.includes(`if: ${GITHUB_EXPRESSION} needs.sync.result == 'success'`))
  t.ok(legacyWorkflow.includes('actions: write\n      contents: read'))
  t.ok(legacyWorkflow.includes(`Checkout exact released source\n        uses: actions/checkout@${CHECKOUT_ACTION_SHA}`))
  t.ok(legacyWorkflow.includes('persist-credentials: false'))
  t.ok(legacyWorkflow.includes('Release workflow_dispatch ref $WORKFLOW_REF does not match exact tag'))
  t.ok(legacyWorkflow.includes('--ref "$RELEASE_TAG"'))
  t.ok(legacyWorkflow.includes('--raw-field "release_surfaces_run_id=$GITHUB_RUN_ID"'))
  t.ok(legacyWorkflow.includes('--raw-field "release_surfaces_run_attempt=$GITHUB_RUN_ATTEMPT"'))
  t.ok(legacyWorkflow.includes('--raw-field "release_image_authority_artifact_id=$IMAGE_AUTHORITY_ARTIFACT_ID"'))
  t.ok(legacyWorkflow.includes('Upload exact StartOS image authority'))
  t.ok(legacyWorkflow.includes('name: release-image-authority-$' + '{{ steps.rel.outputs.version }}-$' + '{{ github.run_id }}-$' + '{{ github.run_attempt }}'))
  t.ok(legacyWorkflow.includes('Dispatch and await source-bound StartOS 0.4 package release'))
  t.ok(legacyWorkflow.includes('Verify published StartOS 0.4 closure assets'))
  t.ok(legacyWorkflow.includes('verify-published-startos-04-release.mjs'))
  t.ok(legacyWorkflow.includes('publish-startos-04-closure:\n    needs: [sync, dispatch-startos-04]'))
  t.ok(legacyWorkflow.includes('timeout-minutes: 20'))
  t.ok(legacyWorkflow.includes('actions: read\n      contents: write'))
  t.ok(legacyWorkflow.includes('Install authenticated StartOS CLI for independent inspection'))
  t.is(legacyWorkflow.includes('gh run download "$CHILD_RUN_ID"'), false)
  t.ok(legacyWorkflow.includes('actions/artifacts/$artifact_id/zip'))
  t.ok(legacyWorkflow.includes('actions/artifacts/$IMAGE_AUTHORITY_ARTIFACT_ID/zip'))
  t.ok(legacyWorkflow.includes('verify-startos-04-parent-run.mjs'))
  t.ok(legacyWorkflow.includes('--image-authority-metadata "$CLOSURE_DIR/image-authority-artifact.json"'))
  t.ok(legacyWorkflow.includes('--image-authority-artifact-id "$IMAGE_AUTHORITY_ARTIFACT_ID"'))
  t.ok(legacyWorkflow.includes('downloaded_digest="sha256:$(sha256sum "$artifact_zip"'))
  t.ok(legacyWorkflow.includes('unzip -q "$artifact_zip" -d "$artifact_dir"'))
  t.ok(legacyWorkflow.includes('.workflow_run.head_sha'))
  t.ok(legacyWorkflow.includes('live_closure_artifact'))
  t.ok(legacyWorkflow.includes('start-cli s9pk inspect "$package" commitment'))
  t.ok(legacyWorkflow.includes('start-cli s9pk inspect "$package" manifest --format json'))
  t.ok(legacyWorkflow.includes('write-release-closure-evidence.mjs'))
  t.ok(legacyWorkflow.includes('verify-release-closure-evidence.mjs'))
  t.ok(legacyWorkflow.includes('--bundle-dir "$published_dir"'))
  t.ok(legacyWorkflow.includes('--live-github'))
  t.ok(legacyWorkflow.includes('--allow-in-progress-parent'))
  t.ok(legacyWorkflow.includes('release-closure-evidence.json'))
  t.ok(legacyWorkflow.indexOf('Independently inspect exact child package') < legacyWorkflow.indexOf('Publish and verify final release closure'))
  t.is(legacyWorkflow.includes('permissions:\n  actions: write'), false)
})

test('StartOS 0.4 toolchain and release image are pinned before signing', async (t) => {
  const [workflow, makefile, installer] = await Promise.all([
    readFile(WORKFLOW, 'utf8'),
    readFile(MAKEFILE, 'utf8'),
    readFile(START_CLI_INSTALLER, 'utf8')
  ])

  t.ok(workflow.includes(`actions/checkout@${CHECKOUT_ACTION_SHA}`))
  t.ok(workflow.includes(`actions/upload-artifact@${UPLOAD_ARTIFACT_ACTION_SHA}`))
  for (const uses of workflow.matchAll(/^\s*uses:\s*([^\s#]+)/gm)) {
    t.ok(/@[a-f0-9]{40}$/.test(uses[1]), `child action is immutable: ${uses[1]}`)
  }
  t.is(workflow.includes('setup-build-env@'), false)
  t.ok(workflow.includes('bash scripts/install-startos-cli.sh'))
  t.ok(installer.includes(`cli_url='${START_CLI_URL}'`))
  t.ok(installer.includes(`expected_sha='${START_CLI_SHA256}'`))
  t.ok(installer.includes("expected 'start-cli 1.1.0'"))
  const install = workflow.indexOf('Install authenticated StartOS CLI')
  const installDependencies = workflow.indexOf('Install locked StartOS dependencies')
  const exposeKey = workflow.indexOf('STARTOS_DEV_KEY:', install)
  const download = installer.indexOf('curl --fail --location')
  const checksum = installer.indexOf('actual_sha="$(sha256sum')
  const makeExecutable = installer.indexOf('chmod 700 "$cli_path"')
  const firstExecution = installer.indexOf('cli_version="$("$cli_path" --version)"')
  const exposePath = installer.indexOf('echo "$install_dir" >> "$github_path_file"')
  t.ok(install >= 0 && install < exposeKey)
  t.ok(installDependencies > install && installDependencies < exposeKey)
  t.ok(download >= 0)
  t.ok(download < checksum)
  t.ok(checksum < makeExecutable)
  t.ok(makeExecutable < firstExecution)
  t.ok(firstExecution < exposePath)
  t.ok(exposePath < exposeKey)
  t.ok(makefile.includes('REQUIRE_RELEASE_IMAGE_DIGEST ?= 0'))
  t.ok(makefile.includes('HIVERELAY_STARTOS_04_IMAGE_REF := $(IMAGE_TAG)'))
  t.ok(makefile.includes('universal: check-release-image'))
})

test('StartOS 0.4 CLI installer rejects downloaded bytes before chmod or execution', async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), 'hiverelay-startos-04-cli-'))
  t.teardown(async () => {
    await rm(root, { recursive: true, force: true })
  })
  const bin = path.join(root, 'bin')
  const runnerTemp = path.join(root, 'runner-temp')
  const marker = path.join(root, 'executed')
  const githubPath = path.join(root, 'github-path')
  await Promise.all([mkdir(bin), mkdir(runnerTemp)])
  const curl = path.join(bin, 'curl')
  await writeFile(curl, `#!/bin/sh
set -eu
out=''
while [ "$#" -gt 0 ]; do
  if [ "$1" = '--output' ]; then
    out="$2"
    shift 2
    continue
  fi
  shift
done
cat > "$out" <<'EOF'
#!/bin/sh
printf executed > '${marker}'
printf '%s\\n' 'start-cli 1.1.0'
EOF
`)
  await chmod(curl, 0o755)

  const result = await runShell(START_CLI_INSTALLER, [path.join(runnerTemp, 'startos-cli-1.1.0'), githubPath], {
    PATH: `${bin}:${process.env.PATH || ''}`,
    HOME: root
  })
  t.is(result.status, 1)
  t.ok(result.stderr.includes('start-cli checksum mismatch'))
  const downloaded = path.join(runnerTemp, 'startos-cli-1.1.0/start-cli')
  t.is((await stat(downloaded)).mode & 0o111, 0)
  let executed = true
  try {
    await stat(marker)
  } catch {
    executed = false
  }
  t.is(executed, false)
})

test('release-surfaces reuses one source-bound image digest across equivalent reruns', async (t) => {
  const workflow = await readFile(LEGACY_WORKFLOW, 'utf8')

  const installCosign = workflow.indexOf('- name: Install cosign')
  const resolveReusable = workflow.indexOf('- name: Resolve reusable source-bound release image')
  const restoreReusable = workflow.indexOf('- name: Restore release image tags to reusable digest')
  for (const uses of workflow.matchAll(/^\s*uses:\s*([^\s#]+)/gm)) {
    t.ok(/@[a-f0-9]{40}$/.test(uses[1]), `release action is immutable: ${uses[1]}`)
  }
  t.ok(workflow.includes(`actions/checkout@${CHECKOUT_ACTION_SHA} # v7.0.1 (Node 24)`))
  t.ok(workflow.includes(`actions/setup-node@${SETUP_NODE_ACTION_SHA} # v6 (Node 24)`))
  t.ok(workflow.includes(`docker/setup-buildx-action@${BUILDX_ACTION_SHA} # v4`))
  t.ok(workflow.includes(`docker/login-action@${LOGIN_ACTION_SHA} # v4`))
  t.ok(workflow.includes(`sigstore/cosign-installer@${COSIGN_INSTALLER_ACTION_SHA} # v4.1.2`))
  t.ok(workflow.includes('Resolve reusable source-bound release image'))
  t.ok(workflow.includes('select-reusable-release-image-artifact.mjs'))
  t.ok(workflow.includes('resolve-reusable-release-image.mjs'))
  t.ok(workflow.includes('verify-reusable-release-run.mjs'))
  t.ok(workflow.includes('--attempt "$HIVERELAY_REUSABLE_RELEASE_SURFACES_RUN_ATTEMPT"'))
  t.ok(workflow.includes('--json databaseId,attempt,url,workflowName,headSha,headBranch,event,status,conclusion,jobs'))
  t.ok(workflow.includes('actions/runs/$HIVERELAY_REUSABLE_RELEASE_SURFACES_RUN_ID/attempts/$HIVERELAY_REUSABLE_RELEASE_SURFACES_RUN_ATTEMPT'))
  t.ok(workflow.includes('. + {workflowPath: $workflowPath}'))
  t.ok(workflow.includes('--run-id "$HIVERELAY_REUSABLE_RELEASE_SURFACES_RUN_ID"'))
  t.ok(workflow.includes('--run-attempt "$HIVERELAY_REUSABLE_RELEASE_SURFACES_RUN_ATTEMPT"'))
  t.ok(workflow.includes('--run-url "$HIVERELAY_REUSABLE_RELEASE_SURFACES_RUN_URL"'))
  t.ok(workflow.includes('actions/artifacts/$HIVERELAY_REUSABLE_ARTIFACT_ID/zip'))
  t.ok(workflow.includes('archive_digest="sha256:$(sha256sum "$artifact_zip"'))
  t.ok(workflow.includes('release-evidence.json release-image-manifest-evidence.json'))
  t.ok(workflow.includes('HIVERELAY_REUSABLE_RELEASE_SURFACES_RUN_ID" != "$HIVERELAY_REUSABLE_ARTIFACT_SOURCE_RUN_ID'))
  t.ok(workflow.includes('Published release state exists but its immutable reusable image authority artifact is absent or expired'))
  t.ok(workflow.includes('startos-0\\.4-release-evidence\\.json'))
  t.is(workflow.includes("--jq '.assets[].name' 2>/dev/null || true"), false)
  t.ok(workflow.includes('releases/$release_id/assets?per_page=100'))
  t.ok(workflow.includes('GitHub Release id is malformed while checking prior image authority'))
  t.ok(workflow.includes('Reusable image authority artifact source workflow identity is invalid'))
  t.ok(workflow.includes('.path == ".github/workflows/release-surfaces.yml"'))
  t.ok(workflow.includes('expected_identity="https://github.com/bigdestiny2/P2P-Hiverelay/.github/workflows/release-surfaces.yml@refs/tags/'))
  t.ok(workflow.includes('--certificate-identity "$expected_identity"'))
  t.ok(workflow.includes("--certificate-oidc-issuer 'https://token.actions.githubusercontent.com'"))
  t.ok(workflow.includes('verify-startos-04-image-index.mjs'))
  t.ok(workflow.includes('--index-digest "$HIVERELAY_IMAGE_DIGEST"'))
  t.ok(workflow.includes('verify_child amd64 "$HIVERELAY_IMAGE_AMD64_DIGEST"'))
  t.ok(workflow.includes('verify_child arm64 "$HIVERELAY_IMAGE_ARM64_DIGEST"'))
  t.ok(workflow.includes('--revision "$HIVERELAY_RELEASE_SHA"'))
  t.ok(installCosign >= 0 && installCosign < resolveReusable)
  t.ok(resolveReusable < restoreReusable)
  t.ok(workflow.indexOf('cosign verify', resolveReusable) < restoreReusable)
  t.ok(workflow.indexOf('verify-startos-04-image-index.mjs', resolveReusable) < restoreReusable)
  t.ok(workflow.indexOf('verify_child amd64', resolveReusable) < restoreReusable)
  t.ok(workflow.indexOf('source workflow identity is invalid', resolveReusable) < workflow.indexOf('unzip -q "$artifact_zip"', resolveReusable))
  const reusableStep = workflow.slice(resolveReusable, restoreReusable)
  t.is(reusableStep.includes('gh release download'), false)
  const uploadAuthority = workflow.indexOf('- name: Upload immutable reusable image authority')
  const uploadPublicEvidence = workflow.indexOf('- name: Upload release evidence to GitHub Release')
  t.ok(uploadAuthority > resolveReusable && uploadAuthority < uploadPublicEvidence)
  t.ok(workflow.includes('name: release-image-authority-$' + '{{ steps.rel.outputs.version }}'))
  t.ok(workflow.includes('if-no-files-found: error'))
  t.ok(workflow.includes(`if: ${GITHUB_EXPRESSION} steps.prior_image.outputs.reuse != 'true' }}`))
  t.ok(workflow.includes('Restore release image tags to reusable digest'))
  t.ok(workflow.includes('actual_digest="sha256:$(sha256sum "$raw_manifest"'))
})

test('reusable image authority lookup fails closed when Release inventory is unavailable', async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), 'hiverelay-reusable-image-lookup-'))
  t.teardown(async () => rm(root, { recursive: true, force: true }))
  const bin = path.join(root, 'bin')
  const runnerTemp = path.join(root, 'runner-temp')
  await Promise.all([mkdir(bin), mkdir(runnerTemp)])
  const gh = path.join(bin, 'gh')
  await writeFile(gh, `#!/bin/sh
set -eu
case "$*" in
  *actions/artifacts*)
    printf '%s\\n' '{"total_count":0,"artifacts":[]}'
    ;;
  *releases/tags/*)
    exit 44
    ;;
  *)
    exit 98
    ;;
esac
`)
  await chmod(gh, 0o755)
  let script = await workflowStepScript('Resolve reusable source-bound release image', LEGACY_WORKFLOW)
  script = script.replaceAll('$' + '{{ steps.rel.outputs.version }}', 'v0.26.0-rc.3')
  const result = await runInlineScript(script, process.cwd(), {
    GITHUB_OUTPUT: path.join(root, 'github-output'),
    GITHUB_REPOSITORY: 'bigdestiny2/P2P-Hiverelay',
    HIVERELAY_RELEASE_SHA: 'a'.repeat(40),
    PATH: `${bin}:${process.env.PATH || ''}`,
    RUNNER_TEMP: runnerTemp
  })
  t.is(result.status, 44, result.stderr)
})

test('missing reusable image authority fails closed on a sidecar-only Release', async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), 'hiverelay-reusable-image-sidecar-'))
  t.teardown(async () => rm(root, { recursive: true, force: true }))
  const bin = path.join(root, 'bin')
  const runnerTemp = path.join(root, 'runner-temp')
  await Promise.all([mkdir(bin), mkdir(runnerTemp)])
  const gh = path.join(bin, 'gh')
  await writeFile(gh, `#!/bin/sh
set -eu
case "$*" in
  *actions/artifacts*)
    printf '%s\\n' '{"total_count":0,"artifacts":[]}'
    ;;
  *releases/tags/*)
    printf '%s\\n' '123'
    ;;
  *releases/123/assets*)
    printf '%s\\n' 'startos-0.4-release-evidence.json'
    ;;
  *)
    exit 98
    ;;
esac
`)
  await chmod(gh, 0o755)
  let script = await workflowStepScript('Resolve reusable source-bound release image', LEGACY_WORKFLOW)
  script = script.replaceAll('$' + '{{ steps.rel.outputs.version }}', 'v0.26.0-rc.3')
  const result = await runInlineScript(script, process.cwd(), {
    GITHUB_OUTPUT: path.join(root, 'github-output'),
    GITHUB_REPOSITORY: 'bigdestiny2/P2P-Hiverelay',
    HIVERELAY_RELEASE_SHA: 'a'.repeat(40),
    PATH: `${bin}:${process.env.PATH || ''}`,
    RUNNER_TEMP: runnerTemp
  })
  t.is(result.status, 1)
  t.ok(result.stderr.includes('Published release state exists but its immutable reusable image authority artifact is absent or expired'))
})

test('StartOS 0.4 child always builds source and treats a complete public pair as compare-only', async (t) => {
  const workflow = await readFile(WORKFLOW, 'utf8')

  t.ok(workflow.includes('Inspect existing immutable release assets'))
  t.is(workflow.includes('needs_build='), false)
  t.is(workflow.includes('cp "$existing_dir/$STARTOS_04_RELEASE_ASSET"'), false)
  t.is(workflow.includes('cp "$existing_dir/$STARTOS_04_RELEASE_EVIDENCE"'), false)
  t.ok(workflow.includes('Package-only evidence recovery is forbidden'))
  t.ok(workflow.includes('this child will still build from exact source'))
  t.ok(workflow.includes('make universal REQUIRE_RELEASE_IMAGE_DIGEST=1'))
  t.ok(workflow.includes('cmp "startos-0.4/$STARTOS_04_RELEASE_ASSET" "$handoff_dir/$STARTOS_04_RELEASE_ASSET"'))
  t.ok(workflow.includes('cp "startos-0.4/$STARTOS_04_RELEASE_ASSET" "$artifact_dir/$STARTOS_04_RELEASE_ASSET"'))
  t.ok(workflow.indexOf('make universal REQUIRE_RELEASE_IMAGE_DIGEST=1') < workflow.indexOf('Upload immutable child closure artifact'))
  t.ok(workflow.includes('audited manual recovery is required'))
})

test('parent dispatches a fresh child when a successful child artifact is expired', async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), 'hiverelay-startos-04-dispatch-'))
  t.teardown(async () => rm(root, { recursive: true, force: true }))
  const bin = path.join(root, 'bin')
  const marker = path.join(root, 'dispatched')
  const output = path.join(root, 'github-output')
  await mkdir(bin)
  const gh = path.join(bin, 'gh')
  await writeFile(gh, `#!/bin/sh
set -eu
if [ "$1" = run ] && [ "$2" = list ]; then
  if [ -f "$GH_DISPATCH_MARKER" ]; then
    printf '[{"databaseId":100,"displayTitle":"%s","status":"completed","conclusion":"success","headSha":"%s"},{"databaseId":101,"displayTitle":"%s","status":"completed","conclusion":"success","headSha":"%s"}]\n' "$EXPECTED_TITLE" "$RELEASE_SHA" "$EXPECTED_TITLE" "$RELEASE_SHA"
  else
    printf '[{"databaseId":100,"displayTitle":"%s","status":"completed","conclusion":"success","headSha":"%s"}]\n' "$EXPECTED_TITLE" "$RELEASE_SHA"
  fi
elif [ "$1" = api ] && printf '%s' "$2" | grep -q '/actions/runs/100/artifacts'; then
  printf '{"total_count":1,"artifacts":[{"id":200,"name":"startos-0.4-closure-100-2","expired":true,"size_in_bytes":100,"digest":"sha256:%s","workflow_run":{"id":100,"head_sha":"%s","head_branch":"%s"}}]}\n' "$(printf e%.0s $(seq 1 64))" "$RELEASE_SHA" "$RELEASE_TAG"
elif [ "$1" = api ] && printf '%s' "$2" | grep -q '/actions/runs/100$'; then
  printf '{"run_attempt":2}\n'
elif [ "$1" = workflow ] && [ "$2" = run ]; then
  : > "$GH_DISPATCH_MARKER"
elif [ "$1" = run ] && [ "$2" = view ]; then
  printf '{"workflowName":"Release StartOS 0.4 package","displayTitle":"%s","headSha":"%s","status":"completed","conclusion":"success","url":"https://github.com/bigdestiny2/P2P-Hiverelay/actions/runs/101"}\n' "$EXPECTED_TITLE" "$RELEASE_SHA"
else
  exit 97
fi
`)
  await chmod(gh, 0o755)

  const result = await runInlineWorkflowStep('Dispatch and await source-bound StartOS 0.4 package release', root, {
    PATH: `${bin}:${process.env.PATH || ''}`,
    GH_TOKEN: 'test',
    GH_DISPATCH_MARKER: marker,
    GITHUB_OUTPUT: output,
    GITHUB_REPOSITORY: 'bigdestiny2/P2P-Hiverelay',
    GITHUB_RUN_ID: '700',
    GITHUB_RUN_ATTEMPT: '3',
    IMAGE_AUTHORITY_ARTIFACT_ID: '990',
    RELEASE_TAG: 'v9.9.9',
    RELEASE_SHA: 'a'.repeat(40)
  }, LEGACY_WORKFLOW)

  t.is(result.status, 0, result.stderr)
  t.is(await readFile(marker, 'utf8'), '')
  t.ok((await readFile(output, 'utf8')).includes('child_run_id=101'))
})

test('StartOS 0.4 asset inventory rejects starter and package-only recovery states', async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), 'hiverelay-startos-04-assets-'))
  t.teardown(async () => rm(root, { recursive: true, force: true }))
  const bin = path.join(root, 'bin')
  await mkdir(bin)
  const gh = path.join(bin, 'gh')
  await writeFile(gh, `#!/bin/sh
set -eu
case "$*" in
  *'/releases/tags/'*) printf '%s\n' 42 ;;
  *'/releases/42/assets?per_page=100'*) printf '[%s]\n' "$GH_ASSETS_JSON" ;;
  *) exit 97 ;;
esac
`)
  await chmod(gh, 0o755)
  const baseEnv = {
    PATH: `${bin}:${process.env.PATH || ''}`,
    GH_TOKEN: 'test',
    GITHUB_REPOSITORY: 'bigdestiny2/P2P-Hiverelay',
    HIVERELAY_RELEASE_TAG: 'v9.9.9',
    STARTOS_04_RELEASE_ASSET: RELEASE_ASSET,
    STARTOS_04_RELEASE_EVIDENCE: RELEASE_EVIDENCE,
    RUNNER_TEMP: root,
    GITHUB_OUTPUT: path.join(root, 'github-output')
  }

  const starter = await runInlineWorkflowStep('Inspect existing immutable release assets', root, {
    ...baseEnv,
    GH_ASSETS_JSON: JSON.stringify([
      { id: 1, node_id: 'RA_graphql-package', name: RELEASE_ASSET, state: 'starter', size: 0, digest: null },
      { id: 2, node_id: 'RA_graphql-evidence', name: RELEASE_EVIDENCE, state: 'uploaded', size: 20, digest: `sha256:${'a'.repeat(64)}` }
    ])
  })
  t.is(starter.status, 1)
  t.ok(starter.stderr.includes('unowned/starter record'))

  const packageOnly = await runInlineWorkflowStep('Inspect existing immutable release assets', root, {
    ...baseEnv,
    GH_ASSETS_JSON: JSON.stringify([
      { id: 1, node_id: 'RA_graphql-package', name: RELEASE_ASSET, state: 'uploaded', size: 20, digest: `sha256:${'a'.repeat(64)}` }
    ])
  })
  t.is(packageOnly.status, 1)
  t.ok(packageOnly.stderr.includes('Package-only evidence recovery is forbidden'))

  const workflow = await readFile(WORKFLOW, 'utf8')
  t.ok(workflow.includes('releases/$release_id/assets?per_page=100'))
  t.is(workflow.includes('gh release view "$HIVERELAY_RELEASE_TAG"'), false)
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
  return workflowStepScript('Configure StartOS developer key')
}

async function runShell (file, args, env) {
  return new Promise((resolve) => {
    execFile('/bin/bash', [file, ...args], {
      env,
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

async function runInlineWorkflowStep (name, cwd, env, workflow = WORKFLOW) {
  const script = await workflowStepScript(name, workflow)
  return runInlineScript(script, cwd, env)
}

async function runInlineScript (script, cwd, env) {
  return new Promise((resolve) => {
    execFile('/bin/bash', ['-c', script], { cwd, env, timeout: 10000 }, (err, stdout, stderr) => {
      resolve({
        status: err && typeof err.code === 'number' ? err.code : 0,
        stdout,
        stderr
      })
    })
  })
}

async function workflowStepScript (name, workflowPath = WORKFLOW) {
  const workflow = await readFile(workflowPath, 'utf8')
  const stepStart = workflow.indexOf(`      - name: ${name}`)
  const nextStep = workflow.indexOf('\n      - name:', stepStart + 1)
  const step = workflow.slice(stepStart, nextStep)
  const marker = '        run: |\n'
  const runStart = step.indexOf(marker)
  if (stepStart < 0 || nextStep < 0 || runStart < 0) throw new Error(`${name} run block is missing`)

  const runLines = step.slice(runStart + marker.length).split('\n')
  const boundary = runLines.findIndex(line => line !== '' && !line.startsWith('          '))
  const indented = runLines.slice(0, boundary < 0 ? undefined : boundary).join('\n').trimEnd()
  return indented.replace(/^ {10}/gm, '') + '\n'
}
