import test from 'brittle'
import fs from 'node:fs'
import yaml from 'js-yaml'

const workflow = yaml.load(fs.readFileSync('.github/workflows/docker-publish.yml', 'utf8'))
const job = workflow.jobs['build-and-push']
const metadata = job.steps.find(step => step.id === 'meta')
const rules = metadata.with.tags.trim().split('\n').map(line => Object.fromEntries(line.trim().split(',').map(field => field.split('='))))

// Keep this a policy/configuration test. Real metadata-action execution is
// qualified separately using the unmodified upstream v6 bundle; do not emulate
// its Handlebars helpers or tag renderer in this suite.
test('snapshot publisher excludes tags and automatic latest at the publication boundary', t => {
  t.alike(workflow.on, { push: { branches: ['main'] }, workflow_dispatch: null })
  t.is(job.if, "github.ref_type == 'branch'", 'tag dispatch is skipped before credentials or publishing')
  t.is(metadata.with.flavor.trim(), 'latest=false', 'metadata cannot synthesize latest')
  t.is(metadata.uses, 'docker/metadata-action@v6')
  const build = job.steps.find(step => step.id === 'build')
  t.is(build.with.tags, '$' + '{{ steps.meta.outputs.tags }}', 'publisher uses only the reviewed tag policy')
  t.is(build.with.push, true)
  t.absent(metadata.with.tags.includes('${{'), 'no package/version or dispatch interpolation can inject tags')
  for (const rule of rules) {
    t.ok(['raw', 'ref', 'sha'].includes(rule.type), 'no semver, tag or other implicit release producer')
    if (rule.type === 'raw') {
      t.is(rule.value, 'main')
      t.is(rule.enable, '{{is_default_branch}}')
      t.absent(rule.prefix || rule.suffix)
    } else {
      t.is(rule.prefix, rule.enable === '{{is_default_branch}}' ? 'main-' : 'branch-')
      t.absent(rule.suffix)
      if (rule.type === 'ref') t.is(rule.enable, '{{is_not_default_branch}}', 'all branch names are namespaced')
    }
  }
})

test('snapshot configuration namespaces every branch-derived tag and preserves main tags', t => {
  // Both helpers are defined by upstream v6 src/meta.ts and documented under
  // https://github.com/docker/metadata-action#global-expressions.
  t.alike(rules, [
    { type: 'raw', value: 'main', enable: '{{is_default_branch}}' },
    { type: 'ref', event: 'branch', prefix: 'branch-', enable: '{{is_not_default_branch}}' },
    { type: 'sha', prefix: 'main-', enable: '{{is_default_branch}}' },
    { type: 'sha', prefix: 'branch-', enable: '{{is_not_default_branch}}' }
  ], 'no unreviewed tag producer, enable helper or release namespace')
  t.absent(job.steps.some(step => step.run?.includes('package.json')), 'package version cannot enable stable promotion')
})

test('stable publishing retains its separate protected qualification boundary', t => {
  const stable = yaml.load(fs.readFileSync('.github/workflows/release-stable-promotion.yml', 'utf8'))
  t.alike(Object.keys(stable.on), ['workflow_dispatch'])
  t.is(stable.jobs.promote.environment, 'hiverelay-stable-promotion')
  const steps = stable.jobs.promote.steps
  t.ok(steps.some(step => step.run?.includes('download-qualification.mjs')))
  t.ok(steps.some(step => step.run?.includes('promote.mjs --mode promote --bundle-dir')))
  t.absent(job.steps.some(step => step.run?.includes('promote.mjs')), 'snapshot workflow cannot call the stable publisher')
})
