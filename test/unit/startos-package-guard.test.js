import test from 'brittle'
import { readFile } from 'node:fs/promises'

test('StartOS packaging requires an image digest unless local tag-only mode is explicit', async (t) => {
  const makefile = await readFile('startos/Makefile', 'utf8')
  const pkg = JSON.parse(await readFile('package.json', 'utf8'))

  t.ok(makefile.includes('ALLOW_TAG_ONLY_IMAGE ?='))
  t.ok(makefile.includes('validate-image-ref:'))
  t.ok(makefile.includes('IMAGE_DIGEST=sha256:<multi-arch-digest> is required for StartOS packaging'))
  t.ok(makefile.includes('Use ALLOW_TAG_ONLY_IMAGE=1 only for local mechanics checks.'))
  t.ok(makefile.includes("grep -Eq '^sha256:[a-f0-9]{64}$$'"))
  t.ok(makefile.includes('check-digest:'))
  t.ok(makefile.includes('IMAGE_DIGEST does not match the $(IMAGE) manifest'))
  t.ok(/^image:\s+validate-image-ref\s+check-digest\s+Dockerfile\.retag/m.test(makefile))
  t.is(pkg.scripts['startos:verify'], 'cd startos && make verify IMAGE_DIGEST="$HIVERELAY_IMAGE_DIGEST"')
  t.is(pkg.scripts['startos:verify:local'], 'cd startos && make verify ALLOW_TAG_ONLY_IMAGE=1')
})
