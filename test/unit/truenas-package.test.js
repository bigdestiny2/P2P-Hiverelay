import test from 'brittle'
import { execFile } from 'node:child_process'

test('TrueNAS Community package remains release-aligned and security-scoped', async (t) => {
  const result = await new Promise((resolve) => {
    execFile(process.execPath, ['scripts/check-truenas-package.mjs'], {
      cwd: process.cwd(),
      env: { PATH: process.env.PATH || '' },
      timeout: 10000
    }, (err, stdout, stderr) => {
      resolve({
        status: err && typeof err.code === 'number' ? err.code : 0,
        stdout,
        stderr
      })
    })
  })

  t.is(result.status, 0, result.stderr)
  t.ok(result.stdout.includes('TrueNAS Community package validates for Blindspark.'))
})
