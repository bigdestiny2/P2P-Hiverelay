/**
 * Prove NotifyService.start() resolves config.notify.push through
 * createPushProvider so the service holds a real (non-memory) provider.
 */
import test from 'brittle'
import { generateKeyPairSync } from 'node:crypto'
import {
  NotifyService,
  createMemoryPushProvider
} from '../../packages/services/builtin/notify-service.js'
import defaultConfig from '../../packages/core/config/default.js'

function vapidPrivateKey () {
  return generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    .privateKey.export({ format: 'jwk' }).d
}

test('default config documents notify.push as null (memory until operator sets it)', (t) => {
  t.ok(defaultConfig.notify)
  t.is(defaultConfig.notify.push, null)
})

test('NotifyService without push config keeps the memory provider (live:false)', async (t) => {
  const service = new NotifyService({ persistence: false })
  await service.start({ config: { notify: { push: null } } })
  t.teardown(async () => { await service.stop() })

  t.is(service.provider.kind, 'memory')
  t.is(service.provider.live, false)
})

test('NotifyService.start resolves webpush descriptor to a live non-memory provider', async (t) => {
  const privateKey = vapidPrivateKey()
  const service = new NotifyService({ persistence: false })

  await service.start({
    config: {
      notify: {
        push: {
          kind: 'webpush',
          // plaintext so we don't need a relay keyPair to open sealed tokens
          tokenEncoding: 'plaintext',
          credentials: {
            subject: 'mailto:test@example.com',
            privateKey
          }
        }
      }
    }
  })
  t.teardown(async () => { await service.stop() })

  t.ok(service.provider, 'provider resolved')
  t.is(service.provider.kind, 'webpush')
  t.is(service.provider.live, true)
  t.ok(service.provider.kind !== 'memory')
  t.is(typeof service.provider.send, 'function')
  // Must not be the memory stub identity
  t.ok(service.provider !== createMemoryPushProvider())
})

test('NotifyService.start rejects a bad push descriptor fail-closed', async (t) => {
  const service = new NotifyService({ persistence: false })
  await t.exception(
    () => service.start({
      config: {
        notify: {
          push: { kind: 'not-a-real-provider', credentials: {} }
        }
      }
    }),
    /NOTIFY_PUSH_UNKNOWN_KIND|must be/
  )
})

test('explicitly injected provider is not clobbered by config.notify.push', async (t) => {
  const injected = createMemoryPushProvider({ status: 'accepted_by_provider' })
  injected.kind = 'memory'
  injected.marker = 'injected-wins'

  const service = new NotifyService({ provider: injected, persistence: false })
  await service.start({
    config: {
      notify: {
        push: {
          kind: 'webpush',
          tokenEncoding: 'plaintext',
          credentials: {
            subject: 'mailto:test@example.com',
            privateKey: vapidPrivateKey()
          }
        }
      }
    }
  })
  t.teardown(async () => { await service.stop() })

  t.is(service.provider.marker, 'injected-wins')
  t.is(service.provider.kind, 'memory')
})
