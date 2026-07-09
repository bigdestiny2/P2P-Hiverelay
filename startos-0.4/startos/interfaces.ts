import { sdk } from './sdk'
import { uiPort } from './utils'

// Expose the single-page Blindspark dashboard as StartOS fronts it over
// Tor/LAN (mirrors the 0.3.x package's tor-config + lan-config on 9100).
export const setInterfaces = sdk.setupInterfaces(async ({ effects }) => {
  const uiMulti = sdk.MultiHost.of(effects, 'ui-multi')
  const uiMultiOrigin = await uiMulti.bindPort(uiPort, {
    protocol: 'http',
  })
  const ui = sdk.createInterface(effects, {
    name: 'Blindspark Dashboard',
    id: 'ui',
    description:
      'Web dashboard — status, peers, storage, and the apps your relay keeps alive',
    type: 'ui',
    masked: false,
    schemeOverride: null,
    username: null,
    path: '',
    query: {},
  })

  const uiReceipt = await uiMultiOrigin.export([ui])

  return [uiReceipt]
})
