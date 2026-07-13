import test from 'brittle'

test('private IPC v2 has an explicit additive package subpath', async t => {
  const contract = await import('@hiverelay/blind-ipc/private-ipc-v2-contract')

  t.is(contract.PRIVATE_IPC_V2_FORMAT_VERSION, 2)
  t.is(contract.PRIVATE_IPC_V2_CONTRACT.v1FallbackPermitted, false)
  t.is(contract.PRIVATE_IPC_V2_CONTRACT.contractLayerMintsRuntimeAuthority, false)
})
