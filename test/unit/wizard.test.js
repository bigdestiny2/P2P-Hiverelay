import test from 'brittle'
import { tmpdir } from 'os'
import { join } from 'path'
import { mkdtemp, rm, readFile, writeFile, stat } from 'fs/promises'
import { SetupWizard, WIZARD_SCHEMA_VERSION } from 'p2p-hiverelay/core/wizard.js'

const VALID_BTC = 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq'
const VALID_BTC_LEGACY = '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2'

async function makeWizard (t) {
  const dir = await mkdtemp(join(tmpdir(), 'bs-wizard-'))
  t.teardown(async () => { try { await rm(dir, { recursive: true, force: true }) } catch (_) {} })
  return new SetupWizard({ storagePath: join(dir, 'wizard.json') })
}

test('constructor requires storagePath', async (t) => {
  try {
    // eslint-disable-next-line no-new
    new SetupWizard({})
    t.fail('should throw')
  } catch (err) {
    t.ok(err.message.includes('storagePath'))
  }
})

test('initial state starts at welcome with sane defaults', async (t) => {
  const w = await makeWizard(t)
  const snap = w.snapshot()
  t.is(snap.step, 'welcome')
  t.absent(snap.isComplete)
  t.is(snap.acceptMode, 'review')
  t.ok(snap.relayName.length > 0, 'relayName has a generated default')
  t.is(snap.payoutDestination, null, 'no payout address yet')
  t.absent(snap.hasPayout, 'hasPayout false by default')
})

test('goToStep validates step name', async (t) => {
  const w = await makeWizard(t)
  const bad = w.goToStep({ step: 'made-up-step' })
  t.absent(bad.ok)
  t.ok(bad.reason.includes('unknown step'))
  const good = w.goToStep({ step: 'payout' })
  t.ok(good.ok)
  t.is(good.state.step, 'payout')
})

test('first goToStep stamps startedAt', async (t) => {
  const w = await makeWizard(t)
  t.is(w.snapshot().startedAt, null)
  w.goToStep({ step: 'relay_name' })
  t.ok(typeof w.snapshot().startedAt === 'number', 'startedAt set on first navigation')
})

test('setRelayName validates length and emptiness', async (t) => {
  const w = await makeWizard(t)
  t.absent(w.setRelayName({ relayName: '' }).ok, 'empty rejected')
  t.absent(w.setRelayName({ relayName: 'a'.repeat(61) }).ok, '>60 chars rejected')
  t.absent(w.setRelayName({ relayName: 42 }).ok, 'non-string rejected')
  const ok = w.setRelayName({ relayName: '  Tokyo Relay 01  ' })
  t.ok(ok.ok)
  t.is(ok.state.relayName, 'Tokyo Relay 01', 'whitespace trimmed')
})

test('setPayoutDestination accepts a valid on-chain BTC address', async (t) => {
  const w = await makeWizard(t)
  const ok = w.setPayoutDestination({ address: VALID_BTC })
  t.ok(ok.ok)
  t.is(ok.state.payoutDestination, VALID_BTC)
  t.ok(ok.state.hasPayout)
  // legacy base58 also accepted
  t.ok(w.setPayoutDestination({ address: VALID_BTC_LEGACY }).ok)
})

test('setPayoutDestination rejects non-onchain and malformed input', async (t) => {
  const w = await makeWizard(t)
  t.absent(w.setPayoutDestination({ address: 'not-an-address' }).ok, 'garbage rejected')
  t.absent(w.setPayoutDestination({ address: 'user@example.com' }).ok, 'lightning address rejected (on-chain only)')
  t.absent(w.setPayoutDestination({ address: 42 }).ok, 'non-string rejected')
})

test('setPayoutDestination with empty/null clears (skip)', async (t) => {
  const w = await makeWizard(t)
  w.setPayoutDestination({ address: VALID_BTC })
  t.ok(w.snapshot().hasPayout)
  const skip = w.setPayoutDestination({ address: '' })
  t.ok(skip.ok, 'empty string is a valid skip')
  t.is(skip.state.payoutDestination, null)
  t.absent(skip.state.hasPayout)
  t.ok(w.setPayoutDestination({ address: null }).ok, 'null is a valid skip')
  t.ok(w.setPayoutDestination({}).ok, 'missing address is a valid skip')
})

test('setAcceptMode validates against the four allowed values', async (t) => {
  const w = await makeWizard(t)
  for (const mode of ['open', 'review', 'allowlist', 'closed']) {
    t.ok(w.setAcceptMode({ acceptMode: mode }).ok, `${mode} accepted`)
  }
  t.absent(w.setAcceptMode({ acceptMode: 'random' }).ok, 'invalid mode rejected')
})

test('complete() sets step to complete and stamps completedAt', async (t) => {
  const w = await makeWizard(t)
  w.complete()
  const snap = w.snapshot()
  t.is(snap.step, 'complete')
  t.ok(snap.isComplete)
  t.ok(typeof snap.completedAt === 'number')
})

test('toConfig returns name, acceptMode, and subsidy.payoutDestination', async (t) => {
  const w = await makeWizard(t)
  w.setRelayName({ relayName: 'myrelay' })
  w.setPayoutDestination({ address: VALID_BTC })
  w.setAcceptMode({ acceptMode: 'allowlist' })
  const cfg = w.toConfig()
  t.is(cfg.name, 'myrelay')
  t.is(cfg.acceptMode, 'allowlist')
  t.is(cfg.subsidy.payoutDestination, VALID_BTC)
})

test('toConfig payoutDestination is null when skipped', async (t) => {
  const w = await makeWizard(t)
  w.setRelayName({ relayName: 'norpayout' })
  const cfg = w.toConfig()
  t.is(cfg.subsidy.payoutDestination, null)
})

test('save + load persists state across instances (payout address is plaintext — it is public)', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'bs-wizard-'))
  t.teardown(async () => { try { await rm(dir, { recursive: true, force: true }) } catch (_) {} })
  const path = join(dir, 'wizard.json')

  const a = new SetupWizard({ storagePath: path })
  a.setRelayName({ relayName: 'persisted' })
  a.setAcceptMode({ acceptMode: 'open' })
  a.setPayoutDestination({ address: VALID_BTC })
  a.complete()
  await a.save()

  const b = new SetupWizard({ storagePath: path })
  await b.load()
  t.is(b.snapshot().step, 'complete')
  t.is(b.snapshot().relayName, 'persisted')
  t.is(b.snapshot().acceptMode, 'open')
  t.is(b.snapshot().payoutDestination, VALID_BTC)
  // The address is public — it is stored plaintext on disk (no envelope).
  const raw = JSON.parse(await readFile(path, 'utf8'))
  t.is(raw.payoutDestination, VALID_BTC)
  t.absent(raw.lnbits, 'no legacy lnbits block written')
})

test('load is no-op on missing file (first run)', async (t) => {
  const w = await makeWizard(t)
  await w.load() // file doesn't exist yet
  t.is(w.snapshot().step, 'welcome', 'state untouched')
})

test('load tolerates corrupted JSON without crashing', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'bs-wizard-'))
  t.teardown(async () => { try { await rm(dir, { recursive: true, force: true }) } catch (_) {} })
  const path = join(dir, 'wizard.json')
  await writeFile(path, '{this is not json', 'utf8')

  const w = new SetupWizard({ storagePath: path })
  let errored = false
  w.on('load-error', () => { errored = true })
  await w.load()
  t.ok(errored, 'load-error event fired')
  t.is(w.snapshot().step, 'welcome', 'fallback to default state')
})

test('load of a legacy v2 file drops lnbits and maps the old step forward', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'bs-wizard-'))
  t.teardown(async () => { try { await rm(dir, { recursive: true, force: true }) } catch (_) {} })
  const path = join(dir, 'wizard.json')
  // Simulate a v2 wizard.json mid-wizard on the now-removed lnbits step.
  await writeFile(path, JSON.stringify({
    schemaVersion: 2,
    step: 'lnbits_connect',
    relayName: 'legacy-relay',
    lnbits: { url: 'http://lnbits', adminKey: { v: 1, iv: 'x', ciphertext: 'y', authTag: 'z' } },
    acceptMode: 'open',
    startedAt: 1000,
    completedAt: null
  }), 'utf8')

  const w = new SetupWizard({ storagePath: path })
  await w.load()
  const snap = w.snapshot()
  t.is(snap.relayName, 'legacy-relay', 'kept the name')
  t.is(snap.acceptMode, 'open', 'kept the accept mode')
  t.is(snap.step, 'payout', 'removed lnbits_connect step maps forward to payout')
  t.is(snap.payoutDestination, null, 'no payout carried over from v2')
  // After re-save, the legacy lnbits block is gone.
  await w.save()
  const raw = JSON.parse(await readFile(path, 'utf8'))
  t.is(raw.schemaVersion, WIZARD_SCHEMA_VERSION)
  t.absent(raw.lnbits, 'legacy lnbits block dropped on save')
})

test('reset clears state back to welcome', async (t) => {
  const w = await makeWizard(t)
  w.setRelayName({ relayName: 'x' })
  w.setPayoutDestination({ address: VALID_BTC })
  w.setAcceptMode({ acceptMode: 'open' })
  w.complete()
  w.reset()
  const snap = w.snapshot()
  t.is(snap.step, 'welcome')
  t.is(snap.acceptMode, 'review')
  t.absent(snap.isComplete)
  t.is(snap.payoutDestination, null)
})

test('schema version is exposed for forward compat checks', async (t) => {
  t.is(WIZARD_SCHEMA_VERSION, 3, 'schemaVersion is 3 after the lnbits→payout change')
})

test('storage permissions tightened to 0600 after save', async (t) => {
  const w = await makeWizard(t)
  w.setPayoutDestination({ address: VALID_BTC })
  await w.save()
  const st = await stat(w.storagePath)
  const perms = st.mode & 0o777
  t.is(perms, 0o600, 'wizard.json is owner-read/write only')
})
