# Holepunch outreach — Pear Mobile SDK + iOS xcframework gap

**Status:** draft for user review before sending
**Audience:** Holepunch team (whoever maintains react-native-bare-kit, Pear)
**Goal:** Coordinate on a Pear-mobile app SDK we're packaging; surface two gaps (iOS xcframework staging, App Store JSC posture) where their input materially shapes our work

---

## Suggested recipient + channel

- Best: GitHub issue on `holepunchto/bare-kit` titled something like "RFC: react-native-pear-end — packaging the Pear-on-mobile integration as a reusable SDK"
- Alt: direct email if you have a Holepunch contact
- Alt: Pear Discord if that's where active Holepunch eng hangs out

Public GitHub issue is probably best — it's discoverable by any other Pear-mobile devs hitting the same problems, and Holepunch tends to respond well to clearly-written technical proposals.

---

## Draft message

**Subject:** RFC: packaging Pear-on-mobile integration as a reusable SDK (`react-native-pear-end`)

Hi Holepunch team,

We're building infrastructure (HiveRelay — P2P relay nodes for Hypercore/Hyperswarm apps) and one of our customers, PearPaste, has just shipped a working end-to-end Bare-on-mobile integration: same `corestore + autobase + hypercore + hyperbee + hyperswarm + hyperdht` backend running natively on iOS Simulator + Android (ZTE Blade A35e, armeabi-v7a), all UDP/UDX through `react-native-bare-kit@0.13.3`. Full P2P from a phone, no WebSocket bridge in the path.

It works. It's also painful to set up from scratch — the PearPaste team paid a meaningful integration tax that any next mobile-Pear app would have to pay again. We'd like to package their work as a reusable npm + Gradle package (provisional name `react-native-pear-end`) so the third+ mobile app on Bare doesn't have to rediscover the same potholes.

**What the SDK would package:**

1. A Gradle plugin that runs `bare-link` from the *consumer's* `node_modules` (not bare-kit's host project — see point #1 below)
2. Bundled `patch-package` patches for two upstream bugs (see point #2)
3. A `bare-pack --linked` CLI wrapper with per-platform output paths
4. A typed JS wrapper around `Worklet.start` + `BareKit.IPC` (with the TextEncoder gotcha + the dynamic-import gotcha + lifecycle hooks already baked in)
5. Memory-tuning constants for argon2id and similar (PearPaste hit `MEMLIMIT_MODERATE` OOM on 1.9 GB phones)
6. Metro platform shims so per-ABI bundles resolve correctly

**Three things where your input would materially shape our work:**

### 1. `react-native-bare-kit`'s `link.mjs` rooting

`link.mjs` roots its `link()` call at `react-native-bare-kit/../../..` — which is the RN host project's `node_modules`. For PearPaste's setup (and likely any Pear-style app where the backend is shared with desktop), the Pear-end's native deps are installed at the *repo root* `node_modules`, not the host project's. So bare-kit only stages its internal addons; everything else (udx-native, sodium-native, rocksdb-native, hypercore-crypto, fs-native-extensions, bare-crypto, bare-dns) gets silently missed. At runtime the worklet aborts with `AddonError: Cannot find addon '.' imported from 'udx-native/binding.js'`.

PearPaste worked around this with a custom Gradle task that re-runs `bare-link` rooted at the repo root and writes into bare-kit's `src/main/addons` directory. We're going to ship that as part of the SDK.

**Ask:** would you accept a PR to `react-native-bare-kit` that adds a `--root` flag (or auto-detects a `package.json` `workspaces` parent) to `link.mjs`? That would eliminate the need for downstream Gradle tasks for the simple-monorepo case, and our plugin could become a thin wrapper for the genuinely-complex cases.

### 2. iOS xcframework staging gap

Native addons on iOS ship as `.xcframework` bundles in `react-native-bare-kit/ios/addons/`. They're referenced by the podspec and rsync'd at build time. But:

- `bare-link` doesn't produce xcframeworks (it generates `.so` for Android via `bare-link --host android-*`)
- `npm install` doesn't install pre-built xcframeworks deterministically — they have to already exist in `node_modules/react-native-bare-kit/ios/addons/`
- When PearPaste did `rm -rf node_modules && npm install`, the xcframeworks vanished and the iOS build failed with `rsync: ... bare-abort.2.0.13.xcframework: No such file or directory`

Their workaround was hand-copying from a different install path that happened to retain them. We don't have a clean SDK answer for this yet.

**Ask:** what's the intended install path for iOS native addons? Options as we see them:

- (a) An iOS equivalent of `bare-link` that generates xcframeworks from native source/prebuilds at install time
- (b) Ship xcframeworks as a Pod that addon authors publish to CocoaPods and consumers depend on
- (c) Ship xcframeworks via Swift Package Manager
- (d) An npm postinstall hook in `react-native-bare-kit` (or in each native addon) that fetches the right prebuilt xcframework from a release URL

We'd happily contribute to whichever direction you'd take. Right now this gap effectively makes iOS undeployable for any non-Pear-team project.

### 3. App Store JSC posture

Apple historically requires apps that use JavaScript to go through `JavaScriptCore`. `react-native-bare-kit` embeds Bare's own runtime (V8 + libuv) rather than JSC. We're concerned that any app shipping `libbare-kit.so` + the equivalent iOS framework might face App Store rejection on "non-WebKit JS engine" grounds, even if the JS only runs in the worklet context.

PearPaste hasn't been through review yet. We don't know what Apple will say.

**Ask:** Do you have empirical signal on this? Has Pear or anyone using bare-kit been through iOS App Store review? If there's a known workaround (entitlement, justification language, specific framework configuration), the SDK should ship it as a default. If review rejection is a real risk, we'd want to flag it loudly in the SDK docs so consumers can make an informed call.

---

## What we're committing to

Whatever you say on the above three: we will package the existing PearPaste work into a reusable SDK on our own timeline. The questions above shape *quality*, not whether the SDK happens.

We'd also be happy to:

- File PRs for the upstream patches PearPaste is currently vendoring (`fs-native-extensions` EINVAL on 32-bit ARM kernels, `device-file` inode/mtime check failing on Android reinstall). We'll prep these regardless of SDK status.
- Coordinate naming, scope, and any donation/upstream path if the SDK ends up being something Holepunch would prefer to host
- Co-maintain if it'd reduce burden on your side

If the right call is "let us own this ourselves, you stand back," that works too. PearPaste is the existence proof; the SDK is just packaging.

Happy to jump on a call or thread back here. PearPaste is doing the artifact handover this week and we're starting extraction next week regardless.

— [your name / handle]
HiveRelay maintainer
github.com/bigdestiny2/p2p-hiverelay

---

## What we're NOT asking

A few things worth being explicit we're NOT asking, to keep this from looking like a "do work for us" message:

- We're not asking Holepunch to write the SDK
- We're not asking for a Holepunch endorsement of the package name or branding
- We're not asking for synchronous review of our designs
- We're not asking for promises about future bare-kit features

We're asking for: (1) yes/no on the `--root` flag PR, (2) the intended install path for iOS xcframeworks, (3) any empirical signal on App Store review.

---

## Open questions for the user before sending

1. **Naming:** "react-native-pear-end" is PearPaste's suggested name. Other options: `@p2phiverelay/react-native-pear-end`, `@pear-community/...`, just `pear-mobile`. Which framing for the message?

2. **Public vs private:** GitHub issue (public, discoverable by other devs hitting same issues) vs email (private, lower-stakes). Lean public, but if you want quiet diplomacy first, email is fine.

3. **Mention HiveRelay's circuit-relay bug?** We're fixing it for v0.8.19 this week — could mention as a "by the way, you'd be a downstream consumer of a HiveRelay-as-circuit-relay-tunnel for NAT traversal on mobile, and we just fixed the relevant gap." Or could omit if it'd dilute the message.

4. **Co-sign with PearPaste team?** They could be cc'd as the existence proof. Politely makes the message harder to ignore. Risk: implies they're co-authoring something they're not.
