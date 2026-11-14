# Holepunch and Pear: current scoped release reconciliation, 14 November 2026

The official check completed at **18:32:47 UTC** with zero errors across **160 npm families, 65 release/tag repositories, 787 organization repositories inventoried and four official documents**. The original complete 155-family audit remains preserved. Six explicit closure families were added; bare-posix was already discovered implicitly, so the current unique total is 160.

The current HiveRelay source is `1a7f6085231269eb016e2b9f755854cb16ea3923`, with root-lock SHA `cbd13228f6b0fadf7179119e4e364b9d3c134dd76fd88723582e356c54ad7fd2`. Every current watched family has an exposure/disposition below. 84 families are represented in this source root; 76 are knowledge-only for this consumer. 121 installed Mac resolution slots were checked, plus one host-excluded optional slot retained in the lock. Nine nonlatest resolutions remain for concrete parent-major, exact-owner, protocol or private ABI reasons. No public patch is held merely because the candidate was frozen or because it is a development dependency.

Actual final Linux qualification binds this source, Node 22.23.5, 47 owning-workspace bindings and 10 local lock slots. Both ARM64 and AMD64 passed selected native/storage/gateway/composition tests, public Bare: 11 tests / 46 assertions and five real thread/advanced-IPC checks per architecture. ARM64 ran natively in a Linux VM; AMD64 was CPU-emulated. Exact-commit GitHub verification passed seven CI jobs and nine PR checks. These checks are local/synthetic qualification; they do not establish live fleet acceptance, systemd or uid999 behavior. An inherited stable-publisher workflow parsing error at `1a7f6085` was repaired by the workflow-only commit `9d8900bf`. All three workflows triggered on that successor passed, including [Test](https://github.com/bigdestiny2/P2P-Hiverelay/actions/runs/43627930941). Runtime, dependency and browser bytes are unchanged by that correction.

## Release planes and material changes

Pear's **published platform/CLI release is 3.7.0**, published November 12 at 15:43:36 UTC. Its repository HEAD declares 3.8.0-rc.0, while npm `pear` remains the separate 3.0.0 installer and `pear-runtime` remains 1.3.1. A GitHub release, HEAD, npm installer and installed P2P production/stage/dev channel are different observations. This study did not verify installed channel bytes. The [official Pear overview](https://docs.pears.com/pear/release-overview/) documents `pear make`, structured CLI changes, the removed sidecar inspection command and seed exit/error behavior; automation must use actual current fields rather than historical command output.

The selected public graph includes Hypercore 11.40.4, Corestore 7.16.1, hypercore-storage 3.4.0, Hyperbee 2.27.3, Hyperdrive 13.3.4, Hyperswarm 4.17.2, HyperDHT 6.36.0, compact-encoding 3.7.0, Protomux 3.13.1, development Autobee 2.13.6 and publicBare 1.37.1. The compatible closure additionally converges fs-native-extensions 1.5.3, streamx 2.28.1, protomux-rpc 1.10.1, rache 1.0.1, public sodium-native 5.2.1 and current compatible Bare/testing families. fs-native's native compiler/ABI corrections were rebuilt and tested on both architectures, including high-offset locking and actual read-only source import. RPC numeric error-code handling has a direct regression test. Streamx's patch is declarations only and rache's patch runtime formatting only.

Parent-driven BareHTTPS 4/TLS 4/signals 5 and structured-clone 2 changes were reviewed and tested through their actual updated parents; they are not forced across old consumers. The paired Bare thread/channel and subprocess fixture checks cycles, Map, Set, BigInt, typed bytes, transferred-buffer detachment and normal joins/exits. The updated generic brittle launcher uses Bare, so the Node soak command explicitly selects the Node runner. Compatible development updates were adopted too.

The [P2P release overview](https://docs.pears.com/p2p/release-overview/) still defines important migration boundaries: Hypercore fixes do not retroactively repair already-damaged trees; Autobee 2.13 remaps state that old readers cannot use; compatible blind-peer/blind-peering server versions must remain aligned. The [Bare overview](https://docs.pears.com/bare/release-overview/) also covers BareKit 3/mobile bindings and RPC 2's new wire behavior. Those available technologies are recorded as knowledge when absent from HiveRelay; unused dependencies are not added solely to match a release inventory.

## Concrete remaining holds

| Resolution | Selected / latest | Actual constraint |
|---|---|---|
| bare-dgram |1.0.1 /1.1.1|Holesail 2.4.4 declares exact1.0.1.|
| bare-module |6.4.0 /7.5.2|Holesail and coverage parent require^6.1.2;6.4.0 is the upgraded latest compatible6.|
| child_process alias |bare-subprocess5.2.3 /6.2.2|Holesail declares the5.x alias; the separate public6.x resolution is updated.|
| distributed-drive |0.1.1 /1.0.1|A bridge/protocol and consumer migration is required; current RPC patch remains adopted.|
| compact-encoding, three old-wire slots |2.19.2 /3.7.0|Distributed-drive 0.1 plus blind IPC/protocol retain their2.x wire contracts; public3.x is current.|
| root sodium-native |4.3.3 /5.2.1|Root sodium-universal4 consumes native4; public owning workspaces use5.2.1.|
| root sodium-universal |4.0.1 /5.0.1|Private blind consumers and hyper-cmd-lib-keys explicitly require4.x.|

Independent private own-lock/runtime contracts and immutable RC9 authority remain unchanged. The old aggregate `test:blind-protocol:bare` command is not qualified: publicBare 1.37 plus its private sodium4 graph reproduces a historical native fault, while simply choosing privateBare 1.31 fails the new root test-runner engine minimum. It was not silently rerouted or reported passing. Dedicated privateBare 1.31 wire: 10 and composition: 17 validators pass with exact executable/version selection; publicBare 1.37 qualification is separate.

## Current family inventory

Each row links to its official npm package registry record. “Knowledge only” means absent from this source root, not globally unused. Exact selected versions and integrity values are recorded in the committed [dependency lock](../../package-lock.json). The [release notes](0.27.0-rc.1.md) describe qualification, migration and deployment results. This dated inventory contains public research only.

|Family|Official latest|Selected source versions|Disposition|
|---|---|---|---|
|[@hyperswarm/secret-stream](https://registry.npmjs.org/%40hyperswarm%2Fsecret-stream)|6.9.2|6.9.2|Latest selected|
|[@hyperswarm/testnet](https://registry.npmjs.org/%40hyperswarm%2Ftestnet)|3.1.4|3.1.4|Latest selected|
|[@types/react-native](https://registry.npmjs.org/%40types%2Freact-native)|0.73.0|—|Knowledge only|
|[autobase](https://registry.npmjs.org/autobase)|7.28.2|—|Knowledge only|
|[autobee](https://registry.npmjs.org/autobee)|2.13.6|2.13.6|Latest selected|
|[autopass](https://registry.npmjs.org/autopass)|3.4.1|—|Knowledge only|
|[b4a](https://registry.npmjs.org/b4a)|1.9.0|1.9.0|Latest selected|
|[bare](https://registry.npmjs.org/bare)|1.37.1|1.37.1|Latest selected|
|[bare-addon-resolve](https://registry.npmjs.org/bare-addon-resolve)|1.12.0|1.12.0|Latest selected|
|[bare-broadcast-channel](https://registry.npmjs.org/bare-broadcast-channel)|0.2.1|—|Knowledge only|
|[bare-buffer](https://registry.npmjs.org/bare-buffer)|3.7.2|3.7.2|Latest selected|
|[bare-build](https://registry.npmjs.org/bare-build)|1.6.2|—|Knowledge only|
|[bare-bundle](https://registry.npmjs.org/bare-bundle)|1.11.0|1.11.0|Latest selected|
|[bare-channel](https://registry.npmjs.org/bare-channel)|5.3.0|5.3.0|Latest selected|
|[bare-crypto](https://registry.npmjs.org/bare-crypto)|1.15.4|1.15.4|Latest selected|
|[bare-daemon](https://registry.npmjs.org/bare-daemon)|1.2.5|—|Knowledge only|
|[bare-dgram](https://registry.npmjs.org/bare-dgram)|1.1.1|1.0.1|Current public scope; named held slots above|
|[bare-encoding](https://registry.npmjs.org/bare-encoding)|1.0.3|1.0.3|Latest selected|
|[bare-env](https://registry.npmjs.org/bare-env)|3.0.1|3.0.1|Latest selected|
|[bare-events](https://registry.npmjs.org/bare-events)|2.9.2|2.9.2|Latest selected|
|[bare-fetch](https://registry.npmjs.org/bare-fetch)|3.5.0|—|Knowledge only|
|[bare-ffmpeg](https://registry.npmjs.org/bare-ffmpeg)|1.7.1|—|Knowledge only|
|[bare-file-logger](https://registry.npmjs.org/bare-file-logger)|1.2.3|—|Knowledge only|
|[bare-format](https://registry.npmjs.org/bare-format)|1.0.3|1.0.3|Latest selected|
|[bare-fs](https://registry.npmjs.org/bare-fs)|4.8.4|4.8.4|Latest selected|
|[bare-headers](https://registry.npmjs.org/bare-headers)|1.37.0|—|Knowledge only|
|[bare-host-parser](https://registry.npmjs.org/bare-host-parser)|1.0.0|1.0.0|Latest selected|
|[bare-hrtime](https://registry.npmjs.org/bare-hrtime)|2.1.2|2.1.2|Latest selected|
|[bare-http1](https://registry.npmjs.org/bare-http1)|4.6.3|4.6.3|Latest selected|
|[bare-https](https://registry.npmjs.org/bare-https)|4.0.0|4.0.0|Latest selected|
|[bare-inspector](https://registry.npmjs.org/bare-inspector)|6.1.0|6.1.0|Latest selected|
|[bare-ipc](https://registry.npmjs.org/bare-ipc)|1.1.3|—|Knowledge only|
|[bare-make](https://registry.npmjs.org/bare-make)|2.1.2|—|Knowledge only|
|[bare-module](https://registry.npmjs.org/bare-module)|7.5.2|6.4.0|Current public scope; named held slots above|
|[bare-module-traverse](https://registry.npmjs.org/bare-module-traverse)|2.7.6|2.7.6|Latest selected|
|[bare-native](https://registry.npmjs.org/bare-native)|0.3.8|—|Knowledge only|
|[bare-net](https://registry.npmjs.org/bare-net)|2.3.3|2.3.3|Latest selected|
|[bare-os](https://registry.npmjs.org/bare-os)|3.9.4|3.9.4|Latest selected|
|[bare-pack](https://registry.npmjs.org/bare-pack)|3.1.0|—|Knowledge only|
|[bare-path](https://registry.npmjs.org/bare-path)|3.1.3|3.1.3|Latest selected|
|[bare-pipe](https://registry.npmjs.org/bare-pipe)|4.4.0|4.4.0|Latest selected|
|[bare-posix](https://registry.npmjs.org/bare-posix)|1.0.1|1.0.1|Latest selected|
|[bare-process](https://registry.npmjs.org/bare-process)|4.5.1|4.5.1|Latest selected|
|[bare-readline](https://registry.npmjs.org/bare-readline)|1.3.1|—|Knowledge only|
|[bare-rpc](https://registry.npmjs.org/bare-rpc)|2.0.0|—|Knowledge only|
|[bare-runtime](https://registry.npmjs.org/bare-runtime)|1.37.1|1.37.1|Latest selected|
|[bare-runtime-linux-x64](https://registry.npmjs.org/bare-runtime-linux-x64)|1.37.1|1.37.1|Latest selected|
|[bare-sidecar](https://registry.npmjs.org/bare-sidecar)|0.5.16|—|Knowledge only|
|[bare-signals](https://registry.npmjs.org/bare-signals)|5.0.0|5.0.0|Latest selected|
|[bare-storage](https://registry.npmjs.org/bare-storage)|1.1.1|—|Knowledge only|
|[bare-stow](https://registry.npmjs.org/bare-stow)|0.3.9|—|Knowledge only|
|[bare-stream](https://registry.npmjs.org/bare-stream)|2.13.4|2.13.4|Latest selected|
|[bare-structured-clone](https://registry.npmjs.org/bare-structured-clone)|2.0.1|2.0.1|Latest selected|
|[bare-subprocess](https://registry.npmjs.org/bare-subprocess)|6.2.2|5.2.3, 6.2.2|Current public scope; named held slots above|
|[bare-tcp](https://registry.npmjs.org/bare-tcp)|2.6.1|2.6.1|Latest selected|
|[bare-thread](https://registry.npmjs.org/bare-thread)|1.4.0|1.4.0|Latest selected|
|[bare-tls](https://registry.npmjs.org/bare-tls)|4.0.0|4.0.0|Latest selected|
|[bare-tty](https://registry.npmjs.org/bare-tty)|5.2.2|5.2.2|Latest selected|
|[bare-type](https://registry.npmjs.org/bare-type)|1.6.0|1.6.0|Latest selected|
|[bare-type-stripper](https://registry.npmjs.org/bare-type-stripper)|0.1.7|0.1.7|Latest selected|
|[bare-url](https://registry.npmjs.org/bare-url)|2.5.7|2.5.7|Latest selected|
|[bare-worker](https://registry.npmjs.org/bare-worker)|4.5.3|—|Knowledge only|
|[bare-ws](https://registry.npmjs.org/bare-ws)|3.3.0|3.3.0|Latest selected|
|[bare-zlib](https://registry.npmjs.org/bare-zlib)|1.4.1|—|Knowledge only|
|[bip39-mnemonic](https://registry.npmjs.org/bip39-mnemonic)|2.5.0|—|Knowledge only|
|[blind-pairing](https://registry.npmjs.org/blind-pairing)|2.3.1|—|Knowledge only|
|[blind-pairing-core](https://registry.npmjs.org/blind-pairing-core)|2.10.1|—|Knowledge only|
|[blind-peer](https://registry.npmjs.org/blind-peer)|3.18.2|—|Knowledge only|
|[blind-peering](https://registry.npmjs.org/blind-peering)|2.14.0|—|Knowledge only|
|[blind-relay](https://registry.npmjs.org/blind-relay)|1.6.1|1.6.1|Latest selected|
|[brittle](https://registry.npmjs.org/brittle)|4.5.0|4.5.0|Latest selected|
|[cmake-bare](https://registry.npmjs.org/cmake-bare)|1.14.1|—|Knowledge only|
|[cmake-bare-bundle](https://registry.npmjs.org/cmake-bare-bundle)|3.1.0|—|Knowledge only|
|[cmake-fetch](https://registry.npmjs.org/cmake-fetch)|1.5.3|—|Knowledge only|
|[cmake-pear](https://registry.npmjs.org/cmake-pear)|2.0.9|—|Knowledge only|
|[compact-encoding](https://registry.npmjs.org/compact-encoding)|3.7.0|2.19.2, 3.7.0|Current public scope; named held slots above|
|[corestore](https://registry.npmjs.org/corestore)|7.16.1|7.16.1|Latest selected|
|[db-lock](https://registry.npmjs.org/db-lock)|1.2.0|—|Knowledge only|
|[device-file](https://registry.npmjs.org/device-file)|2.3.1|2.3.1|Latest selected|
|[dht-rpc](https://registry.npmjs.org/dht-rpc)|6.28.0|6.28.0|Latest selected|
|[distributed-drive](https://registry.npmjs.org/distributed-drive)|1.0.1|0.1.1|Current public scope; named held slots above|
|[electron](https://registry.npmjs.org/electron)|45.3.2|—|Knowledge only|
|[fd-lock](https://registry.npmjs.org/fd-lock)|2.2.0|2.2.0|Latest selected|
|[framed-stream](https://registry.npmjs.org/framed-stream)|1.0.1|—|Knowledge only|
|[fs-native-extensions](https://registry.npmjs.org/fs-native-extensions)|1.5.3|1.5.3|Latest selected|
|[hrpc](https://registry.npmjs.org/hrpc)|4.3.2|—|Knowledge only|
|[hrpc-swift](https://registry.npmjs.org/hrpc-swift)|1.0.0|—|Knowledge only|
|[hyper-multisig](https://registry.npmjs.org/hyper-multisig)|2.5.0|—|Knowledge only|
|[hyperbee](https://registry.npmjs.org/hyperbee)|2.27.3|2.27.3|Latest selected|
|[hyperbee-diff-stream](https://registry.npmjs.org/hyperbee-diff-stream)|2.0.1|—|Knowledge only|
|[hyperblobs](https://registry.npmjs.org/hyperblobs)|2.13.0|2.13.0|Latest selected|
|[hypercore](https://registry.npmjs.org/hypercore)|11.40.4|11.40.4|Latest selected|
|[hypercore-blob-server](https://registry.npmjs.org/hypercore-blob-server)|1.15.1|—|Knowledge only|
|[hypercore-crypto](https://registry.npmjs.org/hypercore-crypto)|3.7.0|3.7.0|Latest selected|
|[hypercore-id-encoding](https://registry.npmjs.org/hypercore-id-encoding)|1.3.0|1.3.0|Latest selected|
|[hypercore-sign](https://registry.npmjs.org/hypercore-sign)|3.0.0|—|Knowledge only|
|[hypercore-storage](https://registry.npmjs.org/hypercore-storage)|3.4.0|3.4.0|Latest selected|
|[hyperdb](https://registry.npmjs.org/hyperdb)|6.11.1|—|Knowledge only|
|[hyperdht](https://registry.npmjs.org/hyperdht)|6.36.0|6.36.0|Latest selected|
|[hyperdht-address](https://registry.npmjs.org/hyperdht-address)|1.1.1|1.1.1|Latest selected|
|[hyperdispatch](https://registry.npmjs.org/hyperdispatch)|1.6.0|—|Knowledge only|
|[hyperdrive](https://registry.npmjs.org/hyperdrive)|13.3.4|13.3.4|Latest selected|
|[hyperschema](https://registry.npmjs.org/hyperschema)|1.26.2|1.26.2|Latest selected|
|[hyperschema-swift](https://registry.npmjs.org/hyperschema-swift)|1.0.1|—|Knowledge only|
|[hyperswarm](https://registry.npmjs.org/hyperswarm)|4.17.2|4.17.2|Latest selected|
|[hyperswarm-stats](https://registry.npmjs.org/hyperswarm-stats)|1.3.4|—|Knowledge only|
|[keet-identity-key](https://registry.npmjs.org/keet-identity-key)|3.2.0|—|Knowledge only|
|[localdrive](https://registry.npmjs.org/localdrive)|2.2.1|—|Knowledge only|
|[localwatch](https://registry.npmjs.org/localwatch)|1.4.4|—|Knowledge only|
|[lunte](https://registry.npmjs.org/lunte)|1.8.6|—|Knowledge only|
|[mirror-drive](https://registry.npmjs.org/mirror-drive)|1.14.2|1.14.2|Latest selected|
|[paparam](https://registry.npmjs.org/paparam)|1.15.0|1.15.0|Latest selected|
|[pear](https://registry.npmjs.org/pear)|3.0.0|—|Knowledge only|
|[pear-bridge](https://registry.npmjs.org/pear-bridge)|1.2.5|—|Knowledge only|
|[pear-build](https://registry.npmjs.org/pear-build)|1.3.2|—|Knowledge only|
|[pear-changelog](https://registry.npmjs.org/pear-changelog)|1.0.3|—|Knowledge only|
|[pear-electron](https://registry.npmjs.org/pear-electron)|1.7.28|—|Knowledge only|
|[pear-errors](https://registry.npmjs.org/pear-errors)|1.0.2|—|Knowledge only|
|[pear-gracedown](https://registry.npmjs.org/pear-gracedown)|1.0.5|1.0.5|Latest selected|
|[pear-inspect](https://registry.npmjs.org/pear-inspect)|1.2.6|—|Knowledge only|
|[pear-install](https://registry.npmjs.org/pear-install)|1.6.0|—|Knowledge only|
|[pear-interface](https://registry.npmjs.org/pear-interface)|1.1.0|—|Knowledge only|
|[pear-ipc](https://registry.npmjs.org/pear-ipc)|6.17.0|—|Knowledge only|
|[pear-link](https://registry.npmjs.org/pear-link)|5.0.1|—|Knowledge only|
|[pear-mobile](https://registry.npmjs.org/pear-mobile)|4.3.0|—|Knowledge only|
|[pear-opstream](https://registry.npmjs.org/pear-opstream)|1.2.0|—|Knowledge only|
|[pear-opwait](https://registry.npmjs.org/pear-opwait)|1.0.1|—|Knowledge only|
|[pear-pipe](https://registry.npmjs.org/pear-pipe)|1.0.6|—|Knowledge only|
|[pear-restart](https://registry.npmjs.org/pear-restart)|1.0.0|—|Knowledge only|
|[pear-run](https://registry.npmjs.org/pear-run)|2.0.0|—|Knowledge only|
|[pear-runtime](https://registry.npmjs.org/pear-runtime)|1.3.1|—|Knowledge only|
|[pear-runtime-react-native](https://registry.npmjs.org/pear-runtime-react-native)|3.0.1|—|Knowledge only|
|[pear-runtime-updater](https://registry.npmjs.org/pear-runtime-updater)|3.4.0|—|Knowledge only|
|[pear-updater](https://registry.npmjs.org/pear-updater)|3.10.0|—|Knowledge only|
|[pear-updates](https://registry.npmjs.org/pear-updates)|1.1.0|—|Knowledge only|
|[prettier-config-holepunch](https://registry.npmjs.org/prettier-config-holepunch)|2.0.0|2.0.0|Latest selected|
|[protomux](https://registry.npmjs.org/protomux)|3.13.1|3.13.1|Latest selected|
|[protomux-rpc](https://registry.npmjs.org/protomux-rpc)|1.10.1|1.10.1|Latest selected|
|[protomux-wakeup](https://registry.npmjs.org/protomux-wakeup)|2.9.1|2.9.1|Latest selected|
|[quickbit-native](https://registry.npmjs.org/quickbit-native)|2.4.9|2.4.9|Latest selected|
|[rache](https://registry.npmjs.org/rache)|1.0.1|1.0.1|Latest selected|
|[react-native](https://registry.npmjs.org/react-native)|0.88.1|—|Knowledge only|
|[react-native-b4a](https://registry.npmjs.org/react-native-b4a)|0.1.1|—|Knowledge only|
|[react-native-bare-kit](https://registry.npmjs.org/react-native-bare-kit)|0.17.1|—|Knowledge only|
|[ready-resource](https://registry.npmjs.org/ready-resource)|1.2.0|1.2.0|Latest selected|
|[require-asset](https://registry.npmjs.org/require-asset)|1.2.4|1.2.4|Latest selected|
|[rocksdb-native](https://registry.npmjs.org/rocksdb-native)|3.19.5|3.19.5|Latest selected|
|[semifies](https://registry.npmjs.org/semifies)|1.0.0|—|Knowledge only|
|[simdle-native](https://registry.npmjs.org/simdle-native)|1.3.10|1.3.10|Latest selected|
|[sodium-native](https://registry.npmjs.org/sodium-native)|5.2.1|4.3.3, 5.2.1|Current public scope; named held slots above|
|[sodium-universal](https://registry.npmjs.org/sodium-universal)|5.0.1|4.0.1, 5.0.1|Current public scope; named held slots above|
|[streamx](https://registry.npmjs.org/streamx)|2.28.1|2.28.1|Latest selected|
|[sub-encoder](https://registry.npmjs.org/sub-encoder)|2.1.3|2.1.3|Latest selected|
|[text-decoder](https://registry.npmjs.org/text-decoder)|1.2.7|1.2.7|Latest selected|
|[tiny-buffer-rpc](https://registry.npmjs.org/tiny-buffer-rpc)|2.4.0|—|Knowledge only|
|[udx-native](https://registry.npmjs.org/udx-native)|1.22.1|1.22.1|Latest selected|
|[uncaughts](https://registry.npmjs.org/uncaughts)|1.1.4|—|Knowledge only|
|[unicode-to-plain-text](https://registry.npmjs.org/unicode-to-plain-text)|2.2.0|—|Knowledge only|
|[url-file-url](https://registry.npmjs.org/url-file-url)|1.0.5|1.0.5|Latest selected|
|[which-runtime](https://registry.npmjs.org/which-runtime)|1.4.0|1.4.0|Latest selected|
