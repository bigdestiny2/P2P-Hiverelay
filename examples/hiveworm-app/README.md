# HiveWorm — browser frontend

A single-page browser bundle for HiveWorm — the perpetual P2P life-sim
that runs against a HiveRelay node.

You're a worm in a 2D meadow. Eat dots to grow. Crash into another worm
and you die. Async multiplayer: one move per worm every five seconds,
played from anywhere in the world, anchored on the relay's autobase log.

## What's in the bundle

```
index.html         page shell, viewport, mount point
game.js            entry — wires identity + network + world + renderer
network.js         relay HTTP + WS client (graceful poll fallback)
identity.js        ed25519 keygen + localStorage + backup/import
schema.js          canonical signing — must match relay/schema.js
worm.js            client Worm: rendering + interpolation + color
world.js           tracks worms + food, applies entries from log
renderer.js        Canvas2D draw routines
input.js           keyboard + touch + cooldown gate
audio.js           synthesized SFX over WebAudio (no audio files)
config.js          relay endpoint, default biome key
style.css          saturated 90s-cartoon aesthetic
package.json       single dep: @noble/ed25519
```

No build step. Pure ES modules. The only third-party dep is
`@noble/ed25519`, loaded directly from `unpkg.com` via `import`.

## Running locally

You need two things:

1. A running HiveRelay node with `enableHiveworm: true` in its config.
   The relay must serve `/api/hiveworm/*` — see
   `packages/core/core/relay-node/api.js` for the route handlers.

2. A static file server pointed at this directory. Any will do; for
   the absolutely simplest case:

   ```bash
   cd examples/hiveworm-app
   python3 -m http.server 8080
   ```

   Then open `http://localhost:8080` in your browser. By default the
   bundle tries to talk to a relay at `http://localhost:9100`. Override
   it with a query string:

   ```
   http://localhost:8080/?relay=http://10.0.0.5:9100
   ```

You can also override the biome:

```
http://localhost:8080/?biome=<64-hex-chars>
```

The default biome is `0x000…0001` — a zero-ish placeholder so the
bundle works against a fresh relay. When you publish a real foundation
biome, edit `config.js` (`defaultBiome`) before publishing.

## Multiplayer test

Open the page in two browsers (or two profiles). They'll generate
different keypairs and show up as separate worms. Crash one into
another and watch the splat.

## Identity & backups

- The browser generates a fresh ed25519 keypair on first launch and
  persists it in `localStorage` under `hiveworm/identity/v1`.
- There's no password. If localStorage is wiped, the worm is gone.
- Click **backup** to download a `.json` file containing the seed.
- Click **import** to restore from a backup file. WARNING: this
  replaces the current worm permanently.

## Controls

- Arrow keys or WASD to move (one cell per press)
- 5-second cooldown between moves (matches the relay's default)
- `M` toggles audio mute
- On touch devices, a directional pad appears in the lower-right

## Bundle size

The full bundle is well under 250 KB unminified (most files are 3-10 KB
each; the largest is `renderer.js`). The only runtime download is
`@noble/ed25519` from unpkg, which adds ~5 KB gzipped.

## What's next

This is a static site. To deploy it as a Hyperdrive on the HiveRelay
network — so it's served peer-to-peer alongside everything else — wrap
this directory in a publish step:

```js
import { HiveRelayClient } from 'p2p-hiverelay-client'
const relay = new HiveRelayClient('./app-storage')
await relay.start()
const drive = await relay.publish('./examples/hiveworm-app')
console.log('App key:', drive.key.toString('hex'))
await relay.seed(drive.key.toString('hex'), { replicas: 3 })
```

The user is handling the publish step separately.

## Design notes

- **Aesthetic.** Goofy + nostalgic + slick. References: Worms 2 (Team17)
  for chunky cartoon worms with personality, Pokémon Gold/Silver route
  maps for the saturated meadow palette, Earthbound for quirky character
  density, Bubble Bobble for bouncy proportions. *Goofy is the
  personality, slick is the quality* — every animation has a real easing
  curve, every sound is timed to its on-screen frame, every worm has a
  face that blinks, chomps, and goes x_x on death.
- **Palette.** Saturated 90s cartoon, not pastel — sky blue
  (`#7ec8e3`) → mint horizon (`#a8e6cf`) → grass (`#7cba5f`), with
  worms in bubblegum pink, lime, electric blue, sunshine yellow,
  tomato, hot purple. Chunky black outlines + offset paper shadows on
  every UI panel.
- **Type.** "Press Start 2P" for chunky pixel headings (LENGTH, K.O.!,
  SPAWN), "VT323" for body. Loaded from Google Fonts.
- **Optimistic rendering.** When you submit a move, the client applies
  it locally before the relay confirms — keeps the UI feeling snappy
  even on a high-latency link. The next state pull / WS message
  reconciles drift.
- **Soft state hydration.** `loadState()` doesn't delete unknown
  worms, so death animations stay on screen for a beat after the
  authoritative state has dropped them.
- **Synthesized SFX.** Web Audio oscillators with envelopes — no audio
  files in the bundle. Square waves with short envelopes for the eat
  blip, a 4-note arpeggio for rare food (Mario-star style), slide-whistle
  for death, FM-flavored chime for milestones, and an optional
  bossa-meets-chiptune ambient bed (off by default — call
  `audio.startAmbient()`).
- **Canvas2D, not WebGL.** Renderer paints faces, food sprites
  (apples, donuts, ice cream, pizza, gummy bears, cherries — each with
  a tiny smile), grass tufts, flowers, pebbles, drifting clouds, and
  rolling distant hills. All procedural, no asset pipeline.
- **No frameworks.** Vanilla ES modules + DOM. The biggest file is
  `renderer.js` at ~24 KB (food sprites add weight, but everything is
  procedural).

## Spec ambiguities resolved

- **Default biome key.** The spec said "use a placeholder to fill in
  later." I picked `0x000…0001` (63 zeros + a 1) over all-zeros so
  it's distinct from any genuine "uninitialized" value the relay
  might check for. Edit `config.js` to change it.
- **WS event format.** The other agent is building this; the client
  accepts both `{ type: 'entry', entry }` envelopes and bare entries
  with a `schema` field. If their format is different, only
  `network.js` needs updating.
- **Spawn cell selection.** Spec didn't say where to spawn. I pick a
  random cell and retry up to 6 times if `spawn-occupied` comes back.
- **Memorial UI.** The schema supports an epitaph but the spec didn't
  ask for the UI to write one. I omitted the form for v1; the
  rendering side will display memorials when they appear in state.
- **Audio files.** Spec mentioned `.ogg` placeholders but allowed
  synthesis. I synthesized — keeps the bundle in budget without
  asset pipelines.
