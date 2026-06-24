# Gallery placeholder

Per Umbrel App Store spec:
- **3 to 5 high-quality gallery images** required
- **Size**: 1440×900 px
- Replace this file (and add the images) before opening the submission PR

Suggested screenshots for Blindspark (no earning/Lightning imagery — this
is a blind availability node):

1. **`1.png`** — the dashboard: live status, apps seeded, stored / served
   bytes, connections (the headline view).
2. **`2.png`** — the first-run wizard mid-flow (naming the relay /
   choosing accept-mode).
3. **`3.png`** — the seed-request review queue (operator approving an
   incoming request).
4. **`4.png`** (optional) — the wizard welcome step.
5. **`5.png`** (optional) — settings / accept-mode configuration.

## Filenames

Keep `umbrel-app.yml` at `gallery: []` for the first official submission unless
you are ready to submit screenshots in-repo. Once you list gallery filenames,
keep them in sync with whatever you capture (PNG is the spec; some store apps
use JPG — reviewers accept either).

## Capturing them

Take screenshots from a real Umbrel device for authenticity. The Umbrel
reviewers note they'll help design the final gallery from plain
screenshots if pixel-perfect 1440×900 isn't feasible from a dev setup.
