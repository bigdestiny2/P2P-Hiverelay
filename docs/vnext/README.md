# HiveRelay vNext programme control

`program-state.json` is the machine-readable release-profile, decision, gate,
and track board for the vNext integration train. Recommendations are not owner
decisions. A pending decision stays visibly pending, and a gate cannot be
marked passed without at least one immutable evidence reference.

Validate it with:

```bash
npm run vnext:check-program
```

The current integration base is post-release `main` at `999b0afd…`; the exact
`v0.24.3` artifact baseline remains `d0190577…`. The tentative train is
`v0.25.0-rc.N`. No concrete RC number, profile promotion, channel movement, or
public claim is authorized by this file.
