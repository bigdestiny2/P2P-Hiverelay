# TrueNAS apps rendering library notice

The source files under
`truenas-app/templates/library/base_v2_3_8/` are vendored from the
[`truenas/apps`](https://github.com/truenas/apps) project.
They are not covered by HiveRelay's Apache-2.0 license. Those files remain licensed under the GNU
Lesser General Public License version 3 only (LGPL-3.0-only); the exact license
text is distributed beside this notice as `LICENSE.LGPL-3.0`.

Snapshot provenance:

- upstream repository: `https://github.com/truenas/apps.git`
- upstream commit: `531009fca352356237287dbcc119c1365307ab86`
- upstream path: `ix-dev/community/bambuddy/templates/library/base_v2_3_8`
- upstream Git tree: `3d946a0dbe832cb16e5da40c4a5d6f0dafb2be21`
- TrueNAS library version: `2.3.8`
- official `library/hashes.yaml` value:
  `cd75c897a1e8fef54b5bd00d0d8849f240bc50db2ef650eccc0ee74f3b2b2dc1`

The local snapshot matches the substantive upstream files. The two package
marker files listed in `PROVENANCE.json` contain a single trailing newline
instead of the upstream empty blob. The offline package validator recomputes a
deterministic SHA-256 over every vendored path and byte and rejects any content
drift. It also verifies that these two declared newline-only deviations remain
exactly one byte each.

Copyright remains with the TrueNAS apps contributors. Source availability,
modification, and redistribution of this subtree are governed by LGPL-3.0-only.
All HiveRelay-authored files outside this explicitly identified subtree remain
under the repository's Apache-2.0 license.
