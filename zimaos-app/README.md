# Blindspark for ZimaOS and CasaOS

`Apps/Blindspark/` is a contribution-ready source directory for the ZimaOS
AppStore v2 repository (which also retains legacy CasaOS compatibility).

The package uses the official Compose plus top-level `x-casaos` model. On first
boot it generates a random management API key, stores it at
`/DATA/AppData/$AppID/data/.management-key`, and reuses it across restarts. The
dashboard receives the token so its controls work without a shared default
credential. Keep the published dashboard port on a trusted LAN unless an
authenticating reverse proxy protects it.

Release preparation updates the upstream version, release note, date, and
immutable container digest. Publishing remains a separate pull request to
`IceWhaleTech/CasaOS-AppStore`, where `./scripts/build_dist.sh` and the
repository CI perform the official validation.
