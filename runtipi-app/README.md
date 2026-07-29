# Blindspark for Runtipi

`apps/blindspark/` mirrors the directory layout expected by the official
Runtipi App Store.

Runtipi generates a random management API key from the `random` install field
and injects it into the container. The dashboard receives that token so its
controls can authenticate. Keep the app private to the trusted home network
unless an authenticating proxy protects it.

Release preparation updates `config.json`, bumps `tipi_version` when the
runtime changes, and pins `docker-compose.yml` to the released multi-arch image
digest. Publishing remains a separate pull request to
`runtipi/runtipi-appstore`.
