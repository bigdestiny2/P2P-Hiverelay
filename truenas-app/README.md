# Blindspark by HiveRelay for TrueNAS

Blindspark runs the released HiveRelay container as a TrueNAS Community app. It provides an always-on blind relay for Pear and Holepunch applications while keeping relay identity, configuration, and seeded data on persistent TrueNAS storage.

## Install defaults

- Upstream HiveRelay release: `1.0.0-rc.1`
- Dashboard port: `30452` on the TrueNAS host
- Persistent state: one `ixVolume` mounted at `/data`
- Runtime user and group: `999:999`
- First-boot storage cap: `10 GB`
- Incoming seed requests: queued for operator review
- Management API: protected by the API key entered during installation

The simple dashboard is enabled by default. Management-token embedding is disabled because a normal TrueNAS published port is not an authenticated reverse proxy. Enabling **Expose Management Token in Dashboard** makes management controls usable in a browser, but every client able to load that page can read the token; only enable it on a trusted, access-controlled network.

## TrueNAS Community submission

Copy this directory to `ix-dev/community/blindspark` in a fork of [truenas/apps](https://github.com/truenas/apps). Run the catalog metadata generator and app test suite described in the TrueNAS contributor guide before opening a draft pull request. Attach `umbrel-app/icon.svg` from the HiveRelay repository so the TrueNAS reviewer can publish it to the catalog media CDN.

Catalog publication and real-device acceptance remain subject to TrueNAS Community review.
