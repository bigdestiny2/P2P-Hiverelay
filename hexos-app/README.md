# Blindspark curation for HexOS

`blindspark.json` is a HexOS V4 install script for the TrueNAS Community app
named `blindspark`.

The curation requests the default dashboard port, creates a random management
key, enables the appliance dashboard, and applies conservative home-server
storage and resource defaults. The underlying application definition and
container image come from `truenas-app/`.

Release preparation bumps the curation script revision and records the
upstream HiveRelay version. Publishing remains a separate pull request to
`eshtek/hexos-app-catalog`, followed by fresh-install and upgrade testing in
HexOS Expert Mode.
