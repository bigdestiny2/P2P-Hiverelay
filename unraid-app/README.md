# Blindspark for Unraid Community Applications

This directory is the source bundle for the Blindspark Unraid template.

The Community Applications submission repository expects `ca_profile.xml` at
its root and one XML file per application under `templates/`. To publish this
bundle, copy the contents of `unraid-app/` into a dedicated repository made
from Unraid's official Community Applications starter, then submit that
repository through the Community Applications portal.

Release preparation updates the container version, immutable image digest,
change text, and release date in `templates/blindspark.xml`. It does not submit
the repository or bypass Unraid's Validate, Scan, and moderator-review steps.

At install time, Unraid requires the operator to provide a unique management
API key of at least 32 characters. The dashboard embeds that key so its
controls can authenticate; publish the dashboard only to a trusted LAN or
place it behind an authenticating reverse proxy.
