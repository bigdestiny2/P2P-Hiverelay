# Blindspark — StartOS 0.4 package build.
#
# HiveRelay ships as a multi-arch image (linux/amd64 + linux/arm64), so we
# pack the two matching StartOS arches into one universal package. All real
# work — `npm run check`
# (tsc), `npm run build` (ncc bundle of startos/index.ts), pulling the
# dockerTag image per arch, and `start-cli s9pk pack` — lives in the SDK's
# s9pk.mk. Run `npm ci` once, then `make`.
ARCHES := x86 arm
# The release workflow uploads blindspark.s9pk. Without this override the SDK
# defaults to per-arch files (blindspark_x86_64.s9pk and
# blindspark_aarch64.s9pk), so the release job would fail after a good build.
TARGETS := universal
# overrides to s9pk.mk must precede the include statement
include node_modules/@start9labs/start-sdk/s9pk.mk
