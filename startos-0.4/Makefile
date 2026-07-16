# Blindspark — StartOS 0.4 package build.
#
# HiveRelay ships as a multi-arch image (linux/amd64 + linux/arm64), so we
# build the two matching StartOS arches. All real work — `npm run check`
# (tsc), `npm run build` (ncc bundle of startos/index.ts), pulling the
# dockerTag image per arch, and `start-cli s9pk pack` — lives in the SDK's
# s9pk.mk. Run `npm ci` once, then `make`.
ARCHES := x86 arm
# overrides to s9pk.mk must precede the include statement
include node_modules/@start9labs/start-sdk/s9pk.mk
