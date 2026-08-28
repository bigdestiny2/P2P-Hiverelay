# Blindspark — StartOS 0.4 package build.
#
# HiveRelay ships as a multi-arch image (linux/amd64 + linux/arm64), so we
# pack the two matching StartOS arches into one universal package. All real
# work — `npm run check`
# (tsc), `npm run build` (ncc bundle of startos/index.ts), pulling the
# dockerTag image per arch, and `start-cli s9pk pack` — lives in the SDK's
# s9pk.mk. Run `npm ci` once, then `make`.
ARCHES := x86 arm
IMAGE_NAME := ghcr.io/bigdestiny2/p2p-hiverelay
IMAGE_VERSION := $(shell node -p "require('../package.json').version")
IMAGE_TAG := $(IMAGE_NAME):$(IMAGE_VERSION)
IMAGE_DIGEST ?=
REQUIRE_RELEASE_IMAGE_DIGEST ?= 0
# The TypeScript manifest reads this at build/pack time. Local mechanics builds
# retain the aligned semver tag; release CI supplies the release-surfaces digest
# and turns REQUIRE_RELEASE_IMAGE_DIGEST on so a mutable image cannot be packed.
# Release CI intentionally runs `ingredients`, verifies the manifest emitted by
# that exact javascript/index.js bundle, then invokes the same `start-cli s9pk
# pack -o blindspark.s9pk` command as the SDK universal target without giving
# Make a second opportunity to rebuild the verified bundle.
HIVERELAY_STARTOS_04_IMAGE_REF := $(IMAGE_TAG)$(if $(strip $(IMAGE_DIGEST)),@$(strip $(IMAGE_DIGEST)))
export HIVERELAY_STARTOS_04_IMAGE_REF
# The release contract is the SDK's universal target, which emits the
# predictable local filename blindspark.s9pk instead of per-arch filenames.
TARGETS := universal
# overrides to s9pk.mk must precede the include statement
include node_modules/@start9labs/start-sdk/s9pk.mk

.PHONY: check-release-image
check-release-image:
	@if [ "$(REQUIRE_RELEASE_IMAGE_DIGEST)" = "1" ]; then \
	  printf '%s\n' "$(IMAGE_DIGEST)" | grep -Eq '^sha256:[a-f0-9]{64}$$' || { \
	    echo "IMAGE_DIGEST=sha256:<64 lowercase hex> from a successful release-surfaces run is required for StartOS 0.4 release packaging." >&2; \
	    exit 1; \
	  }; \
	fi

universal: check-release-image
