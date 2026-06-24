# Blindspark — StartOS package build.
#
# Reuses the published multi-arch GHCR image (same one the Umbrel app
# pins) rather than rebuilding. Requires docker (with buildx) and
# start-sdk (https://github.com/Start9Labs/start-os, `cargo install` or
# release binary). Run `make` from this directory.

VERSION ?= $(shell sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' ../package.json | head -n 1)
IMAGE_NAME := ghcr.io/bigdestiny2/p2p-hiverelay
IMAGE_DIGEST ?=
ALLOW_TAG_ONLY_IMAGE ?=
IMAGE := $(IMAGE_NAME):$(VERSION)
IMAGE_REF := $(IMAGE)$(if $(IMAGE_DIGEST),@$(IMAGE_DIGEST),)
S9PK := blindspark.s9pk
TAG := start9/blindspark/main:$(VERSION)

.PHONY: all clean verify digest check-digest image validate-image-ref Dockerfile.retag

all: $(S9PK)

# Print the authoritative multi-arch manifest (index) digest for the current
# VERSION — paste it into IMAGE_DIGEST when cutting a release.
digest:
	@docker buildx imagetools inspect $(IMAGE) 2>/dev/null | awk '/^Digest:[[:space:]]/{print $$2; exit}' \
	  | grep . || { echo "digest: cannot resolve $(IMAGE) — is the image published?"; exit 1; }

# Guard run before the image build: a pinned IMAGE_DIGEST must equal the
# :$(VERSION) tag's manifest digest. Catches a wrong (blob) digest AND a stale
# digest carried over from a previous version (which would silently build the
# wrong image). One imagetools inspect per build — cheap, not a poll loop.
check-digest:
	@if [ -n "$(IMAGE_DIGEST)" ]; then \
	  actual=$$(docker buildx imagetools inspect $(IMAGE) 2>/dev/null | awk '/^Digest:[[:space:]]/{print $$2; exit}'); \
	  if [ -z "$$actual" ]; then echo "check-digest: cannot resolve $(IMAGE) — is it published?"; exit 1; fi; \
	  if [ "$$actual" != "$(IMAGE_DIGEST)" ]; then \
	    echo "check-digest: IMAGE_DIGEST does not match the $(IMAGE) manifest:"; \
	    echo "    pinned:   $(IMAGE_DIGEST)"; \
	    echo "    manifest: $$actual"; \
	    echo "  Fix: set IMAGE_DIGEST to the manifest digest above (run 'make digest')."; \
	    exit 1; \
	  fi; \
	  echo "check-digest: IMAGE_DIGEST matches $(IMAGE) ($$actual)"; \
	fi

icon.png: ../umbrel-app/icon.svg
	@command -v rsvg-convert >/dev/null 2>&1 \
	  && rsvg-convert -w 256 -h 256 $< -o $@ \
	  || { echo "rsvg-convert not found — render ../umbrel-app/icon.svg to icon.png (256x256) manually"; exit 1; }

# Multi-arch: StartOS 0.3.5.x reads `docker-images` as a DIRECTORY of
# per-arch tarballs named <arch>.tar (x86_64.tar, aarch64.tar). At pack
# time start-sdk writes a multiarch.cbor index (default aarch64 if
# present); on install the device extracts the tar matching its CPU
# (see core/startos/src/s9pk/{mod,docker}.rs).
#
# StartOS expects each image tagged start9/<pkg-id>/<image-name>:<version>.
# A trivial FROM build re-tags per platform, and buildx's `type=docker`
# exporter writes a legacy docker-archive (with manifest.json) that the
# 0.3.5.x reader requires — plain `docker save` fails under Docker's
# containerd image store. buildx pulls the right platform automatically.
image: validate-image-ref check-digest Dockerfile.retag
	rm -rf image
	mkdir -p image
	docker buildx build --platform linux/amd64 -f Dockerfile.retag -t $(TAG) \
	  --output type=docker,dest=image/x86_64.tar .
	docker buildx build --platform linux/arm64 -f Dockerfile.retag -t $(TAG) \
	  --output type=docker,dest=image/aarch64.tar .
	@touch image

validate-image-ref:
	@if [ -z "$(IMAGE_DIGEST)" ] && [ "$(ALLOW_TAG_ONLY_IMAGE)" != "1" ]; then \
	  echo "IMAGE_DIGEST=sha256:<multi-arch-digest> is required for StartOS packaging. Use ALLOW_TAG_ONLY_IMAGE=1 only for local mechanics checks."; \
	  exit 1; \
	fi
	@if [ -n "$(IMAGE_DIGEST)" ] && ! printf '%s' "$(IMAGE_DIGEST)" | grep -Eq '^sha256:[a-f0-9]{64}$$'; then \
	  echo "IMAGE_DIGEST must be sha256:<64 lowercase hex chars>."; \
	  exit 1; \
	fi

# Generated (gitignored) — regenerated whenever VERSION/IMAGE_DIGEST change,
# since it depends on this Makefile. Without the prerequisite a stale retag
# from a previous version's build would silently FROM the wrong image.
Dockerfile.retag: Makefile
	printf 'FROM $(IMAGE_REF)\n' > Dockerfile.retag

$(S9PK): manifest.yaml instructions.md icon.png image docker_entrypoint.sh check-web.sh ../LICENSE
	cp ../LICENSE LICENSE
	start-sdk pack

verify: $(S9PK)
	start-sdk verify s9pk $(S9PK)

clean:
	rm -rf image icon.png LICENSE $(S9PK) Dockerfile.retag
