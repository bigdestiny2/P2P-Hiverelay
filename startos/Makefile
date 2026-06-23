# Blindspark — StartOS package build.
#
# Reuses the published multi-arch GHCR image (same one the Umbrel app
# pins) rather than rebuilding. Requires docker (with buildx) and
# start-sdk (https://github.com/Start9Labs/start-os, `cargo install` or
# release binary). Run `make` from this directory.

VERSION := 0.20.0
IMAGE := ghcr.io/bigdestiny2/p2p-hiverelay:$(VERSION)
# Optional immutable pin for the retag FROM: `make IMAGE_DIGEST=sha256:...`.
# Default empty -> FROM the :$(VERSION) tag (resolves to the current multi-arch
# image). The image is bundled into the s9pk at build time either way.
IMAGE_DIGEST ?= sha256:0b8857cda2d0e399031a135a0c5f9c8a2ec6fa77cf64ed1c59aba58351c9eae1
S9PK := blindspark.s9pk
TAG := start9/blindspark/main:$(VERSION)

.PHONY: all clean verify

all: $(S9PK)

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
image: Dockerfile.retag
	mkdir -p image
	docker buildx build --platform linux/amd64 -f Dockerfile.retag -t $(TAG) \
	  --output type=docker,dest=image/x86_64.tar .
	docker buildx build --platform linux/arm64 -f Dockerfile.retag -t $(TAG) \
	  --output type=docker,dest=image/aarch64.tar .
	@touch image

# Generated (gitignored) — regenerated whenever VERSION/IMAGE_DIGEST change,
# since it depends on this Makefile. Without the prerequisite a stale retag
# from a previous version's build would silently FROM the wrong image.
Dockerfile.retag: Makefile
	printf 'FROM $(IMAGE)$(if $(IMAGE_DIGEST),@$(IMAGE_DIGEST),)\n' > Dockerfile.retag

$(S9PK): manifest.yaml instructions.md icon.png image docker_entrypoint.sh check-web.sh ../LICENSE
	cp ../LICENSE LICENSE
	start-sdk pack

verify: $(S9PK)
	start-sdk verify s9pk $(S9PK)

clean:
	rm -rf image icon.png LICENSE $(S9PK) Dockerfile.retag
