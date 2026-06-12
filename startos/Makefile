# Blindspark — StartOS package build.
#
# Reuses the published multi-arch GHCR image (same one the Umbrel app
# pins) rather than rebuilding: pull → save → pack. Requires docker and
# start-sdk (https://github.com/Start9Labs/start-os, `cargo install` or
# release binary). Run `make` from this directory.

VERSION := 0.15.6
IMAGE := ghcr.io/bigdestiny2/p2p-hiverelay:$(VERSION)
S9PK := blindspark.s9pk

.PHONY: all clean verify

all: $(S9PK)

icon.png: ../umbrel-app/icon.svg
	@command -v rsvg-convert >/dev/null 2>&1 \
	  && rsvg-convert -w 256 -h 256 $< -o $@ \
	  || { echo "rsvg-convert not found — render ../umbrel-app/icon.svg to icon.png (256x256) manually"; exit 1; }

# StartOS expects the image inside the tar to be tagged
# start9/<pkg-id>/<image-name>:<version>. A trivial FROM build re-tags
# (and re-manifests — dodges Docker Desktop content-store quirks with
# platform-filtered registry pulls).
image.tar:
	docker pull --platform linux/amd64 $(IMAGE)
	printf 'FROM $(IMAGE)\n' > Dockerfile.retag
	docker build --platform linux/amd64 -f Dockerfile.retag -t start9/blindspark/main:$(VERSION) .
	rm Dockerfile.retag
	docker save start9/blindspark/main:$(VERSION) -o image.tar

$(S9PK): manifest.yaml instructions.md icon.png image.tar docker_entrypoint.sh check-web.sh ../LICENSE
	cp ../LICENSE LICENSE
	start-sdk pack

verify: $(S9PK)
	start-sdk verify s9pk $(S9PK)

clean:
	rm -f image.tar icon.png LICENSE $(S9PK)
