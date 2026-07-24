#!/usr/bin/env python3
"""Extract OCI image index + platform manifest digests from an OCI layout tar.

Handles the buildx nested layout (top-level index.json -> image index ->
platform image manifests + attestation manifests).

Usage: extract-oci-digests.py <archive.oci.tar>
"""
import hashlib
import json
import sys
import tarfile


def load_json(tf, blobs, digest):
    return json.loads(tf.extractfile(blobs[digest]).read())


def main(path):
    with tarfile.open(path) as tf:
        index_raw = tf.extractfile("index.json").read()
        top_index = json.loads(index_raw)
        blobs = {
            "sha256:" + n.split("/")[-1]: n
            for n in tf.getnames()
            if n.startswith("blobs/sha256/")
        }

        platforms = []
        attestations = []
        image_indexes = []

        def walk_index(idx, digest):
            for m in idx.get("manifests", []):
                mt = m.get("mediaType", "")
                if mt.endswith("image.index.v1+json"):
                    image_indexes.append(m["digest"])
                    walk_index(load_json(tf, blobs, m["digest"]), m["digest"])
                    continue
                blob = load_json(tf, blobs, m["digest"])
                entry = {
                    "digest": m["digest"],
                    "mediaType": mt,
                    "size": m.get("size"),
                    "platform": m.get("platform"),
                    "annotations": m.get("annotations"),
                    "subject_digest": (blob.get("subject") or {}).get("digest"),
                    "config_digest": (blob.get("config") or {}).get("digest"),
                    "layer_digests": [l["digest"] for l in blob.get("layers", [])],
                }
                ref_type = (m.get("annotations") or {}).get("vnd.docker.reference.type")
                if blob.get("subject") or ref_type == "attestation-manifest":
                    attestations.append(entry)
                else:
                    platforms.append(entry)

        walk_index(top_index, "sha256:" + hashlib.sha256(index_raw).hexdigest())

        out = {
            "archive": path.split("/")[-1],
            "top_index_digest": "sha256:" + hashlib.sha256(index_raw).hexdigest(),
            "image_index_digest": image_indexes[-1] if image_indexes else None,
            "ref_annotations": (top_index.get("manifests") or [{}])[0].get("annotations"),
            "platform_manifests": platforms,
            "attestation_manifests": [
                {k: v for k, v in a.items() if k != "layer_digests"} for a in attestations
            ],
        }
        json.dump(out, sys.stdout, indent=2)
        print()


if __name__ == "__main__":
    main(sys.argv[1])
