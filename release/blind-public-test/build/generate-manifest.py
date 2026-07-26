#!/usr/bin/env python3
"""Generate release/blind-public-test/artifact-manifest.json from recorded
build digests and on-disk artifact hashes. Run from the repository root."""
import hashlib
import json
import os

ROOT = os.path.dirname(os.path.abspath(__file__)) + "/../../.."
REL = "release/blind-public-test"
VERSION = "1.0.0-rc.1.public-test.1"
SOURCE_REVISION = "973f25c212553653b65811eacd28ed35b1b54124"
SOURCE_TREE = "ebd504fa318a90f34fc52e9febb9385db606330d"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def rel(path):
    return os.path.join(ROOT, path)


def load(path):
    with open(rel(path)) as f:
        return json.load(f)


def component(c):
    b1 = load(f"{REL}/build/{c}-build1.digests.json")
    b2 = load(f"{REL}/build/{c}-build2.digests.json")
    platforms = []
    for m in b2["platform_manifests"]:
        plat = m["platform"]
        p1 = next(
            x for x in b1["platform_manifests"]
            if x["platform"]["os"] == plat["os"] and x["platform"]["architecture"] == plat["architecture"]
        )
        attest = next(
            a for a in b2["attestation_manifests"]
            if a["annotations"].get("vnd.docker.reference.digest") == m["digest"]
        )
        platforms.append({
            "platform": f"{plat['os']}/{plat['architecture']}",
            "manifest_digest": m["digest"],
            "config_digest": m["config_digest"],
            "reproducibility_build1_manifest_digest": p1["digest"],
            "reproducible": p1["digest"] == m["digest"],
            "attestation_manifest_digest": attest["digest"],
            "provenance_statement_file": f"{REL}/provenance/{c}-{plat['os']}-{plat['architecture']}.slsa.json",
            "provenance_statement_sha256": sha256_file(rel(f"{REL}/provenance/{c}-{plat['os']}-{plat['architecture']}.slsa.json")),
        })
    return {
        "component": c,
        "image": f"hiverelay/blind-{c}",
        "version": VERSION,
        "dockerfile": f"Dockerfile.blind-{c}",
        "dockerfile_sha256": sha256_file(rel(f"Dockerfile.blind-{c}")),
        "canonical_image_index_digest": b2["image_index_digest"],
        "reproducibility_build1_image_index_digest": b1["image_index_digest"],
        "index_note": "image indexes differ between clean builds only in attestation-manifest entries (provenance build timestamps); platform manifests are byte-identical",
        "oci_archive_build2": f"{REL}/oci-archives/blind-{c}-{VERSION}-build2.oci.tar",
        "oci_archive_build2_sha256": sha256_file(rel(f"{REL}/oci-archives/blind-{c}-{VERSION}-build2.oci.tar")),
        "oci_archive_build1_sha256": sha256_file(rel(f"{REL}/oci-archives/blind-{c}-{VERSION}-build1.oci.tar")),
        "platforms": platforms,
        "sbom": {
            p["platform"]: {
                "file": f"{REL}/sbom/blind-{c}-linux-{p['platform'].split('/')[1]}.spdx.json",
                "sha256": sha256_file(rel(f"{REL}/sbom/blind-{c}-linux-{p['platform'].split('/')[1]}.spdx.json")),
                "format": "SPDX-2.3",
                "generator": "anchore/syft:v1.49.0@sha256:13b53ebabe3d215268c90cf8fb9b875f0183908245f376fd4b3a2cb69d21d484",
            }
            for p in platforms
        },
    }


manifest = {
    "schema_version": 1,
    "manifest_id": "hiverelay-blind-public-test-artifact-manifest-v1",
    "signature_status": "UNSIGNED-PENDING-CONDUCTOR-RESIGN",
    "signature_note": "This manifest is NOT signed. It was RECONSTRUCTED after an external actor destroyed the release worktree and branch (incident assignments/programme-control/external-worktree-teardown-incident-20260726t130752z.json: commits 3088ee1/866fec3/a4ba363 and the signed manifest, phase-2 manifest and pin-history files lost from git). The conductor re-signs this reconstructed manifest as a separate step; pin-history.json is reconstructed with signature fields marked PENDING-RESIGN. Do not deploy from this file until the re-signed successor exists.",
    "release": VERSION,
    "claim_boundary": "LIVE_PUBLIC_TEST_ONLY",
    "claim_boundary_detail": "no GA; no catalogue; no marketplace; no stable promotion; no documentation-complete claim; readiness stays zero",
    "source": {
        "repository": "https://github.com/bigdestiny2/p2p-hiverelay",
        "commit": SOURCE_REVISION,
        "tree": SOURCE_TREE,
        "runtime_acceptance_record_sha256": "1febe4dbe0070fbf74e7f6707974ae0decd4174c3e351e78f97b5f1a8974d3a5",
        "assembly_acceptance_record_sha256": "59bcf6862722fb94f009b50bcd84783a15968d7f90364790637e9e73a41e6d69",
        "note": "merged rebuild-branch HEAD: accepted runtime 447bbbf + browser regeneration 51a0b37 (F2) + release tooling + packaging fix ba710dc (F1) + independently ACCEPTED production-profile assembly 66e0fa7/tree 64ad55eb779abae8ef8035c3d8a6c62c4d2056d8 + independently-accepted FLEET-DURABILITY-P1-1 boot-restore fix 49e12d8 (merge 973f25c). This build carries the assembled production profile AND the verified manifest-floor boot-restore fix; the daemon passes its own release gate for LIMITED_PUBLIC_TEST_V1 and boots restored past lapsed chain windows. Browser artifact bytes are not copied into either image",
    },
    "base_images": {
        "toolchain": "node:22-bookworm@sha256:5647be709086c696ff32edaaf1c70cd26d1da6ab2b39c32f3c7b4c4a31957e37",
        "runtime": "node:22-bookworm-slim@sha256:53ada149d435c38b14476cb57e4a7da73c15595aba79bd6971b547ceb6d018bf",
        "dockerfile_frontend": "docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e",
        "apt_inputs": "none — no apt-get in any build stage; Debian package inputs are exactly the pinned base-image contents",
    },
    "build": {
        "builder": "docker buildx v0.31.1-desktop.1 / buildkit v0.27.0 (Docker 29.2.0, containerd image store)",
        "source_date_epoch": 1785072458,
        "source_date_epoch_note": "matches merged HEAD 973f25c commit timestamp used by build-image.sh and all four SLSA predicates",
        "provenance": "mode=max (SLSA v0.2), verified: subjects match platform manifests; materials pin dockerfile frontend and both base images by digest; HIVERELAY_BLIND_SOURCE_REVISION build-arg present (merged source revision)",
        "reproducibility": "two consecutive clean builds per image (BOTH rounds --no-cache: buildkit rewrite-timestamp only rewrites layers built in the same invocation; a fully cache-hit round exports stale wall-clock mtimes); platform manifests byte-identical",
        "build_script": f"{REL}/build/build-image.sh",
        "build_script_sha256": sha256_file(rel(f"{REL}/build/build-image.sh")),
        "build_logs": f"{REL}/build/logs/",
    },
    "images": [component("edge"), component("daemon")],
    "browser_artifact": {
        "path": "packages/blind-client/browser-artifacts/blind-client-control-v3.mjs",
        "sha256": "sha256:874afd4a1927d4df2f0b439c1ecb72679de7eadde91ab256a330d85378e98744",
        "artifact_hash_v3": "46a86079fb5fcaaeee42362113182ca0d41b9d004f0f5d62ec04869c0844f3ff",
        "manifest_cenc_sha256": "sha256:819358a1638cf13e5ce149b52ddae922159c595558081135b1e74737ddcca3c4",
        "authority_json_sha256": "sha256:3943a61c1b8fd7d75b339620d17320954729f1516b100a8ff858a265731cb928",
        "source_closure_json_sha256": "sha256:f9f49e6a58f8861cde0aff1c5b2d75938cde0c9d8a002ed1764c9f9659280563",
        "determinism": "regenerated twice from the exact accepted source with esbuild@0.28.1 (lockfile npm ci); byte-identical; generator --check passes; test/unit/blind-client-composition-v3.test.js 1/1",
        "binding": "OUTSIDE both relay images (separate artifact); verified zero blind-client-control-* files inside both images",
        "disclosed_staleness_finding": "the v3 artifact committed at 447bbbf (mjs sha256 bbef09b6c0cf2b27673dba31a53288f4ae31b85646d5d7adf6a7ad66105369ea, artifactHash 2197a9600f0c2e453155acfd03e63ecbae15cba00ae4616934f3026012cceb9b) was generated from a node_modules tree that did not match package-lock.json (root compact-encoding 3.3.0 instead of the locked packages/blind-protocol/node_modules compact-encoding 2.19.2); the regenerated artifact bound here is lockfile-faithful and is committed separately by this lane",
    },
    "compose_overlay": {
        "file": "docker-compose.blind-public-test.yml",
        "sha256": sha256_file(rel("docker-compose.blind-public-test.yml")),
        "properties": "digest-pinned images; host TCP 443 mapped directly to Edge TLS 9100 (no reverse proxy); daemon network_mode none on private Unix-socket volume; mem/cpu/pids/ulimit limits; compose config validated",
    },
    "vulnerability": {
        "policy": f"{REL}/security/vulnerability-policy.json",
        "policy_sha256": sha256_file(rel(f"{REL}/security/vulnerability-policy.json")),
        "disposition": f"{REL}/security/scan-disposition.json",
        "disposition_sha256": sha256_file(rel(f"{REL}/security/scan-disposition.json")),
        "gate_result": "NO_BLOCKING_FINDING (report-only gate); zero findings in the relay closure /opt/hiverelay",
    },
    "rollback": {
        "plan": f"{REL}/rollback/README.md",
        "script": f"{REL}/rollback/rollback-public-test.sh",
        "script_sha256": sha256_file(rel(f"{REL}/rollback/rollback-public-test.sh")),
        "summary": "stops/removes only the sidecar Edge listener + daemon + volume-init containers of project hiverelay-blind-public-test; retains all named-volume roots; leaves fleet and T1 untouched",
    },
    "disclosed_defects_and_remediation": {
        "packaging_metadata_files_omissions": "F1 RESOLVED at source level: ba710dc (fix(packaging)) adds private-ipc v3/v4 contract/status/authority + vectors-v3/v4 to packages/blind-ipc files[] and forward-https-vnext.js to packages/blind-edge files[]; verified via npm pack dry-run and build-time test -f gates. The release lane's earlier Dockerfile-level workaround (exact-source closure copies, used for the 447bbbf builds) is fully removed; images are now the plain npm-pack filtered lockfile install from the corrected source.",
        "build_gates_retained": "test -f assertions on the previously-omitted files plus a full closure module-graph import gate remain in both Dockerfiles (they caught the original omission)",
        "browser_artifact_staleness": "F2 remains as previously disclosed: the v3 artifact committed at 447bbbf was stale vs package-lock.json; the lockfile-faithful regeneration (lane commit 51a0b37, in ba710dc ancestry) is bound below and verified unchanged at ba710dc via generator --check",
    },
    "t1": {
        "file": "fleet/public-hive-gateway-release.json",
        "sha256": "sha256:bfcc12664be108cdb13b1ca83f088a87fdcb03efa598377aca1c1d34a0f36064",
        "enabled": False,
        "note": "byte-identical and disabled; untouched by this lane",
    },
    "readiness_zero": True,
    "not_performed": ["signing", "registry push/tag", "transfer", "deployment", "T1 mutation", "runtime-code changes"],
}

with open(rel(f"{REL}/artifact-manifest.json"), "w") as f:
    json.dump(manifest, f, indent=2)
    f.write("\n")
print("wrote", f"{REL}/artifact-manifest.json")
