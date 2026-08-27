import { setupManifest } from '@start9labs/start-sdk'
import { long, short } from './i18n'

// Blindspark reuses the SAME published multi-arch GHCR image that the 0.3.x
// StartOS package and the Umbrel app pin — StartOS 0.4 pulls it directly from
// the registry at pack time (`source.dockerTag`), so there is no Dockerfile,
// no per-arch retag, and no docker-archive export to maintain.
//
// RELEASE: bump `version` here-adjacent in ../versions/current.ts AND the
// image tag below together, so the package version and the image it runs stay
// in lockstep with the HiveRelay monorepo version (see ../../package.json).
// Release CI overrides the aligned authoring tag with the exact digest-qualified
// ref proven by release-surfaces; local mechanics builds retain the authoring
// tag so contributors can still run the SDK toolchain before an image exists.
const releaseImageRef =
  process.env.HIVERELAY_STARTOS_04_IMAGE_REF ||
  'ghcr.io/bigdestiny2/p2p-hiverelay:0.26.0-rc.7'

export const manifest = setupManifest({
  id: 'blindspark',
  title: 'Blindspark',
  license: 'apache-2.0',
  packageRepo: 'https://github.com/bigdestiny2/P2P-Hiverelay',
  upstreamRepo: 'https://github.com/bigdestiny2/P2P-Hiverelay',
  marketingUrl: 'https://hiverelay.com/',
  donationUrl: null,
  description: { short, long },
  volumes: ['main'],
  images: {
    blindspark: {
      source: { dockerTag: releaseImageRef },
      arch: ['x86_64', 'aarch64'],
    },
  },
  dependencies: {},
})
