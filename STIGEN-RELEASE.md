# Stigen package releases

This fork publishes compiled npm tarballs as GitHub release assets, not into the
upstream npm namespace. The upstream registry-publish step is disabled for this
repository. No npm registry credentials are needed.

After the owner merges the release changes, create a tag such as
`stigen-v1.17.0-stigen.1` at the reviewed commit. The release workflow runs the full
suite, audits production dependencies, builds an `@stigenai/saml20` tarball,
smoke-tests the packed module, and publishes its checksum and GitHub provenance.
Pull requests run the same package checks without publishing or attesting.

Before pinning Polis, download the exact release asset and verify its checksum and
`gh attestation verify <asset.tgz> --repo stigenai/saml20`. Pin the versioned asset
URL under the existing `@boxyhq/saml20` dependency key and commit the regenerated
consumer lockfile, including its integrity digest. Do not use a branch URL, a
floating tag, a source archive without compiled `dist`, or the upstream registry
package as a substitute.

The fork lockfile updates the two transitive xmldom instances to 0.8.15 for
GHSA-6gmq-8vp8-gcm6. A library lockfile does not constrain its consumers: verify
the Polis dependency tree and production audit after installation, and preserve
the consumer lockfile. Package and provenance checks do not establish that the
enterprise SAML login flow is ready; protocol tests and deployment evidence remain
separate requirements of infra-blocks-xv08.28.
