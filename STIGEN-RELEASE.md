# Stigen package releases

This fork publishes compiled npm tarballs as GitHub release assets, not into the
upstream npm namespace. The upstream registry-publish step is disabled for this
repository. No npm registry credentials are needed.

After the owner merges the release changes, create a tag such as
`stigen-v1.17.0-stigen.1` at the reviewed commit on main. The workflow rejects tags
whose commit is not in main history or whose upstream version does not equal
`package.json.version`. These checks do not replace repository access controls:
restrict write access to trusted maintainers and retain owner-reviewed merges.
The release workflow runs the full
suite, audits production dependencies, builds an `@stigenai/saml20` tarball,
smoke-tests the packed module, and publishes its checksum and GitHub provenance.
Pull requests run the same package checks without publishing or attesting.

The privileged release job uses the `stigen-release` environment. Its server-side
policy permits only `stigen-v*` tags, requires approval from the owner account
`zach-source`, and disables administrator bypass. Self-review is allowed because
the owner may also create the tag. The agent must not approve the environment on
the owner's behalf. Before approving, verify the tag commit, source version,
package test results, and workflow diff. This gate protects this workflow; it is
not a substitute for restricting repository writers or protecting workflow source
against direct edits.

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
