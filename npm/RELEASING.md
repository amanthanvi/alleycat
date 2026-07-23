# Remora Link npm releases

The `Remora Link release` workflow builds five native targets from one tag and
one locked source tree, runs each native CLI on a matching GitHub-hosted
architecture, generates SPDX SBOMs and GitHub attestations, publishes the
native packages first, and publishes the zero-dependency launcher last.

## One-time trusted-publishing bootstrap

The package owner must first reserve and publish these public packages using a
2FA-protected maintainer account:

- `remora-link`
- `@remora/link-darwin-arm64`
- `@remora/link-darwin-x64`
- `@remora/link-linux-arm64-gnu`
- `@remora/link-linux-x64-gnu`
- `@remora/link-win32-x64-msvc`

Use a distinct placeholder version such as `0.0.0` for that one-time manual
reservation, built from temporary package copies. Do not manually publish the
first automated release version or modify the reviewed release manifests just
for reservation; registry integrity checks will correctly reject different
bytes under an already-used version.

For every package, configure npm's GitHub Actions trusted publisher with:

- owner: `amanthanvi`
- repository: `remora-link`
- workflow: `remora-link-release.yml`
- environment: `npm`
- allowed action: `npm publish`

Protect the GitHub `npm` environment with required review. Once an OIDC
release succeeds and provenance is visible on npm, disallow token-based
publication and revoke any temporary bootstrap token. The workflow does not
contain or consume an npm write token.

## Cutting a release

1. Update `crates/remora-link`'s version, the launcher version, every platform
   package version, and every exact optional dependency together. Leave the
   Remora workspace version independent.
2. Run:

   ```sh
   cargo test --locked -p remora-link
   BRIDGE_CONFORMANCE_SKIP_UPSTREAM_SCHEMA=1 cargo test --locked --workspace
   node --test npm/test/*.test.mjs
   node npm/scripts/verify-packages.mjs
   ```

   The workspace command is deliberately the no-external-schema gate. Run the
   schema-present gate separately against the exact Codex revision pinned by
   the release workflow:

   ```sh
   CODEX_SCHEMA_REV=13595c36e218fcbd13df118eeadf00d4eb0e6d31
   : "${CODEX_CHECKOUT:?set CODEX_CHECKOUT to an exact openai/codex checkout}"
   test "$(git -C "$CODEX_CHECKOUT" rev-parse HEAD)" = "$CODEX_SCHEMA_REV"
   BRIDGE_CONFORMANCE_CODEX_SCHEMA_DIR="$CODEX_CHECKOUT/codex-rs/app-server-protocol/schema/json/v2" \
     cargo test --locked --package remora-bridge-conformance
   ```

   `CODEX_CHECKOUT` must be an exact checkout of `openai/codex`, not a moving
   branch. Bump the workflow pin and this command together after reviewing
   upstream schema changes.

3. Merge through normal review and green locked builds.
4. Create the protected tag `remora-link-vX.Y.Z` at the reviewed commit.
5. Approve the protected `npm` environment only after the five build jobs and
   their native smoke tests pass.
6. Verify npm provenance, the GitHub release checksums, SBOMs, and attestations.

`SHA256SUMS` names and hashes the downloadable tarball, SBOM, and nested
checksum assets directly. `BINARIES_SHA256SUMS` separately records the native
binary paths and hashes inside the platform tarballs.

Published npm versions are immutable. A partial run may be resumed by
re-running the same workflow only when every rebuilt tarball has the same
SHA-512 SRI as any package already in the registry. Existing GitHub release
assets are also downloaded and compared byte-for-byte; they are never
clobbered. A mismatch fails closed and requires recovery from the original
attested artifacts or a new version. Native packages are always completed
before the launcher is published. Never replace a tarball or reuse a version.

The workflow's Sigstore/npm provenance is not an Apple notarization ticket or
a Windows Authenticode signature. Do not claim signed production binaries
until the corresponding protected signing identities and verification steps
are configured.
