# Remora Link maintenance policy

## Ownership boundary

Remora Link owns the host product identity, release pipeline, secure pairing
extensions, and Remora-specific integration seams. Alleycat remains the
upstream transport and harness bridge. Remora Link wraps `alleycat::App`; it
does not duplicate Alleycat's harness discovery, process supervision, or wire
translation.

Harnesses are always user-installed. The host may resolve an explicitly
configured absolute executable or a trusted executable already on the user's
launch path, probe its version and capabilities, and launch it with an argv
array. It must never run `npm`, `npx`, `brew`, `cargo install`, a curl-to-shell
installer, or another package-manager fallback on a user's behalf.

## Upstream-first, 30-day patch window

For a generally useful Alleycat bug fix or hardening change:

1. Reproduce it in the maintenance fork and prepare focused tests.
2. Open an upstream issue or pull request before carrying a divergent patch.
3. Give upstream 30 calendar days to merge it, request changes, or state that
   it is out of scope.
4. If the issue still materially blocks Remora after that window, the fork may
   land the smallest tested patch. Its commit or pull request must link the
   upstream discussion, record the window's start date, and state removal
   criteria.
5. Remove or reconcile the fork patch promptly after upstream ships an
   equivalent fix.

Remora-specific product behavior does not need an upstream waiting period.
Actively exploited vulnerabilities may be patched immediately while following
coordinated-disclosure and embargo requirements; the security exception must
not disclose private vulnerability details in a public issue.

The `Upstream sync` GitHub workflow fetches `dnakov/alleycat`, creates or
updates a review branch, and opens a pull request. It never enables auto-merge
or mutates the protected default branch. Every sync receives normal review and
locked-build validation before merge. Repository owners must enable **Allow
GitHub Actions to create and approve pull requests** in Actions settings so the
workflow can open the review PR. Keep Actions-created PRs subject to required
human review and explicitly approve any repository-policy-gated workflow runs;
the sync workflow runs the locked Rust workspace and npm launcher tests at the
exact merge commit in a separate read-only job, then records that result on the
review PR. That workspace gate explicitly sets
`BRIDGE_CONFORMANCE_SKIP_UPSTREAM_SCHEMA=1`; a second read-only job checks the
conformance crate against the exact `openai/codex` schema revision
`13595c36e218fcbd13df118eeadf00d4eb0e6d31`. This makes a missing external
checkout explicit without silently losing schema drift coverage. Unreviewed
upstream code never executes in a write-capable job.

## Relay provider seam

The transport-facing provider contract is intentionally narrower than the
host daemon:

- `connect`: supply the relay URLs and discovery inputs needed to establish an
  authenticated Iroh endpoint;
- `observe`: report connection state and durable event cursors without
  exposing prompts, transcripts, credentials, or approval contents;
- `publish_hint`: emit an opaque, idempotent wake hint keyed by host/device and
  monotonic sequence; hints are never canonical state;
- `shutdown`: drain bounded in-flight work and close provider resources.

The default public provider is N0/Iroh discovery and relay infrastructure. A
self-hosted provider implements the same contract by supplying operator-owned
Iroh relay/discovery URLs and, when background awareness is enabled, its own
opaque wake service. Pairing, device grants, event ordering, and Rust-owned
reconciliation remain provider-independent. Provider choice must not fork the
mobile or harness protocol.

The seam is documented here until a typed provider interface is introduced in
Alleycat core. That future interface belongs beside endpoint construction; it
must not leak into individual harness bridges.
