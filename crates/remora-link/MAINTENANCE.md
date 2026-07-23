# Remora Link maintenance policy

## Ownership boundary

Remora Link owns the host product identity, release pipeline, secure pairing,
transport, harness bridges, and integration seams. The canonical command wraps
`remora_host::App`; harness discovery, process supervision, and wire
translation remain in the same reviewed workspace.

Harnesses are always user-installed. The host may resolve an explicitly
configured absolute executable or a trusted executable already on the user's
launch path, probe its version and capabilities, and launch it with an argv
array. It must never run `npm`, `npx`, `brew`, `cargo install`, a curl-to-shell
installer, or another package-manager fallback on a user's behalf.

## Continuous integration boundary

The `Remora Link CI` workflow gates pull requests and default-branch pushes on
the locked, frozen Rust workspace, npm launcher tests, package-graph checks,
formatting, pinned Codex schema conformance, and native Linux, macOS, and
Windows compilation. Live external harness tests stay opt-in; CI compiles their
targets but does not launch user-installed agents.

Clippy denies warnings across the full workspace and all targets. Every bridge
package is also covered by locked, frozen workspace tests and all-target
compile jobs.

## Relay provider seam

The transport-facing provider contract is intentionally narrower than the host
daemon:

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
Remora core. That future interface belongs beside endpoint construction; it
must not leak into individual harness bridges.
