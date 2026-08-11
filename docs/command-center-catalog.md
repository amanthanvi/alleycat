# Command-center Host catalog

Remora Link owns the durable command-center hierarchy. The initial schema is
implemented in `remora_bridge_core::command_center`; the Host persists it as:

- `command-center-v1.json`: atomically replaced canonical snapshot.
- `command-center-v1.journal.jsonl`: checksum-verified recovery entries,
  compacted after 4 MiB.
- `command-center-v1.lock`: exclusive mutation lock.

All files are owner-only on Unix. The containing state directory is mode 0700.
Every durable identity is 16 random bytes encoded as 22 unpadded base64url
characters. Paths, display labels, provider names, and model names are never
identities.

## Commit and recovery order

1. Clone the current in-memory catalog.
2. Apply one mutation and increment the generation exactly once.
3. Validate bounds, references, identity, and immutable Thread runtime fields.
4. Append and fsync a full checksum-protected recovery entry.
5. Write and fsync a temporary canonical snapshot.
6. Rename the snapshot atomically and fsync its parent directory.
7. Publish the new in-memory state.

Startup compares the canonical snapshot with all checksum-valid recovery
entries. A newer journal generation repairs an older snapshot, covering a
crash between steps 4 and 6. A corrupt snapshot is repaired from the newest
valid journal entry. If neither source validates, Link fails closed instead of
silently replacing owner work state.

The local `status` response exposes only the opaque Host ID and catalog
generation. It never exposes Projects, roots, Threads, Turns, checkpoints, or
provider-session data. Remote catalog reads and mutations remain unavailable
until their progressive Link grants and bounded wire operations land.
