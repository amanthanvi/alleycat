# Remora Link v2 wire contract

Status: implementation contract for the Rust host and mobile client

Protocol version: `2`

ALPN: `remora-link/2`

This document describes the byte-level contract implemented by Remora Link. It
is intentionally narrower than the security architecture that motivated it:
manual locator codes, SPAKE2, grant delegation, peer administration, recovery,
and device-key rotation are not part of this version.

Any ALPN other than `remora-link/2` and any payload from an earlier protocol
version is unsupported and rejected. Clients must never retry another protocol
after a v2 failure.

V2 does not send a portable bearer or signed grant object to the client. The
host-local device record is authoritative; the client retains only the public
credential ID, its non-exportable key reference, host identity, policy summary,
and crash-recovery journal. Authorization always comes from a fresh P-256 proof.
This version therefore uses DER ECDSA proof signatures rather than a COSE/CBOR
grant envelope.

## Transport and framing

The client connects to the invitation's pinned Iroh endpoint with the exact
ALPN `remora-link/2`. Relay URLs and direct addresses are route hints; they do
not replace the pinned endpoint identity. Enrollment and routine operations run
only after the full Iroh handshake.

Each control message is one UTF-8 JSON document framed as:

```text
u32be json_length
json_length bytes of JSON
```

There is no delimiter after the JSON. Every v2 input and output control frame
is limited to 65,536 bytes. The receiver rejects an oversized length before
allocating or reading its body. Request and proof types reject unknown JSON
fields.

One client-initiated bidirectional stream carries exactly this exchange:

```text
client                              host
  RequestV2 ------------------------>
         <--------------------------- ResponseV2 { challenge }
  ProofV2 -------------------------->
         <--------------------------- terminal ResponseV2
```

For `connect`, the terminal response contains `session`; after that response,
the same stream becomes the selected runtime's byte stream. All other
operations finish after the terminal response.

## Scalar encodings

- Binary values in JSON use unpadded URL-safe base64 (`A-Z a-z 0-9 - _`).
- `invitation_id`, `claim_id`, and `challenge_id` are generated from 16 random
  bytes and therefore encode to 22 characters.
- `credential_id` is an opaque 22-character base64url value derived by the host
  from a 128-bit truncated prospective-credential digest. It is stable for
  exact retries of one invitation, endpoint, device key, and enrollment
  idempotency key, but clients must not interpret it.
- Invitation secrets are 32 random bytes encoded as 43 base64url characters.
- Client and server nonces are 32 random bytes encoded as 43 base64url
  characters.
- Device public keys are 65-byte uncompressed SEC1 P-256 points
  (`0x04 || X[32] || Y[32]`) encoded as base64url.
- Proof signatures are ASN.1 DER ECDSA signatures encoded as base64url. The
  signature algorithm is P-256 ECDSA with SHA-256.
- Timestamps are signed Unix seconds. Epochs, command sequences, and session
  sequence cursors are unsigned 64-bit JSON integers.
- Idempotency keys are opaque non-empty strings of at most 128 UTF-8 bytes with
  no control characters. Clients should generate at least 128 random bits and
  must persist the key until the operation settles.

## Closed policy types

The only accepted scope strings are:

| JSON value | Authority |
| --- | --- |
| `inspect_runtimes` | List the grant's allowed runtimes and read bounded Host/provider capability status. |
| `connect_runtime` | Attach to a runtime named in the grant. |
| `restart_runtime` | Restart a runtime named in the grant. |
| `self_revoke` | Revoke or roll back this credential with a fresh proof. |

Runtime authority is the intersection of the invitation ceiling, the client's
selection, and the local host approval. Runtime IDs are case-sensitive and
contain 1–64 bytes from `[A-Za-z0-9._/-]`. A request may contain at most 16
runtime IDs. Every runtime and scope array on the wire must already be sorted
in canonical order and contain no duplicate. Unknown scopes, non-canonical
arrays, and runtimes outside the grant fail closed.

The canonical scope order is:

```text
inspect_runtimes
connect_runtime
restart_runtime
self_revoke
```

Every usable grant contains at least one runtime plus `connect_runtime` and
`self_revoke`; host narrowing cannot remove either required scope. The default
interactive invitation grants no authority by itself. Its ceiling
is selected runtimes plus `inspect_runtimes`, `connect_runtime`,
`self_revoke`, and optionally `restart_runtime`. The host must confirm the
device label, requested policy, and six-character SAS, and may only narrow the
request.

`unattended` is an explicit weaker mode. It is limited to exactly one runtime,
exactly `inspect_runtimes`, `connect_runtime`, and `self_revoke`, has no restart
authority, and expires within 60 seconds. Interactive invitations expire
within 300 seconds.

## Pairing-code envelope

The QR/copy representation is:

```text
remora-link:v2:<base64url(JSON PairingInvitation)>
```

The encoded segment is limited to 4,096 bytes. JSON rejects unknown fields:

```json
{
  "v": 2,
  "node_id": "<Iroh endpoint public key>",
  "invitation_id": "<16 random bytes, base64url>",
  "secret": "<32 random bytes, base64url>",
  "expires_at": 1770000000,
  "max_runtime_ids": ["codex"],
  "max_scopes": [
    "inspect_runtimes",
    "connect_runtime",
    "self_revoke"
  ],
  "confirmation_mode": "interactive",
  "host_name": "Optional display-only host label",
  "relay": "https://optional-valid-iroh-relay.example"
}
```

`host_name` and `relay` are omitted when absent. The client pins `node_id`, not
either display field. The host enforces expiry and policy from its durable
record. The envelope timestamp and policy are hints until a proof-bound
`inspect_invitation` returns the authoritative values; the client must reject a
mismatch rather than widening from the envelope.

Pairing-code decoding validates the timestamp's type but deliberately does not
compare `expires_at` with the phone's local clock. Clock skew therefore cannot
reject an otherwise live invitation. Only the host decides whether the invite
has expired during proof-bound inspection or enrollment; the phone uses the
returned host-authoritative expiry for display and scheduling.

The host base64url-decodes the secret and persists a domain-separated SHA-256
digest of those 32 raw bytes, not the raw secret. The raw secret must not enter
logs, errors, snapshots, or crash metadata.

## Request frames

Every request contains `v: 2` and a fresh base64url 32-byte `client_nonce`.
Every operation, including invitation inspection, requires a P-256 proof.

### `inspect_invitation`

Authenticates knowledge of the invitation and possession of the proposed
device key without reserving or consuming the invitation.

```json
{
  "op": "inspect_invitation",
  "v": 2,
  "invitation_id": "<id>",
  "secret": "<invite secret>",
  "device_public_key": "<SEC1 P-256 public key>",
  "client_nonce": "<32 random bytes>"
}
```

The terminal response contains `inspection` with `invitation_id`,
`expires_at`, `max_runtime_ids`, `max_scopes`, `confirmation_mode`, and
`runtime_offers`. Offers have this display-safe typed shape:

```json
{
  "runtime_id": "codex",
  "display_name": "Codex",
  "available": true,
  "recommended": true
}
```

The host filters offers to the invitation's precommitted runtime ceiling. It
never exposes an installed runtime outside `max_runtime_ids`. The current host
marks an available `codex` runtime as recommended; recommendation is a UI hint,
not authority. A configured but temporarily unavailable allowed runtime remains
in the list with `available: false`; an allowed ID with no host manifest may be
absent. In both cases `max_runtime_ids` remains the policy ceiling.

### `enroll`

Claims an invitation and either enters host confirmation or commits a narrowly
scoped unattended grant.

```json
{
  "op": "enroll",
  "v": 2,
  "invitation_id": "<id>",
  "secret": "<invite secret>",
  "device_name": "Aman's iPhone",
  "device_public_key": "<SEC1 P-256 public key>",
  "selected_runtime_ids": ["codex"],
  "requested_scopes": [
    "inspect_runtimes",
    "connect_runtime",
    "self_revoke"
  ],
  "idempotency_key": "<stable enrollment operation id>",
  "client_nonce": "<32 random bytes>"
}
```

`device_name` is limited to 80 UTF-8 bytes and may not contain control
characters. The host trims surrounding whitespace for display; an empty or
whitespace-only result becomes `Remora device`. The untrimmed wire value is the
value bound into the proof and idempotency fingerprint.

An interactive first claim returns `pending`. The client then repeats the exact
enrollment operation with the same idempotency key and policy, but a fresh
challenge and nonce, until it receives `enrolled` or a terminal generic error.
An unattended first claim returns `enrolled` after the grant is durable.

### `list_agents`

```json
{
  "op": "list_agents",
  "v": 2,
  "credential_id": "<credential id>",
  "client_nonce": "<32 random bytes>"
}
```

Requires `inspect_runtimes`. The host filters `agents` to the grant's runtime
allowlist.

### `command_center_status`

```json
{
  "op": "command_center_status",
  "v": 2,
  "credential_id": "<credential id>",
  "client_nonce": "<32 random bytes>"
}
```

Requires `inspect_runtimes`. The response contains only the opaque Host ID,
catalog generation, typed Host capability availability, and bounded provider
instance readiness/models/capabilities. Its serialized payload is limited to
512 KiB at catalog ingress. It never includes Projects, paths, Working Copies,
Threads, Turns, scripts, browser state, prompts, transcripts, or credentials;
those require separate workspace contracts and grants.

### `restart_agent`

```json
{
  "op": "restart_agent",
  "v": 2,
  "credential_id": "<credential id>",
  "client_nonce": "<32 random bytes>",
  "agent": "codex",
  "idempotency_key": "<stable restart operation id>",
  "command_sequence": 1
}
```

Requires `restart_runtime` and an exact allowlisted runtime ID. The host
durably prepares the idempotency key and sequence before dispatching the
restart. Sequence numbering is per credential: the first new command is `1`,
and each later new command must be exactly the durable high watermark plus one.
Zero and gaps fail. Runtime unavailability rejects a new command before the
high watermark advances.

The host marks the operation succeeded durably before returning success. An
exact retained replay of a succeeded operation returns the same logical result.
A retained replay that finds only the prepared record returns
`outcome_unknown` and never dispatches again; this conservatively covers a
crash between preparation, dispatch, and the durable success record. The host
keeps the most recent 256 restart records plus a non-decreasing high watermark.
Any older/pruned sequence at or below that watermark also returns
`outcome_unknown` without execution. A runtime becoming unavailable does not
hide a retained replay result.

Runtime restart dispatch is observed for at most five seconds. A timeout or
runtime error after durable preparation returns `outcome_unknown`, because the
host cannot safely infer that no side effect occurred.

### `connect`

```json
{
  "op": "connect",
  "v": 2,
  "credential_id": "<credential id>",
  "client_nonce": "<32 random bytes>",
  "agent": "codex",
  "resume": { "last_seq": 42 }
}
```

Requires `connect_runtime` and an exact allowlisted runtime ID. `resume` is
optional and omitted for a fresh attachment. The host holds the credential's
connect-start fence through session resolution, the `session` response write,
lazy runtime startup, and attachment installation. That setup has a ten-second
deadline; on timeout the host closes the Iroh connection rather than admitting
an unfenced late attachment.

### `revoke_self`

```json
{
  "op": "revoke_self",
  "v": 2,
  "credential_id": "<credential id>",
  "client_nonce": "<32 random bytes>",
  "idempotency_key": "<stable revoke operation id>"
}
```

Requires `self_revoke`. The durable mutation increments the grant epoch, marks
the grant revoked, and persists its receipt first. The host then closes the
credential's other registered Iroh connections, writes and finishes the
`revocation` response on the requesting connection, waits at most one second
for the peer to acknowledge the finished send stream, and finally closes that
connection too. A transport close immediately after the complete receipt frame
is therefore expected. If the frame is lost, an exact proof-bound retry with
the same key returns the durable receipt without repeating the mutation.

### `rollback_enrollment`

```json
{
  "op": "rollback_enrollment",
  "v": 2,
  "credential_id": "<credential id returned by enrollment>",
  "enrollment_idempotency_key": "<original enrollment operation id>",
  "client_nonce": "<32 random bytes>",
  "idempotency_key": "<stable rollback operation id>"
}
```

This compensates for a client-side secure-store failure. It rolls back the
pending claim or revokes the committed grant only when the original enrollment
idempotency key matches. It returns the same `revocation` receipt on an exact
retry. When it revokes an already committed grant, it uses the same
receipt-flush-then-close sequence as `revoke_self`.

## Challenge and proof

The host's first response is:

```json
{
  "v": 2,
  "ok": true,
  "challenge": {
    "challenge_id": "<16 random bytes>",
    "credential_id": "<credential or pending credential id>",
    "auth_epoch": 0,
    "server_nonce": "<32 random bytes>",
    "expires_at": 1770000030
  }
}
```

Challenges expire after 30 seconds. For invitation inspection,
`credential_id` is the invitation ID and `auth_epoch` is zero. Enrollment uses
the pending credential ID (stable for an idempotent retry). Routine operations
use the grant's current epoch.

For a new `enroll` request, the prospective credential ID is independent of
invitation lookup state:

```text
material = "remora-link/2/prospective-credential/v2"
         || field(invitation_id UTF-8)
         || field(authenticated_client_endpoint_id UTF-8)
         || field(device_public_key base64url text)
         || field(enrollment_idempotency_key UTF-8)
credential_id = base64url_no_pad(SHA-256(material)[0..16])
```

This makes exact challenge retries stable without revealing, through the
challenge ID, whether an attacker-supplied invitation ID exists. The invitation
secret is still verified after the proof; the prospective ID grants no
authority.

The client answers:

```json
{
  "v": 2,
  "challenge_id": "<exact challenge id>",
  "signature": "<base64url ASN.1 DER P-256 ECDSA signature>"
}
```

The signature is over the proof transcript below. The invite secret is absent
from routine operations. Both Iroh endpoint IDs come from the completed
transport, not from client-authored JSON.

## Canonical proof transcript

All transcript integers use network byte order. `field(x)` means:

```text
u32be(len(x)) || x
```

The signed byte string is the raw domain followed by these fields, with no
terminator:

```text
"remora-link/2/proof/v2"
field(u32be(2))
field("remora-link/2")
field(host_iroh_endpoint_id UTF-8)
field(client_iroh_endpoint_id UTF-8)
field(operation UTF-8)
field(credential_id UTF-8)
field(u64be(auth_epoch))
field(SHA-256(uncompressed SEC1 device public key))
field(challenge_id UTF-8)
field(server_nonce base64url text)
field(client_nonce base64url text)
field(operation_payload_hash[32])
```

The exact operation strings are `inspect_invitation`, `enroll`, `list_agents`,
`command_center_status`, `restart_agent`, `connect`, `revoke_self`, and
`rollback_enrollment`.

### Operation payload hash

`operation_payload_hash` is SHA-256 of the raw domain
`remora-link/2/payload/v2` followed by a `field(...)` for each UTF-8 value in
this table:

| Operation | Fields in order |
| --- | --- |
| `inspect_invitation` | invitation ID, invitation secret, device public key |
| `enroll` | invitation ID, secret, device name, public key, canonical runtime list, canonical scope list, enrollment idempotency key |
| `list_agents` | no fields |
| `command_center_status` | no fields |
| `restart_agent` | runtime ID, restart idempotency key, decimal command sequence |
| `connect` | runtime ID, decimal `last_seq` or empty string |
| `revoke_self` | revoke idempotency key |
| `rollback_enrollment` | original enrollment idempotency key, rollback idempotency key |

Canonical lists are sorted, deduplicated values joined by one NUL byte, with no
leading or trailing NUL.

## Enrollment confirmation transcript and SAS

The confirmation transcript hash is SHA-256 of the raw domain
`remora-link/2/enrollment/v2` followed by length-delimited fields:

```text
field(u32be(2))
field("remora-link/2")
field(host_iroh_endpoint_id UTF-8)
field(client_iroh_endpoint_id UTF-8)
field(invitation_id UTF-8)
field(enrollment_idempotency_key UTF-8; the redemption ID)
field(server_nonce base64url text)
field(client_nonce base64url text)
field(uncompressed SEC1 device public key[65])
field(canonical selected runtime list UTF-8)
field(canonical requested scope list UTF-8)
field(host_policy_digest[32])
field(confirmation mode byte: interactive=0, unattended=1)
```

`host_policy_digest` is SHA-256 of the raw domain
`remora-link/2/policy/v2`, then `field(canonical invitation-maximum runtime
list UTF-8)`, then `field(canonical invitation-maximum scope list UTF-8)`.
This binds the SAS to the host's full invitation ceiling without introducing
two variable-length policy fields into the outer confirmation transcript.

The SAS uses the top 30 bits of the HMAC and six Crockford Base32 characters:

```text
digest = HMAC-SHA-256(invitation_secret,
                     "remora-link/2/sas/v2" || confirmation_transcript_hash)
value = u32be(digest[0..4]) >> 2
alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
code = six 5-bit groups from value, most-significant group first
sas = code[0..3] || "-" || code[3..6]
```

Here `invitation_secret` means the 32 decoded random bytes, not their base64url
text. The first accepted claim's nonces remain part of the persisted
confirmation transcript. An exact enrollment replay uses a fresh proof
challenge but returns that original durable SAS and claim.

The phone and host display the same SAS, device label, selected runtimes, and
requested scopes. A matching SAS is meaningful only for this transcript and
does not authorize any operation by itself.

Both `pending` and `enrolled` carry the confirmation material from the first
accepted claim, including on an exact replay:

```json
{
  "enrollment_confirmation": {
    "transcript_hash": "<32-byte SHA-256 digest, base64url>",
    "sas": "N3N-FY1"
  }
}
```

The client durably stages the complete enrollment transcript inputs before
sending each proof. After any response loss it retains every candidate staged
under that enrollment idempotency key. The returned 256-bit hash identifies the
one attempt the host accepted; the client must reproduce both that hash and its
SAS before treating either `pending` or `enrolled` as authentic confirmation.
This remains unambiguous when several fresh-nonce attempts timed out before an
approved replay returned `enrolled`.

## Terminal responses

Every response contains `v` and `ok`. Exactly one operation-specific result is
normally present on success:

| Field | Shape and use |
| --- | --- |
| `inspection` | Invitation ID, expiry, maximum runtimes/scopes, confirmation mode, and filtered typed runtime offers. |
| `pending` | Claim ID, credential ID, display name, selected runtimes, requested scopes, enrollment confirmation, creation and expiry timestamps. |
| `enrolled` | Device ID, display name, redacted endpoint/key fingerprints, selected runtimes, granted scopes, authorization epoch, creation timestamp, and original enrollment confirmation. |
| `agents` | Existing typed `AgentInfo[]`, filtered to the credential's runtime allowlist. |
| `session` | `{attached, current_seq, floor_seq}` followed by the runtime stream. `attached` is `fresh`, `resumed`, or `drift_reload`. |
| `restart` | Runtime ID, restart idempotency key, command sequence, and `succeeded` or `outcome_unknown` status. |
| `revocation` | Credential ID, incremented authorization epoch, revocation timestamp, idempotency key. |

A completed restart returns:

```json
{
  "v": 2,
  "ok": true,
  "restart": {
    "agent": "codex",
    "idempotency_key": "restart-operation-1",
    "command_sequence": 1,
    "status": "succeeded"
  }
}
```

If the durable record proves only that dispatch was prepared, the host returns
the correlated ambiguous result without executing it again:

```json
{
  "v": 2,
  "ok": false,
  "restart": {
    "agent": "codex",
    "idempotency_key": "restart-operation-1",
    "command_sequence": 1,
    "status": "outcome_unknown"
  },
  "error_code": "outcome_unknown",
  "error": "operation outcome unknown"
}
```

`revoke_self` and `rollback_enrollment` use the same error code differently
when the mutation was applied in the current host process but parent-directory
durability could not be confirmed:

```json
{
  "v": 2,
  "ok": false,
  "revocation": {
    "credential_id": "<credential id>",
    "auth_epoch": 8,
    "revoked_at": 1770000042,
    "idempotency_key": "revoke-operation-1"
  },
  "error_code": "outcome_unknown",
  "error": "operation outcome unknown"
}
```

The host treats that credential as revoked and terminates its sessions. The
client must retain the credential and the same mutation key, reconnect, and
retry until it receives the durable `ok: true` receipt. This contrasts with a
restart `outcome_unknown`, for which automatic retry can never safely execute
again and is terminal until an operator chooses a new sequence.

Failure responses contain no secret-bearing detail:

```json
{
  "v": 2,
  "ok": false,
  "error_code": "authorization_required",
  "error": "device authorization required"
}
```

The closed error codes are `pairing_unavailable`, `authorization_required`,
`invalid_request`, `agent_unavailable`, `outcome_unknown`, and `internal`.
Enrollment failures are deliberately coarsened so unknown, expired, rejected,
already-used, wrong-secret, and conflicting claims are not remotely
distinguishable.

`enrolled.device_id`, `pending.credential_id`, challenge `credential_id`, and
the `credential_id` used by routine requests name the same host grant.

## Durable state and idempotency

The host uses store schema version 3. It does not import grants from earlier
experimental store versions; devices must re-pair. Writes use a mode-0600
temporary file, file sync, atomic rename, and parent-directory sync where the
platform supports it.

The rename is the state machine's commit point. An error before rename leaves
the previous in-memory and on-disk state authoritative. If rename succeeds but
the parent-directory sync fails, the complete new state is applied in memory
and present at the target path, but its survival across an immediate host crash
is unknown. The manager records that condition and rewrites plus resyncs the
same complete state before admitting later work; it never falls back to the
pre-commit state.

While that reconciliation still fails, operations fail closed and cannot
create a fresh side effect. Restart is deliberately allowed to verify its
device proof against the applied in-memory grant so the restart journal can
distinguish a retained command from a new one: a retained command returns its
correlated `outcome_unknown`, while a new sequence is not dispatched.
Revocation and rollback similarly return their correlated
`revocation`/`outcome_unknown` receipt after an applied-but-not-yet-confirmed
commit and close the credential's sessions. An exact retry must keep the same
operation identity; after resync succeeds it returns the durable stored result.

Invitation and enrollment transitions are:

```text
issued
  -> pending(interactive claim)
  -> approved(grant committed)

issued
  -> approved(unattended claim and grant committed)

issued | pending
  -> rejected | expired | rolled_back
```

The first valid claim reserves the invitation. A competing key, authenticated
Iroh endpoint, idempotency key, or request fingerprint receives the same generic
failure. Replaying the same enrollment key with the same fingerprint and
endpoint returns the durable pending state or enrolled record; it cannot create
a second grant. Rejection never returns an invitation to `issued`.

The host may approve only subsets of the claimed runtime IDs and scopes, while
retaining at least one runtime, `connect_runtime`, and `self_revoke`. Host
approval is durable before an enrolled result can be returned. Unattended mode
commits the claim and grant in one durable write. Issued and pending claims are
durable across daemon restart and retain their absolute host-enforced expiry;
restart never extends an invitation.

`revoke_self` and `rollback_enrollment` keep durable mutation records keyed by
credential, operation, and idempotency key. Restart records are keyed by
credential and command sequence and retain the idempotency key plus signed
request fingerprint. Reusing a retained key or sequence with a different
fingerprint fails. An exact replay returns the original succeeded or revocation
result; a prepared-only restart instead returns its durable `outcome_unknown`
result and is never automatically re-executed.

Restart additionally persists a monotonic high watermark and retains its most
recent 256 exact records. A pruned sequence can no longer prove its original
key or payload, so it returns `outcome_unknown` for any authenticated request at
or below the high watermark and never executes. New commands require the next
sequence. The sequence is the lifetime-monotonic, non-reusable at-most-once
identity; its idempotency key must remain stable and should be freshly generated
for that sequence, but the host can enforce key uniqueness only while an exact
recent record remains retained. Revocation/rollback receipts and invitation
terminal records/tombstones are retained for 90 days. Revoked device records
remain durable credential tombstones and are not converted back into reusable
IDs.

If a revocation state transition is applied but directory durability is
unknown, the host returns the correlated `outcome_unknown` receipt and closes
the credential's sessions fail-closed. An exact same-key retry reconciles that
ambiguous commit and is the only permitted automatic retry for the mutation.

Revocation changes the durable grant before closing live connections. It
increments `auth_epoch`, rejects later proofs at the old epoch, and closes only
connections registered to that credential. Host-side selective revocation is
also idempotent and follows the same epoch/connection semantics.

Runtime admission is linearized against revocation per credential. A restart
holds a short read fence from its durable prepare record through dispatch and
the durable succeeded update; revocation takes the matching write fence. A
connect holds the read fence through session resolution, response installation,
lazy runtime startup, and attachment installation, then releases it before the
long-lived stream. Consequently either revocation commits first and admission
fails, or admission becomes registered first and revocation closes it.

## Bounds

| Item | Limit |
| --- | ---: |
| v2 JSON control frame | 65,536 bytes |
| pairing-code encoded segment | 4,096 bytes |
| simultaneously nonterminal issued + pending invitations | 16 |
| invitation ID / claim ID / challenge ID | 16 random bytes; 22 base64url characters |
| credential ID | opaque truncated SHA-256 derivation; 16 bytes / 22 base64url characters |
| invitation secret | 32 random bytes |
| client/server nonce | 32 random bytes |
| host initial request-frame timeout | 10 seconds |
| challenge lifetime | 30 seconds |
| host proof-frame read timeout | 31 seconds |
| runtime restart dispatch observation | 5 seconds; timeout becomes `outcome_unknown` |
| connect admission/setup deadline | 10 seconds; timeout closes the Iroh connection |
| interactive invitation lifetime | 300 seconds |
| unattended invitation lifetime | 60 seconds |
| runtime IDs per invitation/grant | 16 |
| runtime ID | 64 bytes; ASCII `[A-Za-z0-9._/-]` only |
| device label | 80 UTF-8 bytes, no control characters |
| host label | 255 UTF-8 bytes, no control characters |
| endpoint ID text | 256 bytes |
| idempotency key | 128 UTF-8 bytes, no control characters |
| device public-key base64url text | 128 bytes |
| signature base64url text | 128 bytes |
| recent in-process client nonces per credential | 256 |
| simultaneously registered Iroh connections per credential | 8 |
| retained exact restart records per credential | most recent 256, plus durable high watermark |
| revocation/rollback receipt and invitation tombstone retention | 90 days |

## Golden vectors

The deterministic corpus is tracked at
`tests/fixtures/remora-link-v2/golden-vectors.json`. It contains the exact JSON,
payload hashes, transcript bytes, transcript hashes, SAS value, and signatures
asserted by the Rust tests. Implementations must compare bytes, not reconstructed
pretty-printed JSON.

## Mobile implementation requirements

- Parse pairing codes and all wire JSON in shared Rust, not Swift or Kotlin.
- Create one non-exportable P-256 key per host and pass only public-key bytes and
  signing operations across the platform boundary.
- Sign the transcript bytes exactly once with ECDSA/SHA-256. Do not prehash in
  the platform adapter and then invoke an API that hashes again.
- Pin the invitation's Iroh endpoint. Never infer authority from relay, route,
  host label, discovery, or QR proximity.
- Persist enrollment, revoke, and rollback idempotency keys before sending.
- On a revocation or rollback `outcome_unknown`, retain the credential and
  exact mutation key and retry that same operation until the host returns a
  durable `ok: true` receipt. Do not confuse this recoverable durability state
  with restart ambiguity.
- Atomically persist the next lifetime-monotonic restart command sequence and a
  stable, preferably fresh idempotency key before sending. Replays retain both
  values; sequence, not the key, is the non-reusable at-most-once authority.
  Treat `outcome_unknown` as a terminal state for automatic retry; only an
  explicit operator decision may issue another restart at the next sequence.
- Treat `pending` as an explicit cancellable/waiting state. Do not report
  pairing success until `enrolled` is received and the credential/journal write
  is durable.
- Before every enrollment proof, durably stage that attempt's complete
  confirmation-transcript inputs and retain all ambiguous candidates. Match the
  returned `enrollment_confirmation.transcript_hash` to exactly one locally
  recomputed hash, then recompute and compare its six-character SAS. A missing,
  ambiguous, or mismatched candidate requires rollback/re-pair, never success.
  An idempotent retry returns the original confirmation even though its proof
  challenge is fresh.
- On secure-store failure after host commit, replay `rollback_enrollment` with
  the original enrollment key and a stable rollback key.
- Reconnect and every new operation use a fresh challenge and device proof.
- Treat v1 input, unknown versions/scopes/fields, host identity changes, and v2
  negotiation failure as explicit repair or migration states. Never downgrade.
