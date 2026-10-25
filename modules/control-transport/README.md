# Encrypted control transport

`amaterasu.control-transport/1` owns a GameStream control connection independently
of the shell. It combines Rust ENet connection/reliability state with modern
Sunshine AES-GCM control envelopes and exposes borrowed plaintext through a C
interface. It does not interpret input, launch applications or coordinate media.

## Authority and configuration

Startup defaults open no sockets:

```json
{"enabled":false,"allow_remote":false,"allowed_principals":[]}
```

A trusted session coordinator needs signed control/native grants and an explicit
allowlist entry. Open accepts these strict fields:

| Field | Meaning |
| --- | --- |
| `peer_ip` | Peer address authorized by the trusted session owner |
| `peer_port` | Optional fixed source UDP port; otherwise pin the accepted CONNECT sender |
| `local_bind` | Optional local socket address; defaults to loopback port zero for local peers, otherwise an unspecified address of the same family |
| `connect_data` | Expected 32-bit ENet connection data supplied during session negotiation |
| `key_hex` | Fresh 128-bit launch key encoded as 32 hexadecimal characters |
| `ping_timeout_ms` | Optional timeout in milliseconds, 0–2147483647; defaults to 10000 |
| `operation_id` | Optional caller-scoped idempotency name, 1–128 bytes without control characters |

Non-loopback peers/binds require `allow_remote`. Unspecified, multicast,
limited-broadcast and IPv4-mapped IPv6 peers are rejected. Peer/bind families
must match. An explicitly supplied peer port must be nonzero. No public HTTP
control-open route or unauthenticated session issuer is provided.

ENet connection data is only an admission hint, **not cryptographic proof**.
The socket admits only the authorized IP and, when configured, port. A matching
CONNECT pins that endpoint for the connection; other endpoints cannot move it.
The state remains `awaiting_authentication` until a control message authenticates
with the launch key. Native sends are withheld until that proof arrives. A bad
tag or replay delivers no plaintext and does not extend the authenticated idle
clock. `ping_timeout_ms` sets both the initial authentication deadline and the
idle limit after authentication; the default is ten seconds. The selected value
is returned in stream metadata.

The trusted coordinator must derive the peer and key from authenticated session
negotiation and apply revocation/teardown. Native modules are trusted code;
API grants are not a sandbox against arbitrary native sockets or memory access.

## Lifetime and controls

`open` returns `ok`, `stream`, `local`, `peer_ip`, `peer`, `state`,
`authenticated`, `ping_timeout_ms`, `failure`, queue sizes and message/datagram
counters. Keys and connection data are not returned. States distinguish
listening, connecting, waiting for authentication, active operation and terminal
failure.

`lookup {operation_id}` returns the live owned stream's metadata.
`status {stream?:u64}` returns `{ok,enabled,streams:[...]}` scoped to the immediate
caller. Unknown or foreign IDs produce an empty status list. `close {stream}`
aborts an owned connection and releases its socket; unknown or foreign IDs return
`stream_not_found`. Close does not wait for a peer's disconnect acknowledgement.

Four streams may exist globally, two per caller. Nonzero IDs use OS randomness;
callers must preserve full 64-bit integer precision. The provider retains at most
1024 issued IDs, 128 idempotency records and 128 historical keys per lifetime.
Matching open retries return the original stream; changed parameters conflict,
and a closed operation cannot recreate sockets or encryption state. A cancelled
or undeliverable new open closes its allocation. Failed delivery of an existing
open retry does not close somebody's already active resource.

Every key may be used for only one control stream during the provider lifetime,
including after close and across owners. The bounded history retains raw keys
and private open specifications until controller destruction; they have no Debug
or response exposure. The coordinator **must provide fresh keys across provider
reloads and host restarts**. These in-memory guards do not implement durable key
issuance or revocation.

## Native message interface

`ControlTransportApi` exposes `send` and `receive` on an owned stream. A
`ControlMessage` contains a 16-bit-representable message type, channel, delivery
mode, borrowed payload and received encryption sequence. The reserved field must
be zero. Messages may carry up to 65,511 bytes, the complete representable control
payload; the encrypted envelope is at most 65,539 bytes.

The sender selects reliable, sequenced-unreliable or unsequenced delivery. ENet
negotiates up to 48 channels and MTU 1392 by default. Fragmentation, acknowledgement,
retransmission and window bounds belong to the shared
ENet peer engine in the separately pinned `amaterasu-protocol` repository. Its unsupported
compression, checksums, migration and adaptive congestion shaping are not silently
enabled by this provider.

Send admission checks the complete encrypted length before sealing. `MEDIA_BUSY`
accepts nothing and consumes no nonce. Success means locally queued, not an
acknowledgement. Unexpected failure after sealing fails the stream instead of
rewinding cryptographic state. Send ignores the caller's sequence field; the
provider always chooses its own monotonically increasing encryption sequence.

Receive calls the supplied sink at most once with authenticated plaintext.
Rejection retains identical bytes and metadata for retry. The provider copies
accepted outgoing bytes and retains incoming allocations; ownership never crosses
the ABI. Reentrant calls return busy. Bound interfaces must be released before
provider code unloads through signed dependency ordering.

The authenticated inner type and body establish message meaning. ENet channel
and delivery headers are **outside the GCM authentication**; consumers must not
use them as an authorization boundary. One 65,536-sequence replay window is
shared across all incoming channels so a duplicate cannot move between channels.
Expired sequences are rejected; the window does not promise arbitrarily delayed
reliable delivery. Legacy NVIDIA control encryption is explicitly unsupported.

## Bounds and failure behavior

The plaintext receive queue holds at most 256 messages and 1 MiB. Exhaustion
fails visibly and discards queued plaintext, rather than silently dropping a
reliable input event. The peer engine independently bounds pending fragments,
reliable messages, wire datagrams and events. Each module tick reads at most 32
UDP datagrams per stream and attempts at most 64 writes across its two flushes.
There are no detached workers or arbitrary destination redirects.

Socket backpressure retains the exact unsent ciphertext. Datagram parsing errors,
wrong endpoints and failed authentication are rejected without delivery. Fatal
socket errors, peer timeouts/disconnect, queue overflow and expired authentication
release the socket and expose a terminal failure code. Windows delayed ICMP and
oversized-datagram receive errors do not bypass sender policy or become proof of
peer failure; authenticated deadlines still bound their resource lifetime.

Tests exercise authority, cancellation, poisoned-lock teardown, key/idempotency
history, packet rejection, native sink retry and queue/deadline bounds. The signed
integration used the original pinned C ENet client and independent Python GCM for
exact 0-, 2,000- and 65,511-byte round trips. That historical oracle lives in
the host integration source; it is not included in this standalone repository.

This verifies an encrypted control component, not a complete Moonlight session.
Authenticated launch/RTSP orchestration, actual input dispatch, IDR/feedback
routing, congestion/pacing integration, reconnect policy and target-system
runtime qualification remain required.
