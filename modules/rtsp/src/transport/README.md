# Encrypted TCP transport

`Transport` owns a nonblocking TCP listener, bounded connections, and ticket crypto
state. The module controller authorizes tickets and routes authenticated requests;
network data never chooses a broker principal. There is no plaintext mode.

The API is `bind(address, allow_remote)`, `local_addr()`, `add_ticket(id, peer_ip,
key)`, `remove_ticket(id)`, `poll(now_ms)`, and `reply(connection, plaintext)`.
Replies must already be serialized by the RTSP serializer. `poll` returns owned
`Request {connection,ticket,request}` or `Disconnected {connection,ticket,reason}`
events. The controller cancels pending work when its connection disappears.
`response_complete` means all encrypted bytes were accepted locally by TCP, not
that the peer processed them. Removal closes authenticated connections immediately
and returns their disconnect events; unassociated sockets remain bounded by their
read deadline and cannot authenticate against the removed ticket.

One encrypted envelope must contain exactly one RTSP request, without trailing
bytes. One response is encrypted and the connection closes after flushing it. This
matches the primary Moonlight TCP transaction behavior: `RtspConnection.c`
`transactRtspMessageTcp()` opens a connection for each transaction and reads until
server EOF. Reference checkout: `moonlight-common-c` commit
`874ac9548f1bd6f095ef2b435c42cdde460e7821`, inspected locally. The implementation is
original Rust using the existing tested GameStream codecs, not translated C.

Ticket selection checks the remote IP and then authenticates against at most two
live candidates. A failed decryption does not consume replay state. Opener replay
windows and response sealers live on tickets, so changing TCP connections cannot
reset either sequence. Ticket IDs and keys cannot be reused after removal; the
module retains bounded history for 128 allocations. Historical raw keys are kept
in private memory solely for equality checks until transport drop and never appear
in debug output, events or errors. Restart requires the controller to provision
fresh keys; history is intentionally not a durable key-management facility.

Bounds are 16 connections total, 8 per IP, 4 accepts per tick, and 16 KiB of read or
write work per connection per tick. Header/body limits come from the RTSP codec
(16 KiB headers,64 KiB body). Each connection retains one bounded envelope or one
bounded encrypted response. Reads and writes have absolute 10-second deadlines;
router work has 15 seconds. Input does not refresh a deadline. Poll time is monotonic
and backwards values cannot extend connections. Loopback is the default policy;
nonloopback listening and peer tickets require explicit `allow_remote`.

Framing/authentication failures close silently; no plaintext error or fallback is
sent. Additional input while awaiting a reply cancels the transaction. Half-close
is treated as disconnect rather than supporting a half-closed request protocol.
No detached workers, socket threads, compression, or application negotiation live
here.

Tests use real loopback TCP and tested Rust cryptography to cover split writes,
same-IP candidate selection, malformed/plaintext input, replay across connections,
shared response sequences, duplicate reply admission, disconnect/revocation,
connection floods, deadlines, and key-history limits. This layer alone does not
qualify a complete Moonlight session; signed integration and negotiation are
separate checks.
