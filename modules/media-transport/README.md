# Media UDP transport

`amaterasu.media-transport/1` is an independently signed native provider for
bounded GameStream video/audio UDP delivery. It accepts complete encoded media
through `MediaTransportApi`; JSON carries controls and negotiated metadata only.
A successful submit means queued locally, not received or decoded by a peer.

## Authority and defaults

Settings default to:

```json
{"enabled":false,"allow_remote":false,"allowed_principals":[]}
```

Disabled startup opens no sockets. A runtime caller needs both its signed
service/native-use grants and an `allowed_principals` entry to open streams.
Read-only status returns only that caller's streams, including an empty list
when disabled. The native factory binds ownership to the runtime-provided
principal; a guessed stream ID does not authorize submission or teardown.

The allowlisted caller is responsible for deriving `peer_ip` and either fixed
destination ports or fresh discovery payloads from an authenticated streaming
session. This module cannot establish that provenance from an IP address. There
is no public HTTP route, unauthenticated destination selection, or automatic
launch/session policy. Native modules are trusted code: grants are not a
sandbox against arbitrary native socket calls.

Without `allow_remote`, peers and explicit local binds must be loopback. Remote
operation requires explicit startup opt-in. Unspecified, multicast, IPv4-mapped IPv6, and IPv4
limited-broadcast peers are rejected. Fixed ports must be nonzero. Default local
binds are loopback port zero for loopback peers, otherwise an unspecified
address of the peer's family so the OS selects a route. Explicit binds must
match that family. Each stream owns separate nonblocking audio/video sockets.

## Control contract

The action and all fields are strict. Open fields:

| Field | Meaning |
| --- | --- |
| `peer_ip` | Authenticated peer IP supplied by the trusted session owner |
| `video_port`, `audio_port` | Fixed destination UDP ports, 1–65535; both omitted for discovery |
| `discovery` | Optional `{video_ping_payload,audio_ping_payload}`; both are distinct 16-character unpadded base64url strings |
| `video_bind`, `audio_bind` | Optional local socket addresses, normally port zero |
| `video` | Optional `{codec:"h264",packet_size:1024,fec_percentage:20,min_parity_shards:2,max_fec_blocks:1,max_batch_size_kb:64}`; `codecs:["h264","hevc","av1"]` replaces `codec` with an offer that the first video packet resolves |
| `audio` | Required `{packet_ms:5\|10,channels:2,wire_payload_bytes:N,ssrc:0}`; `ssrc` defaults to zero |
| `stream_audio` | Optional boolean, defaults to `true`; `false` keeps the negotiated audio lane but rejects audio payloads while accepting its EOS marker |
| `ping_timeout_ms` | Optional discovery timeout in milliseconds, 0–2147483647; defaults to 10000 |
| `encryption` | Optional `{key_hex:32 hexadecimal characters,key_id:u32,video:bool,audio:bool,permit_legacy_audio_iv_wrap:false}` |
| `operation_id` | Optional caller-scoped idempotency key, 1–128 bytes without control characters |

`video.packet_size` follows the packetizer's NV-header-plus-payload convention,
with another 16 RTP bytes and, when encrypted, 32 encryption-prefix bytes.
FEC settings are validated by the shared packetizer; `max_fec_blocks:1` is the
safe legacy default. A negotiated modern client may explicitly select up to
four blocks. FEC-disabled configurations must satisfy the packetizer's own
zero-parity requirements. Audio uses the established stereo 48 kHz 4-data/2-parity
profile. Surround and alternative channel mappings are unsupported.

`video.max_batch_size_kb` defaults to 64 and accepts integer values from 0 to
64. Zero means automatic and resolves to 64 KiB. The supported explicit values
are 16, 32, and 64; another in-range value resolves to 64 KiB and is reported as
`video_batch_size_fallback:true` in open, lookup, and status metadata. Values
above 64 fail with `invalid_video_configuration`. The effective value is
returned as `video.max_batch_size_kb`.

`wire_payload_bytes` is the constant audio data-shard length, excluding RTP,
and must be 1–1275 for plaintext or a multiple of 16 between 16 and 1280
for CBC. For plaintext it equals the complete CBR Opus packet length.
For CBC it is `(plaintext_length / 16 + 1) * 16`, including PKCS7 padding.
For example, the baseline encoder's stereo 128 kbps, 10 ms CBR packet is 160
bytes and encrypts to 176 bytes. The encoder reports actual `packet_bytes`;
consumers must use that value instead of assuming all codec modes have the same
length. Variable length input is rejected before encryption. Arbitrary padding
of Opus or ciphertext is never used to force a length match.

Fixed mode requires both destination ports and omits `discovery`. It remains
ready immediately and uses connected sockets as before. Discovery mode omits
both destination ports; zero is not a placeholder. It binds both local sockets
and accepts the native packed `SS_PING` layout: 16 payload bytes followed by a
nonzero big-endian 32-bit sequence number. The layout and Moonlight's 500 ms
sender are defined in the pinned primary
[`Video.h`](https://github.com/moonlight-stream/moonlight-common-c/blob/874ac9548f1bd6f095ef2b435c42cdde460e7821/src/Video.h)
and used by
[`AudioStream.c`](https://github.com/moonlight-stream/moonlight-common-c/blob/874ac9548f1bd6f095ef2b435c42cdde460e7821/src/AudioStream.c)
and
[`VideoStream.c`](https://github.com/moonlight-stream/moonlight-common-c/blob/874ac9548f1bd6f095ef2b435c42cdde460e7821/src/VideoStream.c).
Each lane ignores malformed datagrams, the other lane's payload, and source IPs
other than `peer_ip`. Its first matching payload freezes that lane's source
port by connecting the socket. Later packets cannot rebind it. The payload is
bearer evidence supplied by the authenticated session; it is not cryptographic
sender authentication. `ping_timeout_ms` bounds discovery, including at zero;
the selected value is returned in open, lookup, and status metadata.

Open replies contain `ok`, `stream`, `peer_ip`, `stream_audio`, `peer_discovery`, `ready`, destination ports,
`video_local`/`audio_local`, the effective `video`/`audio` configuration,
`video_batch_size_fallback`, `ping_timeout_ms`, `video_encrypted`,
`audio_encrypted`, and `permit_legacy_audio_iv_wrap`. Keys/key IDs are not returned.
Discovery destination ports are null until the corresponding lane freezes, then
report the learned source port. Payloads are never returned.
`lookup {operation_id}` returns the same metadata for a live owned stream.
`close {stream}` aborts it and returns `{"ok":true}`. Unknown/foreign IDs return
`stream_not_found`; status filters them out.

`status {stream?:u64}` returns `{ok,enabled,streams:[...]}`. Each entry adds:

- `state`: `discovering`, `sending`, `draining`, `drained`, or `failed`.
- `queued_datagrams`, `queued_bytes`, `sent_datagrams`, `discarded_datagrams`.
- `discarded_audio_fec_shards`, `audio_iv_reuse_started`, and a redacted `failure` code.

Errors are `{ok:false,code}` and contain no keys or media. Nonzero stream IDs are
OS-random 64-bit integers; callers must preserve full integer precision. Limits
are four live streams, two per owner, 128 retained operation records, 1024
issued IDs, 128 encryption keys, and 128 discovery-payload pairs per provider
lifetime. Matching open retries
return the existing stream; changed parameters return `operation_conflict`.
Closed operations remain tombstones, returning `stream_closed` on open retry
and `stream_not_found` on lookup. No retry silently recreates sockets or cipher
state. Cancellation is checked before opening; failed completion of a new open
closes its sockets. These records are in-memory, not durable.

## Admission, packetization, and delivery

Each video submit carries one access unit of the stream's codec: Annex B for
`h264` and `hevc`, one low-overhead OBU temporal unit for `av1`. H.264 remains the
default. When `codecs` lists several codecs, the client negotiates one after the
transport opens; the first video packet whose ABI codec is in the list fixes the
stream's codec, and later packets of another codec are rejected. A codec here is
a transport input contract and does not by itself enable client negotiation or
encoder support. HEVC and AV1 producers may split an access unit into fragments
that end with `FLAG_END_OF_ACCESS_UNIT`; the transport keeps one bounded owned copy
until the final fragment and announces a keyframe when any fragment carried
`FLAG_KEYFRAME`. AV1 frame types come from that flag; H.264 and HEVC frame types
come from their NAL units. Consumers must otherwise assemble producer fragments
before calling; an arbitrary encoder fragment is not a frame. Accepted video producer sequences must strictly increase and
timestamps cannot regress. Wire frame indices start at one and are bounded
before wrap; timestamps use the producer's epoch converted to the 90 kHz RTP
clock. The video packetizer creates data and negotiated parity before each
complete UDP payload is optionally GCM-sealed.

Each audio submit contains one complete Opus packet with the negotiated duration
and fixed wire size. Input sequence numbers must be contiguous unless explicitly
marked `AUDIO_PACKET_DISCONTINUITY`. The RTP audio timestamp uses packet counts
in milliseconds, starting at zero, independently of producer timestamps. CBC
seals Opus bytes before audio parity is computed; RTP headers and FEC headers
remain plaintext as required by this legacy protocol. Discontinuity abandons
only cached parity inputs, skips to the next four-packet boundary, and advances
the existing CBC sealer's IV slots. Queued data remains intact. No silent audio
or partial parity group is fabricated.

One stream queues at most 2048 datagrams and 8 MiB. Video reservations use the
packetizer's non-mutating size/FEC planner before packetization; encrypted size
includes every prefix. A single batch larger than the queue is invalid. Audio
validates framing/length and reserves all prospective data/parity datagrams
before changing packetizer or cipher state. `MEDIA_BUSY` accepts nothing,
consumes no indices or nonces, and lets the caller retry the original media.
Input allocations are borrowed only during the callback and copied before
return. There is no media service-request replay or automatic retransmission.
Discovery admission returns `MEDIA_BUSY` without validating or changing media
state until both lanes freeze.

Each controller tick distributes at most 64 sends evenly across its live
streams; the remainder rotates between streams, and a blocked stream does not
consume another stream's allowance. Video frames are queued as complete
packetizer groups. A frame's software send allowance is the integer number of
actual UDP payloads that fit in `min(64 KiB, max_batch_size_kb * 1024)`, clamped
to 1–64 packets. A single payload larger than the byte cap still gets one send.
Audio remains limited to 16 sends per stream per tick. `WouldBlock` or `Interrupted`
retains the exact queued datagram, including its existing ciphertext, for a
later tick. Other socket errors, short UDP sends, or five seconds without send
progress fail the stream visibly and discard its remaining queue. Crypto
failure also fails and discards the queue; consumed nonces are never rewound.
UDP send success is only kernel admission: delivery loss, decoding failure,
congestion control, retransmission and peer acknowledgements are not measured.
The allowance also bounds OS segmentation batches. On Linux, equal-size
consecutive datagrams from one video frame use `UDP_SEGMENT`; on Windows, they
temporarily set the `IPPROTO_UDP` `UDP_SEND_MSG_SIZE` socket option for that
send, then restore it to zero. The final shorter payload is sent separately.
The transport treats an unsupported OS, kernel, socket provider, or network
device as a capability miss and falls back to individual `UdpSocket::send`
calls for the rest of that stream. Microsoft documents the option starting with
Windows 10 version 2004; older versions fall back. Other platforms use
individual sends. The Linux kernel may segment in software when the NIC cannot
offload the operation, so this does not promise hardware acceleration. Live
qualification across supported kernels, Windows versions, socket providers,
and NIC drivers remains pending.
Discovery reads at most 16 datagrams per lane per tick. Five seconds from open
without both lanes fails with `udp_discovery_timeout`; queued pings cannot revive
an expired stream.

Native EOS marks that medium closed without enqueuing an EOS datagram. The other
medium may continue. Native `drain` closes both inputs and returns immediately;
status reaches `drained` after the local queue empties. Repeated drain is harmless.
An incomplete audio FEC group emits no extra packets at drain. Close/shutdown
abort pending queues and release both sockets. There are no detached workers.
Bindings must be released before provider unload through signed dependency
ordering; documented FFI boundaries require live initialized packet allocations
and prohibit unwinding across the native ABI.

## Cryptographic lifetime and compatibility

The shared GameStream crypto implementation uses vetted ring AES-128-GCM for
the explicitly supported Sunshine host-to-client video profile and RustCrypto
AES-128-CBC/PKCS7 for legacy audio. It owns cipher state; the transport adds no
cipher implementation. See [crypto contract](../../crates/gamestream/src/crypto/README.md).

A key may be shared by video and audio within its one launch session. Private,
bounded history rejects reusing it in another stream during this module
instance, even after close, cancellation, or under another owner. The trusted
session coordinator **must supply a fresh key across provider reloads and host
restarts**. The module cannot enforce that cross-restart contract without a
durable coordinator. No key is persisted, returned, or logged by this module;
configuration and key-history memory are retained until provider destruction.

Discovery payload history follows the same provider lifetime: neither lane's
payload may appear in a later stream, including after close or cancellation and
across owners. The session coordinator must generate fresh payloads across
provider reloads and host restarts because this in-memory module cannot enforce
cross-restart freshness.

Audio defaults to rejecting IV reuse. Its 16-bit sequence-derived IV budget
ends after 65536 slots, about 5.46 minutes at 5 ms or 10.92 minutes at 10 ms,
and discontinuity skips consume that budget too. Exhaustion fails the stream
and requires a fresh-key session. Only an explicit
`permit_legacy_audio_iv_wrap:true` selects long-session legacy compatibility;
`audio_iv_reuse_started` reports when IV reuse begins. CBC has no authentication
or replay protection, and this option does not add either. Video GCM's outer
frame-number routing hint is unauthenticated by the client protocol; the full
RTP/NV plaintext and ciphertext integrity are authenticated.

## Verification and remaining scope

Tests use real loopback UDP receivers for video/audio data and parity, encrypted
queue behavior, EOS/drain, caller isolation, fairness, cancellation/socket release,
retry/key-history redaction, exact ping parsing, wrong-lane/IP rejection, and
source-port freeze. Deterministic send-result tests cover exact
retention on backpressure and visible discard on failure or prolonged stall.
The shared packetizer/crypto crates independently verify wire fixtures, FEC,
cryptographic vectors and tampering. No hardware is opened by transport tests.

This is a bounded media UDP component, not a complete GameStream server.
Cryptographic UDP sender authentication, RTSP/session coordination, launch ownership,
producer assembly, bitrate/pacing feedback, ENet control/session coordination, retransmissions,
long-term audio/video synchronization, and real Moonlight client qualification
remain separate requirements. No public streaming readiness is advertised.
