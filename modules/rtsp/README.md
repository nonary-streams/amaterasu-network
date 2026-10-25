# Managed encrypted RTSP

This library owns the RTSP listener and negotiation lifecycle. It delegates media
allocation, authenticated startup and cleanup to `amaterasu.stream-session/1`.
The native shell has no protocol-specific behavior. The service is
`amaterasu.rtsp/1`; the platform and synthetic stream-probe packages include it
with networking disabled and an empty caller allowlist.

A trusted caller provisions a ticket with an already authorized peer, fresh key,
either fixed media destination ports or UDP peer discovery, capture selection and
a fixed media profile. Ticket knowledge does not grant another broker principal ownership.
Network requests must prove key possession through encrypted RTSP envelopes and
match the ticket's peer address. Keys never appear in replies or events.

The control actions are `open`, `close {ticket}`, `status {ticket?}` and
`lookup {operation_id}`. Open takes `operation_id`, `peer_ip`, `video_port`,
`audio_port`, `key_hex`, `key_id`, `connect_data`, `capture`, optional
`device_name`, `profile`, and `discover_peers` (default false). `device_name` is
Moonlight's bounded session label; it is passed separately from capture `output`.
Fixed mode requires both ports.
Discovery mode requires them to be omitted or zero so caller-supplied ports cannot
silently override discovery.
Capture contains `capture_provider` (`dxgi` or `wgc`), optional `constant_rate`
(default false), `output`, `encoder`, `audio_endpoint` and optional
`host_audio_enabled` (default false). That flag snapshots Moonlight's
`localAudioPlayMode` choice and is forwarded through stream-session to AudioCapture.
Constant-rate capture is accepted only with WGC and is forwarded to stream-session
and Video as part of the per-open selection. The profile supplies dimensions, frame rate, bitrate in kbps,
reference-frame limit, video packet/FEC settings, Opus packet duration/bitrate and
encryption policy. Unknown fields are rejected; network data cannot override these
authorized settings.
NVHTTP also supplies `profile.video_max_batch_size_kb` for each launch; direct
RTSP opens default it to 64. The effective 16/32/64 value is copied to the nested
`video.max_batch_size_kb` stream-session setting.
The ticket peer and selected listener must use the same address family; an
unreachable ticket is rejected before media allocation.

NVHTTP is the only caller allowed to use the private `network_configure {port}`
action. For a valid base port in 1029..=65514, it configures this listener at
base+21 and passes per-stream local UDP binds at base+9 (video), base+10 (control),
and base+11 (audio) to `stream-session`. The existing listener IP is preserved.
The action defers while a ticket is live or an accepted TCP connection remains,
and reports active only after the replacement RTSP listener binds and all three
UDP addresses pass a simultaneous bind check. UDP sockets themselves belong to
per-session stream owners, so the check does not reserve ports between streams.
Pending updates keep new opens on the currently bound listener's base until retry
succeeds.
An occupied unrelated target leaves the old TCP listeners bound. Same-port
overlap can require releasing the old set; if replacement and restoration both
fail, status clears the active tuple and addresses and retries the requested
policy instead of reporting cached sockets. Live tickets and unconfirmed cleanup
continue to defer listener changes.
This does not alter NVHTTP's HTTP/HTTPS listener or weaken its loopback policy.

Startup settings accept `address_family` (`ipv4` or `both`) and `bind_address`
(an IP address or empty string). A nonempty `bind_address` replaces the RTSP
listener IP and supplies the same-family video, control and audio UDP bind
addresses while preserving configured ports. When both policy keys are omitted,
the legacy `bind` IP remains in effect. An explicit `address_family` supplies
family defaults when `bind_address` is omitted or empty: loopback addresses when
remote access is disabled, and family wildcards when remote access is enabled.
For wildcard listeners, RTSP selects a concrete local route for each peer and
uses it in the returned URL and that stream's UDP binds.

With an explicit IP, RTSP and derived UDP binds use that one family. With an
explicit empty address and `both`, RTSP binds separate IPv4 and IPv6 TCP sockets
on the same port, and UDP preflight checks both family-specific video, control,
and audio ports together. IPv6 sockets are v6-only, so IPv4 reachability does not
depend on host dual-stack defaults. When remote access is disabled, both sockets
are loopback-only; otherwise each family uses its wildcard. Wildcard RTSP selects
a concrete same-family local route for each peer and uses it for that ticket's URL
and UDP binds. Status retains the compatibility `local` field for the primary
listener and adds `locals` containing every bound address.
The shared `amaterasu-network-policy` library also binds actual media/control UDP
sockets with the same v6-only behavior. Each ticket freezes its requested UDP
endpoints; prepare readback must preserve their IP/family and fixed ports before
SETUP can advertise them. Provider mismatches retain cleanup ownership until the
existing stream-session cancellation and release workflow settles.

Replies expose an opaque ticket, bound address, RTSP URL, protocol `state`,
downstream `stream_state`, and fixed failure/cleanup codes. `playing` means PLAY
was accepted; `stream_state: active` separately indicates media startup completed.
Two live tickets and 128 retained operation records bound allocations. Lists show
at most 16 owned records and report truncation. Identical open retries preserve the
original ticket; changed input conflicts, including after the ticket closes.

The initial profile is H.264 SDR with limited-range BT.709, stereo 48 kHz PCM and
5/10 ms Opus. The prepared profile must match ANNOUNCE, including reference-frame
constraints, packet sizing, FEC and encryption. An optional single-reference
constraint is forwarded to the encoder and requires explicit backend confirmation.
The trusted profile also forwards `permit_legacy_audio_iv_wrap`, default false,
so installed policy can explicitly select the transport's existing legacy
long-session audio behavior. This does not add authentication to CBC audio;
see the [media transport contract](../media-transport/README.md).

## Client ordering

The modern transcript is OPTIONS, DESCRIBE, SETUP for audio/video/control,
ANNOUNCE, then PLAY. Session tokens, targets, CSeq progression, launch epochs and
pending completion tickets are checked explicitly. SETUP reports the allocated
server ports. ANNOUNCE acceptance commits only a supported prepared profile.

PLAY arms the owned media session. It does not claim capture is already active:
Moonlight opens control after RTSP completes. The session library waits for
control authentication before opening capture, with bounded startup and rollback.
RTSP TEARDOWN and trusted ticket close require confirmed session cleanup.

One encrypted RTSP request is accepted per TCP connection, followed by an encrypted
response and EOF. Crypto counters and replay windows live on the ticket across
connections. There is no plaintext fallback. See the
[transport contract](src/transport/README.md) for bounds and disconnect semantics,
and the negotiation contract in the separately pinned `amaterasu-protocol`
repository (`crates/gamestream/src/rtsp/negotiation/README.md`)
for protocol state and compatibility limits.

## Qualification and remaining integration

`scripts/test_rtsp.py` exercises the signed synthetic-source composition with an
independent Python AES-GCM RTSP client, the pinned ENet C client, real Opus and
independently checked media encryption/FEC. Synthetic video is a framing fixture,
not a decodable H.264 stream or evidence of hardware behavior.

Moonlight's `X-GS-ClientPort` setup field remains a placeholder and is never
accepted as destination authorization. In discovery mode, RTSP creates distinct
16-character base64url audio and video bearer tokens from 12 random bytes each,
for 96 bits of entropy per lane. Only the corresponding encrypted SETUP response
receives each `X-SS-Ping-Payload`; ticket responses and status never expose them.
The downstream media transport validates `SS_PING` and freezes each lane's source
port. NAT rebinding after that point is not supported. Public NVHTTP launch,
application and display transactions, paired-client revocation wiring,
reconnect/resume, OS input dispatch, pacing and actual client/hardware qualification
remain required.
The HTTP adapter continues to report streaming unsupported.

Orderly ticket close must precede replacement for confirmed cleanup. Synchronous
module unload can release sockets and settle bounded broker work, but cannot drive
asynchronous provider teardown after ticking stops. Provider unload/process exit
is the backstop for active resources; native grants do not sandbox trusted code.

Encoder selection preserves legacy unsigned startup ordinals and accepts a full
stable encoder identity or the exact `"auto"`/`"software"` backend selectors.
The selection passes unchanged to video, which resolves non-identity selectors
once before capture allocation. Missing software support fails explicitly; fixture
control success does not qualify real capture, encode, or client playback. See
[video selection policy](../video/README.md) for bounds and automatic-selection
limits.

Software tuning remains exact through the launch snapshot: nullable `sw_preset`
and `sw_tune` inherit defaults, while explicit empty strings are retained.
RTSP freezes signed `min_threads` and QP with the global/application/client
precedence before opening the stream. ANNOUNCE contributes the client slice
count; software requests `max(videoEncoderSlicesPerFrame, min_threads)` and
passes it to the video encoder, subject to x264 frame-size and backend limits.
QP defaults to 28 and remains metadata because
x264 ABR ignores it and Amaterasu has no VAAPI CQP consumer. The backend policy
supports `auto` and `software`, and real codec availability remains a separate
requirement. [NVHTTP policy](../nvhttp/README.md#software-encoder-policy)
documents persistence, scope precedence and platform qualification limits.
