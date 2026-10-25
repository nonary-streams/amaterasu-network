# Moonlight HTTP/TLS adapter

`amaterasu-nvhttp` is an independently built Rust module. It supplies the
Moonlight Gen7 pairing HTTP/XML adapter and the bounded transport described below;
cryptography and durable client trust remain owned by `amaterasu.pairing/1` and
`amaterasu.identity/1`. Native modules are trusted code, not sandboxed by grants.

Startup defaults are disabled, the machine hostname, HTTP `127.0.0.1:47989`,
HTTPS `127.0.0.1:47984`, and `allow_remote:false`. If the platform hostname API
fails or returns a value outside NVHTTP's bounds, startup uses `Amaterasu` as a
last-resort name. A blank configured hostname means use the machine hostname;
nonempty names are preserved without trimming or case normalization. The transport
owns listener settings and reports the actual bound ports. Public routes do not
initialize a private host identity: an administrator must initialize/import one
through pairing first. The configured hostname is the bootstrap fallback. After
startup, NVHTTP loads `product/amaterasu.nvhttp` from
`amaterasu.configuration/1`; the committed effective hostname replaces the fallback
in subsequent server-info replies. NVHTTP needs configuration calls in addition to
pairing/state calls for delegated transcript operations and native use of the
identity service for TLS signing and live client checks.
Catalog export additionally requires a catalog call grant and an explicit catalog
`export_principals` mapping from `amaterasu.nvhttp` to the desired owner (the
platform profile uses `amaterasu.management`). The HTTP caller cannot select the
owner. It does not need administrative PIN approval or unpair authority.

## Product hostname settings

The management API exposes `GET /v1/nvhttp/settings` and
`POST /v1/nvhttp/settings_update`. Only requests authenticated and forwarded by
`amaterasu.management` are accepted by NVHTTP. The frontend requires the
`configuration.read` scope for reads and `configuration.write` for updates.

Reads return both the effective value used by Moonlight and the configured override.
An empty `configured_hostname` means the machine hostname is active; `hostname`
remains the effective name for compatibility:

```json
{"ok":true,"hostname":"Studio PC","configured_hostname":"","port":47989,"https_port":47984,"active_http_port":47989,"active_https_port":47984,"listener_error":null,"revision":3}
```

An update sends a whole hostname replacement and its observed revision. Sending an
empty name stores the default selection and uses the machine hostname:

```json
{"hostname":"Studio PC","port":47989,"expected_revision":3}
```

The successful update response has the same shape as a read and is returned only
after the configuration service confirms the persisted write. The `hostname` and
`configured_hostname` fields distinguish the effective Moonlight name from the
stored override. Names are limited to 128 UTF-8 bytes and reject control
characters. A stale revision returns `revision_conflict` with `current_revision`.
When a write result is
ambiguous, NVHTTP reads the product document again and returns
`settings_outcome_unknown`; it never reports success based only on the requested
hostname. The readback still updates server-info to the hostname currently stored.
The effective name also becomes the default device name for new stream sessions.
Moonlight's optional `clientName` query value overrides the name for that launch;
existing sessions retain the name resolved when they started. Capture output stays
separate and continues to identify the display source.
The standalone virtual-display service has no launch/session lifecycle binding, so
its caller-supplied driver names are not changed by this setting. Platform discovery
continues to use the operating system hostname.
While configuration is unavailable, the bootstrap hostname remains active,
settings reads and writes fail with a configuration error, and NVHTTP retries the
load with backoff. A missing product document uses the bootstrap hostname and
configured component port at revision 0; its first successful update creates
revision 1.

## Moonlight listener base port

The NVHTTP product settings editor also stores a Moonlight HTTP base port. It
accepts 1029 through 65514; the HTTP listener binds to that port and HTTPS to the
base port minus five. This matches Vibeshine's NVHTTP port offsets and keeps both
ports in range. The same setting configures RTSP TCP at base+21 and the per-stream
UDP source ports at base+9 (video), base+10 (control), and base+11 (audio). The
RTSP listener retains its configured bind IP; the NVHTTP control listener remains
loopback unless startup policy explicitly allows remote binding.

Updating the base port prepares both NVHTTP replacement listeners before releasing
either current listener, retains accepted connections, and updates `/serverinfo`
to advertise the new bound ports. RTSP changes wait until all live RTSP tickets
are terminal and accepted RTSP TCP connections have closed. While that change is
pending, new RTSP opens keep using the base of the currently bound RTSP listener.
Before acknowledging application, the RTSP module checks that all three UDP
addresses can bind together, then passes those addresses to `stream-session` for
each later stream. Per-session UDP
sockets are created by the stream owner and are not reserved while idle, so an
external process can still claim a port after preflight.

A successful update is acknowledged only after both NVHTTP listeners and the RTSP
listener/UDP bind preflight are active at the requested base. If an RTSP stream is
active, a TCP or UDP target is occupied, or a listener cannot bind after
persistence, NVHTTP returns `listener_apply_pending` with `persisted:true`, retains
the previous ports while their sockets remain bound, and retries applying the stored port.
If an overlapping replacement and restoration both fail, active ports and addresses
become empty until recovery; status does not resurrect a cached listener or clear
the failure during retry backoff. Restart loads the
stored base and repeats reconciliation. The settings response includes
`active_rtsp_port` and `rtsp_listener_error` alongside the active HTTP ports.

## UPnP listener mappings

Product document v21 adds the persisted `upnp` boolean; documents v1 through v20
migrate it to `false`. The management settings response also exposes runtime-only
`upnp_status` and nullable `upnp_error` fields. Status values are `disabled`,
`waiting_for_listener`, `waiting_for_ipv4_listener`,
`waiting_for_gateway_route`, `active`, and `error`.

When enabled, NVHTTP discovers the IPv4 gateway and maps only live listener
addresses and ports. With `address_family: both`, it separately searches scoped
IPv6 interfaces for `WANIPv6FirewallControl` and opens pinholes only for active
IPv6 listeners on those interfaces. Wildcard IPv6 listeners use the selected
local interface address; explicit listeners are accepted only when that address
belongs to the interface. IPv4-only mode skips the IPv6 search.

IPv4 mappings and IPv6 pinholes request 3600-second leases and refresh every 120
seconds. Failed cleanup remains visible and retries while the process is running.
Shutdown makes three best-effort cleanup attempts; if the gateway remains
unavailable, surviving leases may remain active until they expire. The IPv4
manager preserves pre-existing or externally changed mappings. The IPv6 manager
tracks exact gateway-issued IDs and deletes only pinholes created by that owner.
Management HTTPS is exposed only when the live management peer policy enables
WAN access and a TLS listener is active, for both address families.

IPv6 firewall status is queried before reconciliation; additions follow the
gateway's `NewInboundPinholeAllowed` policy. Tests use fake gateway controls and
local protocol fixtures, and do not contact physical routers or change host
firewall state. If no pinholes remain active because a discovered gateway denies
inbound pinholes, runtime status is `error` with the bounded detail
`IPv6 gateway policy disallows inbound pinholes` rather than implying route
discovery failed.

The live settings response includes the configured port, derived https_port, and
active_http_port/active_https_port values. Product document versions 1 through 14
remain readable: v1 stores the hostname, v2 adds the port, v3 adds the listener
address policy, v4 adds the global capture output, v5 adds audio enablement, v6
adds the global capture mode, v7 adds the global video batch allowance, v8 adds
the global maximum bitrate, v9 adds the nullable global minimum FPS target, v10
adds the global audio sink, v11 adds WGC pacing smoothing, v12 adds the external
IP, v13 adds the ping timeout, and v14 adds audio sink capture-only policy.

NVHTTP, RTSP and per-session media/control sockets share the independently built
`amaterasu-network-policy` address, port and endpoint contract. IPv6 UDP sockets
are explicitly v6-only, matching RTSP preflight. Prepared session readback must
match the requested local IP/family and fixed port before RTSP advertises it;
substituted endpoints trigger the existing owned-resource cleanup path.

NVHTTP startup also accepts `address_family` (`ipv4` or `both`) and `bind_address`
(an IP address or empty string). An explicit IP replaces the address for both HTTP
listeners while preserving their configured ports and must match the selected family.
When both keys are omitted, the legacy `http_bind` and `https_bind` addresses remain
in effect. An explicit family with an omitted or empty address selects that family's
loopbacks, or wildcards when remote access is enabled. An empty address with no
explicit family follows the family defaults resolved from the legacy bind addresses.
`allow_remote` remains the gate for non-loopback listeners. With an
explicit empty address and `both`, each HTTP and HTTPS protocol binds separate
IPv4 and IPv6 sockets on the same respective port. IPv6 sockets are v6-only, so
IPv4 reachability does not depend on the host's dual-stack default. When remote
access is disabled, the pair is loopback-only; otherwise it uses both family
wildcards. Status retains the legacy primary `http_address` and `https_address`
fields and also exposes `http_addresses` and `https_addresses` for the full pair.

Public streaming is a separate startup opt-in. Omitting `streaming` disables it.
The complete settings object has no executable, arguments, environment, or catalog
owner field:

```json
{
  "streaming": {
    "capture": {
      "capture_provider": "dxgi",
      "output": "display-one",
      "encoder": 0,
      "audio_endpoint": "default"
    },
    "desktop": { "enabled": false },
    "profile": {
      "max_width": 1920,
      "max_height": 1080,
      "max_fps": 60,
      "bitrate_kbps": 10000,
      "max_reference_frames": 1,
      "packet_size": 1024,
      "fec_percentage": 20,
      "min_parity_shards": 2,
      "max_fec_blocks": 1,
      "packet_ms": 10,
      "audio_bitrate": 128000,
      "encrypt_video": true,
      "encrypt_audio": true,
      "permit_legacy_audio_iv_wrap": false
    }
  }
}
```

The optional `streaming.desktop.enabled` flag defaults to `false`. When enabled,
NVHTTP advertises a `Desktop` app with reserved Moonlight ID `2147483647`; a catalog
collision fails the app-list request. Desktop launch, resume, and cancellation still
require the paired TLS client and use the normal RTSP session path without a catalog
entry or application process. Resume retires the existing RTSP ticket and opens a
fresh ticket for that same paired client.

Unknown or missing required nested fields fail startup. Maximum dimensions must be even and
within 16–3840 by 16–2160; maximum FPS is 1–120. Bitrate, audio, packet duration,
and reference-frame bounds are validated before listeners start. Video FEC and
packetization settings are additionally checked by the same packetizer used for
the stream.

### Video codecs

The profile does not choose a codec. NVHTTP enumerates `amaterasu.encode/1` at
startup and then every five minutes while no stream is active, retrying failures
with backoff and keeping the last good snapshot. From each encoder entry it reads
only `codec` (`"h264"`, `"hevc"` or `"av1"`; other values are kept for numeric
indexing but never offered) and `hardware`. At `/launch` it fixes the codecs that
launch may negotiate: with `"encoder":"auto"` every codec that has an encoder, and
with a numeric `encoder` only the codec of that enumerated entry. A codec whose only
encoders are software is offered only when the requested mode is at most 1920x1080
at 60 FPS, and such an offer also limits RTSP negotiation to that mode. A launch
for which no codec qualifies is refused with HTTP 503 before any application,
display, or RTSP effect: `no hardware encoder for this stream mode`, `no video
encoder is available`, or, before the first enumeration completes for a mode above
the software limit, `encoder capabilities are not known yet`. Until that first
enumeration completes the host offers H.264 only. RTSP receives the offer as
`profile.codecs` (omitted when it is H.264 alone) and the client picks one in
ANNOUNCE. The legacy `profile.codec` field is still accepted but no longer has any
effect.

## Global capture output

The NVHTTP settings API reads and updates the global `output_name` setting. Reads
return `configured_output_name`, `effective_output_name`, and `capture_provider`.
The effective name is the selected output ID, or the bootstrap
`streaming.capture.output` when no selection is stored. Updates may omit
`output_name` to keep its current value; `null` or `""` resets it to the bootstrap
output. A nonempty value is stored exactly and limited to 512 UTF-8 bytes; values
with controls or leading/trailing whitespace are rejected. A v4 product document
stores the setting as a nullable string. Versions 1 through 3 load with no global
selection.

NVHTTP snapshots the effective output ID when a new Moonlight stream starts and
passes it through RTSP to the existing capture provider. Direct RTSP opens retain
their explicit per-session capture output. The selected ID applies to future
sessions; changing it does not retarget an active capture. If that ID is no longer
available, stream startup fails and does not fall back to another output. The
selector depends on provider-specific output enumeration; Windows DXGI and WGC
are the implemented capture providers. Linux capture/output enumeration and
macOS capture/output enumeration are not implemented, so persisted output choices
do not imply Linux or macOS streaming support.

## Global capture mode

The same NVHTTP settings API accepts `capture` values `auto`, `ddx`, `wgc`, and
`wgcc`. Reads return `configured_capture` and keep `capture_provider` as the
effective provider used by output enumeration. An omitted update field preserves
the stored mode; `null` or `"auto"` selects automatic mode. Product document v6
stores a canonical mode, and older documents load as `auto`.

`ddx` selects DXGI with event-driven delivery, `wgc` selects WGC with variable-rate
delivery, and `wgcc` selects WGC with constant-rate delivery. Explicit WGC modes
fail at stream start when WGC is not allowed by the Video provider configuration;
they do not silently fall back to DXGI. `auto` preserves the startup
`streaming.capture.capture_provider` and uses variable-rate delivery. Vibeshine's
automatic WGC choice can depend on virtual-display and game context; Amaterasu does
not yet model that policy. Per-client and per-application capture overrides are
also not implemented. A direct RTSP open remains explicit about its provider and
constant-rate flag.

## Audio sink capture-only mode

Product document v14 stores `audio_sink_capture_only`, defaulting to `false` for
documents v1 through v13. NVHTTP's settings read returns the boolean. An omitted
update preserves it; an explicit `true` or `false` is written with the expected
product revision, while `null` is rejected. The management adapter can expose the
field as `GET /v1/nvhttp/settings` and `POST /v1/nvhttp/settings_update`.

Each stream snapshots this policy after resolving its audio endpoint. Endpoint
selection uses global, application, then paired-client precedence; the capture-only
boolean uses global, application, then certificate-verified client precedence, so
an explicit `false` override disables a global or application `true`. The policy
is forwarded through RTSP and stream-session to AudioCapture's
`capture_sink_without_routing` open field. It is enabled only when the winning
policy is true and the resolved configured sink is nonempty and matches the
selected endpoint. An empty scoped sink selects the bootstrap endpoint and does
not enable capture-only routing.

Application and paired-client `config_overrides.back_button_timeout` values are
sparse signed 32-bit millisecond overrides. The management API and editor expose
the field for both scopes. NVHTTP snapshots the authenticated client's value
before the application value and carries that winner through RTSP and
stream-session to input lease acquisition. Explicit negative values, including
`-1`, disable the Back timeout; an absent value lets input use its durable global
policy and snapshot it when the lease starts.

## Virtual audio sink

Product document v15 stores nullable `virtual_sink`; documents v1 through v14
migrate with it unset. Settings reads return `configured_virtual_sink`. An
omitted update preserves it, `null` clears it, and a string up to 4096 bytes
without control characters is stored exactly, including explicit empty. Signed
management settings expose the same distinction.

Each new stream resolves the authenticated client's selector, then the
application selector, then the global selector. A scoped explicit empty string
clears inherited managed selection and resumes regular endpoint precedence. A
nonempty selector overrides regular endpoint choices and is forwarded through
RTSP and stream-session to AudioCapture with an empty regular endpoint and
`channels: 2`; the global capture-only preference remains stored, but the
effective capture-only flag is false for virtual capture. Windows selection
matches exact ID, friendly name, device description, then adapter name. An
unavailable selected device fails without falling back.

The current stream transport and Opus encoder support stereo only. Although the
AudioCapture backend accepts 5.1 and 7.1 layouts, this path cannot yet packetize
those layouts. Amaterasu also has no host-audio toggle or complete source fallback
that selects the default Steam virtual endpoint when host audio is disabled or
the regular endpoint is empty. Thus an explicit empty selector is preserved, but
does not trigger that Sunshine fallback. Full cross-platform virtual-sink parity
and surround streaming remain incomplete.

## Global video batch allowance

Product settings v7 accepts nullable `video_max_batch_size_kb` values from 0
through 64. Omission preserves the configured value and `null` resets it to the
default. Settings reads return `configured_video_max_batch_size_kb`,
`effective_video_max_batch_size_kb`, and `video_batch_size_fallback`. Zero selects
the automatic 64 KiB default. Effective values 16, 32, and 64 pass through; other
accepted in-range values are preserved in storage, use 64 at runtime, and set the
fallback indicator.

NVHTTP snapshots the effective value for each launch and forwards it through RTSP
and stream-session to the media transport. It changes the per-frame software send
allowance while preserving the aggregate 64-send fairness bound. Platform UDP
segmentation offload (USO/GSO) is not implemented yet, so this is not full transport
batching parity.

## Global maximum bitrate

Product document v8 stores nullable `max_bitrate` as a signed 32-bit integer. The
settings API accepts any signed 32-bit value: omission preserves the stored value,
and `null` clears it. Reads return the exact nullable value as
`configured_max_bitrate` and a positive-only cap as `effective_max_bitrate_kbps`;
zero and negative values have no effective cap. Product documents v1 through v7
migrate with no configured cap.

NVHTTP snapshots the effective cap when a stream is admitted and limits Amaterasu's
configured startup profile bitrate passed to RTSP. A cap above the configured
profile does not raise its bitrate. `LaunchRequest` currently has no bitrate field,
so the client-requested bitrate cap used by Vibeshine is still pending. The current NVHTTP profile accepts 100 through
100,000 kbps, and the Windows video encoder accepts 100,000 through 100,000,000
bits per second. A positive configured cap below 100 kbps is retained but causes
launch to fail with an explicit encoder-minimum error instead of starting above
the configured-profile cap. This slice applies only at launch; Amaterasu has no live
`/bitrate` update route, so changing the setting does not modify active streams.

Vibeshine's live `/bitrate` consumer applies a 500,000 kbps ceiling. That runtime
path and ceiling are not implemented here; the current Amaterasu startup profile
has a lower 100,000 kbps maximum.

## Minimum FPS target

Product document v9 stores nullable `minimum_fps_target`. Settings updates accept
finite numbers from 0 through 1000: omission preserves the stored value and
`null` clears it. Reads expose the raw nullable value as
`configured_minimum_fps_target` and its launch value as
`effective_minimum_fps_target`. Documents v1 through v8 migrate with no stored
value and the runtime default of 20 FPS.

NVHTTP snapshots the effective target for each launch and forwards it through
RTSP and stream-session to Video. Positive values request an idle repeat cadence;
zero uses the negotiated capture FPS. Newly captured frames still submit
immediately. Video keeps a bounded owned copy of the last accepted frame and
attempts at most one repeat per module tick when idle. Fresh accepted captures
take precedence over a repeat in the same tick, and output timestamps/sequences
advance only when the encoder accepts the frame. Host tick cadence and encoder
backpressure can reduce the achieved rate; targets above capture FPS are allowed
but do not create a timer or catch-up burst.

The pinned Vibeshine initializer and runtime use 20 FPS by default, while its
documentation says zero means half the client FPS. Its runtime resolves zero to
the negotiated FPS, so this implementation follows source behavior and records
that documentation mismatch. This slice implements startup/session handoff and
Video's idle repeats; it does not change the negotiated capture FPS or claim a
real-time scheduler.

## Wire routes

All routes accept a bodyless GET. Query parsing allows at most 12,288 request-target
bytes and 24 fields. Duplicate fields are rejected after percent-decoding, so
`uniqueid` and `unique%69d` cannot supply competing identities. Invalid UTF-8,
malformed escapes, controls, missing `=`, and duplicate phase selectors fail.
`+` decodes as space. `uuid`, `updateState`, and unrelated bounded client metadata
are not authority. XML values escape all markup delimiters and replace XML-invalid
BMP noncharacters U+FFFE/U+FFFF and controls.

- `/serverinfo` retrieves the persistent host UUID through pairing. Plain HTTP
  always returns `PairStatus=0`; HTTPS requires a currently paired client TLS
  certificate, returning `PairStatus=1` only after the transport's live check.
  An untrusted HTTPS request returns an HTTP 200 reply whose XML root carries
  `status_code="401"`. moonlight-qt maps every non-2xx HTTP status to a network
  error (the host shows offline) and only falls back to plain-HTTP `/serverinfo`
  for an XML 401 (`nvhttp.cpp:355-381`, `:153-165`, `:550-575`).
- `/pair` implements the Gen7 phases below, including the held initial request.
- `/applist` requires trusted paired TLS and exports the configured catalog owner
  as Moonlight `App` elements with `AppTitle`, numeric `ID`, and
  `IsHdrSupported=0`. An empty successful list means that catalog is actually empty.
- `/launch` requires trusted paired TLS and the validated launch query described
  below. It returns success only after the exported application is active and the
  encrypted RTSP ticket is ready.
- `/cancel` requires trusted paired TLS and scopes cancellation to the exact paired
  certificate that owns the active launch. Query `uniqueid` is metadata, not
  authority. A foreign paired certificate cannot inspect or stop the owner record.
- `/unpair` is self-service and authority comes only from the TLS connection. Over
  paired TLS it asks the pairing authority (`unpair_presented_client`) to remove the
  one certificate presented on that connection and answers HTTP 200 with
  `<unpaired>1</unpaired>`, or `0` when that certificate was already gone. The reply
  does not require paired TLS, because the trust it reports was just removed. Any
  later request from that certificate gets 401, and an active launch it owned is
  cancelled by the same revoke path as an administrator unpair (the tick calls
  `revoke_untrusted`, failure `client_revoked`). Plaintext `/unpair` does nothing and
  answers HTTP 200 with `unpaired=0`; `uniqueid` is never used to choose a client.
  An untrusted TLS peer gets 401. Query fields other than `uniqueid` and `uuid` are
  rejected. moonlight-qt calls only the plaintext form, to clean up failed pairings
  (`nvpairingmanager.cpp:248-366`); a pairing transcript that the client abandoned
  therefore expires on its own after 120 seconds.
- `/resume` requires trusted paired TLS and complete launch metadata. It resumes
  an enabled Desktop session owned by that certificate by retiring its RTSP session
  and opening a fresh encrypted ticket. Catalog application resume remains unsupported.

Without streaming configuration, server info advertises `appversion=7.1.0.0` and
`StreamingSupported=0`. Configured Linux streaming advertises
`appversion=7.1.431.-1` so Moonlight enables the Sunshine-compatible RTSP
encryption exchange; Windows retains `7.1.431.0`. Configured streaming advertises
`StreamingSupported=1`. This reports accepted startup policy; it is not a runtime
GPU or capture probe. `ServerCodecModeSupport` is derived from the encoder
snapshot: `SCM_H264` (0x1) always, `SCM_HEVC` (0x100) when an HEVC encoder is
enumerated, and `SCM_AV1_MAIN8` (0x10000) when an AV1 encoder is. 10-bit and 4:4:4
modes are never advertised. `MaxLumaPixelsHEVC` is `1869449984` with an HEVC
encoder and `0` otherwise; Moonlight treats any nonzero value as HEVC support.
Other unavailable hardware and HDR fields remain zero.

The module refreshes one shared encoder snapshot at startup and, while idle, every
five minutes. Refresh failures retain the last good snapshot and retry with bounded
backoff; request handlers read the cache. Each launch freezes that snapshot, then
constrains its RTSP codec offer to the effective scoped encoder selection (including
stable identity, numeric index, and software-only policy). The MAC address comes from
the first physical Linux network interface when available, with a zero fallback.
`state` is globally busy while any owned launch remains active or has
unconfirmed cleanup. `currentgame` contains the app ID only for the owning paired
certificate and remains zero for other clients.

Responses use XML `<root status_code="..." status_message="...">`; the HTTP
status matches the root status, except the untrusted-TLS `/serverinfo` 401 above. Successful cryptographic phases return `paired=1`
only after the pairing service has acknowledged that phase. Runtime/service error
text does not expose private keys, PINs, or internal cryptographic details.

## Catalog export

The adapter reads `export_list` in pages of 32 and requires one unchanged catalog
revision throughout the request. It validates each page and strictly ascending
IDs, including the continuation cursor. Canonical `app-` plus 16 lowercase hex
digits maps directly to its integer in `1..=2147483647`; out-of-range IDs fail
visibly rather than being hashed, truncated, or reassigned. Renames preserve IDs.
Titles are XML escaped. HDR support is not claimed.

There are at most four active lists, 16,384 entries, 1,024 pages, 30 seconds total,
and 1 MiB minus 1 KiB of XML per list. Byte, page, or time bounds may be reached
before the entry bound. Overflow returns 413, revision changes 409, malformed
provider data 502, provider failures 503, and expiry 504. No partial list is sent.
Catalog work is never dispatched for an untrusted HTTP/TLS request. Before a
completed list enters the transport write queue, the exact handshake-proven
certificate is checked against live paired trust again; revocation replaces the
private reply with 401.

## Moonlight client wire audit

Checked against the moonlight-qt checkout and its moonlight-common-c submodule
(paths below are relative to the moonlight-qt root; common-c paths are under
`moonlight-common-c/moonlight-common-c/src/`). "Sent" is what Amaterasu answers.
This audit was read-only and static: no real Moonlight client has run against this
host yet, and that stays pending in `docs/linux-session-acceptance.md`.

`/serverinfo` (fetched over HTTPS first once a server certificate is pinned, with
HTTP fallback on an XML 401; `app/backend/nvhttp.cpp:134-195`). Every field is read
by `NvComputer::NvComputer` (`app/backend/nvcomputer.cpp:131-221`) unless noted.

| Field | Client reads | Sent | Notes |
| --- | --- | --- | --- |
| `hostname` | `nvcomputer.cpp:136` | configured hostname | Empty becomes "UNKNOWN". |
| `uniqueid` | `nvcomputer.cpp:141` | persistent host id | Identity of the PC in the client's list. |
| `mac` | `nvcomputer.cpp:142-148` | first physical interface, else zeros | Wake-on-LAN only; all-zero means unknown. |
| `ServerCodecModeSupport` | `nvcomputer.cpp:150-157`, `session.cpp:1798`, `session.cpp:1144-1300` | H.264 baseline while streaming is configured, plus enumerated HEVC and AV1 bits | `Connection.c:228-233` aborts `LiStartConnection` with -1 when zero. |
| `MaxLumaPixelsHEVC` | `nvcomputer.cpp:159-165`, `session.cpp:1174,1216,1377` | `0`, or `1869449984` with HEVC | Zero removes HEVC from the client's formats. |
| `FrameLimiter*` | `framelimitercapabilities.h:16-37` | omitted | Vibeshine extension; absent means unsupported. |
| `DisplayMode` list (`Width`, `Height`, `RefreshRate`) | `nvhttp.cpp:274-300` | omitted | Only used for NVIDIA servers (`session.cpp:1749-1760`). |
| `LocalIP` | `nvcomputer.cpp:181-184` | omitted | Optional; the client keeps the address it connected to (`:562`). |
| `HttpsPort` | `nvcomputer.cpp:186-189`, `nvhttp.cpp:183` | active HTTPS port | Falls back to 47984 if absent or zero. |
| `ExternalPort` | `nvcomputer.cpp:193-196` | active HTTP port | Sunshine extension. |
| `ExternalIP` | `nvcomputer.cpp:198-204` | omitted | Optional. |
| `state` | `nvcomputer.cpp:209`, `nvhttp.cpp:122` | `AMATERASU_SERVER_FREE` / `_BUSY` | The client needs the `_SERVER_BUSY` suffix and must not see `MJOLNIR`. |
| `currentgame` | `nvhttp.cpp:117-131` | app id for the owner only | Zero unless `state` is busy; this is what selects resume. |
| `PairStatus` | `nvcomputer.cpp:211` | `1` only on live-trusted TLS | Plaintext always `0`. |
| `appversion` | `nvcomputer.cpp:214`, `session.cpp:1793`, `Connection.c:237` | `7.1.431.0` (`7.1.0.0` when unconfigured) | Selects SHA-256 pairing, encrypted control and RTSP (`RtspConnection.c:953-955`, `InputStream.c:105`). A non-Sunshine version quad. |
| `GfeVersion` | `nvcomputer.cpp:215,220`, `session.cpp:1333,1802` | `0.0.0.0` | `compatfetcher.cpp:53-120` accepts it; only an empty or `2.x` value limits 4K. No client dependency found, so unchanged. |
| `gputype` | `nvcomputer.cpp:216` | omitted | Informational. |

`/applist` (`nvhttp.cpp:303-352`, status check `:355-392`): the root must carry
`status_code="200"`. Each `App` needs `AppTitle` (a null title counts as
uninitialized, an empty one is allowed) and a nonzero integer `ID`; `IsHdrSupported`
(`== "1"`) and `IsAppCollectorGame` are optional. Sent: `AppTitle`, `ID`,
`IsHdrSupported=0` in that order. Element order does not matter to the parser.

`/launch` (`nvhttp.cpp:200-248`, `session.cpp:1745-1812`). The client sends
`uniqueid`, `uuid`, `appid`, `mode`, `additionalStates`, `sops`, `rikey`, `rikeyid`,
`localAudioPlayMode`, `surroundAudioInfo`, `remoteControllersBitmap`, `gcmap`,
`psmap`, `gcpersist`, `corever`, and the `hdrMode`/`clientHdrCap*` group only for
10-bit formats (`nvhttp.cpp:219-239`, `Connection.c:550-554`). It reads `status_code`
and `sessionUrl0` (`nvhttp.cpp:247`). `LiStartConnection` takes the RTSP port from the
last `:` of `sessionUrl0` (`Connection.c:182-203,272`), expects `rtspenc://` for
encryption (`RtspConnection.c:955`), and connects to the address it already used.
Fixed: the launch parser rejected `psmap`, `sops=1`, any nonzero controller bitmap
(player 1 is always reported as `1`, `gamepad.cpp:994-1004`), `gcpersist=1`, and the
real 5.1/7.1 `surroundAudioInfo` values, so every default launch returned 400. See
"Public launch lifecycle". HDR requests are still refused.

`/cancel` (`nvhttp.cpp:251-272`): sends only `uniqueid` and `uuid`; reads
`status_code` and then `/serverinfo` `currentgame`, which must be zero or the client
reports "can't kill someone else's stream" (`:269`). The owner's `currentgame` drops
to zero as soon as cleanup starts.

`/resume` (`session.cpp:1775`): moonlight-qt sends `resume` instead of `launch`
whenever `/serverinfo` reports a nonzero `currentgame` for its certificate, which is
the normal state after closing a stream without choosing "quit app" (the default
preference). Amaterasu supports this transition for the enabled Desktop application,
with fresh certificate authorization before opening the replacement RTSP ticket.
Catalog application resume remains an unimplemented parity requirement.

Error mapping (`nvhttp.cpp:550-575`, `:153-165`): any non-2xx HTTP status becomes a
network error and the host shows offline. Only an XML `status_code` inside a 2xx
reply reaches `verifyResponseStatus`. Fixed: an untrusted TLS `/serverinfo` is now
HTTP 200 with XML 401, which triggers the plain-HTTP fallback. Other 4xx/5xx replies
keep the HTTP status equal to the XML status and surface as a launch/list error,
which is acceptable because those requests have no fallback. A failed TLS handshake
also falls back (`:556-562`).

Pairing (`nvpairingmanager.cpp:233-366`): `paired`, `plaincert`, `challengeresponse`,
`pairingsecret`, then HTTPS `pairchallenge`; the query carries `devicename` and
`updateState`, both accepted. `/appasset` returns 404, which the client tolerates
(`boxartmanager.cpp:113-115`).

Not verified here: the RTSP/UDP legs after `LiStartConnection`, which the RTSP,
video, audio and input modules own; that `sessionUrl0` names an address a LAN client
can use; and any behavior of a real Moonlight session.

## Public launch lifecycle

Moonlight launch accepts required `appid`, `mode=WIDTHxHEIGHTxFPS`, `rikey`, and
`rikeyid`. The application ID is a decimal catalog ID in `1..=2147483647`.
Dimensions are even and at least 16, and cannot exceed the configured maxima; FPS
is positive and cannot exceed `max_fps`. The selected values configure capture and
encoding for this ticket, but do not claim that the host changed its display mode.
`rikey` is exactly 16 hexadecimal bytes. `rikeyid` accepts Moonlight Qt's signed
32-bit decimal representation and the equivalent nonnegative unsigned 32-bit
representation, preserving the bit pattern.

The bounded normal metadata allowlist is `uniqueid`, `uuid`, `additionalStates`,
`clientName`, `sops`, the `clientHdrCap*` fields, `hdrMode`, `localAudioPlayMode`,
`surroundAudioInfo`, `remoteControllersBitmap`, `gcmap`, `gcpmap`, `psmap`,
`gcpersist`, `clientVrrRequested`, `continuousAudio`, and `corever`.
Unknown fields are rejected, including executable, path, arguments,
environment, or catalog-owner overrides. The current profile accepts SDR,
negotiated stereo or surround playback, core version 1, and Boolean `sops` hints.
`surroundAudioInfo` uses Moonlight's `channel_mask << 16 | channel_count` encoding:
196610 for stereo, 4128774 for 5.1, and 104792072 for 7.1. Controller slot masks
are bounded to 16 bits; `gcpersist` is Boolean. These hints do not grant native
input access or override the configured controller lifecycle. `localAudioPlayMode` accepts
only `0` or `1` and defaults to `0`; it snapshots whether audio capture should
prefer host audio, with the Windows audio module applying its Steam-sink fallback
when host audio is disabled or the ordinary sink is unavailable. HDR remains
unsupported, and SOPS/VRR hints do not apply display or game settings. Actual
surround capture and encoding still require the selected provider's support.
`additionalStates` is accepted only as a decimal Boolean.

The lifecycle calls the launch service's exported-app API with only the immutable
numeric catalog ID and a private operation ID. Catalog policy resolves the trusted
owner and executable. Once the service confirms the application is active, the
lifecycle opens a fresh encrypted RTSP ticket for the TLS peer IP using UDP peer
discovery and the configured capture/profile policy. The returned XML contains
`gamesession=1` and its `rtspenc://` URL only after both operations are confirmed.
Fresh launch records use unpredictable private operation identifiers and nonzero
RTSP connection data. Key material and discovery tokens do not enter public status
or logs.

The exact client certificate owns the application and RTSP records. Trust is
checked before admission, again before any private response enters the transport,
and on subsequent module ticks. Revocation, early disconnect, timeout, provider
failure, or a lost successful response starts owned RTSP and application cleanup.
After a successful launch, the lifecycle periodically checks both providers and
cleans up if either ends. A cleanup failure stays owned and keeps admission busy
instead of freeing a possibly live process or stream. A matching retry can recover
the same ready ticket without launching another application.

The server adopts a launch only after the complete HTTP response and TLS
`close_notify` have been written to the socket. This is a transport flush boundary,
not proof that the Moonlight process received or parsed the XML. A socket failure
before that boundary causes cleanup; a normal connection close after it does not
stop the adopted stream. `/cancel` performs the same owned cleanup and returns
`gamesession=0` only when it is confirmed.

Launch preflight supplies a required integer `cleanup_budget_ms`, frozen from the
resolved application/provider plan before effects. NVHTTP accepts 20,000 through
2,745,000 ms and requires subsequent owned launch readback to match the snapshot.
Missing or malformed budgets, including responses from an older launch module,
reject preflight before application or RTSP launch. Deploy these module versions
together. Each cleanup pass uses that budget plus 30 seconds for serial RTSP close,
lookups, history release, and polling. Cancellation, revocation, and healthy status
polling do not extend the deadline; an explicit failed-cleanup retry starts one new
pass. RPC limits remain unchanged: application stop 15 seconds and status 5 seconds.
A short stop RPC expiry triggers owned readback rather than cancelling the native
undo plan. Healthy `stopping` readback is polled at most every 100 ms until terminal
cleanup or the fixed deadline. Actual `cleanup_failed`, unhealthy or mismatched
readback, and ambiguous broker settlement retain ownership for explicit retry.
The HTTP routing window can still close a long cancel request; background cleanup
and terminal reconciliation continue without its response delivery slot. The
signed `scripts/test_public_preparation_cleanup.py` fixture qualifies Linux
loopback natural exit, cancel, and RTSP teardown with controlled children and
synthetic capture/input. It does not change the native worker's five-second EOF
watchdog or qualify whole-host shutdown, hardware capture, client playback,
installed hosts, or Windows/macOS native behavior.

## Pairing transcript

Each request includes the same `uniqueid` (1..64 identifier bytes). The adapter
accepts Moonlight's actual initial query:

```
/pair?uniqueid=CLIENT&phrase=getservercert&salt=HEX16&clientcert=HEX_PEM&devicename=NAME
```

`clientcert` is hex-encoded certificate PEM, at most 4096 decoded bytes; the
pairing authority validates the certificate itself. `salt` is exactly 16 hex
bytes. The adapter starts a private pairing-service transcript and retains its
opaque ID. Only an administrator approves the PIN through the existing pairing
control service. The original HTTP request remains open while the adapter polls
`get_server_cert` every 250 ms. Internal `pending:true,paired:0` replies are never
sent to Moonlight. Approval returns `paired=1` and hex PEM `plaincert`.

Subsequent separate HTTP requests contain exactly one phase field:

1. `clientchallenge=HEX16` → `challengeresponse` (48 encrypted bytes).
2. `serverchallengeresp=HEX32` → `pairingsecret` (host secret and RSA signature).
3. `clientpairingsecret=HEX_SECRET_AND_SIGNATURE` → `paired=1` only after the
   pairing authority reports durable certificate persistence.
4. HTTPS `phrase=pairchallenge` → `paired=1` only with TLS private-key possession,
   a live paired-certificate check, and the exact original transcript certificate.

No cryptographic phase is automatically retried. One phase may be in flight per
transcript, and out-of-order/replayed phases are rejected before calling the
pairing service. Public routes cannot approve a PIN or fabricate phase completion.

The private map binds the client ID to its original remote **IP**, initial DER
certificate, expected phase, opaque authority ID, and deadline. Source ports are
not used because Moonlight opens different connections for successive phases.
A supplied later `clientcert` or TLS peer certificate must match the original.
Replacing an existing client's certificate or source address cannot cancel its
transcript; duplicate begin and foreign phases fail without forwarding a cancel.

Moonlight omits certificates on later plaintext phases. Therefore remote-IP plus
`uniqueid` association is **not cryptographic peer authentication**. A party sharing
that IP who knows the ID may interfere with plaintext pairing traffic, though the
PIN/certificate-bound transcript still controls actual pairing. The adapter does
not invent incompatible mandatory fields to hide this protocol limitation.
Privileged access never relies on IP or uniqueid: the transport must prove TLS
possession and call `IdentityApi.verify_client` against live committed trust for
each request. Its `RequestContext.peer_trusted` represents that fresh result,
not a hostname/query claim or cached connection authorization.

There are at most eight private transcripts and 32 asynchronous service jobs,
including retired requests awaiting confirmed cleanup.
The pairing deadline is 120 seconds including PIN waiting; individual broker
requests have at most five seconds. Known owned transcripts are cancelled on
request cancellation or expiry. A cancelled begin already dispatched to the
service is drained to recover its opaque ID, then cancelled. A begin cancelled
before dispatch creates nothing. Cleanup results release runtime request tracking.
Known broker request IDs survive cancellation, result-consumption, and release
failures in a bounded retry ledger. Every 100 ms, cleanup retries cancellation and
terminal consumption/release, retaining its admission slot until release or
`not_found` confirms removal. Service operations themselves are never replayed.
Persistent broker failure therefore reduces admission capacity rather than leaking
untracked requests. Retries require module ticks: shutdown makes one best-effort
connection cancellation pass and does not run a background drain. Unresolved
broker records then rely on runtime expiry; unknown pairing transcripts rely on
the pairing authority deadline.

Delivery loss cannot roll back a consumed cryptographic phase or a committed
certificate. A transport failure before an accepted begin ID is learned can leave
an authority transcript until its own 120-second expiry. Losing a reply after it
has left the router likewise requires a fresh client attempt after cleanup/expiry;
cryptographic requests are not replayed to guess their outcome. A completed private
mapping stays only through the original deadline for final HTTPS verification.
Restart loses mappings; an administrator can inspect or unpair committed trust.

## Transport boundary and validation

`wire::Request` contains method, target, and body. `RequestContext` contains the
transport's remote IP, TLS flag, handshake-proven client certificate DER, and fresh
paired trust result. `Router::dispatch` returns an immediate reply or queues work;
`poll` yields connection/reply pairs. The server separately reports a fully flushed
reply or a premature close, and the router passes that result to launch ownership.
The transport owns HTTP framing, sockets, TLS, request deadlines, and bounded writes.
It must not promote the plaintext `clientcert` query to a TLS-authenticated identity.

Wire tests exercise parser limits and ambiguous encodings, XML escaping,
held PIN requests, replay prevention, source/certificate matching, victim-preserving
rejections, cancellation before and after begin dispatch, deadlines, and final
TLS identity requirements. Catalog tests cover authenticated admission, multipage
assembly, stable revisions, numeric ID bounds, malformed pages, visible overflow,
revocation before delivery, and retained cleanup after cancellation/release errors.
Launch tests cover signed/unsigned key IDs, exact secret parsing, mode/profile gates,
unknown and unsupported options, exported-app/RTSP sequencing, foreign cancellation,
lost-response cleanup, cleanup failure retention, and transport delivery state.
Those tests use mock brokers; real AES/RSA and TLS integration are separate gates.
The repository's `scripts/test_nvhttp.py`
performs an independent cryptographic GET transcript when run against the signed
composition.

Behavioral references were the pinned sibling's Gen7 server-info/pairing behavior
and the primary Moonlight Qt client in `app/backend/nvpairingmanager.cpp`,
`nvhttp.cpp`, and `nvcomputer.cpp`. The implementation does not copy or translate
sibling source. Gen6/SHA-1, discovery,
catalog application resume and HDR remain unimplemented here. Surround capture,
display optimization, and controller forwarding depend on the selected providers;
mock protocol tests do not establish real-client or hardware acceptance.

The enabled transport accepts `:0` for ephemeral ports; non-loopback binding
requires `allow_remote:true`. Its control status reports `enabled`, actual
`http_address`/`https_address`, `tls_ready`, `connections`, and fixed TLS status
codes (`identity_unavailable`, `identity_refresh_pending`, or
`tls_configuration_failed`). HTTP may serve before an administrator initializes
the identity; HTTPS becomes ready only after identity material is available.
Identity refresh reads existing state and never generates a private key.

TLS uses rustls 0.23 with the ring provider, TLS 1.2/1.3, no session resumption,
and no early data. Client certificates are optional for public pairing, but
certificate possession is verified cryptographically during the TLS handshake.
DER parsing includes supported legacy X.509 v1 certificates. RSA SHA-2 signature
verification checks the TLS transcript and exact public key; PKCS#1 signatures
are confined to TLS 1.2, with PSS available for TLS 1.2/1.3. Live pairing trust is
checked separately for each request. Host signing uses the native identity API;
the host private key is never exported to this transport. An active bridge gate
prevents rustls signer clones from calling an identity binding after teardown.
Certificate rotation rebuilds TLS configuration and closes older TLS connections.

The single tick thread allows at most 32 connections and eight per source IP,
four accepts per listener per tick, and 16 KiB of per-connection I/O per tick.
Requests are bounded to 32 KiB and 32 HTTP headers; replies to 1 MiB. Duplicate
Content-Length, chunked transfer encoding, and pipelining are rejected. Connections
close after one HTTP request. Handshake/header/write deadlines are ten seconds;
queued routing allows 130 seconds to accommodate the wire's 120-second PIN wait.
There are no detached I/O workers. Transport tests separately cover framing,
real local TCP, deferred deadlines, reply backpressure, legacy certificate
signatures, wrong keys/transcripts/schemes, and native signer teardown. Windows
and Linux workspace checks pass using the genuine SDK and C toolchains documented
in `docs/cross-compilation.md`; compilation alone does not qualify hardware capture
or a real Moonlight client.

`scripts/test_nvhttp.py` additionally exercises the signed libraries through real
HTTP/TLS with an independent Python cryptographic client. It verifies PIN waiting,
all Gen7 phases, exact peer-certificate pinning, TLS 1.2/1.3, foreign client rejection,
and pairing/revocation across restarts. The test client explicitly accepts legacy
v1 certificate metadata while retaining certificate/signature verification and an
exact DER pin; it never accepts an arbitrary server certificate.

The signed HTTP/TLS integration also covers 40 catalog entries across pages,
escaped titles, rename/delete/new IDs, TLS 1.2/1.3 app lists, stable IDs after
restart, and denial of untrusted or revoked clients.

`scripts/test_public_launch.py` exercises the signed exported-app, RTSP, stream
session, and media composition through real paired HTTPS. It is the integration
gate for launch XML, encrypted RTSP negotiation, UDP discovery, ownership, and
cleanup behavior; the startup advertisement remains a configuration declaration
rather than a replacement for that probe.

Encoder selection preserves legacy unsigned startup ordinals and accepts a full
stable encoder identity or the exact `"auto"`/`"software"` backend selectors.
The selection passes unchanged to video, which resolves non-identity selectors
once before capture allocation. Missing software support fails explicitly; fixture
control success does not qualify real capture, encode, or client playback. See
video selection policy in the separately pinned `amaterasu-encode-video`
repository (`modules/video/README.md`) for bounds and automatic-selection
limits.

## Software encoder policy

Product document v22 persists nullable `sw_preset`, `sw_tune`, `encoder`,
`min_threads`, and `qp` (v21 adds the independent UPnP setting).
An omitted update preserves the current value; null resets tuning to the effective
`superfast`/`zerolatency` defaults and backend selection to the trusted startup
selector. Empty tuning is an explicit raw string, preserved across CAS writes,
readback, restart, and admission. Preset/tune syntax allows at most 128/256 UTF-8
bytes respectively and no control characters; the actual x264 consumer validates
codec names at Open. Backend labels are exactly `auto` and `software`.

Sparse application and certificate-authorized client overrides use the same
signed 32-bit integer domain as the reference C++ parser. `min_threads` defaults
to 2 and QP defaults to 28. ANNOUNCE supplies `videoEncoderSlicesPerFrame`; the
software encoder requests `max(client slices, min_threads)` for x264 thread
count, sliced threading, and slice count. x264 can cap effective threads or
slices for frame dimensions and backend limits. Every field resolves independently, client
before application before global. Null inherits the lower scope. NVHTTP freezes global/client values at
admission and application values at preflight, rejects changed application
readback, and verifies the RTSP encoder/tuning snapshot before completing launch.
RTSP copies this into stream-session and video; real video resolves ordinals and
backend labels once into a stable identity before capture allocation.

QP is persisted and included in each launch and video snapshot. The pinned
reference consumes it for Linux VAAPI constant-quality encoding. Amaterasu has
no VAAPI provider, and x264 uses ABR, so the current software path reports the
effective QP without claiming an encoding effect. A real VAAPI CQP provider is
required to complete `global:qp` parity.

Signed host, application and client editors distinguish inheritance from an
explicit empty string. Host settings expose configured and effective tuning;
`media/encoders` reports the genuine current runtime availability. Disabled
software builds and missing headers/libraries cannot select a software encoder.
See encoder distribution requirements in the `amaterasu-encode-video`
repository (`modules/encode/README.md`, software x264 section).
Auto prefers registered hardware then available x264, with no hardware probing
or fallback after failed hardware Open. Unsupported reference vendor labels are
rejected. Windows software packaging, hardware qualification and live playback
remain gates. The preset, tune, and signed `global:min_threads` contract is
implemented; QP remains incomplete until the native VAAPI CQP consumer exists.

`python scripts/test_software_encoder_policy.py` builds and loads the signed
platform package in an isolated temporary host. It checks authenticated global,
application and certificate-bound persistence, CAS conflicts, exact raw and empty
strings, null reset/inheritance, process restart, forbidden scopes, forged
authority fields and genuine disabled-feature codec availability. It opens only
a loopback management listener. It does not qualify public stream projection,
capture or playback; native software encode and independent decode have separate
opt-in tests in `amaterasu-encode`.

## Steam Streaming Speakers driver policy

Product document v25 stores the global boolean `install_steam_audio_drivers`;
documents v1 through v24 migrate with it enabled. Updates accept only `true` or
`false`, participate in the product revision compare-and-swap, and are returned
by both the signed settings read and update. The setting is intentionally absent
from application and paired-client override schemas.

After the durable document loads or changes, NVHTTP sends the setting and
revision to `amaterasu.audio/1` asynchronously. Provider unavailability is
retried and does not fail NVHTTP startup or block an otherwise successful
settings write. Windows performs best-effort installation only when the active
Steam Streaming Speakers endpoint is absent. Installer and conditional default
role restoration status is available through `POST /v1/media/audio_driver_status`
with an empty object and `media.read`. Machine installation and Windows default
route behavior still require native Windows qualification.
