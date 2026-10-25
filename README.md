# Amaterasu network module source proof

Extracted from committed Amaterasu `a6b0db9e36a1a59328ab4b4785b27b210f8182b7`.
This local-only source workspace owns NVHTTP, RTSP, encrypted control/media
transports and their UPnP helper. The existing service IDs, native exports,
protocol logic and module manifests are unchanged. The pinned SDK foundation
is `fe3004d5889df3eb0ce6f68c74fbef0f33c76e94`; protocol/policy source is
`840e902bc4bfb7a416b4c347f4ab18af155ae0ff` and itself pins that same
foundation. No public remote exists.

Only test fixture paths changed. RTSP tests carry the exact checked-in Moonlight
SDP from `crates/gamestream/src/sdp/fixtures/moonlight-h264.sdp`. NVHTTP TLS
tests carry exact synthetic public fixtures from
`modules/pairing/tests/fixtures/host-cert.pem`, `client-cert.pem`, and
`client-key.pem`; their origin README says the private test key must never be
deployed. Runtime source has no new secret or path access. These small test
copies remove monorepo-relative `include_*` paths; all other source bytes
match the source revision. The SDP is marked binary in `.gitattributes` to
retain CRLF bytes.

`file://` dependency URLs are local proofs, not portable release pins. A stable
approved source location and regenerated lockfile are needed before publication.
Source extraction does not sign, load, bind, or activate any network service.
The host's verified package and caller grants remain authoritative.
