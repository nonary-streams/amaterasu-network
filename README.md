# Amaterasu network module source (publication candidate)

This workspace holds NVHTTP, RTSP, encrypted control/media transports and
UPnP. Its proposed portable Cargo pins reference exact commits of
`nonary-streams/amaterasu-sdk` and `nonary-streams/amaterasu-protocol`. The
committed lockfile preserves the vetted `yoke-derive 0.8.3` resolution because
a fresh offline solve cannot select that yanked version; a dependency update
needs separate review. `cargo test --workspace --locked --offline --no-run`
compiled all test binaries locally without binding sockets.

RTSP tests include a copied synthetic Moonlight SDP. NVHTTP TLS tests include
public synthetic certificates and a **test-only private key** copied from the
committed pairing fixtures; it must never be deployed or mistaken for a user
credential. See `modules/nvhttp/tests/fixtures/README.pairing-source.md`.
The host's signed package and caller grants still control every service.
Source publication creates no listener or runtime permission. The Amaterasu
source license remains pending.
