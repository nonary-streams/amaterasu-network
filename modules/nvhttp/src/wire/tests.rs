use super::*;
use crate::encoder_snapshot::{CodecAdvertisement, EncoderSnapshot};
use crate::launch::{CaptureConfig, CaptureProvider, StreamProfile, StreamingConfig};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[test]
fn paired_client_display_mode_decodes_only_as_optional_string() {
    let parsed: ClientConfigOverrides =
        serde_json::from_value(json!({"display_mode":"1920x1080x59.94"})).unwrap();
    assert_eq!(parsed.display_mode.as_deref(), Some("1920x1080x59.94"));
    assert!(
        serde_json::from_value::<ClientConfigOverrides>(json!({"display_mode":59.94})).is_err()
    );
    assert!(
        serde_json::from_value::<ClientConfigOverrides>(json!({"display_mode":null}))
            .unwrap()
            .display_mode
            .is_none()
    );
}

#[test]
fn paired_client_capture_mode_decodes_only_as_a_supported_capture_mode() {
    let parsed: ClientConfigOverrides =
        serde_json::from_value(json!({"capture":"pipewire"})).unwrap();
    assert_eq!(parsed.capture, Some(crate::launch::CaptureMode::PipeWire));
    assert!(
        serde_json::from_value::<ClientConfigOverrides>(json!({"capture":"fallback"})).is_err()
    );
    assert!(serde_json::from_value::<ClientConfigOverrides>(json!({"capture":7})).is_err());
}

#[derive(Default)]
struct Broker {
    next: u64,
    requests: BTreeMap<u64, Value>,
    services: BTreeMap<u64, String>,
    accepted: Vec<Value>,
    cancelled: BTreeSet<u64>,
    approved: bool,
    pause_begin: bool,
    /// Last exported application launch and RTSP session, replayed by the
    /// status and teardown calls of a cleanup.
    launch_template: Option<Value>,
    rtsp_template: Option<Value>,
    cleanup_started: bool,
    unpair_misses: bool,
}

impl Broker {
    fn send(&mut self, command: Command) -> ModuleResult<Response> {
        Ok(match command {
            Command::Request {
                service, payload, ..
            } => {
                assert!(matches!(
                    service.as_str(),
                    PAIRING_SERVICE
                        | "amaterasu.encode/1"
                        | "amaterasu.input/1"
                        | "amaterasu.launch/1"
                        | "amaterasu.rtsp/1"
                        | "amaterasu.stream-session/1"
                ));
                self.next += 1;
                self.accepted.push(payload.clone());
                self.services.insert(self.next, service);
                self.requests.insert(self.next, payload);
                Response::Accepted { id: self.next }
            }
            Command::TakeResult { request } => {
                if self.cancelled.contains(&request) {
                    return Ok(Response::Error {
                        code: "cancelled".into(),
                        message: String::new(),
                    });
                }
                let payload = &self.requests[&request];
                if self.pause_begin && payload["action"] == "begin" {
                    return Ok(Response::Pending);
                }
                let service = &self.services[&request];
                let key = (
                    service.clone(),
                    payload["action"].as_str().unwrap().to_owned(),
                );
                let result = match (key.0.as_str(), key.1.as_str()) {
                    ("amaterasu.input/1", "settings_get") => json!({
                        "ok":true,
                        "persisted":true,
                        "revision":1,
                        "values":{"proton_dualsense_compatibility":true}
                    }),
                    ("amaterasu.stream-session/1", "reserve_history_activity") => json!({
                        "ok":true,"reserved":true,"activity_id":payload["activity_id"],
                        "rtsp_operation_id":payload["rtsp_operation_id"]
                    }),
                    ("amaterasu.stream-session/1", "release_history_activity") => json!({
                        "ok":true,"released":true,"activity_id":payload["activity_id"],
                        "rtsp_operation_id":payload["rtsp_operation_id"]
                    }),
                    (PAIRING_SERVICE, "identity") => {
                        json!({"ok":true,"host_id":"12345678-1234-4234-8234-123456789abc"})
                    }
                    (PAIRING_SERVICE, "check_client_certificate") => {
                        let encoded = payload["certificate_pem"].as_str().unwrap();
                        let (_, certificate_der) =
                            pem_rfc7468::decode_vec(encoded.as_bytes()).unwrap();
                        json!({
                            "ok": true,
                            "paired": 1,
                            "certificate_id": hex(&Sha256::digest(certificate_der)),
                            "client_id": "certificate-bound-client",
                            "config_overrides": {
                                "fec_percentage": 49,
                                "stream_audio": false,
                                "audio_sink": "endpoint.client",
                                "audio_sink_capture_only": true,
                                "back_button_timeout": -1,
                                "controller": false,
                                "gamepad": "auto",
                                "keyboard": false,
                                "mouse": true,
                                "ds4_back_as_touchpad_click": false
                            }
                        })
                    }
                    (PAIRING_SERVICE, "begin") => {
                        json!({"ok":true,"pending":true,"pairing_id":"test-private-pairing-id"})
                    }
                    (PAIRING_SERVICE, "get_server_cert") if !self.approved => {
                        json!({"ok":true,"pending":true,"paired":0})
                    }
                    (PAIRING_SERVICE, "get_server_cert") => {
                        json!({"ok":true,"paired":1,"plaincert":hex(pem().as_bytes())})
                    }
                    (PAIRING_SERVICE, "client_challenge") => {
                        json!({"ok":true,"paired":1,"challengeresponse":"00".repeat(48)})
                    }
                    (PAIRING_SERVICE, "server_challenge_response") => {
                        json!({"ok":true,"paired":1,"pairingsecret":"00".repeat(272)})
                    }
                    (PAIRING_SERVICE, "client_pairing_secret") => {
                        json!({"ok":true,"paired":1,"certificate_id":"00".repeat(32)})
                    }
                    (PAIRING_SERVICE, "cancel") => json!({"ok":true}),
                    (PAIRING_SERVICE, "unpair_presented_client") => json!({
                        "ok":true,
                        "unpaired":if self.unpair_misses { 0 } else { 1 },
                        "certificate_id":"00".repeat(32)
                    }),
                    ("amaterasu.launch/1", "preflight_export") => json!({
                        "ok":true,
                        "preflight_token":"fixture-preflight-token",
                        "cleanup_budget_ms":20_000,
                        "app_id":payload["app_id"],
                        "catalog_revision":0,
                        "config_overrides":{
                            "fec_percentage":37,
                            "stream_audio":true,
                            "audio_sink":"endpoint.app",
                            "audio_sink_capture_only":false,
                            "back_button_timeout":1200,
                            "controller":true,
                            "gamepad":"auto",
                            "keyboard":true,
                            "mouse":false,
                            "ds4_back_as_touchpad_click":true
                        }
                    }),
                    ("amaterasu.launch/1", "launch_export") => json!({
                        "ok": true,
                        "launch": {
                            "launch_id": 1,
                            "operation_id": payload["operation_id"],
                            "app_id": payload["app_id"],
                            "state": "active",
                            "failure": null,
                            "cleanup_error": null,
                            "cleanup_budget_ms":20_000,
                            "frame_limiter_settings":payload["frame_limiter_settings"],
                            "catalog_revision": 0,
                            "application_display_overrides": {},
                            "config_overrides": {
                                "fec_percentage": 37,
                                "stream_audio": true,
                                "audio_sink": "endpoint.app",
                                "audio_sink_capture_only": false,
                                "back_button_timeout": 1200,
                                "controller": true,
                                "gamepad": "auto",
                                "keyboard": true,
                                "mouse": false,
                                "ds4_back_as_touchpad_click":true
                            }
                        }
                    }),
                    ("amaterasu.rtsp/1", "open") => json!({
                        "ok": true,
                        "ticket": 1,
                        "encoder":payload["capture"]["encoder"],"sw_preset":payload["sw_preset"],"sw_tune":payload["sw_tune"],
                        "min_threads":payload["min_threads"],
                        "qp":payload["qp"],
                        "nvenc_settings":payload["nvenc_settings"],
                        "nvenc_spatial_aq":payload["nvenc_spatial_aq"],
                        "rtsp_url": "rtspenc://127.0.0.1:48010",
                        "state": "ready",
                        "frame_limiter_settings": payload["frame_limiter_settings"],
                        "frame_limiter_executable_path": payload["frame_limiter_executable_path"],
                        "display_policy_snapshot": payload["display_policy_snapshot"],
                        "display_request": payload["display_request"],
                        "failure": null,
                        "cleanup_error": null
                    }),
                    ("amaterasu.launch/1", "stop" | "status") => {
                        let mut launch = self.launch_template.clone().expect("exported launch");
                        launch["state"] = json!(if self.cleanup_started {
                            "stopped"
                        } else {
                            "active"
                        });
                        json!({"ok":true,"launch":launch})
                    }
                    ("amaterasu.rtsp/1", "close" | "status") => {
                        self.cleanup_started |= key.1 == "close";
                        let mut session = self.rtsp_template.clone().expect("opened RTSP session");
                        session["state"] = json!(if self.cleanup_started {
                            "closed"
                        } else {
                            "ready"
                        });
                        session
                    }
                    (service, action) => panic!("unexpected service operation {service} {action}"),
                };
                match (key.0.as_str(), key.1.as_str()) {
                    ("amaterasu.launch/1", "launch_export") => {
                        self.launch_template = Some(result["launch"].clone());
                    }
                    ("amaterasu.rtsp/1", "open") => self.rtsp_template = Some(result.clone()),
                    _ => {}
                }
                self.requests.remove(&request);
                self.services.remove(&request);
                Response::Result { payload: result }
            }
            Command::Cancel { request } => {
                self.cancelled.insert(request);
                Response::Ok
            }
            other => panic!("unexpected runtime command {other:?}"),
        })
    }
}

fn router() -> Router {
    Router::new(
        RouterConfig {
            hostname: "Amaterasu & <test>".into(),
            http_port: 47989,
            https_port: 47984,
        },
        LaunchController::new(None).unwrap(),
    )
}

fn streaming_router() -> Router {
    Router::new(
        RouterConfig {
            hostname: "Amaterasu".into(),
            http_port: 47989,
            https_port: 47984,
        },
        LaunchController::new(Some(StreamingConfig {
            capture: CaptureConfig {
                capture_provider: CaptureProvider::Dxgi,
                output: "display-one".into(),
                encoder: amaterasu_module_sdk::EncoderSelection::Index(0),
                audio_endpoint: "default".into(),
            },
            desktop: crate::launch::DesktopSettings::default(),
            profile: StreamProfile {
                codec: amaterasu_media::VideoCodec::H264,
                max_width: 1920,
                max_height: 1080,
                max_fps: 60,
                bitrate_kbps: 10_000,
                max_reference_frames: 1,
                packet_size: 1024,
                fec_percentage: 20,
                min_parity_shards: 2,
                max_fec_blocks: 1,
                packet_ms: 10,
                audio_bitrate: 128_000,
                encrypt_video: true,
                encrypt_audio: true,
                permit_legacy_audio_iv_wrap: false,
            },
        }))
        .unwrap(),
    )
}

fn pem() -> String {
    pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, &[1, 2, 3]).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn begin_target() -> String {
    format!(
        "/pair?uniqueid=client-1&phrase=getservercert&salt={}&clientcert={}&devicename=Living+room&uuid=request-uuid",
        "00".repeat(16),
        hex(pem().as_bytes())
    )
}

fn request(target: &str) -> Request {
    Request {
        method: "GET".into(),
        target: target.into(),
        body: Vec::new(),
    }
}

fn dispatch(
    router: &mut Router,
    broker: &mut Broker,
    connection: u64,
    target: &str,
    now: Instant,
) -> Option<Reply> {
    router.dispatch_with(
        connection,
        request(target),
        peer("127.0.0.1", false, None, false),
        now,
        &mut |command| broker.send(command),
    )
}

fn poll(router: &mut Router, broker: &mut Broker, now: Instant) -> Vec<(u64, Reply)> {
    router.poll_with(now, &mut |command| broker.send(command))
}

fn ready(router: &mut Router, broker: &mut Broker, now: Instant) {
    broker.approved = true;
    assert!(dispatch(router, broker, 1, &begin_target(), now).is_none());
    for _ in 0..3 {
        assert!(poll(router, broker, now).is_empty());
    }
    let result = poll(router, broker, now);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].1.status, 200);
}

#[test]
fn query_rejects_duplicate_escaped_fields_and_bounded_malformed_input() {
    for target in [
        "/pair?uniqueid=a&unique%69d=b",
        "/pair?uniqueid=a&phase=%",
        "/pair?uniqueid=%00",
        "/pair?devicename=%C2%85",
        "/pair?uniqueid=%GG",
        "/pair?uniqueid=%ff",
        "/pair?missingequals",
        "https://attacker/pair?uniqueid=a",
    ] {
        assert!(Query::parse(target).is_err(), "{target}");
    }
    assert!(Query::parse(&format!("/pair?x={}", "a".repeat(query::MAX_TARGET))).is_err());
    let fields = (0..25)
        .map(|index| format!("x{index}=y"))
        .collect::<Vec<_>>()
        .join("&");
    assert!(Query::parse(&format!("/pair?{fields}")).is_err());
    let parsed = Query::parse("/pair?devicename=Living+room%26TV&uniqueid=client").unwrap();
    assert_eq!(parsed.get("devicename"), Some("Living room&TV"));
}

#[test]
fn xml_escapes_metadata_and_advertises_configured_streaming_honestly() {
    assert_eq!(xml::escape("<&>\"'"), "&lt;&amp;&gt;&quot;&apos;");
    let response = xml::server_info(
        &router().config,
        "host-id",
        false,
        0,
        false,
        false,
        CodecAdvertisement::NONE,
    );
    let text = String::from_utf8(response.body).unwrap();
    assert!(text.contains("Amaterasu &amp; &lt;test&gt;"));
    assert!(text.contains("<appversion>7.1.0.0</appversion>"));
    assert!(text.contains("<ServerCodecModeSupport>0</ServerCodecModeSupport>"));
    assert!(text.contains("<MaxLumaPixelsHEVC>0</MaxLumaPixelsHEVC>"));
    assert!(text.contains("<PairStatus>0</PairStatus>"));
    assert!(text.contains("<currentgame>0</currentgame>"));
    assert!(text.contains("<StreamingSupported>0</StreamingSupported>"));
}

#[test]
fn hostname_updates_change_the_default_launch_device_name() {
    let mut router = streaming_router();
    router.set_hostname("Studio PC".into());
    let mut broker = Broker::default();
    let now = Instant::now();
    let target = concat!(
        "/launch?appid=7&mode=1280x720x60&",
        "rikey=00112233445566778899aabbccddeeff&rikeyid=17"
    );
    assert!(
        router
            .dispatch_with(
                19,
                request(target),
                peer("127.0.0.1", true, Some(vec![1, 2, 3]), true),
                now,
                &mut |command| broker.send(command),
            )
            .is_none()
    );

    let mut replies = Vec::new();
    for _ in 0..16 {
        replies.extend(poll(&mut router, &mut broker, now));
        if !replies.is_empty() {
            break;
        }
    }
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].1.status, 200);
    let rtsp_open = broker
        .accepted
        .iter()
        .find(|payload| payload["action"] == "open")
        .expect("RTSP open request");
    assert_eq!(rtsp_open["device_name"], "Studio PC");
}

#[test]
fn configured_streaming_advertises_only_the_supported_h264_codec() {
    let response = xml::server_info(
        &router().config,
        "host-id",
        true,
        0,
        true,
        true,
        EncoderSnapshot::default().advertisement(),
    );
    let text = String::from_utf8(response.body).unwrap();
    let expected_version = if cfg!(target_os = "linux") {
        "7.1.431.-1"
    } else {
        "7.1.431.0"
    };
    assert!(text.contains(&format!("<appversion>{expected_version}</appversion>")));
    assert!(text.contains("<StreamingSupported>1</StreamingSupported>"));
    assert!(text.contains("<currentgame>0</currentgame>"));
    assert!(text.contains("<state>AMATERASU_SERVER_BUSY</state>"));
    assert!(text.contains("<ServerCodecModeSupport>1</ServerCodecModeSupport>"));
    assert!(text.contains("<MaxLumaPixelsHEVC>0</MaxLumaPixelsHEVC>"));
}

#[test]
fn serverinfo_codec_mask_and_hevc_luma_follow_the_encoder_snapshot() {
    let encoder = |codec: &str, hardware: bool| {
        json!({"identity":{"clsid":format!("test.{codec}.{hardware}"),"hardware_url":null,
            "friendly_name":codec},"name":codec,"codec":codec,"hardware":hardware,
            "vendor_id":null})
    };
    let cases = [
        (vec![encoder("h264", false)], "1", "0"),
        (
            vec![encoder("h264", true), encoder("hevc", true)],
            "257",
            "1869449984",
        ),
        (
            vec![encoder("h264", true), encoder("av1", true)],
            "65537",
            "0",
        ),
        (
            vec![
                encoder("h264", true),
                encoder("hevc", true),
                encoder("av1", true),
            ],
            "65793",
            "1869449984",
        ),
    ];
    for (encoders, mask, luma) in cases {
        let snapshot =
            EncoderSnapshot::parse(&json!({"ok":true,"enabled":true,"encoders":encoders})).unwrap();
        let response = xml::server_info(
            &router().config,
            "host-id",
            true,
            0,
            false,
            true,
            snapshot.advertisement(),
        );
        let text = String::from_utf8(response.body).unwrap();
        assert!(
            text.contains(&format!(
                "<ServerCodecModeSupport>{mask}</ServerCodecModeSupport>"
            )),
            "{text}"
        );
        assert!(text.contains(&format!("<MaxLumaPixelsHEVC>{luma}</MaxLumaPixelsHEVC>")));
    }
}

#[test]
fn public_launch_requires_paired_tls_before_parsing_private_fields() {
    let mut router = router();
    let mut broker = Broker::default();
    let now = Instant::now();
    let malformed = "/launch?appid=bad&mode=bad&rikey=bad&rikeyid=bad";
    let response = router
        .dispatch_with(
            1,
            request(malformed),
            peer("127.0.0.1", true, Some(vec![1, 2, 3]), false),
            now,
            &mut |command| broker.send(command),
        )
        .unwrap();
    assert_eq!(response.status, 401);
    assert!(broker.accepted.is_empty());

    let response = router
        .dispatch_with(
            2,
            request(malformed),
            peer("127.0.0.1", true, Some(vec![1, 2, 3]), true),
            now,
            &mut |command| broker.send(command),
        )
        .unwrap();
    assert_eq!(response.status, 400);
    assert!(broker.accepted.is_empty());
}

#[test]
fn launch_identity_and_client_override_come_from_the_authenticated_certificate() {
    let mut router = streaming_router();
    router
        .launches
        .set_audio_sink_settings(Some("endpoint.global"));
    router.launches.set_audio_sink_capture_only(true);
    let mut broker = Broker::default();
    let now = Instant::now();
    let target = concat!(
        "/launch?appid=7&mode=1280x720x60&",
        "rikey=00112233445566778899aabbccddeeff&rikeyid=17&uniqueid=forged-client",
        "&clientName=Moonlight+Desk&localAudioPlayMode=1"
    );
    assert!(
        router
            .dispatch_with(
                19,
                request(target),
                peer("127.0.0.1", true, Some(vec![1, 2, 3]), true),
                now,
                &mut |command| broker.send(command),
            )
            .is_none()
    );

    assert!(poll(&mut router, &mut broker, now).is_empty());
    let pairing_lookup = broker
        .accepted
        .iter()
        .find(|payload| payload["action"] == "check_client_certificate")
        .unwrap();
    assert_eq!(pairing_lookup["certificate_pem"], pem());
    assert!(pairing_lookup.get("uniqueid").is_none());

    let mut replies = Vec::new();
    for _ in 0..12 {
        replies.extend(poll(&mut router, &mut broker, now));
        if !replies.is_empty() {
            break;
        }
    }
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].0, 19);
    assert_eq!(replies[0].1.status, 200);

    let launch = broker
        .accepted
        .iter()
        .find(|payload| payload["action"] == "launch_export")
        .unwrap();
    assert_eq!(launch["app_id"], "app-0000000000000007");
    let rtsp_open = broker
        .accepted
        .iter()
        .find(|payload| payload["action"] == "open")
        .unwrap();
    // The pairing record's certificate-keyed value outranks the app value (37)
    // and global value (20). The query's forged uniqueid has no effect.
    assert_eq!(rtsp_open["profile"]["fec_percentage"], 49);
    assert_eq!(rtsp_open["stream_audio"], false);
    assert_eq!(rtsp_open["capture"]["audio_endpoint"], "endpoint.client");
    assert_eq!(rtsp_open["capture"]["host_audio_enabled"], true);
    assert_eq!(rtsp_open["capture_sink_without_routing"], true);
    assert_eq!(rtsp_open["device_name"], "Moonlight Desk");
    // The authenticated certificate-scoped explicit disable wins over the app.
    assert_eq!(rtsp_open["back_button_timeout"], -1);
    assert_eq!(rtsp_open["controller"], false);
    assert_eq!(rtsp_open["gamepad"], "auto");
    assert_eq!(rtsp_open["keyboard"], false);
    assert_eq!(rtsp_open["mouse"], true);
    assert_eq!(rtsp_open["ds4_back_as_touchpad_click"], false);
}

#[test]
fn server_certificate_request_is_held_until_pin_approval() {
    let mut router = router();
    let mut broker = Broker::default();
    let now = Instant::now();
    assert!(dispatch(&mut router, &mut broker, 1, &begin_target(), now).is_none());
    for _ in 0..4 {
        assert!(poll(&mut router, &mut broker, now).is_empty());
    }
    assert_eq!(router.jobs.len(), 1);
    assert!(poll(&mut router, &mut broker, now + Duration::from_millis(100)).is_empty());
    broker.approved = true;
    let later = now + Duration::from_millis(300);
    assert!(poll(&mut router, &mut broker, later).is_empty());
    let replies = poll(&mut router, &mut broker, later);
    assert_eq!(replies.len(), 1);
    let text = String::from_utf8(replies[0].1.body.clone()).unwrap();
    assert!(text.contains("<paired>1</paired>"));
    assert!(text.contains("<plaincert>"));
    assert!(!text.contains("pending"));
}

#[test]
fn foreign_peer_duplicate_begin_and_unpair_cannot_consume_a_victim_transcript() {
    let mut router = router();
    let mut broker = Broker::default();
    let now = Instant::now();
    ready(&mut router, &mut broker, now);
    let requests = broker.accepted.len();
    let challenge = format!(
        "/pair?uniqueid=client-1&clientchallenge={}",
        "00".repeat(16)
    );
    let foreign = router
        .dispatch_with(
            2,
            request(&challenge),
            peer("127.0.0.2", false, None, false),
            now,
            &mut |command| broker.send(command),
        )
        .unwrap();
    assert_eq!(foreign.status, 403);
    assert_eq!(
        dispatch(&mut router, &mut broker, 3, &begin_target(), now)
            .unwrap()
            .status,
        409
    );
    // Plaintext unpair is inert: it neither names a victim nor ends a transcript.
    let plaintext = dispatch(
        &mut router,
        &mut broker,
        4,
        "/unpair?uniqueid=client-1",
        now,
    )
    .unwrap();
    assert_eq!(plaintext.status, 200);
    assert!(
        String::from_utf8(plaintext.body)
            .unwrap()
            .contains("<unpaired>0</unpaired>")
    );
    assert_eq!(broker.accepted.len(), requests);
    assert_eq!(router.transcripts.len(), 1);
    assert!(dispatch(&mut router, &mut broker, 5, &challenge, now).is_none());
}

#[test]
fn duplicate_or_out_of_order_phases_never_replay_crypto_calls() {
    let mut router = router();
    let mut broker = Broker::default();
    let now = Instant::now();
    ready(&mut router, &mut broker, now);
    let wrong = format!(
        "/pair?uniqueid=client-1&serverchallengeresp={}",
        "00".repeat(32)
    );
    assert_eq!(
        dispatch(&mut router, &mut broker, 2, &wrong, now)
            .unwrap()
            .status,
        409
    );
    let challenge = format!(
        "/pair?uniqueid=client-1&clientchallenge={}",
        "00".repeat(16)
    );
    assert!(dispatch(&mut router, &mut broker, 3, &challenge, now).is_none());
    assert_eq!(
        dispatch(&mut router, &mut broker, 4, &challenge, now)
            .unwrap()
            .status,
        409
    );
    assert!(poll(&mut router, &mut broker, now).is_empty());
    assert_eq!(poll(&mut router, &mut broker, now)[0].1.status, 200);
    assert_eq!(
        dispatch(&mut router, &mut broker, 5, &challenge, now)
            .unwrap()
            .status,
        409
    );
    assert_eq!(
        broker
            .accepted
            .iter()
            .filter(|payload| payload["action"] == "client_challenge")
            .count(),
        1
    );
}

#[test]
fn cancelled_begin_is_drained_then_cancelled_by_opaque_id() {
    let mut router = router();
    let mut broker = Broker {
        pause_begin: true,
        ..Default::default()
    };
    let now = Instant::now();
    dispatch(&mut router, &mut broker, 1, &begin_target(), now);
    poll(&mut router, &mut broker, now);
    router.cancel_with(1, now, &mut |command| broker.send(command));
    assert!(poll(&mut router, &mut broker, now).is_empty());
    broker.pause_begin = false;
    for _ in 0..3 {
        assert!(poll(&mut router, &mut broker, now).is_empty());
    }
    assert!(router.transcripts.is_empty());
    assert!(
        broker
            .accepted
            .iter()
            .any(|payload| payload["action"] == "cancel"
                && payload["pairing_id"] == "test-private-pairing-id")
    );
}

#[test]
fn timeout_closes_held_pin_request_and_cancels_the_transcript() {
    let mut router = router();
    let mut broker = Broker::default();
    let now = Instant::now();
    dispatch(&mut router, &mut broker, 1, &begin_target(), now);
    for _ in 0..4 {
        poll(&mut router, &mut broker, now);
    }
    let expired = now + PAIRING_TIMEOUT;
    let replies = poll(&mut router, &mut broker, expired);
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].1.status, 504);
    assert!(router.transcripts.is_empty());
    poll(&mut router, &mut broker, expired);
    poll(&mut router, &mut broker, expired);
    assert!(
        broker
            .accepted
            .iter()
            .any(|payload| payload["action"] == "cancel")
    );
}

#[test]
fn final_pairchallenge_requires_live_tls_trust_and_the_original_certificate() {
    let mut router = router();
    let mut broker = Broker::default();
    let now = Instant::now();
    ready(&mut router, &mut broker, now);
    for (field, length) in [
        ("clientchallenge", 16),
        ("serverchallengeresp", 32),
        ("clientpairingsecret", 272),
    ] {
        let target = format!("/pair?uniqueid=client-1&{field}={}", "00".repeat(length));
        assert!(dispatch(&mut router, &mut broker, 2, &target, now).is_none());
        poll(&mut router, &mut broker, now);
        assert_eq!(poll(&mut router, &mut broker, now)[0].1.status, 200);
    }
    let target = "/pair?uniqueid=client-1&phrase=pairchallenge";
    assert_eq!(
        dispatch(&mut router, &mut broker, 3, target, now)
            .unwrap()
            .status,
        401
    );
    for (certificate, trusted, expected) in [
        (vec![1, 2, 3], false, 401),
        (vec![9], true, 403),
        (vec![1, 2, 3], true, 200),
    ] {
        let reply = router
            .dispatch_with(
                4,
                request(target),
                peer("127.0.0.1", true, Some(certificate), trusted),
                now,
                &mut |command| broker.send(command),
            )
            .unwrap();
        assert_eq!(reply.status, expected);
    }
}

fn peer(
    remote: &str,
    secure: bool,
    peer_certificate: Option<Vec<u8>>,
    peer_trusted: bool,
) -> RequestContext {
    RequestContext {
        remote: remote.parse().unwrap(),
        secure,
        peer_certificate,
        peer_trusted,
    }
}

#[test]
fn configured_hostname_replaces_xml_noncharacters_and_escapes_quotes() {
    let mut config = router().config;
    config.hostname = "A&<\"'\u{fffe}\u{ffff}Z".into();
    let reply = xml::server_info(
        &config,
        "host",
        false,
        0,
        false,
        false,
        CodecAdvertisement::NONE,
    );
    let body = String::from_utf8(reply.body).unwrap();
    assert!(body.contains("<hostname>A&amp;&lt;&quot;&apos;  Z</hostname>"));
    assert!(!body.contains('\u{fffe}'));
    assert!(!body.contains('\u{ffff}'));
}

#[test]
fn committed_hostname_updates_are_visible_in_live_serverinfo_without_restart() {
    let mut router = router();
    let mut broker = Broker::default();
    let now = Instant::now();

    assert!(dispatch(&mut router, &mut broker, 1, "/serverinfo", now).is_none());
    assert!(poll(&mut router, &mut broker, now).is_empty());
    let initial = poll(&mut router, &mut broker, now);
    assert_eq!(initial.len(), 1);
    let initial_body = String::from_utf8(initial[0].1.body.clone()).unwrap();
    assert!(initial_body.contains("<hostname>Amaterasu &amp; &lt;test&gt;</hostname>"));

    router.set_hostname("Living Room & Games".into());
    router.set_ports(48_000, 47_995);
    assert!(dispatch(&mut router, &mut broker, 2, "/serverinfo", now).is_none());
    assert!(poll(&mut router, &mut broker, now).is_empty());
    let updated = poll(&mut router, &mut broker, now);
    assert_eq!(updated.len(), 1);
    let updated_body = String::from_utf8(updated[0].1.body.clone()).unwrap();
    assert!(updated_body.contains("<hostname>Living Room &amp; Games</hostname>"));
    assert!(updated_body.contains("<ExternalPort>48000</ExternalPort>"));
    assert!(updated_body.contains("<HttpsPort>47995</HttpsPort>"));
}

#[test]
fn cancellation_before_begin_dispatch_does_not_create_a_transcript() {
    let mut router = router();
    let mut broker = Broker::default();
    let now = Instant::now();
    dispatch(&mut router, &mut broker, 1, &begin_target(), now);
    router.cancel_with(1, now, &mut |command| broker.send(command));
    assert!(poll(&mut router, &mut broker, now).is_empty());
    assert!(broker.accepted.is_empty());
    assert!(router.transcripts.is_empty());
}

#[test]
fn conflicting_phase_selectors_and_foreign_certificate_do_not_advance() {
    let mut router = router();
    let mut broker = Broker::default();
    let now = Instant::now();
    ready(&mut router, &mut broker, now);
    let invalid = format!(
        "/pair?uniqueid=client-1&phrase=pairchallenge&clientchallenge={}",
        "00".repeat(16)
    );
    assert_eq!(
        dispatch(&mut router, &mut broker, 2, &invalid, now)
            .unwrap()
            .status,
        400
    );
    let replacement =
        pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, &[9, 9, 9]).unwrap();
    let duplicate = begin_target().replace(&hex(pem().as_bytes()), &hex(replacement.as_bytes()));
    assert_eq!(
        dispatch(&mut router, &mut broker, 3, &duplicate, now)
            .unwrap()
            .status,
        409
    );
    let phase = format!(
        "/pair?uniqueid=client-1&clientchallenge={}&clientcert={}",
        "00".repeat(16),
        hex(replacement.as_bytes())
    );
    assert_eq!(
        dispatch(&mut router, &mut broker, 4, &phase, now)
            .unwrap()
            .status,
        403
    );
    assert_eq!(
        broker
            .accepted
            .iter()
            .filter(
                |payload| payload["action"] == "client_challenge" || payload["action"] == "cancel"
            )
            .count(),
        0
    );
    assert_eq!(router.transcripts.len(), 1);
}

fn server_info_text(router: &mut Router, broker: &mut Broker, now: Instant) -> String {
    assert!(dispatch(router, broker, 31, "/serverinfo", now).is_none());
    for _ in 0..4 {
        let replies = poll(router, broker, now);
        if let Some((_, reply)) = replies.into_iter().find(|(id, _)| *id == 31) {
            assert_eq!(reply.status, 200);
            return String::from_utf8(reply.body).unwrap();
        }
    }
    panic!("serverinfo did not complete");
}

fn codec_fields(text: &str) -> (u32, u32) {
    let field = |name: &str| -> u32 {
        let open = format!("<{name}>");
        let start = text.find(&open).unwrap() + open.len();
        let end = text[start..].find('<').unwrap() + start;
        text[start..end].parse().unwrap()
    };
    (field("ServerCodecModeSupport"), field("MaxLumaPixelsHEVC"))
}

const SCM_H264: u32 = 0x1;
const SCM_HEVC: u32 = 0x100;

#[test]
fn serverinfo_without_streaming_never_asks_for_encoders() {
    let mut router = router();
    let mut broker = Broker::default();
    let text = server_info_text(&mut router, &mut broker, Instant::now());
    assert_eq!(codec_fields(&text), (0, 0));
    assert!(
        broker
            .requests
            .values()
            .all(|payload| payload["action"] != "enumerate")
    );
}

#[test]
fn serverinfo_reads_the_shared_encoder_snapshot_without_encoder_calls() {
    let mut router = streaming_router();
    let mut broker = Broker::default();
    let now = Instant::now();
    assert_eq!(
        codec_fields(&server_info_text(&mut router, &mut broker, now)),
        (SCM_H264, 0)
    );
    router.set_encoder_snapshot(
        EncoderSnapshot::parse(
            &json!({"ok":true,"enabled":true,"encoders":[{"codec":"hevc","hardware":true}]}),
        )
        .unwrap(),
    );
    assert_eq!(
        codec_fields(&server_info_text(&mut router, &mut broker, now)),
        (SCM_H264 | SCM_HEVC, 1_869_449_984)
    );
    assert!(
        broker
            .requests
            .values()
            .all(|payload| payload["action"] != "enumerate")
    );
}

const LAUNCH_TARGET: &str = concat!(
    "/launch?appid=7&mode=1280x720x60&",
    "rikey=00112233445566778899aabbccddeeff&rikeyid=17"
);

fn poll_until_reply(router: &mut Router, broker: &mut Broker, now: Instant) -> (u64, Reply) {
    for _ in 0..32 {
        if let Some(reply) = poll(router, broker, now).into_iter().next() {
            return reply;
        }
    }
    panic!("no reply was produced");
}

fn trusted_tls(certificate: &[u8]) -> RequestContext {
    peer("127.0.0.1", true, Some(certificate.to_vec()), true)
}

fn unpair_over_tls(
    router: &mut Router,
    broker: &mut Broker,
    connection: u64,
    now: Instant,
) -> Reply {
    assert!(
        router
            .dispatch_with(
                connection,
                request("/unpair?uniqueid=ignored-metadata"),
                trusted_tls(&[1, 2, 3]),
                now,
                &mut |command| broker.send(command),
            )
            .is_none()
    );
    let (id, reply) = poll_until_reply(router, broker, now);
    assert_eq!(id, connection);
    reply
}

#[test]
fn plaintext_unpair_answers_unpaired_zero_and_calls_no_service() {
    let mut router = streaming_router();
    let mut broker = Broker::default();
    let now = Instant::now();
    for target in ["/unpair", "/unpair?uniqueid=victim&uuid=1234"] {
        let reply = dispatch(&mut router, &mut broker, 1, target, now).unwrap();
        assert_eq!(reply.status, 200);
        assert!(!reply.requires_paired_tls);
        let body = String::from_utf8(reply.body).unwrap();
        assert!(body.contains("<unpaired>0</unpaired>"), "{body}");
    }
    assert!(broker.accepted.is_empty());
}

#[test]
fn untrusted_tls_unpair_is_rejected_without_a_service_call() {
    let mut router = router();
    let mut broker = Broker::default();
    let reply = router
        .dispatch_with(
            1,
            request("/unpair"),
            peer("127.0.0.1", true, Some(vec![9, 9, 9]), false),
            Instant::now(),
            &mut |command| broker.send(command),
        )
        .unwrap();
    assert_eq!(reply.status, 401);
    assert!(broker.accepted.is_empty());
}

#[test]
fn paired_tls_unpair_removes_the_presented_certificate_and_answers_one() {
    let mut router = router();
    let mut broker = Broker::default();
    let now = Instant::now();
    let reply = unpair_over_tls(&mut router, &mut broker, 5, now);
    assert_eq!(reply.status, 200);
    // The certificate stops being trusted the moment the removal commits; the
    // acknowledgement must still reach the client that asked for it.
    assert!(!reply.requires_paired_tls);
    let delivered = reply.authorize(false);
    assert_eq!(delivered.status, 200);
    let body = String::from_utf8(delivered.body).unwrap();
    assert!(body.contains("<unpaired>1</unpaired>"), "{body}");

    let removal = broker
        .accepted
        .iter()
        .find(|payload| payload["action"] == "unpair_presented_client")
        .unwrap();
    assert_eq!(removal["certificate_pem"], pem());
    assert!(removal.get("uniqueid").is_none());
    assert!(removal.get("certificate_id").is_none());
}

#[test]
fn paired_tls_unpair_reports_zero_when_nothing_was_removed() {
    let mut router = router();
    let mut broker = Broker {
        unpair_misses: true,
        ..Broker::default()
    };
    let reply = unpair_over_tls(&mut router, &mut broker, 5, Instant::now());
    assert_eq!(reply.status, 200);
    let body = String::from_utf8(reply.body).unwrap();
    assert!(body.contains("<unpaired>0</unpaired>"), "{body}");
}

#[test]
fn unpair_rejects_unknown_query_fields_before_calling_the_pairing_service() {
    let mut router = router();
    let mut broker = Broker::default();
    let reply = router
        .dispatch_with(
            1,
            request("/unpair?certificate_id=00"),
            trusted_tls(&[1, 2, 3]),
            Instant::now(),
            &mut |command| broker.send(command),
        )
        .unwrap();
    assert_eq!(reply.status, 400);
    assert!(broker.accepted.is_empty());
}

#[test]
fn resume_requires_complete_launch_metadata_and_paired_tls() {
    let mut router = router();
    let mut broker = Broker::default();
    let trusted = router
        .dispatch_with(
            1,
            request("/resume?uniqueid=client"),
            trusted_tls(&[1, 2, 3]),
            Instant::now(),
            &mut |command| broker.send(command),
        )
        .unwrap();
    assert_eq!(trusted.status, 400);
    let plaintext = dispatch(&mut router, &mut broker, 2, "/resume", Instant::now()).unwrap();
    assert_eq!(plaintext.status, 401);
    assert!(broker.accepted.is_empty());
}

#[test]
fn unpairing_a_client_cancels_its_active_launch_through_the_revoke_path() {
    let mut router = streaming_router();
    let mut broker = Broker::default();
    let now = Instant::now();
    assert!(
        router
            .dispatch_with(
                19,
                request(LAUNCH_TARGET),
                trusted_tls(&[1, 2, 3]),
                now,
                &mut |command| broker.send(command),
            )
            .is_none()
    );
    let (_, launched) = poll_until_reply(&mut router, &mut broker, now);
    assert_eq!(launched.status, 200);
    router.reply_delivered(19);
    let owner = PeerIdentity::new("127.0.0.1".parse().unwrap(), vec![1, 2, 3]).unwrap();
    assert_eq!(router.launches.current_game(&owner), 7);
    assert!(router.launches.busy());

    let reply = unpair_over_tls(&mut router, &mut broker, 20, now);
    assert!(
        String::from_utf8(reply.body)
            .unwrap()
            .contains("<unpaired>1</unpaired>")
    );

    // Mirrors NvhttpModule::tick: after the pairing authority drops the
    // certificate, every non-terminal launch it owns is revoked.
    let unrelated = [9u8, 9, 9];
    router.revoke_untrusted(|certificate| certificate == unrelated);
    let actions = |broker: &Broker| {
        broker
            .accepted
            .iter()
            .filter_map(|payload| payload["action"].as_str().map(str::to_owned))
            .collect::<Vec<_>>()
    };
    for _ in 0..64 {
        poll(&mut router, &mut broker, now);
        if !router.launches.busy() {
            break;
        }
    }
    let actions = actions(&broker);
    assert!(actions.contains(&"close".to_owned()), "{actions:?}");
    assert!(actions.contains(&"stop".to_owned()), "{actions:?}");
    assert!(!router.launches.busy());
    assert_eq!(router.launches.current_game(&owner), 0);
}

#[test]
fn untrusted_tls_serverinfo_is_an_http_success_carrying_xml_401() {
    let mut router = router();
    let mut broker = Broker::default();
    let reply = router
        .dispatch_with(
            1,
            request("/serverinfo?uniqueid=client"),
            peer("127.0.0.1", true, Some(vec![9, 9, 9]), false),
            Instant::now(),
            &mut |command| broker.send(command),
        )
        .unwrap();
    // A non-2xx HTTP status makes moonlight-qt report the host offline instead
    // of falling back to plain-HTTP /serverinfo; the XML status drives that.
    assert_eq!(reply.status, 200);
    let body = String::from_utf8(reply.body).unwrap();
    assert!(body.contains("status_code=\"401\""), "{body}");
    assert!(!body.contains("PairStatus"));
    assert!(broker.accepted.is_empty());
}
