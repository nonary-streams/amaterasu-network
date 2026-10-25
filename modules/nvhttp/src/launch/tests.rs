use super::*;
use amaterasu_module_sdk::{Command, Response};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

fn config() -> StreamingConfig {
    StreamingConfig {
        capture: CaptureConfig {
            capture_provider: CaptureProvider::Dxgi,
            output: "display-one".into(),
            encoder: amaterasu_module_sdk::EncoderSelection::Index(0),
            audio_endpoint: "default".into(),
        },
        desktop: DesktopSettings::default(),
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
    }
}

fn encoder_entry(clsid: &str, codec: &str, hardware: bool) -> Value {
    json!({"identity":{"clsid":clsid,"hardware_url":null,"friendly_name":clsid},
        "name":clsid,"codec":codec,"hardware":hardware,"vendor_id":null})
}

fn encoders(entries: Vec<Value>) -> EncoderSnapshot {
    EncoderSnapshot::parse(&json!({"ok":true,"enabled":true,"encoders":entries})).unwrap()
}

/// A hardware H.264 encoder: launches above the software limit offer H.264.
fn hardware_h264() -> EncoderSnapshot {
    encoders(vec![encoder_entry("test.hardware.h264", "h264", true)])
}

#[test]
fn signed_stream_profile_codec_defaults_to_h264_and_serializes_hevc_explicitly() {
    let mut configured = config();
    let legacy = serde_json::to_value(&configured).unwrap();
    assert!(legacy["profile"].get("codec").is_none());
    assert_eq!(
        serde_json::from_value::<StreamingConfig>(legacy)
            .unwrap()
            .profile
            .codec,
        amaterasu_media::VideoCodec::H264
    );
    configured.profile.codec = amaterasu_media::VideoCodec::Hevc;
    assert!(configured.validate().is_ok());
    let selected = serde_json::to_value(&configured).unwrap();
    assert_eq!(selected["profile"]["codec"], "hevc");
}

#[test]
fn linux_pipewire_profile_accepts_auto_encoder_selection() {
    let mut value = serde_json::to_value(config()).unwrap();
    value["capture"]["capture_provider"] = json!("pipewire");
    value["capture"]["encoder"] = json!("auto");

    let streaming: StreamingConfig = serde_json::from_value(value.clone()).unwrap();
    assert!(streaming.validate().is_ok());
    assert_eq!(
        streaming.capture.capture_provider,
        CaptureProvider::PipeWire
    );
    assert_eq!(
        streaming.capture.encoder,
        EncoderSelection::Backend(amaterasu_module_sdk::EncoderBackend::Auto)
    );
    let automatic_value = serde_json::to_value(&streaming).unwrap();
    assert_eq!(automatic_value["capture"]["encoder"], "auto");
    value["capture"]["encoder"] = json!(0);
    let indexed: StreamingConfig = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(indexed.capture.encoder, EncoderSelection::Index(0));
    let indexed_value = serde_json::to_value(&indexed).unwrap();
    assert_eq!(indexed_value["capture"]["encoder"], 0);

    value["capture"]["encoder"] = json!("software");
    let software: StreamingConfig = serde_json::from_value(value).unwrap();
    assert_eq!(
        software.capture.encoder,
        EncoderSelection::Backend(amaterasu_module_sdk::EncoderBackend::Software)
    );
    assert!(software.validate().is_ok());
}

fn peer(marker: u8) -> PeerIdentity {
    peer_with_fec(marker, None)
}

fn peer_with_fec(marker: u8, fec_percentage: Option<u8>) -> PeerIdentity {
    peer_with_overrides(marker, fec_percentage, None)
}

fn peer_with_proton_override(
    marker: u8,
    proton_dualsense_compatibility: Option<bool>,
) -> PeerIdentity {
    let certificate = vec![marker; 32];
    PeerIdentity::new("127.0.0.1".parse().unwrap(), certificate.clone())
        .unwrap()
        .with_paired_identity(
            format!("client-{marker}"),
            fingerprint(&certificate),
            ClientConfigOverrides {
                proton_dualsense_compatibility,
                ..Default::default()
            },
        )
        .unwrap()
}

fn peer_with_stream_overrides(
    marker: u8,
    max_bitrate: Option<i32>,
    minimum_fps_target: Option<f64>,
    video_max_batch_size_kb: Option<u8>,
) -> PeerIdentity {
    let certificate = vec![marker; 32];
    PeerIdentity::new("127.0.0.1".parse().unwrap(), certificate.clone())
        .unwrap()
        .with_paired_identity(
            format!("client-{marker}"),
            fingerprint(&certificate),
            ClientConfigOverrides {
                max_bitrate,
                minimum_fps_target,
                video_max_batch_size_kb,
                ..Default::default()
            },
        )
        .unwrap()
}

fn peer_with_frame_limiter_overrides(
    marker: u8,
    enable: Option<bool>,
    fps_limit: Option<f64>,
) -> PeerIdentity {
    let certificate = vec![marker; 32];
    PeerIdentity::new("127.0.0.1".parse().unwrap(), certificate.clone())
        .unwrap()
        .with_paired_identity(
            format!("client-{marker}"),
            fingerprint(&certificate),
            ClientConfigOverrides {
                frame_limiter_enable: enable,
                frame_limiter_fps_limit: fps_limit,
                ..Default::default()
            },
        )
        .unwrap()
}

fn peer_with_overrides(
    marker: u8,
    fec_percentage: Option<u8>,
    stream_audio: Option<bool>,
) -> PeerIdentity {
    peer_with_settings(marker, fec_percentage, stream_audio, None)
}

fn peer_with_audio_sink(marker: u8, audio_sink: Option<&str>) -> PeerIdentity {
    peer_with_settings(marker, None, None, audio_sink.map(str::to_owned))
}

fn peer_with_capture_options(
    marker: u8,
    audio_sink: Option<&str>,
    audio_sink_capture_only: Option<bool>,
) -> PeerIdentity {
    let certificate = vec![marker; 32];
    PeerIdentity::new("127.0.0.1".parse().unwrap(), certificate.clone())
        .unwrap()
        .with_paired_identity(
            format!("client-{marker}"),
            fingerprint(&certificate),
            ClientConfigOverrides {
                audio_sink: audio_sink.map(str::to_owned),
                audio_sink_capture_only,
                ..Default::default()
            },
        )
        .unwrap()
}

fn peer_with_virtual_sink(marker: u8, selector: Option<&str>) -> PeerIdentity {
    let certificate = vec![marker; 32];
    PeerIdentity::new("127.0.0.1".parse().unwrap(), certificate.clone())
        .unwrap()
        .with_paired_identity(
            format!("client-{marker}"),
            fingerprint(&certificate),
            ClientConfigOverrides {
                virtual_sink: selector.map(str::to_owned),
                ..Default::default()
            },
        )
        .unwrap()
}

fn opened_rtsp_payload(broker: &Broker) -> Value {
    broker
        .commands
        .iter()
        .find_map(|command| match command {
            Command::Request {
                service, payload, ..
            } if service == "amaterasu.rtsp/1" && payload["action"] == "open" => {
                Some(payload.clone())
            }
            _ => None,
        })
        .expect("RTSP open")
}

fn launch_export_payload(broker: &Broker) -> Value {
    broker
        .commands
        .iter()
        .find_map(|command| match command {
            Command::Request {
                service, payload, ..
            } if service == "amaterasu.launch/1" && payload["action"] == "launch_export" => {
                Some(payload.clone())
            }
            _ => None,
        })
        .expect("launch export")
}

fn peer_with_settings(
    marker: u8,
    fec_percentage: Option<u8>,
    stream_audio: Option<bool>,
    audio_sink: Option<String>,
) -> PeerIdentity {
    let certificate = vec![marker; 32];
    let certificate_id = fingerprint(&certificate);
    PeerIdentity::new("127.0.0.1".parse().unwrap(), certificate)
        .unwrap()
        .with_paired_identity(
            format!("client-{marker}"),
            certificate_id,
            ClientConfigOverrides {
                fec_percentage,
                stream_audio,
                audio_sink,
                ..Default::default()
            },
        )
        .unwrap()
}

fn peer_with_back_button_timeout(marker: u8, timeout: Option<i32>) -> PeerIdentity {
    let certificate = vec![marker; 32];
    PeerIdentity::new("127.0.0.1".parse().unwrap(), certificate.clone())
        .unwrap()
        .with_paired_identity(
            format!("client-{marker}"),
            fingerprint(&certificate),
            ClientConfigOverrides {
                back_button_timeout: timeout,
                ..Default::default()
            },
        )
        .unwrap()
}

fn peer_with_input_overrides(
    marker: u8,
    controller: Option<bool>,
    gamepad: Option<&str>,
    keyboard: Option<bool>,
    mouse: Option<bool>,
) -> PeerIdentity {
    let certificate = vec![marker; 32];
    PeerIdentity::new("127.0.0.1".parse().unwrap(), certificate.clone())
        .unwrap()
        .with_paired_identity(
            format!("client-{marker}"),
            fingerprint(&certificate),
            ClientConfigOverrides {
                controller,
                gamepad: gamepad.map(str::to_owned),
                keyboard,
                mouse,
                ..Default::default()
            },
        )
        .unwrap()
}

fn peer_with_native_pen_touch(marker: u8, native_pen_touch: Option<bool>) -> PeerIdentity {
    let certificate = vec![marker; 32];
    PeerIdentity::new("127.0.0.1".parse().unwrap(), certificate.clone())
        .unwrap()
        .with_paired_identity(
            format!("client-{marker}"),
            fingerprint(&certificate),
            ClientConfigOverrides {
                native_pen_touch,
                ..Default::default()
            },
        )
        .unwrap()
}

fn peer_with_controller_compatibility_overrides(
    marker: u8,
    motion_as_ds4: Option<bool>,
    touchpad_as_ds4: Option<bool>,
    ds5_inputtino_randomize_mac: Option<bool>,
) -> PeerIdentity {
    let certificate = vec![marker; 32];
    PeerIdentity::new("127.0.0.1".parse().unwrap(), certificate.clone())
        .unwrap()
        .with_paired_identity(
            format!("client-{marker}"),
            fingerprint(&certificate),
            ClientConfigOverrides {
                motion_as_ds4,
                touchpad_as_ds4,
                ds5_inputtino_randomize_mac,
                ..Default::default()
            },
        )
        .unwrap()
}

fn peer_with_ds4_back_as_touchpad_click(
    marker: u8,
    ds4_back_as_touchpad_click: Option<bool>,
) -> PeerIdentity {
    let certificate = vec![marker; 32];
    PeerIdentity::new("127.0.0.1".parse().unwrap(), certificate.clone())
        .unwrap()
        .with_paired_identity(
            format!("client-{marker}"),
            fingerprint(&certificate),
            ClientConfigOverrides {
                ds4_back_as_touchpad_click,
                ..Default::default()
            },
        )
        .unwrap()
}

fn request(key: u8) -> LaunchRequest {
    LaunchRequest {
        app_id: 1,
        width: 1280,
        height: 720,
        fps: 60,
        host_audio_enabled: false,
        continuous_audio: false,
        audio_channels: 2,
        device_name: None,
        remote_input_key: [key; 16],
        key_id: 17,
    }
}

fn peer_with_display_mode(marker: u8, display_mode: &str) -> Result<PeerIdentity, &'static str> {
    let certificate = vec![marker; 32];
    PeerIdentity::new("127.0.0.1".parse().unwrap(), certificate.clone())?.with_paired_identity(
        format!("client-{marker}"),
        fingerprint(&certificate),
        ClientConfigOverrides {
            display_mode: Some(display_mode.to_owned()),
            ..Default::default()
        },
    )
}

#[test]
fn paired_physical_mode_freezes_independently_of_stream_cadence_and_retry() {
    let now = Instant::now();
    let mut streaming = config();
    streaming.profile.max_fps = 120;
    let mut controller = Controller::new(Some(streaming)).unwrap();
    controller.set_encoder_snapshot(hardware_h264());
    let paired = peer_with_display_mode(19, "1920x1080x59.94").unwrap();
    let mut stream = request(19);
    stream.fps = 120;
    let mut broker = Broker::default();

    assert!(
        controller
            .launch(10, stream.clone(), paired.clone(), now)
            .is_none()
    );
    let (_, first_reply) = poll_until_reply(&mut controller, &mut broker, now);
    let first_body = String::from_utf8(first_reply.body).unwrap();
    assert!(first_body.contains("<streamWidth>1280</streamWidth>"));
    assert!(first_body.contains("<streamHeight>720</streamHeight>"));
    assert!(first_body.contains("<streamFps>120</streamFps>"));
    assert!(first_body.contains("<physicalDisplayWidth>1920</physicalDisplayWidth>"));
    assert!(first_body.contains("<physicalDisplayHeight>1080</physicalDisplayHeight>"));
    assert!(
        first_body.contains("<physicalDisplayRefreshMilliHz>59940</physicalDisplayRefreshMilliHz>")
    );
    assert!(first_body.contains("<clientDisplayModeOverride>1</clientDisplayModeOverride>"));
    assert_eq!(
        broker.application_snapshot.as_ref().unwrap()["requested_stream_fps_millihz"],
        120000
    );
    assert_eq!(
        broker.application_snapshot.as_ref().unwrap()["client_display_mode_override_millihz"],
        59940
    );
    assert_eq!(opened_rtsp_payload(&broker)["profile"]["fps"], 120);
    controller.reply_delivered(10, now);

    let retry = controller
        .launch(11, stream, paired, now)
        .expect("ready retry");
    assert_eq!(String::from_utf8(retry.body).unwrap(), first_body);
}

#[test]
fn virtual_display_intent_is_frozen_and_admission_bound_before_rtsp_open() {
    let now = Instant::now();
    let settings = json!({
        "virtual_screen": false,
        "virtual_display_mode": "shared",
        "virtual_display_layout": "extended"
    });
    let mut controller = Controller::new(Some(config())).unwrap();
    controller.set_global_display_policy(
        7,
        json!({
            "virtual_display_mode":"disabled",
            "dd_activate_virtual_display":false
        }),
    );
    let mut broker = Broker {
        application_display_settings: Some(settings.clone()),
        ..Broker::default()
    };

    assert!(controller.launch(10, request(33), peer(33), now).is_none());
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(
        reply.status,
        200,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );

    let open = opened_rtsp_payload(&broker);
    let intent = &open["virtual_display_intent"];
    assert_eq!(intent["virtual_display_mode"], "shared");
    assert_eq!(intent["virtual_display_layout"], "extended");
    assert_eq!(intent["dd_activate_virtual_display"], false);
    assert_eq!(intent["request_virtual_display"], true);
    assert_eq!(open["application_display_settings"], settings);
    assert_eq!(
        open["display_policy_snapshot"]["virtual_display_intent"],
        *intent
    );
    assert_eq!(
        open["display_policy_snapshot"]["application_display_settings"],
        settings
    );
    assert_eq!(open["display_admission_token"], "ab".repeat(32));

    let admission = broker
        .commands
        .iter()
        .find_map(|command| match command {
            Command::Request {
                service, payload, ..
            } if service == "amaterasu.launch/1"
                && payload["action"] == "prepare_display_admission" =>
            {
                Some(payload)
            }
            _ => None,
        })
        .expect("signed display admission");
    assert_eq!(admission["virtual_display_intent"], *intent);
    assert_eq!(admission["application_display_settings"], settings);

    let export = broker
        .commands
        .iter()
        .find_map(|command| match command {
            Command::Request {
                service, payload, ..
            } if service == "amaterasu.launch/1" && payload["action"] == "launch_export" => {
                Some(payload)
            }
            _ => None,
        })
        .expect("launch export");
    assert_eq!(export["virtual_display_intent"], *intent);
    assert_eq!(export["application_display_settings"], settings);
}

#[test]
fn malformed_paired_physical_mode_rejects_before_launch_and_absent_inherits_stream() {
    for malformed in [
        "",
        "1920x1080x0",
        "1920x1080x59.9999",
        "1920X1080x60",
        "1920x1080x+60",
        "1920x1080x60x1",
    ] {
        assert!(
            peer_with_display_mode(20, malformed).is_err(),
            "{malformed}"
        );
    }
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut broker = Broker::default();
    assert!(controller.launch(10, request(21), peer(21), now).is_none());
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
    let body = String::from_utf8(reply.body).unwrap();
    assert!(body.contains("<physicalDisplayWidth>1280</physicalDisplayWidth>"));
    assert!(body.contains("<physicalDisplayRefreshMilliHz>60000</physicalDisplayRefreshMilliHz>"));
    assert!(body.contains("<clientDisplayModeOverride>0</clientDisplayModeOverride>"));
    assert!(
        broker.application_snapshot.as_ref().unwrap()["client_display_mode_override_millihz"]
            .is_null()
    );
    assert!(opened_rtsp_payload(&broker)["display_request"].is_null());
}

#[test]
fn settings_reject_unsupported_packetization_before_launch() {
    let mut invalid = config();
    invalid.profile.fec_percentage = 0;
    assert_eq!(invalid.validate().unwrap_err(), "invalid_streaming_profile");
}

#[test]
fn pairing_lookup_identity_must_match_the_certificate_bytes() {
    let certificate = vec![7; 32];
    let peer = PeerIdentity::new("127.0.0.1".parse().unwrap(), certificate.clone()).unwrap();
    assert_eq!(
        peer.with_paired_identity(
            "moonlight-id".into(),
            "00".repeat(32),
            ClientConfigOverrides::default(),
        )
        .err()
        .unwrap(),
        "invalid_paired_identity"
    );
    assert_eq!(
        PeerIdentity::new("127.0.0.1".parse().unwrap(), certificate.clone())
            .unwrap()
            .with_paired_identity(
                "moonlight-id".into(),
                fingerprint(&certificate),
                ClientConfigOverrides {
                    audio_sink: Some("bad\nendpoint".into()),
                    ..Default::default()
                },
            )
            .err()
            .unwrap(),
        "invalid_paired_identity"
    );
    let paired = PeerIdentity::new("127.0.0.1".parse().unwrap(), certificate.clone())
        .unwrap()
        .with_paired_identity(
            "moonlight-id".into(),
            fingerprint(&certificate),
            ClientConfigOverrides {
                fec_percentage: Some(37),
                stream_audio: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(paired.paired_client_id(), Some("moonlight-id"));
}

#[test]
fn disabled_streaming_and_foreign_cancel_fail_without_work() {
    let now = Instant::now();
    let mut disabled = Controller::new(None).unwrap();
    assert_eq!(
        disabled.launch(1, request(1), peer(1), now).unwrap().status,
        503
    );

    let mut controller = Controller::new(Some(config())).unwrap();
    assert!(controller.launch(1, request(1), peer(1), now).is_none());
    assert_eq!(controller.cancel(2, &peer(2), now).unwrap().status, 403);
}

#[test]
fn secret_key_reuse_is_global_but_key_id_reuse_is_allowed_for_fresh_sessions() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    assert!(controller.launch(1, request(1), peer(1), now).is_none());

    let mut changed = request(1);
    changed.app_id = 2;
    assert_eq!(
        controller.launch(2, changed, peer(2), now).unwrap().status,
        409
    );
}

#[test]
fn stream_start_waits_for_persisted_output_settings() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    controller.set_output_name_settings(false, None);

    let reply = controller
        .launch(1, request(1), peer(1), now)
        .expect("unloaded persisted settings reject streaming");
    assert_eq!(reply.status, 503);
    assert!(!controller.busy());
}

#[test]
fn selected_or_default_output_is_snapshotted_into_rtsp_open() {
    for (configured, expected) in [
        (Some("selected-display-id"), "selected-display-id"),
        (None, "display-one"),
    ] {
        let now = Instant::now();
        let mut controller = Controller::new(Some(config())).unwrap();
        controller.set_output_name_settings(true, configured);
        assert!(controller.launch(10, request(1), peer(1), now).is_none());
        // A later settings write affects later sessions, not this launch transaction.
        controller.set_output_name_settings(true, Some("changed-after-launch"));

        let mut broker = Broker::default();
        let _ = poll_until_reply(&mut controller, &mut broker, now);
        let rtsp_open = broker
            .commands
            .iter()
            .find_map(|command| match command {
                Command::Request {
                    service, payload, ..
                } if service == "amaterasu.rtsp/1" && payload["action"] == "open" => Some(payload),
                _ => None,
            })
            .expect("RTSP open request");
        assert_eq!(rtsp_open["capture"]["output"], expected);
    }
}

#[test]
fn configured_device_name_and_moonlight_override_are_snapshotted_separately_from_output() {
    for (override_name, configured, expected) in [
        (None, "Studio PC", "Studio PC"),
        (Some(""), "Studio PC", "Studio PC"),
        (Some("Moonlight Desk"), "Studio PC", "Moonlight Desk"),
    ] {
        let now = Instant::now();
        let mut controller = Controller::new(Some(config())).unwrap();
        controller.set_device_name(configured);
        let mut launch_request = request(1);
        launch_request.device_name = override_name.map(str::to_owned);
        assert!(
            controller
                .launch(10, launch_request, peer(1), now)
                .is_none()
        );

        // The active launch keeps its resolved name after later setting changes.
        controller.set_device_name("Changed after launch");
        let mut broker = Broker::default();
        let _ = poll_until_reply(&mut controller, &mut broker, now);
        let rtsp_open = broker
            .commands
            .iter()
            .find_map(|command| match command {
                Command::Request {
                    service, payload, ..
                } if service == "amaterasu.rtsp/1" && payload["action"] == "open" => Some(payload),
                _ => None,
            })
            .expect("RTSP open request");

        assert_eq!(rtsp_open["device_name"], expected);
        assert_eq!(rtsp_open["capture"]["output"], "display-one");
    }
}

#[test]
fn selected_or_bootstrap_audio_sink_is_snapshotted_into_rtsp_capture_open() {
    for (configured, expected) in [
        (Some("endpoint.selected"), "endpoint.selected"),
        (None, "default"),
    ] {
        let now = Instant::now();
        let mut controller = Controller::new(Some(config())).unwrap();
        controller.set_audio_sink_settings(configured);
        assert!(controller.launch(10, request(1), peer(1), now).is_none());
        controller.set_audio_sink_settings(Some("endpoint.changed"));

        let mut broker = Broker::default();
        let _ = poll_until_reply(&mut controller, &mut broker, now);
        let rtsp_open = broker
            .commands
            .iter()
            .find_map(|command| match command {
                Command::Request {
                    service, payload, ..
                } if service == "amaterasu.rtsp/1" && payload["action"] == "open" => Some(payload),
                _ => None,
            })
            .expect("RTSP open request");
        assert_eq!(rtsp_open["capture"]["audio_endpoint"], expected);
    }
}

#[test]
fn unavailable_selected_audio_sink_fails_without_opening_bootstrap_sink() {
    let now = Instant::now();
    let selected = "endpoint.unavailable";
    let mut controller = Controller::new(Some(config())).unwrap();
    controller.set_audio_sink_settings(Some(selected));
    let mut broker = Broker {
        unavailable_audio_endpoint: Some(selected.into()),
        ..Broker::default()
    };

    assert!(controller.launch(10, request(1), peer(1), now).is_none());
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);

    assert_ne!(reply.status, 200);
    let opened_endpoints: Vec<_> = broker
        .commands
        .iter()
        .filter_map(|command| match command {
            Command::Request {
                service, payload, ..
            } if service == "amaterasu.rtsp/1" && payload["action"] == "open" => {
                payload["capture"]["audio_endpoint"].as_str()
            }
            _ => None,
        })
        .collect();
    assert_eq!(opened_endpoints, [selected]);
}

#[test]
fn audio_sink_overrides_preserve_empty_values_and_apply_client_app_global_precedence() {
    for (app, client, expected) in [
        (None, None, "endpoint.global"),
        (Some("endpoint.app"), None, "endpoint.app"),
        (
            Some("endpoint.app"),
            Some("endpoint.client"),
            "endpoint.client",
        ),
        (Some(""), None, "default"),
        (Some("endpoint.app"), Some(""), "default"),
    ] {
        let now = Instant::now();
        let mut controller = Controller::new(Some(config())).unwrap();
        controller.set_audio_sink_settings(Some("endpoint.global"));
        let mut broker = Broker {
            application_audio_sink: app.map(str::to_owned),
            ..Broker::default()
        };
        assert!(
            controller
                .launch(10, request(1), peer_with_audio_sink(1, client), now)
                .is_none()
        );

        let _ = poll_until_reply(&mut controller, &mut broker, now);
        assert_eq!(opened_audio_endpoint(&broker), expected);
    }
}

#[test]
fn audio_sink_capture_only_requires_an_explicit_resolved_sink_and_uses_client_app_global_precedence()
 {
    let cases = [
        (true, None, None, None, None, None, false, "default"),
        (
            true,
            Some("endpoint.global"),
            None,
            None,
            None,
            None,
            true,
            "endpoint.global",
        ),
        (
            true,
            Some("endpoint.global"),
            Some(false),
            None,
            None,
            None,
            false,
            "endpoint.global",
        ),
        (
            true,
            Some("endpoint.global"),
            Some(true),
            Some(false),
            None,
            None,
            false,
            "endpoint.global",
        ),
        (
            false,
            None,
            Some(true),
            None,
            Some("endpoint.app"),
            None,
            true,
            "endpoint.app",
        ),
        (
            true,
            Some("endpoint.global"),
            Some(false),
            Some(true),
            Some("endpoint.app"),
            Some("endpoint.client"),
            true,
            "endpoint.client",
        ),
        (
            true,
            Some("endpoint.global"),
            None,
            None,
            Some(""),
            None,
            false,
            "default",
        ),
    ];

    for (
        index,
        (
            global_enabled,
            global_sink,
            app_enabled,
            client_enabled,
            app_sink,
            client_sink,
            expected,
            endpoint,
        ),
    ) in cases.into_iter().enumerate()
    {
        let now = Instant::now();
        let mut controller = Controller::new(Some(config())).unwrap();
        controller.set_audio_sink_settings(global_sink);
        controller.set_audio_sink_capture_only(global_enabled);
        let peer = peer_with_capture_options(index as u8 + 20, client_sink, client_enabled);
        let mut broker = Broker {
            application_audio_sink: app_sink.map(str::to_owned),
            application_audio_sink_capture_only: app_enabled,
            ..Broker::default()
        };

        assert!(controller.launch(10, request(1), peer, now).is_none());
        controller.set_audio_sink_capture_only(!global_enabled);
        let _ = poll_until_reply(&mut controller, &mut broker, now);
        let rtsp_open = broker
            .commands
            .iter()
            .find_map(|command| match command {
                Command::Request {
                    service, payload, ..
                } if service == "amaterasu.rtsp/1" && payload["action"] == "open" => Some(payload),
                _ => None,
            })
            .expect("RTSP open request");
        assert_eq!(rtsp_open["capture_sink_without_routing"], expected);
        assert_eq!(rtsp_open["capture"]["audio_endpoint"], endpoint);
    }
}

#[test]
fn scoped_back_button_timeout_uses_client_then_application_and_preserves_disable() {
    for (client, application, expected) in [
        (Some(-1), Some(1200), Some(-1)),
        (Some(250), Some(1200), Some(250)),
        (None, Some(1200), Some(1200)),
        (None, None, None),
    ] {
        let now = Instant::now();
        let mut controller = Controller::new(Some(config())).unwrap();
        let peer = peer_with_back_button_timeout(33, client);
        let mut broker = Broker {
            application_back_button_timeout: application,
            ..Broker::default()
        };
        assert!(controller.launch(10, request(1), peer, now).is_none());
        let _ = poll_until_reply(&mut controller, &mut broker, now);
        let rtsp_open = broker
            .commands
            .iter()
            .find_map(|command| match command {
                Command::Request {
                    service, payload, ..
                } if service == "amaterasu.rtsp/1" && payload["action"] == "open" => Some(payload),
                _ => None,
            })
            .expect("RTSP open request");
        assert_eq!(rtsp_open["back_button_timeout"], json!(expected));
    }
}

#[test]
fn scoped_input_overrides_use_client_then_application_precedence_and_preserve_false() {
    let now = Instant::now();
    let client_gamepad = selected_supported_gamepad_profile();
    let client_peer = peer_with_input_overrides(
        42,
        Some(false),
        Some(client_gamepad),
        Some(false),
        Some(true),
    );
    let mut broker = Broker {
        application_input_overrides: Some(json!({
            "controller":true,
            "gamepad":"auto",
            "keyboard":true,
            "mouse":false
        })),
        ..Broker::default()
    };
    let mut controller = Controller::new(Some(config())).unwrap();
    assert!(
        controller
            .launch(10, request(1), client_peer, now)
            .is_none()
    );
    let _ = poll_until_reply(&mut controller, &mut broker, now);

    let rtsp_open = opened_rtsp_payload(&broker);
    assert_eq!(rtsp_open["controller"], false);
    assert_eq!(rtsp_open["gamepad"], client_gamepad);
    assert_eq!(rtsp_open["keyboard"], false);
    assert_eq!(rtsp_open["mouse"], true);

    let application_only = {
        let now = Instant::now();
        let peer = peer(43);
        let mut broker = Broker {
            application_input_overrides: Some(json!({
                "controller":false,
                "gamepad":"auto",
                "keyboard":true,
                "mouse":false
            })),
            ..Broker::default()
        };
        let mut controller = Controller::new(Some(config())).unwrap();
        assert!(controller.launch(11, request(2), peer, now).is_none());
        let _ = poll_until_reply(&mut controller, &mut broker, now);
        opened_rtsp_payload(&broker)
    };
    assert_eq!(application_only["controller"], false);
    assert_eq!(application_only["gamepad"], "auto");
    assert_eq!(application_only["keyboard"], true);
    assert_eq!(application_only["mouse"], false);
}

#[test]
fn scoped_controller_compatibility_overrides_preserve_false_and_client_precedence() {
    let now = Instant::now();
    let client_peer =
        peer_with_controller_compatibility_overrides(88, Some(false), None, Some(false));
    let mut broker = Broker {
        application_input_overrides: Some(json!({
            "motion_as_ds4":true,
            "touchpad_as_ds4":false,
            "ds5_inputtino_randomize_mac":true,
        })),
        ..Broker::default()
    };
    let mut controller = Controller::new(Some(config())).unwrap();
    assert!(
        controller
            .launch(10, request(1), client_peer, now)
            .is_none()
    );
    let _ = poll_until_reply(&mut controller, &mut broker, now);

    let rtsp_open = opened_rtsp_payload(&broker);
    assert_eq!(rtsp_open["motion_as_ds4"], false);
    assert_eq!(rtsp_open["touchpad_as_ds4"], false);
    assert_eq!(rtsp_open["ds5_inputtino_randomize_mac"], false);

    let now = Instant::now();
    let mut application_broker = Broker {
        application_input_overrides: Some(json!({
            "motion_as_ds4":false,
            "touchpad_as_ds4":true,
            "ds5_inputtino_randomize_mac":false,
        })),
        ..Broker::default()
    };
    let mut application_controller = Controller::new(Some(config())).unwrap();
    assert!(
        application_controller
            .launch(11, request(2), peer(89), now)
            .is_none()
    );
    let _ = poll_until_reply(&mut application_controller, &mut application_broker, now);
    let rtsp_open = opened_rtsp_payload(&application_broker);
    assert_eq!(rtsp_open["motion_as_ds4"], false);
    assert_eq!(rtsp_open["touchpad_as_ds4"], true);
    assert_eq!(rtsp_open["ds5_inputtino_randomize_mac"], false);
}

fn selected_supported_gamepad_profile() -> &'static str {
    #[cfg(windows)]
    {
        "x360"
    }
    #[cfg(target_os = "linux")]
    {
        "xone"
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        "auto"
    }
}

#[test]
fn unavailable_scoped_audio_sink_fails_without_falling_back_to_global() {
    let now = Instant::now();
    let selected = "endpoint.unavailable";
    let mut controller = Controller::new(Some(config())).unwrap();
    controller.set_audio_sink_settings(Some("endpoint.global"));
    let mut broker = Broker {
        application_audio_sink: Some(selected.into()),
        unavailable_audio_endpoint: Some(selected.into()),
        ..Broker::default()
    };

    assert!(controller.launch(10, request(1), peer(1), now).is_none());
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);

    assert_ne!(reply.status, 200);
    assert_eq!(opened_audio_endpoints(&broker), [selected]);
}

#[test]
fn invalid_application_audio_sink_is_rejected_before_rtsp_open() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut broker = Broker {
        application_audio_sink: Some("invalid\nendpoint".into()),
        ..Broker::default()
    };

    assert!(controller.launch(10, request(1), peer(1), now).is_none());
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);

    assert_ne!(reply.status, 200);
    assert!(opened_audio_endpoints(&broker).is_empty());
}

#[test]
fn client_audio_sink_override_does_not_leak_to_another_client() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    controller.set_audio_sink_settings(Some("endpoint.global"));
    let first_peer = peer_with_audio_sink(1, Some("endpoint.client-one"));
    let second_peer = peer_with_audio_sink(2, None);
    let mut broker = Broker::default();

    assert!(
        controller
            .launch(10, request(1), first_peer.clone(), now)
            .is_none()
    );
    let (connection, reply) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(connection, 10);
    assert_eq!(reply.status, 200);
    assert_eq!(opened_audio_endpoint(&broker), "endpoint.client-one");
    controller.reply_delivered(connection, now);

    assert!(controller.cancel(11, &first_peer, now).is_none());
    let (connection, reply) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(connection, 11);
    assert_eq!(reply.status, 200);

    assert!(
        controller
            .launch(12, request(2), second_peer, now)
            .is_none()
    );
    let (connection, reply) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(connection, 12);
    assert_eq!(reply.status, 200);
    assert_eq!(
        opened_audio_endpoints(&broker),
        ["endpoint.client-one", "endpoint.global"]
    );
}

#[test]
fn virtual_sink_overrides_follow_client_app_global_precedence_and_empty_clears_inheritance() {
    fn launch_payload(
        client_selector: Option<&str>,
        application_selector: Option<&str>,
        expected_selector: Option<&str>,
        expected_endpoint: &str,
        expected_capture_only: bool,
    ) -> Value {
        let now = Instant::now();
        let mut controller = Controller::new(Some(config())).unwrap();
        controller.set_audio_sink_settings(Some("endpoint.global"));
        controller.set_audio_sink_capture_only(true);
        controller.set_virtual_sink_settings(Some("virtual.global"));
        let peer = peer_with_virtual_sink(1, client_selector);
        let mut broker = Broker {
            application_virtual_sink: application_selector.map(str::to_owned),
            application_audio_sink: Some("endpoint.application".into()),
            ..Broker::default()
        };

        assert!(controller.launch(10, request(1), peer, now).is_none());
        let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
        assert_eq!(reply.status, 200);
        let payload = opened_rtsp_payload(&broker);
        if let Some(expected_selector) = expected_selector {
            assert_eq!(payload["virtual_sink"], expected_selector);
        } else {
            assert!(payload["virtual_sink"].is_null());
        }
        let expected_channels = expected_selector.map_or(Value::Null, |_| json!(2));
        assert_eq!(payload["channels"], expected_channels);
        assert_eq!(payload["capture"]["audio_endpoint"], expected_endpoint);
        assert_eq!(
            payload["capture_sink_without_routing"],
            expected_capture_only
        );
        payload
    }

    launch_payload(None, None, Some("virtual.global"), "", false);
    launch_payload(
        None,
        Some("virtual.application"),
        Some("virtual.application"),
        "",
        false,
    );
    launch_payload(
        Some("virtual.client"),
        Some("virtual.application"),
        Some("virtual.client"),
        "",
        false,
    );
    // Explicit empty in the client scope clears inherited virtual selectors, then
    // regular endpoint resolution continues from the application preference.
    launch_payload(
        Some(""),
        Some("virtual.application"),
        None,
        "endpoint.application",
        true,
    );
    // Explicit empty in the app scope clears the global selector while the
    // regular application endpoint keeps its capture-only policy.
    launch_payload(None, Some(""), None, "endpoint.application", true);
}

#[test]
fn authenticated_surround_request_reaches_rtsp_and_binds_retry_identity() {
    for (channels, bitrate) in [(6, 256_000), (8, 512_000)] {
        let now = Instant::now();
        let mut settings = config();
        settings.profile.audio_bitrate = bitrate;
        let mut controller = Controller::new(Some(settings)).unwrap();
        let mut broker = Broker::default();
        let mut stream = request(channels as u8);
        stream.audio_channels = channels;
        let paired = peer_with_virtual_sink(channels as u8, Some("virtual.surround"));
        assert!(
            controller
                .launch(10, stream.clone(), paired.clone(), now)
                .is_none()
        );
        let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
        assert_eq!(reply.status, 200);
        let open = opened_rtsp_payload(&broker);
        assert_eq!(open["channels"], channels);
        assert_eq!(open["virtual_sink"], "virtual.surround");
        assert_eq!(open["profile"]["audio_bitrate"], bitrate);
        controller.reply_delivered(10, now);
        assert_eq!(
            controller
                .launch(11, stream.clone(), paired.clone(), now)
                .unwrap()
                .body,
            reply.body
        );
        stream.audio_channels = if channels == 6 { 2 } else { 6 };
        assert_eq!(
            controller.launch(12, stream, paired, now).unwrap().status,
            409
        );
    }
}

#[test]
fn surround_without_virtual_sink_or_supported_bitrate_stops_before_launch() {
    for (sink, bitrate) in [(None, 256_000), (Some("virtual.surround"), 128_000)] {
        let now = Instant::now();
        let mut settings = config();
        settings.profile.audio_bitrate = bitrate;
        let mut controller = Controller::new(Some(settings)).unwrap();
        let mut broker = Broker::default();
        let mut stream = request(6);
        stream.audio_channels = 6;
        let result = controller.launch(10, stream, peer_with_virtual_sink(6, sink), now);
        if bitrate == 128_000 {
            assert_eq!(result.unwrap().status, 400);
        } else {
            assert!(result.is_none());
            let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
            assert_ne!(reply.status, 200);
        }
        assert!(
            !broker
                .actions()
                .iter()
                .any(|(service, action)| *service == "amaterasu.rtsp/1" && *action == "open")
        );
        assert!(!broker.actions().iter().any(
            |(service, action)| *service == "amaterasu.launch/1" && *action == "launch_export"
        ));
    }
}

#[test]
fn surround_uses_frozen_application_sink_and_stream_audio_before_launch() {
    for application_stream_audio in [Some(false), Some(true)] {
        let now = Instant::now();
        let mut settings = config();
        settings.profile.audio_bitrate = 256_000;
        let mut controller = Controller::new(Some(settings)).unwrap();
        let mut broker = Broker {
            application_virtual_sink: Some("virtual.application".into()),
            application_stream_audio,
            ..Broker::default()
        };
        let mut stream = request(7);
        stream.audio_channels = 6;
        assert!(controller.launch(10, stream, peer(7), now).is_none());
        let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
        if application_stream_audio == Some(false) {
            assert_ne!(reply.status, 200);
            assert!(
                !broker
                    .actions()
                    .iter()
                    .any(|(service, action)| *service == "amaterasu.launch/1"
                        && *action == "launch_export")
            );
        } else {
            assert_eq!(reply.status, 200);
            let open = opened_rtsp_payload(&broker);
            assert_eq!(open["virtual_sink"], "virtual.application");
            assert_eq!(open["channels"], 6);
        }
    }
}

#[test]
fn unavailable_selected_output_fails_without_opening_bootstrap_output() {
    let now = Instant::now();
    let selected = "unavailable-display-id";
    let mut controller = Controller::new(Some(config())).unwrap();
    controller.set_output_name_settings(true, Some(selected));
    let mut broker = Broker {
        unavailable_output: Some(selected.into()),
        ..Broker::default()
    };

    assert!(controller.launch(10, request(1), peer(1), now).is_none());
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);

    assert_ne!(reply.status, 200);
    let opened_outputs: Vec<_> = broker
        .commands
        .iter()
        .filter_map(|command| match command {
            Command::Request {
                service, payload, ..
            } if service == "amaterasu.rtsp/1" && payload["action"] == "open" => {
                payload["capture"]["output"].as_str()
            }
            _ => None,
        })
        .collect();
    assert_eq!(opened_outputs, [selected]);
}

struct Broker {
    next: u64,
    results: BTreeMap<u64, Value>,
    commands: Vec<Command>,
    history_reserve_unavailable: bool,
    history_reserve_wrong_identity: bool,
    history_release_unavailable: bool,
    history_release_in_use_once: bool,
    history_reserved: bool,
    input_policy_response: Value,
    input_policy_requests: usize,
    lose_history_reserve_once: bool,
    lost_history_reserve: bool,
    lose_history_release_result_once: bool,
    lost_history_release_result: bool,
    history_release_request: Option<u64>,
    application_state: &'static str,
    application_cleanup_budget: Value,
    application_stop_pending: bool,
    application_terminal_stop_state: Option<&'static str>,
    held_application_stop_request: Option<u64>,
    application_stop_expired: bool,
    fail_rtsp_cleanup: bool,
    wrong_application_id: bool,
    lose_rtsp_open_once: bool,
    lost_rtsp_open: bool,
    application_operation: String,
    application_id: String,
    fail_rtsp_settlement: bool,
    fail_application_settlement: bool,
    unavailable_output: Option<String>,
    unavailable_audio_endpoint: Option<String>,
    unsettled_rtsp: BTreeSet<u64>,
    unsettled_application: BTreeSet<u64>,
    rtsp_closed: bool,
    application_stopped: bool,
    application_unhealthy: bool,
    application_fec_percentage: Option<u8>,
    application_max_bitrate: Option<i32>,
    application_minimum_fps_target: Option<f64>,
    application_video_max_batch_size_kb: Option<u8>,
    application_stream_audio: Option<bool>,
    application_audio_sink: Option<String>,
    application_virtual_sink: Option<String>,
    application_audio_sink_capture_only: Option<bool>,
    application_back_button_timeout: Option<i32>,
    application_input_overrides: Option<Value>,
    application_display_settings: Option<Value>,
    application_snapshot: Option<Value>,
    application_executable_path: Option<String>,
    application_catalog_revision: u64,
    rtsp_snapshot: Option<Value>,
    rtsp_display_policy_snapshot: Option<Value>,
    rtsp_encoder: Value,
    rtsp_sw_preset: Value,
    rtsp_sw_tune: Value,
    rtsp_min_threads: Value,
    rtsp_qp: Value,
    rtsp_nvenc_settings: Value,
    rtsp_nvenc_spatial_aq: Value,
    rtsp_display_request: Option<Value>,
    rtsp_executable_path: Option<String>,
    wrong_rtsp_snapshot: bool,
    wrong_rtsp_display_policy_snapshot: bool,
    reject_rtsp_display_apply: bool,
    missing_rtsp_display_readback: bool,
    reject_launch_export: bool,
    hold_launch_export_result: bool,
    held_launch_export_request: Option<u64>,
    wrong_application_display_overrides: bool,
    display_entries: Vec<Value>,
    display_snapshot_ids: Vec<String>,
    display_snapshot_configuration: Option<Value>,
    display_configuration_drift: bool,
    display_revision_drift: bool,
    display_snapshot_calls: usize,
    reject_display_admission: bool,
    forge_display_admission_hash: bool,
}

impl Default for Broker {
    fn default() -> Self {
        Self {
            next: 0,
            results: BTreeMap::new(),
            commands: Vec::new(),
            history_reserve_unavailable: false,
            history_reserve_wrong_identity: false,
            history_release_unavailable: false,
            history_release_in_use_once: false,
            history_reserved: false,
            input_policy_response: json!({
                "ok":true,
                "persisted":true,
                "revision":1,
                "values":{"proton_dualsense_compatibility":true}
            }),
            input_policy_requests: 0,
            lose_history_reserve_once: false,
            lost_history_reserve: false,
            lose_history_release_result_once: false,
            lost_history_release_result: false,
            history_release_request: None,
            application_state: "active",
            application_cleanup_budget: json!(20_000),
            application_stop_pending: false,
            application_terminal_stop_state: None,
            held_application_stop_request: None,
            application_stop_expired: false,
            fail_rtsp_cleanup: false,
            wrong_application_id: false,
            lose_rtsp_open_once: false,
            lost_rtsp_open: false,
            application_operation: String::new(),
            application_id: "app-0000000000000001".into(),
            fail_rtsp_settlement: false,
            fail_application_settlement: false,
            unavailable_output: None,
            unavailable_audio_endpoint: None,
            unsettled_rtsp: BTreeSet::new(),
            unsettled_application: BTreeSet::new(),
            rtsp_closed: false,
            application_stopped: false,
            application_unhealthy: false,
            application_fec_percentage: None,
            application_max_bitrate: None,
            application_minimum_fps_target: None,
            application_video_max_batch_size_kb: None,
            application_stream_audio: None,
            application_audio_sink: None,
            application_virtual_sink: None,
            application_audio_sink_capture_only: None,
            application_back_button_timeout: None,
            application_input_overrides: None,
            application_display_settings: None,
            application_snapshot: None,
            application_executable_path: None,
            application_catalog_revision: 1,
            rtsp_snapshot: None,
            rtsp_display_policy_snapshot: None,
            rtsp_encoder: Value::Null,
            rtsp_sw_preset: Value::Null,
            rtsp_sw_tune: Value::Null,
            rtsp_min_threads: Value::Null,
            rtsp_qp: Value::Null,
            rtsp_nvenc_settings: Value::Null,
            rtsp_nvenc_spatial_aq: Value::Null,
            rtsp_display_request: None,
            rtsp_executable_path: None,
            wrong_rtsp_snapshot: false,
            wrong_rtsp_display_policy_snapshot: false,
            reject_rtsp_display_apply: false,
            missing_rtsp_display_readback: false,
            reject_launch_export: false,
            hold_launch_export_result: false,
            held_launch_export_request: None,
            wrong_application_display_overrides: false,
            display_entries: Vec::new(),
            display_snapshot_ids: Vec::new(),
            display_snapshot_configuration: None,
            display_configuration_drift: false,
            display_revision_drift: false,
            display_snapshot_calls: 0,
            reject_display_admission: false,
            forge_display_admission_hash: false,
        }
    }
}

impl Broker {
    fn send(&mut self, command: Command) -> Transport {
        self.commands.push(command.clone());
        match command {
            Command::Request {
                service, payload, ..
            } => {
                if self.lose_history_reserve_once
                    && !self.lost_history_reserve
                    && service == "amaterasu.stream-session/1"
                    && payload["action"] == "reserve_history_activity"
                {
                    self.lost_history_reserve = true;
                    self.history_reserved = true;
                    return Err("lost history reservation admission".into());
                }
                if self.lose_rtsp_open_once
                    && !self.lost_rtsp_open
                    && service == "amaterasu.rtsp/1"
                    && payload["action"] == "open"
                {
                    self.lost_rtsp_open = true;
                    return Err("lost admission".into());
                }
                self.next += 1;
                let request = self.next;
                if service == "amaterasu.stream-session/1"
                    && payload["action"] == "release_history_activity"
                    && self.lose_history_release_result_once
                    && !self.lost_history_release_result
                {
                    self.history_release_request = Some(request);
                }
                if self.hold_launch_export_result
                    && service == "amaterasu.launch/1"
                    && payload["action"] == "launch_export"
                {
                    self.held_launch_export_request = Some(request);
                }
                if service == "amaterasu.rtsp/1" && payload["action"] == "close" {
                    self.rtsp_closed = true;
                    self.unsettled_rtsp.insert(request);
                }
                if service == "amaterasu.launch/1" && payload["action"] == "stop" {
                    self.application_stopped = true;
                    if self.application_stop_pending {
                        self.held_application_stop_request = Some(request);
                    }
                    self.unsettled_application.insert(request);
                }
                let result = self.response(&service, &payload);
                self.results.insert(request, result);
                Ok(Response::Accepted { id: request })
            }
            Command::TakeResult { request }
                if self.held_application_stop_request == Some(request) =>
            {
                if self.application_stop_expired {
                    Ok(Response::error("request_ended", "stop RPC expired"))
                } else {
                    Ok(Response::Pending)
                }
            }
            Command::TakeResult { request }
                if self.history_release_request == Some(request)
                    && !self.lost_history_release_result =>
            {
                self.lost_history_release_result = true;
                Err("lost history release result".into())
            }
            Command::TakeResult { request }
                if self.hold_launch_export_result
                    && self.held_launch_export_request == Some(request) =>
            {
                Ok(Response::Pending)
            }
            Command::TakeResult { request }
                if (self.fail_rtsp_settlement && self.unsettled_rtsp.contains(&request))
                    || (self.fail_application_settlement
                        && self.unsettled_application.contains(&request)) =>
            {
                Err("lost result".into())
            }
            Command::TakeResult { request } => Ok(Response::Result {
                payload: self.results.remove(&request).expect("queued result"),
            }),
            Command::Cancel { request } | Command::ReleaseResult { request }
                if (self.fail_rtsp_settlement && self.unsettled_rtsp.contains(&request))
                    || (self.fail_application_settlement
                        && self.unsettled_application.contains(&request)) =>
            {
                Ok(Response::error("unavailable", "fixture settlement failure"))
            }
            Command::Cancel { .. } | Command::ReleaseResult { .. } => Ok(Response::Ok),
            _ => Ok(Response::error("unexpected", "unexpected command")),
        }
    }

    fn response(&mut self, service: &str, payload: &Value) -> Value {
        let action = payload["action"].as_str().unwrap_or_default();
        if service == "amaterasu.input/1" && action == "settings_get" {
            self.input_policy_requests += 1;
            return self.input_policy_response.clone();
        }
        if service == "amaterasu.stream-session/1" {
            return match action {
                "reserve_history_activity" => {
                    if self.history_reserve_unavailable {
                        json!({"ok":true,"reserved":false,"activity_id":payload["activity_id"],
                            "rtsp_operation_id":payload["rtsp_operation_id"]})
                    } else if self.history_reserve_wrong_identity {
                        self.history_reserved = true;
                        json!({"ok":true,"reserved":true,"activity_id":"foreign-activity",
                            "rtsp_operation_id":payload["rtsp_operation_id"]})
                    } else {
                        self.history_reserved = true;
                        json!({"ok":true,"reserved":true,"activity_id":payload["activity_id"],
                            "rtsp_operation_id":payload["rtsp_operation_id"]})
                    }
                }
                "release_history_activity" => {
                    if self.history_release_in_use_once {
                        self.history_release_in_use_once = false;
                        json!({"ok":false,"code":"history_activity_in_use"})
                    } else if self.history_release_unavailable {
                        json!({"ok":false,"released":false,"activity_id":payload["activity_id"],
                            "rtsp_operation_id":payload["rtsp_operation_id"]})
                    } else {
                        let was_reserved = self.history_reserved;
                        self.history_reserved = false;
                        json!({"ok":true,"released":was_reserved,"activity_id":payload["activity_id"],
                            "rtsp_operation_id":payload["rtsp_operation_id"]})
                    }
                }
                _ => panic!("unexpected stream-session action: {action}"),
            };
        }
        if service == "amaterasu.display/1" {
            return match action {
                "snapshot" => {
                    self.display_snapshot_calls += 1;
                    let revision = if self.display_revision_drift && self.display_snapshot_calls > 1
                    {
                        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    } else {
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    };
                    let mut configuration = self
                        .display_snapshot_configuration
                        .clone()
                        .unwrap_or_else(|| {
                            json!({"displays":self.display_snapshot_ids.iter().map(|id| json!({
                        "id":id,"width":1920,"height":1080,
                        "refresh":{"numerator":60,"denominator":1},
                        "x":0,"y":0
                    })).collect::<Vec<_>>()})
                        });
                    if self.display_configuration_drift && self.display_snapshot_calls > 1 {
                        configuration["displays"][0]["width"] = json!(1680);
                    }
                    json!({
                        "ok":true,
                        "topology_revision":revision,
                        "configuration":configuration
                    })
                }
                "enumerate" => {
                    let offset = payload["offset"].as_u64().unwrap() as usize;
                    let rows: Vec<_> = self
                        .display_entries
                        .iter()
                        .skip(offset)
                        .take(32)
                        .cloned()
                        .collect();
                    let next = (offset + rows.len() < self.display_entries.len())
                        .then_some(offset + rows.len());
                    json!({"ok":true,"entries":rows,"next_offset":next})
                }
                _ => panic!("unexpected display mutation: {action}"),
            };
        }
        if service == "amaterasu.rtsp/1" && action == "open" {
            if self.reject_rtsp_display_apply && payload.get("display_request").is_some() {
                return json!({"ok":false,"code":"display_apply_failed"});
            }
            self.rtsp_encoder = payload["capture"]["encoder"].clone();
            self.rtsp_sw_preset = payload["sw_preset"].clone();
            self.rtsp_sw_tune = payload["sw_tune"].clone();
            self.rtsp_min_threads = payload["min_threads"].clone();
            self.rtsp_qp = payload["qp"].clone();
            self.rtsp_nvenc_settings = payload["nvenc_settings"].clone();
            self.rtsp_nvenc_spatial_aq = payload["nvenc_spatial_aq"].clone();
            self.rtsp_snapshot = payload.get("frame_limiter_settings").cloned();
            self.rtsp_display_policy_snapshot = payload.get("display_policy_snapshot").cloned();
            self.rtsp_display_request = payload.get("display_request").cloned();
            self.rtsp_executable_path = payload["frame_limiter_executable_path"]
                .as_str()
                .map(str::to_owned);
        }
        if service == "amaterasu.rtsp/1"
            && self
                .unavailable_output
                .as_deref()
                .is_some_and(|output| action == "open" && payload["capture"]["output"] == output)
        {
            return json!({"ok":false,"code":"not_found"});
        }
        if service == "amaterasu.rtsp/1"
            && self
                .unavailable_audio_endpoint
                .as_deref()
                .is_some_and(|endpoint| {
                    action == "open" && payload["capture"]["audio_endpoint"] == endpoint
                })
        {
            return json!({"ok":false,"code":"not_found"});
        }
        if service == "amaterasu.rtsp/1"
            && (self.unavailable_output.is_some() || self.reject_rtsp_display_apply)
            && action == "lookup"
        {
            return json!({"ok":false,"code":"ticket_not_found"});
        }
        if service == "amaterasu.launch/1" {
            if action == "launch_export" && self.reject_launch_export {
                return json!({"ok":false,"code":"display_admission_denied"});
            }
            if action == "lookup" && self.reject_launch_export {
                return json!({"ok":false,"code":"launch_not_found"});
            }
            if action == "prepare_display_admission" {
                if self.reject_display_admission {
                    return json!({"ok":false,"code":"display_admission_denied"});
                }
                let mut effective = payload["global_overrides"].as_object().unwrap().clone();
                effective.extend(
                    payload["application_display_overrides"]
                        .as_object()
                        .unwrap()
                        .clone(),
                );
                effective.extend(
                    payload["client_display_overrides"]
                        .as_object()
                        .unwrap()
                        .clone(),
                );
                let mut snapshot = json!({
                    "catalog_revision":payload["catalog_revision"],
                    "global_revision":payload["global_revision"],
                    "global_overrides":payload["global_overrides"],
                    "certificate_id":payload["certificate_id"],
                    "application_overrides":payload["application_display_overrides"],
                    "application_display_settings":payload["application_display_settings"],
                    "client_overrides":payload["client_display_overrides"],
                    "effective_overrides":effective,
                });
                if let Some(intent) = payload
                    .get("virtual_display_intent")
                    .filter(|intent| !intent.is_null())
                {
                    snapshot["virtual_display_intent"] = intent.clone();
                }
                return json!({
                    "ok":true,
                    "display_admission_token":"ab".repeat(32),
                    "display_policy_snapshot":snapshot,
                    "application_operation_id":payload["application_operation_id"],
                    "rtsp_operation_id":payload["rtsp_operation_id"],
                    "request_sha256":if self.forge_display_admission_hash { json!("00".repeat(32)) } else { payload["request_sha256"].clone() },
                });
            }
            if action == "preflight_export" {
                let launch = self.response(
                    service,
                    &json!({
                        "action":"launch_export",
                        "operation_id":payload["operation_id"],
                        "app_id":payload["app_id"],
                    }),
                );
                return json!({
                    "ok":true,
                    "preflight_token":"fixture-preflight-token",
                    "app_id":payload["app_id"],
                    "catalog_revision":1,
                    "cleanup_budget_ms":self.application_cleanup_budget,
                    "config_overrides":launch["launch"]["config_overrides"].as_object()
                        .map(|overrides| json!(overrides)).unwrap_or_else(|| json!({})),
                    "application_display_settings":self.application_display_settings,
                    "executable_path":self.application_executable_path,
                });
            }
            if action == "launch_export" {
                self.application_operation = payload["operation_id"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned();
                self.application_id = payload["app_id"].as_str().unwrap_or_default().to_owned();
                self.application_snapshot = payload.get("frame_limiter_settings").cloned();
            }
            let operation = self.application_operation.as_str();
            let app = self.application_id.as_str();
            let launch_id = if self.wrong_application_id { 99 } else { 41 };
            let state = if self.application_stopped
                && let Some(state) = self.application_terminal_stop_state
            {
                state
            } else if self.application_stopped && self.application_stop_pending {
                "stopping"
            } else if action == "stop" || (action == "status" && self.application_stopped) {
                "stopped"
            } else {
                self.application_state
            };
            let mut launch = json!({
                "launch_id": launch_id,
                "operation_id": operation,
                "app_id": app,
                "state": state,
                "session_id": 2,
                "process_id": 3,
                "failure": null,
                "cleanup_error": if self.application_unhealthy {
                    Value::String("fixture_failure".into())
                } else {
                    Value::Null
                },
                "catalog_revision": self.application_catalog_revision,
                "cleanup_budget_ms":self.application_cleanup_budget,
            });
            launch["frame_limiter_settings"] =
                self.application_snapshot.clone().unwrap_or(Value::Null);
            launch["executable_path"] = json!(self.application_executable_path);
            if self.application_fec_percentage.is_some()
                || self.application_max_bitrate.is_some()
                || self.application_minimum_fps_target.is_some()
                || self.application_video_max_batch_size_kb.is_some()
                || self.application_stream_audio.is_some()
                || self.application_audio_sink.is_some()
                || self.application_virtual_sink.is_some()
                || self.application_audio_sink_capture_only.is_some()
                || self.application_back_button_timeout.is_some()
                || self
                    .application_input_overrides
                    .as_ref()
                    .is_some_and(|overrides| {
                        overrides
                            .as_object()
                            .is_some_and(|object| !object.is_empty())
                    })
            {
                let mut config_overrides = json!({});
                if let Some(fec_percentage) = self.application_fec_percentage {
                    config_overrides["fec_percentage"] = json!(fec_percentage);
                }
                if let Some(max_bitrate) = self.application_max_bitrate {
                    config_overrides["max_bitrate"] = json!(max_bitrate);
                }
                if let Some(minimum_fps_target) = self.application_minimum_fps_target {
                    config_overrides["minimum_fps_target"] = json!(minimum_fps_target);
                }
                if let Some(video_max_batch_size_kb) = self.application_video_max_batch_size_kb {
                    config_overrides["video_max_batch_size_kb"] = json!(video_max_batch_size_kb);
                }
                if let Some(stream_audio) = self.application_stream_audio {
                    config_overrides["stream_audio"] = json!(stream_audio);
                }
                if let Some(audio_sink) = &self.application_audio_sink {
                    config_overrides["audio_sink"] = json!(audio_sink);
                }
                if let Some(virtual_sink) = &self.application_virtual_sink {
                    config_overrides["virtual_sink"] = json!(virtual_sink);
                }
                if let Some(capture_only) = self.application_audio_sink_capture_only {
                    config_overrides["audio_sink_capture_only"] = json!(capture_only);
                }
                if let Some(timeout) = self.application_back_button_timeout {
                    config_overrides["back_button_timeout"] = json!(timeout);
                }
                if let Some(input_overrides) = &self.application_input_overrides
                    && let Some(overrides) = input_overrides.as_object()
                {
                    for (key, value) in overrides {
                        config_overrides[key] = value.clone();
                    }
                }
                launch["config_overrides"] = config_overrides;
            }
            launch["application_display_overrides"] =
                super::workflow::application_display_overrides(launch.get("config_overrides"));
            if self.wrong_application_display_overrides {
                launch["application_display_overrides"] = json!({});
            }
            return json!({"ok":true,"launch":launch});
        }
        let state = if action == "close" && self.fail_rtsp_cleanup {
            "cleanup_failed"
        } else if action == "close" {
            "closed"
        } else if action == "status" && self.fail_rtsp_cleanup {
            "cleanup_failed"
        } else if action == "status" && self.rtsp_closed {
            "closed"
        } else {
            "ready"
        };
        let wrong_rtsp_snapshot = self.wrong_rtsp_snapshot;
        self.wrong_rtsp_snapshot = false;
        let wrong_rtsp_display_policy_snapshot = self.wrong_rtsp_display_policy_snapshot;
        self.wrong_rtsp_display_policy_snapshot = false;
        let missing_rtsp_display_readback = self.missing_rtsp_display_readback;
        self.missing_rtsp_display_readback = false;
        json!({
            "ok": true,
            "ticket": 71,
            "state": state,
            "local": "127.0.0.1:48010",
            "rtsp_url": "rtspenc://127.0.0.1:48010/launch-47",
            "session": 11,
            "stream_state": "prepared",
            "encoder":self.rtsp_encoder,"sw_preset":self.rtsp_sw_preset,"sw_tune":self.rtsp_sw_tune,
            "min_threads":self.rtsp_min_threads,
            "qp":self.rtsp_qp,
            "nvenc_settings":self.rtsp_nvenc_settings,
            "nvenc_spatial_aq":self.rtsp_nvenc_spatial_aq,
            "frame_limiter_settings": if wrong_rtsp_snapshot {
                json!({"wrong":"snapshot"})
            } else {
                self.rtsp_snapshot.clone().unwrap_or(Value::Null)
            },
            "frame_limiter_executable_path": self.rtsp_executable_path,
            "display_policy_snapshot": if wrong_rtsp_display_policy_snapshot {
                json!({"forged":true})
            } else {
                self.rtsp_display_policy_snapshot.clone().unwrap_or(Value::Null)
            },
            "display_request": self.rtsp_display_request.clone().unwrap_or(Value::Null),
            "display_applied": state == "ready" && self.rtsp_display_request.is_some()
                && !missing_rtsp_display_readback,
            "failure": null,
            "cleanup_error": if state == "cleanup_failed" {
                Value::String("fixture_failure".into())
            } else {
                Value::Null
            },
        })
    }

    fn actions(&self) -> Vec<(&str, &str)> {
        self.commands
            .iter()
            .filter_map(|command| match command {
                Command::Request {
                    service, payload, ..
                } => Some((
                    service.as_str(),
                    payload["action"].as_str().unwrap_or_default(),
                )),
                _ => None,
            })
            .collect()
    }
}

fn poll_until_reply(
    controller: &mut Controller,
    broker: &mut Broker,
    now: Instant,
) -> (u64, Reply) {
    for _ in 0..32 {
        let replies = controller.poll(now, &mut |command| broker.send(command));
        if let Some(reply) = replies.into_iter().next() {
            return reply;
        }
    }
    panic!("lifecycle did not produce a bounded reply")
}

fn poll_until_reply_with_trust(
    controller: &mut Controller,
    broker: &mut Broker,
    now: Instant,
    mut trusted: impl FnMut(&[u8]) -> bool,
) -> (u64, Reply) {
    for _ in 0..32 {
        let replies =
            controller.poll_with_trust(now, &mut |command| broker.send(command), &mut trusted);
        if let Some(reply) = replies.into_iter().next() {
            return reply;
        }
    }
    panic!("trusted lifecycle did not produce a bounded reply")
}

fn poll_until_stopped(controller: &mut Controller, broker: &mut Broker, now: Instant, id: u64) {
    for _ in 0..32 {
        if controller
            .records
            .get(&id)
            .is_some_and(|record| record.state == State::Stopped)
        {
            return;
        }
        controller.poll(now, &mut |command| broker.send(command));
    }
    panic!("cleanup did not reach Stopped")
}

fn launch_ready(controller: &mut Controller, broker: &mut Broker, now: Instant) {
    assert!(controller.launch(10, request(1), peer(1), now).is_none());
    let (connection, reply) = poll_until_reply(controller, broker, now);
    assert_eq!(connection, 10);
    assert_eq!(reply.status, 200);
    assert!(
        String::from_utf8(reply.body)
            .unwrap()
            .contains("rtspenc://")
    );
    controller.reply_delivered(connection, now);
    assert_eq!(controller.current_game(&peer(1)), 1);
}

#[test]
fn desktop_launch_and_cancel_only_manage_rtsp_and_history() {
    let now = Instant::now();
    let mut settings = config();
    settings.desktop.enabled = true;
    let mut controller = Controller::new(Some(settings)).unwrap();
    let mut broker = Broker::default();
    let mut desktop_request = request(91);
    desktop_request.app_id = DESKTOP_APP_ID;

    assert!(
        controller
            .launch(91, desktop_request, peer(91), now)
            .is_none()
    );
    let (connection, reply) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(connection, 91);
    assert_eq!(reply.status, 200);
    assert!(
        String::from_utf8(reply.body)
            .unwrap()
            .contains("rtspenc://")
    );
    assert!(
        !broker
            .actions()
            .iter()
            .any(|(service, _)| *service == "amaterasu.launch/1")
    );
    controller.reply_delivered(connection, now);
    assert_eq!(controller.current_game(&peer(91)), DESKTOP_APP_ID);

    assert!(controller.cancel(92, &peer(91), now).is_none());
    let (connection, reply) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(connection, 92);
    assert_eq!(reply.status, 200);
    assert_eq!(controller.current_game(&peer(91)), 0);
    assert!(
        !broker
            .actions()
            .iter()
            .any(|(service, _)| *service == "amaterasu.launch/1")
    );
}

#[test]
fn pipewire_launch_carries_the_owned_display_request_to_rtsp() {
    let now = Instant::now();
    let mut settings = config();
    settings.desktop.enabled = true;
    settings.capture.capture_provider = CaptureProvider::PipeWire;
    settings.capture.output = OWNED_DISPLAY_OUTPUT.into();
    let mut controller = Controller::new(Some(settings)).unwrap();
    let mut broker = Broker::default();
    let mut desktop_request = request(96);
    desktop_request.app_id = DESKTOP_APP_ID;

    assert!(
        controller
            .launch(96, desktop_request, peer(96), now)
            .is_none()
    );
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(reply.status, 200);
    let rtsp_open = broker
        .commands
        .iter()
        .find_map(|command| match command {
            Command::Request {
                service, payload, ..
            } if service == "amaterasu.rtsp/1" && payload["action"] == "open" => Some(payload),
            _ => None,
        })
        .expect("RTSP open request");
    assert_eq!(rtsp_open["capture"]["output"], OWNED_DISPLAY_OUTPUT);
}

#[test]
fn desktop_launch_carries_portal_pipewire_source_to_rtsp_without_display_preflight() {
    let now = Instant::now();
    let mut settings = config();
    settings.desktop.enabled = true;
    settings.capture.capture_provider = CaptureProvider::PipeWire;
    settings.capture.output = "profile-output-must-not-be-used".into();
    let mut controller = Controller::new(Some(settings)).unwrap();
    controller.set_output_name_settings(true, Some("configured-physical-display"));
    let mut broker = Broker::default();
    let mut desktop_request = request(95);
    desktop_request.app_id = DESKTOP_APP_ID;

    assert!(
        controller
            .launch(95, desktop_request, peer(95), now)
            .is_none()
    );
    let (connection, reply) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(connection, 95);
    assert_eq!(reply.status, 200);

    let rtsp_open = broker
        .commands
        .iter()
        .find_map(|command| match command {
            Command::Request {
                service, payload, ..
            } if service == "amaterasu.rtsp/1" && payload["action"] == "open" => Some(payload),
            _ => None,
        })
        .expect("desktop RTSP open request");
    assert_eq!(rtsp_open["capture"]["capture_provider"], "pipewire");
    assert!(rtsp_open["display_policy_snapshot"].is_null());
    assert!(rtsp_open["display_request"].is_null());
    assert_eq!(
        rtsp_open["capture"]["output"],
        PORTAL_SELECTED_SESSION_SOURCE
    );
    assert!(!broker.actions().iter().any(|(service, action)| {
        *service == "amaterasu.display/1"
            || *service == "amaterasu.launch/1"
            || (*service == "amaterasu.rtsp/1" && *action == "prepare_display_admission")
    }));
}

#[test]
fn desktop_resume_retires_rtsp_then_opens_a_fresh_ticket_without_app_calls() {
    let now = Instant::now();
    let mut settings = config();
    settings.desktop.enabled = true;
    let mut controller = Controller::new(Some(settings)).unwrap();
    let mut broker = Broker::default();
    let client = peer(93);
    let mut first = request(93);
    first.app_id = DESKTOP_APP_ID;
    assert!(controller.launch(93, first, client.clone(), now).is_none());
    let (connection, _) = poll_until_reply(&mut controller, &mut broker, now);
    controller.reply_delivered(connection, now);

    let mut resumed = request(93);
    resumed.app_id = DESKTOP_APP_ID;
    assert!(controller.resume(94, resumed, &client, now).is_none());
    let (connection, reply) =
        poll_until_reply_with_trust(&mut controller, &mut broker, now, |_| true);
    assert_eq!(connection, 94);
    assert_eq!(reply.status, 200);
    assert!(
        String::from_utf8(reply.body)
            .unwrap()
            .contains("<resume>1</resume>")
    );
    let open_payloads: Vec<_> = broker
        .commands
        .iter()
        .filter_map(|command| match command {
            Command::Request {
                service, payload, ..
            } if service == "amaterasu.rtsp/1" && payload["action"] == "open" => Some(payload),
            _ => None,
        })
        .collect();
    assert_eq!(open_payloads.len(), 2);
    assert_ne!(
        open_payloads[0]["operation_id"], open_payloads[1]["operation_id"],
        "authenticated /resume must receive a fresh RTSP operation identity"
    );
    assert!(
        !broker
            .actions()
            .iter()
            .any(|(service, _)| *service == "amaterasu.launch/1")
    );
}

#[test]
fn revoked_pending_desktop_resume_is_closed_before_stopped_without_reopening_rtsp() {
    let now = Instant::now();
    let mut settings = config();
    settings.desktop.enabled = true;
    let mut controller = Controller::new(Some(settings)).unwrap();
    let mut broker = Broker::default();
    let client = peer(95);
    let mut first = request(95);
    first.app_id = DESKTOP_APP_ID;
    assert!(controller.launch(95, first, client.clone(), now).is_none());
    let (connection, _) = poll_until_reply(&mut controller, &mut broker, now);
    controller.reply_delivered(connection, now);
    let opens_before_resume = broker
        .actions()
        .iter()
        .filter(|(service, action)| *service == "amaterasu.rtsp/1" && *action == "open")
        .count();
    assert_eq!(opens_before_resume, 1);

    let mut resumed = request(95);
    resumed.app_id = DESKTOP_APP_ID;
    assert!(controller.resume(96, resumed, &client, now).is_none());
    let closed = controller.revoke_untrusted(now, |_| false);
    assert_eq!(closed, vec![96]);
    assert!(controller.pending_resume.is_none());
    poll_until_stopped(&mut controller, &mut broker, now, 1);
    assert!(controller.records.get(&1).unwrap().revoked);
    let opens_after_revoke = broker
        .actions()
        .iter()
        .filter(|(service, action)| *service == "amaterasu.rtsp/1" && *action == "open")
        .count();
    assert_eq!(opens_after_revoke, opens_before_resume);
}

#[test]
fn deferred_desktop_resume_revalidates_current_certificate_trust() {
    let now = Instant::now();
    let mut settings = config();
    settings.desktop.enabled = true;
    let mut controller = Controller::new(Some(settings)).unwrap();
    let mut broker = Broker::default();
    let client = peer(97);
    let mut first = request(97);
    first.app_id = DESKTOP_APP_ID;
    assert!(controller.launch(97, first, client.clone(), now).is_none());
    let (connection, _) = poll_until_reply(&mut controller, &mut broker, now);
    controller.reply_delivered(connection, now);

    let mut resumed = request(97);
    resumed.app_id = DESKTOP_APP_ID;
    assert!(controller.resume(98, resumed, &client, now).is_none());
    let (connection, reply) =
        poll_until_reply_with_trust(&mut controller, &mut broker, now, |_| false);
    assert_eq!(connection, 98);
    assert_eq!(reply.status, 401);
    assert!(controller.records.get(&1).unwrap().revoked);
    assert_eq!(
        broker
            .actions()
            .iter()
            .filter(|(service, action)| *service == "amaterasu.rtsp/1" && *action == "open")
            .count(),
        1
    );
}

#[test]
fn duplicate_resume_cancel_and_repeated_revocation_are_idempotent() {
    let now = Instant::now();
    let mut settings = config();
    settings.desktop.enabled = true;
    let mut controller = Controller::new(Some(settings)).unwrap();
    let mut broker = Broker::default();
    let client = peer(99);
    let mut first = request(99);
    first.app_id = DESKTOP_APP_ID;
    assert!(controller.launch(99, first, client.clone(), now).is_none());
    let (connection, _) = poll_until_reply(&mut controller, &mut broker, now);
    controller.reply_delivered(connection, now);

    let mut resumed = request(99);
    resumed.app_id = DESKTOP_APP_ID;
    assert!(
        controller
            .resume(100, resumed.clone(), &client, now)
            .is_none()
    );
    assert_eq!(
        controller
            .resume(101, resumed, &client, now)
            .unwrap()
            .status,
        409
    );
    assert!(controller.pending_resume.is_some());
    assert!(controller.cancel(102, &client, now).is_none());
    assert!(controller.pending_resume.is_none());

    let first_revocation = controller.revoke_untrusted(now, |_| false);
    assert_eq!(first_revocation, vec![102]);
    let repeated_revocation = controller.revoke_untrusted(now, |_| false);
    assert!(repeated_revocation.is_empty());
    poll_until_stopped(&mut controller, &mut broker, now, 1);
    assert_eq!(
        broker
            .actions()
            .iter()
            .filter(|(service, action)| *service == "amaterasu.rtsp/1" && *action == "open")
            .count(),
        1
    );
}

#[test]
fn desktop_app_id_is_rejected_when_opt_in_is_disabled() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut desktop_request = request(92);
    desktop_request.app_id = DESKTOP_APP_ID;
    let reply = controller
        .launch(92, desktop_request, peer(92), now)
        .unwrap();
    assert_eq!(reply.status, 400);
    assert!(!controller.busy());
}

#[test]
fn history_reservation_precedes_preflight_and_releases_after_stream_cleanup() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut broker = Broker::default();
    launch_ready(&mut controller, &mut broker, now);
    let actions = broker.actions();
    assert_eq!(
        actions[0],
        ("amaterasu.stream-session/1", "reserve_history_activity")
    );
    let opened = broker
        .commands
        .iter()
        .find_map(|command| match command {
            Command::Request {
                service, payload, ..
            } if service == "amaterasu.rtsp/1" && payload["action"] == "open" => Some(payload),
            _ => None,
        })
        .unwrap();
    assert_eq!(opened["history_activity_id"], opened["operation_id"]);
    assert!(broker.history_reserved);

    assert!(controller.cancel(20, &peer(1), now).is_none());
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(reply.status, 200);
    let actions = broker.actions();
    let position = |service, action| {
        actions
            .iter()
            .position(|entry| *entry == (service, action))
            .unwrap()
    };
    assert!(position("amaterasu.rtsp/1", "close") < position("amaterasu.launch/1", "stop"));
    assert!(
        position("amaterasu.launch/1", "stop")
            < position("amaterasu.stream-session/1", "release_history_activity")
    );
    assert!(!broker.history_reserved);
}

#[test]
fn missing_history_reservation_is_visible_and_does_not_tag_rtsp() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut broker = Broker {
        history_reserve_unavailable: true,
        ..Broker::default()
    };
    assert!(controller.launch(10, request(1), peer(1), now).is_none());
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(reply.status, 200);
    assert!(
        String::from_utf8(reply.body)
            .unwrap()
            .contains("<historyActivityState>unavailable</historyActivityState>")
    );
    let opened = broker
        .commands
        .iter()
        .find_map(|command| match command {
            Command::Request {
                service, payload, ..
            } if service == "amaterasu.rtsp/1" && payload["action"] == "open" => Some(payload),
            _ => None,
        })
        .unwrap();
    assert!(opened.get("history_activity_id").is_none());
    assert!(
        !broker
            .actions()
            .contains(&("amaterasu.stream-session/1", "release_history_activity"))
    );
}

#[test]
fn mismatched_history_reservation_does_not_tag_rtsp_and_is_released() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut broker = Broker {
        history_reserve_wrong_identity: true,
        ..Broker::default()
    };
    assert!(controller.launch(10, request(1), peer(1), now).is_none());
    let (connection, reply) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(reply.status, 200);
    controller.reply_delivered(connection, now);
    assert_eq!(
        controller.records.values().next().unwrap().history_state,
        "unavailable"
    );
    let opened = broker
        .commands
        .iter()
        .find_map(|command| match command {
            Command::Request {
                service, payload, ..
            } if service == "amaterasu.rtsp/1" && payload["action"] == "open" => Some(payload),
            _ => None,
        })
        .unwrap();
    assert!(opened.get("history_activity_id").is_none());
    assert!(broker.history_reserved);
    assert!(controller.cancel(20, &peer(1), now).is_none());
    let (_, stopped) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(stopped.status, 200);
    assert!(!broker.history_reserved);
}

#[test]
fn lost_history_reservation_admission_retries_same_id_and_releases_on_cancel() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut broker = Broker {
        lose_history_reserve_once: true,
        ..Broker::default()
    };
    assert!(controller.launch(10, request(1), peer(1), now).is_none());
    let (connection, reply) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(reply.status, 200);
    controller.reply_delivered(connection, now);
    assert!(broker.history_reserved);
    let reserve_requests: Vec<_> = broker
        .commands
        .iter()
        .filter_map(|command| match command {
            Command::Request {
                service, payload, ..
            } if service == "amaterasu.stream-session/1"
                && payload["action"] == "reserve_history_activity" =>
            {
                Some(payload)
            }
            _ => None,
        })
        .collect();
    assert_eq!(reserve_requests.len(), 2);
    assert_eq!(reserve_requests[0], reserve_requests[1]);
    assert!(controller.cancel(20, &peer(1), now).is_none());
    let (_, stopped) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(stopped.status, 200);
    assert!(!broker.history_reserved);
}

#[test]
fn failed_history_release_retains_cleanup_ownership_for_retry() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut broker = Broker::default();
    launch_ready(&mut controller, &mut broker, now);
    broker.history_release_unavailable = true;
    assert!(controller.cancel(20, &peer(1), now).is_none());
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(reply.status, 503);
    assert!(controller.busy());
    assert!(broker.history_reserved);
    broker.history_release_unavailable = false;
    assert!(controller.cancel(21, &peer(1), now).is_none());
    let (_, retry) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(retry.status, 200);
    assert!(!broker.history_reserved);
}

#[test]
fn history_in_use_release_keeps_cleanup_owned_until_retry() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut broker = Broker::default();
    launch_ready(&mut controller, &mut broker, now);
    broker.history_release_in_use_once = true;
    assert!(controller.cancel(20, &peer(1), now).is_none());
    let (_, first) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(first.status, 503);
    assert!(broker.history_reserved);
    assert!(controller.busy());
    assert!(controller.cancel(21, &peer(1), now).is_none());
    let (_, second) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(second.status, 200);
    assert!(!broker.history_reserved);
    let actions = broker.actions();
    let stopped = actions
        .iter()
        .position(|entry| *entry == ("amaterasu.launch/1", "stop"))
        .unwrap();
    let first_release = actions
        .iter()
        .position(|entry| *entry == ("amaterasu.stream-session/1", "release_history_activity"))
        .unwrap();
    assert!(stopped < first_release);
}

#[test]
fn lost_history_release_result_accepts_idempotent_terminal_readback() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut broker = Broker::default();
    launch_ready(&mut controller, &mut broker, now);
    broker.lose_history_release_result_once = true;
    assert!(controller.cancel(20, &peer(1), now).is_none());
    let (_, first) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(first.status, 503);
    assert!(!broker.history_reserved);
    assert!(controller.busy());
    assert!(controller.cancel(21, &peer(1), now).is_none());
    let (_, retry) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(retry.status, 200);
    let releases: Vec<_> = broker
        .commands
        .iter()
        .filter_map(|command| match command {
            Command::Request {
                service, payload, ..
            } if service == "amaterasu.stream-session/1"
                && payload["action"] == "release_history_activity" =>
            {
                Some(payload)
            }
            _ => None,
        })
        .collect();
    assert_eq!(releases.len(), 2);
    assert_eq!(releases[0], releases[1]);
}

fn opened_audio_endpoint(broker: &Broker) -> &str {
    broker
        .commands
        .iter()
        .find_map(|command| match command {
            Command::Request {
                service, payload, ..
            } if service == "amaterasu.rtsp/1" && payload["action"] == "open" => {
                payload["capture"]["audio_endpoint"].as_str()
            }
            _ => None,
        })
        .expect("RTSP open request includes audio endpoint")
}

fn opened_audio_endpoints(broker: &Broker) -> Vec<&str> {
    broker
        .commands
        .iter()
        .filter_map(|command| match command {
            Command::Request {
                service, payload, ..
            } if service == "amaterasu.rtsp/1" && payload["action"] == "open" => {
                payload["capture"]["audio_endpoint"].as_str()
            }
            _ => None,
        })
        .collect()
}

#[test]
fn global_app_and_verified_client_fec_values_apply_in_precedence_order() {
    for (global_fec, app_fec, client_fec, expected) in [
        (None, None, None, 20),
        (Some(31), None, None, 31),
        (Some(31), Some(37), None, 37),
        (Some(31), Some(37), Some(49), 49),
    ] {
        let now = Instant::now();
        let mut controller = Controller::new(Some(config())).unwrap();
        controller.set_global_fec_percentage(global_fec);
        let mut broker = Broker {
            application_fec_percentage: app_fec,
            ..Default::default()
        };
        assert!(
            controller
                .launch(10, request(1), peer_with_fec(1, client_fec), now)
                .is_none()
        );
        let _ = poll_until_reply(&mut controller, &mut broker, now);
        let rtsp_open = broker
            .commands
            .iter()
            .find_map(|command| match command {
                Command::Request {
                    service, payload, ..
                } if service == "amaterasu.rtsp/1" && payload["action"] == "open" => Some(payload),
                _ => None,
            })
            .expect("RTSP open request");
        assert_eq!(rtsp_open["profile"]["fec_percentage"], expected);
    }
}

#[test]
fn global_app_and_verified_client_audio_values_apply_in_precedence_order() {
    for (global, app, client, expected) in [
        (true, None, None, true),
        (false, None, None, false),
        (false, Some(true), None, true),
        (true, Some(false), None, false),
        (true, Some(false), Some(true), true),
        (false, Some(true), Some(false), false),
    ] {
        let now = Instant::now();
        let mut controller = Controller::new(Some(config())).unwrap();
        controller.set_global_stream_audio(global);
        let mut broker = Broker {
            application_stream_audio: app,
            ..Default::default()
        };
        assert!(
            controller
                .launch(10, request(1), peer_with_overrides(1, None, client), now)
                .is_none()
        );
        // Settings changes after admission apply to later launches only.
        controller.set_global_stream_audio(!global);
        let _ = poll_until_reply(&mut controller, &mut broker, now);
        let rtsp_open = broker
            .commands
            .iter()
            .find_map(|command| match command {
                Command::Request {
                    service, payload, ..
                } if service == "amaterasu.rtsp/1" && payload["action"] == "open" => Some(payload),
                _ => None,
            })
            .expect("RTSP open request");
        assert_eq!(rtsp_open["stream_audio"], expected);
    }
}

#[test]
fn continuous_audio_is_requested_per_launch_and_requires_effective_stream_audio() {
    for (requested, global, app, client, expected) in [
        (false, true, None, None, false),
        (true, true, None, None, true),
        (true, false, None, None, false),
        (true, true, Some(false), None, false),
        (true, false, Some(true), None, true),
        (true, true, Some(false), Some(true), true),
        (true, false, Some(true), Some(false), false),
    ] {
        let now = Instant::now();
        let mut controller = Controller::new(Some(config())).unwrap();
        controller.set_global_stream_audio(global);
        let mut broker = Broker {
            application_stream_audio: app,
            ..Default::default()
        };
        let mut launch_request = request(1);
        launch_request.continuous_audio = requested;

        assert!(
            controller
                .launch(
                    10,
                    launch_request,
                    peer_with_overrides(1, None, client),
                    now,
                )
                .is_none()
        );
        let _ = poll_until_reply(&mut controller, &mut broker, now);

        let rtsp_open = opened_rtsp_payload(&broker);
        assert_eq!(
            rtsp_open["continuous_audio"], expected,
            "requested={requested}, global={global}, app={app:?}, client={client:?}"
        );
    }
}

#[test]
fn global_video_batch_size_reaches_rtsp_open_and_is_snapshotted_at_admission() {
    for (configured, later_value) in [(16, 32), (32, 64), (64, 16)] {
        let now = Instant::now();
        let mut controller = Controller::new(Some(config())).unwrap();
        controller.set_global_video_max_batch_size_kb(configured);
        let mut broker = Broker::default();

        assert!(controller.launch(10, request(1), peer(1), now).is_none());
        controller.set_global_video_max_batch_size_kb(later_value);
        let _ = poll_until_reply(&mut controller, &mut broker, now);

        let rtsp_open = broker
            .commands
            .iter()
            .find_map(|command| match command {
                Command::Request {
                    service, payload, ..
                } if service == "amaterasu.rtsp/1" && payload["action"] == "open" => Some(payload),
                _ => None,
            })
            .expect("RTSP open request");
        assert_eq!(rtsp_open["profile"]["video_max_batch_size_kb"], configured);
    }
}

#[test]
fn global_ping_timeout_reaches_rtsp_open_and_is_snapshotted_at_admission() {
    for (configured, later_value) in [(0, 250), (250, 10_000), (i32::MAX as u32, 0)] {
        let now = Instant::now();
        let mut controller = Controller::new(Some(config())).unwrap();
        controller.set_global_ping_timeout_ms(configured);
        let mut broker = Broker::default();

        assert!(controller.launch(10, request(1), peer(1), now).is_none());
        controller.set_global_ping_timeout_ms(later_value);
        let _ = poll_until_reply(&mut controller, &mut broker, now);

        let rtsp_open = broker
            .commands
            .iter()
            .find_map(|command| match command {
                Command::Request {
                    service, payload, ..
                } if service == "amaterasu.rtsp/1" && payload["action"] == "open" => Some(payload),
                _ => None,
            })
            .expect("RTSP open request");
        assert_eq!(rtsp_open["ping_timeout_ms"], configured);
    }
}

#[test]
fn native_pen_touch_resolves_client_before_application_and_preserves_inheritance() {
    for (marker, client, application, expected) in [
        (51, Some(false), Some(true), Some(false)),
        (52, Some(true), Some(false), Some(true)),
        (53, None, Some(false), Some(false)),
        (54, None, None, None),
    ] {
        let now = Instant::now();
        let mut broker = Broker {
            application_input_overrides: Some(json!({"native_pen_touch":application})),
            ..Broker::default()
        };
        let mut controller = Controller::new(Some(config())).unwrap();
        assert!(
            controller
                .launch(
                    10,
                    request(marker),
                    peer_with_native_pen_touch(marker, client),
                    now,
                )
                .is_none()
        );
        let _ = poll_until_reply(&mut controller, &mut broker, now);

        let rtsp_open = opened_rtsp_payload(&broker);
        assert_eq!(rtsp_open["native_pen_touch"], json!(expected));
    }
}

#[test]
fn paired_client_ds4_touchpad_override_precedes_application_and_preserves_false() {
    for (marker, client_value, application_value, expected) in [
        (61, Some(false), Some(true), json!(false)),
        (62, Some(true), Some(false), json!(true)),
        (63, None, Some(false), json!(false)),
        (64, None, None, Value::Null),
        (65, None, Some(true), json!(true)),
    ] {
        let now = Instant::now();
        let application_overrides = application_value
            .map(|value| json!({"ds4_back_as_touchpad_click":value}))
            .unwrap_or_else(|| json!({}));
        let mut broker = Broker {
            application_input_overrides: Some(application_overrides),
            ..Broker::default()
        };
        let mut controller = Controller::new(Some(config())).unwrap();
        assert!(
            controller
                .launch(
                    10,
                    request(marker),
                    peer_with_ds4_back_as_touchpad_click(marker, client_value),
                    now,
                )
                .is_none()
        );
        let _ = poll_until_reply(&mut controller, &mut broker, now);

        let rtsp_open = opened_rtsp_payload(&broker);
        assert_eq!(rtsp_open["ds4_back_as_touchpad_click"], expected);
    }
}

#[test]
fn encryption_modes_and_authenticated_peer_ip_are_snapshotted_into_rtsp_open() {
    let now = Instant::now();
    let remote = "198.51.100.42".parse().unwrap();
    let certificate = vec![42; 32];
    let peer = PeerIdentity::new(remote, certificate.clone())
        .unwrap()
        .with_paired_identity(
            "trusted-policy-peer".into(),
            fingerprint(&certificate),
            ClientConfigOverrides::default(),
        )
        .unwrap();
    let mut controller = Controller::new(Some(config())).unwrap();
    controller.set_global_video_encryption_modes(2, 0);
    let mut broker = Broker::default();

    assert!(controller.launch(10, request(1), peer, now).is_none());
    controller.set_global_video_encryption_modes(0, 2);
    let _ = poll_until_reply(&mut controller, &mut broker, now);

    let rtsp_open = opened_rtsp_payload(&broker);
    assert_eq!(rtsp_open["peer_ip"], "198.51.100.42");
    assert_eq!(
        rtsp_open["video_encryption_policy"],
        json!({"lan_mode":2,"wan_mode":0})
    );
}

#[test]
fn global_max_bitrate_is_sent_as_encoder_cap_and_snapshotted_at_admission() {
    for (configured, later_value, expected) in [
        (Some(5_000), Some(8_000), Some(5_000)),
        (Some(200_000), None, Some(200_000)),
        (None, Some(5_000), None),
    ] {
        let now = Instant::now();
        let mut controller = Controller::new(Some(config())).unwrap();
        controller.set_global_max_bitrate_kbps(configured);
        let mut broker = Broker::default();

        assert!(controller.launch(10, request(1), peer(1), now).is_none());
        controller.set_global_max_bitrate_kbps(later_value);
        let _ = poll_until_reply(&mut controller, &mut broker, now);

        let rtsp_open = broker
            .commands
            .iter()
            .find_map(|command| match command {
                Command::Request {
                    service, payload, ..
                } if service == "amaterasu.rtsp/1" && payload["action"] == "open" => Some(payload),
                _ => None,
            })
            .expect("RTSP open request");
        assert_eq!(rtsp_open["profile"]["bitrate_kbps"], 10_000);
        assert_eq!(rtsp_open["max_bitrate_kbps"], json!(expected));
        assert_eq!(
            rtsp_open["negotiation_bounds"],
            json!({
                "max_width": 1920,
                "max_height": 1080,
                "max_fps": 60,
                "max_bitrate_kbps": expected.unwrap_or(10_000).min(10_000),
                "max_reference_frames": 1,
            })
        );
    }
}

#[test]
fn stream_overrides_resolve_client_before_application_before_global() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    controller.set_global_max_bitrate_kbps(Some(9_000));
    controller.set_global_minimum_fps_target(20.0);
    controller.set_global_video_max_batch_size_kb(64);
    let client = peer_with_stream_overrides(1, Some(5_000), Some(45.5), Some(16));
    let mut broker = Broker {
        application_max_bitrate: Some(6_000),
        application_minimum_fps_target: Some(30.0),
        application_video_max_batch_size_kb: Some(32),
        ..Default::default()
    };

    assert!(controller.launch(10, request(1), client, now).is_none());
    controller.set_global_max_bitrate_kbps(None);
    controller.set_global_minimum_fps_target(60.0);
    controller.set_global_video_max_batch_size_kb(64);
    let _ = poll_until_reply(&mut controller, &mut broker, now);

    let rtsp_open = opened_rtsp_payload(&broker);
    assert_eq!(rtsp_open["profile"]["bitrate_kbps"], 10_000);
    assert_eq!(rtsp_open["max_bitrate_kbps"], 5_000);
    assert_eq!(rtsp_open["minimum_fps_target"], 45.5);
    assert_eq!(rtsp_open["profile"]["video_max_batch_size_kb"], 16);
}

#[test]
fn stream_overrides_preserve_explicit_zero_and_fall_back_to_application_or_global() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    controller.set_global_max_bitrate_kbps(Some(8_000));
    controller.set_global_minimum_fps_target(20.0);
    controller.set_global_video_max_batch_size_kb(16);
    let mut broker = Broker {
        application_max_bitrate: Some(6_000),
        application_minimum_fps_target: Some(30.0),
        application_video_max_batch_size_kb: Some(32),
        ..Default::default()
    };

    assert!(controller.launch(10, request(1), peer(1), now).is_none());
    let _ = poll_until_reply(&mut controller, &mut broker, now);

    let rtsp_open = opened_rtsp_payload(&broker);
    assert_eq!(rtsp_open["max_bitrate_kbps"], 6_000);
    assert_eq!(rtsp_open["minimum_fps_target"], 30.0);
    assert_eq!(rtsp_open["profile"]["video_max_batch_size_kb"], 32);

    let mut controller = Controller::new(Some(config())).unwrap();
    controller.set_global_max_bitrate_kbps(Some(8_000));
    controller.set_global_minimum_fps_target(20.0);
    controller.set_global_video_max_batch_size_kb(16);
    let client = peer_with_stream_overrides(2, Some(0), Some(0.0), Some(0));
    let mut broker = Broker {
        application_max_bitrate: Some(6_000),
        application_minimum_fps_target: Some(30.0),
        application_video_max_batch_size_kb: Some(32),
        ..Default::default()
    };

    assert!(controller.launch(10, request(2), client, now).is_none());
    let _ = poll_until_reply(&mut controller, &mut broker, now);

    let rtsp_open = opened_rtsp_payload(&broker);
    assert_eq!(rtsp_open["max_bitrate_kbps"], Value::Null);
    assert_eq!(rtsp_open["minimum_fps_target"], 0.0);
    assert_eq!(rtsp_open["profile"]["video_max_batch_size_kb"], 0);
}

#[test]
fn global_minimum_fps_target_reaches_rtsp_open_and_is_snapshotted_at_admission() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    controller.set_global_minimum_fps_target(23.5);
    let mut broker = Broker::default();

    assert!(controller.launch(10, request(1), peer(1), now).is_none());
    controller.set_global_minimum_fps_target(60.0);
    let _ = poll_until_reply(&mut controller, &mut broker, now);

    let rtsp_open = broker
        .commands
        .iter()
        .find_map(|command| match command {
            Command::Request {
                service, payload, ..
            } if service == "amaterasu.rtsp/1" && payload["action"] == "open" => Some(payload),
            _ => None,
        })
        .expect("RTSP open request");
    assert_eq!(rtsp_open["minimum_fps_target"], 23.5);
}

#[test]
fn global_wgc_pacing_smoothing_reaches_rtsp_open_and_is_snapshotted_at_admission() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    controller.set_global_wgc_pacing_smoothing(false);
    let mut broker = Broker::default();

    assert!(controller.launch(10, request(1), peer(1), now).is_none());
    controller.set_global_wgc_pacing_smoothing(true);
    let _ = poll_until_reply(&mut controller, &mut broker, now);

    let rtsp_open = broker
        .commands
        .iter()
        .find_map(|command| match command {
            Command::Request {
                service, payload, ..
            } if service == "amaterasu.rtsp/1" && payload["action"] == "open" => Some(payload),
            _ => None,
        })
        .expect("RTSP open request");
    assert_eq!(rtsp_open["wgc_pacing_smoothing"], false);
}

#[test]
fn global_bitrate_below_encoder_minimum_can_be_overridden_by_client_cap() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    controller.set_global_max_bitrate_kbps(Some(99));
    let client = peer_with_stream_overrides(1, Some(5_000), None, None);
    let mut broker = Broker::default();

    assert!(controller.launch(10, request(1), client, now).is_none());
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);

    assert_eq!(reply.status, 200);
    assert_eq!(opened_rtsp_payload(&broker)["max_bitrate_kbps"], 5_000);
}

#[test]
fn global_bitrate_below_encoder_minimum_can_be_overridden_by_application_cap() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    controller.set_global_max_bitrate_kbps(Some(99));
    let mut broker = Broker {
        application_max_bitrate: Some(6_000),
        ..Default::default()
    };

    assert!(controller.launch(10, request(1), peer(1), now).is_none());
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);

    assert_eq!(reply.status, 200);
    assert_eq!(opened_rtsp_payload(&broker)["max_bitrate_kbps"], 6_000);
}

#[test]
fn global_bitrate_below_encoder_minimum_can_be_cleared_by_client_override() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    controller.set_global_max_bitrate_kbps(Some(99));
    let client = peer_with_stream_overrides(1, Some(0), None, None);
    let mut broker = Broker {
        application_max_bitrate: Some(6_000),
        ..Default::default()
    };

    assert!(controller.launch(10, request(1), client, now).is_none());
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);

    assert_eq!(reply.status, 200);
    assert_eq!(
        opened_rtsp_payload(&broker)["max_bitrate_kbps"],
        Value::Null
    );
}

#[test]
fn effective_client_bitrate_below_encoder_minimum_fails_before_rtsp_open() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    controller.set_global_max_bitrate_kbps(Some(5_000));
    let client = peer_with_stream_overrides(1, Some(99), None, None);
    let mut broker = Broker::default();

    assert!(controller.launch(10, request(1), client, now).is_none());
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);

    assert_ne!(reply.status, 200);
    assert!(!broker.actions().contains(&("amaterasu.rtsp/1", "open")));
}

#[test]
fn effective_application_bitrate_below_encoder_minimum_fails_before_rtsp_open() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    controller.set_global_max_bitrate_kbps(Some(5_000));
    let mut broker = Broker {
        application_max_bitrate: Some(99),
        ..Default::default()
    };

    assert!(controller.launch(10, request(1), peer(1), now).is_none());
    let _ = poll_until_reply(&mut controller, &mut broker, now);

    assert_eq!(
        controller
            .records
            .values()
            .next()
            .expect("launch record")
            .failure,
        Some("max_bitrate_below_encoder_minimum")
    );
    assert!(!broker.actions().contains(&("amaterasu.rtsp/1", "open")));
}

#[test]
fn global_bitrate_below_encoder_minimum_without_override_fails_before_rtsp_open() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    controller.set_global_max_bitrate_kbps(Some(99));
    let mut broker = Broker::default();

    assert!(controller.launch(10, request(1), peer(1), now).is_none());
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);

    assert_ne!(reply.status, 200);
    assert!(!broker.actions().contains(&("amaterasu.rtsp/1", "open")));
}

#[test]
fn global_capture_modes_reach_rtsp_open_and_are_snapshotted_at_admission() {
    for (mode, bootstrap_provider, expected_provider, expected_constant_rate) in [
        (
            CaptureMode::Auto,
            CaptureProvider::Dxgi,
            CaptureProvider::Dxgi,
            false,
        ),
        (
            CaptureMode::Auto,
            CaptureProvider::Wgc,
            CaptureProvider::Wgc,
            false,
        ),
        (
            CaptureMode::Auto,
            CaptureProvider::PipeWire,
            CaptureProvider::PipeWire,
            false,
        ),
        (
            CaptureMode::Ddx,
            CaptureProvider::Wgc,
            CaptureProvider::Dxgi,
            false,
        ),
        (
            CaptureMode::Wgc,
            CaptureProvider::Dxgi,
            CaptureProvider::Wgc,
            false,
        ),
        (
            CaptureMode::Wgcc,
            CaptureProvider::Dxgi,
            CaptureProvider::Wgc,
            true,
        ),
        (
            CaptureMode::PipeWire,
            CaptureProvider::Dxgi,
            CaptureProvider::PipeWire,
            false,
        ),
        (
            CaptureMode::X11,
            CaptureProvider::Dxgi,
            CaptureProvider::X11,
            false,
        ),
        (
            CaptureMode::Kms,
            CaptureProvider::Dxgi,
            CaptureProvider::Kms,
            false,
        ),
    ] {
        let now = Instant::now();
        let mut stream_config = config();
        stream_config.capture.capture_provider = bootstrap_provider;
        let mut controller = Controller::new(Some(stream_config)).unwrap();
        controller.set_capture_mode(mode);
        let mut broker = Broker::default();

        assert!(controller.launch(10, request(1), peer(1), now).is_none());
        controller.set_capture_mode(CaptureMode::Ddx);
        let _ = poll_until_reply(&mut controller, &mut broker, now);

        let rtsp_open = broker
            .commands
            .iter()
            .find_map(|command| match command {
                Command::Request {
                    service, payload, ..
                } if service == "amaterasu.rtsp/1" && payload["action"] == "open" => Some(payload),
                _ => None,
            })
            .expect("RTSP open request");
        assert_eq!(
            rtsp_open["capture"]["capture_provider"],
            json!(expected_provider)
        );
        assert_eq!(
            rtsp_open["capture"]["constant_rate"],
            expected_constant_rate
        );
    }
}

#[test]
fn scoped_capture_selection_prefers_client_then_application_then_global() {
    let cases = [
        (
            CaptureMode::Kms,
            Some(CaptureMode::X11),
            Some(CaptureMode::Kms),
            CaptureProvider::Kms,
            false,
        ),
        (
            CaptureMode::X11,
            Some(CaptureMode::PipeWire),
            Some(CaptureMode::X11),
            CaptureProvider::X11,
            false,
        ),
        (
            CaptureMode::X11,
            Some(CaptureMode::PipeWire),
            None,
            CaptureProvider::PipeWire,
            false,
        ),
        (CaptureMode::Wgcc, None, None, CaptureProvider::Wgc, true),
    ];

    for (global, application, client, expected_provider, expected_constant_rate) in cases {
        let now = Instant::now();
        let mut controller = Controller::new(Some(config())).unwrap();
        controller.set_capture_mode(global);
        let peer = client.map_or_else(
            || peer(91),
            |capture| {
                let certificate = vec![91; 32];
                PeerIdentity::new("127.0.0.1".parse().unwrap(), certificate.clone())
                    .unwrap()
                    .with_paired_identity(
                        "capture-client".into(),
                        fingerprint(&certificate),
                        ClientConfigOverrides {
                            capture: Some(capture),
                            ..Default::default()
                        },
                    )
                    .unwrap()
            },
        );
        let mut broker = Broker {
            application_input_overrides: application.map(|capture| json!({"capture":capture})),
            ..Broker::default()
        };

        assert!(controller.launch(10, request(1), peer, now).is_none());
        let _ = poll_until_reply(&mut controller, &mut broker, now);
        let open = broker
            .commands
            .iter()
            .find_map(|command| match command {
                Command::Request {
                    service, payload, ..
                } if service == "amaterasu.rtsp/1" && payload["action"] == "open" => Some(payload),
                _ => None,
            })
            .expect("RTSP open request");
        assert_eq!(
            open["capture"]["capture_provider"],
            json!(expected_provider)
        );
        assert_eq!(open["capture"]["constant_rate"], expected_constant_rate);
    }
}

#[test]
fn success_requires_active_application_and_ready_rtsp_then_retries_same_url() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut broker = Broker::default();
    launch_ready(&mut controller, &mut broker, now);

    let retry = controller
        .launch(11, request(1), peer(1), now)
        .expect("idempotent ready reply");
    assert_eq!(retry.status, 200);
    controller.reply_delivered(11, now);
    assert_eq!(
        broker.actions()[..5],
        [
            ("amaterasu.stream-session/1", "reserve_history_activity"),
            ("amaterasu.input/1", "settings_get"),
            ("amaterasu.launch/1", "preflight_export"),
            ("amaterasu.launch/1", "launch_export"),
            ("amaterasu.rtsp/1", "open")
        ]
    );
}

#[test]
fn proton_compatibility_freezes_client_application_global_precedence() {
    let cases = [
        (false, Some(true), Some(false), false),
        (true, Some(false), None, false),
        (false, None, Some(true), true),
        (false, None, None, false),
        (true, None, None, true),
    ];

    for (index, (global, application, client, expected)) in cases.into_iter().enumerate() {
        let now = Instant::now();
        let mut controller = Controller::new(Some(config())).unwrap();
        let mut broker = Broker {
            input_policy_response: json!({
                "ok":true,
                "persisted":true,
                "revision":4,
                "values":{"proton_dualsense_compatibility":global}
            }),
            application_input_overrides: application
                .map(|value| json!({"proton_dualsense_compatibility":value})),
            ..Broker::default()
        };

        assert!(
            controller
                .launch(
                    10,
                    request(1),
                    peer_with_proton_override(index as u8 + 1, client),
                    now,
                )
                .is_none()
        );
        let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
        assert_eq!(reply.status, 200);
        assert_eq!(broker.input_policy_requests, 1);

        let launch = launch_export_payload(&broker);
        assert_eq!(launch["proton_dualsense_compatibility"], expected);

        let actions = broker.actions();
        let position = |service, action| {
            actions
                .iter()
                .position(|entry| *entry == (service, action))
                .unwrap()
        };
        assert!(
            position("amaterasu.input/1", "settings_get")
                < position("amaterasu.launch/1", "preflight_export")
        );
        assert!(
            position("amaterasu.launch/1", "preflight_export")
                < position("amaterasu.launch/1", "launch_export")
        );
    }
}

#[test]
fn invalid_proton_policy_snapshot_fails_before_application_preflight() {
    let malformed = [
        json!({"ok":false,"persisted":false}),
        json!({"ok":true,"persisted":false,"values":{"proton_dualsense_compatibility":true}}),
        json!({"ok":true,"persisted":true,"values":{"proton_dualsense_compatibility":"true"}}),
        json!({"ok":true,"persisted":true,"values":{}}),
    ];

    for response in malformed {
        let now = Instant::now();
        let mut controller = Controller::new(Some(config())).unwrap();
        let mut broker = Broker {
            input_policy_response: response,
            ..Broker::default()
        };

        assert!(controller.launch(10, request(1), peer(1), now).is_none());
        let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);

        assert_ne!(reply.status, 200);
        assert!(
            broker
                .actions()
                .contains(&("amaterasu.input/1", "settings_get"))
        );
        assert!(
            !broker
                .actions()
                .contains(&("amaterasu.launch/1", "preflight_export"))
        );
        assert!(
            !broker
                .actions()
                .contains(&("amaterasu.launch/1", "launch_export"))
        );
        assert!(!broker.actions().contains(&("amaterasu.rtsp/1", "open")));
    }
}

#[test]
fn launch_export_uses_the_preparation_snapshot_captured_at_admission() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let original: PreparationStep = serde_json::from_value(json!({
        "run":{"executable":std::env::current_exe().unwrap(),"args":["original"]}
    }))
    .unwrap();
    let changed: PreparationStep = serde_json::from_value(json!({
        "run":{"executable":std::env::current_exe().unwrap(),"args":["changed"]}
    }))
    .unwrap();
    controller.set_global_preparation(std::slice::from_ref(&original));
    let mut broker = Broker::default();

    assert!(controller.launch(10, request(1), peer(1), now).is_none());
    controller.set_global_preparation(std::slice::from_ref(&changed));
    let _ = poll_until_reply(&mut controller, &mut broker, now);

    let launch_payload = broker
        .commands
        .iter()
        .find_map(|command| match command {
            Command::Request {
                service, payload, ..
            } if service == "amaterasu.launch/1" && payload["action"] == "launch_export" => {
                Some(payload)
            }
            _ => None,
        })
        .expect("launch export request");
    assert_eq!(
        launch_payload["global_preparation"][0]["run"]["args"],
        json!(["original"])
    );
}

#[test]
fn launch_export_includes_admitted_frame_limiter_settings_and_context() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let original = FrameLimiterSettings {
        frame_limiter_enable: Some(true),
        frame_limiter_fps_limit: Some(144.0),
        frame_limiter_provider: Some("none".into()),
        ..Default::default()
    };
    let changed = FrameLimiterSettings {
        frame_limiter_enable: Some(false),
        frame_limiter_fps_limit: Some(72.0),
        frame_limiter_provider: Some("auto".into()),
        ..Default::default()
    };
    controller.set_global_frame_limiter_settings(&original);
    let mut launch_request = request(1);
    launch_request.fps = 60;
    let mut broker = Broker::default();

    assert!(
        controller
            .launch(10, launch_request, peer(1), now)
            .is_none()
    );
    controller.set_global_frame_limiter_settings(&changed);
    let _ = poll_until_reply(&mut controller, &mut broker, now);

    let launch_payload = broker
        .commands
        .iter()
        .find_map(|command| match command {
            Command::Request {
                service, payload, ..
            } if service == "amaterasu.launch/1" && payload["action"] == "launch_export" => {
                Some(payload)
            }
            _ => None,
        })
        .expect("launch export request");
    let expected_settings = json!({
        "version":1,
        "settings":serde_json::to_value(original.effective()).unwrap(),
        "requested_stream_fps_millihz":60000,
        "client_display_mode_override_millihz":null,
        "lossless_scaling_limit_millihz":null,
        "virtual_display_active":null,
        "physical_framegen_capture":null,
        "game_frame_generation_mode":null,
        "rtss_frame_limit_type_explicit_override":null
    });

    assert_eq!(launch_payload["application_display_overrides"], json!({}));
    assert_eq!(launch_payload["frame_limiter_settings"], expected_settings);
    assert_eq!(launch_payload["client_frame_limiter_overrides"], json!({}));
    let rtsp_open = opened_rtsp_payload(&broker);
    assert!(rtsp_open["frame_limiter_settings"].is_null());
    assert!(rtsp_open["frame_limiter_executable_path"].is_null());
    assert!(rtsp_open.get("application_operation_id").is_none());
    assert!(rtsp_open.get("app_id").is_none());
    assert!(rtsp_open.get("catalog_revision").is_none());
}

#[test]
fn paired_frame_limiter_values_override_global_settings_and_keep_sparse_presence() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let global_settings = FrameLimiterSettings {
        frame_limiter_enable: Some(true),
        frame_limiter_fps_limit: Some(120.0),
        ..Default::default()
    };
    controller.set_global_frame_limiter_settings(&global_settings);
    let mut broker = Broker::default();

    assert!(
        controller
            .launch(
                10,
                request(1),
                peer_with_frame_limiter_overrides(1, Some(false), Some(0.0)),
                now,
            )
            .is_none()
    );
    let _ = poll_until_reply(&mut controller, &mut broker, now);

    let launch_payload = broker
        .commands
        .iter()
        .find_map(|command| match command {
            Command::Request {
                service, payload, ..
            } if service == "amaterasu.launch/1" && payload["action"] == "launch_export" => {
                Some(payload)
            }
            _ => None,
        })
        .expect("launch export request");
    assert_eq!(
        launch_payload["frame_limiter_settings"]["settings"]["frame_limiter_enable"],
        false
    );
    assert_eq!(
        launch_payload["frame_limiter_settings"]["settings"]["frame_limiter_fps_limit_millihz"],
        0
    );
    assert_eq!(
        launch_payload["client_frame_limiter_overrides"],
        json!({"frame_limiter_enable":false,"frame_limiter_fps_limit":0.0})
    );
}

#[test]
fn application_frame_limiter_values_decode_sparsely_and_reject_malformed_values() {
    let payload = json!({
        "launch": {
            "config_overrides": {
                "frame_limiter_enable":false,
                "frame_limiter_fps_limit":72.0,
                "frame_limiter_provider":"auto"
            }
        }
    });
    let decoded = super::workflow::application_config_overrides(&payload).unwrap();
    assert_eq!(
        decoded.frame_limiter_settings(),
        FrameLimiterSettings {
            frame_limiter_enable: Some(false),
            frame_limiter_fps_limit: Some(72.0),
            frame_limiter_provider: Some("auto".into()),
            ..Default::default()
        }
    );

    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut broker = Broker {
        application_input_overrides: Some(json!({
            "frame_limiter_fps_limit":72.0,
            "frame_limiter_provider":"auto"
        })),
        ..Broker::default()
    };
    assert!(controller.launch(10, request(1), peer(1), now).is_none());
    let _ = poll_until_reply(&mut controller, &mut broker, now);
    let record = controller.records.values().next().expect("launch record");
    assert_eq!(
        record.application_frame_limiter_settings,
        FrameLimiterSettings {
            frame_limiter_fps_limit: Some(72.0),
            frame_limiter_provider: Some("auto".into()),
            ..Default::default()
        }
    );
    let launch_payload = broker
        .commands
        .iter()
        .find_map(|command| match command {
            Command::Request {
                service, payload, ..
            } if service == "amaterasu.launch/1" && payload["action"] == "launch_export" => {
                Some(payload)
            }
            _ => None,
        })
        .expect("launch export");
    assert_eq!(launch_payload["client_frame_limiter_overrides"], json!({}));

    #[cfg(windows)]
    {
        let windows_payload = json!({
            "launch": {
                "config_overrides": {
                    "frame_limiter_disable_vsync":false,
                    "frame_limiter_auto_virtual_framegen":"legacy"
                }
            }
        });
        let decoded = super::workflow::application_config_overrides(&windows_payload).unwrap();
        assert_eq!(
            decoded.frame_limiter_settings(),
            FrameLimiterSettings {
                frame_limiter_disable_vsync: Some(false),
                frame_limiter_auto_virtual_framegen: Some("legacy".into()),
                ..Default::default()
            }
        );
    }

    let malformed_values = [
        json!({"frame_limiter_enable":"false"}),
        json!({"frame_limiter_fps_limit":"60"}),
        json!({"frame_limiter_fps_limit":1000.001}),
        json!({"frame_limiter_provider":[]}),
        json!({"frame_limiter_disable_vsync":1}),
        json!({"frame_limiter_auto_virtual_framegen":"invalid"}),
        json!({"lossless_scaling_framegen":"true"}),
        json!({"lossless_scaling_target_fps":0}),
        json!({"lossless_scaling_target_fps":1001}),
        json!({"lossless_scaling_target_fps":"60"}),
        json!({"frame_generation_provider":"unknown"}),
        json!({"frame_generation_provider":false}),
        json!({"frame_generation_mode":"disabled"}),
        json!({"frame_generation_mode":0}),
        json!({"rtss_frame_limit_type":false}),
        json!({"ds4_back_as_touchpad_click":"false"}),
        json!({"unrecognized_override":true}),
    ];
    for application_overrides in malformed_values.iter() {
        let payload = json!({"launch":{"config_overrides":application_overrides}});
        assert!(super::workflow::application_config_overrides(&payload).is_err());
    }

    for (offset, application_overrides) in malformed_values.into_iter().enumerate() {
        let now = Instant::now();
        let marker = 70 + offset as u8;
        let mut controller = Controller::new(Some(config())).unwrap();
        let mut broker = Broker {
            application_input_overrides: Some(application_overrides),
            ..Broker::default()
        };

        assert!(
            controller
                .launch(10, request(marker), peer(marker), now)
                .is_none()
        );
        let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
        assert_eq!(reply.status, 503);
        assert!(!broker.commands.iter().any(|command| matches!(
            command,
            Command::Request { service, payload, .. }
                if service == "amaterasu.rtsp/1" && payload["action"] == "open"
        )));
    }
}

#[test]
fn application_lossless_scaling_framegen_projects_into_the_frozen_launch_snapshot() {
    for (offset, application_overrides, expected_mode, expected_limit) in [
        (0, None, json!(null), json!(null)),
        (1, Some(json!({})), json!(null), json!(null)),
        (
            2,
            Some(json!({"lossless_scaling_framegen":null})),
            json!(null),
            json!(null),
        ),
        (
            3,
            Some(json!({"lossless_scaling_framegen":false})),
            json!("none"),
            json!(null),
        ),
        (
            4,
            Some(json!({"lossless_scaling_framegen":true})),
            json!("lossless-scaling"),
            json!(60_000),
        ),
        (
            5,
            Some(
                json!({"frame_generation_provider":"game-provided","lossless_scaling_framegen":false}),
            ),
            json!("game-provided"),
            json!(null),
        ),
        (
            6,
            Some(
                json!({"frame_generation_provider":"nvidia-smooth-motion","lossless_scaling_framegen":false}),
            ),
            json!("nvidia-smooth-motion"),
            json!(null),
        ),
        (
            7,
            Some(json!({"frame_generation_provider":"lossless-scaling"})),
            json!(null),
            json!(null),
        ),
        (
            8,
            Some(
                json!({"frame_generation_provider":"lossless-scaling","lossless_scaling_framegen":false}),
            ),
            json!("none"),
            json!(null),
        ),
        (
            9,
            Some(
                json!({"frame_generation_mode":"off","frame_generation_provider":"game-provided","lossless_scaling_framegen":true}),
            ),
            json!("none"),
            json!(null),
        ),
        (
            10,
            Some(
                json!({"frame_generation_mode":"nvidia-smooth-motion","frame_generation_provider":"game-provided","lossless_scaling_framegen":false}),
            ),
            json!("nvidia-smooth-motion"),
            json!(null),
        ),
        (
            11,
            Some(
                json!({"frame_generation_mode":"game-provided","lossless_scaling_framegen":false}),
            ),
            json!("game-provided"),
            json!(null),
        ),
        (
            12,
            Some(
                json!({"frame_generation_mode":"lossless-scaling","lossless_scaling_framegen":false,"lossless_scaling_target_fps":144}),
            ),
            json!("lossless-scaling"),
            json!(144_000),
        ),
        (
            13,
            Some(
                json!({"frame_generation_mode":"game-provided","lossless_scaling_target_fps":144}),
            ),
            json!("game-provided"),
            json!(null),
        ),
    ] {
        let now = Instant::now();
        let marker = 80 + offset;
        let mut controller = Controller::new(Some(config())).unwrap();
        let mut broker = Broker {
            application_input_overrides: application_overrides,
            ..Broker::default()
        };

        assert!(
            controller
                .launch(10, request(marker), peer(marker), now)
                .is_none()
        );
        let _ = poll_until_reply(&mut controller, &mut broker, now);

        let launch_payload = broker
            .commands
            .iter()
            .find_map(|command| match command {
                Command::Request {
                    service, payload, ..
                } if service == "amaterasu.launch/1" && payload["action"] == "launch_export" => {
                    Some(payload)
                }
                _ => None,
            })
            .expect("launch export request");
        assert_eq!(
            launch_payload["frame_limiter_settings"]["game_frame_generation_mode"], expected_mode,
            "application override case {offset}"
        );
        assert_eq!(
            launch_payload["frame_limiter_settings"]["lossless_scaling_limit_millihz"],
            expected_limit,
            "application override case {offset}"
        );
    }
}

#[test]
fn lossless_scaling_target_fps_uses_checked_millihertz_conversion() {
    assert_eq!(
        super::workflow::lossless_scaling_target_fps_millihz(60),
        Some(60_000)
    );
    assert_eq!(
        super::workflow::lossless_scaling_target_fps_millihz(1000),
        Some(1_000_000)
    );
    assert_eq!(
        super::workflow::lossless_scaling_target_fps_millihz(0),
        None
    );
    assert_eq!(
        super::workflow::lossless_scaling_target_fps_millihz(1001),
        None
    );
    assert_eq!(
        super::workflow::lossless_scaling_target_fps_millihz(u32::MAX),
        None
    );
}

#[cfg(windows)]
#[test]
fn application_rtss_frame_limit_type_decodes_windows_domain_values() {
    for frame_limit_type in [
        "async",
        "front edge sync",
        "back edge sync",
        "nvidia reflex",
    ] {
        let payload = json!({
            "launch": {
                "config_overrides": {
                    "rtss_frame_limit_type":frame_limit_type
                }
            }
        });
        let decoded = super::workflow::application_config_overrides(&payload).unwrap();
        assert_eq!(
            decoded
                .frame_limiter_settings()
                .rtss_frame_limit_type
                .as_deref(),
            Some(frame_limit_type)
        );
    }

    let invalid_payload = json!({
        "launch": {
            "config_overrides": {
                "rtss_frame_limit_type":"sync"
            }
        }
    });
    assert!(super::workflow::application_config_overrides(&invalid_payload).is_err());
    assert_eq!(
        FrameLimiterSettings {
            rtss_frame_limit_type: Some("sync".into()),
            ..Default::default()
        }
        .validate(),
        Err("invalid_rtss_frame_limit_type")
    );
}

#[cfg(not(windows))]
#[test]
fn application_rtss_frame_limit_type_rejects_windows_domain_values_off_windows() {
    let payload = json!({
        "launch": {
            "config_overrides": {
                "rtss_frame_limit_type":"async"
            }
        }
    });
    assert!(super::workflow::application_config_overrides(&payload).is_err());
    assert_eq!(
        FrameLimiterSettings {
            rtss_frame_limit_type: Some("async".into()),
            ..Default::default()
        }
        .validate(),
        Err("unsupported_frame_limiter_setting")
    );
}

#[test]
fn frame_limiter_fields_resolve_client_then_application_then_global_independently() {
    let global = FrameLimiterSettings {
        frame_limiter_enable: Some(true),
        frame_limiter_fps_limit: Some(60.0),
        frame_limiter_provider: Some("auto".into()),
        frame_limiter_disable_vsync: Some(true),
        frame_limiter_auto_virtual_framegen: Some("enabled".into()),
        ..Default::default()
    };
    let application = FrameLimiterSettings {
        frame_limiter_enable: Some(true),
        frame_limiter_fps_limit: Some(90.0),
        frame_limiter_provider: Some("rtss".into()),
        frame_limiter_disable_vsync: Some(false),
        frame_limiter_auto_virtual_framegen: Some("legacy".into()),
        ..Default::default()
    };
    let client = FrameLimiterSettings {
        frame_limiter_enable: Some(false),
        frame_limiter_fps_limit: Some(144.0),
        frame_limiter_provider: Some("none".into()),
        frame_limiter_disable_vsync: Some(true),
        frame_limiter_auto_virtual_framegen: Some("vrr".into()),
        ..Default::default()
    };
    let resolved = super::workflow::resolve_frame_limiter_settings(&global, &application, &client);
    assert_eq!(resolved.frame_limiter_enable, Some(false));
    assert_eq!(resolved.frame_limiter_fps_limit, Some(144.0));
    assert_eq!(resolved.frame_limiter_provider.as_deref(), Some("none"));
    assert_eq!(resolved.frame_limiter_disable_vsync, Some(true));
    assert_eq!(
        resolved.frame_limiter_auto_virtual_framegen.as_deref(),
        Some("vrr")
    );

    let application_resolved = super::workflow::resolve_frame_limiter_settings(
        &global,
        &application,
        &FrameLimiterSettings::default(),
    );
    assert_eq!(application_resolved.frame_limiter_enable, Some(true));
    assert_eq!(application_resolved.frame_limiter_fps_limit, Some(90.0));
    assert_eq!(
        application_resolved.frame_limiter_provider.as_deref(),
        Some("rtss")
    );
    assert_eq!(
        application_resolved.frame_limiter_disable_vsync,
        Some(false)
    );
    assert_eq!(
        application_resolved
            .frame_limiter_auto_virtual_framegen
            .as_deref(),
        Some("legacy")
    );

    let global_resolved = super::workflow::resolve_frame_limiter_settings(
        &global,
        &FrameLimiterSettings::default(),
        &FrameLimiterSettings::default(),
    );
    assert_eq!(global_resolved.frame_limiter_enable, Some(true));
    assert_eq!(global_resolved.frame_limiter_fps_limit, Some(60.0));
    assert_eq!(
        global_resolved.frame_limiter_provider.as_deref(),
        Some("auto")
    );
    assert_eq!(global_resolved.frame_limiter_disable_vsync, Some(true));
    assert_eq!(
        global_resolved
            .frame_limiter_auto_virtual_framegen
            .as_deref(),
        Some("enabled")
    );

    let defaults = super::workflow::resolve_frame_limiter_settings(
        &FrameLimiterSettings::default(),
        &FrameLimiterSettings::default(),
        &FrameLimiterSettings::default(),
    );
    assert_eq!(defaults.frame_limiter_enable, None);
    assert_eq!(defaults.frame_limiter_fps_limit, None);
    assert_eq!(defaults.frame_limiter_provider, None);
    assert_eq!(defaults.frame_limiter_disable_vsync, None);
    assert_eq!(defaults.frame_limiter_auto_virtual_framegen, None);
}

#[cfg(windows)]
#[test]
fn rtss_frame_limit_type_resolves_client_then_application_then_global_then_default() {
    let global = FrameLimiterSettings {
        rtss_frame_limit_type: Some("async".into()),
        ..Default::default()
    };
    let application = FrameLimiterSettings {
        rtss_frame_limit_type: Some("front edge sync".into()),
        ..Default::default()
    };
    let client = FrameLimiterSettings {
        rtss_frame_limit_type: Some("nvidia reflex".into()),
        ..Default::default()
    };

    let client_resolved =
        super::workflow::resolve_frame_limiter_settings(&global, &application, &client);
    assert_eq!(
        client_resolved.rtss_frame_limit_type.as_deref(),
        Some("nvidia reflex")
    );

    let application_resolved = super::workflow::resolve_frame_limiter_settings(
        &global,
        &application,
        &FrameLimiterSettings::default(),
    );
    assert_eq!(
        application_resolved.rtss_frame_limit_type.as_deref(),
        Some("front edge sync")
    );

    let global_resolved = super::workflow::resolve_frame_limiter_settings(
        &global,
        &FrameLimiterSettings::default(),
        &FrameLimiterSettings::default(),
    );
    assert_eq!(
        global_resolved.rtss_frame_limit_type.as_deref(),
        Some("async")
    );

    let defaults = super::workflow::resolve_frame_limiter_settings(
        &FrameLimiterSettings::default(),
        &FrameLimiterSettings::default(),
        &FrameLimiterSettings::default(),
    );
    assert_eq!(defaults.rtss_frame_limit_type, None);
    assert_eq!(defaults.effective().rtss_frame_limit_type, "async");
}

#[cfg(windows)]
#[test]
fn application_rtss_frame_limit_type_is_captured_after_launch_export() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let global_settings = FrameLimiterSettings {
        rtss_frame_limit_type: Some("async".into()),
        ..Default::default()
    };
    controller.set_global_frame_limiter_settings(&global_settings);
    let mut broker = Broker {
        application_input_overrides: Some(json!({
            "rtss_frame_limit_type":"back edge sync"
        })),
        application_executable_path: Some("C:\\Games\\Example.exe".into()),
        ..Broker::default()
    };

    assert!(controller.launch(10, request(1), peer(1), now).is_none());
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(reply.status, 200);

    let record = controller.records.values().next().expect("launch record");
    assert_eq!(
        record
            .application_frame_limiter_settings
            .rtss_frame_limit_type
            .as_deref(),
        Some("back edge sync")
    );
    let actions = broker.actions();
    assert!(
        actions
            .iter()
            .position(|(_, action)| *action == "preflight_export")
            < actions
                .iter()
                .position(|(_, action)| *action == "launch_export")
    );
    let launch_payload = broker
        .commands
        .iter()
        .find_map(|command| match command {
            Command::Request {
                service, payload, ..
            } if service == "amaterasu.launch/1" && payload["action"] == "launch_export" => {
                Some(payload)
            }
            _ => None,
        })
        .unwrap();
    assert_eq!(launch_payload["preflight_token"], "fixture-preflight-token");
    assert_eq!(
        launch_payload["frame_limiter_settings"]["settings"]["rtss_frame_limit_type"],
        "back edge sync"
    );
    assert_eq!(
        launch_payload["frame_limiter_settings"]["rtss_frame_limit_type_explicit_override"],
        true
    );
    assert_eq!(
        opened_rtsp_payload(&broker)["frame_limiter_settings"],
        launch_payload["frame_limiter_settings"]
    );
    assert_eq!(
        opened_rtsp_payload(&broker)["frame_limiter_executable_path"],
        "C:\\Games\\Example.exe"
    );
    let resolved = super::workflow::resolve_frame_limiter_settings(
        &global_settings,
        &record.application_frame_limiter_settings,
        &FrameLimiterSettings::default(),
    );
    assert_eq!(
        resolved.rtss_frame_limit_type.as_deref(),
        Some("back edge sync")
    );
}

#[test]
fn malformed_preflight_override_fails_before_application_launch() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut broker = Broker {
        application_input_overrides: Some(json!({"frame_limiter_enable":"false"})),
        ..Broker::default()
    };
    assert!(controller.launch(10, request(1), peer(1), now).is_none());
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
    assert_ne!(reply.status, 200);
    assert!(
        broker
            .actions()
            .contains(&("amaterasu.launch/1", "preflight_export"))
    );
    assert!(
        !broker
            .actions()
            .contains(&("amaterasu.launch/1", "launch_export"))
    );
    assert!(
        broker
            .actions()
            .contains(&("amaterasu.stream-session/1", "release_history_activity"))
    );
    assert!(!broker.history_reserved);
}

#[test]
fn whitespace_executable_path_fails_preflight_before_launch_or_rtsp_open() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut broker = Broker {
        application_executable_path: Some(" \t ".into()),
        ..Broker::default()
    };

    assert!(controller.launch(10, request(1), peer(1), now).is_none());
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);

    assert_ne!(reply.status, 200);
    assert!(
        broker
            .actions()
            .contains(&("amaterasu.launch/1", "preflight_export"))
    );
    assert!(
        !broker
            .actions()
            .contains(&("amaterasu.launch/1", "launch_export"))
    );
    assert!(!broker.actions().contains(&("amaterasu.rtsp/1", "open")));
}

#[test]
fn changed_application_policy_after_preflight_never_opens_rtsp() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut broker = Broker {
        application_fec_percentage: Some(31),
        ..Broker::default()
    };
    assert!(controller.launch(10, request(1), peer(1), now).is_none());
    for _ in 0..8 {
        controller.poll(now, &mut |command| broker.send(command));
        if controller
            .records
            .values()
            .any(|record| record.stage == Stage::LaunchApplication)
        {
            break;
        }
    }
    assert!(
        controller
            .records
            .values()
            .any(|record| record.stage == Stage::LaunchApplication)
    );
    broker.application_fec_percentage = Some(32);
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
    assert_ne!(reply.status, 200);
    assert!(!broker.actions().contains(&("amaterasu.rtsp/1", "open")));
}

#[test]
fn changed_catalog_revision_after_preflight_stops_application_before_rtsp() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut broker = Broker::default();
    assert!(controller.launch(10, request(1), peer(1), now).is_none());
    for _ in 0..8 {
        controller.poll(now, &mut |command| broker.send(command));
        if controller
            .records
            .values()
            .any(|record| record.stage == Stage::LaunchApplication)
        {
            break;
        }
    }
    assert!(
        controller
            .records
            .values()
            .any(|record| record.application_catalog_revision == Some(1))
    );

    broker.application_catalog_revision = 2;
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
    assert_ne!(reply.status, 200);
    assert!(broker.actions().contains(&("amaterasu.launch/1", "stop")));
    assert!(!broker.actions().contains(&("amaterasu.rtsp/1", "open")));
}

#[test]
fn sparse_application_display_fields_are_frozen_before_launch_and_checked_on_readback() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut broker = Broker {
        application_input_overrides: Some(json!({
            "dd_refresh_rate_option":"prefer_highest",
            "dd_hdr_request_override":"force_off",
            "display_policy":{"dd_virtual_display_permanent_count":2}
        })),
        ..Broker::default()
    };
    assert!(controller.launch(10, request(1), peer(1), now).is_none());
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(
        reply.status,
        200,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    let record = controller.records.values().next().unwrap();
    assert_eq!(record.application_catalog_revision, Some(1));
    assert_eq!(
        record.application_display_overrides,
        Some(json!({
            "dd_refresh_rate_option":"prefer_highest",
            "dd_hdr_request_override":"force_off",
            "dd_virtual_display_permanent_count":2
        }))
    );
    assert!(
        opened_rtsp_payload(&broker)
            .get("display_request")
            .is_none()
    );
    let launch_export = broker
        .commands
        .iter()
        .find_map(|command| match command {
            Command::Request {
                service, payload, ..
            } if service == "amaterasu.launch/1" && payload["action"] == "launch_export" => {
                Some(payload)
            }
            _ => None,
        })
        .unwrap();
    assert_eq!(
        launch_export["application_display_overrides"],
        record
            .application_display_overrides
            .as_ref()
            .unwrap()
            .clone()
    );
    assert_eq!(
        opened_rtsp_payload(&broker)["display_policy_snapshot"],
        record.display_policy_snapshot.as_ref().unwrap().clone()
    );
}

#[test]
fn paired_client_display_policy_overrides_application_fields_without_global_defaults() {
    let now = Instant::now();
    let certificate = vec![13; 32];
    let paired = PeerIdentity::new("127.0.0.1".parse().unwrap(), certificate.clone())
        .unwrap()
        .with_paired_identity(
            "display-client".into(),
            fingerprint(&certificate),
            ClientConfigOverrides {
                dd_refresh_rate_option: Some("disabled".into()),
                dd_hdr_option: Some("auto".into()),
                ..Default::default()
            },
        )
        .unwrap();
    let mut streaming = config();
    streaming.capture.output = "00000000:00000001/\\\\.\\DISPLAY1".into();
    let mut controller = Controller::new(Some(streaming)).unwrap();
    let mut broker = Broker {
        display_snapshot_ids: vec!["monitor.one".into()],
        display_entries: vec![json!({
            "id":"monitor.one","source":"\\\\.\\DISPLAY1","active":true
        })],
        application_input_overrides: Some(json!({
            "dd_refresh_rate_option":"manual",
            "dd_manual_refresh_rate":"59.94",
            "dd_configuration_option":"verify_only"
        })),
        ..Broker::default()
    };
    assert!(controller.launch(10, request(13), paired, now).is_none());
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(reply.status, 200);
    assert!(
        String::from_utf8(reply.body.clone())
            .unwrap()
            .contains("<verifiedDisplayId>monitor.one</verifiedDisplayId>")
    );
    let snapshot = &opened_rtsp_payload(&broker)["display_policy_snapshot"];
    assert_eq!(
        snapshot["application_overrides"]["dd_refresh_rate_option"],
        "manual"
    );
    assert_eq!(
        snapshot["client_overrides"],
        json!({
            "dd_refresh_rate_option":"disabled", "dd_hdr_option":"auto"
        })
    );
    assert_eq!(
        snapshot["effective_overrides"],
        json!({
            "dd_refresh_rate_option":"disabled",
            "dd_hdr_option":"auto",
            "dd_manual_refresh_rate":"59.94",
            "dd_configuration_option":"verify_only"
        })
    );
    assert!(
        snapshot["effective_overrides"]
            .get("dd_resolution_option")
            .is_none()
    );
    assert_eq!(snapshot["global_overrides"], json!({}));
    assert!(snapshot["global_revision"].is_null());
    assert!(
        opened_rtsp_payload(&broker)
            .get("display_request")
            .is_none()
    );
}

#[test]
fn pipewire_display_topology_mapping_stays_explicitly_unsupported() {
    let now = Instant::now();
    let mut streaming = config();
    streaming.capture.capture_provider = CaptureProvider::PipeWire;
    streaming.capture.output = "portal-session-source".into();
    let mut controller = Controller::new(Some(streaming)).unwrap();
    controller.set_global_display_policy(9, json!({"dd_configuration_option":"verify_only"}));
    let mut broker = Broker::default();
    assert!(controller.launch(10, request(1), peer(1), now).is_none());
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
    assert_ne!(reply.status, 200);
    assert_eq!(
        controller.records.values().next().unwrap().failure,
        Some("capture_display_mapping_unsupported")
    );
    assert!(!broker.commands.iter().any(|command| matches!(command,
        Command::Request { service, .. } if service == "amaterasu.display/1")));
}

#[test]
fn verify_only_freezes_unique_active_monitor_without_mutation_and_retries_exactly() {
    let now = Instant::now();
    let mut streaming = config();
    streaming.capture.capture_provider = CaptureProvider::Wgc;
    streaming.capture.output = "\\\\.\\DISPLAY2".into();
    let mut controller = Controller::new(Some(streaming)).unwrap();
    controller.set_global_display_policy(9, json!({"dd_configuration_option":"verify_only"}));
    let mut broker = Broker {
        display_snapshot_ids: vec!["monitor.one".into(), "Monitor.Two".into()],
        display_entries: vec![
            json!({"id":"monitor.one","source":"\\\\.\\DISPLAY1","active":true}),
            json!({"id":"monitor.two","source":"\\\\.\\DISPLAY2","active":true}),
        ],
        ..Default::default()
    };
    let paired = peer(22);
    let stream = request(22);
    assert!(
        controller
            .launch(10, stream.clone(), paired.clone(), now)
            .is_none()
    );
    controller.set_global_display_policy(10, json!({"dd_configuration_option":"disabled"}));
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(reply.status, 200);
    let body = String::from_utf8(reply.body).unwrap();
    assert!(body.contains("<verifiedDisplayId>Monitor.Two</verifiedDisplayId>"));
    assert!(body.contains(
        "<displayTopologyRevision>aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</displayTopologyRevision>"
    ));
    assert_eq!(broker.display_snapshot_calls, 2);
    assert_eq!(
        broker
            .actions()
            .iter()
            .filter(|(service, _)| *service == "amaterasu.display/1")
            .count(),
        3
    );
    assert!(
        !broker
            .actions()
            .iter()
            .any(|(service, action)| *service == "amaterasu.display/1" && *action == "apply")
    );
    assert!(
        opened_rtsp_payload(&broker)
            .get("display_request")
            .is_none()
    );
    controller.reply_delivered(10, now);
    let retry = controller
        .launch(11, stream, paired, now)
        .expect("ready retry");
    assert_eq!(String::from_utf8(retry.body).unwrap(), body);
}

#[test]
fn display_and_frame_limiter_open_share_frozen_application_identity() {
    let now = Instant::now();
    let mut streaming = config();
    streaming.capture.capture_provider = CaptureProvider::Wgc;
    streaming.capture.output = "\\\\.\\DISPLAY2".into();
    let mut controller = Controller::new(Some(streaming)).unwrap();
    controller.set_global_display_policy(9, json!({"dd_configuration_option":"ensure_active"}));
    let mut broker = Broker {
        display_snapshot_ids: vec!["monitor.one".into(), "monitor.two".into()],
        display_entries: vec![
            json!({"id":"monitor.one","source":"\\\\.\\DISPLAY1","active":true}),
            json!({"id":"monitor.two","source":"\\\\.\\DISPLAY2","active":true}),
        ],
        application_executable_path: Some("C:\\Games\\Example.exe".into()),
        ..Broker::default()
    };

    assert!(controller.launch(10, request(1), peer(1), now).is_none());
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(reply.status, 200);
    let record = controller.records.values().next().expect("launch record");
    let open = opened_rtsp_payload(&broker);
    assert!(open["display_request"].is_object());
    assert!(open["frame_limiter_settings"].is_object());
    assert_eq!(
        open["application_operation_id"],
        record.application_operation
    );
    assert_eq!(open["app_id"], super::app_id(1));
    assert_eq!(
        open["catalog_revision"],
        record.application_catalog_revision.unwrap()
    );
    assert_eq!(
        open["display_policy_snapshot"]["catalog_revision"],
        open["catalog_revision"]
    );
}

#[test]
fn verify_only_fails_before_application_for_missing_ambiguous_inactive_or_changed_output() {
    let cases = [
        (
            "missing",
            vec![json!({"id":"monitor.one","source":"\\\\.\\DISPLAY1","active":true})],
            vec!["monitor.one"],
            false,
        ),
        (
            "ambiguous",
            vec![
                json!({"id":"monitor.one","source":"\\\\.\\DISPLAY2","active":true}),
                json!({"id":"monitor.two","source":"\\\\.\\DISPLAY2","active":true}),
            ],
            vec!["monitor.one", "monitor.two"],
            false,
        ),
        (
            "inactive",
            vec![json!({"id":"monitor.one","source":"\\\\.\\DISPLAY2","active":false})],
            vec!["monitor.one"],
            false,
        ),
        (
            "changed",
            vec![json!({"id":"monitor.one","source":"\\\\.\\DISPLAY2","active":true})],
            vec!["monitor.one"],
            true,
        ),
    ];
    for (case, entries, ids, drift) in cases {
        let now = Instant::now();
        let mut streaming = config();
        streaming.capture.capture_provider = CaptureProvider::Wgc;
        streaming.capture.output = "\\\\.\\DISPLAY2".into();
        let mut controller = Controller::new(Some(streaming)).unwrap();
        controller.set_global_display_policy(9, json!({"dd_configuration_option":"verify_only"}));
        let mut broker = Broker {
            display_entries: entries,
            display_snapshot_ids: ids.into_iter().map(str::to_owned).collect(),
            display_revision_drift: drift,
            ..Default::default()
        };
        assert!(controller.launch(10, request(23), peer(23), now).is_none());
        let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
        assert_ne!(reply.status, 200, "{case}");
        assert!(
            !broker
                .actions()
                .iter()
                .any(|(service, action)| (*service == "amaterasu.launch/1"
                    && *action == "launch_export")
                    || (*service == "amaterasu.display/1" && *action == "apply")),
            "{case}"
        );
    }
}

#[test]
fn disabled_display_policy_skips_provider_and_mutating_policy_fails_before_launch() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut broker = Broker::default();
    assert!(controller.launch(10, request(24), peer(24), now).is_none());
    assert_eq!(
        poll_until_reply(&mut controller, &mut broker, now).1.status,
        200
    );
    assert!(
        !broker
            .actions()
            .iter()
            .any(|(service, _)| *service == "amaterasu.display/1")
    );

    let mut controller = Controller::new(Some(config())).unwrap();
    controller.set_global_display_policy(9, json!({"dd_configuration_option":"ensure_active"}));
    let mut broker = Broker::default();
    assert!(controller.launch(10, request(25), peer(25), now).is_none());
    assert_ne!(
        poll_until_reply(&mut controller, &mut broker, now).1.status,
        200
    );
    assert!(
        !broker
            .actions()
            .iter()
            .any(|(service, _)| *service == "amaterasu.display/1")
    );
    assert!(!broker.actions().iter().any(|(service, action)| *service == "amaterasu.launch/1" && *action == "launch_export"));
}

#[test]
fn global_display_policy_is_frozen_and_resolves_below_application_and_client() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    controller.set_global_display_policy(
        17,
        json!({
            "dd_refresh_rate_option":"auto",
            "dd_hdr_option":"disabled"
        }),
    );
    let mut broker = Broker {
        application_input_overrides: Some(json!({"dd_refresh_rate_option":"manual"})),
        ..Broker::default()
    };
    let certificate = vec![16; 32];
    let paired = PeerIdentity::new("127.0.0.1".parse().unwrap(), certificate.clone())
        .unwrap()
        .with_paired_identity(
            "client-16".into(),
            fingerprint(&certificate),
            ClientConfigOverrides {
                dd_hdr_option: Some("auto".into()),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(controller.launch(10, request(16), paired, now).is_none());
    controller.set_global_display_policy(18, json!({"dd_refresh_rate_option":"disabled"}));
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(reply.status, 200);
    let snapshot = &opened_rtsp_payload(&broker)["display_policy_snapshot"];
    assert_eq!(snapshot["global_revision"], 17);
    assert_eq!(
        snapshot["global_overrides"],
        json!({
            "dd_refresh_rate_option":"auto", "dd_hdr_option":"disabled"
        })
    );
    assert_eq!(
        snapshot["effective_overrides"],
        json!({
            "dd_refresh_rate_option":"manual", "dd_hdr_option":"auto"
        })
    );
    assert!(
        opened_rtsp_payload(&broker)
            .get("display_request")
            .is_none()
    );
}

#[test]
fn certificate_matched_peer_preserves_all_eight_sparse_display_fields() {
    let certificate = vec![15; 32];
    let display = json!({
        "dd_mode_remapping":{"mixed":[]},
        "dd_resolution_option":"manual",
        "dd_manual_resolution":"1920x1080",
        "dd_refresh_rate_option":"manual",
        "dd_manual_refresh_rate":"59.94",
        "dd_hdr_option":"disabled",
        "dd_configuration_option":"ensure_active",
        "dd_hdr_request_override":"force_off"
    });
    let overrides: ClientConfigOverrides = serde_json::from_value(display.clone()).unwrap();
    let selected = PeerIdentity::new("127.0.0.1".parse().unwrap(), certificate.clone())
        .unwrap()
        .with_paired_identity(
            "display-client".into(),
            fingerprint(&certificate),
            overrides,
        )
        .unwrap();
    assert_eq!(selected.client_display_overrides, display);
}

#[test]
fn forged_display_readback_stops_before_rtsp_open() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut broker = Broker {
        application_input_overrides: Some(json!({"dd_refresh_rate_option":"manual"})),
        wrong_application_display_overrides: true,
        ..Broker::default()
    };
    assert!(controller.launch(10, request(1), peer(1), now).is_none());
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
    assert_ne!(reply.status, 200);
    assert!(!broker.actions().contains(&("amaterasu.rtsp/1", "open")));
}

#[test]
fn forged_rtsp_display_snapshot_never_completes_launch() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut broker = Broker {
        wrong_rtsp_display_policy_snapshot: true,
        ..Broker::default()
    };
    assert!(controller.launch(10, request(1), peer(1), now).is_none());
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
    assert_ne!(reply.status, 200);
    assert!(broker.actions().contains(&("amaterasu.rtsp/1", "open")));
}

#[test]
fn explicit_null_client_display_field_inherits_application_choice() {
    let certificate = vec![14; 32];
    let config_overrides: ClientConfigOverrides = serde_json::from_value(json!({
        "dd_refresh_rate_option":null,
        "dd_hdr_option":"disabled"
    }))
    .unwrap();
    let paired = PeerIdentity::new("127.0.0.1".parse().unwrap(), certificate.clone())
        .unwrap()
        .with_paired_identity(
            "display-client".into(),
            fingerprint(&certificate),
            config_overrides,
        )
        .unwrap();
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut broker = Broker {
        application_input_overrides: Some(json!({"dd_refresh_rate_option":"manual"})),
        ..Broker::default()
    };
    assert!(controller.launch(10, request(14), paired, now).is_none());
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(reply.status, 200);
    let snapshot = &opened_rtsp_payload(&broker)["display_policy_snapshot"];
    assert!(
        snapshot["client_overrides"]
            .get("dd_refresh_rate_option")
            .is_none()
    );
    assert_eq!(
        snapshot["effective_overrides"]["dd_refresh_rate_option"],
        "manual"
    );
    assert_eq!(snapshot["effective_overrides"]["dd_hdr_option"], "disabled");
}

#[test]
fn rtsp_snapshot_readback_mismatch_never_completes_launch() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut broker = Broker {
        application_executable_path: Some("C:\\Games\\Example.exe".into()),
        wrong_rtsp_snapshot: true,
        ..Broker::default()
    };
    assert!(controller.launch(10, request(1), peer(1), now).is_none());
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
    assert_ne!(reply.status, 200);
    assert!(broker.actions().contains(&("amaterasu.rtsp/1", "open")));
    assert_eq!(controller.current_game(&peer(1)), 0);
}

#[test]
fn expired_preflight_settles_without_scheduling_application_cleanup() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut broker = Broker::default();
    assert!(controller.launch(10, request(1), peer(1), now).is_none());
    for _ in 0..8 {
        assert!(
            controller
                .poll(now, &mut |command| broker.send(command))
                .is_empty()
        );
        if broker
            .actions()
            .contains(&("amaterasu.launch/1", "preflight_export"))
        {
            break;
        }
    }
    assert!(
        broker
            .actions()
            .contains(&("amaterasu.launch/1", "preflight_export"))
    );
    let expired = now + std::time::Duration::from_secs(41);
    assert!(
        controller
            .poll(expired, &mut |command| broker.send(command))
            .is_empty()
    );
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, expired);
    assert_ne!(reply.status, 200);
    assert!(
        !broker
            .actions()
            .contains(&("amaterasu.launch/1", "launch_export"))
    );
    assert!(!broker.actions().contains(&("amaterasu.launch/1", "lookup")));
}

#[test]
fn response_loss_before_first_flush_stops_rtsp_and_application() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut broker = Broker::default();
    assert!(controller.launch(10, request(1), peer(1), now).is_none());
    let (connection, reply) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(reply.status, 200);
    controller.connection_closed(connection, now);
    for _ in 0..24 {
        controller.poll(now, &mut |command| broker.send(command));
    }
    let actions = broker.actions();
    assert!(actions.contains(&("amaterasu.rtsp/1", "close")));
    assert!(actions.contains(&("amaterasu.launch/1", "stop")));
    assert_eq!(controller.current_game(&peer(1)), 0);
}

#[test]
fn rtsp_cleanup_failure_still_stops_application_and_retains_failure() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut broker = Broker::default();
    launch_ready(&mut controller, &mut broker, now);
    broker.fail_rtsp_cleanup = true;

    assert!(controller.cancel(20, &peer(1), now).is_none());
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(reply.status, 503);
    assert!(broker.actions().contains(&("amaterasu.launch/1", "stop")));
    assert!(controller.busy(), "unconfirmed RTSP cleanup remains owned");
}

#[test]
fn malformed_or_wrong_provider_identity_never_becomes_ready() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut broker = Broker::default();
    launch_ready(&mut controller, &mut broker, now);
    broker.wrong_application_id = true;
    for _ in 0..4 {
        controller.poll(now, &mut |command| broker.send(command));
    }
    assert_eq!(controller.current_game(&peer(1)), 0);
}

#[test]
fn unhealthy_application_response_adopts_the_owned_id_then_cleans_it() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut broker = Broker {
        application_unhealthy: true,
        ..Broker::default()
    };
    assert!(controller.launch(10, request(1), peer(1), now).is_none());
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(reply.status, 503);
    assert!(broker.actions().contains(&("amaterasu.launch/1", "stop")));
    assert_eq!(controller.current_game(&peer(1)), 0);
}

#[test]
fn lost_rtsp_admission_is_settled_before_owned_lookup_without_reopening() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut broker = Broker {
        lose_rtsp_open_once: true,
        application_executable_path: Some("C:\\Games\\Example.exe".into()),
        ..Broker::default()
    };
    assert!(controller.launch(10, request(1), peer(1), now).is_none());
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(reply.status, 200);

    let rtsp_requests: Vec<_> = broker
        .commands
        .iter()
        .enumerate()
        .filter_map(|(index, command)| match command {
            Command::Request {
                service,
                payload,
                operation_id,
                ..
            } if service == "amaterasu.rtsp/1" => {
                Some((index, payload.clone(), operation_id.clone()))
            }
            _ => None,
        })
        .collect();
    assert_eq!(rtsp_requests.len(), 3);
    assert_eq!(rtsp_requests[0].1, rtsp_requests[1].1);
    let record = controller.records.values().next().expect("launch record");
    assert_eq!(
        rtsp_requests[0].1["application_operation_id"],
        record.application_operation
    );
    assert_eq!(rtsp_requests[0].1["app_id"], super::app_id(1));
    assert_eq!(
        rtsp_requests[0].1["catalog_revision"],
        record.application_catalog_revision.unwrap()
    );
    assert!(rtsp_requests[0].1.get("display_request").is_none());
    assert_eq!(
        rtsp_requests[0].1["frame_limiter_settings"],
        broker.rtsp_snapshot.clone().expect("frozen RTSP snapshot")
    );
    assert_eq!(rtsp_requests[0].2, rtsp_requests[1].2);
    assert_eq!(rtsp_requests[2].1["action"], "lookup");
    let cancel = broker
        .commands
        .iter()
        .position(|command| matches!(command, Command::Cancel { .. }))
        .expect("cancel uncertain admission");
    let release = broker
        .commands
        .iter()
        .position(|command| matches!(command, Command::ReleaseResult { .. }))
        .expect("release uncertain admission");
    assert!(rtsp_requests[1].0 < cancel && cancel < release && release < rtsp_requests[2].0);
}

#[test]
fn natural_application_exit_closes_the_stream_and_releases_the_application() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut broker = Broker::default();
    launch_ready(&mut controller, &mut broker, now);
    broker.application_state = "stopped";
    for _ in 0..24 {
        controller.poll(now, &mut |command| broker.send(command));
    }
    let actions = broker.actions();
    assert!(actions.contains(&("amaterasu.rtsp/1", "close")));
    assert!(actions.contains(&("amaterasu.launch/1", "stop")));
    assert_eq!(controller.current_game(&peer(1)), 0);
}

#[test]
fn long_cleanup_outlives_short_stop_rpc_and_automatically_observes_terminal_undo() {
    for disconnect_cancel in [false, true] {
        let now = Instant::now();
        let mut controller = Controller::new(Some(config())).unwrap();
        let mut broker = Broker {
            // Provider 321s plus eight sequential 300s raw undos with 3s tails.
            application_cleanup_budget: json!(2_745_000),
            application_stop_pending: true,
            ..Broker::default()
        };
        launch_ready(&mut controller, &mut broker, now);
        assert!(controller.cancel(20, &peer(1), now).is_none());
        let deadline = controller.records.values().next().unwrap().deadline;
        assert_eq!(deadline, now + Duration::from_secs(2_775));
        for _ in 0..16 {
            assert!(
                controller
                    .poll(now, &mut |command| broker.send(command))
                    .is_empty()
            );
        }
        assert!(broker.held_application_stop_request.is_some());
        // A 15s broker RPC expires independently of the total owed undo budget.
        broker.application_stop_expired = true;
        if disconnect_cancel {
            // An early closed cancel request drops only its delivery slot.
            controller.connection_closed(20, now + Duration::from_secs(16));
        }
        for elapsed in [16, 21, 300, 2_700] {
            let current = now + Duration::from_secs(elapsed);
            for _ in 0..12 {
                assert!(
                    controller
                        .poll(current, &mut |command| broker.send(command))
                        .is_empty()
                );
            }
            let record = controller.records.values().next().unwrap();
            assert_eq!(record.state, super::record::State::Stopping);
            assert!(record.application_requested);
            assert!(!record.application_cleanup_blocked);
            assert_eq!(record.deadline, deadline);
            let request_count = broker
                .commands
                .iter()
                .filter(|command| matches!(command, Command::Request { .. }))
                .count();
            for _ in 0..12 {
                assert!(
                    controller
                        .poll(current, &mut |command| broker.send(command))
                        .is_empty()
                );
            }
            assert_eq!(
                broker
                    .commands
                    .iter()
                    .filter(|command| matches!(command, Command::Request { .. }))
                    .count(),
                request_count,
                "healthy stopping readback waits for the 100ms poll interval"
            );
        }
        broker.application_stop_pending = false;
        let mut replies = Vec::new();
        for _ in 0..16 {
            replies.extend(
                controller.poll(now + Duration::from_secs(2_701), &mut |command| {
                    broker.send(command)
                }),
            );
        }
        let record = controller.records.values().next().unwrap();
        assert_eq!(record.state, super::record::State::Stopped);
        assert!(!record.application_requested);
        assert!(record.application_launch.is_none());
        assert!(!controller.busy());
        if disconnect_cancel {
            assert!(replies.is_empty());
        } else {
            assert_eq!(replies.len(), 1);
            assert_eq!(replies[0].0, 20);
            assert_eq!(replies[0].1.status, 200);
        }
        assert_eq!(
            broker
                .actions()
                .iter()
                .filter(|action| **action == ("amaterasu.launch/1", "stop"))
                .count(),
            1
        );
        assert!(broker.commands.iter().all(|command| !matches!(command, Command::Request { timeout_ms, .. } if *timeout_ms > 30_000)));
        assert!(broker.commands.iter().any(|command| matches!(command, Command::Request { service, payload, timeout_ms:15_000, .. } if service == "amaterasu.launch/1" && payload["action"] == "stop")));
    }
}

#[test]
fn cleanup_deadline_expiry_retains_application_until_explicit_retry() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut broker = Broker {
        application_stop_pending: true,
        application_stop_expired: true,
        ..Broker::default()
    };
    launch_ready(&mut controller, &mut broker, now);
    assert!(controller.cancel(20, &peer(1), now).is_none());
    let deadline = controller.records.values().next().unwrap().deadline;
    assert_eq!(deadline, now + Duration::from_secs(50));

    for _ in 0..16 {
        assert!(
            controller
                .poll(now, &mut |command| broker.send(command))
                .is_empty()
        );
    }

    let mut replies = Vec::new();
    for _ in 0..16 {
        replies.extend(controller.poll(deadline, &mut |command| broker.send(command)));
    }
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].0, 20);
    assert_eq!(replies[0].1.status, 503);
    let record = controller.records.values().next().unwrap();
    assert_eq!(record.state, super::record::State::CleanupFailed);
    assert_eq!(record.cleanup_error, Some("cleanup_deadline_exceeded"));
    assert!(record.application_requested);
    assert!(controller.busy());

    broker.application_stop_pending = false;
    let retry_at = deadline + Duration::from_secs(1);
    assert!(controller.cancel(21, &peer(1), retry_at).is_none());
    let (_, retried) = poll_until_reply(&mut controller, &mut broker, retry_at);
    assert_eq!(retried.status, 200);
    assert!(controller.records.values().next().unwrap().state.terminal());
    assert!(!controller.busy());
}

#[test]
fn cleanup_budget_contract_rejects_missing_malformed_and_out_of_range_preflight() {
    for budget in [
        None,
        Some(Value::Null),
        Some(json!(false)),
        Some(json!("30000")),
        Some(json!(20_000.5)),
        Some(json!(-1)),
        Some(json!(19_999)),
        Some(json!(2_745_001)),
        Some(json!(u64::MAX)),
    ] {
        let now = Instant::now();
        let mut controller = Controller::new(Some(config())).unwrap();
        let mut broker = Broker::default();
        assert!(controller.launch(10, request(1), peer(1), now).is_none());
        let mut reply = None;
        for _ in 0..24 {
            let replies = controller.poll(now, &mut |command| {
                let response = broker.send(command)?;
                Ok(match response {
                    Response::Result { mut payload }
                        if payload.get("preflight_token").is_some() =>
                    {
                        match &budget {
                            Some(value) => payload["cleanup_budget_ms"] = value.clone(),
                            None => {
                                payload.as_object_mut().unwrap().remove("cleanup_budget_ms");
                            }
                        }
                        Response::Result { payload }
                    }
                    other => other,
                })
            });
            if let Some(result) = replies.into_iter().next() {
                reply = Some(result.1);
                break;
            }
        }
        assert_eq!(
            reply.expect("invalid budget must produce failure").status,
            503
        );
        assert!(
            !broker
                .actions()
                .contains(&("amaterasu.launch/1", "launch_export"))
        );
        assert!(!broker.actions().contains(&("amaterasu.rtsp/1", "open")));
    }
}

#[test]
fn genuine_application_cleanup_failure_requires_explicit_retry() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut broker = Broker::default();
    launch_ready(&mut controller, &mut broker, now);
    broker.application_terminal_stop_state = Some("cleanup_failed");
    assert!(controller.cancel(20, &peer(1), now).is_none());
    let (_, failed) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(failed.status, 503);
    let record = controller.records.values().next().unwrap();
    assert_eq!(record.state, super::record::State::CleanupFailed);
    assert!(record.application_requested);
    assert!(record.application_cleanup_blocked);
    let deadline = record.deadline;
    broker.application_terminal_stop_state = None;
    for _ in 0..8 {
        assert!(
            controller
                .poll(now + Duration::from_secs(1), &mut |command| broker
                    .send(command))
                .is_empty()
        );
    }
    assert_eq!(
        controller.records.values().next().unwrap().deadline,
        deadline
    );
    assert!(
        controller
            .cancel(21, &peer(1), now + Duration::from_secs(1))
            .is_none()
    );
    let (_, completed) =
        poll_until_reply(&mut controller, &mut broker, now + Duration::from_secs(1));
    assert_eq!(completed.status, 200);
    assert!(controller.records.values().next().unwrap().state.terminal());
}

#[test]
fn changed_cleanup_budget_and_unhealthy_stopping_readback_retain_owned_failure() {
    for changed_budget in [false, true] {
        let now = Instant::now();
        let mut controller = Controller::new(Some(config())).unwrap();
        let mut broker = Broker::default();
        launch_ready(&mut controller, &mut broker, now);
        if changed_budget {
            broker.application_cleanup_budget = json!(21_000);
        } else {
            broker.application_stop_pending = true;
            broker.application_stop_expired = true;
            broker.application_unhealthy = true;
        }
        assert!(controller.cancel(20, &peer(1), now).is_none());
        let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
        assert_eq!(reply.status, 503);
        let record = controller.records.values().next().unwrap();
        assert_eq!(record.state, super::record::State::CleanupFailed);
        assert!(record.application_requested);
        assert!(record.application_cleanup_blocked);
        assert!(controller.busy());
    }
}

#[test]
fn repeated_cancel_and_revocation_do_not_extend_cleanup_deadlines() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut broker = Broker {
        application_cleanup_budget: json!(2_745_000),
        ..Broker::default()
    };
    launch_ready(&mut controller, &mut broker, now);

    assert!(controller.cancel(20, &peer(1), now).is_none());
    let deadline = controller.records.values().next().unwrap().deadline;
    assert_eq!(deadline, now + Duration::from_secs(2_775));
    assert_eq!(
        controller
            .cancel(21, &peer(1), now + Duration::from_secs(1))
            .unwrap()
            .status,
        409
    );
    assert_eq!(
        controller.records.values().next().unwrap().deadline,
        deadline
    );
    controller.revoke_untrusted(now + Duration::from_secs(2), |_| false);
    controller.revoke_untrusted(now + Duration::from_secs(3), |_| false);
    assert_eq!(
        controller.records.values().next().unwrap().deadline,
        deadline
    );
}
#[test]
fn dual_uncertain_cleanup_calls_are_both_retained_and_reconciled_before_success() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut broker = Broker::default();
    launch_ready(&mut controller, &mut broker, now);
    broker.fail_rtsp_settlement = true;
    broker.fail_application_settlement = true;
    assert!(controller.cancel(20, &peer(1), now).is_none());

    let (_, failed) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(failed.status, 503);
    let record = controller.records.values().next().unwrap();
    assert_eq!(record.uncertain.len(), 2);
    let deadline = record.deadline;

    broker.fail_rtsp_settlement = false;
    broker.fail_application_settlement = false;
    assert!(
        controller
            .cancel(21, &peer(1), now + Duration::from_secs(1))
            .is_none()
    );
    let (_, completed) =
        poll_until_reply(&mut controller, &mut broker, now + Duration::from_secs(1));
    assert_eq!(completed.status, 200);
    let record = controller.records.values().next().unwrap();
    assert!(record.uncertain.is_empty());
    assert!(record.state.terminal());
    assert!(
        record.deadline > deadline,
        "explicit retry gets one fresh budget"
    );
}

#[test]
fn software_scopes_freeze_and_qp_resolves_client_before_application_before_global() {
    let now = Instant::now();
    for (client_override, client_threads, client_qp, application_qp, expected_qp) in [
        (None, None, None, None, 28),
        (Some(""), Some(-7), Some(31), Some(30), 31),
        (None, None, None, Some(30), 30),
    ] {
        let mut controller = Controller::new(Some(config())).unwrap();
        controller.set_global_qp(28);
        controller.set_software_encoder_options(SoftwareEncoderOptions {
            sw_preset: Some("fast".into()),
            sw_tune: Some("film".into()),
            encoder: Some(amaterasu_module_sdk::EncoderBackend::Auto),
            min_threads: Some(4),
        });
        let mut application_overrides = json!({"sw_preset":"slow","sw_tune":"film,zerolatency","encoder":"software","min_threads":6});
        if let Some(qp) = application_qp {
            application_overrides["qp"] = json!(qp);
        }
        let mut broker = Broker {
            application_input_overrides: Some(application_overrides),
            ..Default::default()
        };
        let cert = vec![9; 32];
        let client = PeerIdentity::new("127.0.0.1".parse().unwrap(), cert.clone())
            .unwrap()
            .with_paired_identity(
                "client-9".into(),
                fingerprint(&cert),
                ClientConfigOverrides {
                    sw_preset: client_override.map(str::to_owned),
                    sw_tune: None,
                    encoder: None,
                    min_threads: client_threads,
                    qp: client_qp,
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(controller.launch(10, request(9), client, now).is_none());
        controller.set_software_encoder_options(SoftwareEncoderOptions {
            sw_preset: Some("ultrafast".into()),
            sw_tune: Some("animation".into()),
            encoder: None,
            min_threads: Some(32),
        });
        controller.set_global_qp(35);
        let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
        assert_eq!(reply.status, 200);
        let open = opened_rtsp_payload(&broker);
        assert_eq!(open["sw_preset"], client_override.unwrap_or("slow"));
        assert_eq!(open["sw_tune"], "film,zerolatency");
        assert_eq!(open["capture"]["encoder"], "software");
        assert_eq!(open["min_threads"], client_threads.unwrap_or(6));
        assert_eq!(open["qp"], expected_qp);
        let cert = vec![10; 32];
        let unpaired = PeerIdentity::new("127.0.0.1".parse().unwrap(), cert.clone()).unwrap();
        assert!(
            unpaired
                .with_paired_identity(
                    "client-9".into(),
                    fingerprint(&[9; 32]),
                    ClientConfigOverrides {
                        sw_preset: Some("slow".into()),
                        ..Default::default()
                    }
                )
                .is_err()
        );
    }
}

#[test]
fn nvenc_scopes_freeze_client_over_application_over_global_and_verify_readback() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let global = amaterasu_module_sdk::NvencSettings {
        nvenc_preset: 2,
        nvenc_vbv_increase: 10,
        ..Default::default()
    };
    controller.set_nvenc_settings(global);
    controller.set_nvenc_spatial_aq(true);

    let application_overrides = json!({
        "nvenc_preset": 4,
        "nvenc_h264_cavlc": true,
        "nvenc_twopass": "full_res",
        "nvenc_vbv_increase": 25,
        "nvenc_spatial_aq": false
    });
    let mut broker = Broker {
        application_input_overrides: Some(application_overrides),
        ..Default::default()
    };
    let certificate = vec![19; 32];
    let client = PeerIdentity::new("127.0.0.1".parse().unwrap(), certificate.clone())
        .unwrap()
        .with_paired_identity(
            "nvenc-client".into(),
            fingerprint(&certificate),
            serde_json::from_value(json!({
                "nvenc_preset": 7,
                "nvenc_split_encode": "disabled",
                "nvenc_spatial_aq": true
            }))
            .unwrap(),
        )
        .unwrap();

    assert!(controller.launch(10, request(19), client, now).is_none());
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(reply.status, 200);
    let open = opened_rtsp_payload(&broker);
    assert_eq!(open["nvenc_settings"]["nvenc_preset"], 7);
    assert_eq!(open["nvenc_settings"]["nvenc_h264_cavlc"], true);
    assert_eq!(open["nvenc_settings"]["nvenc_twopass"], "full_res");
    assert_eq!(open["nvenc_settings"]["nvenc_vbv_increase"], 25);
    assert_eq!(open["nvenc_settings"]["nvenc_split_encode"], "disabled");
    assert_eq!(open["nvenc_spatial_aq"], true);
    assert_eq!(broker.rtsp_nvenc_settings, open["nvenc_settings"]);
}

#[test]
fn malformed_software_application_options_fail_before_rtsp_and_launch() {
    for overrides in [
        json!({"sw_preset":false}),
        json!({"sw_tune":"x".repeat(257)}),
        json!({"encoder":"nvenc"}),
        json!({"min_threads":2147483648_i64}),
        json!({"min_threads":1.5}),
        json!({"qp":-2147483649_i64}),
        json!({"qp":1.5}),
    ] {
        let now = Instant::now();
        let mut controller = Controller::new(Some(config())).unwrap();
        let mut broker = Broker {
            application_input_overrides: Some(overrides),
            ..Default::default()
        };
        assert!(controller.launch(10, request(8), peer(8), now).is_none());
        let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
        assert_ne!(reply.status, 200);
        assert!(
            !broker
                .actions()
                .iter()
                .any(
                    |(service, action)| (*service == "amaterasu.rtsp/1" && *action == "open")
                        || (*service == "amaterasu.launch/1" && *action == "launch_export")
                )
        );
    }
}

fn peer_with_keybindings(marker: u8, keybindings: Option<Value>) -> PeerIdentity {
    let certificate = vec![marker; 32];
    let overrides: ClientConfigOverrides =
        serde_json::from_value(json!({"keybindings":keybindings})).unwrap();
    PeerIdentity::new("127.0.0.1".parse().unwrap(), certificate.clone())
        .unwrap()
        .with_paired_identity(
            format!("client-{marker}"),
            fingerprint(&certificate),
            overrides,
        )
        .unwrap()
}

#[test]
fn admitted_keybindings_select_the_client_whole_list_then_application_then_global() {
    let application = json!([65, 66, 70, 71]);
    let client = json!([65, 67, 65, 68, 0, 255]);
    for (marker, client, application, expected) in [
        (71, Some(client.clone()), Some(application.clone()), client),
        (72, Some(json!([])), Some(application.clone()), json!([])),
        (
            73,
            Some(Value::Null),
            Some(application.clone()),
            application.clone(),
        ),
        (74, None, Some(application.clone()), application),
        (75, None, Some(json!([])), json!([])),
        (76, None, Some(Value::Null), Value::Null),
        (77, None, None, Value::Null),
    ] {
        let now = Instant::now();
        let mut broker = Broker {
            application_input_overrides: application
                .map(|selected| json!({"keybindings":selected})),
            ..Broker::default()
        };
        let mut controller = Controller::new(Some(config())).unwrap();
        assert!(
            controller
                .launch(
                    10,
                    request(marker),
                    peer_with_keybindings(marker, client),
                    now
                )
                .is_none()
        );
        let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
        assert_eq!(reply.status, 200);
        let opened = opened_rtsp_payload(&broker);
        assert_eq!(opened["keybindings"], expected);
        assert_eq!(
            opened["display_policy_snapshot"]["certificate_id"],
            fingerprint(&[marker; 32])
        );
    }
}

#[test]
fn invalid_keybindings_fail_before_launch_export_and_rtsp_open() {
    for invalid in [
        json!([65]),
        json!([0, 256]),
        json!([-1, 0]),
        json!([65.0, 66]),
        json!([true, 66]),
        json!(["65", 66]),
        json!({}),
        json!(vec![0_u8; 514]),
    ] {
        assert!(
            serde_json::from_value::<ClientConfigOverrides>(json!({"keybindings":invalid}))
                .is_err()
        );
        let now = Instant::now();
        let mut controller = Controller::new(Some(config())).unwrap();
        let mut broker = Broker {
            application_input_overrides: Some(json!({"keybindings":invalid})),
            ..Broker::default()
        };
        assert!(controller.launch(10, request(78), peer(78), now).is_none());
        let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
        assert_ne!(reply.status, 200, "{invalid}");
        assert!(
            !broker
                .actions()
                .contains(&("amaterasu.launch/1", "launch_export"))
        );
        assert!(!broker.actions().contains(&("amaterasu.rtsp/1", "open")));
    }
}

#[test]
fn keybindings_do_not_make_a_mismatched_certificate_an_authorized_client() {
    let certificate = vec![79; 32];
    let peer = PeerIdentity::new("127.0.0.1".parse().unwrap(), certificate).unwrap();
    let overrides = serde_json::from_value(json!({"keybindings":[65,66]})).unwrap();
    assert_eq!(
        peer.with_paired_identity("client-79".into(), "00".repeat(32), overrides)
            .err(),
        Some("invalid_paired_identity")
    );
}

#[test]
fn changed_application_keybindings_after_preflight_cannot_open_rtsp() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut broker = Broker {
        application_input_overrides: Some(json!({"keybindings":[65,66]})),
        ..Broker::default()
    };
    assert!(controller.launch(10, request(80), peer(80), now).is_none());
    for _ in 0..8 {
        controller.poll(now, &mut |command| broker.send(command));
        if controller
            .records
            .values()
            .any(|record| record.stage == Stage::LaunchApplication)
        {
            break;
        }
    }
    assert!(
        controller
            .records
            .values()
            .any(|record| record.stage == Stage::LaunchApplication)
    );
    broker.application_input_overrides = Some(json!({"keybindings":[]}));
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
    assert_ne!(reply.status, 200);
    assert!(!broker.actions().contains(&("amaterasu.rtsp/1", "open")));
}

fn uhd_profile(encoder: EncoderSelection) -> StreamingConfig {
    let mut streaming = config();
    streaming.capture.encoder = encoder;
    streaming.profile.max_width = 3840;
    streaming.profile.max_height = 2160;
    streaming.profile.max_fps = 120;
    streaming
}

fn uhd_request(key: u8) -> LaunchRequest {
    LaunchRequest {
        width: 3840,
        height: 2160,
        fps: 120,
        ..request(key)
    }
}

fn nvenc_and_x264() -> EncoderSnapshot {
    encoders(vec![
        encoder_entry("amaterasu.hardware.nvenc-cuda.h264", "h264", true),
        encoder_entry("amaterasu.hardware.nvenc-cuda.hevc", "hevc", true),
        encoder_entry("amaterasu.hardware.nvenc-cuda.av1", "av1", true),
        encoder_entry("amaterasu.software.x264", "h264", false),
    ])
}

const AUTO_ENCODER: EncoderSelection =
    EncoderSelection::Backend(amaterasu_module_sdk::EncoderBackend::Auto);

#[test]
fn hardware_encoders_offer_every_codec_to_rtsp_up_to_the_profile_maximum() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(uhd_profile(AUTO_ENCODER))).unwrap();
    controller.set_encoder_snapshot(nvenc_and_x264());
    let mut broker = Broker::default();

    assert!(
        controller
            .launch(10, uhd_request(61), peer(61), now)
            .is_none()
    );
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(reply.status, 200);
    let open = opened_rtsp_payload(&broker);
    assert_eq!(open["profile"]["codecs"], json!(["av1", "hevc", "h264"]));
    assert!(open["profile"].get("codec").is_none());
    assert_eq!(open["negotiation_bounds"]["max_width"], 3840);
    assert_eq!(open["negotiation_bounds"]["max_height"], 2160);
    assert_eq!(open["negotiation_bounds"]["max_fps"], 120);
}

#[test]
fn software_only_launches_above_full_hd_sixty_are_refused_before_any_effect() {
    let now = Instant::now();
    for (snapshot, message) in [
        (
            Some(encoders(vec![encoder_entry(
                "amaterasu.software.x264",
                "h264",
                false,
            )])),
            "no hardware encoder for this stream mode",
        ),
        (None, "encoder capabilities are not known yet"),
        (Some(encoders(vec![])), "no video encoder is available"),
    ] {
        let mut controller = Controller::new(Some(uhd_profile(AUTO_ENCODER))).unwrap();
        if let Some(snapshot) = snapshot {
            controller.set_encoder_snapshot(snapshot);
        }
        let mut broker = Broker::default();
        let reply = controller
            .launch(10, uhd_request(62), peer(62), now)
            .expect("immediate refusal");
        assert_eq!(reply.status, 503);
        assert!(String::from_utf8(reply.body).unwrap().contains(message));
        assert!(controller.records.is_empty());
        assert!(
            controller
                .poll(now, &mut |command| broker.send(command))
                .is_empty()
        );
        assert!(broker.commands.is_empty());
    }
}

#[test]
fn software_codecs_keep_negotiation_within_the_software_limit() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(uhd_profile(AUTO_ENCODER))).unwrap();
    controller.set_encoder_snapshot(encoders(vec![
        encoder_entry("amaterasu.hardware.nvenc-cuda.hevc", "hevc", true),
        encoder_entry("amaterasu.software.x264", "h264", false),
    ]));
    let mut broker = Broker::default();
    let full_hd = LaunchRequest {
        width: 1920,
        height: 1080,
        fps: 60,
        ..request(63)
    };
    assert!(controller.launch(10, full_hd, peer(63), now).is_none());
    let _ = poll_until_reply(&mut controller, &mut broker, now);
    let open = opened_rtsp_payload(&broker);
    assert_eq!(open["profile"]["codecs"], json!(["hevc", "h264"]));
    assert_eq!(
        (
            &open["negotiation_bounds"]["max_width"],
            &open["negotiation_bounds"]["max_height"],
            &open["negotiation_bounds"]["max_fps"],
        ),
        (&json!(1920), &json!(1080), &json!(60))
    );
}

#[test]
fn a_numeric_encoder_selection_offers_only_that_encoder_codec() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(uhd_profile(EncoderSelection::Index(1)))).unwrap();
    controller.set_encoder_snapshot(nvenc_and_x264());
    let mut broker = Broker::default();
    assert!(
        controller
            .launch(10, uhd_request(64), peer(64), now)
            .is_none()
    );
    let _ = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(
        opened_rtsp_payload(&broker)["profile"]["codecs"],
        json!(["hevc"])
    );
}

#[test]
fn an_h264_only_offer_keeps_the_legacy_rtsp_profile_shape() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    controller.set_encoder_snapshot(hardware_h264());
    let mut broker = Broker::default();
    assert!(controller.launch(10, request(65), peer(65), now).is_none());
    let _ = poll_until_reply(&mut controller, &mut broker, now);
    let profile = &opened_rtsp_payload(&broker)["profile"];
    assert!(profile.get("codecs").is_none() && profile.get("codec").is_none());
}

#[test]
fn codec_advertisement_tracks_configuration_and_the_latest_snapshot() {
    assert_eq!(
        Controller::new(None).unwrap().codec_advertisement(),
        CodecAdvertisement::NONE
    );
    let mut controller = Controller::new(Some(config())).unwrap();
    assert_eq!(controller.codec_advertisement().codec_mode_support, 0x1);
    controller.set_encoder_snapshot(nvenc_and_x264());
    assert_eq!(
        controller.codec_advertisement(),
        CodecAdvertisement {
            codec_mode_support: 0x10101,
            max_luma_pixels_hevc: 1_869_449_984,
        }
    );
}

#[test]
fn scoped_software_selection_uses_the_frozen_snapshot_to_constrain_codec_negotiation() {
    let now = Instant::now();
    let mut controller = Controller::new(Some(uhd_profile(AUTO_ENCODER))).unwrap();
    controller.set_encoder_snapshot(nvenc_and_x264());
    let mut broker = Broker {
        application_input_overrides: Some(json!({"encoder":"software"})),
        ..Default::default()
    };
    assert!(controller.launch(10, request(84), peer(84), now).is_none());
    controller.set_encoder_snapshot(encoders(vec![]));
    let (_, reply) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(reply.status, 200);
    let open = opened_rtsp_payload(&broker);
    assert_eq!(open["capture"]["encoder"], "software");
    assert!(open["profile"].get("codecs").is_none());
    assert_eq!(open["negotiation_bounds"]["max_width"], 1920);
    assert_eq!(open["negotiation_bounds"]["max_fps"], 60);
}
