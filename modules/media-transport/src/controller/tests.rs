use super::*;
use crate::stream::tests::{receivers, request, video_packet};
use amaterasu_module_sdk::abi::{STATUS_INVALID_ARGUMENT, STATUS_OK};

fn controller() -> Controller {
    Controller::new(Settings {
        enabled: true,
        allow_remote: false,
        allowed_principals: vec!["owner".into(), "other".into()],
    })
}

#[test]
fn disabled_authorization_destination_and_lookup_are_fail_closed() {
    let (video, audio) = receivers();
    let request = request(&video, &audio, false);
    let mut disabled = Controller::new(Settings::default());
    assert_eq!(
        disabled
            .handle("owner", Operation::Status { stream: None })
            .unwrap()
            .payload["enabled"],
        false
    );
    assert_eq!(
        disabled
            .handle("owner", Operation::Open(request.clone()))
            .err(),
        Some("disabled")
    );
    let mut controller = controller();
    assert_eq!(
        controller
            .handle("foreign", Operation::Open(request.clone()))
            .err(),
        Some("forbidden")
    );
    let mut remote = request.clone();
    remote.peer_ip = "192.0.2.1".parse().unwrap();
    assert_eq!(
        controller.handle("owner", Operation::Open(remote)).err(),
        Some("remote_disabled")
    );
    let mut invalid = request;
    invalid.peer_ip = "224.0.0.1".parse().unwrap();
    assert_eq!(
        controller.handle("owner", Operation::Open(invalid)).err(),
        Some("invalid_destination")
    );
    assert_eq!(
        controller
            .handle(
                "owner",
                Operation::Lookup {
                    operation_id: "missing".into()
                }
            )
            .err(),
        Some("stream_not_found")
    );
}

#[test]
fn ping_timeout_defaults_to_ten_seconds_and_validates_the_signed_integer_range() {
    let mut request: Open = serde_json::from_value(json!({
        "peer_ip": "127.0.0.1",
        "video_port": 49001,
        "audio_port": 49002,
        "audio": {"packet_ms": 10, "channels": 2, "wire_payload_bytes": 4}
    }))
    .unwrap();
    assert_eq!(request.ping_timeout_ms, 10_000);
    assert!(request.validate(false).is_ok());

    for value in [0, i32::MAX as i64] {
        request.ping_timeout_ms = value;
        assert!(request.validate(false).is_ok());
    }
    for value in [-1, i32::MAX as i64 + 1] {
        request.ping_timeout_ms = value;
        assert_eq!(request.validate(false), Err("invalid_ping_timeout"));
    }
}

#[test]
fn authenticated_video_format_selection_rejects_mismatched_packets_before_queueing() {
    let (video, audio) = receivers();
    let mut stream_controller = controller();
    let opened = stream_controller
        .handle("owner", Operation::Open(request(&video, &audio, false)))
        .unwrap();
    let id = opened.created.unwrap();
    let hevc = amaterasu_module_sdk::VideoStreamFormat {
        codec: amaterasu_module_sdk::VideoCodec::Hevc,
        bit_depth: 8,
        dynamic_range: amaterasu_module_sdk::DynamicRange::Sdr,
    };
    let configured = stream_controller
        .handle(
            "owner",
            Operation::ConfigureVideoFormat {
                stream: id,
                video_stream_format: hevc,
            },
        )
        .unwrap();
    assert_eq!(configured.payload["video_stream_format"], json!(hevc));

    let h264 = [0, 0, 0, 1, 0x65, 1];
    // SAFETY: the fixture access unit stays live for the synchronous admission call.
    assert_eq!(
        unsafe { stream_controller.submit_video("owner", id, &video_packet(&h264, 0)) },
        STATUS_INVALID_ARGUMENT
    );
    let hevc_payload = [0, 0, 0, 1, 0x26, 1, 0x80];
    let packet = EncodedPacket {
        codec: amaterasu_media::CODEC_HEVC,
        ..video_packet(&hevc_payload, 0)
    };
    // SAFETY: the fixture access unit stays live for the synchronous admission call.
    assert_eq!(
        unsafe { stream_controller.submit_video("owner", id, &packet) },
        STATUS_OK
    );

    let mut wrong_owner = controller();
    assert_eq!(
        wrong_owner
            .handle(
                "foreign",
                Operation::ConfigureVideoFormat {
                    stream: id,
                    video_stream_format: hevc,
                }
            )
            .err(),
        Some("stream_not_found")
    );
}

#[test]
fn ownership_retry_key_history_secret_redaction_and_close_do_not_recreate_cipher_state() {
    let (video, audio) = receivers();
    let mut request = request(&video, &audio, true);
    request.operation_id = Some("one".into());
    let mut controller = controller();
    let result = controller
        .handle("owner", Operation::Open(request.clone()))
        .unwrap();
    let id = result.created.unwrap();
    assert!(!result.payload.to_string().contains("00010203"));
    let retry = controller
        .handle("owner", Operation::Open(request.clone()))
        .unwrap();
    assert!(retry.created.is_none());
    assert_eq!(retry.payload, result.payload);
    assert_eq!(controller.close("other", id), Err("stream_not_found"));
    assert_eq!(
        controller
            .handle("other", Operation::Status { stream: Some(id) })
            .unwrap()
            .payload["streams"],
        json!([])
    );
    let bytes = [0, 0, 0, 1, 0x65, 1];
    // SAFETY: owned packet bytes remain live through native admission.
    assert_eq!(
        unsafe { controller.submit_video("other", id, &video_packet(&bytes, 0)) },
        MEDIA_CLOSED
    );
    assert_eq!(
        unsafe { controller.submit_video("owner", id, &video_packet(&bytes, 0)) },
        STATUS_OK
    );
    let mut changed = request.clone();
    changed.video_port = changed.video_port.map(|port| port.saturating_add(1));
    assert_eq!(
        controller.handle("owner", Operation::Open(changed)).err(),
        Some("operation_conflict")
    );
    controller.close("owner", id).unwrap();
    assert_eq!(
        controller
            .handle("owner", Operation::Open(request.clone()))
            .err(),
        Some("stream_closed")
    );
    request.operation_id = Some("two".into());
    assert_eq!(
        controller.handle("other", Operation::Open(request)).err(),
        Some("key_reuse_forbidden")
    );
}

#[test]
fn four_streams_receive_equal_tick_budget_and_owner_limits_cannot_be_evicted() {
    let (video, audio) = receivers();
    let request = request(&video, &audio, false);
    let mut controller = controller();
    for owner in ["owner", "owner", "other", "other"] {
        controller
            .handle(owner, Operation::Open(request.clone()))
            .unwrap();
    }
    assert_eq!(
        controller.handle("owner", Operation::Open(request)).err(),
        Some("stream_limit")
    );
    for stream in controller.streams.values_mut() {
        stream
            .delivery
            .push(crate::datagrams::Medium::Video, vec![vec![1]; 32]);
    }
    controller.tick();
    for stream in controller.streams.values() {
        assert_eq!(stream.delivery.sent_datagrams, 16);
        assert_eq!(stream.delivery.queued(), 16);
    }
    controller.shutdown();
    assert!(controller.streams.is_empty());
}

#[test]
fn open_reports_batch_size_normalization_and_video_frame_uses_selected_allowance() {
    for (requested, effective, fallback, expected_sends) in [
        (0_u8, 64_u8, false, 64_usize),
        (16, 16, false, 16),
        (32, 32, false, 32),
        (64, 64, false, 64),
        (17, 64, true, 64),
    ] {
        let (video, audio) = receivers();
        let mut request = request(&video, &audio, false);
        request.video.max_batch_size_kb = requested;
        let mut controller = controller();
        let opened = controller
            .handle("owner", Operation::Open(request))
            .unwrap()
            .payload;
        assert_eq!(opened["video"]["max_batch_size_kb"], effective);
        assert_eq!(opened["video_batch_size_fallback"], fallback);

        let stream_id = opened["stream"].as_u64().unwrap();
        controller
            .streams
            .get_mut(&stream_id)
            .unwrap()
            .delivery
            .push_video(1, vec![vec![0; 1024]; 72]);
        controller.tick();

        let stream = &controller.streams[&stream_id];
        assert_eq!(stream.delivery.sent_datagrams, expected_sends as u64);
        assert_eq!(stream.delivery.queued(), 72 - expected_sends);
    }
}

#[test]
fn impossible_audio_wire_lengths_and_mapped_destinations_fail_before_open() {
    let (video, audio) = receivers();
    for encrypted in [false, true] {
        let mut controller = controller();
        let mut request = request(&video, &audio, encrypted);
        for length in if encrypted {
            vec![1, 15, 17, 1281, 1376]
        } else {
            vec![0, 1276, 1376]
        } {
            request.audio.wire_payload_bytes = length;
            assert_eq!(
                controller
                    .handle("owner", Operation::Open(request.clone()))
                    .err(),
                Some("invalid_audio_configuration")
            );
            assert!(controller.streams.is_empty());
            assert!(controller.used_keys.is_empty());
        }
    }
    let mut controller = controller();
    controller.settings.allow_remote = true;
    let mut request = request(&video, &audio, false);
    for peer in [
        "::ffff:224.0.0.1",
        "::ffff:255.255.255.255",
        "::ffff:127.0.0.1",
    ] {
        request.peer_ip = peer.parse().unwrap();
        assert_eq!(
            controller
                .handle("owner", Operation::Open(request.clone()))
                .err(),
            Some("invalid_destination")
        );
    }
}

#[test]
fn discovery_contract_rejects_placeholders_and_invalid_or_reused_ping_payloads() {
    let (video, audio) = receivers();
    let mut discovery = request(&video, &audio, false);
    discovery.video_port = None;
    discovery.audio_port = None;
    discovery.discovery = Some(Box::new(Discovery {
        video_ping_payload: "video_token-1234".into(),
        audio_ping_payload: "audio_token-1234".into(),
    }));
    discovery.operation_id = Some("discover-one".into());

    let mut invalid = discovery.clone();
    invalid.video_port = Some(0);
    assert_eq!(invalid.validate(false), Err("invalid_destination"));
    invalid.video_port = None;
    invalid.discovery.as_mut().unwrap().audio_ping_payload = "short".into();
    assert_eq!(invalid.validate(false), Err("invalid_discovery"));
    invalid.discovery.as_mut().unwrap().audio_ping_payload = "video_token-1234".into();
    assert_eq!(invalid.validate(false), Err("invalid_discovery"));
    invalid.discovery.as_mut().unwrap().audio_ping_payload = "non+base64url!!!".into();
    assert_eq!(invalid.validate(false), Err("invalid_discovery"));

    let mut controller = controller();
    let opened = controller
        .handle("owner", Operation::Open(discovery.clone()))
        .unwrap();
    assert_eq!(opened.payload["peer_discovery"], true);
    assert_eq!(opened.payload["ready"], false);
    assert!(opened.payload["video_port"].is_null());
    assert!(opened.payload["audio_port"].is_null());
    assert!(!opened.payload.to_string().contains("video_token"));
    let id = opened.created.unwrap();

    let retry = controller
        .handle("owner", Operation::Open(discovery.clone()))
        .unwrap();
    assert!(retry.created.is_none());
    let mut conflict = discovery.clone();
    conflict.discovery.as_mut().unwrap().audio_ping_payload = "fresh_token-1234".into();
    assert_eq!(
        controller.handle("owner", Operation::Open(conflict)).err(),
        Some("operation_conflict")
    );

    controller.close("owner", id).unwrap();
    discovery.operation_id = Some("discover-two".into());
    assert_eq!(
        controller.handle("other", Operation::Open(discovery)).err(),
        Some("ping_payload_reuse_forbidden")
    );
}

#[test]
fn fixed_ports_remain_ready_without_discovery_metadata_secrets() {
    let (video, audio) = receivers();
    let request = request(&video, &audio, false);
    let reply = controller()
        .handle("owner", Operation::Open(request))
        .unwrap()
        .payload;
    assert_eq!(reply["peer_discovery"], false);
    assert_eq!(reply["ready"], true);
    assert_eq!(reply["video_port"], video.local_addr().unwrap().port());
    assert_eq!(reply["audio_port"], audio.local_addr().unwrap().port());
}
