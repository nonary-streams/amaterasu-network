#[test]
fn audio_bitrate_boundary_matches_the_stereo_encoder_without_widening_packet_cadence() {
    for packet_ms in [5, 10] {
        let mut streaming = config();
        streaming.profile.packet_ms = packet_ms;
        streaming.profile.audio_bitrate = 512_000;
        assert!(streaming.validate().is_ok());

        streaming.profile.audio_bitrate = 512_001;
        assert_eq!(streaming.validate(), Err("invalid_streaming_profile"));
        streaming.profile.audio_bitrate = 5_999;
        assert_eq!(streaming.validate(), Err("invalid_streaming_profile"));
    }

    let mut unsupported_cadence = config();
    unsupported_cadence.profile.audio_bitrate = 512_000;
    unsupported_cadence.profile.packet_ms = 20;
    assert_eq!(
        unsupported_cadence.validate(),
        Err("invalid_streaming_profile")
    );
}

#[test]
fn owner_launch_and_retry_preserve_512000_audio_bitrate_on_rtsp_open() {
    let now = Instant::now();
    let mut streaming = config();
    streaming.profile.audio_bitrate = 512_000;
    streaming.profile.packet_ms = 5;
    let mut controller = Controller::new(Some(streaming)).unwrap();
    let mut broker = Broker::default();

    assert!(controller.launch(10, request(31), peer(31), now).is_none());
    let (connection, first) = poll_until_reply(&mut controller, &mut broker, now);
    assert_eq!(connection, 10);
    assert_eq!(first.status, 200);
    assert_eq!(
        opened_rtsp_payload(&broker)["profile"]["audio_bitrate"],
        512_000
    );
    assert_eq!(opened_rtsp_payload(&broker)["profile"]["packet_ms"], 5);
    controller.reply_delivered(connection, now);

    assert_eq!(controller.current_game(&peer(32)), 0);
    assert_eq!(controller.cancel(12, &peer(32), now).unwrap().status, 403);
    let retry = controller
        .launch(11, request(31), peer(31), now)
        .expect("same owner retry");
    assert_eq!(retry.status, 200);
    assert_eq!(retry.body, first.body);
    let rtsp_opens = broker
        .actions()
        .into_iter()
        .filter(|(service, action)| *service == "amaterasu.rtsp/1" && *action == "open")
        .count();
    assert_eq!(rtsp_opens, 1);
}

#[test]
fn owner_launch_exports_signed_video_ceilings_and_effective_bitrate_bound() {
    let now = Instant::now();
    let mut streaming = config();
    streaming.profile.max_width = 2560;
    streaming.profile.max_height = 1440;
    streaming.profile.max_fps = 120;
    streaming.profile.bitrate_kbps = 20_000;
    let mut controller = Controller::new(Some(streaming)).unwrap();
    controller.set_encoder_snapshot(hardware_h264());
    controller.set_global_max_bitrate_kbps(Some(8_000));
    let mut broker = Broker::default();

    assert!(controller.launch(10, request(41), peer(41), now).is_none());
    let _ = poll_until_reply(&mut controller, &mut broker, now);

    assert_eq!(
        opened_rtsp_payload(&broker)["negotiation_bounds"],
        json!({
            "max_width":2560,
            "max_height":1440,
            "max_fps":120,
            "max_bitrate_kbps":8000,
            "max_reference_frames":1,
        })
    );
}
