use super::*;
use std::{net::UdpSocket, time::Duration};

pub(crate) fn receivers() -> (UdpSocket, UdpSocket) {
    let video = UdpSocket::bind("127.0.0.1:0").unwrap();
    let audio = UdpSocket::bind("127.0.0.1:0").unwrap();
    for socket in [&video, &audio] {
        socket
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
    }
    (video, audio)
}

pub(crate) fn request(video: &UdpSocket, audio: &UdpSocket, encrypted: bool) -> Open {
    Open {
        peer_ip: "127.0.0.1".parse().unwrap(),
        video_stream_format: None,
        video_encryption_policy: None,
        video_port: Some(video.local_addr().unwrap().port()),
        audio_port: Some(audio.local_addr().unwrap().port()),
        discovery: None,
        video_bind: None,
        audio_bind: None,
        video: VideoSettings::default(),
        audio: AudioSettings {
            packet_ms: 10,
            channels: 2,
            wire_payload_bytes: if encrypted { 16 } else { 4 },
            ssrc: 0,
        },
        stream_audio: true,
        ping_timeout_ms: 10_000,
        encryption: encrypted.then(|| Encryption {
            key_hex: "000102030405060708090a0b0c0d0e0f".into(),
            key_id: 9,
            video: true,
            audio: true,
            permit_legacy_audio_iv_wrap: false,
        }),
        operation_id: None,
    }
}

#[test]
fn open_rejects_policy_mismatch_before_udp_setup() {
    let (video, audio) = receivers();
    let mut settings = request(&video, &audio, false);
    settings.video_encryption_policy = Some(Box::new(VideoEncryptionPolicySnapshot {
        lan_mode: 2,
        wan_mode: 0,
    }));
    settings.video_bind = Some(video.local_addr().unwrap());

    assert!(matches!(
        Stream::open("owner", &settings),
        Err("invalid_encryption")
    ));
}

#[test]
fn actual_media_stream_sends_over_ipv6_loopback_and_releases_both_ports() {
    let video = UdpSocket::bind("[::1]:0").unwrap();
    let audio = UdpSocket::bind("[::1]:0").unwrap();
    video
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut specification = request(&video, &audio, false);
    specification.peer_ip = "::1".parse().unwrap();
    specification.video_bind = Some("[::1]:0".parse().unwrap());
    specification.audio_bind = Some("[::1]:0".parse().unwrap());
    specification.validate(false).unwrap();
    let mut stream = Stream::open("owner", &specification).unwrap();
    let locals = [stream.video_local, stream.audio_local];
    for local in locals {
        assert_eq!(local.ip(), specification.peer_ip);
        assert_ne!(local.port(), 0);
        assert!(amaterasu_network_policy::bind_udp(local).is_err());
    }
    let frame = [0, 0, 0, 1, 0x65, 1, 2, 3];
    // SAFETY: the owned frame remains live through this synchronous submission.
    assert_eq!(
        unsafe { stream.submit_video(&video_packet(&frame, 0)) },
        STATUS_OK
    );
    stream.delivery.tick();
    assert!(!receive(&video).is_empty());
    drop(stream);
    for local in locals {
        assert_eq!(
            amaterasu_network_policy::bind_udp(local)
                .unwrap()
                .local_addr()
                .unwrap(),
            local
        );
    }
}

pub(crate) fn video_packet(bytes: &[u8], sequence: u64) -> EncodedPacket {
    EncodedPacket {
        codec: CODEC_H264,
        flags: FLAG_KEYFRAME,
        data: bytes.as_ptr(),
        len: bytes.len(),
        timestamp_us: sequence * 16667,
        sequence,
    }
}

#[test]
fn negotiated_hevc_accepts_only_hevc_packets_without_consuming_rejected_sequence() {
    let (video, audio) = receivers();
    let mut settings = request(&video, &audio, false);
    settings.video.codec = VideoCodec::Hevc;
    let mut stream = Stream::open("owner", &settings).unwrap();
    let access_unit: Vec<_> = [32u8, 33, 34, 19]
        .into_iter()
        .flat_map(|kind| [0, 0, 0, 1, kind << 1, 1])
        .collect();
    let h264 = video_packet(&access_unit, 0);
    // SAFETY: the local access unit remains allocated through both calls.
    assert_eq!(
        unsafe { stream.submit_video(&h264) },
        STATUS_INVALID_ARGUMENT
    );
    assert_eq!(stream.next_frame_index, Some(1));
    let hevc = EncodedPacket {
        codec: CODEC_HEVC,
        flags: FLAG_KEYFRAME | FLAG_END_OF_ACCESS_UNIT,
        ..h264
    };
    // SAFETY: the local access unit remains allocated through the call.
    assert_eq!(unsafe { stream.submit_video(&hevc) }, STATUS_OK);
    assert_eq!(stream.next_frame_index, Some(2));
    let wrong_eos = EncodedPacket {
        codec: CODEC_H264,
        flags: FLAG_END_OF_STREAM,
        len: 0,
        ..hevc
    };
    // SAFETY: EOS has no borrowed payload.
    assert_eq!(
        unsafe { stream.submit_video(&wrong_eos) },
        STATUS_INVALID_ARGUMENT
    );
    assert!(!stream.video_ended);
}

#[test]
fn hevc_fragments_commit_one_access_unit_only_after_final_boundary() {
    let (video, audio) = receivers();
    let mut settings = request(&video, &audio, false);
    settings.video.codec = VideoCodec::Hevc;
    settings.video.fec_percentage = 0;
    settings.video.min_parity_shards = 0;
    let mut stream = Stream::open("owner", &settings).unwrap();
    let access_unit: Vec<_> = [32u8, 33, 34, 19]
        .into_iter()
        .flat_map(|kind| [0, 0, 0, 1, kind << 1, 1])
        .collect();
    let first = EncodedPacket {
        codec: CODEC_HEVC,
        flags: FLAG_KEYFRAME,
        data: access_unit.as_ptr(),
        len: 9,
        timestamp_us: 16_667,
        sequence: 1,
    };
    let last = EncodedPacket {
        flags: FLAG_KEYFRAME | FLAG_END_OF_ACCESS_UNIT,
        data: access_unit[9..].as_ptr(),
        len: access_unit.len() - 9,
        ..first
    };
    assert_eq!(unsafe { stream.submit_video(&first) }, STATUS_OK);
    assert_eq!(stream.next_frame_index, Some(1));
    assert_eq!(stream.video_sequence, None);
    assert_eq!(stream.delivery.queued(), 0);
    let eos = EncodedPacket {
        flags: FLAG_END_OF_STREAM,
        data: std::ptr::null(),
        len: 0,
        ..first
    };
    assert_eq!(
        unsafe { stream.submit_video(&eos) },
        STATUS_INVALID_ARGUMENT
    );
    assert_eq!(stream.drain(), STATUS_INVALID_ARGUMENT);
    let wrong_sequence = EncodedPacket {
        sequence: 2,
        ..last
    };
    assert_eq!(
        unsafe { stream.submit_video(&wrong_sequence) },
        STATUS_INVALID_ARGUMENT
    );
    assert_eq!(
        stream.pending_video.as_ref().unwrap().bytes,
        access_unit[..9]
    );

    stream
        .delivery
        .push(Medium::Video, vec![vec![0]; MAX_DATAGRAMS]);
    assert_eq!(unsafe { stream.submit_video(&last) }, MEDIA_BUSY);
    assert_eq!(
        stream.pending_video.as_ref().unwrap().bytes,
        access_unit[..9]
    );
    assert_eq!(stream.next_frame_index, Some(1));
    stream.delivery = Delivery::bind(
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
        video.local_addr().unwrap(),
        audio.local_addr().unwrap(),
    )
    .unwrap();
    assert_eq!(unsafe { stream.submit_video(&last) }, STATUS_OK);
    assert!(stream.pending_video.is_none());
    assert_eq!(stream.video_sequence, Some(1));
    assert_eq!(stream.next_frame_index, Some(2));
    assert_eq!(
        unsafe { stream.submit_video(&last) },
        STATUS_INVALID_ARGUMENT
    );
}

/// TD, sequence header and one frame OBU: a minimal AV1 keyframe unit.
const AV1_KEYFRAME: [u8; 11] = [0x12, 0x00, 0x0a, 0x02, 0xaa, 0xbb, 0x32, 0x03, 1, 2, 3];
const AV1_DELTA: [u8; 7] = [0x12, 0x00, 0x32, 0x03, 4, 5, 6];

fn offered_stream(video: &UdpSocket, audio: &UdpSocket) -> Stream {
    let mut settings = request(video, audio, false);
    settings.video.codecs = vec![VideoCodec::H264, VideoCodec::Hevc, VideoCodec::Av1];
    settings.video.fec_percentage = 0;
    settings.video.min_parity_shards = 0;
    Stream::open("owner", &settings).unwrap()
}

#[test]
fn first_offered_codec_packet_selects_av1_for_the_rest_of_the_stream() {
    let (video, audio) = receivers();
    let mut stream = offered_stream(&video, &audio);
    assert_eq!(stream.video_codec(), None);
    let keyframe = EncodedPacket {
        codec: CODEC_AV1,
        flags: FLAG_KEYFRAME | FLAG_END_OF_ACCESS_UNIT,
        data: AV1_KEYFRAME.as_ptr(),
        len: AV1_KEYFRAME.len(),
        timestamp_us: 0,
        sequence: 0,
    };
    // SAFETY: the static unit outlives every call below.
    assert_eq!(unsafe { stream.submit_video(&keyframe) }, STATUS_OK);
    assert_eq!(stream.video_codec(), Some(VideoCodec::Av1));
    let h264 = video_packet(&[0, 0, 0, 1, 0x65, 1], 1);
    assert_eq!(
        unsafe { stream.submit_video(&h264) },
        STATUS_INVALID_ARGUMENT
    );
    assert_eq!(stream.next_frame_index, Some(2));
    stream.delivery.tick();
    let datagram = receive(&video);
    // The short frame header announces IDR from the encoder flag and the
    // final payload length (header plus unit) for padding-intolerant AV1.
    assert_eq!(&datagram[32..40], &[1, 0, 0, 2, 19, 0, 0, 0]);
    assert_eq!(&datagram[40..], &AV1_KEYFRAME);
}

#[test]
fn unoffered_codecs_are_rejected_before_selection() {
    let (video, audio) = receivers();
    let mut settings = request(&video, &audio, false);
    settings.video.codecs = vec![VideoCodec::H264, VideoCodec::Av1];
    let mut stream = Stream::open("owner", &settings).unwrap();
    let hevc = EncodedPacket {
        codec: CODEC_HEVC,
        flags: FLAG_KEYFRAME | FLAG_END_OF_ACCESS_UNIT,
        ..video_packet(&[0, 0, 0, 1, 0x40, 1], 0)
    };
    // SAFETY: the packet borrows a temporary that lives through the call.
    assert_eq!(
        unsafe { stream.submit_video(&hevc) },
        STATUS_INVALID_ARGUMENT
    );
    assert_eq!(stream.video_codec(), None);
    let frame = [0, 0, 0, 1, 0x65, 1];
    assert_eq!(
        unsafe { stream.submit_video(&video_packet(&frame, 0)) },
        STATUS_OK
    );
    assert_eq!(stream.video_codec(), Some(VideoCodec::H264));
}

#[test]
fn av1_fragments_assemble_one_temporal_unit_and_keep_the_keyframe_flag() {
    let (video, audio) = receivers();
    let mut stream = offered_stream(&video, &audio);
    let first = EncodedPacket {
        codec: CODEC_AV1,
        flags: FLAG_KEYFRAME,
        data: AV1_KEYFRAME.as_ptr(),
        len: 4,
        timestamp_us: 16_667,
        sequence: 1,
    };
    let last = EncodedPacket {
        flags: FLAG_END_OF_ACCESS_UNIT,
        data: AV1_KEYFRAME[4..].as_ptr(),
        len: AV1_KEYFRAME.len() - 4,
        ..first
    };
    // SAFETY: the static unit outlives every call below.
    assert_eq!(unsafe { stream.submit_video(&first) }, STATUS_OK);
    assert_eq!(stream.delivery.queued(), 0);
    assert_eq!(stream.next_frame_index, Some(1));
    assert_eq!(unsafe { stream.submit_video(&last) }, STATUS_OK);
    assert_eq!(stream.next_frame_index, Some(2));
    let delta = EncodedPacket {
        codec: CODEC_AV1,
        flags: FLAG_END_OF_ACCESS_UNIT,
        data: AV1_DELTA.as_ptr(),
        len: AV1_DELTA.len(),
        timestamp_us: 33_333,
        sequence: 2,
    };
    assert_eq!(unsafe { stream.submit_video(&delta) }, STATUS_OK);
    // A keyframe without its sequence header is not a recovery point.
    let headerless_key = EncodedPacket {
        flags: FLAG_KEYFRAME | FLAG_END_OF_ACCESS_UNIT,
        timestamp_us: 50_000,
        sequence: 3,
        ..delta
    };
    assert_eq!(
        unsafe { stream.submit_video(&headerless_key) },
        STATUS_INVALID_ARGUMENT
    );
    assert_eq!(stream.next_frame_index, Some(3));
    stream.delivery.tick();
    let key = receive(&video);
    assert_eq!(key[35], 2);
    assert_eq!(&key[40..], &AV1_KEYFRAME);
    let delta = receive(&video);
    assert_eq!(&delta[32..40], &[1, 0, 0, 1, 15, 0, 0, 0]);
    assert_eq!(&delta[40..], &AV1_DELTA);
}

pub(crate) fn audio_packet(bytes: &[u8], sequence: u64) -> EncodedAudioPacket {
    EncodedAudioPacket {
        codec: CODEC_OPUS,
        flags: 0,
        sample_rate: 48000,
        channels: 2,
        frames: 480,
        data: bytes.as_ptr(),
        len: bytes.len(),
        timestamp_us: sequence * 10000,
        sequence,
    }
}

fn receive(socket: &UdpSocket) -> Vec<u8> {
    let mut bytes = vec![0u8; 65507];
    let length = socket.recv(&mut bytes).unwrap();
    bytes.truncate(length);
    bytes
}

fn discovery_ping(token: &str) -> Vec<u8> {
    let mut bytes = token.as_bytes().to_vec();
    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes
}

#[test]
fn real_udp_video_fec_and_audio_groups_flush_with_no_invented_eos_datagram() {
    let (video, audio) = receivers();
    let mut stream = Stream::open("owner", &request(&video, &audio, false)).unwrap();
    let frame = [0, 0, 0, 1, 0x65, 1, 2, 3];
    // SAFETY: the locally owned encoded buffers remain live through submit.
    assert_eq!(
        unsafe { stream.submit_video(&video_packet(&frame, 0)) },
        STATUS_OK
    );
    let opus = [0x94, 1, 2, 3];
    for sequence in 0..4 {
        assert_eq!(
            unsafe { stream.submit_audio(&audio_packet(&opus, sequence)) },
            STATUS_OK
        );
    }
    assert_eq!(stream.delivery.queued(), 9); // One data+two parity video; four+two audio.
    assert_eq!(stream.drain(), STATUS_OK);
    assert_eq!(stream.state(), "draining");
    stream.delivery.tick();
    assert_eq!(stream.state(), "drained");
    for _ in 0..3 {
        assert!(receive(&video).len() > 32);
    }
    for index in 0..6 {
        let bytes = receive(&audio);
        assert_eq!(bytes[1], if index < 4 { 97 } else { 127 });
        if index < 4 {
            assert_eq!(&bytes[12..], &opus);
        }
    }
    assert_eq!(stream.delivery.sent_datagrams, 9);
    assert_eq!(stream.drain(), STATUS_OK);
    assert_eq!(
        unsafe { stream.submit_video(&video_packet(&frame, 1)) },
        MEDIA_CLOSED
    );
    assert_eq!(
        unsafe { stream.submit_audio(&audio_packet(&opus, 4)) },
        MEDIA_CLOSED
    );
    assert!(video.recv(&mut [0; 32]).is_err());
    assert!(audio.recv(&mut [0; 32]).is_err());
}

#[test]
fn surround_audio_packetize_submit_and_drain_keep_channel_and_wire_bounds() {
    for channels in [6_u16, 8] {
        for packet_ms in [5, 10] {
            for encrypted in [false, true] {
                let (video, audio) = receivers();
                let mut settings = request(&video, &audio, encrypted);
                settings.audio.channels = channels;
                settings.audio.packet_ms = packet_ms;
                let mut stream = Stream::open("owner", &settings).unwrap();
                let opus = if packet_ms == 5 {
                    [0x8c, 1, 2, 3]
                } else {
                    [0x94, 1, 2, 3]
                };
                let packet = |sequence| EncodedAudioPacket {
                    channels: u32::from(channels),
                    frames: packet_ms * 48,
                    timestamp_us: sequence * u64::from(packet_ms) * 1_000,
                    ..audio_packet(&opus, sequence)
                };
                let wrong = EncodedAudioPacket {
                    channels: 2,
                    ..packet(0)
                };
                assert_eq!(unsafe { stream.submit_audio(&wrong) }, MEDIA_UNSUPPORTED);
                assert_eq!(stream.audio_sequence, None);
                assert_eq!(stream.delivery.queued(), 0);
                for sequence in 0..4 {
                    assert_eq!(unsafe { stream.submit_audio(&packet(sequence)) }, STATUS_OK);
                }
                assert_eq!(stream.delivery.queued(), 6);
                assert_eq!(stream.drain(), STATUS_OK);
                stream.delivery.tick();
                for index in 0..6 {
                    let datagram = receive(&audio);
                    assert_eq!(datagram[1], if index < 4 { 97 } else { 127 });
                    assert!(datagram.len() <= 1_304);
                }
            }
        }
    }
}

#[test]
fn unsupported_surround_counts_and_oversized_opus_fail_without_queue_mutation() {
    let (video, audio) = receivers();
    for channels in [0, 1, 3, 4, 5, 7, 9] {
        let mut settings = request(&video, &audio, false);
        settings.audio.channels = channels;
        assert!(matches!(
            Stream::open("owner", &settings),
            Err("invalid_audio_configuration")
        ));
    }
    let mut settings = request(&video, &audio, false);
    settings.audio.channels = 6;
    let mut stream = Stream::open("owner", &settings).unwrap();
    let oversized = vec![0x94; 1_276];
    let packet = EncodedAudioPacket {
        channels: 6,
        ..audio_packet(&oversized, 0)
    };
    assert_eq!(
        unsafe { stream.submit_audio(&packet) },
        STATUS_INVALID_ARGUMENT
    );
    assert_eq!(stream.audio_sequence, None);
    assert_eq!(stream.delivery.queued(), 0);
}

#[test]
fn maximum_surround_opus_payload_respects_plain_and_encrypted_wire_caps() {
    for channels in [6_u16, 8] {
        for encrypted in [false, true] {
            let (video, audio) = receivers();
            let mut settings = request(&video, &audio, encrypted);
            settings.audio.channels = channels;
            settings.audio.wire_payload_bytes = if encrypted { 1_280 } else { 1_275 };
            let mut stream = Stream::open("owner", &settings).unwrap();
            let opus = vec![0x94; 1_275];
            let packet = EncodedAudioPacket {
                channels: u32::from(channels),
                ..audio_packet(&opus, 0)
            };
            assert_eq!(unsafe { stream.submit_audio(&packet) }, STATUS_OK);
            assert_eq!(stream.delivery.queued(), 1);
            assert_eq!(stream.drain(), STATUS_OK);
            stream.delivery.tick();
            assert_eq!(receive(&audio).len(), if encrypted { 1_292 } else { 1_287 });
        }
    }
}

#[test]
fn real_udp_video_without_fec_emits_only_the_data_datagram() {
    let (video, audio) = receivers();
    let mut settings = request(&video, &audio, false);
    settings.video.fec_percentage = 0;
    settings.video.min_parity_shards = 0;
    let mut stream = Stream::open("owner", &settings).unwrap();
    let frame = [0, 0, 0, 1, 0x65, 1, 2, 3];

    // SAFETY: the locally owned encoded buffer remains live through submit.
    assert_eq!(
        unsafe { stream.submit_video(&video_packet(&frame, 0)) },
        STATUS_OK
    );
    assert_eq!(stream.delivery.queued(), 1);
    assert_eq!(stream.drain(), STATUS_OK);
    assert_eq!(stream.state(), "draining");
    stream.delivery.tick();
    assert_eq!(stream.state(), "drained");

    assert!(receive(&video).len() > 32);
    assert_eq!(stream.delivery.sent_datagrams, 1);
    assert!(video.recv(&mut [0; 65_507]).is_err());
}

#[test]
fn queue_busy_does_not_consume_video_indices_or_crypto_nonces() {
    let (video, audio) = receivers();
    let mut stream = Stream::open("owner", &request(&video, &audio, true)).unwrap();
    stream
        .delivery
        .push(Medium::Video, vec![vec![0]; MAX_DATAGRAMS]);
    let frame = [0, 0, 0, 1, 0x65, 1, 2, 3];
    assert_eq!(
        unsafe { stream.submit_video(&video_packet(&frame, 0)) },
        MEDIA_BUSY
    );
    assert_eq!(stream.next_frame_index, Some(1));
    assert_eq!(stream.video_sequence, None);
    stream.delivery = Delivery::bind(
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
        video.local_addr().unwrap(),
        audio.local_addr().unwrap(),
    )
    .unwrap();
    assert_eq!(
        unsafe { stream.submit_video(&video_packet(&frame, 0)) },
        STATUS_OK
    );
    stream.delivery.tick();
    let packet = receive(&video);
    assert_eq!(&packet[..8], &0u64.to_le_bytes());
    assert_eq!(packet[11], b'V');
    assert_eq!(&packet[12..16], &1u32.to_le_bytes());
    assert_eq!(&receive(&video)[..8], &1u64.to_le_bytes());
    assert_eq!(&receive(&video)[..8], &2u64.to_le_bytes());
}

#[test]
fn audio_ciphertext_is_queued_once_and_discontinuity_skips_iv_slots_without_resetting_key() {
    let (video, audio) = receivers();
    let mut stream = Stream::open("owner", &request(&video, &audio, true)).unwrap();
    let opus = [0x94, 1, 2, 3];
    stream
        .delivery
        .push(Medium::Audio, vec![vec![0]; MAX_DATAGRAMS]);
    assert_eq!(
        unsafe { stream.submit_audio(&audio_packet(&opus, 0)) },
        MEDIA_BUSY
    );
    assert_eq!(stream.audio.next_sequence(), 0);
    stream.delivery = Delivery::bind(
        "127.0.0.1:0".parse().unwrap(),
        "127.0.0.1:0".parse().unwrap(),
        video.local_addr().unwrap(),
        audio.local_addr().unwrap(),
    )
    .unwrap();
    assert_eq!(
        unsafe { stream.submit_audio(&audio_packet(&opus, 0)) },
        STATUS_OK
    );
    let reset = EncodedAudioPacket {
        flags: AUDIO_PACKET_DISCONTINUITY,
        ..audio_packet(&opus, 9)
    };
    assert_eq!(unsafe { stream.submit_audio(&reset) }, STATUS_OK);
    assert_eq!(stream.discarded_audio_fec_shards, 1);
    stream.delivery.tick();
    let first = receive(&audio);
    let second = receive(&audio);
    assert_eq!(&first[2..4], &0u16.to_be_bytes());
    assert_eq!(&second[2..4], &4u16.to_be_bytes());
    assert_ne!(&first[12..], &second[12..]);
    let key: [u8; 16] = std::array::from_fn(|i| i as u8);
    let mut oracle = AudioSealer::new(&key, 9, AudioIvPolicy::RejectReuse);
    assert_eq!(&first[12..], oracle.encrypt(0, &opus).unwrap());
    oracle.skip_to(4).unwrap();
    assert_eq!(&second[12..], oracle.encrypt(4, &opus).unwrap());
}

#[test]
fn invalid_media_changes_no_queued_bytes_or_sequence_and_eos_closes_only_its_medium() {
    let (video, audio) = receivers();
    let mut stream = Stream::open("owner", &request(&video, &audio, true)).unwrap();
    let bad = [1, 2, 3, 4, 5];
    assert_eq!(
        unsafe { stream.submit_video(&video_packet(&bad, 0)) },
        STATUS_INVALID_ARGUMENT
    );
    let bad_audio = [0x94; 17]; // PKCS7 ciphertext would exceed negotiated 16 bytes.
    assert_eq!(
        unsafe { stream.submit_audio(&audio_packet(&bad_audio, 0)) },
        STATUS_INVALID_ARGUMENT
    );
    assert_eq!(stream.delivery.queued_bytes(), 0);
    assert_eq!(stream.audio.next_sequence(), 0);
    let eos = EncodedPacket {
        flags: FLAG_END_OF_STREAM,
        data: std::ptr::null(),
        len: 0,
        ..video_packet(&bad, 0)
    };
    assert_eq!(unsafe { stream.submit_video(&eos) }, STATUS_OK);
    assert_eq!(stream.state(), "sending");
    assert_eq!(
        unsafe { stream.submit_audio(&audio_packet(&[0x94, 1, 2, 3], 0)) },
        STATUS_OK
    );
}

#[test]
fn ping_timeout_defaults_to_ten_seconds_and_sets_the_discovery_deadline() {
    let (video, audio) = receivers();
    let mut request = request(&video, &audio, false);
    assert_eq!(request.ping_timeout_ms, 10_000);
    request.video_port = None;
    request.audio_port = None;
    request.discovery = Some(Box::new(Discovery {
        video_ping_payload: "video_token-1234".into(),
        audio_ping_payload: "audio_token-1234".into(),
    }));
    request.ping_timeout_ms = 0;

    let mut stream = Stream::open("owner", &request).unwrap();
    assert_eq!(stream.ping_timeout_ms, 0);
    stream.delivery.tick();
    assert_eq!(stream.delivery.failure, Some("udp_discovery_timeout"));
}

#[test]
fn disabled_audio_accepts_only_eos_and_never_queues_audio_datagrams() {
    let (video, audio) = receivers();
    let mut settings = request(&video, &audio, false);
    settings.stream_audio = false;
    settings.audio.wire_payload_bytes = 16;
    let mut stream = Stream::open("owner", &settings).unwrap();
    assert_eq!(stream.encryption(), (false, false));

    let opus = [0x94, 1, 2, 3];
    assert_eq!(
        unsafe { stream.submit_audio(&audio_packet(&opus, 0)) },
        MEDIA_UNSUPPORTED
    );
    assert_eq!(stream.delivery.queued(), 0);
    assert_eq!(stream.audio_sequence, None);

    let eos = EncodedAudioPacket {
        flags: AUDIO_PACKET_END_OF_STREAM,
        frames: 0,
        data: std::ptr::null(),
        len: 0,
        ..audio_packet(&[], 0)
    };
    assert_eq!(unsafe { stream.submit_audio(&eos) }, STATUS_OK);
    assert_eq!(stream.state(), "sending");
    assert_eq!(
        unsafe { stream.submit_audio(&audio_packet(&opus, 0)) },
        MEDIA_CLOSED
    );
    let video_eos = EncodedPacket {
        flags: FLAG_END_OF_STREAM,
        data: std::ptr::null(),
        len: 0,
        ..video_packet(&[], 0)
    };
    assert_eq!(unsafe { stream.submit_video(&video_eos) }, STATUS_OK);
    assert_eq!(stream.state(), "drained");
    assert_eq!(stream.delivery.queued(), 0);
    assert!(audio.recv(&mut [0; 32]).is_err());
}

#[test]
fn one_batch_larger_than_hard_byte_limit_is_invalid_instead_of_permanently_busy() {
    let (video, audio) = receivers();
    let mut settings = request(&video, &audio, false);
    settings.video = VideoSettings {
        codec: VideoCodec::H264,
        codecs: Vec::new(),
        packet_size: 65_507 - 16,
        fec_percentage: 0,
        min_parity_shards: 0,
        max_fec_blocks: 1,
        max_batch_size_kb: 64,
    };
    let mut stream = Stream::open("owner", &settings).unwrap();
    let mut bytes = vec![0x55; MAX_QUEUE_BYTES];
    bytes[..5].copy_from_slice(&[0, 0, 0, 1, 0x65]);
    // The access unit itself fits the packetizer, but its added RTP/NV/frame
    // headers exceed the transport's total byte allowance even on an empty queue.
    assert_eq!(
        unsafe { stream.submit_video(&video_packet(&bytes, 0)) },
        STATUS_INVALID_ARGUMENT
    );
    assert_eq!(stream.delivery.queued(), 0);
    assert_eq!(stream.next_frame_index, Some(1));
}

#[test]
fn discovery_admission_is_busy_without_consuming_media_state_until_both_lanes_freeze() {
    let (unused_video, unused_audio) = receivers();
    let mut settings = request(&unused_video, &unused_audio, true);
    settings.video_port = None;
    settings.audio_port = None;
    settings.discovery = Some(Box::new(Discovery {
        video_ping_payload: "video_token-1234".into(),
        audio_ping_payload: "audio_token-1234".into(),
    }));
    let mut stream = Stream::open("owner", &settings).unwrap();
    let video_peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    let audio_peer = UdpSocket::bind("127.0.0.1:0").unwrap();
    let frame = [0, 0, 0, 1, 0x65, 1, 2, 3];
    let opus = [0x94, 1, 2, 3];

    video_peer
        .send_to(&discovery_ping("video_token-1234"), stream.video_local)
        .unwrap();
    wait_for_peer(&mut stream, crate::datagrams::Medium::Video);
    assert_eq!(stream.state(), "discovering");
    // SAFETY: locally owned packet bytes remain live through admission.
    assert_eq!(
        unsafe { stream.submit_video(&video_packet(&frame, 0)) },
        MEDIA_BUSY
    );
    assert_eq!(
        unsafe { stream.submit_audio(&audio_packet(&opus, 0)) },
        MEDIA_BUSY
    );
    assert_eq!(stream.next_frame_index, Some(1));
    assert_eq!(stream.video_sequence, None);
    assert_eq!(stream.audio.next_sequence(), 0);
    assert_eq!(stream.delivery.queued(), 0);

    audio_peer
        .send_to(&discovery_ping("audio_token-1234"), stream.audio_local)
        .unwrap();
    wait_for_peer(&mut stream, crate::datagrams::Medium::Audio);
    assert_eq!(stream.state(), "sending");
    assert_eq!(
        unsafe { stream.submit_video(&video_packet(&frame, 0)) },
        STATUS_OK
    );
    assert_eq!(
        unsafe { stream.submit_audio(&audio_packet(&opus, 0)) },
        STATUS_OK
    );
}

fn wait_for_peer(stream: &mut Stream, medium: crate::datagrams::Medium) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
    while stream.peer_port(medium).is_none() {
        stream.delivery.tick();
        assert!(
            std::time::Instant::now() < deadline,
            "UDP peer was not discovered"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

#[test]
fn frames_stamped_on_the_host_clock_report_their_host_processing_latency() {
    let (video, audio) = receivers();
    let mut stream = offered_stream(&video, &audio);
    let mut keyframe = video_packet(&[0, 0, 0, 1, 0x65, 0x88], 0);
    keyframe.flags |= FLAG_END_OF_ACCESS_UNIT;
    keyframe.timestamp_us = host_monotonic_micros() - 5_000;
    // SAFETY: the packet bytes outlive this synchronous submission.
    assert_eq!(unsafe { stream.submit_video(&keyframe) }, STATUS_OK);
    stream.delivery.tick();
    let datagram = receive(&video);
    let latency = u16::from_le_bytes([datagram[33], datagram[34]]);
    // 5 ms in 0.1 ms units, plus however long this test took to packetize.
    assert!((50..100).contains(&latency), "{latency}");
}

#[test]
fn authenticated_format_freezes_codec_and_rejects_later_reconfiguration() {
    use amaterasu_module_sdk::{DynamicRange, VideoCodec as NegotiatedCodec, VideoStreamFormat};
    let (video, audio) = receivers();
    let mut settings = request(&video, &audio, false);
    settings.video.codecs = vec![VideoCodec::H264, VideoCodec::Hevc, VideoCodec::Av1];
    let mut stream = Stream::open("owner", &settings).unwrap();
    let av1 = VideoStreamFormat {
        codec: NegotiatedCodec::Av1,
        bit_depth: 8,
        dynamic_range: DynamicRange::Sdr,
    };
    stream.configure_video_format(av1).unwrap();
    assert_eq!(stream.video_codec(), Some(VideoCodec::Av1));
    assert_eq!(
        stream.configure_video_format(VideoStreamFormat::H264_SDR),
        Err("video_format_conflict")
    );
    let packet = EncodedPacket {
        codec: CODEC_AV1,
        flags: FLAG_KEYFRAME | FLAG_END_OF_ACCESS_UNIT,
        data: AV1_KEYFRAME.as_ptr(),
        len: AV1_KEYFRAME.len(),
        timestamp_us: 0,
        sequence: 0,
    };
    // SAFETY: the static temporal unit remains allocated through the call.
    assert_eq!(unsafe { stream.submit_video(&packet) }, STATUS_OK);
    assert_eq!(
        stream.configure_video_format(av1),
        Err("video_format_already_in_use")
    );
}

#[test]
fn explicit_open_format_selects_hevc_and_rejects_hdr_before_binding() {
    use amaterasu_module_sdk::{DynamicRange, VideoCodec as NegotiatedCodec, VideoStreamFormat};
    let (video, audio) = receivers();
    let mut settings = request(&video, &audio, false);
    settings.video_stream_format = Some(VideoStreamFormat {
        codec: NegotiatedCodec::Hevc,
        bit_depth: 8,
        dynamic_range: DynamicRange::Sdr,
    });
    assert_eq!(
        Stream::open("owner", &settings).unwrap().video_codec(),
        Some(VideoCodec::Hevc)
    );
    settings.video_stream_format = Some(VideoStreamFormat {
        codec: NegotiatedCodec::Hevc,
        bit_depth: 10,
        dynamic_range: DynamicRange::Hdr,
    });
    assert!(matches!(
        Stream::open("owner", &settings),
        Err("unsupported_video_format")
    ));
}
