use super::*;
use serde_json::json;

const AUTO: EncoderSelection =
    EncoderSelection::Backend(amaterasu_module_sdk::EncoderBackend::Auto);
const FULL_HD_60: StreamMode = StreamMode {
    width: 1920,
    height: 1080,
    fps: 60,
};
const UHD_120: StreamMode = StreamMode {
    width: 3840,
    height: 2160,
    fps: 120,
};

fn encoder(clsid: &str, codec: &str, hardware: bool) -> Value {
    json!({
        "identity":{"clsid":clsid,"hardware_url":null,"friendly_name":clsid},
        "name":clsid,
        "codec":codec,
        "hardware":hardware,
        "vendor_id":null,
    })
}

fn snapshot(encoders: Vec<Value>) -> EncoderSnapshot {
    EncoderSnapshot::parse(&json!({"ok":true,"enabled":true,"encoders":encoders})).unwrap()
}

fn nvenc_and_x264() -> EncoderSnapshot {
    snapshot(vec![
        encoder("amaterasu.hardware.nvenc-cuda.h264", "h264", true),
        encoder("amaterasu.hardware.nvenc-cuda.hevc", "hevc", true),
        encoder("amaterasu.hardware.nvenc-cuda.av1", "av1", true),
        encoder("amaterasu.software.x264", "h264", false),
    ])
}

#[test]
fn serverinfo_mask_follows_the_enumerated_codecs() {
    let cases = [
        (vec![], 0x1, 0),
        (vec![encoder("x264", "h264", false)], 0x1, 0),
        (
            vec![
                encoder("x264", "h264", false),
                encoder("x265", "hevc", false),
            ],
            0x101,
            1_869_449_984,
        ),
        (vec![encoder("nvenc-av1", "av1", true)], 0x10001, 0),
        (
            vec![
                encoder("nvenc-h264", "h264", true),
                encoder("nvenc-hevc", "hevc", true),
                encoder("nvenc-av1", "av1", true),
            ],
            0x10101,
            1_869_449_984,
        ),
        (vec![encoder("future", "vp9", true)], 0x1, 0),
    ];
    for (encoders, mask, luma) in cases {
        assert_eq!(
            snapshot(encoders).advertisement(),
            CodecAdvertisement {
                codec_mode_support: mask,
                max_luma_pixels_hevc: luma,
            }
        );
    }
}

#[test]
fn disabled_encoders_are_an_empty_snapshot_and_bad_replies_are_errors() {
    assert_eq!(
        EncoderSnapshot::parse(&json!({"ok":true,"enabled":false,"encoders":[]})),
        Ok(EncoderSnapshot::default())
    );
    for invalid in [
        json!({"ok":false,"code":"encoder_worker_failed"}),
        json!({"ok":true,"enabled":true}),
        json!({"ok":true,"enabled":true,"encoders":[{"codec":"h264"}]}),
        json!({"ok":true,"enabled":true,"encoders":[{"hardware":true}]}),
        json!({"ok":true,"enabled":true,"encoders":vec![encoder("x", "h264", false); 65]}),
    ] {
        assert!(EncoderSnapshot::parse(&invalid).is_err(), "{invalid}");
    }
}

#[test]
fn automatic_selection_offers_every_codec_in_moonlight_preference_order() {
    let offer = nvenc_and_x264().offer(AUTO, UHD_120).unwrap();
    assert_eq!(
        offer.codecs,
        [VideoCodec::Av1, VideoCodec::Hevc, VideoCodec::H264]
    );
    assert!(!offer.software_limited);
}

#[test]
fn software_only_codecs_are_limited_to_full_hd_at_sixty_frames() {
    let mixed = snapshot(vec![
        encoder("nvenc-hevc", "hevc", true),
        encoder("x264", "h264", false),
    ]);
    let small = mixed.offer(AUTO, FULL_HD_60).unwrap();
    assert_eq!(small.codecs, [VideoCodec::Hevc, VideoCodec::H264]);
    assert!(small.software_limited);
    let large = mixed.offer(AUTO, UHD_120).unwrap();
    assert_eq!(large.codecs, [VideoCodec::Hevc]);
    assert!(!large.software_limited);

    let software = snapshot(vec![encoder("x264", "h264", false)]);
    for mode in [
        UHD_120,
        StreamMode {
            fps: 61,
            ..FULL_HD_60
        },
        StreamMode {
            width: 1922,
            ..FULL_HD_60
        },
        StreamMode {
            height: 1082,
            ..FULL_HD_60
        },
    ] {
        assert_eq!(
            software.offer(AUTO, mode),
            Err("no hardware encoder for this stream mode")
        );
    }
    assert_eq!(
        software.offer(AUTO, FULL_HD_60).unwrap().codecs,
        [VideoCodec::H264]
    );
}

#[test]
fn numeric_selection_offers_only_the_selected_encoder_codec() {
    let snapshot = nvenc_and_x264();
    let pinned = |index| snapshot.offer(EncoderSelection::Index(index), UHD_120);
    assert_eq!(pinned(0).unwrap().codecs, [VideoCodec::H264]);
    assert_eq!(pinned(1).unwrap().codecs, [VideoCodec::Hevc]);
    assert_eq!(pinned(2).unwrap().codecs, [VideoCodec::Av1]);
    assert_eq!(pinned(3), Err("no hardware encoder for this stream mode"));
    assert_eq!(pinned(4), Err("no video encoder is available"));
    assert_eq!(
        EncoderSnapshot::default().offer(AUTO, FULL_HD_60),
        Err("no video encoder is available")
    );
}

#[test]
fn unknown_encoders_offer_only_software_h264() {
    assert_eq!(
        unknown_encoders_offer(FULL_HD_60),
        Ok(CodecOffer {
            codecs: vec![VideoCodec::H264],
            software_limited: true,
        })
    );
    assert!(unknown_encoders_offer(UHD_120).is_err());
}

#[test]
fn sdk_identity_selection_pins_the_exact_encoder_and_software_filters_hardware() {
    let snapshot = nvenc_and_x264();
    let identity = EncoderIdentity {
        clsid: "amaterasu.hardware.nvenc-cuda.hevc".into(),
        hardware_url: None,
        friendly_name: "amaterasu.hardware.nvenc-cuda.hevc".into(),
    };
    assert_eq!(
        snapshot
            .offer(EncoderSelection::Identity(identity), UHD_120)
            .unwrap()
            .codecs,
        [VideoCodec::Hevc]
    );
    let software = EncoderSelection::Backend(EncoderBackend::Software);
    let offer = snapshot.offer(software.clone(), FULL_HD_60).unwrap();
    assert_eq!(offer.codecs, [VideoCodec::H264]);
    assert!(offer.software_limited);
    assert_eq!(
        snapshot.offer(software, UHD_120),
        Err("no hardware encoder for this stream mode")
    );
}
