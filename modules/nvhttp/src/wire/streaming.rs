use super::query::{Query, hex_bytes};
use crate::launch::LaunchRequest;

const LAUNCH_FIELDS: &[&str] = &[
    "appid",
    "mode",
    "clientName",
    "rikey",
    "rikeyid",
    "uniqueid",
    "uuid",
    "additionalStates",
    "sops",
    "hdrMode",
    "clientHdrCapVersion",
    "clientHdrCapSupportedFlagsInUint32",
    "clientHdrCapMetaDataId",
    "clientHdrCapDisplayData",
    "localAudioPlayMode",
    "surroundAudioInfo",
    "remoteControllersBitmap",
    "gcmap",
    "gcpmap",
    "psmap",
    "gcpersist",
    "clientVrrRequested",
    "corever",
    "continuousAudio",
];

pub(super) fn launch_request(query: &Query) -> Result<LaunchRequest, &'static str> {
    query.require_only(LAUNCH_FIELDS)?;
    validate_metadata(query)?;
    let app_id = decimal_u32(query.required("appid")?)?;
    if app_id == 0 {
        return Err("invalid application identifier");
    }
    let (width, height, fps) = mode(query.required("mode")?)?;
    let key = hex_bytes(query.required("rikey")?, 16)?;
    let remote_input_key: [u8; 16] = key
        .try_into()
        .map_err(|_| "remote input key must contain 16 bytes")?;
    let key_id = key_id(query.required("rikeyid")?)?;
    let host_audio_enabled = query.get("localAudioPlayMode") == Some("1");
    let audio_channels = surround_audio_channels(query.get("surroundAudioInfo"))?;
    let device_name = query.get("clientName").unwrap_or_default();
    if !device_name.is_empty()
        && (device_name.len() > 128 || device_name.chars().any(char::is_control))
    {
        return Err("invalid device name");
    }
    Ok(LaunchRequest {
        app_id,
        width,
        height,
        fps,
        host_audio_enabled,
        continuous_audio: query.get("continuousAudio") == Some("1"),
        audio_channels,
        device_name: (!device_name.is_empty()).then(|| device_name.to_owned()),
        remote_input_key,
        key_id,
    })
}

fn validate_metadata(query: &Query) -> Result<(), &'static str> {
    if query.get("uniqueid").is_some() {
        query.client_id()?;
    }
    if let Some(uuid) = query.get("uuid")
        && (uuid.is_empty()
            || uuid.len() > 64
            || !uuid
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'))
    {
        return Err("invalid request identifier");
    }
    optional_boolean(query, "additionalStates")?;
    // Moonlight can request SOPS for a Desktop stream. It is a client hint;
    // Amaterasu never changes the host display or application settings for it.
    optional_boolean(query, "sops")?;
    require_optional_value(query, "hdrMode", "0", "HDR streaming is unsupported")?;
    require_optional_value(
        query,
        "clientHdrCapVersion",
        "0",
        "HDR streaming is unsupported",
    )?;
    require_optional_value(
        query,
        "clientHdrCapSupportedFlagsInUint32",
        "0",
        "HDR streaming is unsupported",
    )?;
    require_optional_value(
        query,
        "clientHdrCapMetaDataId",
        "0",
        "HDR streaming is unsupported",
    )?;
    require_optional_value(
        query,
        "clientHdrCapDisplayData",
        "",
        "HDR streaming is unsupported",
    )?;
    optional_boolean(query, "localAudioPlayMode")?;
    optional_boolean(query, "continuousAudio")?;
    // Slot hints are independent from permission to inject native input. Moonlight
    // reports player one in single-controller mode even without an attached pad.
    for field in ["remoteControllersBitmap", "gcmap", "gcpmap", "psmap"] {
        optional_decimal_mask(query, field, u16::MAX as u32)?;
    }
    optional_boolean(query, "gcpersist")?;
    // This is only a client pacing capability hint; accepting it does not enable host VRR.
    optional_boolean(query, "clientVrrRequested")?;
    require_optional_value(query, "corever", "1", "unsupported Moonlight core version")
}

/// `surroundAudioInfo` is `channel_mask << 16 | channel_count`, from
/// `SURROUNDAUDIOINFO_FROM_AUDIO_CONFIGURATION` in moonlight-common-c.
fn surround_audio_channels(value: Option<&str>) -> Result<u32, &'static str> {
    match value {
        None | Some("196610") => Ok(2),
        // Moonlight encodes channel_mask << 16 | channel_count.
        Some("4128774") => Ok(6),
        Some("104792072") => Ok(8),
        Some(_) => Err("unsupported surround audio configuration"),
    }
}

fn optional_boolean(query: &Query, name: &str) -> Result<(), &'static str> {
    match query.get(name) {
        None | Some("0" | "1") => Ok(()),
        Some(_) => Err("invalid boolean query field"),
    }
}

fn optional_decimal_mask(query: &Query, name: &str, maximum: u32) -> Result<(), &'static str> {
    match query.get(name) {
        None => Ok(()),
        Some(value) if decimal_u32(value).is_ok_and(|mask| mask <= maximum) => Ok(()),
        Some(_) => Err("invalid controller capability mask"),
    }
}

fn require_optional_value(
    query: &Query,
    name: &str,
    expected: &str,
    error: &'static str,
) -> Result<(), &'static str> {
    match query.get(name) {
        None => Ok(()),
        Some(value) if value == expected => Ok(()),
        Some(_) => Err(error),
    }
}

fn decimal_u32(value: &str) -> Result<u32, &'static str> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("invalid unsigned decimal value");
    }
    value
        .parse()
        .map_err(|_| "unsigned decimal value is out of range")
}

fn mode(value: &str) -> Result<(u32, u32, u32), &'static str> {
    let mut fields = value.split('x');
    let width = mode_component(fields.next())?;
    let height = mode_component(fields.next())?;
    let fps = mode_component(fields.next())?;
    if fields.next().is_some() {
        return Err("invalid streaming mode");
    }
    if width < 16 || height < 16 || !width.is_multiple_of(2) || !height.is_multiple_of(2) {
        return Err("streaming dimensions must be even and at least 16 pixels");
    }
    if fps == 0 {
        return Err("streaming frame rate must be positive");
    }
    Ok((width, height, fps))
}

fn mode_component(value: Option<&str>) -> Result<u32, &'static str> {
    let value = value.ok_or("invalid streaming mode")?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("invalid streaming mode");
    }
    value.parse().map_err(|_| "streaming mode is out of range")
}

fn key_id(value: &str) -> Result<u32, &'static str> {
    if let Some(magnitude) = value.strip_prefix('-') {
        if magnitude.is_empty() || !magnitude.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("invalid remote input key identifier");
        }
        let signed: i32 = value
            .parse()
            .map_err(|_| "remote input key identifier is out of range")?;
        if signed >= 0 {
            return Err("invalid remote input key identifier");
        }
        return Ok(signed as u32);
    }
    decimal_u32(value).map_err(|_| "invalid remote input key identifier")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(fields: &str) -> Result<LaunchRequest, &'static str> {
        launch_request(&Query::parse(&format!("/launch?{fields}")).unwrap())
    }

    #[test]
    fn parses_required_authority_and_normal_moonlight_metadata() {
        let request = parse(concat!(
            "appid=7&mode=1920x1080x60&rikey=00112233445566778899aabbccddeeff",
            "&rikeyid=-2147483648&uniqueid=ignored-for-authority&uuid=ticket",
            "&additionalStates=1&sops=0&hdrMode=0&clientHdrCapVersion=0",
            "&clientHdrCapSupportedFlagsInUint32=0&clientHdrCapMetaDataId=0",
            "&clientHdrCapDisplayData=&localAudioPlayMode=0&surroundAudioInfo=196610",
            "&remoteControllersBitmap=0&gcmap=0&psmap=0&gcpersist=0&corever=1"
        ))
        .unwrap();
        assert_eq!(request.app_id, 7);
        assert_eq!(
            (request.width, request.height, request.fps),
            (1920, 1080, 60)
        );
        assert_eq!(
            request.remote_input_key,
            hex_bytes("00112233445566778899aabbccddeeff", 16)
                .unwrap()
                .as_slice()
        );
        assert_eq!(request.key_id, 0x8000_0000);
        assert!(!request.host_audio_enabled);
    }

    #[test]
    fn parses_macos_desktop_launch_metadata_without_exposing_a_session_key() {
        let request = parse(concat!(
            "appid=2147483647&mode=3840x2160x120",
            "&rikey=00000000000000000000000000000000&rikeyid=-475305041",
            "&additionalStates=1&sops=1&localAudioPlayMode=1",
            "&surroundAudioInfo=196610&remoteControllersBitmap=0",
            "&gcmap=0&gcpmap=0&gcpersist=0&corever=1"
        ))
        .unwrap();
        assert_eq!(request.app_id, i32::MAX as u32);
        assert_eq!(
            (request.width, request.height, request.fps),
            (3840, 2160, 120)
        );
        assert_eq!(request.key_id, (-475_305_041_i32) as u32);
        assert!(request.host_audio_enabled);
    }

    #[test]
    fn accepts_full_unsigned_key_id_range_and_rejects_ambiguous_forms() {
        let request =
            parse("appid=1&mode=16x16x1&rikey=00000000000000000000000000000000&rikeyid=4294967295")
                .unwrap();
        assert_eq!(request.key_id, u32::MAX);
        for value in ["+1", "-0", "-2147483649", "4294967296", " 1", "1 "] {
            let fields = format!(
                "appid=1&mode=16x16x1&rikey=00000000000000000000000000000000&rikeyid={value}"
            );
            assert!(parse(&fields).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn preserves_a_bounded_moonlight_client_name_as_the_device_override() {
        let request = parse(concat!(
            "appid=1&mode=16x16x1&rikey=00000000000000000000000000000000",
            "&rikeyid=1&clientName=Living+Room"
        ))
        .unwrap();
        assert_eq!(request.device_name.as_deref(), Some("Living Room"));

        let defaulted = parse(
            "appid=1&mode=16x16x1&rikey=00000000000000000000000000000000&rikeyid=1&clientName=",
        )
        .unwrap();
        assert_eq!(defaulted.device_name, None);

        let too_long = format!(
            "appid=1&mode=16x16x1&rikey=00000000000000000000000000000000&rikeyid=1&clientName={}",
            "x".repeat(129)
        );
        assert!(matches!(parse(&too_long), Err("invalid device name")));
    }

    #[test]
    fn rejects_invalid_modes_keys_and_application_ids_without_panicking() {
        for fields in [
            "appid=0&mode=1920x1080x60&rikey=00112233445566778899aabbccddeeff&rikeyid=1",
            "appid=1&mode=1919x1080x60&rikey=00112233445566778899aabbccddeeff&rikeyid=1",
            "appid=1&mode=1920x1079x60&rikey=00112233445566778899aabbccddeeff&rikeyid=1",
            "appid=1&mode=1920x1080x0&rikey=00112233445566778899aabbccddeeff&rikeyid=1",
            "appid=1&mode=1920X1080X60&rikey=00112233445566778899aabbccddeeff&rikeyid=1",
            "appid=1&mode=1920x1080x60&rikey=00112233445566778899aabbccddeef&rikeyid=1",
            "appid=1&mode=1920x1080x60&rikey=00112233445566778899aabbccddeefg&rikeyid=1",
        ] {
            assert!(parse(fields).is_err(), "accepted {fields:?}");
        }
    }

    #[test]
    fn rejects_fields_that_could_override_trusted_launch_configuration() {
        for field in ["executable", "path", "args", "environment", "catalog_owner"] {
            let fields = format!(
                "appid=1&mode=1920x1080x60&rikey=00112233445566778899aabbccddeeff&rikeyid=1&{field}=attacker"
            );
            assert!(matches!(parse(&fields), Err("unsupported query field")));
        }
    }

    #[test]
    fn rejects_requested_features_that_the_stream_profile_does_not_implement() {
        let base = concat!(
            "appid=1&mode=1920x1080x60&rikey=00112233445566778899aabbccddeeff",
            "&rikeyid=1"
        );
        for field in [
            "hdrMode=1",
            "sops=2",
            "surroundAudioInfo=393223",
            "localAudioPlayMode=2",
            "remoteControllersBitmap=65536",
            "gcmap=-1",
            "psmap=x",
            "gcpmap=65536",
            "gcpersist=2",
            "corever=2",
            "additionalStates=2",
        ] {
            let fields = format!("{base}&{field}");
            assert!(parse(&fields).is_err(), "accepted {field:?}");
        }
    }

    #[test]
    fn local_audio_play_mode_defaults_off_and_accepts_only_zero_or_one() {
        let base = "appid=1&mode=16x16x1&rikey=00000000000000000000000000000000&rikeyid=1";
        let defaulted = parse(base).unwrap();
        assert!(!defaulted.host_audio_enabled);
        let disabled = parse(&format!("{base}&localAudioPlayMode=0")).unwrap();
        assert!(!disabled.host_audio_enabled);
        let enabled = parse(&format!("{base}&localAudioPlayMode=1")).unwrap();
        assert!(enabled.host_audio_enabled);

        for value in ["2", "-1", "", "true"] {
            assert!(
                parse(&format!("{base}&localAudioPlayMode={value}")).is_err(),
                "accepted {value:?}"
            );
        }
    }

    #[test]
    fn surround_audio_info_accepts_only_exact_supported_client_layouts() {
        let base = "appid=1&mode=16x16x1&rikey=00000000000000000000000000000000&rikeyid=1";
        assert_eq!(parse(base).unwrap().audio_channels, 2);
        // AUDIO_CONFIGURATION_* masks and channel counts in Moonlight's Limelight.h.
        for (mask, channels) in [(0x3_u32, 2), (0x3F, 6), (0x63F, 8)] {
            let value = (mask << 16) | channels;
            assert_eq!(
                parse(&format!("{base}&surroundAudioInfo={value}"))
                    .unwrap()
                    .audio_channels,
                channels
            );
        }
        for value in [
            "",
            "0",
            "6",
            "393222",
            "524296",
            "393223",
            "+4128774",
            "4128774 ",
            "104792073",
            "",
            "0",
            "6",
            "393222",
            "524296",
            "393223",
            "524294",
            "+4128774",
            "4128774 ",
        ] {
            assert!(
                parse(&format!("{base}&surroundAudioInfo={value}")).is_err(),
                "accepted {value:?}"
            );
        }
    }

    #[test]
    fn default_moonlight_qt_launch_query_is_accepted() {
        // Captured from NvHTTP::startApp (nvhttp.cpp:208-240) with default
        // preferences: game optimizations on, multi-controller on with no pad,
        // stereo audio, SDR. Every field below is sent on every launch.
        let request = parse(concat!(
            "uniqueid=0123456789ABCDEF&uuid=0f1e2d3c4b5a69788796a5b4c3d2e1f0",
            "&appid=1&mode=1920x1080x60&additionalStates=1&sops=1",
            "&rikey=00112233445566778899aabbccddeeff&rikeyid=-1419472071",
            "&localAudioPlayMode=0&surroundAudioInfo=196610",
            "&remoteControllersBitmap=0&gcmap=0&psmap=0&gcpersist=0&corever=1"
        ))
        .unwrap();
        assert_eq!(
            (request.width, request.height, request.fps),
            (1920, 1080, 60)
        );
        assert_eq!(request.audio_channels, 2);
    }

    #[test]
    fn single_controller_mode_launch_query_is_accepted() {
        // With multi-controller off moonlight-qt always reports player 1
        // present and persists controllers (`gcpersist=1`); a PlayStation pad
        // sets bit 0 of `psmap`.
        let request = parse(concat!(
            "uniqueid=0123456789ABCDEF&appid=1&mode=1280x720x120&additionalStates=1&sops=1",
            "&rikey=00112233445566778899aabbccddeeff&rikeyid=7&localAudioPlayMode=1",
            "&surroundAudioInfo=4128774&remoteControllersBitmap=1&gcmap=1&psmap=1",
            "&gcpersist=1&corever=1"
        ))
        .unwrap();
        assert_eq!(request.audio_channels, 6);
        assert!(request.host_audio_enabled);
    }

    #[test]
    fn hdr_launch_request_from_moonlight_qt_is_still_refused() {
        let error = parse(concat!(
            "appid=1&mode=1920x1080x60&rikey=00112233445566778899aabbccddeeff&rikeyid=1",
            "&hdrMode=1&clientHdrCapVersion=0&clientHdrCapSupportedFlagsInUint32=0",
            "&clientHdrCapMetaDataId=NV_STATIC_METADATA_TYPE_1",
            "&clientHdrCapDisplayData=0x0x0x0x0x0x0x0x0x0x0"
        ))
        .err();
        assert_eq!(error, Some("HDR streaming is unsupported"));
    }

    #[test]
    fn continuous_audio_defaults_off_and_accepts_only_zero_or_one() {
        let base = "appid=1&mode=16x16x1&rikey=00000000000000000000000000000000&rikeyid=1";
        assert!(!parse(base).unwrap().continuous_audio);
        assert!(
            !parse(&format!("{base}&continuousAudio=0"))
                .unwrap()
                .continuous_audio
        );
        assert!(
            parse(&format!("{base}&continuousAudio=1"))
                .unwrap()
                .continuous_audio
        );

        for value in ["2", "-1", "", "true"] {
            assert!(
                parse(&format!("{base}&continuousAudio={value}")).is_err(),
                "accepted {value:?}"
            );
        }
    }

    #[test]
    fn accepts_bounded_controller_slot_hints_without_authorizing_input() {
        let base = "appid=1&mode=16x16x1&rikey=00000000000000000000000000000000&rikeyid=1";
        for field in ["remoteControllersBitmap", "gcmap", "gcpmap", "psmap"] {
            for value in ["0", "1", "65535"] {
                assert!(
                    parse(&format!("{base}&{field}={value}")).is_ok(),
                    "rejected {value}"
                );
            }
            for value in ["65536", "-1", "+1", "1.0", " 1", "1 ", ""] {
                assert!(
                    parse(&format!("{base}&{field}={value}")).is_err(),
                    "accepted {value:?}"
                );
            }
        }
        for value in ["0", "1"] {
            assert!(parse(&format!("{base}&gcpersist={value}")).is_ok());
        }
        for value in ["2", "-1", "", "true"] {
            assert!(parse(&format!("{base}&gcpersist={value}")).is_err());
        }
    }

    #[test]
    fn accepts_optional_vrr_request_hint_but_rejects_malformed_values() {
        let base = "appid=1&mode=16x16x1&rikey=00000000000000000000000000000000&rikeyid=1";
        assert!(parse(base).is_ok());
        for value in ["0", "1"] {
            assert!(parse(&format!("{base}&clientVrrRequested={value}")).is_ok());
        }
        for value in ["2", "-1", "", "true"] {
            assert!(parse(&format!("{base}&clientVrrRequested={value}")).is_err());
        }
        assert!(matches!(
            parse(&format!("{base}&clientVrrRequested=1&vrrUnsupported=1")),
            Err("unsupported query field")
        ));
    }
}
