use super::{Reply, RouterConfig};
use crate::encoder_snapshot::CodecAdvertisement;

pub fn escape(value: &str) -> String {
    let mut output = String::new();
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&apos;"),
            character if character.is_control() || matches!(character, '\u{fffe}' | '\u{ffff}') => {
                output.push(' ')
            }
            character => output.push(character),
        }
    }
    output
}

pub fn response(status: u16, message: &str, fields: &[(&str, &str)]) -> Reply {
    let mut body = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><root status_code=\"{status}\" status_message=\"{}\">",
        escape(message)
    );
    for (name, value) in fields {
        // Names are static literals chosen by this module, never client input.
        body.push_str(&format!("<{name}>{}</{name}>", escape(value)));
    }
    body.push_str("</root>");
    Reply {
        status,
        content_type: "application/xml; charset=utf-8",
        body: body.into_bytes(),
        requires_paired_tls: false,
    }
}

pub fn error(status: u16, message: &str) -> Reply {
    response(status, message, &[("paired", "0")])
}

/// `/serverinfo` over TLS from a certificate that is not (or no longer) paired.
///
/// moonlight-qt treats any non-2xx HTTP status as a network failure and shows
/// the host offline. Only an XML `status_code` of 401 inside a successful HTTP
/// reply (`NvHTTP::verifyResponseStatus`) makes it fall back to plain-HTTP
/// `/serverinfo` and show "not paired", which is also what the Vibeshine
/// reference answers when client verification fails.
pub fn unpaired_certificate() -> Reply {
    let mut reply = error(401, "client certificate is not paired");
    reply.status = 200;
    reply
}

pub fn paired() -> Reply {
    response(200, "OK", &[("paired", "1")])
}

/// Reply to `/unpair`: `unpaired=1` only after a paired certificate was removed.
pub fn unpaired(removed: bool) -> Reply {
    response(200, "OK", &[("unpaired", if removed { "1" } else { "0" })])
}

pub fn server_info(
    config: &RouterConfig,
    host_id: &str,
    paired: bool,
    current_game: u32,
    busy: bool,
    streaming_supported: bool,
    codecs: CodecAdvertisement,
) -> Reply {
    let codec_mode_support = codecs.codec_mode_support.to_string();
    let max_luma_pixels_hevc = codecs.max_luma_pixels_hevc.to_string();
    response(
        200,
        "OK",
        &[
            ("hostname", &config.hostname),
            (
                "appversion",
                if streaming_supported {
                    if cfg!(target_os = "linux") {
                        // Moonlight uses a negative fourth component to enable
                        // Sunshine-compatible RTSP encryption negotiation.
                        "7.1.431.-1"
                    } else {
                        "7.1.431.0"
                    }
                } else {
                    "7.1.0.0"
                },
            ),
            ("GfeVersion", "0.0.0.0"),
            ("uniqueid", host_id),
            ("HttpsPort", &config.https_port.to_string()),
            ("ExternalPort", &config.http_port.to_string()),
            ("mac", super::capabilities::mac()),
            ("PairStatus", if paired { "1" } else { "0" }),
            ("currentgame", &current_game.to_string()),
            (
                "state",
                if busy {
                    "AMATERASU_SERVER_BUSY"
                } else {
                    "AMATERASU_SERVER_FREE"
                },
            ),
            // Moonlight's SCM_* codec bits and its nonzero-means-HEVC luma
            // limit, both derived from the enumerated encoders. A zero mask
            // makes Moonlight abort before RTSP even when /launch succeeded.
            ("ServerCodecModeSupport", codec_mode_support.as_str()),
            ("MaxLumaPixelsHEVC", max_luma_pixels_hevc.as_str()),
            (
                "StreamingSupported",
                if streaming_supported { "1" } else { "0" },
            ),
        ],
    )
}
