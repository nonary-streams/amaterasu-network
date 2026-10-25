use amaterasu_gamestream::network::{NetworkEncryptionPolicy, VideoEncryptionMode};
use amaterasu_media::VideoCodec;
use amaterasu_network_policy::{valid_peer, validate_local_bind};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub type TransportResult<T> = Result<T, &'static str>;
pub const MAX_DATAGRAMS: usize = 2048;
pub const MAX_QUEUE_BYTES: usize = 8 * 1024 * 1024;
pub const SENDS_PER_STREAM: usize = 16;
pub const SENDS_PER_TICK: usize = 64;
pub const DISCOVERY_TOKEN_BYTES: usize = 16;
pub const DEFAULT_PING_TIMEOUT_MS: i64 = 10_000;
pub const MAX_PING_TIMEOUT_MS: i64 = i32::MAX as i64;

fn default_ping_timeout_ms() -> i64 {
    DEFAULT_PING_TIMEOUT_MS
}

fn yes() -> bool {
    true
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub enabled: bool,
    pub allow_remote: bool,
    pub allowed_principals: Vec<String>,
}

impl Settings {
    pub fn validate(&self) -> TransportResult<()> {
        if self.allowed_principals.len() > 16
            || self.allowed_principals.iter().any(|principal| {
                principal.is_empty()
                    || principal.len() > 128
                    || principal.chars().any(char::is_control)
            })
        {
            return Err("invalid_settings");
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct VideoSettings {
    /// The single codec this stream carries when `codecs` is empty.
    #[serde(default, skip_serializing_if = "VideoCodec::is_default")]
    pub codec: VideoCodec,
    /// Codecs the client may still negotiate after this transport opens. The
    /// first video packet selects one of them for the life of the stream.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub codecs: Vec<VideoCodec>,
    pub packet_size: usize,
    pub fec_percentage: u8,
    pub min_parity_shards: u8,
    pub max_fec_blocks: u8,
    #[serde(default = "default_video_max_batch_size_kb")]
    pub max_batch_size_kb: u8,
}

fn default_video_max_batch_size_kb() -> u8 {
    64
}

impl Default for VideoSettings {
    fn default() -> Self {
        Self {
            codec: VideoCodec::H264,
            codecs: Vec::new(),
            packet_size: 1024,
            fec_percentage: 20,
            min_parity_shards: 2,
            max_fec_blocks: 1,
            max_batch_size_kb: default_video_max_batch_size_kb(),
        }
    }
}

impl VideoSettings {
    pub fn valid_batch_size_kb(&self) -> bool {
        self.max_batch_size_kb <= 64
    }

    /// The codecs a video packet may use before one is selected.
    pub fn offered_codecs(&self) -> &[VideoCodec] {
        if self.codecs.is_empty() {
            std::slice::from_ref(&self.codec)
        } else {
            &self.codecs
        }
    }

    /// A codec list replaces the single `codec` field rather than adding to it,
    /// and names each codec at most once.
    pub fn valid_codec_offer(&self) -> bool {
        let unique = self
            .codecs
            .iter()
            .enumerate()
            .all(|(index, codec)| !self.codecs[..index].contains(codec));
        self.codecs.is_empty() || (self.codec.is_default() && unique)
    }

    pub fn effective(&self) -> Self {
        Self {
            max_batch_size_kb: self.effective_batch_size_kb(),
            ..self.clone()
        }
    }

    pub fn effective_batch_size_kb(&self) -> u8 {
        match self.max_batch_size_kb {
            16 | 32 | 64 => self.max_batch_size_kb,
            _ => 64,
        }
    }

    pub fn batch_size_fallback(&self) -> bool {
        self.max_batch_size_kb != 0 && !matches!(self.max_batch_size_kb, 16 | 32 | 64)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AudioSettings {
    pub packet_ms: u32,
    pub channels: u16,
    pub wire_payload_bytes: usize,
    #[serde(default)]
    pub ssrc: u32,
}

#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Encryption {
    pub key_hex: String,
    pub key_id: u32,
    pub video: bool,
    pub audio: bool,
    #[serde(default)]
    pub permit_legacy_audio_iv_wrap: bool,
}

#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Discovery {
    pub video_ping_payload: String,
    pub audio_ping_payload: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VideoEncryptionPolicySnapshot {
    pub lan_mode: i64,
    pub wan_mode: i64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryTokens {
    pub video: [u8; DISCOVERY_TOKEN_BYTES],
    pub audio: [u8; DISCOVERY_TOKEN_BYTES],
}

impl Discovery {
    pub fn tokens(&self) -> TransportResult<DiscoveryTokens> {
        let video = ping_payload(&self.video_ping_payload)?;
        let audio = ping_payload(&self.audio_ping_payload)?;
        if video == audio {
            return Err("invalid_discovery");
        }
        Ok(DiscoveryTokens { video, audio })
    }
}

fn ping_payload(value: &str) -> TransportResult<[u8; DISCOVERY_TOKEN_BYTES]> {
    let bytes = value.as_bytes();
    if bytes.len() != DISCOVERY_TOKEN_BYTES
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("invalid_discovery");
    }
    bytes.try_into().map_err(|_| "invalid_discovery")
}

impl Encryption {
    pub fn key(&self) -> TransportResult<[u8; 16]> {
        if self.key_hex.len() != 32 || (!self.video && !self.audio) {
            return Err("invalid_encryption");
        }
        let mut key = [0u8; 16];
        for (index, pair) in self
            .key_hex
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .enumerate()
        {
            let high = (pair[0] as char).to_digit(16).ok_or("invalid_encryption")?;
            let low = (pair[1] as char).to_digit(16).ok_or("invalid_encryption")?;
            key[index] = ((high << 4) | low) as u8;
        }
        Ok(key)
    }
}

#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Open {
    pub peer_ip: IpAddr,
    #[serde(default)]
    pub video_stream_format: Option<amaterasu_module_sdk::VideoStreamFormat>,
    #[serde(default)]
    pub video_encryption_policy: Option<Box<VideoEncryptionPolicySnapshot>>,
    #[serde(default)]
    pub video_port: Option<u16>,
    #[serde(default)]
    pub audio_port: Option<u16>,
    #[serde(default)]
    pub discovery: Option<Box<Discovery>>,
    #[serde(default)]
    pub video_bind: Option<SocketAddr>,
    #[serde(default)]
    pub audio_bind: Option<SocketAddr>,
    #[serde(default)]
    pub video: VideoSettings,
    pub audio: AudioSettings,
    #[serde(default = "yes")]
    pub stream_audio: bool,
    #[serde(default = "default_ping_timeout_ms")]
    pub ping_timeout_ms: i64,
    #[serde(default)]
    pub encryption: Option<Encryption>,
    #[serde(default)]
    pub operation_id: Option<String>,
}

impl Open {
    pub fn validate(&self, allow_remote: bool) -> TransportResult<()> {
        if let Some(format) = self.video_stream_format {
            validate_video_stream_format(format)?;
        }
        self.validate_video_encryption_policy()?;
        validate_ping_timeout_ms(self.ping_timeout_ms)?;
        if !valid_peer(self.peer_ip) {
            return Err("invalid_destination");
        }
        match (self.video_port, self.audio_port, &self.discovery) {
            (Some(video), Some(audio), None) if video != 0 && audio != 0 => {}
            (None, None, Some(discovery)) => {
                discovery.tokens()?;
            }
            _ => return Err("invalid_destination"),
        }
        if !allow_remote && !self.peer_ip.is_loopback() {
            return Err("remote_disabled");
        }
        if !self.video.valid_batch_size_kb() || !self.video.valid_codec_offer() {
            return Err("invalid_video_configuration");
        }
        for bind in [self.video_bind, self.audio_bind].into_iter().flatten() {
            validate_local_bind(bind.ip(), self.peer_ip, allow_remote)?;
        }
        if !matches!(self.audio.packet_ms, 5 | 10)
            || !matches!(self.audio.channels, 2 | 6 | 8)
            || !self.valid_audio_wire_length()
        {
            return Err("invalid_audio_configuration");
        }
        if !self.stream_audio
            && self
                .encryption
                .as_ref()
                .is_some_and(|encryption| encryption.audio)
        {
            return Err("invalid_encryption");
        }
        if let Some(operation) = &self.operation_id {
            validate_operation(operation)?;
        }
        if let Some(encryption) = &self.encryption {
            encryption.key()?;
        }
        Ok(())
    }

    pub(crate) fn validate_video_encryption_policy(&self) -> TransportResult<()> {
        let Some(snapshot) = self.video_encryption_policy.as_deref() else {
            return Ok(());
        };
        let policy = NetworkEncryptionPolicy {
            lan_mode: VideoEncryptionMode::try_from(snapshot.lan_mode)
                .map_err(|_| "invalid_encryption")?,
            wan_mode: VideoEncryptionMode::try_from(snapshot.wan_mode)
                .map_err(|_| "invalid_encryption")?,
        };
        let announced_video_encryption = self
            .encryption
            .as_ref()
            .is_some_and(|encryption| encryption.video);
        if policy.accepts_video_encryption_for_peer(self.peer_ip, announced_video_encryption) {
            Ok(())
        } else {
            Err("invalid_encryption")
        }
    }

    fn valid_audio_wire_length(&self) -> bool {
        let length = self.audio.wire_payload_bytes;
        if self
            .encryption
            .as_ref()
            .is_some_and(|encryption| encryption.audio)
        {
            (16..=1280).contains(&length) && length.is_multiple_of(16)
        } else {
            (1..=1275).contains(&length)
        }
    }

    pub fn local(&self, video: bool) -> SocketAddr {
        let configured = if video {
            self.video_bind
        } else {
            self.audio_bind
        };
        configured.unwrap_or_else(|| {
            SocketAddr::new(
                if self.peer_ip.is_ipv4() {
                    IpAddr::V4(if self.peer_ip.is_loopback() {
                        Ipv4Addr::LOCALHOST
                    } else {
                        Ipv4Addr::UNSPECIFIED
                    })
                } else {
                    IpAddr::V6(if self.peer_ip.is_loopback() {
                        Ipv6Addr::LOCALHOST
                    } else {
                        Ipv6Addr::UNSPECIFIED
                    })
                },
                0,
            )
        })
    }
}

pub(crate) fn validate_video_stream_format(
    format: amaterasu_module_sdk::VideoStreamFormat,
) -> TransportResult<()> {
    use amaterasu_module_sdk::{DynamicRange, VideoCodec};

    match (format.codec, format.bit_depth, format.dynamic_range) {
        (VideoCodec::H264 | VideoCodec::Hevc | VideoCodec::Av1, 8, DynamicRange::Sdr) => Ok(()),
        _ => Err("unsupported_video_format"),
    }
}

pub fn validate_ping_timeout_ms(value: i64) -> TransportResult<u64> {
    if !(0..=MAX_PING_TIMEOUT_MS).contains(&value) {
        return Err("invalid_ping_timeout");
    }
    Ok(value as u64)
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
// Each request is parsed, handled and dropped within one control call, so the
// larger Open variant costs nothing worth an extra allocation.
#[allow(clippy::large_enum_variant)]
pub enum Operation {
    Open(Open),
    ConfigureVideoFormat {
        stream: u64,
        video_stream_format: amaterasu_module_sdk::VideoStreamFormat,
    },
    Lookup {
        operation_id: String,
    },
    Close {
        stream: u64,
    },
    Status {
        stream: Option<u64>,
    },
}

pub fn validate_operation(operation: &str) -> TransportResult<()> {
    if operation.is_empty() || operation.len() > 128 || operation.chars().any(char::is_control) {
        return Err("invalid_operation_id");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn remote_opt_in_still_rejects_unsafe_or_mismatched_video_and_audio_binds() {
        for field in ["video_bind", "audio_bind"] {
            for (peer, bind) in [
                ("127.0.0.1", "255.255.255.255:0"),
                ("127.0.0.1", "239.1.2.3:0"),
                ("127.0.0.1", "[::1]:0"),
                ("::1", "[ff02::1]:0"),
                ("::1", "[::ffff:127.0.0.1]:0"),
                ("::1", "127.0.0.1:0"),
            ] {
                let mut specification = json!({
                    "peer_ip":peer,
                    "video_port":50001,
                    "audio_port":50002,
                    "audio":{"packet_ms":10,"channels":2,"wire_payload_bytes":4}
                });
                specification[field] = bind.into();
                let request: Open = serde_json::from_value(specification).unwrap();
                assert_eq!(request.validate(true), Err("invalid_bind"));
            }
        }
    }

    #[test]
    fn missing_stream_audio_field_preserves_the_enabled_legacy_default() {
        let request: Open = serde_json::from_value(json!({
            "peer_ip":"127.0.0.1",
            "video_port":50001,
            "audio_port":50002,
            "audio":{"packet_ms":10,"channels":2,"wire_payload_bytes":16}
        }))
        .unwrap();
        assert!(request.stream_audio);
        assert!(request.validate(false).is_ok());
        assert_eq!(request.video.max_batch_size_kb, 64);
    }

    fn open_with_video_policy(
        peer_ip: &str,
        lan_mode: i64,
        wan_mode: i64,
        encrypted: bool,
    ) -> Open {
        serde_json::from_value(json!({
            "peer_ip":peer_ip,
            "video_port":50001,
            "audio_port":50002,
            "audio":{"packet_ms":10,"channels":2,"wire_payload_bytes":4},
            "encryption": if encrypted {
                json!({
                    "key_hex":"000102030405060708090a0b0c0d0e0f",
                    "key_id":1,
                    "video":true,
                    "audio":false
                })
            } else {
                serde_json::Value::Null
            },
            "video_encryption_policy":{"lan_mode":lan_mode,"wan_mode":wan_mode}
        }))
        .unwrap()
    }

    #[test]
    fn mandatory_lan_policy_requires_the_client_to_announce_video_encryption() {
        let encrypted = open_with_video_policy("192.168.1.20", 2, 0, true);
        assert!(encrypted.validate(true).is_ok());

        let plaintext = open_with_video_policy("192.168.1.20", 2, 0, false);
        assert_eq!(plaintext.validate(true), Err("invalid_encryption"));
    }

    #[test]
    fn never_wan_policy_requires_plaintext_video() {
        let plaintext = open_with_video_policy("8.8.8.8", 0, 0, false);
        assert!(plaintext.validate(true).is_ok());

        let encrypted = open_with_video_policy("8.8.8.8", 0, 0, true);
        assert_eq!(encrypted.validate(true), Err("invalid_encryption"));
    }

    #[test]
    fn open_consumer_selects_wan_encryption_mode_for_public_ipv6_peer() {
        let encrypted = open_with_video_policy("2001:4860:4860::8888", 0, 2, true);
        assert!(encrypted.validate(true).is_ok());

        let plaintext = open_with_video_policy("2001:4860:4860::8888", 0, 2, false);
        assert_eq!(plaintext.validate(true), Err("invalid_encryption"));
    }

    #[test]
    fn open_consumer_selects_lan_encryption_mode_for_private_ipv4_peer() {
        let plaintext = open_with_video_policy("192.168.1.20", 0, 2, false);
        assert!(plaintext.validate(true).is_ok());

        let encrypted = open_with_video_policy("192.168.1.20", 0, 2, true);
        assert_eq!(encrypted.validate(true), Err("invalid_encryption"));
    }

    #[test]
    fn opportunistic_policy_accepts_either_video_encryption_choice() {
        for encrypted in [false, true] {
            let request = open_with_video_policy("192.168.1.20", 1, 1, encrypted);
            assert!(request.validate(true).is_ok());
        }
    }

    #[test]
    fn invalid_numeric_video_encryption_modes_are_rejected() {
        for (lan_mode, wan_mode) in [(-1, 0), (0, -1), (3, 0), (0, 3)] {
            let request = open_with_video_policy("192.168.1.20", lan_mode, wan_mode, false);
            assert_eq!(request.validate(true), Err("invalid_encryption"));
        }
    }

    #[test]
    fn video_batch_size_accepts_reference_range_and_reports_normalized_values() {
        for value in 0..=64 {
            let settings = VideoSettings {
                max_batch_size_kb: value,
                ..VideoSettings::default()
            };
            assert!(settings.valid_batch_size_kb());
            assert_eq!(
                settings.effective_batch_size_kb(),
                match value {
                    16 | 32 | 64 => value,
                    _ => 64,
                }
            );
            assert_eq!(
                settings.batch_size_fallback(),
                value != 0 && !matches!(value, 16 | 32 | 64)
            );
        }
        assert!(
            !VideoSettings {
                max_batch_size_kb: 65,
                ..VideoSettings::default()
            }
            .valid_batch_size_kb()
        );
    }

    #[test]
    fn video_codec_defaults_to_h264_and_rejects_unknown_values() {
        let default: VideoSettings = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(default.codec == VideoCodec::H264);
        assert!(
            serde_json::to_value(default)
                .unwrap()
                .get("codec")
                .is_none()
        );
        let hevc: VideoSettings =
            serde_json::from_value(serde_json::json!({"codec":"hevc"})).unwrap();
        assert!(hevc.codec == VideoCodec::Hevc);
        assert_eq!(serde_json::to_value(&hevc).unwrap()["codec"], "hevc");
        let av1: VideoSettings =
            serde_json::from_value(serde_json::json!({"codec":"av1"})).unwrap();
        assert!(av1.offered_codecs() == [VideoCodec::Av1]);
        assert!(
            serde_json::from_value::<VideoSettings>(serde_json::json!({"codec":"vp9"})).is_err()
        );
    }

    #[test]
    fn codec_offer_replaces_the_single_codec_and_rejects_duplicates() {
        let offer: VideoSettings =
            serde_json::from_value(serde_json::json!({"codecs":["h264","hevc","av1"]})).unwrap();
        assert!(offer.valid_codec_offer());
        assert!(offer.offered_codecs() == [VideoCodec::H264, VideoCodec::Hevc, VideoCodec::Av1]);
        assert_eq!(
            serde_json::to_value(&offer).unwrap()["codecs"],
            serde_json::json!(["h264", "hevc", "av1"])
        );
        let single = VideoSettings::default();
        assert!(single.valid_codec_offer());
        assert!(single.offered_codecs() == [VideoCodec::H264]);
        assert!(
            serde_json::to_value(&single)
                .unwrap()
                .get("codecs")
                .is_none()
        );
        for invalid in [
            serde_json::json!({"codecs":["hevc","hevc"]}),
            serde_json::json!({"codec":"hevc","codecs":["hevc","av1"]}),
        ] {
            let settings: VideoSettings = serde_json::from_value(invalid).unwrap();
            assert!(!settings.valid_codec_offer());
        }
    }

    #[test]
    fn video_batch_size_open_field_is_optional_bounded_and_normalized_at_runtime() {
        let base = json!({
            "peer_ip":"127.0.0.1",
            "video_port":50001,
            "audio_port":50002,
            "audio":{"packet_ms":10,"channels":2,"wire_payload_bytes":16}
        });
        let mut omitted = base.clone();
        let request: Open = serde_json::from_value(omitted.clone()).unwrap();
        assert_eq!(request.video.effective_batch_size_kb(), 64);

        omitted["video"] = json!({"max_batch_size_kb":17});
        let request: Open = serde_json::from_value(omitted).unwrap();
        assert!(request.validate(false).is_ok());
        assert_eq!(request.video.effective_batch_size_kb(), 64);
        assert!(request.video.batch_size_fallback());

        let mut out_of_range = base;
        out_of_range["video"] = json!({"max_batch_size_kb":65});
        let request: Open = serde_json::from_value(out_of_range).unwrap();
        assert_eq!(request.validate(false), Err("invalid_video_configuration"));
    }

    #[test]
    fn disabled_audio_rejects_audio_encryption_configuration() {
        let request: Open = serde_json::from_value(json!({
            "peer_ip":"127.0.0.1",
            "video_port":50001,
            "audio_port":50002,
            "audio":{"packet_ms":10,"channels":2,"wire_payload_bytes":16},
            "stream_audio":false,
            "encryption":{"key_hex":"000102030405060708090a0b0c0d0e0f","key_id":1,
                "video":true,"audio":true}
        }))
        .unwrap();
        assert_eq!(request.validate(false), Err("invalid_encryption"));
    }
}
