use amaterasu_contracts::virtual_display::VirtualDisplayIntent;
use amaterasu_gamestream::{
    rtsp::negotiation::UdpDiscovery,
    sdp::{Announce, ColorMode, ControlProtocol},
};
#[cfg(test)]
use amaterasu_module_sdk::EncoderBackend;
use amaterasu_module_sdk::EncoderSelection;
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

const DEFAULT_BASE_PORT: u16 = 47_989;
const MIN_BASE_PORT: u16 = 1_029;
const MAX_BASE_PORT: u16 = 65_514;
const RTSP_SETUP_OFFSET: u16 = 21;
const VIDEO_OFFSET: u16 = 9;
const CONTROL_OFFSET: u16 = 10;
const AUDIO_OFFSET: u16 = 11;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AddressFamily {
    #[default]
    Ipv4,
    Both,
}

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub enabled: bool,
    pub allow_remote: bool,
    pub bind: SocketAddr,
    pub address_family: Option<AddressFamily>,
    pub bind_address: Option<String>,
    pub allowed_principals: Vec<String>,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: false,
            allow_remote: false,
            bind: SocketAddr::from(([127, 0, 0, 1], DEFAULT_BASE_PORT + RTSP_SETUP_OFFSET)),
            address_family: None,
            bind_address: None,
            allowed_principals: Vec::new(),
        }
    }
}
impl Settings {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.allowed_principals.len() > 16
            || self.allowed_principals.iter().any(|name| !valid_name(name))
        {
            return Err("invalid_settings");
        }
        self.resolved_bind()?;
        Ok(())
    }

    pub fn resolved_bind(&self) -> Result<SocketAddr, &'static str> {
        self.resolved_binds()?
            .into_iter()
            .next()
            .ok_or("invalid_bind")
    }

    pub fn resolved_binds(&self) -> Result<Vec<SocketAddr>, &'static str> {
        Ok(self
            .resolved_bind_ips()?
            .into_iter()
            .map(|ip| SocketAddr::new(ip, self.bind.port()))
            .collect())
    }

    fn resolved_bind_ips(&self) -> Result<Vec<IpAddr>, &'static str> {
        let family = self.resolved_address_family();
        let addresses = match self.bind_address.as_deref() {
            None if self.address_family.is_none() => vec![self.bind.ip()],
            None => default_bind_ips(family, self.allow_remote),
            Some(configured) if configured.trim().is_empty() && self.address_family.is_none() => {
                legacy_empty_bind_ips(family, self.allow_remote, self.bind.ip())
            }
            Some(configured) if configured.trim().is_empty() => {
                default_bind_ips(family, self.allow_remote)
            }
            Some(configured) => vec![
                configured
                    .trim()
                    .parse::<IpAddr>()
                    .map_err(|_| "invalid_bind")?,
            ],
        };
        addresses
            .into_iter()
            .map(|ip| {
                if !family.supports(ip) {
                    return Err("address_family_mismatch");
                }
                if invalid_configured_bind(ip)
                    || (self.bind_address.is_none()
                        && self.address_family.is_none()
                        && invalid_bind_address(ip))
                    || (!self.allow_remote && !ip.is_loopback())
                {
                    return Err("invalid_bind");
                }
                Ok(ip)
            })
            .collect()
    }

    fn resolved_address_family(&self) -> AddressFamily {
        self.address_family.unwrap_or_else(|| {
            let ip = self
                .bind_address
                .as_deref()
                .and_then(|address| address.trim().parse::<IpAddr>().ok())
                .unwrap_or_else(|| self.bind.ip());
            if ip.is_ipv4() {
                AddressFamily::Ipv4
            } else {
                AddressFamily::Both
            }
        })
    }

    pub fn default_base_port(&self) -> Option<u16> {
        let port = self.bind.port();
        if port == 0 {
            None
        } else {
            port.checked_sub(RTSP_SETUP_OFFSET)
                .filter(|base| (MIN_BASE_PORT..=MAX_BASE_PORT).contains(base))
        }
    }

    pub fn set_base_port(&mut self, base_port: u16) -> Result<(), &'static str> {
        validate_base_port(base_port)?;
        self.bind.set_port(base_port + RTSP_SETUP_OFFSET);
        Ok(())
    }

    #[cfg(test)]
    pub fn rtsp_bind_for_base(&self, base_port: u16) -> Result<SocketAddr, &'static str> {
        self.rtsp_binds_for_base(base_port)?
            .into_iter()
            .next()
            .ok_or("invalid_bind")
    }

    pub fn rtsp_binds_for_base(&self, base_port: u16) -> Result<Vec<SocketAddr>, &'static str> {
        validate_base_port(base_port)?;
        Ok(self
            .resolved_bind_ips()?
            .into_iter()
            .map(|address| SocketAddr::new(address, base_port + RTSP_SETUP_OFFSET))
            .collect())
    }

    #[cfg(test)]
    pub fn media_binds(&self, base_port: u16) -> Result<MediaBinds, &'static str> {
        let address = self
            .resolved_bind_ips()?
            .into_iter()
            .next()
            .ok_or("invalid_bind")?;
        self.media_binds_on(base_port, address)
    }

    pub fn media_binds_on(
        &self,
        base_port: u16,
        local_address: IpAddr,
    ) -> Result<MediaBinds, &'static str> {
        validate_base_port(base_port)?;
        let configured_addresses = self.resolved_bind_ips()?;
        let configured_address = configured_addresses
            .into_iter()
            .find(|address| address.is_ipv4() == local_address.is_ipv4())
            .ok_or("address_family_mismatch")?;
        let address = if configured_address.is_unspecified() {
            local_address
        } else {
            configured_address
        };
        if address.is_ipv4() != configured_address.is_ipv4() {
            return Err("address_family_mismatch");
        }
        Ok(MediaBinds {
            video: SocketAddr::new(address, base_port + VIDEO_OFFSET),
            control: SocketAddr::new(address, base_port + CONTROL_OFFSET),
            audio: SocketAddr::new(address, base_port + AUDIO_OFFSET),
        })
    }

    pub fn probe_media_binds(&self, base_port: u16) -> Result<(), &'static str> {
        let binds = self.media_binds_by_family(base_port)?;
        // Hold every UDP socket until the complete set has been checked. The
        // stream-session service later binds its per-session sockets from the
        // same addresses; this preflight cannot reserve sockets across services.
        let mut sockets = Vec::with_capacity(binds.len() * 3);
        for bind in binds
            .iter()
            .flat_map(|family| [family.video, family.control, family.audio])
        {
            let socket = Socket::new(Domain::for_address(bind), Type::DGRAM, Some(Protocol::UDP))
                .map_err(|_| "udp_bind_failed")?;
            if bind.is_ipv6() {
                socket.set_only_v6(true).map_err(|_| "udp_bind_failed")?;
            }
            socket
                .bind(&SockAddr::from(bind))
                .map_err(|_| "udp_bind_failed")?;
            sockets.push(UdpSocket::from(socket));
        }
        Ok(())
    }

    pub fn media_binds_by_family(&self, base_port: u16) -> Result<Vec<MediaBinds>, &'static str> {
        self.resolved_bind_ips()?
            .into_iter()
            .map(|address| self.media_binds_on(base_port, address))
            .collect()
    }
}

fn default_bind_ips(family: AddressFamily, allow_remote: bool) -> Vec<IpAddr> {
    match (family, allow_remote) {
        (AddressFamily::Ipv4, true) => vec![IpAddr::V4(Ipv4Addr::UNSPECIFIED)],
        (AddressFamily::Ipv4, false) => vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        (AddressFamily::Both, true) => vec![
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        ],
        (AddressFamily::Both, false) => vec![
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ],
    }
}

fn legacy_empty_bind_ips(
    family: AddressFamily,
    allow_remote: bool,
    legacy_bind_ip: IpAddr,
) -> Vec<IpAddr> {
    match (family, allow_remote) {
        (AddressFamily::Ipv4, false) => vec![legacy_bind_ip],
        _ => default_bind_ips(family, allow_remote),
    }
}

impl AddressFamily {
    fn supports(self, address: IpAddr) -> bool {
        matches!(self, Self::Both) || address.is_ipv4()
    }
}

fn invalid_configured_bind(address: IpAddr) -> bool {
    address.is_multicast()
        || address == IpAddr::V4(Ipv4Addr::BROADCAST)
        || matches!(address, IpAddr::V6(address) if address.to_ipv4_mapped().is_some())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MediaBinds {
    pub video: SocketAddr,
    pub control: SocketAddr,
    pub audio: SocketAddr,
}

pub fn validate_base_port(port: u16) -> Result<(), &'static str> {
    if (MIN_BASE_PORT..=MAX_BASE_PORT).contains(&port) {
        Ok(())
    } else {
        Err("invalid_port")
    }
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Capture {
    pub capture_provider: CaptureProvider,
    #[serde(default)]
    pub constant_rate: bool,
    pub output: String,
    pub encoder: EncoderSelection,
    pub audio_endpoint: String,
    #[serde(default)]
    pub host_audio_enabled: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureProvider {
    Dxgi,
    Wgc,
    /// An explicitly selected current-user portal source.
    #[serde(rename = "pipewire")]
    PipeWire,
    X11,
    Kms,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Profile {
    /// The only codec the client may negotiate when `codecs` is empty.
    #[serde(
        default,
        skip_serializing_if = "amaterasu_media::VideoCodec::is_default"
    )]
    pub codec: amaterasu_media::VideoCodec,
    /// Codecs the host's encoders can serve for this launch, as signed by
    /// NVHTTP. DESCRIBE advertises them and ANNOUNCE must choose one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub codecs: Vec<amaterasu_media::VideoCodec>,
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub bitrate_kbps: u32,
    pub max_reference_frames: u32,
    pub packet_size: usize,
    pub fec_percentage: u8,
    pub video_max_batch_size_kb: u8,
    pub min_parity_shards: u8,
    pub max_fec_blocks: u8,
    pub packet_ms: u32,
    pub audio_bitrate: u32,
    pub encrypt_video: bool,
    pub encrypt_audio: bool,
    pub permit_legacy_audio_iv_wrap: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EncryptionSnapshot {
    pub video: bool,
    pub audio: bool,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            codec: amaterasu_media::VideoCodec::H264,
            codecs: Vec::new(),
            width: 1920,
            height: 1080,
            fps: 60,
            bitrate_kbps: 10000,
            max_reference_frames: 1,
            packet_size: 1024,
            fec_percentage: 20,
            video_max_batch_size_kb: 64,
            min_parity_shards: 2,
            max_fec_blocks: 1,
            packet_ms: 10,
            audio_bitrate: 128000,
            encrypt_video: true,
            encrypt_audio: true,
            permit_legacy_audio_iv_wrap: false,
        }
    }
}
fn audio_channel_mask(channels: u32) -> u32 {
    match channels {
        2 => 3,
        6 => 63,
        8 => 1599,
        _ => 0,
    }
}

impl Profile {
    /// The codecs this ticket offers the client.
    pub fn offered_codecs(&self) -> &[amaterasu_media::VideoCodec] {
        if self.codecs.is_empty() {
            std::slice::from_ref(&self.codec)
        } else {
            &self.codecs
        }
    }

    fn offers(&self, codec: amaterasu_media::VideoCodec) -> bool {
        self.offered_codecs().contains(&codec)
    }

    pub fn effective_video_max_batch_size_kb(&self) -> u8 {
        match self.video_max_batch_size_kb {
            16 | 32 | 64 => self.video_max_batch_size_kb,
            _ => 64,
        }
    }

    #[cfg(test)]
    pub fn matches(&self, announce: &Announce) -> bool {
        self.matches_video(announce)
            && self.matches_audio(announce)
            && self.matches_transport(announce)
    }

    fn matches_video(&self, announce: &Announce) -> bool {
        self.offers(sdp_codec(announce.video.format.codec))
            && announce.video.width == self.width
            && announce.video.height == self.height
            && announce.video.fps == self.fps
            && announce.video.bitrate_kbps == self.bitrate_kbps
            && announce.video.max_reference_frames == self.max_reference_frames
            && supported_color(announce.video.color)
            && announce.encryption.video == self.encrypt_video
    }

    fn matches_audio(&self, announce: &Announce) -> bool {
        announce.audio.channels == 2
            && announce.audio.channel_mask == 3
            && announce.audio.packet_duration_ms == self.packet_ms
            && announce.encryption.audio == self.encrypt_audio
    }

    fn matches_transport(&self, announce: &Announce) -> bool {
        announce.packet_size as usize == self.packet_size
            && announce.control == ControlProtocol::EncryptedEnet
            && announce.encryption.control_v2
            && announce.fec.minimum_packets == u32::from(self.min_parity_shards)
            && announce
                .fec
                .repair_percent
                .is_none_or(|percent| percent == u32::from(self.fec_percentage))
    }

    fn validate(&self) -> Result<(), &'static str> {
        if !(16..=3840).contains(&self.width)
            || !(16..=2160).contains(&self.height)
            || !self.width.is_multiple_of(2)
            || !self.height.is_multiple_of(2)
            || !(1..=120).contains(&self.fps)
            || !(100..=100000).contains(&self.bitrate_kbps)
            || self.max_reference_frames > 16
            || self.video_max_batch_size_kb > 64
            || !matches!(self.packet_ms, 5 | 10)
            || !(6000..=512000).contains(&self.audio_bitrate)
        {
            return Err("invalid_profile");
        }

        let unique_codecs = self
            .codecs
            .iter()
            .enumerate()
            .all(|(index, codec)| !self.codecs[..index].contains(codec));
        if !self.codecs.is_empty() && (!self.codec.is_default() || !unique_codecs) {
            return Err("invalid_profile");
        }
        // Framing and FEC limits do not depend on the codec.
        let codec = match self.offered_codecs()[0] {
            amaterasu_media::VideoCodec::H264 => amaterasu_gamestream::video::VideoCodec::H264,
            amaterasu_media::VideoCodec::Hevc => amaterasu_gamestream::video::VideoCodec::Hevc,
            amaterasu_media::VideoCodec::Av1 => amaterasu_gamestream::video::VideoCodec::Av1,
        };
        amaterasu_gamestream::video::VideoPacketizer::new_with_codec(
            amaterasu_gamestream::video::VideoConfig {
                packet_size: self.packet_size,
                fec_percentage: self.fec_percentage,
                min_parity_shards: self.min_parity_shards,
                max_fec_blocks: self.max_fec_blocks,
                // Encryption is applied by media transport after packetization.
                encrypted: false,
            },
            codec,
        )
        .map_err(|_| "invalid_profile")?;
        Ok(())
    }
}

fn sdp_codec(codec: amaterasu_gamestream::sdp::VideoCodec) -> amaterasu_media::VideoCodec {
    match codec {
        amaterasu_gamestream::sdp::VideoCodec::H264 => amaterasu_media::VideoCodec::H264,
        amaterasu_gamestream::sdp::VideoCodec::Hevc => amaterasu_media::VideoCodec::Hevc,
        amaterasu_gamestream::sdp::VideoCodec::Av1 => amaterasu_media::VideoCodec::Av1,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NegotiationBounds {
    pub max_width: u32,
    pub max_height: u32,
    pub max_fps: u32,
    pub max_bitrate_kbps: u32,
    pub max_reference_frames: u32,
}

impl NegotiationBounds {
    fn validate(&self) -> Result<(), &'static str> {
        if !(16..=3840).contains(&self.max_width)
            || !(16..=2160).contains(&self.max_height)
            || !self.max_width.is_multiple_of(2)
            || !self.max_height.is_multiple_of(2)
            || !(1..=120).contains(&self.max_fps)
            || !(100..=100_000).contains(&self.max_bitrate_kbps)
            || self.max_reference_frames > 1
        {
            return Err("invalid_negotiation_bounds");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NegotiatedVideo {
    pub codec: amaterasu_media::VideoCodec,
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub bitrate_kbps: u32,
    pub max_reference_frames: u32,
}

impl NegotiatedVideo {
    pub fn validate(self) -> bool {
        (16..=3840).contains(&self.width)
            && (16..=2160).contains(&self.height)
            && self.width.is_multiple_of(2)
            && self.height.is_multiple_of(2)
            && (1..=120).contains(&self.fps)
            && (100..=100_000).contains(&self.bitrate_kbps)
            && self.bitrate_kbps.checked_mul(1_000).is_some()
            && self.max_reference_frames <= 1
    }
}

fn supported_color(color: ColorMode) -> bool {
    if cfg!(target_os = "linux") {
        matches!(
            color,
            ColorMode::Bt601Limited
                | ColorMode::Bt601Full
                | ColorMode::Bt709Limited
                | ColorMode::Bt709Full
        )
    } else {
        color == ColorMode::Bt709Limited
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VideoEncryptionPolicySnapshot {
    pub lan_mode: i64,
    pub wan_mode: i64,
}

#[derive(Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Open {
    pub operation_id: String,
    /// NVHTTP's nonce-bound RTSP operation, reused as the History session ID.
    #[serde(default)]
    pub history_activity_id: Option<String>,
    pub peer_ip: IpAddr,
    #[serde(default)]
    pub frame_limiter_settings: Option<serde_json::Value>,
    #[serde(default)]
    pub frame_limiter_executable_path: Option<String>,
    /// Frozen Launch identity for verifying a limiter before stream activation.
    #[serde(default)]
    pub app_id: Option<String>,
    #[serde(default)]
    pub catalog_revision: Option<u64>,
    /// Full display configuration, admitted only after Launch verifies its
    /// frozen policy source and authenticated operation binding.
    #[serde(default)]
    pub display_request: Option<serde_json::Value>,
    /// Sparse per-application display selection frozen by Launch preflight.
    #[serde(default)]
    pub application_display_settings: Option<serde_json::Value>,
    /// Resolved stream-time virtual-display policy, signed by Launch.
    #[serde(default)]
    pub virtual_display_intent: Option<VirtualDisplayIntent>,
    /// Private Launch-issued capability, bound to this Open operation.
    #[serde(default)]
    pub display_admission_token: Option<String>,
    #[serde(default)]
    pub application_operation_id: Option<String>,
    /// Frozen sparse source policy for exact readback; this alone never changes a display.
    #[serde(default)]
    pub display_policy_snapshot: Option<serde_json::Value>,
    #[serde(default)]
    pub video_encryption_policy: Option<VideoEncryptionPolicySnapshot>,
    /// Signed release ceilings for client-selected video ANNOUNCE values.
    /// Missing bounds preserve the legacy exact-profile contract.
    #[serde(default)]
    pub negotiation_bounds: Option<NegotiationBounds>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    #[serde(default)]
    pub video_port: u16,
    #[serde(default)]
    pub audio_port: u16,
    #[serde(default)]
    pub discover_peers: bool,
    pub key_hex: String,
    pub key_id: u32,
    pub connect_data: u32,
    #[serde(default = "default_ping_timeout_ms")]
    pub ping_timeout_ms: u32,
    #[serde(default = "default_stream_audio")]
    pub stream_audio: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuous_audio: Option<bool>,
    #[serde(default = "default_minimum_fps_target")]
    pub minimum_fps_target: f64,
    #[serde(default = "default_wgc_pacing_smoothing")]
    pub wgc_pacing_smoothing: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sw_preset: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sw_tune: Option<String>,
    #[serde(default = "default_min_threads")]
    pub min_threads: i32,
    #[serde(default = "default_qp")]
    pub qp: i32,
    #[serde(default)]
    pub nvenc_settings: amaterasu_module_sdk::NvencSettings,
    #[serde(default)]
    pub nvenc_spatial_aq: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter_pnp_id: Option<String>,
    #[serde(default)]
    pub capture_sink_without_routing: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub virtual_sink: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channels: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub back_button_timeout: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gamepad: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ds4_back_as_touchpad_click: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub motion_as_ds4: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub touchpad_as_ds4: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ds5_inputtino_randomize_mac: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyboard: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mouse: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_pen_touch: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub high_resolution_scrolling: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub always_send_scancodes: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_rightalt_to_key_win: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keybindings: Option<amaterasu_input_policy::KeyBindings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_repeat_delay: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_repeat_frequency: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bitrate_kbps: Option<u32>,
    pub capture: Capture,
    #[serde(default)]
    pub profile: Profile,
}
impl Open {
    pub fn display_request_sha256(&self) -> Option<String> {
        use sha2::{Digest, Sha256};
        let bytes = if let Some(intent) = &self.virtual_display_intent {
            serde_json::to_vec(intent).ok()?
        } else if let Some(request) = &self.display_request {
            serde_json::to_vec(request).ok()?
        } else {
            serde_json::to_vec(self.application_display_settings.as_ref()?).ok()?
        };
        let digest = Sha256::digest(bytes);
        Some(digest.iter().map(|byte| format!("{byte:02x}")).collect())
    }

    pub fn display_admission_required(&self) -> bool {
        self.display_request.is_some()
            || self.virtual_display_intent.is_some()
            || self.application_display_settings.is_some()
    }

    pub fn validate(&self, allow_remote: bool) -> Result<[u8; 16], &'static str> {
        if self.frame_limiter_settings.is_some() != self.frame_limiter_executable_path.is_some() {
            return Err("invalid_frame_limiter_snapshot");
        }
        match (
            &self.frame_limiter_settings,
            &self.app_id,
            self.catalog_revision,
        ) {
            (Some(_), Some(app_id), Some(_))
                if valid_name(app_id)
                    && self
                        .application_operation_id
                        .as_deref()
                        .is_some_and(valid_name) => {}
            (None, Some(app_id), Some(revision))
                if self.display_admission_required()
                    && valid_name(app_id)
                    && self
                        .display_policy_snapshot
                        .as_ref()
                        .is_some_and(|snapshot| {
                            snapshot["catalog_revision"].as_u64() == Some(revision)
                        }) => {}
            (None, None, None) => {}
            _ => return Err("frame_limiter_unattested"),
        }
        if self.frame_limiter_settings.is_some()
            && self.display_admission_required()
            && self
                .display_policy_snapshot
                .as_ref()
                .is_some_and(|snapshot| {
                    snapshot["catalog_revision"].as_u64() != self.catalog_revision
                })
        {
            return Err("frame_limiter_unattested");
        }
        if self
            .virtual_display_intent
            .as_ref()
            .is_some_and(|intent| intent.validate().is_err())
        {
            return Err("display_request_unattested");
        }
        if self
            .application_display_settings
            .as_ref()
            .is_some_and(|settings| !valid_application_display_settings(settings))
        {
            return Err("display_request_unattested");
        }
        if self.display_admission_required() {
            let (Some(token), Some(operation), Some(snapshot)) = (
                self.display_admission_token.as_deref(),
                self.application_operation_id.as_deref(),
                self.display_policy_snapshot.as_ref(),
            ) else {
                return Err("display_request_unattested");
            };
            let expected_intent = self
                .virtual_display_intent
                .as_ref()
                .map(serde_json::to_value)
                .transpose()
                .map_err(|_| "display_request_unattested")?;
            if self
                .display_request
                .as_ref()
                .is_some_and(|request| !valid_display_request(request))
                || !valid_display_policy_snapshot(snapshot)
                || token.len() != 64
                || !token
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                || !valid_name(operation)
                || snapshot.get("virtual_display_intent") != expected_intent.as_ref()
                || !application_display_settings_match_snapshot(self, snapshot)
            {
                return Err("display_request_unattested");
            }
        } else if self.display_admission_token.is_some()
            || (self.frame_limiter_settings.is_none() && self.application_operation_id.is_some())
            || self
                .display_policy_snapshot
                .as_ref()
                .is_some_and(|snapshot| snapshot.get("virtual_display_intent").is_some())
        {
            return Err("display_request_unattested");
        }
        if self
            .display_policy_snapshot
            .as_ref()
            .is_some_and(|snapshot| !valid_display_policy_snapshot(snapshot))
        {
            return Err("invalid_display_policy_snapshot");
        }
        if let Some(snapshot) = &self.frame_limiter_settings
            && !valid_frame_limiter_snapshot(snapshot, self.profile.fps)
        {
            return Err("invalid_frame_limiter_snapshot");
        }
        if self
            .frame_limiter_executable_path
            .as_deref()
            .is_some_and(|path| {
                path.trim().is_empty() || path.len() > 4096 || path.chars().any(char::is_control)
            })
        {
            return Err("invalid_executable_path");
        }
        if self.ping_timeout_ms > i32::MAX as u32 {
            return Err("invalid_ping_timeout");
        }
        if self.continuous_audio == Some(true) && !self.stream_audio {
            return Err("continuous_audio_requires_stream_audio");
        }
        self.validate_operation_id()?;
        self.validate_destination(allow_remote)?;
        self.validate_capture()?;
        self.validate_max_bitrate()?;
        self.profile.validate()?;
        self.nvenc_settings
            .validate()
            .map_err(|_| "invalid_nvenc_settings")?;
        if let Some(bounds) = self.negotiation_bounds {
            bounds.validate()?;
            let requested = self.effective_profile();
            if requested.width > bounds.max_width
                || requested.height > bounds.max_height
                || requested.fps > bounds.max_fps
                || requested.bitrate_kbps > bounds.max_bitrate_kbps
                || requested.max_reference_frames > bounds.max_reference_frames
            {
                return Err("profile_exceeds_negotiation_bounds");
            }
        }
        decode_key(&self.key_hex)
    }

    fn validate_max_bitrate(&self) -> Result<(), &'static str> {
        if self
            .max_bitrate_kbps
            .is_some_and(|maximum| maximum > 0 && maximum < 100)
        {
            return Err("invalid_max_bitrate");
        }
        Ok(())
    }

    fn encoder_bitrate_kbps(&self) -> u32 {
        self.max_bitrate_kbps
            .filter(|maximum| *maximum > 0)
            .map_or(self.profile.bitrate_kbps, |maximum| {
                self.profile.bitrate_kbps.min(maximum)
            })
    }

    pub(crate) fn effective_profile(&self) -> Profile {
        let mut profile = self.profile.clone();
        profile.bitrate_kbps = self.encoder_bitrate_kbps();
        profile
    }

    #[cfg(test)]
    pub(crate) fn matches_announce(&self, announce: &Announce) -> bool {
        self.negotiate_announce(announce).is_some()
    }

    pub(crate) fn negotiate_announce(&self, announce: &Announce) -> Option<NegotiatedVideo> {
        let channels = self.channels.unwrap_or(2);
        let profile = self.effective_profile();
        let audio_matches = if channels == 2 {
            profile.matches_audio(announce)
        } else {
            announce.audio.packet_duration_ms == profile.packet_ms
                && announce.encryption.audio == profile.encrypt_audio
                && announce.audio.channels == channels
                && announce.audio.channel_mask == audio_channel_mask(channels)
        };
        let video = NegotiatedVideo {
            codec: sdp_codec(announce.video.format.codec),
            width: announce.video.width,
            height: announce.video.height,
            fps: announce.video.fps,
            bitrate_kbps: announce.video.bitrate_kbps,
            max_reference_frames: announce.video.max_reference_frames,
        };
        let video_matches = if let Some(bounds) = self.negotiation_bounds {
            profile.offers(video.codec)
                && video.validate()
                && video.width <= bounds.max_width
                && video.height <= bounds.max_height
                && video.fps <= bounds.max_fps
                && video.bitrate_kbps <= bounds.max_bitrate_kbps
                && video.max_reference_frames <= bounds.max_reference_frames
                && supported_color(announce.video.color)
                && announce.encryption.video == profile.encrypt_video
        } else {
            profile.matches_video(announce)
        };
        if announce.video.format.bit_depth != 8
            || announce.video.format.dynamic_range != amaterasu_module_sdk::DynamicRange::Sdr
            || !video_matches
            || !audio_matches
            || !profile.matches_transport(announce)
            || (self.frame_limiter_settings.is_some() && video.fps != profile.fps)
        {
            return None;
        }
        Some(video)
    }

    fn validate_operation_id(&self) -> Result<(), &'static str> {
        if !valid_name(&self.operation_id) {
            return Err("invalid_operation_id");
        }
        Ok(())
    }

    fn validate_destination(&self, allow_remote: bool) -> Result<(), &'static str> {
        let invalid_ports = if self.discover_peers {
            self.video_port != 0 || self.audio_port != 0
        } else {
            self.video_port == 0 || self.audio_port == 0
        };
        if invalid_peer(self.peer_ip) || invalid_ports {
            return Err("invalid_peer");
        }
        if !allow_remote && !self.peer_ip.is_loopback() {
            return Err("remote_disabled");
        }
        Ok(())
    }

    fn validate_capture(&self) -> Result<(), &'static str> {
        self.capture.encoder.validate()?;
        amaterasu_module_sdk::validate_software_options(
            self.sw_preset.as_deref(),
            self.sw_tune.as_deref(),
        )?;
        if self
            .device_name
            .as_deref()
            .is_some_and(|name| !valid_name(name))
        {
            return Err("invalid_device_name");
        }
        if self
            .key_repeat_delay
            .is_some_and(|delay| delay > i32::MAX as u32)
            || self
                .key_repeat_frequency
                .is_some_and(|frequency| !frequency.is_finite() || frequency < 0.0)
        {
            return Err("invalid_input_policy_override");
        }
        if !valid_minimum_fps_target(self.minimum_fps_target) {
            return Err("invalid_minimum_fps_target");
        }
        if self
            .adapter_name
            .as_deref()
            .is_some_and(|name| name.len() > 1024 || name.chars().any(char::is_control))
            || self
                .adapter_pnp_id
                .as_deref()
                .is_some_and(|id| id.len() > 256 || id.chars().any(char::is_control))
            || self.adapter_pnp_id.as_deref().is_some_and(|id| {
                !id.is_empty() && self.adapter_name.as_deref().is_none_or(str::is_empty)
            })
        {
            return Err("invalid_adapter_selection");
        }
        if self.capture.constant_rate && self.capture.capture_provider != CaptureProvider::Wgc {
            return Err("constant_rate_requires_wgc");
        }
        if !valid_label(&self.capture.output, 512)
            || (!self.capture.audio_endpoint.is_empty()
                && !valid_label(&self.capture.audio_endpoint, 4096))
        {
            return Err("invalid_profile");
        }
        match (&self.virtual_sink, self.channels) {
            (None, None) if valid_label(&self.capture.audio_endpoint, 4096) => {}
            (None, _) => return Err("invalid_virtual_sink_channels"),
            (Some(selector), Some(channels))
                if selector.len() <= 4096
                    && !selector.chars().any(char::is_control)
                    && matches!(channels, 2 | 6 | 8)
                    && self.capture.audio_endpoint.is_empty()
                    && !self.capture_sink_without_routing => {}
            (Some(_), _) => return Err("invalid_virtual_sink_channels"),
        }
        if self.channels.is_some_and(|channels| channels != 2) {
            if !self.stream_audio {
                return Err("surround_requires_stream_audio");
            }
            let minimum = if self.channels == Some(6) {
                256000
            } else {
                512000
            };
            if self.profile.audio_bitrate < minimum {
                return Err("unsupported_surround_bitrate");
            }
            let packet_bytes = (u64::from(self.profile.audio_bitrate)
                * u64::from(self.profile.packet_ms))
            .div_ceil(8000);
            if packet_bytes > 1275 {
                return Err("unsupported_audio_packet");
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn prepare(&self, operation: &str, discovery: Option<&UdpDiscovery>) -> serde_json::Value {
        self.prepare_with_media_binds(operation, discovery, None)
    }

    pub fn prepare_with_media_binds(
        &self,
        operation: &str,
        discovery: Option<&UdpDiscovery>,
        binds: Option<MediaBinds>,
    ) -> serde_json::Value {
        let mut payload = serde_json::json!({
            "action": "prepare",
            "operation_id": operation,
            "peer_ip": self.peer_ip,
            "key_hex": self.key_hex,
            "key_id": self.key_id,
            "connect_data": self.connect_data,
            "ping_timeout_ms": self.ping_timeout_ms,
            "stream_audio": self.stream_audio,
            "video": {
                "packet_size": self.profile.packet_size,
                "fec_percentage": self.profile.fec_percentage,
                "min_parity_shards": self.profile.min_parity_shards,
                "max_fec_blocks": self.profile.max_fec_blocks,
                "max_batch_size_kb": self.profile.effective_video_max_batch_size_kb(),
            },
            "audio": {
                "packet_ms": self.profile.packet_ms,
                "bitrate": self.profile.audio_bitrate,
            },
            "encrypt_video": self.profile.encrypt_video,
            "encrypt_audio": self.profile.encrypt_audio,
            "permit_legacy_audio_iv_wrap": self.profile.permit_legacy_audio_iv_wrap,
        });
        if !self.profile.codecs.is_empty() {
            payload["video"]["codecs"] = serde_json::json!(self.profile.codecs);
        } else if !self.profile.codec.is_default() {
            payload["video"]["codec"] = serde_json::json!(self.profile.codec);
        }
        if let Some(channels @ (6 | 8)) = self.channels {
            payload["audio"]["channels"] = serde_json::json!(channels);
            payload["audio"]["channel_mask"] = serde_json::json!(audio_channel_mask(channels));
            payload["audio"]["layout"] =
                serde_json::json!(if channels == 6 { "5.1" } else { "7.1" });
        }
        if let Some(discovery) = discovery {
            payload["discovery"] = serde_json::json!({
                "audio_ping_payload": discovery.audio_ping_payload,
                "video_ping_payload": discovery.video_ping_payload,
            });
        } else {
            payload["video_port"] = self.video_port.into();
            payload["audio_port"] = self.audio_port.into();
        }
        if let Some(binds) = binds {
            payload["video_bind"] = serde_json::json!(binds.video);
            payload["control_bind"] = serde_json::json!(binds.control);
            payload["audio_bind"] = serde_json::json!(binds.audio);
        }
        if let Some(policy) = self.video_encryption_policy {
            payload["video_encryption_policy"] = serde_json::json!({
                "lan_mode": policy.lan_mode,
                "wan_mode": policy.wan_mode,
            });
        }
        if let Some(snapshot) = &self.frame_limiter_settings {
            payload["frame_limiter_settings"] = snapshot.clone();
        }
        if let Some(path) = &self.frame_limiter_executable_path {
            payload["frame_limiter_executable_path"] = serde_json::json!(path);
        }
        if let Some(request) = &self.display_request {
            payload["display_request"] = request.clone();
        }
        if let Some(intent) = &self.virtual_display_intent {
            payload["virtual_display_intent"] = serde_json::json!(intent);
        }
        if let Some(activity_id) = &self.history_activity_id {
            payload["history_activity_id"] = serde_json::json!(activity_id);
            payload["rtsp_operation_id"] = serde_json::json!(self.operation_id);
        }
        payload
    }

    pub fn arm(&self, session: u64) -> serde_json::Value {
        let mut payload = serde_json::json!({
            "action": "start_when_authenticated",
            "session": session,
            "configuration": {
                "capture_provider": self.capture.capture_provider,
                "constant_rate": self.capture.constant_rate,
                "minimum_fps_target": self.minimum_fps_target,
                "wgc_pacing_smoothing": self.wgc_pacing_smoothing,
                "output": self.capture.output,
                "encoder": self.capture.encoder,
                "audio_endpoint": self.capture.audio_endpoint,
                "host_audio_enabled": self.capture.host_audio_enabled,
                "capture_sink_without_routing": self.capture_sink_without_routing,
                "virtual_sink": self.virtual_sink,
                "channels": self.channels,
                "back_button_timeout": self.back_button_timeout,
                "controller": self.controller,
                "gamepad": self.gamepad,
                "ds4_back_as_touchpad_click": self.ds4_back_as_touchpad_click,
                "motion_as_ds4": self.motion_as_ds4,
                "touchpad_as_ds4": self.touchpad_as_ds4,
                "ds5_inputtino_randomize_mac": self.ds5_inputtino_randomize_mac,
                "keyboard": self.keyboard,
                "mouse": self.mouse,
                "native_pen_touch": self.native_pen_touch,
                "high_resolution_scrolling": self.high_resolution_scrolling,
                "always_send_scancodes": self.always_send_scancodes,
                "key_rightalt_to_key_win": self.key_rightalt_to_key_win,
                "keybindings": self.keybindings,
                "key_repeat_delay": self.key_repeat_delay,
                "key_repeat_frequency": self.key_repeat_frequency,
                "device_name": self.device_name,
                "configuration": {
                    "width": self.profile.width,
                    "height": self.profile.height,
                    "fps": self.profile.fps,
                    "bitrate": self.encoder_bitrate_kbps() * 1000,
                    "min_threads": self.min_threads,
                    "qp": self.qp,
                    "adapter_name": self.adapter_name,
                    "adapter_pnp_id": self.adapter_pnp_id,
                    "max_reference_frames": self.profile.max_reference_frames,
                    "nvenc_settings": self.nvenc_settings,
                    "nvenc_spatial_aq": self.nvenc_spatial_aq,
                },
            },
        });
        if let Some(preset) = &self.sw_preset {
            payload["configuration"]["configuration"]["sw_preset"] = serde_json::json!(preset);
        }
        if let Some(tune) = &self.sw_tune {
            payload["configuration"]["configuration"]["sw_tune"] = serde_json::json!(tune);
        }
        if let Some(continuous_audio) = self.continuous_audio {
            payload["configuration"]["continuous_audio"] = serde_json::json!(continuous_audio);
        }
        payload
    }

    pub(crate) fn arm_with_negotiation(
        &self,
        session: u64,
        encryption: EncryptionSnapshot,
        slices_per_frame: i32,
        video_stream_format: amaterasu_module_sdk::VideoStreamFormat,
        client_feature_flags: u32,
    ) -> serde_json::Value {
        let mut payload = self.arm(session);
        payload["configuration"]["encrypt_video"] = serde_json::json!(encryption.video);
        payload["configuration"]["encrypt_audio"] = serde_json::json!(encryption.audio);
        payload["configuration"]["configuration"]["slices_per_frame"] =
            serde_json::json!(slices_per_frame);
        payload["configuration"]["configuration"]["video_stream_format"] =
            serde_json::json!(video_stream_format);
        payload["configuration"]["client_feature_flags"] = serde_json::json!(client_feature_flags);
        payload
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DisplayTopology {
    displays: Vec<DisplayMode>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DisplayMode {
    id: String,
    width: u32,
    height: u32,
    refresh: DisplayRefresh,
    #[serde(rename = "x")]
    _x: i32,
    #[serde(rename = "y")]
    _y: i32,
    rotation: Option<String>,
    #[serde(rename = "hdr_enabled")]
    _hdr_enabled: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DisplayRefresh {
    numerator: u32,
    denominator: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DisplayModePolicy {
    display_id: String,
    #[serde(rename = "remapping")]
    _remapping: DisplayRemapping,
    #[serde(rename = "context")]
    _context: DisplayModeContext,
    resolution_option: Option<String>,
    #[serde(rename = "manual_resolution")]
    _manual_resolution: Option<String>,
    refresh_rate_option: Option<String>,
    #[serde(rename = "manual_refresh_rate")]
    _manual_refresh_rate: Option<String>,
    hdr_option: Option<String>,
    configuration_option: Option<String>,
    #[serde(rename = "effective_client_hdr_request")]
    _effective_client_hdr_request: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DisplayRemapping {
    #[serde(default, rename = "mixed")]
    _mixed: Vec<DisplayRemappingEntry>,
    #[serde(default, rename = "resolution_only")]
    _resolution_only: Vec<DisplayRemappingEntry>,
    #[serde(default, rename = "refresh_rate_only")]
    _refresh_rate_only: Vec<DisplayRemappingEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DisplayRemappingEntry {
    #[serde(default, rename = "requested_resolution")]
    _requested_resolution: String,
    #[serde(default, rename = "requested_fps")]
    _requested_fps: String,
    #[serde(default, rename = "final_resolution")]
    _final_resolution: String,
    #[serde(default, rename = "final_refresh_rate")]
    _final_refresh_rate: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DisplayModeContext {
    #[serde(rename = "resolution_is_automatic")]
    _resolution_is_automatic: bool,
    #[serde(rename = "refresh_rate_is_automatic")]
    _refresh_rate_is_automatic: bool,
    #[serde(rename = "client_display_mode_override")]
    _client_display_mode_override: bool,
    #[serde(rename = "optimize_game_settings")]
    _optimize_game_settings: bool,
}

fn valid_display_request(request: &serde_json::Value) -> bool {
    let Some(fields) = request.as_object().filter(|fields| fields.len() == 3) else {
        return false;
    };
    if !fields
        .get("expected_topology_revision")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|revision| {
            revision.len() == 32
                && revision
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
    {
        return false;
    }
    let Ok(topology) = serde_json::from_value::<DisplayTopology>(request["configuration"].clone())
    else {
        return false;
    };
    if topology.displays.is_empty() || topology.displays.len() > 16 {
        return false;
    }
    let mut targets = std::collections::BTreeSet::new();
    for display in &topology.displays {
        if display.id.is_empty()
            || display.id.len() > 4096
            || display.width == 0
            || display.height == 0
            || display.refresh.numerator == 0
            || display.refresh.denominator == 0
            || display.rotation.as_deref().is_some_and(|rotation| {
                !matches!(
                    rotation,
                    "identity" | "rotate90" | "rotate180" | "rotate270"
                )
            })
            || !targets.insert(display.id.to_ascii_lowercase())
        {
            return false;
        }
    }
    let policies: Vec<&serde_json::Value> =
        match (fields.get("mode_policy"), fields.get("mode_policies")) {
            (Some(policy), None) => vec![policy],
            (None, Some(serde_json::Value::Array(policies))) if policies.len() == targets.len() => {
                policies.iter().collect()
            }
            _ => return false,
        };
    let mut policy_targets = std::collections::BTreeSet::new();
    for raw in policies {
        let Ok(policy) = serde_json::from_value::<DisplayModePolicy>(raw.clone()) else {
            return false;
        };
        let id = policy.display_id.to_ascii_lowercase();
        if !targets.contains(&id)
            || !policy_targets.insert(id)
            || (fields.get("mode_policies").is_some() && raw.get("configuration_option").is_some())
            || (targets.len() > 1
                && fields.get("mode_policy").is_some()
                && policy.configuration_option.is_none())
            || policy
                .resolution_option
                .as_deref()
                .is_some_and(|option| !matches!(option, "auto" | "disabled" | "manual"))
            || policy.refresh_rate_option.as_deref().is_some_and(|option| {
                !matches!(option, "auto" | "disabled" | "manual" | "prefer_highest")
            })
            || policy
                .hdr_option
                .as_deref()
                .is_some_and(|option| !matches!(option, "auto" | "disabled"))
            || policy
                .configuration_option
                .as_deref()
                .is_some_and(|option| {
                    !matches!(
                        option,
                        "disabled"
                            | "verify_only"
                            | "ensure_active"
                            | "ensure_primary"
                            | "ensure_only_display"
                    )
                })
        {
            return false;
        }
    }
    true
}

fn valid_application_display_settings(value: &serde_json::Value) -> bool {
    let Some(fields) = value.as_object() else {
        return false;
    };
    fields.len() <= 4
        && fields.keys().all(|key| {
            matches!(
                key.as_str(),
                "display_output"
                    | "virtual_screen"
                    | "virtual_display_mode"
                    | "virtual_display_layout"
            )
        })
        && value.get("display_output").is_none_or(|output| {
            output.as_str().is_some_and(|output| {
                output.len() <= 1_024 && !output.chars().any(char::is_control)
            })
        })
        && value
            .get("virtual_screen")
            .is_none_or(serde_json::Value::is_boolean)
        && value
            .get("virtual_display_mode")
            .is_none_or(|mode| matches!(mode.as_str(), Some("disabled" | "per_client" | "shared")))
        && value.get("virtual_display_layout").is_none_or(|layout| {
            matches!(
                layout.as_str(),
                Some(
                    "exclusive"
                        | "extended"
                        | "extended_primary"
                        | "extended_isolated"
                        | "extended_primary_isolated"
                )
            )
        })
}

fn application_display_settings_match_snapshot(open: &Open, snapshot: &serde_json::Value) -> bool {
    match (
        open.application_display_settings.as_ref(),
        snapshot.get("application_display_settings"),
    ) {
        (Some(expected), Some(actual)) => expected == actual,
        (Some(_), None) => false,
        (None, Some(actual)) => actual.is_null(),
        (None, None) => true,
    }
}

fn valid_display_policy_snapshot(snapshot: &serde_json::Value) -> bool {
    let Some(fields) = snapshot.as_object() else {
        return false;
    };
    let Some(application) = snapshot["application_overrides"].as_object() else {
        return false;
    };
    let Some(client) = snapshot["client_overrides"].as_object() else {
        return false;
    };
    let Some(effective) = snapshot["effective_overrides"].as_object() else {
        return false;
    };
    let Some(certificate_id) = snapshot["certificate_id"].as_str() else {
        return false;
    };
    let has_intent = fields.contains_key("virtual_display_intent");
    let has_application_settings = fields.contains_key("application_display_settings");
    let base_field_count = fields
        .len()
        .saturating_sub(usize::from(has_intent))
        .saturating_sub(usize::from(has_application_settings));
    let intent_is_valid = snapshot.get("virtual_display_intent").is_none_or(|value| {
        serde_json::from_value::<VirtualDisplayIntent>(value.clone())
            .is_ok_and(|intent| intent.validate().is_ok())
    });
    let application_settings_are_valid = snapshot
        .get("application_display_settings")
        .is_none_or(|value| value.is_null() || valid_application_display_settings(value));
    if !matches!(base_field_count, 5 | 7)
        || !intent_is_valid
        || !application_settings_are_valid
        || fields.keys().any(|key| {
            !matches!(
                key.as_str(),
                "global_revision"
                    | "global_overrides"
                    | "catalog_revision"
                    | "certificate_id"
                    | "application_overrides"
                    | "client_overrides"
                    | "effective_overrides"
                    | "application_display_settings"
                    | "virtual_display_intent"
            )
        })
        || (base_field_count == 7
            && (snapshot
                .get("global_revision")
                .is_none_or(|revision| !revision.is_null() && !revision.is_u64())
                || !snapshot["global_overrides"].is_object()))
        || snapshot["catalog_revision"].as_u64().is_none()
        || certificate_id.len() != 64
        || !certificate_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        || application
            .keys()
            .chain(client.keys())
            .chain(
                snapshot["global_overrides"]
                    .as_object()
                    .into_iter()
                    .flat_map(|overrides| overrides.keys()),
            )
            .any(|key| {
                !matches!(
                    key.as_str(),
                    "adapter_name"
                        | "adapter_pnp_id"
                        | "virtual_display_mode"
                        | "virtual_display_layout"
                        | "dd_mode_remapping"
                        | "dd_resolution_option"
                        | "dd_manual_resolution"
                        | "dd_refresh_rate_option"
                        | "dd_manual_refresh_rate"
                        | "dd_hdr_option"
                        | "dd_configuration_option"
                        | "dd_hdr_request_override"
                        | "dd_config_revert_delay"
                        | "dd_config_revert_on_disconnect"
                        | "dd_paused_virtual_display_timeout_secs"
                        | "dd_always_restore_from_golden"
                        | "dd_display_helper_engine"
                        | "dd_snapshot_restore_hotkey"
                        | "dd_snapshot_restore_hotkey_modifiers"
                        | "dd_use_sunshine_virtual_display_driver"
                        | "dd_activate_virtual_display"
                        | "dd_virtual_display_scale"
                        | "dd_virtual_display_permanent_count"
                        | "virtual_display_outputs"
                        | "dd_snapshot_exclude_devices"
                        | "dd_wa_dummy_plug_hdr10"
                        | "dd_wa_hdr_toggle"
                        | "dd_wa_hdr_toggle_delay"
                        | "vulkan_hdr_layer"
                        | "wayland_hdr_compatibility"
                )
            })
    {
        return false;
    }
    let mut resolved = snapshot["global_overrides"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    resolved.extend(application.clone());
    resolved.extend(client.clone());
    &resolved == effective
}

fn valid_frame_limiter_snapshot(snapshot: &serde_json::Value, stream_fps: u32) -> bool {
    let Some(fields) = snapshot.as_object() else {
        return false;
    };
    let Some(settings) = snapshot["settings"].as_object() else {
        return false;
    };
    let Some(requested_fps) = stream_fps.checked_mul(1_000) else {
        return false;
    };
    if fields.len() != 9
        || settings.len() != 11
        || snapshot["version"] != 1
        || snapshot["requested_stream_fps_millihz"] != requested_fps
        || !matches!(settings["frame_limiter_enable"], serde_json::Value::Bool(_))
        || settings["frame_limiter_fps_limit_millihz"]
            .as_u64()
            .is_none_or(|fps| fps > 1_000_000)
        || !matches!(
            settings["frame_limiter_disable_vsync"],
            serde_json::Value::Bool(_)
        )
        || !matches!(
            settings["rtss_allow_virtual_display_override"],
            serde_json::Value::Bool(_)
        )
        || !matches!(
            settings["mangohud_always_show_graph"],
            serde_json::Value::Bool(_)
        )
        || !matches!(
            settings["frame_limiter_provider"].as_str(),
            Some(
                "auto"
                    | "rtss"
                    | "nvidia-control-panel"
                    | "mangohud"
                    | "proton"
                    | "mangohud-proton"
                    | "none"
            )
        )
        || !matches!(
            settings["frame_limiter_auto_virtual_framegen"].as_str(),
            Some("enabled" | "vrr" | "legacy" | "disabled")
        )
        || !matches!(
            settings["rtss_frame_limit_type"].as_str(),
            Some("async" | "front edge sync" | "back edge sync" | "nvidia reflex")
        )
        || !matches!(
            settings["mangohud_preset"].as_str(),
            Some("custom" | "1" | "2" | "3" | "4")
        )
        || !matches!(
            settings["mangohud_limiter_method"].as_str(),
            Some("early" | "late")
        )
        || settings["rtss_install_path"]
            .as_str()
            .is_none_or(|path| path.len() > 4096 || path.chars().any(char::is_control))
    {
        return false;
    }
    for rate in [
        "client_display_mode_override_millihz",
        "lossless_scaling_limit_millihz",
    ] {
        if !fields.contains_key(rate)
            || (!snapshot[rate].is_null()
                && snapshot[rate].as_u64().is_none_or(|rate| rate > 1_000_000))
        {
            return false;
        }
    }
    for flag in [
        "virtual_display_active",
        "physical_framegen_capture",
        "rtss_frame_limit_type_explicit_override",
    ] {
        if !fields.contains_key(flag) || (!snapshot[flag].is_null() && !snapshot[flag].is_boolean())
        {
            return false;
        }
    }
    fields.contains_key("game_frame_generation_mode")
        && matches!(
            snapshot["game_frame_generation_mode"].as_str(),
            None | Some(
                "none" | "lossless-scaling" | "game-provided" | "nvidia-smooth-motion" | "other"
            )
        )
        && (snapshot["game_frame_generation_mode"].is_null()
            || snapshot["game_frame_generation_mode"].is_string())
}

fn default_stream_audio() -> bool {
    true
}
fn default_ping_timeout_ms() -> u32 {
    10_000
}

fn default_minimum_fps_target() -> f64 {
    20.0
}

fn default_wgc_pacing_smoothing() -> bool {
    true
}

fn default_min_threads() -> i32 {
    2
}

fn default_qp() -> i32 {
    28
}

fn valid_minimum_fps_target(value: f64) -> bool {
    value.is_finite() && (0.0..=1000.0).contains(&value)
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Open(Box<Open>),
    NetworkConfigure {
        port: u16,
        #[serde(default)]
        address_family: Option<AddressFamily>,
        #[serde(default)]
        bind_address: Option<String>,
    },
    Close {
        ticket: u64,
    },
    Status {
        ticket: Option<u64>,
    },
    Lookup {
        operation_id: String,
    },
}

pub fn valid_name(value: &str) -> bool {
    valid_label(value, 128)
}
fn valid_label(value: &str, limit: usize) -> bool {
    !value.is_empty() && value.len() <= limit && !value.chars().any(char::is_control)
}

fn invalid_peer(address: IpAddr) -> bool {
    address.is_unspecified()
        || address.is_multicast()
        || address == IpAddr::V4(Ipv4Addr::BROADCAST)
        || is_ipv4_mapped(address)
}

fn invalid_bind_address(address: IpAddr) -> bool {
    address.is_unspecified()
        || address.is_multicast()
        || address == IpAddr::V4(Ipv4Addr::BROADCAST)
        || is_ipv4_mapped(address)
}

fn is_ipv4_mapped(address: IpAddr) -> bool {
    matches!(address, IpAddr::V6(address) if address.to_ipv4_mapped().is_some())
}

fn decode_key(value: &str) -> Result<[u8; 16], &'static str> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid_key");
    }
    let mut key = [0; 16];
    for (index, byte) in key.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| "invalid_key")?;
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use amaterasu_gamestream::sdp::parse_announce;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};

    const PRIMARY_ANNOUNCE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/moonlight-h264.sdp"
    ));

    fn open_json() -> Value {
        json!({
            "operation_id": "launch-one",
            "peer_ip": "127.0.0.1",
            "video_port": 47998,
            "audio_port": 48000,
            "key_hex": "00112233445566778899aabbccddeeff",
            "key_id": 7,
            "connect_data": 11,
            "capture": {
                "capture_provider": "dxgi",
                "output": "display-one",
                "encoder": 0,
                "audio_endpoint": "default"
            }
        })
    }

    fn open() -> Open {
        serde_json::from_value(open_json()).unwrap()
    }

    #[test]
    fn per_application_settings_require_and_match_signed_admission() {
        let settings = json!({
            "display_output":"DP-1",
            "virtual_screen":false,
            "virtual_display_mode":"disabled",
            "virtual_display_layout":"extended_primary"
        });
        let mut input = open_json();
        input["app_id"] = json!("game");
        input["catalog_revision"] = json!(7);
        input["application_operation_id"] = json!("launch-one");
        input["display_admission_token"] = json!("ab".repeat(32));
        input["application_display_settings"] = settings.clone();
        input["display_policy_snapshot"] = json!({
            "global_revision":1,
            "global_overrides":{},
            "catalog_revision":7,
            "certificate_id":"cd".repeat(32),
            "application_overrides":{},
            "application_display_settings":settings,
            "client_overrides":{},
            "effective_overrides":{}
        });

        let accepted: Open = serde_json::from_value(input.clone()).unwrap();
        accepted.validate(false).unwrap();
        assert!(accepted.display_admission_required());
        let expected_hash =
            Sha256::digest(serde_json::to_vec(&accepted.application_display_settings).unwrap());
        assert_eq!(
            accepted.display_request_sha256().unwrap(),
            expected_hash
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );

        let mut mismatched = input.clone();
        mismatched["display_policy_snapshot"]["application_display_settings"]["virtual_screen"] =
            json!(true);
        assert_eq!(
            serde_json::from_value::<Open>(mismatched)
                .unwrap()
                .validate(false),
            Err("display_request_unattested")
        );
        for invalid in [
            json!({"virtual_screen":"false"}),
            json!({"virtual_display_mode":"automatic"}),
            json!({"virtual_display_layout":"portrait"}),
            json!({"unexpected":true}),
        ] {
            let mut malformed = input.clone();
            malformed["application_display_settings"] = invalid;
            assert_eq!(
                serde_json::from_value::<Open>(malformed)
                    .unwrap()
                    .validate(false),
                Err("display_request_unattested")
            );
        }
    }

    #[test]
    fn complete_display_request_is_rejected_even_with_a_policy_snapshot() {
        let mut input = open_json();
        let display_request = json!({
            "expected_topology_revision":"aa".repeat(16),
            "configuration":{"displays":[
                {"id":"monitor.one","width":1920,"height":1080,
                 "refresh":{"numerator":60,"denominator":1},"x":0,"y":0},
                {"id":"monitor.two","width":1280,"height":720,
                 "refresh":{"numerator":60,"denominator":1},"x":1920,"y":0}
            ]},
            "mode_policies":[
                {"display_id":"monitor.one","remapping":{},"context":{}},
                {"display_id":"monitor.two","remapping":{},"context":{}}
            ]
        });
        input["display_request"] = display_request;
        let request: Open = serde_json::from_value(input.clone()).unwrap();
        assert_eq!(request.validate(false), Err("display_request_unattested"));
        input["display_policy_snapshot"] = json!({
            "catalog_revision":7,
            "certificate_id":"ab".repeat(32),
            "application_overrides":{},
            "client_overrides":{},
            "effective_overrides":{}
        });
        let request: Open = serde_json::from_value(input).unwrap();
        assert_eq!(request.validate(false), Err("display_request_unattested"));
        assert!(
            open()
                .prepare("prepare", None)
                .get("display_request")
                .is_none()
        );
    }

    #[test]
    fn attested_display_request_keeps_exact_modes_and_rejects_incomplete_policy() {
        let mut input = open_json();
        let request = json!({
            "expected_topology_revision":"aa".repeat(16),
            "configuration":{"displays":[
                {"id":"one","width":1920,"height":1080,"refresh":{"numerator":60,"denominator":1},"x":0,"y":0},
                {"id":"two","width":1280,"height":720,"refresh":{"numerator":60,"denominator":1},"x":1920,"y":0}
            ]},
            "mode_policies":[
                {"display_id":"one","remapping":{},"context":{"resolution_is_automatic":true,"refresh_rate_is_automatic":true,"client_display_mode_override":false,"optimize_game_settings":false}},
                {"display_id":"two","remapping":{},"context":{"resolution_is_automatic":true,"refresh_rate_is_automatic":true,"client_display_mode_override":false,"optimize_game_settings":false}}
            ]
        });
        input["display_request"] = request.clone();
        input["display_admission_token"] = json!("ab".repeat(32));
        input["application_operation_id"] = json!("launch-one");
        input["display_policy_snapshot"] = json!({
            "global_revision":1,"global_overrides":{},"catalog_revision":0,
            "certificate_id":"cd".repeat(32),"application_overrides":{},
            "client_overrides":{},"effective_overrides":{}
        });
        let selected: Open = serde_json::from_value(input.clone()).unwrap();
        selected.validate(false).unwrap();
        assert_eq!(
            selected.prepare("prepare", None)["display_request"],
            request
        );
        let original_digest = selected.display_request_sha256().unwrap();
        assert_eq!(original_digest.len(), 64);
        for option in [
            "disabled",
            "verify_only",
            "ensure_active",
            "ensure_primary",
            "ensure_only_display",
        ] {
            let mut rejected = input.clone();
            rejected["display_request"]["mode_policies"][0]["configuration_option"] = json!(option);
            assert_eq!(
                serde_json::from_value::<Open>(rejected)
                    .unwrap()
                    .validate(false),
                Err("display_request_unattested")
            );
        }
        for invalid in [
            Value::Null,
            json!("ensure_everything"),
            json!("Ensure_Active"),
            json!(7),
        ] {
            let mut malformed = input.clone();
            malformed["display_request"]["mode_policies"][0]["configuration_option"] = invalid;
            let malformed: Open = serde_json::from_value(malformed).unwrap();
            assert_eq!(malformed.validate(false), Err("display_request_unattested"));
        }

        for invalid in [
            json!(null),
            json!("AA".repeat(16)),
            json!("aa".repeat(15)),
            json!("gg".repeat(16)),
        ] {
            let mut malformed = input.clone();
            malformed["display_request"]["expected_topology_revision"] = invalid;
            let malformed: Open = serde_json::from_value(malformed).unwrap();
            assert_eq!(malformed.validate(false), Err("display_request_unattested"));
        }
        let mut missing = input.clone();
        missing["display_request"]
            .as_object_mut()
            .unwrap()
            .remove("expected_topology_revision");
        let missing: Open = serde_json::from_value(missing).unwrap();
        assert_eq!(missing.validate(false), Err("display_request_unattested"));

        let mut changed = input.clone();
        changed["display_request"]["expected_topology_revision"] = json!("bb".repeat(16));
        let changed: Open = serde_json::from_value(changed).unwrap();
        changed.validate(false).unwrap();
        assert_ne!(changed.display_request_sha256().unwrap(), original_digest);
        assert_eq!(
            changed.prepare("prepare", None)["display_request"]["expected_topology_revision"],
            "bb".repeat(16)
        );
        let mut extra = input.clone();
        extra["display_request"]["unexpected"] = json!(true);
        let extra: Open = serde_json::from_value(extra).unwrap();
        assert_eq!(extra.validate(false), Err("display_request_unattested"));

        input["display_request"]["mode_policies"]
            .as_array_mut()
            .unwrap()
            .pop();
        let incomplete: Open = serde_json::from_value(input.clone()).unwrap();
        assert_eq!(
            incomplete.validate(false),
            Err("display_request_unattested")
        );
        input["display_request"] = request;
        input["display_request"]["configuration"]["displays"][0]["unexpected"] = json!(true);
        let malformed: Open = serde_json::from_value(input).unwrap();
        assert_eq!(malformed.validate(false), Err("display_request_unattested"));
    }

    #[test]
    fn singular_policy_keeps_full_multimonitor_topology() {
        let mut input = open_json();
        let full_request = json!({
            "expected_topology_revision":"aa".repeat(16),
            "configuration":{"displays":[
                {"id":"one","width":1920,"height":1080,"refresh":{"numerator":60,"denominator":1},"x":0,"y":0},
                {"id":"two","width":1280,"height":720,"refresh":{"numerator":60,"denominator":1},"x":1920,"y":0}
            ]},
            "mode_policy":{"display_id":"two","configuration_option":"ensure_only_display",
                "remapping":{},"context":{"resolution_is_automatic":true,
                    "refresh_rate_is_automatic":true,"client_display_mode_override":false,
                    "optimize_game_settings":false}}
        });
        input["display_request"] = full_request.clone();
        input["display_admission_token"] = json!("ab".repeat(32));
        input["application_operation_id"] = json!("launch-one");
        input["display_policy_snapshot"] = json!({
            "global_revision":1,"global_overrides":{},"catalog_revision":0,
            "certificate_id":"cd".repeat(32),"application_overrides":{},
            "client_overrides":{},"effective_overrides":{}
        });
        let accepted: Open = serde_json::from_value(input.clone()).unwrap();
        accepted.validate(false).unwrap();
        assert_eq!(
            accepted.prepare("prepare", None)["display_request"],
            full_request
        );
        let selected_digest = accepted.display_request_sha256().unwrap();

        let mut invalid = input.clone();
        invalid["display_request"]["mode_policy"]["display_id"] = json!("missing");
        let invalid: Open = serde_json::from_value(invalid).unwrap();
        assert_eq!(invalid.validate(false), Err("display_request_unattested"));
        for missing in [None, Some(Value::Null)] {
            let mut invalid = input.clone();
            if let Some(value) = missing {
                invalid["display_request"]["mode_policy"]["configuration_option"] = value;
            } else {
                invalid["display_request"]["mode_policy"]
                    .as_object_mut()
                    .unwrap()
                    .remove("configuration_option");
            }
            let invalid: Open = serde_json::from_value(invalid).unwrap();
            assert_eq!(invalid.validate(false), Err("display_request_unattested"));
        }
        for option in [
            "disabled",
            "verify_only",
            "ensure_active",
            "ensure_primary",
            "ensure_only_display",
        ] {
            let mut supported = input.clone();
            supported["display_request"]["mode_policy"]["configuration_option"] = json!(option);
            serde_json::from_value::<Open>(supported)
                .unwrap()
                .validate(false)
                .unwrap();
        }
        let mut changed = input.clone();
        changed["display_request"]["mode_policy"]["display_id"] = json!("one");
        let changed: Open = serde_json::from_value(changed).unwrap();
        changed.validate(false).unwrap();
        assert_ne!(changed.display_request_sha256().unwrap(), selected_digest);

        let mut single_target = input;
        single_target["display_request"]["configuration"]["displays"] =
            json!([single_target["display_request"]["configuration"]["displays"][1].clone()]);
        for option in [
            "disabled",
            "verify_only",
            "ensure_active",
            "ensure_primary",
            "ensure_only_display",
        ] {
            single_target["display_request"]["mode_policy"]["configuration_option"] = json!(option);
            serde_json::from_value::<Open>(single_target.clone())
                .unwrap()
                .validate(false)
                .unwrap();
        }
    }

    #[test]
    fn sparse_display_policy_snapshot_requires_exact_client_precedence() {
        let mut input = open_json();
        input["display_policy_snapshot"] = json!({
            "catalog_revision":7,
            "certificate_id":"ab".repeat(32),
            "application_overrides":{"dd_refresh_rate_option":"manual"},
            "client_overrides":{"dd_refresh_rate_option":"disabled"},
            "effective_overrides":{"dd_refresh_rate_option":"disabled"}
        });
        let selected: Open = serde_json::from_value(input.clone()).unwrap();
        selected.validate(false).unwrap();
        assert!(
            selected
                .prepare("prepare", None)
                .get("display_request")
                .is_none()
        );

        input["display_policy_snapshot"]["effective_overrides"]["dd_refresh_rate_option"] =
            json!("manual");
        let forged: Open = serde_json::from_value(input).unwrap();
        assert_eq!(
            forged.validate(false),
            Err("invalid_display_policy_snapshot")
        );
    }

    #[test]
    fn incomplete_or_ambiguous_display_request_is_also_rejected() {
        let mut input = open_json();
        for display_request in [
            json!({"configuration":{"displays":[]},"mode_policies":[]}),
            json!({"configuration":{"displays":[{"id":"one"}]},
                   "mode_policy":{"display_id":"other","remapping":{},"context":{}}}),
            json!({"configuration":{"displays":[{"id":"one"}]},
                   "mode_policy":{"display_id":"one","remapping":{},"context":{}},
                   "mode_policies":[]}),
        ] {
            input["display_request"] = display_request;
            let request: Open = serde_json::from_value(input.clone()).unwrap();
            assert_eq!(request.validate(false), Err("display_request_unattested"));
        }
    }

    #[test]
    fn ping_timeout_reaches_stream_preparation_with_reference_bounds() {
        let defaulted = open();
        assert_eq!(defaulted.ping_timeout_ms, 10_000);
        assert_eq!(
            defaulted.prepare("default", None)["ping_timeout_ms"],
            10_000
        );

        for selected in [0, 250, i32::MAX as u32] {
            let mut value = open_json();
            value["ping_timeout_ms"] = json!(selected);
            let request: Open = serde_json::from_value(value).unwrap();
            assert!(request.validate(false).is_ok());
            assert_eq!(
                request.prepare("selected", None)["ping_timeout_ms"],
                selected
            );
        }
        let mut invalid = open_json();
        invalid["ping_timeout_ms"] = json!(i32::MAX as u64 + 1);
        let invalid: Open = serde_json::from_value(invalid).unwrap();
        assert_eq!(invalid.validate(false), Err("invalid_ping_timeout"));
    }

    #[test]
    fn configured_video_encryption_policy_and_peer_reach_stream_session_prepare() {
        let mut value = open_json();
        value["peer_ip"] = json!("198.51.100.42");
        value["video_encryption_policy"] = json!({"lan_mode":2,"wan_mode":0});
        let request: Open = serde_json::from_value(value).unwrap();
        assert!(request.validate(true).is_ok());

        let prepare = request.prepare("configured", None);
        assert_eq!(prepare["peer_ip"], "198.51.100.42");
        assert_eq!(
            prepare["video_encryption_policy"],
            json!({"lan_mode":2,"wan_mode":0})
        );

        let legacy = open().prepare("legacy", None);
        assert!(legacy.get("video_encryption_policy").is_none());
    }

    #[test]
    fn frozen_frame_limiter_snapshot_reaches_stream_preparation() {
        let mut value = open_json();
        value["application_operation_id"] = json!("launch-one");
        value["app_id"] = json!("app-0000000000000001");
        value["catalog_revision"] = json!(1);
        value["frame_limiter_settings"] = json!({
            "version":1,
            "settings":{
                "frame_limiter_enable":true,
                "frame_limiter_fps_limit_millihz":60000,
                "frame_limiter_provider":"auto",
                "frame_limiter_disable_vsync":false,
                "frame_limiter_auto_virtual_framegen":"enabled",
                "rtss_frame_limit_type":"back edge sync",
                "rtss_allow_virtual_display_override":false,
                "rtss_install_path":"",
                "mangohud_limiter_method":"late",
                "mangohud_preset":"custom",
                "mangohud_always_show_graph":false
            },
            "requested_stream_fps_millihz":60000,
            "client_display_mode_override_millihz":null,
            "lossless_scaling_limit_millihz":null,
            "virtual_display_active":null,
            "physical_framegen_capture":null,
            "game_frame_generation_mode":null,
            "rtss_frame_limit_type_explicit_override":true
        });
        value["frame_limiter_executable_path"] = json!("C:\\Games\\Example.exe");
        let request: Open = serde_json::from_value(value.clone()).unwrap();
        assert!(request.validate(false).is_ok());
        let prepare = request.prepare("frozen", None);
        assert_eq!(
            prepare["frame_limiter_settings"],
            value["frame_limiter_settings"]
        );
        assert_eq!(
            prepare["frame_limiter_executable_path"],
            value["frame_limiter_executable_path"]
        );

        let mut combined = value.clone();
        combined["display_request"] = json!({
            "expected_topology_revision":"aa".repeat(16),
            "configuration":{"displays":[
                {"id":"one","width":1920,"height":1080,
                 "refresh":{"numerator":60,"denominator":1},"x":0,"y":0}
            ]},
            "mode_policy":{"display_id":"one","remapping":{},"context":{
                "resolution_is_automatic":true,"refresh_rate_is_automatic":true,
                "client_display_mode_override":false,"optimize_game_settings":false
            }}
        });
        combined["display_admission_token"] = json!("ab".repeat(32));
        combined["display_policy_snapshot"] = json!({
            "global_revision":1,"global_overrides":{},"catalog_revision":1,
            "certificate_id":"cd".repeat(32),"application_overrides":{},
            "client_overrides":{},"effective_overrides":{}
        });
        let consistent: Open = serde_json::from_value(combined.clone()).unwrap();
        consistent.validate(false).unwrap();
        combined["display_policy_snapshot"]["catalog_revision"] = json!(2);
        let inconsistent: Open = serde_json::from_value(combined).unwrap();
        assert_eq!(
            inconsistent.validate(false),
            Err("frame_limiter_unattested")
        );

        let mut unbound = value.clone();
        unbound.as_object_mut().unwrap().remove("app_id");
        let unbound: Open = serde_json::from_value(unbound).unwrap();
        assert_eq!(unbound.validate(false), Err("frame_limiter_unattested"));

        value["frame_limiter_settings"]["requested_stream_fps_millihz"] = json!(120000);
        let mismatched: Open = serde_json::from_value(value).unwrap();
        assert_eq!(
            mismatched.validate(false),
            Err("invalid_frame_limiter_snapshot")
        );
        let mut missing_path = open_json();
        missing_path["frame_limiter_settings"] = prepare["frame_limiter_settings"].clone();
        let missing_path: Open = serde_json::from_value(missing_path).unwrap();
        assert_eq!(
            missing_path.validate(false),
            Err("invalid_frame_limiter_snapshot")
        );

        for path in ["  ", "C:\\Games\\Bad\nName.exe"] {
            let mut invalid = open_json();
            invalid["application_operation_id"] = json!("launch-one");
            invalid["app_id"] = json!("app-0000000000000001");
            invalid["catalog_revision"] = json!(1);
            invalid["frame_limiter_settings"] = prepare["frame_limiter_settings"].clone();
            invalid["frame_limiter_executable_path"] = json!(path);
            let invalid: Open = serde_json::from_value(invalid).unwrap();
            assert_eq!(invalid.validate(false), Err("invalid_executable_path"));
        }
        for install_path in ["C:\\RTSS\\Bad\nName", &"x".repeat(4097)] {
            let mut invalid = open_json();
            invalid["application_operation_id"] = json!("launch-one");
            invalid["app_id"] = json!("app-0000000000000001");
            invalid["catalog_revision"] = json!(1);
            invalid["frame_limiter_settings"] = prepare["frame_limiter_settings"].clone();
            invalid["frame_limiter_settings"]["settings"]["rtss_install_path"] =
                json!(install_path);
            invalid["frame_limiter_executable_path"] = json!("C:\\Games\\Example.exe");
            let invalid: Open = serde_json::from_value(invalid).unwrap();
            assert_eq!(
                invalid.validate(false),
                Err("invalid_frame_limiter_snapshot")
            );
        }
    }

    #[test]
    fn native_pen_touch_scope_value_reaches_stream_session_start() {
        for selected in [None, Some(false), Some(true)] {
            let mut value = open_json();
            if let Some(enabled) = selected {
                value["native_pen_touch"] = json!(enabled);
            }
            let request: Open = serde_json::from_value(value).unwrap();
            assert_eq!(
                request.arm(51)["configuration"]["native_pen_touch"],
                json!(selected)
            );
        }
    }

    #[test]
    fn configured_device_name_reaches_the_authenticated_session_start() {
        let mut value = open_json();
        value["device_name"] = json!("Studio PC");
        let request: Open = serde_json::from_value(value).unwrap();
        assert!(request.validate(false).is_ok());
        assert_eq!(request.arm(51)["configuration"]["device_name"], "Studio PC");

        for invalid in [String::new(), "x".repeat(129)] {
            let mut value = open_json();
            value["device_name"] = json!(invalid);
            let request: Open = serde_json::from_value(value).unwrap();
            assert_eq!(request.validate(false), Err("invalid_device_name"));
        }
    }

    #[test]
    fn input_settings_default_to_absent_for_older_open_payloads() {
        let request = open();
        assert_eq!(request.controller, None);
        assert_eq!(request.gamepad, None);
        assert_eq!(request.ds4_back_as_touchpad_click, None);
        assert_eq!(request.keyboard, None);
        assert_eq!(request.mouse, None);

        let configuration = request.arm(51)["configuration"].clone();
        assert!(configuration["controller"].is_null());
        assert!(configuration["gamepad"].is_null());
        assert!(configuration["ds4_back_as_touchpad_click"].is_null());
        assert!(configuration["keyboard"].is_null());
        assert!(configuration["mouse"].is_null());
    }

    #[test]
    fn input_settings_preserve_explicit_false_and_true_values_in_arm() {
        for selected in [false, true] {
            let mut value = open_json();
            value["controller"] = json!(selected);
            value["gamepad"] = json!("auto");
            value["ds4_back_as_touchpad_click"] = json!(selected);
            value["keyboard"] = json!(selected);
            value["mouse"] = json!(selected);
            let request: Open = serde_json::from_value(value).unwrap();

            assert!(request.validate(false).is_ok());
            let configuration = request.arm(51)["configuration"].clone();
            assert_eq!(configuration["controller"], selected);
            assert_eq!(configuration["gamepad"], "auto");
            assert_eq!(configuration["ds4_back_as_touchpad_click"], selected);
            assert_eq!(configuration["keyboard"], selected);
            assert_eq!(configuration["mouse"], selected);
        }
    }

    #[test]
    fn continuous_audio_flag_reaches_stream_session_and_requires_stream_audio() {
        for enabled in [false, true] {
            let mut value = open_json();
            value["continuous_audio"] = json!(enabled);
            let request: Open = serde_json::from_value(value).unwrap();

            assert!(request.validate(false).is_ok());
            let configuration = request.arm(51)["configuration"].clone();
            if enabled {
                assert_eq!(configuration["continuous_audio"], true);
            } else {
                assert!(
                    configuration
                        .get("continuous_audio")
                        .is_none_or(|value| value == &json!(false))
                );
            }
            assert!(
                request
                    .prepare("continuous-audio", None)
                    .get("continuous_audio")
                    .is_none()
            );
        }

        let legacy_start = open().arm(51);
        assert!(
            legacy_start["configuration"]
                .get("continuous_audio")
                .is_none()
        );

        let mut disabled_audio = open();
        disabled_audio.stream_audio = false;
        disabled_audio.continuous_audio = Some(true);
        assert_eq!(
            disabled_audio.validate(false).unwrap_err(),
            "continuous_audio_requires_stream_audio"
        );
    }

    fn open_operation_json() -> Value {
        let mut value = open_json();
        value["action"] = json!("open");
        value
    }

    fn changed_announce(name: &str, value: &str) -> String {
        replace_announce_attribute(PRIMARY_ANNOUNCE, name, value)
    }

    fn replace_announce_attribute(announcement: &str, name: &str, value: &str) -> String {
        let prefix = format!("a={name}:");
        announcement
            .split_inclusive("\r\n")
            .map(|line| {
                if line.starts_with(&prefix) {
                    format!("{prefix}{value} \r\n")
                } else {
                    line.into()
                }
            })
            .collect()
    }

    fn matching_profile() -> Profile {
        Profile {
            bitrate_kbps: 16000,
            packet_size: 1392,
            packet_ms: 5,
            ..Profile::default()
        }
    }

    #[test]
    fn settings_default_to_a_disabled_loopback_listener() {
        let settings: Settings = serde_json::from_str("{}").unwrap();
        assert!(!settings.enabled);
        assert!(!settings.allow_remote);
        assert_eq!(settings.bind, "127.0.0.1:48010".parse().unwrap());
        assert!(settings.address_family.is_none());
        assert!(settings.bind_address.is_none());
        assert!(settings.allowed_principals.is_empty());
        assert_eq!(settings.validate(), Ok(()));

        for value in [
            json!({"allowed_principals": vec!["owner"; 17]}),
            json!({"allowed_principals": [""]}),
            json!({"allowed_principals": ["line\nfeed"]}),
        ] {
            assert_eq!(
                serde_json::from_value::<Settings>(value)
                    .unwrap()
                    .validate(),
                Err("invalid_settings")
            );
        }
    }

    #[test]
    fn global_port_uses_vibeshine_rtsp_and_media_offsets_on_the_configured_ip() {
        let settings: Settings = serde_json::from_str("{}").unwrap();
        let binds = settings.media_binds(DEFAULT_BASE_PORT).unwrap();
        assert_eq!(binds.video, "127.0.0.1:47998".parse().unwrap());
        assert_eq!(binds.control, "127.0.0.1:47999".parse().unwrap());
        assert_eq!(binds.audio, "127.0.0.1:48000".parse().unwrap());
        assert_eq!(
            settings.rtsp_bind_for_base(DEFAULT_BASE_PORT).unwrap(),
            "127.0.0.1:48010".parse().unwrap()
        );

        let ipv6: Settings = serde_json::from_value(serde_json::json!({
            "bind": "[::1]:48010"
        }))
        .unwrap();
        let ipv6_binds = ipv6.media_binds(48_000).unwrap();
        assert_eq!(ipv6_binds.video, "[::1]:48009".parse().unwrap());
        assert_eq!(ipv6_binds.control, "[::1]:48010".parse().unwrap());
        assert_eq!(ipv6_binds.audio, "[::1]:48011".parse().unwrap());

        for invalid in [0, 1_028, 65_515, u16::MAX] {
            assert_eq!(settings.media_binds(invalid), Err("invalid_port"));
            assert_eq!(settings.rtsp_bind_for_base(invalid), Err("invalid_port"));
        }
    }

    #[test]
    fn omitted_policy_fields_preserve_the_legacy_ipv6_bind() {
        for allow_remote in [false, true] {
            let settings = Settings {
                allow_remote,
                bind: "[::1]:48010".parse().unwrap(),
                ..Settings::default()
            };

            assert_eq!(
                settings.resolved_binds().unwrap(),
                vec!["[::1]:48010".parse().unwrap()],
                "allow_remote={allow_remote}"
            );
        }
    }

    #[test]
    fn explicit_family_defaults_apply_to_omitted_or_blank_address_over_legacy_ipv6() {
        for allow_remote in [false, true] {
            let ipv4_bind = if allow_remote {
                "0.0.0.0:48010"
            } else {
                "127.0.0.1:48010"
            };
            let ipv6_bind = if allow_remote {
                "[::]:48010"
            } else {
                "[::1]:48010"
            };

            for family in [AddressFamily::Ipv4, AddressFamily::Both] {
                let expected: Vec<SocketAddr> = match family {
                    AddressFamily::Ipv4 => vec![ipv4_bind.parse().unwrap()],
                    AddressFamily::Both => {
                        vec![ipv4_bind.parse().unwrap(), ipv6_bind.parse().unwrap()]
                    }
                };

                for bind_address in [None, Some(""), Some(" \t ")] {
                    let settings = Settings {
                        allow_remote,
                        bind: "[::1]:48010".parse().unwrap(),
                        address_family: Some(family),
                        bind_address: bind_address.map(str::to_owned),
                        ..Settings::default()
                    };

                    assert_eq!(
                        settings.resolved_binds().unwrap(),
                        expected,
                        "family={family:?}, bind_address={bind_address:?}, allow_remote={allow_remote}"
                    );
                }
            }
        }
    }

    #[test]
    fn configured_family_and_address_drive_rtsp_and_all_udp_listener_addresses() {
        let settings: Settings = serde_json::from_value(json!({
            "address_family": "both",
            "bind_address": " ::1 ",
            "bind": "127.0.0.1:48010"
        }))
        .unwrap();
        assert_eq!(settings.validate(), Ok(()));
        assert_eq!(
            settings.resolved_bind().unwrap(),
            "[::1]:48010".parse().unwrap()
        );
        assert_eq!(
            settings.rtsp_bind_for_base(DEFAULT_BASE_PORT).unwrap(),
            "[::1]:48010".parse().unwrap()
        );
        assert_eq!(
            settings.media_binds(DEFAULT_BASE_PORT).unwrap(),
            MediaBinds {
                video: "[::1]:47998".parse().unwrap(),
                control: "[::1]:47999".parse().unwrap(),
                audio: "[::1]:48000".parse().unwrap(),
            }
        );

        let mismatch: Settings = serde_json::from_value(json!({
            "address_family": "ipv4",
            "bind_address": "::1"
        }))
        .unwrap();
        assert_eq!(mismatch.validate(), Err("address_family_mismatch"));

        let malformed: Settings = serde_json::from_value(json!({
            "address_family": "both",
            "bind_address": "rtsp.example"
        }))
        .unwrap();
        assert_eq!(malformed.validate(), Err("invalid_bind"));
    }

    #[test]
    fn explicit_empty_bind_address_uses_family_wildcard_only_when_remote_is_enabled() {
        let settings: Settings = serde_json::from_value(json!({
            "enabled": true,
            "allow_remote": true,
            "address_family": "both",
            "bind_address": "",
            "bind": "127.0.0.1:48010"
        }))
        .unwrap();
        assert_eq!(
            settings.resolved_binds().unwrap(),
            vec![
                "0.0.0.0:48010".parse().unwrap(),
                "[::]:48010".parse().unwrap()
            ]
        );
        assert_eq!(
            settings.media_binds_by_family(DEFAULT_BASE_PORT).unwrap(),
            vec![
                MediaBinds {
                    video: "0.0.0.0:47998".parse().unwrap(),
                    control: "0.0.0.0:47999".parse().unwrap(),
                    audio: "0.0.0.0:48000".parse().unwrap(),
                },
                MediaBinds {
                    video: "[::]:47998".parse().unwrap(),
                    control: "[::]:47999".parse().unwrap(),
                    audio: "[::]:48000".parse().unwrap(),
                }
            ]
        );
    }

    #[test]
    fn dual_family_udp_preflight_checks_the_ipv6_addresses_too() {
        assert_dual_family_udp_preflight_checks_the_ipv6_addresses(false);
    }

    #[test]
    #[ignore = "opens wildcard UDP sockets; run explicitly when testing remote binding"]
    fn remote_dual_family_udp_preflight_checks_the_ipv6_addresses_too() {
        assert_dual_family_udp_preflight_checks_the_ipv6_addresses(true);
    }

    fn assert_dual_family_udp_preflight_checks_the_ipv6_addresses(allow_remote: bool) {
        let settings: Settings = serde_json::from_value(json!({
            "enabled": true,
            "allow_remote": allow_remote,
            "address_family": "both",
            "bind_address": "",
            "bind": "127.0.0.1:48010"
        }))
        .unwrap();
        let base_port = (20_000..=30_000)
            .find(|port| settings.probe_media_binds(*port).is_ok())
            .expect("find an available local UDP bind set");
        settings
            .probe_media_binds(base_port)
            .expect("all six family-specific UDP sockets bind together");

        let occupied_address = SocketAddr::new(
            IpAddr::V6(if allow_remote {
                Ipv6Addr::UNSPECIFIED
            } else {
                Ipv6Addr::LOCALHOST
            }),
            base_port + VIDEO_OFFSET,
        );
        let blocker = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        blocker.set_only_v6(true).unwrap();
        blocker.bind(&SockAddr::from(occupied_address)).unwrap();
        let _blocker = UdpSocket::from(blocker);

        assert_eq!(
            settings.probe_media_binds(base_port),
            Err("udp_bind_failed"),
            "a conflict on only the IPv6 video bind must defer network activation"
        );
    }

    #[test]
    fn rtsp_prepare_includes_configured_server_udp_source_ports() {
        let settings: Settings = serde_json::from_str("{}").unwrap();
        let binds = settings.media_binds(DEFAULT_BASE_PORT).unwrap();
        let payload = open().prepare_with_media_binds("operation", None, Some(binds));
        assert_eq!(payload["video_bind"], "127.0.0.1:47998");
        assert_eq!(payload["control_bind"], "127.0.0.1:47999");
        assert_eq!(payload["audio_bind"], "127.0.0.1:48000");

        let discovery = UdpDiscovery {
            video_ping_payload: "video-token-0001".into(),
            audio_ping_payload: "audio-token-0001".into(),
        };
        let payload = open().prepare_with_media_binds("discovery", Some(&discovery), Some(binds));
        assert!(payload.get("video_port").is_none());
        assert!(payload.get("audio_port").is_none());
        assert_eq!(payload["video_bind"], "127.0.0.1:47998");
        assert_eq!(payload["audio_bind"], "127.0.0.1:48000");
    }

    #[test]
    fn configured_video_batch_size_reaches_stream_session_as_effective_video_setting() {
        for (requested, effective) in [(0, 64), (16, 16), (32, 32), (64, 64), (17, 64)] {
            let mut request = open();
            request.profile.video_max_batch_size_kb = requested;
            let payload = request.prepare("operation", None);
            assert_eq!(payload["video"]["max_batch_size_kb"], effective);
        }

        let mut invalid = open();
        invalid.profile.video_max_batch_size_kb = 65;
        assert_eq!(invalid.validate(false), Err("invalid_profile"));
    }

    #[test]
    fn minimum_fps_target_reaches_stream_session_start_and_defaults_to_source_value() {
        let mut request = open();
        assert_eq!(request.minimum_fps_target, 20.0);
        request.minimum_fps_target = 23.5;
        assert!(request.validate(false).is_ok());
        assert_eq!(request.arm(51)["configuration"]["minimum_fps_target"], 23.5);

        request.minimum_fps_target = 1000.1;
        assert_eq!(
            request.validate_capture(),
            Err("invalid_minimum_fps_target")
        );
    }

    #[test]
    fn nvenc_settings_and_spatial_aq_reach_the_frozen_video_open() {
        let mut request = open();
        request.nvenc_settings.nvenc_preset = 6;
        request.nvenc_settings.nvenc_h264_cavlc = true;
        request.nvenc_settings.nvenc_vbv_increase = 40;
        request.nvenc_spatial_aq = true;
        request.validate(false).unwrap();

        let payload = request.arm(52);
        assert_eq!(
            payload["configuration"]["configuration"]["nvenc_settings"]["nvenc_preset"],
            6
        );
        assert_eq!(
            payload["configuration"]["configuration"]["nvenc_settings"]["nvenc_h264_cavlc"],
            true
        );
        assert_eq!(
            payload["configuration"]["configuration"]["nvenc_settings"]["nvenc_vbv_increase"],
            40
        );
        assert_eq!(
            payload["configuration"]["configuration"]["nvenc_spatial_aq"],
            true
        );

        request.nvenc_settings.nvenc_preset = 8;
        assert_eq!(request.validate(false), Err("invalid_nvenc_settings"));
    }

    #[test]
    fn wgc_pacing_smoothing_defaults_on_and_reaches_stream_session_start() {
        let mut request = open();
        assert!(request.wgc_pacing_smoothing);
        request.wgc_pacing_smoothing = false;
        assert!(request.validate(false).is_ok());
        assert_eq!(
            request.arm(51)["configuration"]["wgc_pacing_smoothing"],
            false
        );
    }

    #[test]
    fn stream_audio_flag_reaches_prepare_without_removing_the_required_audio_lane() {
        let legacy_open = open();
        assert!(
            legacy_open.stream_audio,
            "older callers retain audio by default"
        );

        let mut disabled = legacy_open;
        disabled.stream_audio = false;
        let payload = disabled.prepare("operation", None);
        assert_eq!(payload["stream_audio"], false);
        assert_eq!(payload["video_port"], 47_998);
        assert_eq!(payload["audio_port"], 48_000);
        assert_eq!(payload["audio"]["packet_ms"], 10);
        assert_eq!(payload["audio"]["bitrate"], 128_000);
        assert_eq!(payload["encrypt_audio"], true);
    }

    #[test]
    fn settings_reject_unusable_listener_addresses_and_enforce_remote_policy() {
        for address in [
            "0.0.0.0:48010",
            "[::]:48010",
            "239.1.2.3:48010",
            "[ff02::1]:48010",
            "255.255.255.255:48010",
            "[::ffff:127.0.0.1]:48010",
            "[::ffff:192.0.2.1]:48010",
        ] {
            let settings: Settings = serde_json::from_value(json!({
                "allow_remote": true,
                "bind": address
            }))
            .unwrap();
            assert_eq!(settings.validate(), Err("invalid_bind"), "{address}");
        }

        for address in ["192.0.2.1:48010", "[2001:db8::1]:48010"] {
            let local_only: Settings = serde_json::from_value(json!({"bind": address})).unwrap();
            assert_eq!(local_only.validate(), Err("invalid_bind"), "{address}");
            let remote: Settings =
                serde_json::from_value(json!({"allow_remote": true, "bind": address})).unwrap();
            assert_eq!(remote.validate(), Ok(()), "{address}");
        }

        let ipv6_loopback: Settings =
            serde_json::from_value(json!({"bind": "[::1]:48010"})).unwrap();
        assert_eq!(ipv6_loopback.validate(), Ok(()));
    }

    #[test]
    fn keys_require_exact_ascii_hex_without_panicking_on_utf8() {
        assert_eq!(
            decode_key("00112233445566778899aAbBcCdDeEfF"),
            Ok([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ])
        );
        for value in [
            "",
            "00112233445566778899aabbccddeef",
            "00112233445566778899aabbccddeeff00",
            "00112233445566778899aabbccddeezz",
            &"é".repeat(16),
            &format!("é{}", "0".repeat(30)),
        ] {
            assert!(
                matches!(
                    std::panic::catch_unwind(|| decode_key(value)),
                    Ok(Err("invalid_key"))
                ),
                "{value:?}"
            );
        }
    }

    #[test]
    fn unknown_fields_are_rejected_at_every_configuration_boundary() {
        assert!(serde_json::from_value::<Settings>(json!({"listen_backlog": 8})).is_err());

        let mut operation = open_operation_json();
        operation["administrator"] = json!(true);
        assert!(serde_json::from_value::<Operation>(operation).is_err());

        let mut operation = open_operation_json();
        operation["capture"]["codec"] = json!("h264");
        assert!(serde_json::from_value::<Operation>(operation).is_err());

        let mut operation = open_operation_json();
        operation["profile"] = json!({"unsupported_fec_mode": 2});
        assert!(serde_json::from_value::<Operation>(operation).is_err());

        assert!(
            serde_json::from_value::<Operation>(
                json!({"action": "status", "ticket": null, "owner": "forged"})
            )
            .is_err()
        );
    }

    #[test]
    fn peer_validation_rejects_invalid_addresses_and_zero_ports_for_both_families() {
        for address in [
            "0.0.0.0",
            "::",
            "239.1.2.3",
            "ff02::1",
            "255.255.255.255",
            "::ffff:127.0.0.1",
            "::ffff:192.0.2.1",
        ] {
            let mut request = open();
            request.peer_ip = address.parse().unwrap();
            assert_eq!(request.validate(true), Err("invalid_peer"), "{address}");
        }

        let mut request = open();
        request.peer_ip = "192.0.2.1".parse().unwrap();
        assert_eq!(request.validate(false), Err("remote_disabled"));
        assert!(request.validate(true).is_ok());

        request.peer_ip = "::1".parse().unwrap();
        assert!(request.validate(false).is_ok());
        request.video_port = 0;
        assert_eq!(request.validate(false), Err("invalid_peer"));
        request.video_port = 47998;
        request.audio_port = 0;
        assert_eq!(request.validate(false), Err("invalid_peer"));
    }

    #[test]
    fn discovery_and_fixed_port_modes_are_unambiguous_on_both_json_boundaries() {
        let mut discovery_json = open_json();
        discovery_json.as_object_mut().unwrap().remove("video_port");
        discovery_json.as_object_mut().unwrap().remove("audio_port");
        discovery_json["discover_peers"] = json!(true);
        let discovery: Open = serde_json::from_value(discovery_json.clone()).unwrap();
        assert!(discovery.validate(false).is_ok());

        for (field, port) in [("video_port", 47998), ("audio_port", 48000)] {
            let mut mixed = discovery_json.clone();
            mixed[field] = json!(port);
            assert_eq!(
                serde_json::from_value::<Open>(mixed)
                    .unwrap()
                    .validate(false),
                Err("invalid_peer"),
                "{field}"
            );
        }

        let mut missing_fixed_port = open_json();
        missing_fixed_port
            .as_object_mut()
            .unwrap()
            .remove("video_port");
        assert_eq!(
            serde_json::from_value::<Open>(missing_fixed_port)
                .unwrap()
                .validate(false),
            Err("invalid_peer")
        );

        let tokens = UdpDiscovery {
            audio_ping_payload: "AudioToken_12345".into(),
            video_ping_payload: "VideoToken_12345".into(),
        };
        let prepare = discovery.prepare("rtsp-ticket", Some(&tokens));
        assert!(prepare.get("video_port").is_none());
        assert!(prepare.get("audio_port").is_none());
        assert_eq!(
            prepare["discovery"],
            json!({
                "audio_ping_payload": "AudioToken_12345",
                "video_ping_payload": "VideoToken_12345"
            })
        );

        let fixed = open().prepare("rtsp-ticket", None);
        assert_eq!(fixed["video_port"], 47998);
        assert_eq!(fixed["audio_port"], 48000);
        assert!(fixed.get("discovery").is_none());
    }

    #[test]
    fn profile_validation_covers_geometry_media_bounds_and_packetizer_configuration() {
        let request = open();
        assert!(request.validate(false).is_ok());

        for (field, profile_value) in [
            ("width", json!(15)),
            ("width", json!(17)),
            ("width", json!(3842)),
            ("height", json!(15)),
            ("height", json!(17)),
            ("height", json!(2162)),
            ("fps", json!(0)),
            ("fps", json!(121)),
            ("bitrate_kbps", json!(99)),
            ("bitrate_kbps", json!(100001)),
            ("max_reference_frames", json!(17)),
            ("packet_ms", json!(20)),
            ("audio_bitrate", json!(5999)),
            ("audio_bitrate", json!(512001)),
            ("packet_size", json!(0)),
            ("fec_percentage", json!(0)),
            ("max_fec_blocks", json!(0)),
            ("max_fec_blocks", json!(5)),
        ] {
            let mut value = open_json();
            value["profile"] = json!({(field): profile_value});
            let request: Open = serde_json::from_value(value).unwrap();
            assert_eq!(request.validate(false), Err("invalid_profile"), "{field}");
        }

        for maximum in [0, 1, 2, 16] {
            let mut request = open();
            request.profile.max_reference_frames = maximum;
            assert!(request.validate(false).is_ok(), "{maximum}");
        }

        for field in ["output", "audio_endpoint"] {
            let mut value = open_json();
            value["capture"][field] = json!("bad\nlabel");
            let request: Open = serde_json::from_value(value).unwrap();
            assert_eq!(request.validate(false), Err("invalid_profile"), "{field}");
        }
    }

    #[test]
    fn prepare_and_arm_forward_the_validated_profile_without_unit_ambiguity() {
        let mut request = open();
        request.profile = matching_profile();
        request.profile.max_reference_frames = 0;
        assert!(!request.profile.permit_legacy_audio_iv_wrap);
        request.profile.permit_legacy_audio_iv_wrap = true;

        let prepare = request.prepare("rtsp-ticket", None);
        assert_eq!(prepare["operation_id"], "rtsp-ticket");
        assert_eq!(prepare["video"]["packet_size"], 1392);
        assert_eq!(prepare["video"]["fec_percentage"], 20);
        assert_eq!(prepare["video"]["min_parity_shards"], 2);
        assert_eq!(prepare["video"]["max_fec_blocks"], 1);
        assert_eq!(prepare["audio"]["packet_ms"], 5);
        assert_eq!(prepare["audio"]["bitrate"], 128000);
        assert_eq!(prepare["encrypt_video"], true);
        assert_eq!(prepare["encrypt_audio"], true);
        assert_eq!(prepare["permit_legacy_audio_iv_wrap"], true);

        let arm = request.arm(41);
        assert_eq!(arm["session"], 41);
        let video = &arm["configuration"]["configuration"];
        assert_eq!(video["width"], 1920);
        assert_eq!(video["height"], 1080);
        assert_eq!(video["fps"], 60);
        assert_eq!(video["bitrate"], 16_000_000);
        assert_eq!(video["max_reference_frames"], 0);
    }

    #[test]
    fn arm_forwards_capture_only_mode_and_legacy_open_defaults_to_routing() {
        let legacy = open();
        assert!(!legacy.capture_sink_without_routing);
        assert!(!legacy.capture.host_audio_enabled);
        assert_eq!(
            legacy.arm(40)["configuration"]["capture_sink_without_routing"],
            false
        );
        assert_eq!(
            legacy.arm(40)["configuration"]["back_button_timeout"],
            Value::Null
        );
        assert_eq!(legacy.arm(40)["configuration"]["host_audio_enabled"], false);

        let mut value = open_json();
        value["capture_sink_without_routing"] = json!(true);
        let selected: Open = serde_json::from_value(value).unwrap();
        assert!(selected.validate(false).is_ok());
        assert_eq!(
            selected.arm(41)["configuration"]["capture_sink_without_routing"],
            true
        );

        let mut selected_timeout = open();
        selected_timeout.back_button_timeout = Some(-1);
        assert_eq!(
            selected_timeout.arm(42)["configuration"]["back_button_timeout"],
            -1
        );
    }

    #[test]
    fn ordered_keybindings_open_snapshot_preserves_null_empty_and_duplicates_in_arm() {
        for selected in [
            None,
            Some(json!(null)),
            Some(json!([])),
            Some(json!([0, 255, 65, 66, 65, 67])),
        ] {
            let mut value = open_json();
            if let Some(selected) = &selected {
                value["keybindings"] = selected.clone();
            }
            let request: Open = serde_json::from_value(value).unwrap();
            assert!(request.validate(false).is_ok());
            assert_eq!(
                request.arm(51)["configuration"]["keybindings"],
                selected.unwrap_or(Value::Null)
            );
        }
        for invalid in [
            json!([65]),
            json!([0, 256]),
            json!([-1, 0]),
            json!([65.0, 66]),
            json!(["65", 66]),
            json!({}),
            json!(vec![0_u8; 514]),
        ] {
            let mut value = open_json();
            value["keybindings"] = invalid.clone();
            assert!(serde_json::from_value::<Open>(value).is_err(), "{invalid}");
        }
    }

    #[test]
    fn scoped_keyboard_policy_overrides_reach_stream_session_and_stay_sparse() {
        let inherited = open();
        assert_eq!(inherited.high_resolution_scrolling, None);
        assert_eq!(inherited.always_send_scancodes, None);
        assert_eq!(inherited.key_rightalt_to_key_win, None);
        assert_eq!(inherited.key_repeat_delay, None);
        assert_eq!(inherited.key_repeat_frequency, None);

        let mut selected = open();
        selected.high_resolution_scrolling = Some(false);
        selected.always_send_scancodes = Some(false);
        selected.key_rightalt_to_key_win = Some(true);
        selected.key_repeat_delay = Some(0);
        selected.key_repeat_frequency = Some(0.0);
        assert!(selected.validate(false).is_ok());

        let configuration = selected.arm(43)["configuration"].clone();
        assert_eq!(configuration["high_resolution_scrolling"], false);
        assert_eq!(configuration["always_send_scancodes"], false);
        assert_eq!(configuration["key_rightalt_to_key_win"], true);
        assert_eq!(configuration["key_repeat_delay"], 0);
        assert_eq!(configuration["key_repeat_frequency"], 0.0);
    }

    #[test]
    fn scoped_repeat_overrides_reject_values_outside_input_policy_bounds() {
        for (field, value) in [
            ("key_repeat_delay", json!(i32::MAX as u64 + 1)),
            ("key_repeat_frequency", json!(-0.1)),
        ] {
            let mut request = open_json();
            request[field] = value;
            let request: Open = serde_json::from_value(request).unwrap();
            assert_eq!(
                request.validate(false),
                Err("invalid_input_policy_override")
            );
        }
    }

    #[test]
    fn host_audio_policy_is_snapshotted_into_stream_session_arm() {
        let mut value = open_json();
        value["capture"]["host_audio_enabled"] = json!(true);
        let request: Open = serde_json::from_value(value).unwrap();

        assert!(request.capture.host_audio_enabled);
        assert_eq!(request.arm(41)["configuration"]["host_audio_enabled"], true);
    }

    #[test]
    fn virtual_sink_selection_and_stereo_layout_reach_stream_session() {
        let mut value = open_json();
        value["capture"]["audio_endpoint"] = json!("");
        value["virtual_sink"] = json!("Steam Streaming Speakers");
        value["channels"] = json!(2);
        let request: Open = serde_json::from_value(value).unwrap();
        assert!(request.validate(false).is_ok());
        let configuration = request.arm(41)["configuration"].clone();
        assert_eq!(configuration["audio_endpoint"], "");
        assert_eq!(configuration["virtual_sink"], "Steam Streaming Speakers");
        assert_eq!(configuration["channels"], 2);

        for channels in [4, 6, 8] {
            let mut value = open_json();
            value["capture"]["audio_endpoint"] = json!("");
            value["virtual_sink"] = json!("Steam Streaming Speakers");
            value["channels"] = json!(channels);
            let request: Open = serde_json::from_value(value).unwrap();
            let expected = if channels == 4 {
                "invalid_virtual_sink_channels"
            } else {
                "unsupported_surround_bitrate"
            };
            assert_eq!(request.validate(false), Err(expected));
        }
    }

    #[test]
    fn surround_open_preserves_exact_prepared_layout_and_announce_authority() {
        for (channels, mask, layout, bitrate) in [(6, 63, "5.1", 256000), (8, 1599, "7.1", 512000)]
        {
            let mut value = open_json();
            value["capture"]["audio_endpoint"] = json!("");
            value["virtual_sink"] = json!("Steam Streaming Speakers");
            value["channels"] = json!(channels);
            value["profile"]["audio_bitrate"] = json!(bitrate);
            let mut request: Open = serde_json::from_value(value).unwrap();
            request.profile = matching_profile();
            request.profile.audio_bitrate = bitrate;
            assert!(request.validate(false).is_ok());
            let prepare = request.prepare("prepare-surround", None);
            assert_eq!(prepare["audio"]["channels"], channels);
            assert_eq!(prepare["audio"]["channel_mask"], mask);
            assert_eq!(prepare["audio"]["layout"], layout);
            assert_eq!(request.arm(41)["configuration"]["channels"], channels);

            let announce =
                changed_announce("x-nv-audio.surround.numChannels", &channels.to_string())
                    .replace(
                        "a=x-nv-audio.surround.channelMask:3 ",
                        &format!("a=x-nv-audio.surround.channelMask:{mask} "),
                    )
                    .replace(
                        "a=x-nv-audio.surround.enable:0 ",
                        "a=x-nv-audio.surround.enable:1 ",
                    )
                    .replace(
                        "a=x-ss-general.encryptionEnabled:0 ",
                        "a=x-ss-general.encryptionEnabled:7 ",
                    );
            let announce = parse_announce(announce.as_bytes()).unwrap();
            assert!(request.matches_announce(&announce));
            let mut mismatched = request.clone();
            mismatched.channels = Some(if channels == 6 { 8 } else { 6 });
            assert!(!mismatched.matches_announce(&announce));
        }
    }

    #[test]
    fn absent_maximum_bitrate_cap_preserves_requested_rate_in_older_open_payloads() {
        let mut request = open();
        request.profile = matching_profile();
        request.profile.bitrate_kbps = 7_500;

        assert_eq!(request.max_bitrate_kbps, None);
        assert!(request.validate(false).is_ok());
        let arm = request.arm(41);
        assert_eq!(arm["configuration"]["configuration"]["bitrate"], 7_500_000);
    }

    #[test]
    fn maximum_bitrate_cap_limits_only_encoder_start_bitrate() {
        let mut request = open();
        request.profile = matching_profile();
        request.profile.bitrate_kbps = 7_500;
        request.max_bitrate_kbps = Some(5_000);

        assert!(request.validate(false).is_ok());
        assert_eq!(request.profile.bitrate_kbps, 7_500);
        assert_eq!(request.effective_profile().bitrate_kbps, 5_000);
        assert_eq!(
            request.arm(41)["configuration"]["configuration"]["bitrate"],
            5_000_000
        );

        let mut announce =
            parse_announce(changed_announce("x-ss-general.encryptionEnabled", "7").as_bytes())
                .unwrap();
        announce.video.bitrate_kbps = 5_000;
        assert!(request.effective_profile().matches(&announce));
        assert!(!request.profile.matches(&announce));
    }

    #[test]
    fn maximum_bitrate_cap_above_requested_rate_preserves_requested_rate() {
        let mut request = open();
        request.profile = matching_profile();
        request.profile.bitrate_kbps = 7_500;
        request.max_bitrate_kbps = Some(8_000);

        assert!(request.validate(false).is_ok());
        assert_eq!(request.effective_profile().bitrate_kbps, 7_500);
        assert_eq!(
            request.arm(41)["configuration"]["configuration"]["bitrate"],
            7_500_000
        );
    }

    fn bounded_video_open() -> Open {
        let mut request = open();
        request.profile = matching_profile();
        request.negotiation_bounds = Some(NegotiationBounds {
            max_width: 2560,
            max_height: 1440,
            max_fps: 120,
            max_bitrate_kbps: 20_000,
            max_reference_frames: 1,
        });
        request
    }

    fn encrypted_announce() -> Announce {
        parse_announce(changed_announce("x-ss-general.encryptionEnabled", "7").as_bytes())
            .expect("Moonlight H.264/Opus fixture")
    }

    #[test]
    fn signed_codec_is_kept_from_announce_through_prepare_and_start() {
        let mut request = bounded_video_open();
        let mut h264 = encrypted_announce();
        assert!(request.negotiate_announce(&h264).is_some());
        request.profile.codec = amaterasu_media::VideoCodec::Hevc;
        assert!(request.negotiate_announce(&h264).is_none());
        h264.video.format.codec = amaterasu_gamestream::sdp::VideoCodec::Hevc;
        h264.video.color = amaterasu_gamestream::sdp::ColorMode::Bt709Limited;
        let selected = request.negotiate_announce(&h264).unwrap();
        assert_eq!(selected.codec, amaterasu_media::VideoCodec::Hevc);
        assert_eq!(
            request.prepare("hevc-codec-ticket", None)["video"]["codec"],
            "hevc"
        );
    }

    #[test]
    fn signed_bounds_accept_client_selected_video_values_and_preserve_prepare_transport() {
        let request = bounded_video_open();
        assert!(request.validate(false).is_ok());
        let mut wire = changed_announce("x-ss-general.encryptionEnabled", "7");
        for (name, value) in [
            ("x-nv-video[0].clientViewportWd", "1280"),
            ("x-nv-video[0].clientViewportHt", "720"),
            ("x-nv-video[0].maxFPS", "30"),
            ("x-nv-video[0].clientRefreshRateX100", "3000"),
            ("x-nv-video[0].initialBitrateKbps", "8000"),
            ("x-nv-video[0].initialPeakBitrateKbps", "8000"),
            ("x-nv-vqos[0].bw.minimumBitrateKbps", "8000"),
            ("x-nv-vqos[0].bw.maximumBitrateKbps", "8000"),
            ("x-nv-video[0].maxNumReferenceFrames", "0"),
        ] {
            wire = replace_announce_attribute(&wire, name, value);
        }
        let announce = parse_announce(wire.as_bytes()).expect("bounded Moonlight SDP");

        assert_eq!(
            request.negotiate_announce(&announce),
            Some(NegotiatedVideo {
                codec: amaterasu_media::VideoCodec::H264,
                width: 1280,
                height: 720,
                fps: 30,
                bitrate_kbps: 8_000,
                max_reference_frames: 0,
            })
        );
        let prepared = request.prepare("bounded-video", None);
        assert_eq!(prepared["video"]["packet_size"], 1392);
        assert_eq!(prepared["audio"]["packet_ms"], 5);
    }

    #[test]
    fn signed_video_bounds_enforce_ceiling_lower_bounds_even_geometry_and_overflow() {
        let request = bounded_video_open();
        let mut ceiling = encrypted_announce();
        ceiling.video.width = 2560;
        ceiling.video.height = 1440;
        ceiling.video.fps = 120;
        ceiling.video.bitrate_kbps = 20_000;
        ceiling.video.max_reference_frames = 1;
        assert!(request.negotiate_announce(&ceiling).is_some());

        let mut minimum = encrypted_announce();
        minimum.video.width = 16;
        minimum.video.height = 16;
        minimum.video.fps = 1;
        minimum.video.bitrate_kbps = 100;
        minimum.video.max_reference_frames = 0;
        assert!(request.negotiate_announce(&minimum).is_some());

        let mut out_of_range = ceiling.clone();
        out_of_range.video.width = 2562;
        assert!(request.negotiate_announce(&out_of_range).is_none());
        let mut invalid_height = ceiling.clone();
        invalid_height.video.height = 1442;
        assert!(request.negotiate_announce(&invalid_height).is_none());
        let mut invalid_fps = ceiling.clone();
        invalid_fps.video.fps = 121;
        assert!(request.negotiate_announce(&invalid_fps).is_none());
        let mut invalid_reference_frames = ceiling.clone();
        invalid_reference_frames.video.max_reference_frames = 2;
        assert!(
            request
                .negotiate_announce(&invalid_reference_frames)
                .is_none()
        );

        for (width, height, fps, bitrate) in [
            (14, 16, 1, 100),
            (1279, 720, 30, 8_000),
            (16, 16, 0, 100),
            (16, 16, 1, 99),
            (16, 16, 1, u32::MAX),
        ] {
            let mut below_or_invalid = ceiling.clone();
            below_or_invalid.video.width = width;
            below_or_invalid.video.height = height;
            below_or_invalid.video.fps = fps;
            below_or_invalid.video.bitrate_kbps = bitrate;
            below_or_invalid.video.max_reference_frames = 0;
            assert!(request.negotiate_announce(&below_or_invalid).is_none());
        }
    }

    #[test]
    fn malformed_signed_video_bounds_are_rejected_at_open() {
        for bounds in [
            NegotiationBounds {
                max_width: u32::MAX,
                max_height: 1440,
                max_fps: 120,
                max_bitrate_kbps: 20_000,
                max_reference_frames: 1,
            },
            NegotiationBounds {
                max_width: 2560,
                max_height: 1440,
                max_fps: 120,
                max_bitrate_kbps: 100_001,
                max_reference_frames: 1,
            },
        ] {
            let mut request = bounded_video_open();
            request.negotiation_bounds = Some(bounds);
            assert_eq!(request.validate(false), Err("invalid_negotiation_bounds"));
        }
    }

    #[test]
    fn zero_maximum_bitrate_cap_preserves_requested_rate() {
        let mut request = open();
        request.profile = matching_profile();
        request.profile.bitrate_kbps = 7_500;
        request.max_bitrate_kbps = Some(0);

        assert!(request.validate(false).is_ok());
        assert_eq!(request.effective_profile().bitrate_kbps, 7_500);
        assert_eq!(
            request.arm(41)["configuration"]["configuration"]["bitrate"],
            7_500_000
        );
    }

    #[test]
    fn positive_maximum_bitrate_cap_below_encoder_minimum_is_rejected() {
        let mut value = open_json();
        value["max_bitrate_kbps"] = json!(99);
        let request: Open = serde_json::from_value(value).unwrap();

        assert_eq!(request.validate(false), Err("invalid_max_bitrate"));
    }

    #[test]
    fn selected_pipewire_source_reaches_session_without_windows_capture_flags() {
        let mut request = open();
        request.capture.capture_provider = CaptureProvider::PipeWire;
        request.capture.output = "portal-selected-session-source".into();
        assert!(request.validate(false).is_ok());
        let configuration = &request.arm(41)["configuration"];
        assert_eq!(configuration["capture_provider"], "pipewire");
        assert_eq!(configuration["output"], "portal-selected-session-source");
        assert_eq!(configuration["constant_rate"], false);
        request.capture.constant_rate = true;
        assert_eq!(request.validate(false), Err("constant_rate_requires_wgc"));
    }

    #[test]
    fn selected_x11_output_reaches_session_without_windows_capture_flags() {
        let mut request = open();
        request.capture.capture_provider = CaptureProvider::X11;
        request.capture.output = "x11:DP-1/000000a4".into();
        assert!(request.validate(false).is_ok());
        let configuration = &request.arm(41)["configuration"];
        assert_eq!(configuration["capture_provider"], "x11");
        assert_eq!(configuration["output"], "x11:DP-1/000000a4");
        assert_eq!(configuration["constant_rate"], false);
        request.capture.constant_rate = true;
        assert_eq!(request.validate(false), Err("constant_rate_requires_wgc"));
    }

    #[test]
    fn selected_kms_output_reaches_session_without_windows_capture_flags() {
        let mut request = open();
        request.capture.capture_provider = CaptureProvider::Kms;
        request.capture.output = "kms:card1/conn=34/crtc=56/plane=78".into();
        assert!(request.validate(false).is_ok());
        let configuration = &request.arm(42)["configuration"];
        assert_eq!(configuration["capture_provider"], "kms");
        assert_eq!(
            configuration["output"],
            "kms:card1/conn=34/crtc=56/plane=78"
        );
        assert_eq!(configuration["constant_rate"], false);
        request.capture.constant_rate = true;
        assert_eq!(request.validate(false), Err("constant_rate_requires_wgc"));
    }

    #[test]
    fn constant_rate_capture_is_wgc_only_and_reaches_session_start() {
        let mut request = open();
        assert!(!request.capture.constant_rate);
        request.capture.capture_provider = CaptureProvider::Wgc;
        request.capture.constant_rate = true;
        assert!(request.validate(false).is_ok());

        let arm = request.arm(41);
        assert_eq!(arm["configuration"]["capture_provider"], "wgc");
        assert_eq!(arm["configuration"]["constant_rate"], true);

        request.capture.capture_provider = CaptureProvider::Dxgi;
        assert_eq!(request.validate(false), Err("constant_rate_requires_wgc"));
    }

    #[test]
    fn pipewire_capture_is_valid_and_serializes_portal_source_to_stream_session() {
        let mut request = open();
        request.capture.capture_provider = CaptureProvider::PipeWire;
        request.capture.output = "portal-selected-session-source".into();

        assert!(request.validate(false).is_ok());
        let start = request.arm(41)["configuration"].clone();
        assert_eq!(start["capture_provider"], "pipewire");
        assert_eq!(start["output"], "portal-selected-session-source");
        assert_eq!(start["encoder"], 0);
        let decoded: CaptureProvider = serde_json::from_value(start["capture_provider"].clone())
            .expect("serialized PipeWire provider is accepted by the session model");
        assert!(matches!(decoded, CaptureProvider::PipeWire));

        request.capture.encoder = EncoderSelection::Backend(EncoderBackend::Auto);
        assert_eq!(request.arm(41)["configuration"]["encoder"], "auto");
        request.capture.encoder = EncoderSelection::Index(7);
        assert_eq!(request.arm(41)["configuration"]["encoder"], 7);
    }

    #[test]
    fn announce_matching_requires_the_exact_supported_profile() {
        let profile = matching_profile();
        let encrypted = changed_announce("x-ss-general.encryptionEnabled", "7");
        let primary = parse_announce(encrypted.as_bytes()).unwrap();
        assert_eq!(
            (
                primary.video.width,
                primary.video.height,
                primary.video.fps,
                primary.video.bitrate_kbps,
                primary.packet_size,
                primary.audio.packet_duration_ms,
            ),
            (1920, 1080, 60, 16000, 1392, 5)
        );
        assert!(profile.matches(&primary));

        let original = parse_announce(PRIMARY_ANNOUNCE.as_bytes()).unwrap();
        assert!(!profile.matches(&original), "unencrypted ANNOUNCE matched");

        for (name, value) in [
            ("x-ss-general.encryptionEnabled", "5"),
            ("x-nv-vqos[0].fec.minRequiredFecPackets", "1"),
            ("x-nv-video[0].encoderCscMode", "3"),
            ("x-nv-video[0].maxNumReferenceFrames", "0"),
            ("x-nv-aqos.packetDuration", "10"),
        ] {
            let announce_text = changed_announce(name, value);
            let announce = parse_announce(announce_text.as_bytes()).unwrap();
            assert!(!profile.matches(&announce), "matched {name}={value}");
        }

        let fec_percent = format!("{encrypted}a=x-nv-vqos[0].fec.repairPercent:19\r\n");
        let announce = parse_announce(fec_percent.as_bytes()).unwrap();
        assert!(
            !profile.matches(&announce),
            "matched a different FEC percent"
        );

        let mut zero_reference_profile = profile.clone();
        zero_reference_profile.max_reference_frames = 0;
        let zero_reference = changed_announce("x-nv-video[0].maxNumReferenceFrames", "0");
        let zero_reference = zero_reference.replace(
            "a=x-ss-general.encryptionEnabled:0 ",
            "a=x-ss-general.encryptionEnabled:7 ",
        );
        let announce = parse_announce(zero_reference.as_bytes()).unwrap();
        assert!(zero_reference_profile.matches(&announce));
    }
    #[test]
    fn software_options_and_backend_reach_stream_start_exactly() {
        let mut request = open();
        request.capture.encoder =
            EncoderSelection::Backend(amaterasu_module_sdk::EncoderBackend::Software);
        request.sw_preset = Some("slow".into());
        request.sw_tune = Some(String::new());
        assert!(request.validate(false).is_ok());
        let started = request.arm(51);
        assert_eq!(started["configuration"]["encoder"], "software");
        assert_eq!(
            started["configuration"]["configuration"]["sw_preset"],
            "slow"
        );
        assert_eq!(started["configuration"]["configuration"]["sw_tune"], "");
        request.sw_tune = Some("film\n".into());
        assert_eq!(
            request.validate_capture(),
            Err("invalid_software_encoder_options")
        );
    }
}
