//! Caller-owned Moonlight launch orchestration.
//!
//! The wire layer authenticates the TLS peer and parses Moonlight fields. This
//! controller owns the resulting application and RTSP operations until the
//! successful HTTP reply has been re-authorized and completely written.
use amaterasu_module_sdk::{
    EncoderSelection, NvencSettings, NvencSettingsOverrides, SoftwareEncoderOptions,
};
mod call;
mod record;
mod workflow;

#[cfg(test)]
mod tests {
    include!("launch/tests.rs");
    include!("launch/audio_tests.rs");
    include!("launch/display_mutation_tests.rs");
    include!("launch/lifecycle_tests.rs");
}

use crate::encoder_snapshot::{
    CodecAdvertisement, CodecOffer, EncoderSnapshot, StreamMode, unknown_encoders_offer,
};
use crate::frame_limiter::FrameLimiterSettings;
use crate::preparation::{LegacyPreparationStep, PreparationStep};
use crate::wire::{ClientConfigOverrides, Reply, xml};
use amaterasu_module_sdk::{Command, ModuleResult, Response};
use record::{Record, Stage, State};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr},
    time::{Duration, Instant},
};
use workflow::Job;

pub(crate) type Transport = ModuleResult<Response>;
pub(crate) type Send<'a> = dyn FnMut(Command) -> Transport + 'a;

const MAX_RECORDS: usize = 32;
pub(crate) const DESKTOP_APP_ID: u32 = i32::MAX as u32;
pub(crate) const PORTAL_SELECTED_SESSION_SOURCE: &str = "portal-selected-session-source";
/// Asks the stream session to allocate a per-stream virtual output and
/// capture it directly, instead of a user-selected portal source.
pub(crate) const OWNED_DISPLAY_OUTPUT: &str = "amaterasu-owned-display";
const INITIAL_DEADLINE: Duration = Duration::from_secs(40);
const DEFAULT_CLEANUP_BUDGET: Duration = Duration::from_secs(20);
// Launch/1 contract: provider 321s plus eight raw undos of 300s and 3s containment.
const MAX_APPLICATION_CLEANUP_BUDGET_MS: u64 = 2_745_000;
// RTSP close 15s, lookup 5s, history release 5s, and 5s for asynchronous polling.
const STREAM_CLEANUP_MARGIN_MS: u64 = 30_000;
const CLEANUP_POLL_INTERVAL: Duration = Duration::from_millis(100);
const MONITOR_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VideoEncryptionPolicySnapshot {
    pub(crate) lan_mode: i64,
    pub(crate) wan_mode: i64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct LaunchRequest {
    pub app_id: u32,
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    /// Moonlight's localAudioPlayMode bit selecting ordinary host audio.
    pub host_audio_enabled: bool,
    /// Moonlight's optional continuousAudio request for silence-padded capture.
    pub continuous_audio: bool,
    /// Authenticated Moonlight surroundAudioInfo selection (2, 6, or 8 channels).
    pub audio_channels: u32,
    /// Moonlight's optional per-launch device-name override (`clientName`).
    pub device_name: Option<String>,
    pub remote_input_key: [u8; 16],
    pub key_id: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhysicalDisplayMode {
    pub width: u32,
    pub height: u32,
    pub refresh_millihz: u32,
}

impl PhysicalDisplayMode {
    fn parse(value: &str) -> Option<Self> {
        let mut parts = value.split('x');
        let width = decimal_component(parts.next()?)?;
        let height = decimal_component(parts.next()?)?;
        let refresh = parts.next()?;
        if parts.next().is_some() {
            return None;
        }
        let refresh_millihz = if let Some((whole, fractional)) = refresh.split_once('.') {
            let whole = decimal_component(whole)?;
            if fractional.is_empty()
                || fractional.len() > 3
                || !fractional.bytes().all(|byte| byte.is_ascii_digit())
            {
                return None;
            }
            let scale = 10_u32.pow(3 - fractional.len() as u32);
            whole
                .checked_mul(1_000)?
                .checked_add(fractional.parse::<u32>().ok()?.checked_mul(scale)?)?
        } else {
            let rate = decimal_component(refresh)?;
            if rate > 1_000 {
                rate
            } else {
                rate.checked_mul(1_000)?
            }
        };
        (10_000..=1_000_000)
            .contains(&refresh_millihz)
            .then_some(Self {
                width,
                height,
                refresh_millihz,
            })
    }
}

fn decimal_component(value: &str) -> Option<u32> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let component = value.parse::<u32>().ok()?;
    (1..=i32::MAX as u32)
        .contains(&component)
        .then_some(component)
}

#[derive(Clone, PartialEq)]
pub struct PeerIdentity {
    remote: IpAddr,
    certificate: Vec<u8>,
    client_id: Option<String>,
    certificate_id: Option<String>,
    client_fec_percentage: Option<u8>,
    client_max_bitrate: Option<i32>,
    client_qp: Option<i32>,
    client_minimum_fps_target: Option<f64>,
    client_video_max_batch_size_kb: Option<u8>,
    client_capture: Option<CaptureMode>,
    client_stream_audio: Option<bool>,
    client_audio_sink: Option<String>,
    client_virtual_sink: Option<String>,
    client_audio_sink_capture_only: Option<bool>,
    client_back_button_timeout: Option<i32>,
    client_controller: Option<bool>,
    client_gamepad: Option<String>,
    client_keyboard: Option<bool>,
    client_mouse: Option<bool>,
    client_native_pen_touch: Option<bool>,
    client_ds4_back_as_touchpad_click: Option<bool>,
    client_motion_as_ds4: Option<bool>,
    client_touchpad_as_ds4: Option<bool>,
    client_ds5_inputtino_randomize_mac: Option<bool>,
    client_proton_dualsense_compatibility: Option<bool>,
    client_high_resolution_scrolling: Option<bool>,
    client_always_send_scancodes: Option<bool>,
    client_key_rightalt_to_key_win: Option<bool>,
    client_keybindings: Option<amaterasu_input_policy::KeyBindings>,
    client_key_repeat_delay: Option<u32>,
    client_key_repeat_frequency: Option<f64>,
    client_frame_limiter_settings: FrameLimiterSettings,
    client_display_overrides: Value,
    client_display_mode: Option<PhysicalDisplayMode>,
    client_software_encoder: SoftwareEncoderOptions,
    client_nvenc_settings: NvencSettingsOverrides,
    client_nvenc_spatial_aq: Option<bool>,
}

impl PeerIdentity {
    pub fn new(remote: IpAddr, certificate: Vec<u8>) -> Result<Self, &'static str> {
        if invalid_peer(remote)
            || certificate.is_empty()
            || certificate.len() > amaterasu_identity::MAX_CERTIFICATE_BYTES
        {
            return Err("invalid_peer_identity");
        }
        Ok(Self {
            remote,
            certificate,
            client_id: None,
            certificate_id: None,
            client_fec_percentage: None,
            client_max_bitrate: None,
            client_qp: None,
            client_minimum_fps_target: None,
            client_video_max_batch_size_kb: None,
            client_capture: None,
            client_stream_audio: None,
            client_audio_sink: None,
            client_virtual_sink: None,
            client_audio_sink_capture_only: None,
            client_back_button_timeout: None,
            client_controller: None,
            client_gamepad: None,
            client_keyboard: None,
            client_mouse: None,
            client_native_pen_touch: None,
            client_ds4_back_as_touchpad_click: None,
            client_motion_as_ds4: None,
            client_touchpad_as_ds4: None,
            client_ds5_inputtino_randomize_mac: None,
            client_proton_dualsense_compatibility: None,
            client_high_resolution_scrolling: None,
            client_always_send_scancodes: None,
            client_key_rightalt_to_key_win: None,
            client_keybindings: None,
            client_key_repeat_delay: None,
            client_key_repeat_frequency: None,
            client_frame_limiter_settings: FrameLimiterSettings::default(),
            client_display_overrides: json!({}),
            client_display_mode: None,
            client_software_encoder: SoftwareEncoderOptions::default(),
            client_nvenc_settings: NvencSettingsOverrides::default(),
            client_nvenc_spatial_aq: None,
        })
    }

    pub(crate) fn with_paired_identity(
        mut self,
        client_id: String,
        certificate_id: String,
        config_overrides: ClientConfigOverrides,
    ) -> Result<Self, &'static str> {
        let client_display_overrides = config_overrides.display_overrides();
        let client_nvenc_settings = NvencSettingsOverrides {
            nvenc_preset: config_overrides.nvenc_preset,
            nvenc_h264_cavlc: config_overrides.nvenc_h264_cavlc,
            nvenc_twopass: config_overrides.nvenc_twopass,
            nvenc_vbv_increase: config_overrides.nvenc_vbv_increase,
            nvenc_split_encode: config_overrides.nvenc_split_encode,
            nvenc_realtime_hags: config_overrides.nvenc_realtime_hags,
            nvenc_opengl_vulkan_on_dxgi: config_overrides.nvenc_opengl_vulkan_on_dxgi,
            nvenc_latency_over_power: config_overrides.nvenc_latency_over_power,
            vaapi_strict_rc_buffer: config_overrides.vaapi_strict_rc_buffer,
        };
        let client_nvenc_spatial_aq = config_overrides.nvenc_spatial_aq;
        client_nvenc_settings
            .validate()
            .map_err(|_| "invalid_paired_identity")?;
        let client_software_encoder = SoftwareEncoderOptions {
            sw_preset: config_overrides.sw_preset.clone(),
            sw_tune: config_overrides.sw_tune.clone(),
            encoder: config_overrides.encoder,
            min_threads: config_overrides.min_threads,
        };
        client_software_encoder
            .validate()
            .map_err(|_| "invalid_paired_identity")?;
        let client_capture = config_overrides.capture;
        let client_display_mode = match config_overrides.display_mode.as_deref() {
            Some(mode) => Some(PhysicalDisplayMode::parse(mode).ok_or("invalid_paired_identity")?),
            None => None,
        };
        let ClientConfigOverrides {
            fec_percentage,
            max_bitrate,
            qp,
            minimum_fps_target,
            video_max_batch_size_kb,
            stream_audio,
            audio_sink,
            virtual_sink,
            audio_sink_capture_only,
            back_button_timeout,
            controller,
            gamepad,
            keyboard,
            mouse,
            native_pen_touch,
            ds4_back_as_touchpad_click,
            motion_as_ds4,
            touchpad_as_ds4,
            ds5_inputtino_randomize_mac,
            proton_dualsense_compatibility,
            high_resolution_scrolling,
            always_send_scancodes,
            key_rightalt_to_key_win,
            keybindings,
            key_repeat_delay,
            key_repeat_frequency,
            frame_limiter_enable,
            frame_limiter_fps_limit,
            frame_limiter_provider,
            frame_limiter_disable_vsync,
            frame_limiter_auto_virtual_framegen,
            rtss_frame_limit_type,
            ..
        } = config_overrides;
        let client_frame_limiter_settings = FrameLimiterSettings {
            frame_limiter_enable,
            frame_limiter_fps_limit,
            frame_limiter_provider,
            frame_limiter_disable_vsync,
            frame_limiter_auto_virtual_framegen,
            rtss_frame_limit_type,
            ..FrameLimiterSettings::default()
        };
        if !valid_client_id(&client_id)
            || !valid_fingerprint(&certificate_id)
            || !fingerprint(&self.certificate).eq_ignore_ascii_case(&certificate_id)
            || fec_percentage == Some(0)
            || minimum_fps_target
                .is_some_and(|target| !target.is_finite() || !(0.0..=1000.0).contains(&target))
            || video_max_batch_size_kb.is_some_and(|size| size > 64)
            || audio_sink
                .as_deref()
                .is_some_and(|value| !valid_audio_sink_override(value))
            || virtual_sink
                .as_deref()
                .is_some_and(|value| !valid_audio_sink_override(value))
            || gamepad
                .as_deref()
                .is_some_and(|profile| !valid_gamepad_profile(profile))
            || key_repeat_delay.is_some_and(|delay| delay > i32::MAX as u32)
            || key_repeat_frequency
                .is_some_and(|frequency| !frequency.is_finite() || frequency < 0.0)
            || client_frame_limiter_settings.validate().is_err()
            || workflow::parse_application_config_overrides(Some(&client_display_overrides))
                .is_err()
        {
            return Err("invalid_paired_identity");
        }
        self.client_id = Some(client_id);
        self.certificate_id = Some(certificate_id.to_ascii_lowercase());
        self.client_fec_percentage = fec_percentage;
        self.client_max_bitrate = max_bitrate;
        self.client_qp = qp;
        self.client_minimum_fps_target = minimum_fps_target;
        self.client_video_max_batch_size_kb = video_max_batch_size_kb;
        self.client_capture = client_capture;
        self.client_stream_audio = stream_audio;
        self.client_audio_sink = audio_sink;
        self.client_virtual_sink = virtual_sink;
        self.client_audio_sink_capture_only = audio_sink_capture_only;
        self.client_back_button_timeout = back_button_timeout;
        self.client_controller = controller;
        self.client_gamepad = gamepad;
        self.client_keyboard = keyboard;
        self.client_mouse = mouse;
        self.client_native_pen_touch = native_pen_touch;
        self.client_ds4_back_as_touchpad_click = ds4_back_as_touchpad_click;
        self.client_motion_as_ds4 = motion_as_ds4;
        self.client_touchpad_as_ds4 = touchpad_as_ds4;
        self.client_ds5_inputtino_randomize_mac = ds5_inputtino_randomize_mac;
        self.client_proton_dualsense_compatibility = proton_dualsense_compatibility;
        self.client_high_resolution_scrolling = high_resolution_scrolling;
        self.client_always_send_scancodes = always_send_scancodes;
        self.client_key_rightalt_to_key_win = key_rightalt_to_key_win;
        self.client_keybindings = keybindings;
        self.client_key_repeat_delay = key_repeat_delay;
        self.client_key_repeat_frequency = key_repeat_frequency;
        self.client_frame_limiter_settings = client_frame_limiter_settings;
        self.client_display_overrides = client_display_overrides;
        self.client_display_mode = client_display_mode;
        self.client_software_encoder = client_software_encoder;
        self.client_nvenc_settings = client_nvenc_settings;
        self.client_nvenc_spatial_aq = client_nvenc_spatial_aq;
        Ok(self)
    }

    fn paired(&self) -> bool {
        self.client_id.is_some() && self.certificate_id.is_some()
    }

    #[cfg(test)]
    pub(crate) fn paired_client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
    }
}

fn valid_gamepad_profile(profile: &str) -> bool {
    #[cfg(windows)]
    {
        matches!(
            profile,
            "auto"
                | "x360"
                | "vhf"
                | "vhf_xbox"
                | "vhf_xbox_one"
                | "vhf_ds4"
                | "vhf_ds5"
                | "vhf_switch"
                | "ds4"
        )
    }
    #[cfg(target_os = "linux")]
    {
        matches!(profile, "auto" | "xone" | "ds4" | "ds5" | "switch")
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        profile == "auto"
    }
}

fn valid_client_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-:/".contains(&byte))
}

fn valid_fingerprint(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) fn valid_audio_sink_override(value: &str) -> bool {
    value.len() <= 4096 && !value.chars().any(char::is_control)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct AudioSinkCaptureOnlyOverrides {
    pub application: Option<bool>,
    pub client: Option<bool>,
}

pub(crate) fn capture_sink_without_routing(
    global_enabled: bool,
    overrides: AudioSinkCaptureOnlyOverrides,
    resolved_configured_audio_sink: Option<&str>,
    selected_audio_sink: &str,
    virtual_sink: Option<&str>,
) -> bool {
    let enabled = overrides
        .client
        .or(overrides.application)
        .unwrap_or(global_enabled);
    enabled
        && resolved_configured_audio_sink.is_some_and(|configured_sink| {
            !configured_sink.is_empty() && configured_sink == selected_audio_sink
        })
        && virtual_sink.is_none_or(str::is_empty)
}

fn fingerprint(certificate: &[u8]) -> String {
    Sha256::digest(certificate)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DesktopSettings {
    pub enabled: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StreamingConfig {
    pub capture: CaptureConfig,
    pub profile: StreamProfile,
    #[serde(default)]
    pub desktop: DesktopSettings,
}

impl StreamingConfig {
    pub fn validate(&self) -> Result<(), &'static str> {
        self.capture.validate()?;
        self.profile.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureConfig {
    pub capture_provider: CaptureProvider,
    pub output: String,
    pub encoder: EncoderSelection,
    pub audio_endpoint: String,
}

impl CaptureConfig {
    fn validate(&self) -> Result<(), &'static str> {
        if self.encoder.validate().is_err()
            || !valid_label(&self.output, 512)
            || !valid_label(&self.audio_endpoint, 4096)
        {
            return Err("invalid_streaming_capture");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CaptureMode {
    #[default]
    Auto,
    Ddx,
    Wgc,
    Wgcc,
    #[serde(rename = "pipewire")]
    PipeWire,
    X11,
    Kms,
}

impl CaptureMode {
    pub fn resolve(self, bootstrap_provider: CaptureProvider) -> (CaptureProvider, bool) {
        match self {
            Self::Auto => (bootstrap_provider, false),
            Self::Ddx => (CaptureProvider::Dxgi, false),
            Self::Wgc => (CaptureProvider::Wgc, false),
            Self::Wgcc => (CaptureProvider::Wgc, true),
            Self::PipeWire => (CaptureProvider::PipeWire, false),
            Self::X11 => (CaptureProvider::X11, false),
            Self::Kms => (CaptureProvider::Kms, false),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Ddx => "ddx",
            Self::Wgc => "wgc",
            Self::Wgcc => "wgcc",
            Self::PipeWire => "pipewire",
            Self::X11 => "x11",
            Self::Kms => "kms",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StreamProfile {
    /// Legacy single-codec setting, still accepted in stored configuration.
    /// It no longer selects the codec: each launch offers the codecs its
    /// encoders support and the client negotiates one in RTSP ANNOUNCE.
    #[serde(
        default,
        skip_serializing_if = "amaterasu_media::VideoCodec::is_default"
    )]
    pub codec: amaterasu_media::VideoCodec,
    pub max_width: u32,
    pub max_height: u32,
    pub max_fps: u32,
    pub bitrate_kbps: u32,
    pub max_reference_frames: u32,
    pub packet_size: usize,
    pub fec_percentage: u8,
    pub min_parity_shards: u8,
    pub max_fec_blocks: u8,
    pub packet_ms: u32,
    pub audio_bitrate: u32,
    pub encrypt_video: bool,
    pub encrypt_audio: bool,
    pub permit_legacy_audio_iv_wrap: bool,
}

impl StreamProfile {
    fn validate(&self) -> Result<(), &'static str> {
        if !(16..=3840).contains(&self.max_width)
            || !(16..=2160).contains(&self.max_height)
            || !self.max_width.is_multiple_of(2)
            || !self.max_height.is_multiple_of(2)
            || !(1..=120).contains(&self.max_fps)
            || !(100..=100_000).contains(&self.bitrate_kbps)
            || self.max_reference_frames > 1
            || !matches!(self.packet_ms, 5 | 10)
            || !(6_000..=512_000).contains(&self.audio_bitrate)
        {
            return Err("invalid_streaming_profile");
        }
        // Framing and FEC limits do not depend on the codec.
        amaterasu_gamestream::video::VideoPacketizer::new(
            amaterasu_gamestream::video::VideoConfig {
                packet_size: self.packet_size,
                fec_percentage: self.fec_percentage,
                min_parity_shards: self.min_parity_shards,
                max_fec_blocks: self.max_fec_blocks,
                encrypted: false,
            },
        )
        .map_err(|_| "invalid_streaming_profile")?;
        Ok(())
    }

    fn accepts(&self, request: &LaunchRequest) -> bool {
        (16..=self.max_width).contains(&request.width)
            && (16..=self.max_height).contains(&request.height)
            && request.width.is_multiple_of(2)
            && request.height.is_multiple_of(2)
            && (1..=self.max_fps).contains(&request.fps)
    }
}

struct PendingResume {
    connection: u64,
    record: u64,
    request: LaunchRequest,
    peer: PeerIdentity,
}

pub struct Controller {
    config: Option<StreamingConfig>,
    /// Latest encoder enumeration; `None` until the first one completes.
    encoder_snapshot: Option<EncoderSnapshot>,
    configured_output_name: Option<String>,
    configured_audio_sink: Option<String>,
    configured_virtual_sink: Option<String>,
    global_preparation: Vec<PreparationStep>,
    legacy_global_preparation: Vec<LegacyPreparationStep>,
    global_frame_limiter_settings: FrameLimiterSettings,
    global_display_revision: Option<u64>,
    global_display_policy: Value,
    global_audio_sink_capture_only: bool,
    configured_capture: CaptureMode,
    output_settings_ready: bool,
    global_fec_percentage: Option<u8>,
    global_stream_audio: bool,
    global_video_encryption_policy: Option<VideoEncryptionPolicySnapshot>,
    global_ping_timeout_ms: u32,
    global_video_max_batch_size_kb: u8,
    global_max_bitrate_kbps: Option<u32>,
    global_qp: i32,
    global_minimum_fps_target: f64,
    global_wgc_pacing_smoothing: bool,
    software_encoder: SoftwareEncoderOptions,
    nvenc_settings: NvencSettings,
    nvenc_spatial_aq: bool,
    device_name: String,
    records: BTreeMap<u64, Record>,
    pending_resume: Option<PendingResume>,
    job: Option<Job>,
    nonce: [u8; 16],
    next_id: u64,
    sequence: u64,
}

impl Controller {
    pub fn new(config: Option<StreamingConfig>) -> Result<Self, &'static str> {
        if let Some(config) = &config {
            config.validate()?;
        }
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).map_err(|_| "random_unavailable")?;
        Ok(Self {
            config,
            encoder_snapshot: None,
            configured_output_name: None,
            configured_audio_sink: None,
            configured_virtual_sink: None,
            global_preparation: Vec::new(),
            legacy_global_preparation: Vec::new(),
            global_frame_limiter_settings: FrameLimiterSettings::default(),
            global_display_revision: None,
            global_display_policy: json!({}),
            global_audio_sink_capture_only: false,
            configured_capture: CaptureMode::Auto,
            output_settings_ready: true,
            global_fec_percentage: None,
            global_stream_audio: true,
            global_video_encryption_policy: None,
            global_ping_timeout_ms: 10_000,
            global_video_max_batch_size_kb: 64,
            global_max_bitrate_kbps: None,
            global_qp: 28,
            global_minimum_fps_target: 20.0,
            global_wgc_pacing_smoothing: true,
            software_encoder: SoftwareEncoderOptions::default(),
            nvenc_settings: NvencSettings::default(),
            nvenc_spatial_aq: false,
            device_name: "Amaterasu".into(),
            records: BTreeMap::new(),
            pending_resume: None,
            job: None,
            nonce,
            next_id: 0,
            sequence: 0,
        })
    }

    pub fn supported(&self) -> bool {
        self.config.is_some()
    }

    pub fn set_encoder_snapshot(&mut self, snapshot: EncoderSnapshot) {
        self.encoder_snapshot = Some(snapshot);
    }

    /// Serverinfo codec values. Until encoders are enumerated, only the
    /// H.264 baseline is advertised.
    pub fn codec_advertisement(&self) -> CodecAdvertisement {
        if self.config.is_none() {
            return CodecAdvertisement::NONE;
        }
        self.encoder_snapshot.as_ref().map_or(
            EncoderSnapshot::default().advertisement(),
            EncoderSnapshot::advertisement,
        )
    }

    /// The codecs this launch may negotiate, or the reason no encoder can
    /// serve the requested mode. This runs before any launch state exists.
    fn codec_offer(
        &self,
        config: &StreamingConfig,
        request: &LaunchRequest,
    ) -> Result<CodecOffer, &'static str> {
        let mode = StreamMode {
            width: request.width,
            height: request.height,
            fps: request.fps,
        };
        match &self.encoder_snapshot {
            Some(snapshot) => snapshot.offer(config.capture.encoder.clone(), mode),
            None => unknown_encoders_offer(mode),
        }
    }

    pub(crate) fn desktop_enabled(&self) -> bool {
        self.config
            .as_ref()
            .is_some_and(|config| config.desktop.enabled)
    }

    pub fn set_output_name_settings(&mut self, ready: bool, configured_output_name: Option<&str>) {
        self.output_settings_ready = ready;
        self.configured_output_name = configured_output_name.map(str::to_owned);
    }

    pub fn set_audio_sink_settings(&mut self, configured_audio_sink: Option<&str>) {
        self.configured_audio_sink = configured_audio_sink.map(str::to_owned);
    }

    pub fn set_virtual_sink_settings(&mut self, configured_virtual_sink: Option<&str>) {
        self.configured_virtual_sink = configured_virtual_sink.map(str::to_owned);
    }

    pub fn set_global_preparation(&mut self, preparation: &[PreparationStep]) {
        self.global_preparation = preparation.to_vec();
    }

    pub fn set_legacy_global_preparation(&mut self, preparation: &[LegacyPreparationStep]) {
        self.legacy_global_preparation = preparation.to_vec();
    }

    pub fn set_global_frame_limiter_settings(&mut self, settings: &FrameLimiterSettings) {
        self.global_frame_limiter_settings = settings.clone();
    }

    pub fn set_global_display_policy(&mut self, revision: u64, policy: Value) {
        self.global_display_revision = Some(revision);
        self.global_display_policy = policy;
    }

    pub fn set_audio_sink_capture_only(&mut self, enabled: bool) {
        self.global_audio_sink_capture_only = enabled;
    }

    pub fn set_capture_mode(&mut self, configured_capture: CaptureMode) {
        self.configured_capture = configured_capture;
    }

    pub fn set_global_stream_audio(&mut self, stream_audio: bool) {
        self.global_stream_audio = stream_audio;
    }

    pub fn set_global_fec_percentage(&mut self, fec_percentage: Option<u8>) {
        self.global_fec_percentage = fec_percentage.filter(|percentage| *percentage != 0);
    }

    pub fn set_global_video_encryption_modes(&mut self, lan_mode: u8, wan_mode: u8) {
        self.global_video_encryption_policy = Some(VideoEncryptionPolicySnapshot {
            lan_mode: i64::from(lan_mode),
            wan_mode: i64::from(wan_mode),
        });
    }

    pub fn set_global_ping_timeout_ms(&mut self, ping_timeout_ms: u32) {
        self.global_ping_timeout_ms = ping_timeout_ms;
    }

    pub fn set_global_video_max_batch_size_kb(&mut self, value: u8) {
        self.global_video_max_batch_size_kb = match value {
            16 | 32 | 64 => value,
            _ => 64,
        };
    }

    pub fn set_global_max_bitrate_kbps(&mut self, value: Option<u32>) {
        self.global_max_bitrate_kbps = value;
    }

    pub fn set_global_qp(&mut self, value: i32) {
        self.global_qp = value;
    }

    pub fn set_global_minimum_fps_target(&mut self, target: f64) {
        self.global_minimum_fps_target = target;
    }

    pub fn set_software_encoder_options(&mut self, options: SoftwareEncoderOptions) {
        self.software_encoder = options;
    }

    pub fn set_nvenc_settings(&mut self, settings: NvencSettings) {
        self.nvenc_settings = settings;
    }

    pub fn set_nvenc_spatial_aq(&mut self, enabled: bool) {
        self.nvenc_spatial_aq = enabled;
    }

    pub fn set_global_wgc_pacing_smoothing(&mut self, enabled: bool) {
        self.global_wgc_pacing_smoothing = enabled;
    }

    pub fn set_device_name(&mut self, device_name: &str) {
        self.device_name = device_name.to_owned();
    }

    pub fn busy(&self) -> bool {
        self.records.values().any(|record| !record.state.terminal())
    }

    pub fn launch(
        &mut self,
        connection: u64,
        request: LaunchRequest,
        peer: PeerIdentity,
        now: Instant,
    ) -> Option<Reply> {
        let Some(config) = &self.config else {
            return Some(private_error(503, "streaming is disabled"));
        };
        if !self.output_settings_ready {
            return Some(private_error(503, "stream settings are loading"));
        }
        if !peer.paired() {
            return Some(private_error(401, "authenticated paired TLS is required"));
        }
        let desktop = request.app_id == DESKTOP_APP_ID;
        if request.app_id == 0
            || request.app_id > i32::MAX as u32
            || (desktop && !config.desktop.enabled)
            || !config.profile.accepts(&request)
            || !matches!(request.audio_channels, 2 | 6 | 8)
            || (request.audio_channels == 6 && config.profile.audio_bitrate < 256_000)
            || (request.audio_channels == 8 && config.profile.audio_bitrate < 512_000)
            || request
                .device_name
                .as_deref()
                .is_some_and(|name| !valid_device_name(name))
        {
            return Some(private_error(400, "unsupported streaming request"));
        }
        let device_name = request
            .device_name
            .as_deref()
            .filter(|name| !name.is_empty())
            .unwrap_or(&self.device_name)
            .to_owned();
        let global_fec_percentage = self
            .global_fec_percentage
            .unwrap_or(config.profile.fec_percentage);
        let global_stream_audio = self.global_stream_audio;
        let global_video_encryption_policy = self.global_video_encryption_policy;
        let global_audio_sink_capture_only = self.global_audio_sink_capture_only;
        let global_preparation = self.global_preparation.clone();
        let legacy_global_preparation = self.legacy_global_preparation.clone();
        let global_frame_limiter_settings = self.global_frame_limiter_settings.clone();
        let client_frame_limiter_settings = peer.client_frame_limiter_settings.clone();
        let global_ping_timeout_ms = self.global_ping_timeout_ms;
        let global_video_max_batch_size_kb = self.global_video_max_batch_size_kb;
        let global_max_bitrate_kbps = self.global_max_bitrate_kbps;
        let global_qp = self.global_qp;
        let global_minimum_fps_target = self.global_minimum_fps_target;
        let global_wgc_pacing_smoothing = self.global_wgc_pacing_smoothing;
        let startup_encoder = config.capture.encoder.clone();
        let capture_output = self
            .configured_output_name
            .as_deref()
            .filter(|output_name| !output_name.is_empty())
            .unwrap_or(&config.capture.output)
            .to_owned();
        let audio_endpoint = self
            .configured_audio_sink
            .as_deref()
            .unwrap_or(&config.capture.audio_endpoint)
            .to_owned();
        let bootstrap_audio_endpoint = config.capture.audio_endpoint.clone();
        let bootstrap_capture_provider = config.capture.capture_provider;
        let global_capture_mode = self.configured_capture;
        let selected_capture_mode = peer.client_capture.unwrap_or(global_capture_mode);
        let (capture_provider, constant_rate) =
            selected_capture_mode.resolve(bootstrap_capture_provider);
        let capture_output = if capture_provider == CaptureProvider::PipeWire {
            if config.capture.output == OWNED_DISPLAY_OUTPUT {
                OWNED_DISPLAY_OUTPUT.to_owned()
            } else {
                PORTAL_SELECTED_SESSION_SOURCE.to_owned()
            }
        } else {
            capture_output
        };

        if let Some(record) = self
            .records
            .values_mut()
            .find(|record| record.request.remote_input_key == request.remote_input_key)
        {
            if record.peer == peer && record.request == request {
                if matches!(record.state, State::Ready) {
                    record.launch_connection = Some(connection);
                    return Some(success_reply(record));
                }
                if !record.state.terminal() {
                    return Some(private_error(409, "launch is already in progress"));
                }
                return Some(private_error(409, "launch key was already used"));
            }
            return Some(private_error(
                409,
                "launch key conflicts with an existing request",
            ));
        }
        if self.records.len() >= MAX_RECORDS
            || self.records.values().any(|record| !record.state.terminal())
        {
            return Some(private_error(503, "another stream is active"));
        }
        let video_codec_offer = match self.codec_offer(config, &request) {
            Ok(offer) => offer,
            Err(message) => return Some(private_error(503, message)),
        };

        let id = match self.allocate_id() {
            Ok(id) => id,
            Err(code) => return Some(private_error(503, code)),
        };
        let connect_data = match random_nonzero_u32() {
            Ok(value) => value,
            Err(code) => return Some(private_error(503, code)),
        };
        let mut record = Record::new(
            id,
            peer,
            request,
            device_name,
            operation_id(&self.nonce, id, "application"),
            operation_id(&self.nonce, id, "rtsp"),
            connect_data,
            global_fec_percentage,
            global_stream_audio,
            global_video_encryption_policy,
            global_audio_sink_capture_only,
            self.configured_audio_sink.clone(),
            self.configured_virtual_sink.clone(),
            global_preparation,
            legacy_global_preparation,
            global_frame_limiter_settings,
            client_frame_limiter_settings,
            global_ping_timeout_ms,
            global_video_max_batch_size_kb,
            global_max_bitrate_kbps,
            global_qp,
            global_minimum_fps_target,
            global_wgc_pacing_smoothing,
            capture_output,
            bootstrap_capture_provider,
            global_capture_mode,
            audio_endpoint,
            bootstrap_audio_endpoint,
            capture_provider,
            constant_rate,
            connection,
            now + INITIAL_DEADLINE,
        );
        record.desktop = desktop;
        record.video_codec_offer = video_codec_offer;
        record.encoder_snapshot = self.encoder_snapshot.clone();
        record.global_display_revision = self.global_display_revision;
        record.global_software_encoder = self.software_encoder.clone();
        record.effective_software_encoder = self
            .software_encoder
            .with_overrides(&record.peer.client_software_encoder);
        record.global_nvenc_settings = self.nvenc_settings.clone();
        record.effective_nvenc_settings = self
            .nvenc_settings
            .with_overrides(&record.peer.client_nvenc_settings);
        record.global_nvenc_spatial_aq = self.nvenc_spatial_aq;
        record.effective_nvenc_spatial_aq = record
            .peer
            .client_nvenc_spatial_aq
            .unwrap_or(self.nvenc_spatial_aq);
        record.global_qp = self.global_qp;
        record.effective_qp = record.peer.client_qp.unwrap_or(record.global_qp);
        record.selected_encoder = startup_encoder;
        record.global_display_policy = self.global_display_policy.clone();
        self.records.insert(id, record);
        None
    }

    pub fn cancel(&mut self, connection: u64, peer: &PeerIdentity, now: Instant) -> Option<Reply> {
        let cancel_pending_resume = self.pending_resume.as_ref().is_some_and(|pending| {
            self.records.get(&pending.record).is_some_and(|record| {
                record.peer.certificate == peer.certificate && record.state == State::Stopping
            })
        });
        if cancel_pending_resume {
            self.pending_resume = None;
        }
        let Some(record) = self
            .records
            .values_mut()
            .find(|record| record.peer.certificate == peer.certificate && !record.state.terminal())
        else {
            if self.records.values().any(|record| !record.state.terminal()) {
                return Some(private_error(403, "stream is owned by another client"));
            }
            return Some(cancel_reply());
        };
        if cancel_pending_resume && record.state == State::Stopping {
            record.cancel_connection = Some(connection);
            return None;
        }
        if record.state == State::Stopping || record.cancel_connection.is_some() {
            return Some(private_error(409, "stream cleanup is already in progress"));
        }
        eprintln!(
            "amaterasu launch cancel requested state={:?} stage={:?}",
            record.state, record.stage
        );
        record.cancel_connection = Some(connection);
        let retry = if record.state == State::CleanupFailed {
            record.retry_cleanup(now)
        } else {
            record.request_cleanup(None, now);
            None
        };
        if let Some((phase, call)) = retry {
            self.job = Some(Job {
                record: record.id,
                phase,
                call,
                deadline: record.deadline,
            });
        }
        if let Some(job) = self.job.as_mut().filter(|job| job.record == record.id) {
            job.call.cancel();
        }
        None
    }

    pub(crate) fn resume(
        &mut self,
        connection: u64,
        request: LaunchRequest,
        peer: &PeerIdentity,
        now: Instant,
    ) -> Option<Reply> {
        let Some(config) = &self.config else {
            return Some(private_error(503, "streaming is disabled"));
        };
        if !config.desktop.enabled || request.app_id != DESKTOP_APP_ID {
            return Some(private_error(404, "Desktop session is unavailable"));
        }
        if !self.output_settings_ready {
            return Some(private_error(503, "stream settings are loading"));
        }
        if !peer.paired() {
            return Some(private_error(401, "authenticated paired TLS is required"));
        }
        if !config.profile.accepts(&request)
            || !matches!(request.audio_channels, 2 | 6 | 8)
            || (request.audio_channels == 6 && config.profile.audio_bitrate < 256_000)
            || (request.audio_channels == 8 && config.profile.audio_bitrate < 512_000)
            || request
                .device_name
                .as_deref()
                .is_some_and(|name| !valid_device_name(name))
        {
            return Some(private_error(400, "unsupported streaming request"));
        }
        if self.pending_resume.is_some() {
            return Some(private_error(409, "Desktop resume is already in progress"));
        }
        // Refuse before tearing down the live session the resume would replace.
        if let Err(message) = self.codec_offer(config, &request) {
            return Some(private_error(503, message));
        }
        if self.records.values().any(|record| {
            record.request.remote_input_key == request.remote_input_key
                && (record.peer != *peer || record.request != request)
        }) {
            return Some(private_error(
                409,
                "launch key conflicts with an existing request",
            ));
        }
        let Some(record) = self.records.values_mut().find(|record| {
            record.desktop
                && record.peer.certificate == peer.certificate
                && record.state == State::Ready
        }) else {
            return Some(private_error(404, "live Desktop session was not found"));
        };
        let id = record.id;
        record.request_cleanup(None, now);
        self.pending_resume = Some(PendingResume {
            connection,
            record: id,
            request,
            peer: peer.clone(),
        });
        None
    }

    pub fn current_game(&self, peer: &PeerIdentity) -> u32 {
        self.records
            .values()
            .find(|record| {
                record.peer.certificate == peer.certificate && record.state == State::Ready
            })
            .map_or(0, |record| record.request.app_id)
    }

    #[cfg(test)]
    pub fn poll(&mut self, now: Instant, send: &mut Send<'_>) -> Vec<(u64, Reply)> {
        self.poll_with_trust(now, send, |_| true)
    }

    pub fn poll_with_trust(
        &mut self,
        now: Instant,
        send: &mut Send<'_>,
        mut trusted: impl FnMut(&[u8]) -> bool,
    ) -> Vec<(u64, Reply)> {
        let mut replies = Vec::new();
        if let Some(mut job) = self.job.take() {
            self.advance(&mut job, now, send, &mut replies);
        }
        if self.job.is_none() {
            self.schedule(now);
        }
        let resume_ready = self.pending_resume.as_ref().is_some_and(|pending| {
            self.records.get(&pending.record).is_some_and(|record| {
                record.state.terminal() || record.state == State::CleanupFailed
            }) && self.job.is_none()
        });
        if resume_ready && let Some(pending) = self.pending_resume.take() {
            if self
                .records
                .get(&pending.record)
                .is_some_and(|record| record.state == State::Stopped)
            {
                let resume_trusted = self
                    .records
                    .get(&pending.record)
                    .is_some_and(|record| !record.revoked && trusted(&pending.peer.certificate));
                if !resume_trusted {
                    if let Some(record) = self.records.get_mut(&pending.record) {
                        record.revoked = true;
                    }
                    replies.push((
                        pending.connection,
                        private_error(401, "paired client is no longer trusted"),
                    ));
                } else {
                    if let Some(old_record) = self.records.get_mut(&pending.record)
                        && old_record.request.remote_input_key == pending.request.remote_input_key
                    {
                        // A resumed RTSP ticket may legitimately reuse Moonlight's key.
                        // The old record is terminal and no longer owns live input.
                        old_record.request.remote_input_key = [0; 16];
                    }
                    if let Some(reply) =
                        self.launch(pending.connection, pending.request, pending.peer, now)
                    {
                        replies.push((pending.connection, reply));
                    } else if let Some(record) = self
                        .records
                        .values_mut()
                        .find(|record| record.launch_connection == Some(pending.connection))
                    {
                        record.resumed = true;
                    }
                }
            } else {
                replies.push((
                    pending.connection,
                    private_error(503, "Desktop cleanup failed"),
                ));
            }
        }
        replies
    }

    pub fn reply_delivered(&mut self, connection: u64, now: Instant) {
        if let Some(record) = self
            .records
            .values_mut()
            .find(|record| record.launch_connection == Some(connection))
        {
            record.launch_connection = None;
            if record.state == State::AwaitingDelivery {
                record.adopted = true;
                record.state = State::Ready;
                record.stage = Stage::Live;
                record.next_monitor = now;
            }
        }
        if let Some(record) = self
            .records
            .values_mut()
            .find(|record| record.cancel_connection == Some(connection))
        {
            record.cancel_connection = None;
        }
    }

    pub fn connection_closed(&mut self, connection: u64, now: Instant) {
        if self
            .pending_resume
            .as_ref()
            .is_some_and(|pending| pending.connection == connection)
        {
            self.pending_resume = None;
        }
        let mut affected = None;
        for record in self.records.values_mut() {
            if record.launch_connection == Some(connection) {
                record.launch_connection = None;
                if !record.adopted {
                    record.request_cleanup(Some("launch_response_unavailable"), now);
                    affected = Some(record.id);
                }
            }
            if record.cancel_connection == Some(connection) {
                record.cancel_connection = None;
            }
        }
        if let Some(job) = self.job.as_mut().filter(|job| Some(job.record) == affected) {
            job.call.cancel();
        }
    }

    pub fn revoke_untrusted(
        &mut self,
        now: Instant,
        mut trusted: impl FnMut(&[u8]) -> bool,
    ) -> Vec<u64> {
        let mut close = Vec::new();
        if self
            .pending_resume
            .as_ref()
            .is_some_and(|pending| !trusted(&pending.peer.certificate))
            && let Some(pending) = self.pending_resume.take()
        {
            close.push(pending.connection);
        }
        let mut affected = Vec::new();
        for record in self.records.values_mut() {
            if !record.state.terminal() && !record.revoked && !trusted(&record.peer.certificate) {
                record.revoked = true;
                close.extend(record.launch_connection.take());
                close.extend(record.cancel_connection.take());
                if !matches!(record.state, State::Stopping | State::CleanupFailed) {
                    record.request_cleanup(Some("client_revoked"), now);
                    affected.push(record.id);
                }
            }
        }
        if let Some(job) = self
            .job
            .as_mut()
            .filter(|job| affected.contains(&job.record))
        {
            job.call.cancel();
        }
        close
    }

    pub fn shutdown(&mut self, send: &mut Send<'_>) {
        if let Some(job) = self.job.as_mut() {
            job.call.shutdown(send);
        }
        for record in self.records.values_mut() {
            for (_, call) in &mut record.uncertain {
                call.shutdown(send);
            }
        }
        // Synchronous module unload cannot prove downstream terminal state.
        // Provider shutdown is the backstop for already adopted resources.
    }

    fn allocate_id(&mut self) -> Result<u64, &'static str> {
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or("launch capacity exhausted")?;
        Ok(self.next_id)
    }

    fn next_operation(&mut self, record: &Record, phase: &str) -> String {
        self.sequence = self.sequence.saturating_add(1);
        format!("{}.{}.{}", record.operation_prefix(), phase, self.sequence)
    }
}

fn private_error(status: u16, message: &str) -> Reply {
    let reason = if message.len() <= 64
        && message
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || matches!(byte, b'_' | b' '))
    {
        message
    } else {
        "redacted"
    };
    eprintln!("amaterasu launch rejection status={status} reason={reason}");
    let mut reply = xml::error(status, message);
    reply.requires_paired_tls = true;
    reply
}

fn success_reply(record: &Record) -> Reply {
    let stream_width = record.request.width.to_string();
    let stream_height = record.request.height.to_string();
    let stream_fps = record.request.fps.to_string();
    let physical_width = record.physical_display_mode.width.to_string();
    let physical_height = record.physical_display_mode.height.to_string();
    let physical_refresh = record.physical_display_mode.refresh_millihz.to_string();
    let mut fields = vec![
        (
            "sessionUrl0",
            record.rtsp_url.as_deref().unwrap_or_default(),
        ),
        ("gamesession", "1"),
        ("historyActivityState", record.history_state),
        ("streamWidth", stream_width.as_str()),
        ("streamHeight", stream_height.as_str()),
        ("streamFps", stream_fps.as_str()),
        (
            "clientDisplayModeOverride",
            if record.peer.client_display_mode.is_some() {
                "1"
            } else {
                "0"
            },
        ),
        ("physicalDisplayWidth", physical_width.as_str()),
        ("physicalDisplayHeight", physical_height.as_str()),
        ("physicalDisplayRefreshMilliHz", physical_refresh.as_str()),
        (
            "verifiedDisplayId",
            record.verified_display_id.as_deref().unwrap_or_default(),
        ),
        (
            "displayTopologyRevision",
            record
                .display_topology_revision
                .as_deref()
                .filter(|_| record.verified_display_id.is_some())
                .unwrap_or_default(),
        ),
    ];
    if record.resumed {
        fields.push(("resume", "1"));
    }
    let mut reply = xml::response(200, "OK", &fields);
    reply.requires_paired_tls = true;
    reply
}

fn cancel_reply() -> Reply {
    let mut reply = xml::response(200, "OK", &[("gamesession", "0")]);
    reply.requires_paired_tls = true;
    reply
}

fn valid_label(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}

fn valid_device_name(value: &str) -> bool {
    value.is_empty() || valid_label(value, 128)
}

fn invalid_peer(address: IpAddr) -> bool {
    address.is_unspecified()
        || address.is_multicast()
        || address == IpAddr::V4(Ipv4Addr::BROADCAST)
        || matches!(address, IpAddr::V6(value) if value.to_ipv4_mapped().is_some())
}

fn random_nonzero_u32() -> Result<u32, &'static str> {
    for _ in 0..8 {
        let mut bytes = [0; 4];
        getrandom::fill(&mut bytes).map_err(|_| "random_unavailable")?;
        let value = u32::from_ne_bytes(bytes);
        if value != 0 {
            return Ok(value);
        }
    }
    Err("random_unavailable")
}

fn operation_id(nonce: &[u8; 16], id: u64, purpose: &str) -> String {
    format!("nvhttp-{}-{id:016x}-{purpose}", hex(nonce))
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut output, "{byte:02x}").expect("hex string write");
    }
    output
}

fn key_hex(key: &[u8; 16]) -> String {
    hex(key)
}

fn app_id(value: u32) -> String {
    format!("app-{value:016x}")
}
