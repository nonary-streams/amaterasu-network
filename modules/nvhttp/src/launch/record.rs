use super::{
    CaptureMode, CaptureProvider, LaunchRequest, PeerIdentity, PhysicalDisplayMode,
    VideoEncryptionPolicySnapshot,
};
use crate::encoder_snapshot::{CodecOffer, EncoderSnapshot};
use crate::frame_limiter::FrameLimiterSettings;
use crate::launch::{DEFAULT_CLEANUP_BUDGET, MONITOR_INTERVAL, STREAM_CLEANUP_MARGIN_MS};
use crate::preparation::{LegacyPreparationStep, PreparationStep};
use amaterasu_contracts::virtual_display::VirtualDisplayIntent;
use serde_json::Value;
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use super::{
    call::Call,
    workflow::{ApplicationConfigOverrides, Phase},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Starting,
    AwaitingDelivery,
    Ready,
    Stopping,
    Stopped,
    Failed,
    CleanupFailed,
}

impl State {
    pub fn terminal(self) -> bool {
        matches!(self, Self::Stopped | Self::Failed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    ReserveHistory,
    ReadProtonPolicy,
    PreflightApplication,
    SnapshotDisplay,
    EnumerateDisplay,
    ConfirmDisplay,
    LaunchApplication,
    AwaitApplicationReady,
    PrepareDisplayAdmission,
    OpenRtsp,
    AwaitingDelivery,
    Live,
    Cleanup,
    VerifyRtspCleanup,
    VerifyApplicationCleanup,
    ReleaseHistory,
    Terminal,
}

pub struct Record {
    pub id: u64,
    pub desktop: bool,
    pub resumed: bool,
    pub peer: PeerIdentity,
    pub request: LaunchRequest,
    /// Frozen requested physical mode; this does not assert a host display topology.
    pub physical_display_mode: PhysicalDisplayMode,
    pub device_name: String,
    pub application_operation: String,
    pub rtsp_operation: String,
    pub history_release_required: bool,
    pub history_reserved: bool,
    pub history_state: &'static str,
    pub connect_data: u32,
    pub global_fec_percentage: u8,
    pub global_stream_audio: bool,
    pub video_encryption_policy: Option<VideoEncryptionPolicySnapshot>,
    pub global_audio_sink_capture_only: bool,
    pub global_configured_audio_sink: Option<String>,
    pub global_configured_virtual_sink: Option<String>,
    pub global_preparation: Vec<PreparationStep>,
    pub legacy_global_preparation: Vec<LegacyPreparationStep>,
    pub global_frame_limiter_settings: FrameLimiterSettings,
    pub client_frame_limiter_settings: FrameLimiterSettings,
    pub application_frame_limiter_settings: FrameLimiterSettings,
    pub application_preflight_overrides: Option<ApplicationConfigOverrides>,
    /// Authoritative global Proton policy read before application preflight.
    pub global_proton_dualsense_compatibility: Option<bool>,
    /// Client/application/global compatibility policy frozen for this launch.
    pub proton_dualsense_compatibility: bool,
    /// Sparse application display fields frozen at preflight for launch readback.
    pub application_display_overrides: Option<Value>,
    /// Typed catalog display selection, kept separate from dd_* overrides.
    pub application_display_settings: Option<Value>,
    pub global_display_revision: Option<u64>,
    pub global_display_policy: Value,
    pub display_policy_snapshot: Option<Value>,
    /// Resolved virtual-display lease intent frozen before Launch admission.
    pub virtual_display_intent: Option<VirtualDisplayIntent>,
    pub display_topology_revision: Option<String>,
    pub display_snapshot_configuration: Option<Value>,
    pub verified_display_id: Option<String>,
    pub display_snapshot_ids: Vec<String>,
    pub display_enumeration_offset: usize,
    pub display_enumerated_ids: Vec<String>,
    pub display_match_id: Option<String>,
    pub display_match_inactive: bool,
    /// Authorized complete display request, absent until admission supplies all facts.
    pub display_request: Option<Value>,
    pub display_admission_token: Option<String>,
    pub application_preflight_token: Option<String>,
    pub application_catalog_revision: Option<u64>,
    /// Validated cleanup budget frozen by launch preflight before provider effects.
    pub application_cleanup_budget_ms: Option<u64>,
    pub frame_limiter_snapshot: Option<Value>,
    pub executable_path: Option<String>,
    pub resolved_virtual_sink: Option<String>,
    pub capture_sink_without_routing: bool,
    /// Sparse client-over-application timeout override captured for this launch.
    /// Input resolves `None` against its authoritative global policy at acquire.
    pub scoped_back_button_timeout: Option<i32>,
    /// Sparse client-over-application input gates/profile captured for this launch.
    pub scoped_controller: Option<bool>,
    pub scoped_gamepad: Option<String>,
    pub scoped_keyboard: Option<bool>,
    pub scoped_mouse: Option<bool>,
    pub scoped_native_pen_touch: Option<bool>,
    pub scoped_ds4_back_as_touchpad_click: Option<bool>,
    pub scoped_motion_as_ds4: Option<bool>,
    pub scoped_touchpad_as_ds4: Option<bool>,
    pub scoped_ds5_inputtino_randomize_mac: Option<bool>,
    pub scoped_high_resolution_scrolling: Option<bool>,
    pub scoped_always_send_scancodes: Option<bool>,
    pub scoped_key_rightalt_to_key_win: Option<bool>,
    /// The entire selected ordered list; absence is resolved by input at acquire.
    pub scoped_keybindings: Option<amaterasu_input_policy::KeyBindings>,
    pub scoped_key_repeat_delay: Option<u32>,
    pub scoped_key_repeat_frequency: Option<f64>,
    pub global_ping_timeout_ms: u32,
    pub global_video_max_batch_size_kb: u8,
    pub global_max_bitrate_kbps: Option<u32>,
    pub global_qp: i32,
    pub global_minimum_fps_target: f64,
    /// Client-over-application stream controls resolved for this launch.
    pub effective_video_max_batch_size_kb: u8,
    /// Codecs RTSP may negotiate for this launch, fixed at admission from
    /// the encoder snapshot and the requested stream mode.
    pub video_codec_offer: CodecOffer,
    pub encoder_snapshot: Option<EncoderSnapshot>,
    pub effective_max_bitrate_kbps: Option<u32>,
    pub effective_qp: i32,
    pub effective_minimum_fps_target: f64,
    pub global_wgc_pacing_smoothing: bool,
    pub global_software_encoder: amaterasu_module_sdk::SoftwareEncoderOptions,
    pub effective_software_encoder: amaterasu_module_sdk::SoftwareEncoderOptions,
    pub global_nvenc_settings: amaterasu_module_sdk::NvencSettings,
    pub effective_nvenc_settings: amaterasu_module_sdk::NvencSettings,
    pub global_nvenc_spatial_aq: bool,
    pub effective_nvenc_spatial_aq: bool,
    pub selected_encoder: amaterasu_module_sdk::EncoderSelection,
    pub application_stream_audio: Option<bool>,
    pub effective_stream_audio: bool,
    pub capture_output: String,
    /// Frozen platform-selected provider used when the configured capture mode is auto.
    pub bootstrap_capture_provider: CaptureProvider,
    pub global_capture_mode: CaptureMode,
    pub audio_endpoint: String,
    pub bootstrap_audio_endpoint: String,
    pub capture_provider: CaptureProvider,
    pub constant_rate: bool,
    pub application_fec_percentage: Option<u8>,
    pub effective_fec_percentage: u8,
    pub application_requested: bool,
    pub application_launch: Option<u64>,
    pub rtsp_requested: bool,
    pub rtsp_ticket: Option<u64>,
    pub rtsp_url: Option<String>,
    pub rtsp_cleanup_blocked: bool,
    pub application_cleanup_blocked: bool,
    pub state: State,
    pub stage: Stage,
    pub adopted: bool,
    pub revoked: bool,
    pub launch_connection: Option<u64>,
    pub cancel_connection: Option<u64>,
    pub deadline: Instant,
    pub next_monitor: Instant,
    pub next_cleanup_poll: Instant,
    pub monitor_application_next: bool,
    pub failure: Option<&'static str>,
    pub cleanup_error: Option<&'static str>,
    pub uncertain: VecDeque<(Phase, Call)>,
    pub retrying_uncertainty: bool,
    pub rtsp_reconcile: Option<Phase>,
    pub application_reconcile: Option<Phase>,
}

impl Record {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: u64,
        peer: PeerIdentity,
        request: LaunchRequest,
        device_name: String,
        application_operation: String,
        rtsp_operation: String,
        connect_data: u32,
        global_fec_percentage: u8,
        global_stream_audio: bool,
        video_encryption_policy: Option<VideoEncryptionPolicySnapshot>,
        global_audio_sink_capture_only: bool,
        global_configured_audio_sink: Option<String>,
        global_configured_virtual_sink: Option<String>,
        global_preparation: Vec<PreparationStep>,
        legacy_global_preparation: Vec<LegacyPreparationStep>,
        global_frame_limiter_settings: FrameLimiterSettings,
        client_frame_limiter_settings: FrameLimiterSettings,
        global_ping_timeout_ms: u32,
        global_video_max_batch_size_kb: u8,
        global_max_bitrate_kbps: Option<u32>,
        global_qp: i32,
        global_minimum_fps_target: f64,
        global_wgc_pacing_smoothing: bool,
        capture_output: String,
        bootstrap_capture_provider: CaptureProvider,
        global_capture_mode: CaptureMode,
        audio_endpoint: String,
        bootstrap_audio_endpoint: String,
        capture_provider: CaptureProvider,
        constant_rate: bool,
        connection: u64,
        deadline: Instant,
    ) -> Self {
        let physical_display_mode = peer.client_display_mode.unwrap_or(PhysicalDisplayMode {
            width: request.width,
            height: request.height,
            refresh_millihz: request.fps * 1_000,
        });
        Self {
            id,
            encoder_snapshot: None,
            video_codec_offer: CodecOffer {
                codecs: vec![amaterasu_media::VideoCodec::H264],
                software_limited: true,
            },
            desktop: false,
            resumed: false,
            peer,
            request,
            physical_display_mode,
            device_name,
            application_operation,
            rtsp_operation,
            history_release_required: false,
            history_reserved: false,
            history_state: "unavailable",
            connect_data,
            global_fec_percentage,
            global_stream_audio,
            video_encryption_policy,
            global_audio_sink_capture_only,
            global_configured_audio_sink,
            global_configured_virtual_sink,
            global_preparation,
            legacy_global_preparation,
            global_frame_limiter_settings,
            client_frame_limiter_settings,
            application_frame_limiter_settings: FrameLimiterSettings::default(),
            application_preflight_overrides: None,
            global_proton_dualsense_compatibility: None,
            proton_dualsense_compatibility: false,
            application_display_overrides: None,
            application_display_settings: None,
            global_display_revision: None,
            global_display_policy: serde_json::json!({}),
            display_policy_snapshot: None,
            virtual_display_intent: None,
            display_topology_revision: None,
            display_snapshot_configuration: None,
            verified_display_id: None,
            display_snapshot_ids: Vec::new(),
            display_enumeration_offset: 0,
            display_enumerated_ids: Vec::new(),
            display_match_id: None,
            display_match_inactive: false,
            display_request: None,
            display_admission_token: None,
            application_preflight_token: None,
            application_catalog_revision: None,
            application_cleanup_budget_ms: None,
            frame_limiter_snapshot: None,
            executable_path: None,
            resolved_virtual_sink: None,
            capture_sink_without_routing: false,
            scoped_back_button_timeout: None,
            scoped_controller: None,
            scoped_gamepad: None,
            scoped_keyboard: None,
            scoped_mouse: None,
            scoped_native_pen_touch: None,
            scoped_ds4_back_as_touchpad_click: None,
            scoped_motion_as_ds4: None,
            scoped_touchpad_as_ds4: None,
            scoped_ds5_inputtino_randomize_mac: None,
            scoped_high_resolution_scrolling: None,
            scoped_always_send_scancodes: None,
            scoped_key_rightalt_to_key_win: None,
            scoped_keybindings: None,
            scoped_key_repeat_delay: None,
            scoped_key_repeat_frequency: None,
            global_ping_timeout_ms,
            global_video_max_batch_size_kb,
            global_max_bitrate_kbps,
            global_qp,
            global_minimum_fps_target,
            effective_video_max_batch_size_kb: global_video_max_batch_size_kb,
            effective_max_bitrate_kbps: global_max_bitrate_kbps,
            effective_qp: global_qp,
            effective_minimum_fps_target: global_minimum_fps_target,
            global_wgc_pacing_smoothing,
            global_software_encoder: amaterasu_module_sdk::SoftwareEncoderOptions::default(),
            effective_software_encoder: amaterasu_module_sdk::SoftwareEncoderOptions::default(),
            global_nvenc_settings: amaterasu_module_sdk::NvencSettings::default(),
            effective_nvenc_settings: amaterasu_module_sdk::NvencSettings::default(),
            global_nvenc_spatial_aq: false,
            effective_nvenc_spatial_aq: false,
            selected_encoder: amaterasu_module_sdk::EncoderSelection::Index(0),
            application_stream_audio: None,
            effective_stream_audio: global_stream_audio,
            capture_output,
            bootstrap_capture_provider,
            global_capture_mode,
            audio_endpoint,
            bootstrap_audio_endpoint,
            capture_provider,
            constant_rate,
            application_fec_percentage: None,
            effective_fec_percentage: global_fec_percentage,
            application_requested: false,
            application_launch: None,
            rtsp_requested: false,
            rtsp_ticket: None,
            rtsp_url: None,
            rtsp_cleanup_blocked: false,
            application_cleanup_blocked: false,
            state: State::Starting,
            stage: Stage::ReserveHistory,
            adopted: false,
            revoked: false,
            launch_connection: Some(connection),
            cancel_connection: None,
            deadline,
            next_monitor: deadline,
            next_cleanup_poll: deadline,
            monitor_application_next: true,
            failure: None,
            cleanup_error: None,
            uncertain: VecDeque::new(),
            retrying_uncertainty: false,
            rtsp_reconcile: None,
            application_reconcile: None,
        }
    }

    pub fn operation_prefix(&self) -> &str {
        &self.rtsp_operation
    }

    pub fn request_cleanup(&mut self, failure: Option<&'static str>, now: Instant) {
        if let Some(failure) = failure {
            self.failure.get_or_insert(failure);
        }
        let already_stopping = self.state == State::Stopping;
        self.state = State::Stopping;
        self.stage = Stage::Cleanup;
        if !already_stopping {
            self.next_cleanup_poll = now;
            self.deadline = self.cleanup_deadline(now);
        }
        self.cleanup_error = None;
    }

    pub fn cleanup_deadline(&self, now: Instant) -> Instant {
        now + self.cleanup_budget()
    }

    fn cleanup_budget(&self) -> Duration {
        self.application_cleanup_budget_ms
            .and_then(|budget| budget.checked_add(STREAM_CLEANUP_MARGIN_MS))
            .map(Duration::from_millis)
            .unwrap_or(DEFAULT_CLEANUP_BUDGET)
    }

    pub fn fail_cleanup(&mut self, error: &'static str) {
        self.state = State::CleanupFailed;
        self.cleanup_error = Some(error);
    }

    pub fn finish_cleanup(&mut self) {
        debug_assert!(self.uncertain.is_empty());
        self.state = if self.failure.is_some() {
            State::Failed
        } else {
            State::Stopped
        };
        self.stage = Stage::Terminal;
        self.cleanup_error = None;
    }

    pub fn monitored(&mut self, now: Instant) {
        self.next_monitor = now + MONITOR_INTERVAL;
        self.monitor_application_next = !self.monitor_application_next;
    }

    pub fn retry_cleanup(&mut self, now: Instant) -> Option<(Phase, Call)> {
        self.state = State::Stopping;
        self.stage = Stage::Cleanup;
        self.cleanup_error = None;
        self.rtsp_cleanup_blocked = false;
        self.application_cleanup_blocked = false;
        self.deadline = self.cleanup_deadline(now);
        self.next_cleanup_poll = now;
        self.retrying_uncertainty = true;
        self.uncertain.pop_front().map(|(phase, mut call)| {
            call.retry_settlement();
            (phase, call)
        })
    }
}
