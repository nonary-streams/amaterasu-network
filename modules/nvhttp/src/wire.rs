//! Moonlight Gen7 HTTP/XML adapter. This layer never performs TLS or PIN approval.
mod applications;
mod capabilities;
mod cleanup;
mod pairing;
mod query;
mod streaming;
pub(crate) mod xml;

use crate::{
    launch::{CaptureMode, Controller as LaunchController, LaunchRequest, PeerIdentity},
    preparation::PreparationStep,
};
use amaterasu_module_sdk::{Command, ModuleResult, Response, RuntimeClient};
use query::Query;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

pub struct Request {
    pub method: String,
    pub target: String,
    pub body: Vec<u8>,
}

pub struct RequestContext {
    pub secure: bool,
    pub remote: IpAddr,
    pub peer_certificate: Option<Vec<u8>>,
    /// Set only after the transport verifies TLS possession and checks this
    /// certificate against the live committed pairing authority for this request.
    pub peer_trusted: bool,
}

impl RequestContext {
    fn trusted(&self) -> bool {
        self.secure
            && self.peer_trusted
            && self
                .peer_certificate
                .as_ref()
                .is_some_and(|certificate| !certificate.is_empty())
    }

    fn identity(&self) -> Result<PeerIdentity, &'static str> {
        if !self.trusted() {
            return Err("authenticated paired TLS is required");
        }
        PeerIdentity::new(
            self.remote,
            self.peer_certificate
                .clone()
                .ok_or("missing peer certificate")?,
        )
    }
}

#[derive(Debug)]
pub struct Reply {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
    pub requires_paired_tls: bool,
}

impl Reply {
    pub fn authorize(self, paired: bool) -> Self {
        if self.requires_paired_tls && !paired {
            xml::error(401, "paired TLS authorization was revoked")
        } else {
            self
        }
    }
}

pub struct RouterConfig {
    pub hostname: String,
    pub http_port: u16,
    pub https_port: u16,
}

pub struct Router {
    config: RouterConfig,
    launches: LaunchController,
    transcripts: BTreeMap<String, pairing::Transcript>,
    jobs: BTreeMap<u64, Job>,
    cancellations: BTreeMap<u64, Instant>,
    next_job: u64,
    next_call: u64,
}

struct Job {
    connection: Option<u64>,
    purpose: Purpose,
    call: Call,
    deadline: Instant,
    applications: Option<applications::Applications>,
}

enum Call {
    Ready { payload: Value, not_before: Instant },
    Waiting { request: u64 },
}

#[derive(Clone)]
enum Purpose {
    Identity {
        paired: bool,
        peer: Option<PeerIdentity>,
    },
    Begin {
        client: String,
    },
    Certificate {
        client: String,
    },
    Phase {
        client: String,
        phase: pairing::Phase,
    },
    LaunchIdentity {
        request: LaunchRequest,
        peer: PeerIdentity,
        resume: bool,
    },
    /// Removes the certificate presented on this paired TLS connection.
    Unpair,
    Cleanup,
    Applications {
        desktop_enabled: bool,
    },
}

const PAIRING_SERVICE: &str = "amaterasu.pairing/1";
const MAX_JOBS: usize = 32;
const SERVICE_TIMEOUT: Duration = Duration::from_secs(5);
const PAIRING_TIMEOUT: Duration = Duration::from_secs(120);

impl Router {
    pub fn new(config: RouterConfig, mut launches: LaunchController) -> Self {
        launches.set_device_name(&config.hostname);
        Self {
            config,
            launches,
            transcripts: BTreeMap::new(),
            jobs: BTreeMap::new(),
            cancellations: BTreeMap::new(),
            next_job: 0,
            next_call: 0,
        }
    }

    pub fn set_hostname(&mut self, hostname: String) {
        self.launches.set_device_name(&hostname);
        self.config.hostname = hostname;
    }

    pub fn set_encoder_snapshot(&mut self, snapshot: crate::encoder_snapshot::EncoderSnapshot) {
        self.launches.set_encoder_snapshot(snapshot);
    }

    pub fn supports_streaming(&self) -> bool {
        self.launches.supported()
    }

    pub fn stream_active(&self) -> bool {
        self.launches.busy()
    }

    pub fn set_ports(&mut self, http_port: u16, https_port: u16) {
        self.config.http_port = http_port;
        self.config.https_port = https_port;
    }

    pub fn set_output_name_settings(&mut self, ready: bool, configured_output_name: Option<&str>) {
        self.launches
            .set_output_name_settings(ready, configured_output_name);
    }

    pub fn set_audio_sink_settings(&mut self, configured_audio_sink: Option<&str>) {
        self.launches.set_audio_sink_settings(configured_audio_sink);
    }

    pub fn set_virtual_sink_settings(&mut self, configured_virtual_sink: Option<&str>) {
        self.launches
            .set_virtual_sink_settings(configured_virtual_sink);
    }

    pub fn set_global_preparation(&mut self, preparation: &[PreparationStep]) {
        self.launches.set_global_preparation(preparation);
    }

    pub fn set_legacy_global_preparation(
        &mut self,
        preparation: &[crate::preparation::LegacyPreparationStep],
    ) {
        self.launches.set_legacy_global_preparation(preparation);
    }

    pub fn set_global_frame_limiter_settings(
        &mut self,
        settings: &crate::frame_limiter::FrameLimiterSettings,
    ) {
        self.launches.set_global_frame_limiter_settings(settings);
    }

    pub fn set_global_display_policy(&mut self, revision: u64, policy: serde_json::Value) {
        self.launches.set_global_display_policy(revision, policy);
    }

    pub fn set_audio_sink_capture_only(&mut self, enabled: bool) {
        self.launches.set_audio_sink_capture_only(enabled);
    }

    pub fn set_global_stream_audio(&mut self, stream_audio: bool) {
        self.launches.set_global_stream_audio(stream_audio);
    }

    pub fn set_global_video_encryption_modes(&mut self, lan_mode: u8, wan_mode: u8) {
        self.launches
            .set_global_video_encryption_modes(lan_mode, wan_mode);
    }

    pub fn set_global_ping_timeout_ms(&mut self, ping_timeout_ms: u32) {
        self.launches.set_global_ping_timeout_ms(ping_timeout_ms);
    }

    pub fn set_global_video_max_batch_size_kb(&mut self, max_batch_size_kb: u8) {
        self.launches
            .set_global_video_max_batch_size_kb(max_batch_size_kb);
    }

    pub fn set_global_max_bitrate_kbps(&mut self, max_bitrate_kbps: Option<u32>) {
        self.launches.set_global_max_bitrate_kbps(max_bitrate_kbps);
    }

    pub fn set_global_qp(&mut self, qp: i32) {
        self.launches.set_global_qp(qp);
    }

    pub fn set_global_fec_percentage(&mut self, fec_percentage: Option<u8>) {
        self.launches.set_global_fec_percentage(fec_percentage);
    }

    pub fn set_global_minimum_fps_target(&mut self, target: f64) {
        self.launches.set_global_minimum_fps_target(target);
    }

    pub fn set_software_encoder_options(
        &mut self,
        options: amaterasu_module_sdk::SoftwareEncoderOptions,
    ) {
        self.launches.set_software_encoder_options(options);
    }

    pub fn set_nvenc_settings(&mut self, settings: amaterasu_module_sdk::NvencSettings) {
        self.launches.set_nvenc_settings(settings);
    }

    pub fn set_nvenc_spatial_aq(&mut self, enabled: bool) {
        self.launches.set_nvenc_spatial_aq(enabled);
    }

    pub fn set_global_wgc_pacing_smoothing(&mut self, enabled: bool) {
        self.launches.set_global_wgc_pacing_smoothing(enabled);
    }

    pub fn set_capture_mode(&mut self, capture: crate::launch::CaptureMode) {
        self.launches.set_capture_mode(capture);
    }

    pub fn dispatch(
        &mut self,
        connection: u64,
        request: Request,
        peer: RequestContext,
        runtime: &RuntimeClient,
    ) -> Option<Reply> {
        self.dispatch_with(connection, request, peer, Instant::now(), &mut |command| {
            runtime.send_ephemeral(command)
        })
    }

    fn dispatch_with(
        &mut self,
        connection: u64,
        request: Request,
        peer: RequestContext,
        now: Instant,
        _send: &mut impl FnMut(Command) -> ModuleResult<Response>,
    ) -> Option<Reply> {
        if request.method != "GET" || !request.body.is_empty() {
            return Some(xml::error(405, "only bodyless GET requests are supported"));
        }
        let query = match Query::parse(&request.target) {
            Ok(query) => query,
            Err(error) => return Some(xml::error(400, error)),
        };
        let trusted = peer.trusted();
        match query.path.as_str() {
            "/serverinfo" => {
                if peer.secure && !trusted {
                    return Some(xml::unpaired_certificate());
                }
                self.queue(
                    connection.into(),
                    Purpose::Identity {
                        paired: trusted,
                        peer: peer.identity().ok(),
                    },
                    json!({"action":"identity"}),
                    now + SERVICE_TIMEOUT,
                    now,
                )
                .err()
                .map(|error| xml::error(503, error))
            }
            "/pair" => self.pair(connection, query, &peer, now),
            "/applist" => self.applications(connection, trusted, now),
            "/launch" => {
                if !trusted {
                    Some(xml::error(401, "authenticated paired TLS is required"))
                } else {
                    let request = match streaming::launch_request(&query) {
                        Ok(request) => request,
                        Err(error) => return Some(xml::error(400, error)),
                    };
                    let identity = match peer.identity() {
                        Ok(identity) => identity,
                        Err(error) => return Some(xml::error(401, error)),
                    };
                    let certificate_pem = match peer.peer_certificate.as_deref().and_then(|der| {
                        pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, der)
                            .ok()
                    }) {
                        Some(certificate_pem) => certificate_pem,
                        None => return Some(xml::error(401, "client certificate is unavailable")),
                    };
                    self.queue(
                        Some(connection),
                        Purpose::LaunchIdentity {
                            request,
                            peer: identity,
                            resume: false,
                        },
                        json!({
                            "action": "check_client_certificate",
                            "certificate_pem": certificate_pem
                        }),
                        now + SERVICE_TIMEOUT,
                        now,
                    )
                    .err()
                    .map(|error| xml::error(503, error))
                }
            }
            "/cancel" => {
                if !trusted {
                    return Some(xml::error(401, "authenticated paired TLS is required"));
                }
                if let Err(error) = query.require_only(&["uniqueid", "uuid"]) {
                    return Some(xml::error(400, error));
                }
                let identity = match peer.identity() {
                    Ok(identity) => identity,
                    Err(error) => return Some(xml::error(401, error)),
                };
                self.launches.cancel(connection, &identity, now)
            }
            "/resume" => {
                if !trusted {
                    return Some(xml::error(401, "authenticated paired TLS is required"));
                }
                let request = match streaming::launch_request(&query) {
                    Ok(request) => request,
                    Err(error) => return Some(xml::error(400, error)),
                };
                let identity = match peer.identity() {
                    Ok(identity) => identity,
                    Err(error) => return Some(xml::error(401, error)),
                };
                let certificate_pem = match peer.peer_certificate.as_deref().and_then(|der| {
                    pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, der).ok()
                }) {
                    Some(certificate_pem) => certificate_pem,
                    None => return Some(xml::error(401, "client certificate is unavailable")),
                };
                self.queue(
                    Some(connection),
                    Purpose::LaunchIdentity {
                        request,
                        peer: identity,
                        resume: true,
                    },
                    json!({"action":"check_client_certificate", "certificate_pem":certificate_pem}),
                    now + SERVICE_TIMEOUT,
                    now,
                )
                .err()
                .map(|error| xml::error(503, error))
            }
            "/unpair" => self.unpair(connection, &query, &peer, now),
            _ => Some(xml::error(404, "unknown Moonlight route")),
        }
    }

    /// Self-service unpair. Authority is the certificate of the verified TLS
    /// connection; `uniqueid` is never used to select a client. Plaintext
    /// requests are inert, because nothing proves who is asking.
    fn unpair(
        &mut self,
        connection: u64,
        query: &Query,
        peer: &RequestContext,
        now: Instant,
    ) -> Option<Reply> {
        if !peer.secure {
            return Some(xml::unpaired(false));
        }
        if !peer.trusted() {
            return Some(xml::error(401, "authenticated paired TLS is required"));
        }
        if let Err(error) = query.require_only(&["uniqueid", "uuid"]) {
            return Some(xml::error(400, error));
        }
        let certificate_pem = match peer.peer_certificate.as_deref().and_then(|der| {
            pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, der).ok()
        }) {
            Some(certificate_pem) => certificate_pem,
            None => return Some(xml::error(401, "client certificate is unavailable")),
        };
        self.queue(
            Some(connection),
            Purpose::Unpair,
            json!({"action":"unpair_presented_client","certificate_pem":certificate_pem}),
            now + SERVICE_TIMEOUT,
            now,
        )
        .err()
        .map(|error| xml::error(503, error))
    }

    fn queue(
        &mut self,
        connection: Option<u64>,
        purpose: Purpose,
        payload: Value,
        deadline: Instant,
        now: Instant,
    ) -> Result<(), &'static str> {
        if self.jobs.len() + self.cancellations.len() >= MAX_JOBS {
            return Err("request capacity exhausted");
        }
        self.next_job = self
            .next_job
            .checked_add(1)
            .ok_or("request identifier exhausted")?;
        self.jobs.insert(
            self.next_job,
            Job {
                connection,
                applications: match purpose {
                    Purpose::Applications { desktop_enabled } => {
                        Some(applications::Applications::new(desktop_enabled))
                    }
                    _ => None,
                },
                purpose,
                call: Call::Ready {
                    payload,
                    not_before: now,
                },
                deadline,
            },
        );
        Ok(())
    }

    pub fn poll_with_trust(
        &mut self,
        runtime: &RuntimeClient,
        trusted: impl FnMut(&[u8]) -> bool,
    ) -> Vec<(u64, Reply)> {
        self.poll_with_identity(
            Instant::now(),
            &mut |command| runtime.send_ephemeral(command),
            trusted,
        )
    }

    #[cfg(test)]
    fn poll_with(
        &mut self,
        now: Instant,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
    ) -> Vec<(u64, Reply)> {
        self.poll_with_identity(now, send, |_| true)
    }

    fn poll_with_identity(
        &mut self,
        now: Instant,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
        trusted: impl FnMut(&[u8]) -> bool,
    ) -> Vec<(u64, Reply)> {
        self.poll_cancellations(now, send);
        let mut replies = self.launches.poll_with_trust(now, send, trusted);
        let keys: Vec<_> = self.jobs.keys().copied().collect();
        for key in keys {
            let Some(mut job) = self.jobs.remove(&key) else {
                continue;
            };
            if now >= job.deadline {
                self.expire_job(job, now, send, &mut replies);
                continue;
            }
            let Some(result) = self.advance_call(&mut job, now, send) else {
                self.jobs.insert(key, job);
                continue;
            };
            let continued = if matches!(job.purpose, Purpose::Applications { .. }) {
                self.resolve_applications(job, result, now, &mut replies)
            } else {
                self.resolve(job, result, now, &mut replies)
            };
            if let Some(job) = continued {
                self.jobs.insert(key, job);
            }
        }
        let expired: Vec<_> = self
            .transcripts
            .iter()
            .filter(|(_, transcript)| now >= transcript.deadline)
            .map(|(client, _)| client.clone())
            .collect();
        for client in expired {
            self.abort_transcript(&client, now);
        }
        replies
    }

    fn advance_call(
        &mut self,
        job: &mut Job,
        now: Instant,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
    ) -> Option<Result<Value, String>> {
        match &job.call {
            Call::Ready { not_before, .. } if now < *not_before => None,
            Call::Ready { payload, .. } => {
                let Some(sequence) = self.next_call.checked_add(1) else {
                    return Some(Err("request identifier exhausted".into()));
                };
                self.next_call = sequence;
                let timeout_ms = job
                    .deadline
                    .saturating_duration_since(now)
                    .min(SERVICE_TIMEOUT)
                    .as_millis()
                    .max(1) as u64;
                match send(Command::Request {
                    service: job.purpose.service().into(),
                    payload: payload.clone(),
                    timeout_ms,
                    operation_id: format!("nvhttp-wire-{sequence}"),
                    parent: None,
                }) {
                    Ok(Response::Accepted { id }) => {
                        job.call = Call::Waiting { request: id };
                        None
                    }
                    response => Some(Err(response_code(&response).into())),
                }
            }
            Call::Waiting { request } => match send(Command::TakeResult { request: *request }) {
                Ok(Response::Pending) => None,
                Ok(Response::Result { payload }) => Some(Ok(payload)),
                response => {
                    if !cleanup::released(&response) {
                        self.retire_request(*request, now, send);
                    }
                    Some(Err(response_code(&response).into()))
                }
            },
        }
    }

    pub fn cancel(&mut self, connection: u64, runtime: &RuntimeClient) {
        self.cancel_with(connection, Instant::now(), &mut |command| {
            runtime.send_ephemeral(command)
        });
    }

    fn cancel_with(
        &mut self,
        connection: u64,
        now: Instant,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
    ) {
        self.launches.connection_closed(connection, now);
        let keys: Vec<_> = self
            .jobs
            .iter()
            .filter(|(_, job)| job.connection == Some(connection))
            .map(|(key, _)| *key)
            .collect();
        for key in keys {
            let mut job = self.jobs.remove(&key).expect("selected connection job");
            job.connection = None;
            // A begin result contains the only pairing ID. Keep draining it so
            // a committed begin can be cancelled after the socket disappeared.
            if matches!(job.purpose, Purpose::Begin { .. })
                && matches!(job.call, Call::Waiting { .. })
            {
                self.jobs.insert(key, job);
            } else {
                self.expire_job(job, now, send, &mut Vec::new());
            }
        }
    }

    pub fn reply_delivered(&mut self, connection: u64) {
        self.launches.reply_delivered(connection, Instant::now());
    }

    pub fn revoke_untrusted(&mut self, trusted: impl FnMut(&[u8]) -> bool) -> Vec<u64> {
        self.launches.revoke_untrusted(Instant::now(), trusted)
    }

    pub fn shutdown(&mut self, runtime: &RuntimeClient) {
        self.launches
            .shutdown(&mut |command| runtime.send_ephemeral(command));
    }

    fn expire_job(
        &mut self,
        job: Job,
        now: Instant,
        send: &mut impl FnMut(Command) -> ModuleResult<Response>,
        replies: &mut Vec<(u64, Reply)>,
    ) {
        if let Call::Waiting { request } = job.call {
            self.retire_request(request, now, send);
        }
        if let Some(client) = job.purpose.client() {
            self.abort_transcript(client, now);
        }
        if let Some(connection) = job.connection {
            replies.push((connection, xml::error(504, "request expired")));
        }
    }

    fn abort_transcript(&mut self, client: &str, now: Instant) {
        if let Some(transcript) = self.transcripts.remove(client)
            && let Some(pairing_id) = transcript.pairing_id
        {
            let _ = self.queue(
                None,
                Purpose::Cleanup,
                json!({"action":"cancel","pairing_id":pairing_id}),
                now + SERVICE_TIMEOUT,
                now,
            );
        }
    }
}

impl Purpose {
    fn service(&self) -> &'static str {
        if matches!(self, Self::Applications { .. }) {
            applications::CATALOG_SERVICE
        } else {
            PAIRING_SERVICE
        }
    }

    fn client(&self) -> Option<&str> {
        match self {
            Self::Begin { client } | Self::Certificate { client } | Self::Phase { client, .. } => {
                Some(client)
            }
            _ => None,
        }
    }
}

fn response_code(response: &ModuleResult<Response>) -> &str {
    match response {
        Ok(Response::Error { code, .. }) => code,
        _ => "runtime_error",
    }
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct ClientConfigOverrides {
    pub(super) sw_preset: Option<String>,
    pub(super) sw_tune: Option<String>,
    pub(super) encoder: Option<amaterasu_module_sdk::EncoderBackend>,
    pub(super) min_threads: Option<i32>,
    pub(super) qp: Option<i32>,
    pub(super) capture: Option<CaptureMode>,
    pub(super) display_mode: Option<String>,
    pub(super) fec_percentage: Option<u8>,
    pub(super) max_bitrate: Option<i32>,
    pub(super) minimum_fps_target: Option<f64>,
    pub(super) video_max_batch_size_kb: Option<u8>,
    pub(super) nvenc_preset: Option<u8>,
    pub(super) nvenc_h264_cavlc: Option<bool>,
    pub(super) nvenc_twopass: Option<amaterasu_module_sdk::NvencTwoPass>,
    pub(super) nvenc_vbv_increase: Option<u32>,
    #[serde(alias = "nvenc_force_split_encode")]
    pub(super) nvenc_split_encode: Option<amaterasu_module_sdk::NvencSplitEncode>,
    pub(super) nvenc_realtime_hags: Option<bool>,
    pub(super) nvenc_opengl_vulkan_on_dxgi: Option<bool>,
    pub(super) nvenc_latency_over_power: Option<bool>,
    pub(super) vaapi_strict_rc_buffer: Option<bool>,
    pub(super) nvenc_spatial_aq: Option<bool>,
    #[serde(default)]
    pub(super) display_policy: Option<serde_json::Value>,
    pub(super) dd_mode_remapping: Option<serde_json::Value>,
    pub(super) dd_resolution_option: Option<String>,
    pub(super) dd_manual_resolution: Option<String>,
    pub(super) dd_refresh_rate_option: Option<String>,
    pub(super) dd_manual_refresh_rate: Option<String>,
    pub(super) dd_hdr_option: Option<String>,
    pub(super) dd_configuration_option: Option<String>,
    pub(super) dd_hdr_request_override: Option<String>,
    pub(super) stream_audio: Option<bool>,
    pub(super) audio_sink: Option<String>,
    pub(super) virtual_sink: Option<String>,
    pub(super) audio_sink_capture_only: Option<bool>,
    pub(super) back_button_timeout: Option<i32>,
    pub(super) controller: Option<bool>,
    pub(super) gamepad: Option<String>,
    pub(super) keyboard: Option<bool>,
    pub(super) mouse: Option<bool>,
    pub(super) native_pen_touch: Option<bool>,
    pub(super) ds4_back_as_touchpad_click: Option<bool>,
    pub(super) motion_as_ds4: Option<bool>,
    pub(super) touchpad_as_ds4: Option<bool>,
    pub(super) ds5_inputtino_randomize_mac: Option<bool>,
    pub(super) proton_dualsense_compatibility: Option<bool>,
    pub(super) high_resolution_scrolling: Option<bool>,
    pub(super) always_send_scancodes: Option<bool>,
    pub(super) key_rightalt_to_key_win: Option<bool>,
    pub(super) keybindings: Option<amaterasu_input_policy::KeyBindings>,
    pub(super) key_repeat_delay: Option<u32>,
    pub(super) key_repeat_frequency: Option<f64>,
    pub(super) frame_limiter_enable: Option<bool>,
    pub(super) frame_limiter_fps_limit: Option<f64>,
    pub(super) frame_limiter_provider: Option<String>,
    pub(super) frame_limiter_disable_vsync: Option<bool>,
    pub(super) frame_limiter_auto_virtual_framegen: Option<String>,
    pub(super) rtss_frame_limit_type: Option<String>,
}

impl ClientConfigOverrides {
    pub(super) fn display_overrides(&self) -> serde_json::Value {
        let mut fields = serde_json::json!({
            "dd_mode_remapping":self.dd_mode_remapping,
            "dd_resolution_option":self.dd_resolution_option,
            "dd_manual_resolution":self.dd_manual_resolution,
            "dd_refresh_rate_option":self.dd_refresh_rate_option,
            "dd_manual_refresh_rate":self.dd_manual_refresh_rate,
            "dd_hdr_option":self.dd_hdr_option,
            "dd_configuration_option":self.dd_configuration_option,
            "dd_hdr_request_override":self.dd_hdr_request_override,
        });
        fields
            .as_object_mut()
            .expect("display overrides object")
            .retain(|_, value| !value.is_null());
        if let Some(additional) = &self.display_policy
            && let Some(target) = fields.as_object_mut()
        {
            target.insert("display_policy".into(), additional.clone());
        }
        fields
    }
}

#[cfg(test)]
mod tests;
