mod actions;
mod network;
#[cfg(test)]
mod ownership_tests;
mod record;
#[cfg(test)]
mod tests;
mod workflow;

use crate::{
    model::{Open, Operation, Settings, valid_name},
    rpc::{self, Call, Outcome},
    transport::{Event, Transport},
};
use amaterasu_gamestream::rtsp::{
    Request,
    negotiation::{
        Action, Capabilities, Negotiation, Step as NegotiationStep, TrustedLaunch, UdpDiscovery,
    },
    serialize_response,
};
use amaterasu_module_sdk::{Command, ModuleResult, Response, RuntimeClient};
use record::{Job, Phase, Record, State};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    net::{IpAddr, SocketAddr, UdpSocket},
    thread,
    time::{Duration, Instant},
};

const PREPARE_BUDGET_MS: u64 = 5_000;
const STAGED_DISPLAY_PREPARE_MAX_MS: u64 = 40_000;
const CLEANUP_BUDGET_MS: u64 = 15_000;
const MAX_CLEANUP_RETRIES: u8 = 2;
const CLEANUP_RETRY_DELAYS_MS: [u64; 2] = [250, 1_000];
const STATUS_INTERVAL_MS: u64 = 250;
const MAX_RECORDS: usize = 128;
const MAX_LIVE_TICKETS: usize = 2;
const MAX_PENDING_NETWORK: usize = 16;
const MAX_DISPLAY_CLEANUP: usize = 16;
const STARTUP_RECONCILIATION_TIMEOUT_MS: u64 = 45_000;
// Leave five seconds for service-manager shutdown overhead (the user service
// uses TimeoutStopSec=20s); both live RTSP records share this aggregate budget.
const ORDERLY_SESSION_CLEANUP_BUDGET: Duration = Duration::from_secs(15);
const ORDERLY_SESSION_POLL_INTERVAL: Duration = Duration::from_millis(10);

struct PendingNetwork {
    connection: u64,
    ticket: u64,
    request: Request,
}

struct OpenRequest {
    request: u64,
    caller: String,
    config: Open,
    deadline: u64,
    display_preflight_deadline: Option<u64>,
}

struct DisplayAdmission {
    request: u64,
    caller: String,
    config: Open,
    deadline: u64,
    request_sha256: String,
    verified: bool,
    verification_started_at: u64,
    display_preflight_deadline: Option<u64>,
    call: Call,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoveryPhase {
    List,
    Stop,
    Wait,
    Complete,
    Blocked,
}

struct StartupRecovery {
    nonce: u64,
    operation_sequence: u64,
    deadline: u64,
    retry_status_at: u64,
    phase: RecoveryPhase,
    call: Option<Call>,
    stale_sessions: VecDeque<u64>,
    current_session: Option<u64>,
    error: Option<&'static str>,
}

impl StartupRecovery {
    fn new(nonce: u64, timeout_ms: u64) -> Self {
        Self {
            nonce,
            operation_sequence: 0,
            deadline: timeout_ms,
            retry_status_at: 0,
            phase: RecoveryPhase::List,
            call: None,
            stale_sessions: VecDeque::new(),
            current_session: None,
            error: None,
        }
    }

    fn ready(&self) -> bool {
        self.phase == RecoveryPhase::Complete
    }

    #[cfg(test)]
    fn completed(nonce: u64) -> Self {
        let mut recovery = Self::new(nonce, STARTUP_RECONCILIATION_TIMEOUT_MS);
        recovery.phase = RecoveryPhase::Complete;
        recovery
    }

    fn blocked(&self) -> bool {
        self.phase == RecoveryPhase::Blocked
    }

    fn blocked_code(&self) -> &'static str {
        self.error.unwrap_or("startup_reconciliation_unavailable")
    }

    fn operation_id(&mut self, step: &str, session: Option<u64>) -> String {
        self.operation_sequence = self
            .operation_sequence
            .checked_add(1)
            .expect("bounded startup reconciliation");
        match session {
            Some(session) => format!(
                "rtsp-recovery-{:016x}-{session:016x}-{step}-{}",
                self.nonce, self.operation_sequence
            ),
            None => format!(
                "rtsp-recovery-{:016x}-{step}-{}",
                self.nonce, self.operation_sequence
            ),
        }
    }
}

pub struct Controller {
    settings: Settings,
    bootstrap_settings: Settings,
    network_base_port: Option<u16>,
    network_address_family: Option<crate::model::AddressFamily>,
    network_bind_address: Option<String>,
    listener_base_port: Option<u16>,
    active_network_base_port: Option<u16>,
    active_address_family: Option<crate::model::AddressFamily>,
    active_bind_address: Option<String>,
    network_error: Option<&'static str>,
    network_retry_at: u64,
    transport: Option<Transport>,
    local: Option<SocketAddr>,
    locals: Vec<SocketAddr>,
    records: BTreeMap<u64, Record>,
    pending_network: VecDeque<PendingNetwork>,
    job: Option<Job>,
    display_admission: Option<DisplayAdmission>,
    display_cleanup: Vec<Call>,
    startup_recovery: StartupRecovery,
    sequence: u64,
    status_after: u64,
}

impl Controller {
    pub fn new(settings: Settings) -> Result<Self, &'static str> {
        settings.validate()?;
        let mut recovery_nonce = [0; 8];
        getrandom::fill(&mut recovery_nonce).map_err(|_| "random_unavailable")?;
        let network_base_port = settings.default_base_port();
        let (transport, locals, local) = if settings.enabled {
            let transport = Transport::bind_all(settings.resolved_binds()?, settings.allow_remote)?;
            let locals = transport.local_addrs()?;
            let local = locals.first().copied().ok_or("tcp_address_failed")?;
            (Some(transport), locals, Some(local))
        } else {
            (None, Vec::new(), None)
        };
        #[cfg(test)]
        let startup_recovery = StartupRecovery::completed(u64::from_ne_bytes(recovery_nonce));
        #[cfg(not(test))]
        let startup_recovery = StartupRecovery::new(
            u64::from_ne_bytes(recovery_nonce),
            STARTUP_RECONCILIATION_TIMEOUT_MS,
        );
        Ok(Self {
            bootstrap_settings: settings.clone(),
            active_address_family: None,
            active_bind_address: None,
            settings,
            network_base_port,
            network_address_family: None,
            network_bind_address: None,
            listener_base_port: network_base_port,
            active_network_base_port: None,
            network_error: None,
            network_retry_at: 0,
            transport,
            local,
            locals,
            records: BTreeMap::new(),
            pending_network: VecDeque::new(),
            job: None,
            display_admission: None,
            display_cleanup: Vec::new(),
            startup_recovery,
            sequence: 0,
            status_after: 0,
        })
    }

    pub fn tick(&mut self, runtime: &RuntimeClient, now: u64) -> ModuleResult<()> {
        self.poll_transport(now);
        self.advance_startup_recovery(runtime, now);
        self.advance_job(runtime, now);
        self.advance_display_admission(runtime, now);
        self.advance_display_cleanup(runtime);
        if self.job.is_none() {
            self.process_pending_network(now);
        }
        if self.job.is_none() {
            self.schedule_background(now);
        }
        if self.job.is_none() && self.display_admission.is_none() {
            self.poll_caller(runtime, now)?;
        }
        self.reconcile_network_port(now);
        Ok(())
    }

    /// Revoke RTSP tickets and make bounded, owner-scoped stop attempts for every
    /// known stream-session before this module unloads.
    pub fn shutdown(&mut self, runtime: &RuntimeClient) {
        let cleanup_deadline = Instant::now() + ORDERLY_SESSION_CLEANUP_BUDGET;
        if let Some(call) = self.startup_recovery.call.as_mut() {
            call.shutdown(runtime);
        }
        if let Some(job) = self.job.as_mut() {
            job.call.shutdown(runtime);
        }
        if let Some(admission) = self.display_admission.as_mut() {
            admission.call.shutdown(runtime);
        }
        for call in &mut self.display_cleanup {
            call.shutdown(runtime);
        }
        for record in self.records.values_mut() {
            if let Some(call) = record.uncertain.as_mut() {
                call.shutdown(runtime);
            }
        }
        self.stop_owned_sessions_on_shutdown(runtime, cleanup_deadline);
    }

    fn stop_owned_sessions_on_shutdown(&mut self, runtime: &RuntimeClient, deadline: Instant) {
        let tickets: Vec<_> = self.records.keys().copied().collect();
        for ticket in tickets {
            let Some(mut record) = self.records.remove(&ticket) else {
                continue;
            };
            if !record.state.terminal() && record.state != State::Closing {
                record.close(Some("module_stopping"));
            }
            self.revoke_ticket(ticket);
            if !record.cleanup_confirmed {
                self.stop_owned_session_on_shutdown(runtime, &mut record, deadline);
            }
            self.records.insert(ticket, record);
        }
    }

    fn stop_owned_session_on_shutdown(
        &mut self,
        runtime: &RuntimeClient,
        record: &mut Record,
        deadline: Instant,
    ) {
        if record.session.is_none() && record.needs_lookup {
            let lookup = shutdown_request(
                runtime,
                json!({"action":"lookup","operation_id":record.operation()}),
                format!("{}-module-shutdown-lookup", record.operation()),
                deadline,
            );
            match lookup {
                Ok(payload) if payload["ok"] == true => {
                    record.session = response_session(&payload);
                    if record.session.is_none() {
                        record.state = State::CleanupFailed;
                        record.cleanup_error = Some("shutdown_lookup_invalid");
                        return;
                    }
                }
                Ok(payload) if payload["code"] == "session_not_found" => {
                    record.state = State::CleanupFailed;
                    record.cleanup_error = Some("shutdown_lookup_not_found");
                    return;
                }
                _ => {
                    record.state = State::CleanupFailed;
                    record.cleanup_error = Some("shutdown_lookup_unconfirmed");
                    return;
                }
            }
        }

        let Some(session) = record.session else {
            record.cleanup_confirmed = true;
            finish_record(record);
            return;
        };
        let stop = shutdown_request(
            runtime,
            json!({"action":"stop","session":session}),
            format!("{}-module-shutdown-stop", record.operation()),
            deadline,
        );
        match stop {
            Ok(payload) if clean_terminal(record, &payload) => {
                record.stream_state = stream_state(&payload).map(str::to_owned);
                record.cleanup_confirmed = true;
                record.cleanup_error = None;
                finish_record(record);
            }
            Ok(_) => {
                record.state = State::CleanupFailed;
                record.cleanup_error = Some("shutdown_stop_rejected");
            }
            Err(code) => {
                record.state = State::CleanupFailed;
                record.cleanup_error = Some(code);
            }
        }
    }

    fn advance_startup_recovery(&mut self, runtime: &RuntimeClient, now: u64) {
        let recovery = &mut self.startup_recovery;
        if recovery.phase == RecoveryPhase::Complete {
            return;
        }
        if recovery.phase == RecoveryPhase::Blocked {
            if let Some(call) = recovery.call.as_mut() {
                match call.poll(runtime) {
                    Outcome::SettledFailure => recovery.call = None,
                    Outcome::Waiting | Outcome::Uncertain | Outcome::Result(_) => {}
                }
            }
            return;
        }
        if now >= recovery.deadline {
            recovery.error = Some("startup_reconciliation_timeout");
            recovery.phase = RecoveryPhase::Blocked;
            if let Some(call) = recovery.call.as_mut() {
                call.retry_settlement();
            }
            return;
        }

        if recovery.call.is_none() {
            match recovery.phase {
                RecoveryPhase::List => {
                    let operation = recovery.operation_id("list", None);
                    recovery.call = Some(Call::new(json!({"action":"status"}), operation, None));
                }
                RecoveryPhase::Stop => {
                    let Some(session) = recovery.stale_sessions.pop_front() else {
                        recovery.phase = RecoveryPhase::Complete;
                        return;
                    };
                    recovery.current_session = Some(session);
                    let operation = recovery.operation_id("stop", Some(session));
                    recovery.call = Some(Call::new(
                        json!({"action":"stop","session":session}),
                        operation,
                        None,
                    ));
                }
                RecoveryPhase::Wait if now >= recovery.retry_status_at => {
                    let Some(session) = recovery.current_session else {
                        recovery.error = Some("startup_reconciliation_state_invalid");
                        recovery.phase = RecoveryPhase::Blocked;
                        return;
                    };
                    let operation = recovery.operation_id("status", Some(session));
                    recovery.call = Some(Call::new(
                        json!({"action":"status","session":session}),
                        operation,
                        None,
                    ));
                }
                RecoveryPhase::Wait => return,
                RecoveryPhase::Complete | RecoveryPhase::Blocked => return,
            }
        }

        let phase = recovery.phase;
        let outcome = recovery
            .call
            .as_mut()
            .expect("startup recovery call created")
            .poll(runtime);
        match outcome {
            Outcome::Waiting => {}
            Outcome::SettledFailure | Outcome::Uncertain => {
                recovery.error = Some("startup_reconciliation_unavailable");
                recovery.phase = RecoveryPhase::Blocked;
                if let Some(call) = recovery.call.as_mut() {
                    call.retry_settlement();
                }
            }
            Outcome::Result(payload) => {
                recovery.call = None;
                let result = match phase {
                    RecoveryPhase::List => recovery_list(&payload).map(|sessions| {
                        recovery.stale_sessions = sessions;
                        recovery.phase = if recovery.stale_sessions.is_empty() {
                            RecoveryPhase::Complete
                        } else {
                            RecoveryPhase::Stop
                        };
                    }),
                    RecoveryPhase::Stop => {
                        let Some(session) = recovery.current_session else {
                            recovery.error = Some("startup_reconciliation_state_invalid");
                            recovery.phase = RecoveryPhase::Blocked;
                            return;
                        };
                        match recovery_stop_response(&payload, session) {
                            Ok(true) => finish_recovered_session(recovery),
                            Ok(false) => {
                                recovery.phase = RecoveryPhase::Wait;
                                recovery.retry_status_at = now.saturating_add(STATUS_INTERVAL_MS);
                                Ok(())
                            }
                            Err(code) => Err(code),
                        }
                    }
                    RecoveryPhase::Wait => {
                        let Some(session) = recovery.current_session else {
                            recovery.error = Some("startup_reconciliation_state_invalid");
                            recovery.phase = RecoveryPhase::Blocked;
                            return;
                        };
                        match recovery_status_response(&payload, session) {
                            Ok(true) => finish_recovered_session(recovery),
                            Ok(false) => {
                                recovery.retry_status_at = now.saturating_add(STATUS_INTERVAL_MS);
                                Ok(())
                            }
                            Err(code) => Err(code),
                        }
                    }
                    RecoveryPhase::Complete | RecoveryPhase::Blocked => Ok(()),
                };
                if let Err(code) = result {
                    recovery.error = Some(code);
                    recovery.phase = RecoveryPhase::Blocked;
                }
            }
        }
    }

    fn reply_status(&mut self, connection: u64, cseq: u32, status: u16) -> bool {
        serialize_response(status, cseq, &[], &[])
            .ok()
            .is_some_and(|reply| self.reply_bytes(connection, &reply))
    }

    fn reply_bytes(&mut self, connection: u64, reply: &[u8]) -> bool {
        self.transport
            .as_mut()
            .is_some_and(|transport| transport.reply(connection, reply).is_ok())
    }

    fn revoke_ticket(&mut self, ticket: u64) {
        if let Some(transport) = self.transport.as_mut() {
            let _ = transport.remove_ticket(ticket);
        }
        self.pending_network
            .retain(|pending| pending.ticket != ticket);
    }

    pub(super) fn configure_network_policy(
        &mut self,
        port: u16,
        address_family: Option<crate::model::AddressFamily>,
        bind_address: Option<String>,
        now: u64,
    ) -> Result<Value, &'static str> {
        crate::model::validate_base_port(port)?;
        let candidate =
            self.candidate_network_settings(port, address_family, bind_address.clone())?;
        candidate.validate()?;
        self.network_base_port = Some(port);
        self.network_address_family = address_family;
        self.network_bind_address = bind_address;
        self.network_error = None;
        let applied = self.try_apply_network_port();
        if let Err(error) = applied {
            self.network_error = Some(error);
            self.network_retry_at = now.saturating_add(1_000);
        } else if applied == Ok(true) {
            self.active_network_base_port = Some(port);
            self.network_retry_at = 0;
        }
        Ok(self.network_status(applied.is_ok_and(|applied| applied)))
    }

    #[cfg(test)]
    pub(super) fn configure_network_port(
        &mut self,
        port: u16,
        now: u64,
    ) -> Result<Value, &'static str> {
        self.configure_network_policy(port, None, None, now)
    }

    pub(super) fn media_binds_for_open(
        &self,
        local_address: IpAddr,
    ) -> Option<crate::model::MediaBinds> {
        self.active_network_base_port
            .or(self.listener_base_port)
            .and_then(|port| self.settings.media_binds_on(port, local_address).ok())
    }

    pub(super) fn advertised_local_for_peer(
        &self,
        peer: IpAddr,
    ) -> Result<SocketAddr, &'static str> {
        let listener = self
            .locals
            .iter()
            .copied()
            .find(|address| address.ip().is_ipv4() == peer.is_ipv4())
            .ok_or("peer_family_mismatch")?;
        if !listener.ip().is_unspecified() {
            return Ok(listener);
        }

        // UDP connect performs route selection without sending a datagram. The
        // resulting local endpoint is advertised and reused for this stream's
        // per-session UDP listeners instead of returning an unusable wildcard.
        let route = UdpSocket::bind(SocketAddr::new(listener.ip(), 0))
            .map_err(|_| "route_selection_failed")?;
        route
            .connect(SocketAddr::new(peer, 9))
            .map_err(|_| "route_selection_failed")?;
        let source = route.local_addr().map_err(|_| "route_selection_failed")?;
        if source.ip().is_unspecified() {
            return Err("route_selection_failed");
        }
        Ok(SocketAddr::new(source.ip(), listener.port()))
    }

    fn reconcile_network_port(&mut self, now: u64) {
        if self.network_base_port.is_none() || now < self.network_retry_at {
            return;
        }
        match self.try_apply_network_port() {
            Ok(true) => {
                self.active_network_base_port = self.network_base_port;
                self.network_error = None;
                self.network_retry_at = 0;
            }
            Ok(false) => {}
            Err(error) => {
                self.network_error = Some(error);
                self.network_retry_at = now.saturating_add(1_000);
            }
        }
    }

    fn try_apply_network_port(&mut self) -> Result<bool, &'static str> {
        let Some(base_port) = self.network_base_port else {
            return Ok(false);
        };
        let candidate = self.candidate_network_settings(
            base_port,
            self.network_address_family,
            self.network_bind_address.clone(),
        )?;
        candidate.validate()?;
        let binds = candidate.rtsp_binds_for_base(base_port)?;
        if self.active_network_base_port == Some(base_port)
            && self.active_address_family == self.network_address_family
            && self.active_bind_address == self.network_bind_address
            && self.locals == binds
        {
            return Ok(true);
        }
        if !candidate.enabled
            || self.records.values().any(|record| !record.state.terminal())
            || self
                .transport
                .as_ref()
                .is_some_and(|transport| transport.connection_count() != 0)
        {
            return Ok(false);
        }

        candidate.probe_media_binds(base_port)?;
        if self.locals == binds {
            self.listener_base_port = Some(base_port);
            self.active_network_base_port = Some(base_port);
            self.active_address_family = self.network_address_family;
            self.active_bind_address = self.network_bind_address.clone();
            self.settings = candidate;
            self.network_error = None;
            return Ok(true);
        }
        let transport = self.transport.as_mut().ok_or("tcp_listener_unavailable")?;
        transport.rebind_all(binds, candidate.allow_remote)?;
        let locals = transport.local_addrs()?;
        let local = locals.first().copied().ok_or("tcp_address_failed")?;
        self.local = Some(local);
        self.locals = locals;
        self.settings = candidate;
        self.listener_base_port = Some(base_port);
        self.active_network_base_port = Some(base_port);
        self.active_address_family = self.network_address_family;
        self.active_bind_address = self.network_bind_address.clone();
        self.network_error = None;
        Ok(true)
    }

    fn candidate_network_settings(
        &self,
        base_port: u16,
        address_family: Option<crate::model::AddressFamily>,
        bind_address: Option<String>,
    ) -> Result<Settings, &'static str> {
        crate::model::validate_base_port(base_port)?;
        let mut candidate = self.bootstrap_settings.clone();
        candidate.set_base_port(base_port)?;
        candidate.address_family = address_family.or(self.bootstrap_settings.address_family);
        candidate.bind_address =
            bind_address.or_else(|| self.bootstrap_settings.bind_address.clone());
        Ok(candidate)
    }

    fn network_status(&self, applied: bool) -> Value {
        serde_json::json!({
            "ok": true,
            "desired_port": self.network_base_port,
            "desired_address_family": self.network_address_family,
            "desired_bind_address": self.network_bind_address,
            "rtsp_port": self.local.map(|address| address.port()),
            "active_base_port": self.active_network_base_port,
            "active_address_family": self.active_address_family,
            "active_bind_address": self.active_bind_address,
            "rtsp_addresses": self.locals.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "active": applied,
            "pending": !applied,
            "udp_binds_preflighted": applied,
            "error": self.network_error,
        })
    }
}

fn recovery_list(payload: &Value) -> Result<VecDeque<u64>, &'static str> {
    let sessions = payload["sessions"]
        .as_array()
        .ok_or("startup_reconciliation_response_invalid")?;
    let total = payload["total"]
        .as_u64()
        .ok_or("startup_reconciliation_response_invalid")?;
    let truncated = payload["truncated"]
        .as_bool()
        .ok_or("startup_reconciliation_response_invalid")?;
    if payload["ok"] != true
        || sessions.len() > 16
        || total < sessions.len() as u64
        || (truncated && sessions.len() != 16)
        || (!truncated && total != sessions.len() as u64)
    {
        return Err("startup_reconciliation_response_invalid");
    }

    // Stream-session status is broker-scoped to this RTSP module principal and
    // places all nonterminal records before retained terminal history. Its live
    // record limit is two, so the bounded status page includes every orphan.
    let mut stale = VecDeque::new();
    let mut seen = BTreeSet::new();
    for session in sessions {
        let id = session["session"]
            .as_u64()
            .filter(|id| *id != 0)
            .ok_or("startup_reconciliation_response_invalid")?;
        let state = session["state"]
            .as_str()
            .ok_or("startup_reconciliation_response_invalid")?;
        if !known_stream_state(state) || !seen.insert(id) {
            return Err("startup_reconciliation_response_invalid");
        }
        let cleanup_clear = session["cleanup_error"].is_null();
        let terminal = matches!(state, "stopped" | "failed" | "cancelled") && cleanup_clear;
        if !terminal {
            stale.push_back(id);
        }
    }
    Ok(stale)
}

fn recovery_stop_response(payload: &Value, expected_session: u64) -> Result<bool, &'static str> {
    if payload["ok"] == false && payload["code"] == "session_not_found" {
        return Ok(true);
    }
    recovery_session_state(payload, expected_session)
}

fn recovery_status_response(payload: &Value, expected_session: u64) -> Result<bool, &'static str> {
    if payload["ok"] == false && payload["code"] == "session_not_found" {
        return Ok(true);
    }
    recovery_session_state(payload, expected_session)
}

fn recovery_session_state(payload: &Value, expected_session: u64) -> Result<bool, &'static str> {
    if payload["ok"] != true || payload["session"].as_u64() != Some(expected_session) {
        return Err("startup_reconciliation_response_invalid");
    }
    let state = payload["state"]
        .as_str()
        .ok_or("startup_reconciliation_response_invalid")?;
    if !known_stream_state(state) {
        return Err("startup_reconciliation_response_invalid");
    }
    if matches!(state, "stopped" | "failed" | "cancelled") {
        return if payload["cleanup_error"].is_null() {
            Ok(true)
        } else {
            Err("startup_reconciliation_cleanup_failed")
        };
    }
    if state == "cleanup_failed" {
        return Err("startup_reconciliation_cleanup_failed");
    }
    Ok(false)
}

fn known_stream_state(state: &str) -> bool {
    matches!(
        state,
        "preparing"
            | "prepared"
            | "armed"
            | "starting"
            | "active"
            | "stopping"
            | "stopped"
            | "failed"
            | "cancelled"
            | "cleanup_failed"
    )
}

fn finish_recovered_session(recovery: &mut StartupRecovery) -> Result<(), &'static str> {
    recovery.current_session = None;
    recovery.phase = RecoveryPhase::Stop;
    Ok(())
}

fn response_session(payload: &Value) -> Option<u64> {
    payload["session"].as_u64().filter(|session| *session != 0)
}

fn local_port(payload: &Value, field: &str) -> Result<u16, &'static str> {
    let port = payload[field]
        .as_str()
        .ok_or("invalid_prepare_response")?
        .parse::<SocketAddr>()
        .map_err(|_| "invalid_prepare_response")?
        .port();
    (port != 0)
        .then_some(port)
        .ok_or("invalid_prepare_response")
}

fn clean_terminal(record: &Record, payload: &Value) -> bool {
    payload["ok"] == true
        && response_session(payload) == record.session
        && matches!(
            stream_state(payload),
            Some("stopped" | "failed" | "cancelled")
        )
        && payload["cleanup_error"].is_null()
}

fn shutdown_request(
    runtime: &RuntimeClient,
    payload: Value,
    operation_id: String,
    deadline: Instant,
) -> Result<Value, &'static str> {
    let command = Command::Request {
        service: "amaterasu.stream-session/1".into(),
        payload,
        operation_id,
        parent: None,
        timeout_ms: CLEANUP_BUDGET_MS,
    };
    let id = match runtime.send_ephemeral(command) {
        Ok(Response::Accepted { id }) => id,
        Ok(Response::Error { .. }) => return Err("shutdown_request_unavailable"),
        _ => return Err("shutdown_request_unconfirmed"),
    };

    while Instant::now() < deadline {
        match runtime.send_ephemeral(Command::TakeResult { request: id }) {
            Ok(Response::Result { payload }) => {
                let released = match runtime.send_ephemeral(Command::ReleaseResult { request: id })
                {
                    Ok(Response::Ok) => true,
                    Ok(Response::Error { code, .. }) if code == "not_found" => true,
                    _ => false,
                };
                return if released {
                    Ok(payload)
                } else {
                    Err("shutdown_result_release_failed")
                };
            }
            Ok(Response::Pending) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if !remaining.is_zero() {
                    thread::sleep(ORDERLY_SESSION_POLL_INTERVAL.min(remaining));
                }
            }
            _ => return Err("shutdown_request_unconfirmed"),
        }
    }
    Err("shutdown_request_unconfirmed")
}

fn stream_state(payload: &Value) -> Option<&'static str> {
    match payload["state"].as_str()? {
        "preparing" => Some("preparing"),
        "prepared" => Some("prepared"),
        "armed" => Some("armed"),
        "starting" => Some("starting"),
        "active" => Some("active"),
        "stopping" => Some("stopping"),
        "stopped" => Some("stopped"),
        "failed" => Some("failed"),
        "cancelled" => Some("cancelled"),
        "cleanup_failed" => Some("cleanup_failed"),
        _ => None,
    }
}

fn missing(payload: &Value) -> bool {
    matches!(
        payload["code"].as_str(),
        Some("session_not_found" | "not_found")
    )
}

fn finish_record(record: &mut Record) {
    record.display_applied = false;
    record.cleanup_retry_count = 0;
    record.cleanup_retry_at = None;
    record.state = if record.failure.is_some() {
        State::Failed
    } else {
        State::Closed
    };
    record.cleanup_error = None;
}

fn complete_caller(record: &Record, caller: Option<u64>, runtime: &RuntimeClient) {
    if let Some(request) = caller.filter(|request| rpc::active(runtime, *request)) {
        rpc::complete(runtime, request, record.response());
    }
}

fn error(code: &str) -> Value {
    json!({"ok":false,"code":code})
}
