use super::*;
use sha2::{Digest, Sha256};

impl Controller {
    pub(super) fn poll_caller(&mut self, runtime: &RuntimeClient, now: u64) -> ModuleResult<()> {
        match runtime.send_ephemeral(Command::Poll {})? {
            Response::Request {
                id,
                caller,
                service,
                payload,
                remaining_ms,
                ..
            } => {
                if service != crate::SERVICE {
                    rpc::complete(runtime, id, error("invalid_service"));
                } else if !rpc::active(runtime, id) {
                    // The broker has already cancelled the caller-owned ticket.
                } else {
                    match serde_json::from_value::<Operation>(payload) {
                        Ok(operation) => {
                            self.receive(id, caller, operation, now, remaining_ms, runtime)
                        }
                        Err(_) => {
                            rpc::complete(runtime, id, error("invalid_request"));
                        }
                    }
                }
                Ok(())
            }
            Response::Pending => Ok(()),
            _ => Err("RTSP poll failed".into()),
        }
    }

    pub(super) fn receive(
        &mut self,
        request: u64,
        caller: String,
        operation: Operation,
        now: u64,
        remaining: u64,
        runtime: &RuntimeClient,
    ) {
        match operation {
            Operation::Open(config) => self.open(
                OpenRequest {
                    request,
                    caller,
                    config: *config,
                    deadline: now.saturating_add(remaining.min(PREPARE_BUDGET_MS)),
                    display_preflight_deadline: None,
                },
                now,
                runtime,
                false,
            ),
            Operation::NetworkConfigure {
                port,
                address_family,
                bind_address,
            } => {
                if caller != "amaterasu.nvhttp" {
                    rpc::complete(runtime, request, error("permission_denied"));
                } else {
                    let payload = self
                        .configure_network_policy(port, address_family, bind_address, now)
                        .unwrap_or_else(error);
                    rpc::complete(runtime, request, payload);
                }
            }
            Operation::Close { ticket } => self.close(request, &caller, ticket, now, runtime),
            Operation::Status { ticket } => self.status(request, &caller, ticket, runtime),
            Operation::Lookup { operation_id } => {
                self.lookup(request, &caller, &operation_id, runtime)
            }
        }
    }

    pub(super) fn open(
        &mut self,
        input: OpenRequest,
        now: u64,
        runtime: &RuntimeClient,
        verified: bool,
    ) {
        let OpenRequest {
            request,
            caller,
            config,
            deadline,
            display_preflight_deadline,
        } = input;
        if !self.startup_recovery.ready() {
            rpc::complete(
                runtime,
                request,
                error(if self.startup_recovery.blocked() {
                    self.startup_recovery.blocked_code()
                } else {
                    "startup_reconciliation_pending"
                }),
            );
            return;
        }
        if !self.settings.enabled {
            rpc::complete(runtime, request, error("disabled"));
            return;
        }
        if !self
            .settings
            .allowed_principals
            .iter()
            .any(|allowed| allowed == &caller)
        {
            rpc::complete(runtime, request, error("permission_denied"));
            return;
        }
        if let Err(code) = config.validate(self.settings.allow_remote) {
            rpc::complete(runtime, request, error(code));
            return;
        }
        if config.frame_limiter_settings.is_some() && caller != "amaterasu.nvhttp" {
            rpc::complete(runtime, request, error("frame_limiter_snapshot_denied"));
            return;
        }
        if config
            .history_activity_id
            .as_deref()
            .is_some_and(|activity_id| {
                caller != "amaterasu.nvhttp" || activity_id != config.operation_id
            })
        {
            rpc::complete(runtime, request, error("history_activity_denied"));
            return;
        }
        if display_preflight_deadline
            .is_some_and(|expiry| expiry.saturating_sub(now) <= PREPARE_BUDGET_MS)
        {
            rpc::complete(runtime, request, error("display_admission_expired"));
            return;
        }
        let local = match self.advertised_local_for_peer(config.peer_ip) {
            Ok(local) => local,
            Err(code) => {
                rpc::complete(runtime, request, error(code));
                return;
            }
        };
        if let Some(existing) = self.records.values().find(|record| {
            record.owner == caller && record.config.operation_id == config.operation_id
        }) {
            let response = if existing.config == config {
                existing.response()
            } else {
                error("operation_conflict")
            };
            rpc::complete(runtime, request, response);
            return;
        }
        if self.records.len() >= MAX_RECORDS
            || self
                .records
                .values()
                .filter(|record| !record.state.terminal())
                .count()
                >= MAX_LIVE_TICKETS
        {
            rpc::complete(runtime, request, error("capacity_exceeded"));
            return;
        }
        if config.display_admission_required() && !verified {
            if self.display_cleanup.len() >= MAX_DISPLAY_CLEANUP {
                rpc::complete(runtime, request, error("display_admission_unavailable"));
                return;
            }
            if caller != "amaterasu.nvhttp" {
                rpc::complete(runtime, request, error("permission_denied"));
                return;
            }
            let digest = config
                .display_request_sha256()
                .expect("validated display admission request");
            let snapshot = config
                .display_policy_snapshot
                .as_ref()
                .expect("validated snapshot");
            let token = config
                .display_admission_token
                .as_deref()
                .expect("validated token");
            let payload = json!({
                "action":"verify_display_admission",
                "token":token,
                "application_operation_id":config.application_operation_id,
                "rtsp_operation_id":config.operation_id,
                "request_sha256":digest,
                "display_policy_snapshot":snapshot,
                "certificate_id":snapshot["certificate_id"],
                "catalog_revision":snapshot["catalog_revision"],
            });
            let call = Call::for_service(
                "amaterasu.launch/1",
                payload,
                format!(
                    "rtsp-display-{:x}",
                    Sha256::digest(format!("{token}:{}", config.operation_id).as_bytes())
                ),
                Some(request),
            );
            self.display_admission = Some(DisplayAdmission {
                request,
                caller,
                config,
                deadline,
                request_sha256: digest,
                verified: false,
                verification_started_at: now,
                display_preflight_deadline: None,
                call,
            });
            return;
        }
        let (ticket, session_token, udp_discovery) = match self.new_identity(config.discover_peers)
        {
            Ok(identity) => identity,
            Err(code) => {
                rpc::complete(runtime, request, error(code));
                return;
            }
        };
        let url = format!("rtspenc://{local}/launch-{ticket:016x}");
        let expires = deadline;
        let mut record = Record {
            id: ticket,
            owner: caller,
            config,
            state: State::Preparing,
            session: None,
            negotiation: None,
            negotiated_encryption: None,
            negotiated_slices_per_frame: None,
            negotiated_video_stream_format: None,
            client_feature_flags: None,
            negotiated_color: None,
            negotiated_video: None,
            url,
            session_token,
            udp_discovery,
            local,
            expires,
            next_status: expires,
            failure: None,
            cleanup_error: None,
            cleanup_retry_count: 0,
            cleanup_retry_at: None,
            uncertain: None,
            uncertain_phase: None,
            needs_lookup: true,
            stream_state: None,
            display_applied: false,
            display_preflight_deadline,
            display_lease_ready_until: None,
            display_prepare_timeout_ms: None,
            revoke_after: None,
            cleanup_confirmed: false,
        };
        let media_binds = self.media_binds_for_open(local.ip());
        let mut payload = record.config.prepare_with_media_binds(
            &record.operation(),
            record.udp_discovery.as_ref(),
            media_binds,
        );
        if record.config.display_admission_required() {
            // Stream-session starts its prepared timer after Apply/readback. Reserve
            // the whole Prepare budget so an orphaned lease cannot outlive Launch's
            // staged admission if this RTSP module stops before explicit cleanup.
            let remaining = record
                .display_preflight_deadline
                .map_or(u64::MAX, |expiry| {
                    expiry.saturating_sub(now).saturating_sub(PREPARE_BUDGET_MS)
                });
            let effective_timeout = if record.display_preflight_deadline.is_some() {
                remaining.min(STAGED_DISPLAY_PREPARE_MAX_MS)
            } else {
                u64::from(record.config.ping_timeout_ms)
            };
            if record.display_preflight_deadline.is_some() {
                payload["display_prepare_timeout_ms"] = json!(effective_timeout);
                record.display_prepare_timeout_ms = Some(effective_timeout as u32);
            }
            record.display_lease_ready_until = Some(now.saturating_add(effective_timeout));
        }
        let operation = self.operation_id(&record, "prepare");
        self.records.insert(ticket, record);
        self.job = Some(Job {
            ticket,
            phase: Phase::Prepare,
            call: Call::new(payload, operation, Some(request)),
            caller: Some(request),
            network: None,
            deadline: expires,
        });
    }

    pub(super) fn advance_display_admission(&mut self, runtime: &RuntimeClient, now: u64) {
        let Some(mut admission) = self.display_admission.take() else {
            return;
        };
        if admission.verified {
            if self.job.is_some() {
                self.display_admission = Some(admission);
            } else if now < admission.deadline && rpc::active(runtime, admission.request) {
                self.open(
                    OpenRequest {
                        request: admission.request,
                        caller: admission.caller,
                        config: admission.config,
                        deadline: admission.deadline,
                        display_preflight_deadline: admission.display_preflight_deadline,
                    },
                    now,
                    runtime,
                    true,
                );
            } else {
                rpc::complete(
                    runtime,
                    admission.request,
                    error("display_admission_unavailable"),
                );
            }
            return;
        }
        if now >= admission.deadline || !rpc::active(runtime, admission.request) {
            admission.call.cancel();
        }
        match admission.call.poll(runtime) {
            Outcome::Waiting => {
                if now >= admission.deadline || !rpc::active(runtime, admission.request) {
                    rpc::complete(
                        runtime,
                        admission.request,
                        error("display_admission_unavailable"),
                    );
                    self.display_cleanup.push(admission.call);
                } else {
                    self.display_admission = Some(admission);
                }
            }
            Outcome::Result(response) => {
                let remaining = response
                    .get("preflight_remaining_ms")
                    .and_then(Value::as_u64);
                let valid_remaining = response["preflight_remaining_ms"].is_null()
                    || remaining.is_some_and(|value| (1..=120_000).contains(&value));
                let preflight_deadline =
                    remaining.map(|value| admission.verification_started_at.saturating_add(value));
                if response["ok"] == true
                    && response["verified"] == true
                    && response["rtsp_operation_id"] == admission.config.operation_id
                    && response["request_sha256"] == admission.request_sha256
                    && valid_remaining
                    && preflight_deadline.is_none_or(|expiry| now < expiry)
                    && now < admission.deadline
                    && rpc::active(runtime, admission.request)
                {
                    admission.verified = true;
                    admission.display_preflight_deadline = preflight_deadline;
                    self.display_admission = Some(admission);
                } else {
                    rpc::complete(
                        runtime,
                        admission.request,
                        error("display_admission_denied"),
                    );
                }
            }
            Outcome::SettledFailure => {
                rpc::complete(
                    runtime,
                    admission.request,
                    error("display_admission_unavailable"),
                );
            }
            Outcome::Uncertain => {
                admission.call.retry_settlement();
                rpc::complete(
                    runtime,
                    admission.request,
                    error("display_admission_unavailable"),
                );
                self.display_cleanup.push(admission.call);
            }
        }
    }

    pub(super) fn advance_display_cleanup(&mut self, runtime: &RuntimeClient) {
        self.display_cleanup
            .retain_mut(|call| match call.poll(runtime) {
                Outcome::SettledFailure => false,
                Outcome::Waiting => true,
                Outcome::Uncertain | Outcome::Result(_) => {
                    call.retry_settlement();
                    true
                }
            });
    }

    pub(super) fn close(
        &mut self,
        request: u64,
        caller: &str,
        ticket: u64,
        now: u64,
        runtime: &RuntimeClient,
    ) {
        let Some(mut record) = self.records.remove(&ticket) else {
            rpc::complete(runtime, request, error("ticket_not_found"));
            return;
        };
        if record.owner != caller {
            self.records.insert(ticket, record);
            rpc::complete(runtime, request, error("ticket_not_found"));
            return;
        }
        if record.state.terminal() {
            rpc::complete(runtime, request, record.response());
            self.records.insert(ticket, record);
            return;
        }
        record.close(None);
        record.cleanup_error = None;
        self.revoke_ticket(ticket);
        self.schedule_cleanup(&mut record, Some(request), now);
        if self.job.is_none() {
            complete_caller(&record, Some(request), runtime);
        }
        self.records.insert(ticket, record);
    }

    pub(super) fn status(
        &self,
        request: u64,
        caller: &str,
        ticket: Option<u64>,
        runtime: &RuntimeClient,
    ) {
        let response = if let Some(ticket) = ticket {
            self.records
                .get(&ticket)
                .filter(|record| record.owner == caller)
                .map(Record::response)
                .unwrap_or_else(|| error("ticket_not_found"))
        } else {
            let owned: Vec<_> = self
                .records
                .values()
                .filter(|record| record.owner == caller)
                .collect();
            let tickets: Vec<_> = owned
                .iter()
                .filter(|record| !record.state.terminal())
                .chain(owned.iter().filter(|record| record.state.terminal()))
                .take(16)
                .map(|record| record.response())
                .collect();
            json!({"ok":true,"enabled":self.settings.enabled,"local":self.local,
                "locals":self.locals,
                "connections":self.transport.as_ref().map_or(0, Transport::connection_count),
                "tickets":tickets,"total":owned.len(),"truncated":owned.len()>16})
        };
        rpc::complete(runtime, request, response);
    }

    pub(super) fn lookup(
        &self,
        request: u64,
        caller: &str,
        operation_id: &str,
        runtime: &RuntimeClient,
    ) {
        let response = if valid_name(operation_id) {
            self.records
                .values()
                .find(|record| record.owner == caller && record.config.operation_id == operation_id)
                .map(Record::response)
                .unwrap_or_else(|| error("ticket_not_found"))
        } else {
            error("invalid_operation_id")
        };
        rpc::complete(runtime, request, response);
    }

    pub(super) fn new_identity(
        &self,
        discover_peers: bool,
    ) -> Result<(u64, String, Option<UdpDiscovery>), &'static str> {
        for _ in 0..8 {
            let mut bytes = [0; 48];
            getrandom::fill(&mut bytes).map_err(|_| "random_unavailable")?;
            let id = u64::from_ne_bytes(bytes[..8].try_into().expect("fixed slice"));
            if id == 0 || self.records.contains_key(&id) {
                continue;
            }
            let mut token = String::with_capacity(32);
            for byte in &bytes[8..24] {
                use std::fmt::Write;
                write!(&mut token, "{byte:02x}").expect("string write");
            }
            let udp_discovery = discover_peers.then(|| UdpDiscovery {
                audio_ping_payload: encode_ping_payload(
                    bytes[24..36].try_into().expect("fixed slice"),
                ),
                video_ping_payload: encode_ping_payload(
                    bytes[36..48].try_into().expect("fixed slice"),
                ),
            });
            if udp_discovery.as_ref().is_some_and(|discovery| {
                discovery.audio_ping_payload == discovery.video_ping_payload
            }) {
                continue;
            }
            return Ok((id, token, udp_discovery));
        }
        Err("identifier_exhausted")
    }
}

fn encode_ping_payload(bytes: &[u8; 12]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity(16);
    for chunk in bytes.as_chunks::<3>().0 {
        let bits = u32::from_be_bytes([0, chunk[0], chunk[1], chunk[2]]);
        for shift in [18, 12, 6, 0] {
            output.push(ALPHABET[((bits >> shift) & 0x3f) as usize] as char);
        }
    }
    output
}
