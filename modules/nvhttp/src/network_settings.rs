//! Reconciles the persisted NVHTTP base port with the RTSP and UDP endpoint owners.
use crate::product_settings::{NetworkTarget, ProductSettings};
use amaterasu_module_sdk::{Command, ModuleResult, Response, RuntimeClient};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

const RTSP_SERVICE: &str = "amaterasu.rtsp/1";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const INITIAL_RETRY_DELAY: Duration = Duration::from_secs(1);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);

pub struct NetworkSettings {
    active_base_port: Option<u16>,
    active_target: Option<NetworkTarget>,
    active_addresses: Option<Vec<String>>,
    error: Option<String>,
    pending: Option<PendingCall>,
    sequence: u64,
    next_retry: Instant,
    retry_delay: Duration,
}

struct PendingCall {
    operation_id: String,
    target: NetworkTarget,
    parent: Option<u64>,
    state: CallState,
}

enum CallState {
    Submitting,
    Waiting { child: u64 },
    Releasing { child: u64, outcome: ChildOutcome },
}

enum ChildOutcome {
    Payload(Value),
    Failure { code: String, message: String },
}

impl Default for NetworkSettings {
    fn default() -> Self {
        Self {
            active_base_port: None,
            active_target: None,
            active_addresses: None,
            error: None,
            pending: None,
            sequence: 0,
            next_retry: Instant::now(),
            retry_delay: INITIAL_RETRY_DELAY,
        }
    }
}

impl NetworkSettings {
    #[cfg(test)]
    pub fn active_base_port(&self) -> Option<u16> {
        self.active_base_port
    }

    /// Advances one idempotent RTSP configuration call, then starts a retry when needed.
    pub fn tick(
        &mut self,
        runtime: &RuntimeClient,
        port: u16,
        settings: &mut ProductSettings,
    ) -> ModuleResult<()> {
        if let Some(pending) = self.pending.take()
            && !self.advance(pending, runtime, settings)?
        {
            return Ok(());
        }
        let mut target = settings.rtsp_target();
        target.port = port;
        if self.active_target.as_ref() == Some(&target) || Instant::now() < self.next_retry {
            settings.set_active_rtsp_state(
                self.active_target.clone(),
                self.active_base_port,
                self.active_addresses.clone(),
            );
            return Ok(());
        }
        let Some(sequence) = self.sequence.checked_add(1) else {
            self.record_failure(
                &target,
                "resource_exhausted".into(),
                "network configuration operation identifier exhausted".into(),
                settings,
            );
            return Ok(());
        };
        self.sequence = sequence;
        self.pending = Some(PendingCall {
            operation_id: format!("nvhttp.network_settings.{sequence}"),
            target: target.clone(),
            parent: settings.rtsp_completion_request(&target),
            state: CallState::Submitting,
        });
        Ok(())
    }

    fn advance(
        &mut self,
        mut pending: PendingCall,
        runtime: &RuntimeClient,
        settings: &mut ProductSettings,
    ) -> ModuleResult<bool> {
        match &mut pending.state {
            CallState::Submitting => match runtime.send(Command::Request {
                service: RTSP_SERVICE.into(),
                payload: json!({
                    "action":"network_configure",
                    "port":pending.target.port,
                    "address_family":pending.target.address_family,
                    "bind_address":pending.target.bind_address,
                }),
                timeout_ms: REQUEST_TIMEOUT.as_millis() as u64,
                operation_id: pending.operation_id.clone(),
                parent: pending.parent,
            }) {
                Ok(Response::Accepted { id }) => {
                    pending.state = CallState::Waiting { child: id };
                    self.pending = Some(pending);
                    return Ok(false);
                }
                Ok(Response::Error { code, message }) => {
                    self.record_failure(&pending.target, code, message, settings);
                    return Ok(true);
                }
                Ok(response) => {
                    self.record_failure(
                        &pending.target,
                        "invalid_response".into(),
                        format!("RTSP configuration request returned {response:?}"),
                        settings,
                    );
                    return Ok(true);
                }
                Err(error) => {
                    self.error = Some(error.clone());
                    pending.state = CallState::Submitting;
                    self.pending = Some(pending);
                    return Ok(false);
                }
            },
            CallState::Waiting { child } => {
                match runtime.send(Command::TakeResult { request: *child }) {
                    Ok(Response::Pending) => {
                        self.pending = Some(pending);
                        return Ok(false);
                    }
                    Ok(Response::Result { payload }) => {
                        pending.state = CallState::Releasing {
                            child: *child,
                            outcome: ChildOutcome::Payload(payload),
                        };
                    }
                    Ok(Response::Error { code, message }) if code == "not_found" => {
                        self.record_failure(&pending.target, code, message, settings);
                        return Ok(true);
                    }
                    Ok(Response::Error { code, message }) => {
                        pending.state = CallState::Releasing {
                            child: *child,
                            outcome: ChildOutcome::Failure { code, message },
                        };
                    }
                    Ok(response) => {
                        pending.state = CallState::Releasing {
                            child: *child,
                            outcome: ChildOutcome::Failure {
                                code: "invalid_response".into(),
                                message: format!("RTSP configuration result returned {response:?}"),
                            },
                        };
                    }
                    Err(error) => {
                        self.error = Some(error);
                        self.pending = Some(pending);
                        return Ok(false);
                    }
                }
            }
            CallState::Releasing { .. } => {}
        }

        let CallState::Releasing { child, outcome } =
            std::mem::replace(&mut pending.state, CallState::Submitting)
        else {
            unreachable!("terminal child result must be released")
        };
        match runtime.send(Command::ReleaseResult { request: child }) {
            Ok(Response::Ok) => {
                self.finish(&pending.target, outcome, settings);
                Ok(true)
            }
            Ok(Response::Error { code, .. }) if code == "not_found" => {
                self.finish(&pending.target, outcome, settings);
                Ok(true)
            }
            Ok(Response::Error { code, message }) => {
                self.error = Some(format!("RTSP result release failed: {code}: {message}"));
                pending.state = CallState::Releasing { child, outcome };
                self.pending = Some(pending);
                Ok(false)
            }
            Ok(response) => {
                self.error = Some(format!("RTSP result release returned {response:?}"));
                pending.state = CallState::Releasing { child, outcome };
                self.pending = Some(pending);
                Ok(false)
            }
            Err(error) => {
                self.error = Some(error);
                pending.state = CallState::Releasing { child, outcome };
                self.pending = Some(pending);
                Ok(false)
            }
        }
    }

    fn finish(
        &mut self,
        target: &NetworkTarget,
        outcome: ChildOutcome,
        settings: &mut ProductSettings,
    ) {
        match outcome {
            ChildOutcome::Payload(payload) => {
                let reported_active_port = payload["active_base_port"]
                    .as_u64()
                    .and_then(|value| u16::try_from(value).ok());
                let has_reported_family = payload.get("active_address_family").is_some();
                let has_reported_bind = payload.get("active_bind_address").is_some();
                let reported_family =
                    serde_json::from_value(payload["active_address_family"].clone()).ok();
                let reported_bind = payload["active_bind_address"].as_str().map(str::to_owned);
                let reported_target = reported_active_port.map(|port| NetworkTarget {
                    port,
                    address_family: reported_family,
                    bind_address: reported_bind.clone(),
                });
                let reported_addresses = reported_target.as_ref().and_then(|reported| {
                    if !has_reported_family
                        || !has_reported_bind
                        || (!payload["active_address_family"].is_null()
                            && reported_family.is_none())
                        || (!payload["active_bind_address"].is_null() && reported_bind.is_none())
                    {
                        return None;
                    }
                    verified_rtsp_addresses(&payload["rtsp_addresses"], reported)
                });
                let fully_applied = payload["ok"] == true
                    && payload["desired_port"].as_u64() == Some(u64::from(target.port))
                    && payload["desired_address_family"] == json!(target.address_family)
                    && payload["desired_bind_address"] == json!(target.bind_address)
                    && payload["active"] == true
                    && payload["udp_binds_preflighted"] == true
                    && reported_target.as_ref() == Some(target)
                    && reported_addresses.is_some();
                if fully_applied {
                    self.active_base_port = reported_active_port;
                    self.active_target = Some(target.clone());
                    self.active_addresses = reported_addresses;
                    self.error = None;
                    self.retry_delay = INITIAL_RETRY_DELAY;
                    self.next_retry = Instant::now() + self.retry_delay;
                    settings.set_active_rtsp_state(
                        self.active_target.clone(),
                        reported_active_port,
                        self.active_addresses.clone(),
                    );
                    settings.record_rtsp_apply_success();
                } else {
                    // A response is an observation of live listeners, including
                    // loss after failed rollback. Never resurrect a cached tuple
                    // when its returned endpoints are absent or inconsistent.
                    if let Some(addresses) = reported_addresses {
                        // The RTSP owner has accepted a different desired
                        // policy. Old live sockets do not prove that reverting
                        // NVHTTP's desired policy cancels that pending request.
                        self.active_target = None;
                        self.active_base_port = reported_active_port;
                        self.active_addresses = Some(addresses);
                    } else {
                        self.active_target = None;
                        self.active_base_port = None;
                        self.active_addresses = None;
                    }
                    let message = payload["error"]
                        .as_str()
                        .or_else(|| {
                            payload["pending"]
                                .as_bool()
                                .filter(|pending| *pending)
                                .map(|_| "an RTSP stream is active")
                        })
                        .unwrap_or("RTSP did not activate the requested base port")
                        .to_owned();
                    self.record_failure(target, "listener_apply_pending".into(), message, settings);
                    settings.set_active_rtsp_state(
                        self.active_target.clone(),
                        self.active_base_port,
                        self.active_addresses.clone(),
                    );
                }
            }
            ChildOutcome::Failure { code, message } => {
                self.record_failure(target, code, message, settings);
            }
        }
    }

    fn record_failure(
        &mut self,
        target: &NetworkTarget,
        code: String,
        message: String,
        settings: &mut ProductSettings,
    ) {
        let description = format!("{code}: {message}");
        self.error = Some(description.clone());
        settings.record_rtsp_apply_failure(target, description);
        self.next_retry = Instant::now() + self.retry_delay;
        self.retry_delay = (self.retry_delay * 2).min(MAX_RETRY_DELAY);
    }
}

fn verified_rtsp_addresses(payload: &Value, target: &NetworkTarget) -> Option<Vec<String>> {
    use crate::settings::AddressFamily;
    use amaterasu_network_policy::{GameStreamPorts, invalid_configured_bind};
    use std::net::{IpAddr, SocketAddr};
    let port = GameStreamPorts::new(target.port).ok()?.rtsp();
    let values = payload.as_array()?;
    if values.is_empty() || values.len() > 2 {
        return None;
    }
    let explicit = target
        .bind_address
        .as_deref()
        .filter(|address| !address.trim().is_empty())
        .map(|address| address.trim().parse::<IpAddr>())
        .transpose()
        .ok()?;
    let mut addresses = Vec::with_capacity(values.len());
    let mut ips = Vec::with_capacity(values.len());
    for value in values {
        let text = value.as_str()?;
        let address = text.parse::<SocketAddr>().ok()?;
        if address.port() != port
            || invalid_configured_bind(address.ip())
            || target
                .address_family
                .is_some_and(|family| family == AddressFamily::Ipv4 && !address.is_ipv4())
            || explicit.is_some_and(|ip| ip != address.ip())
            || ips.contains(&address.ip())
            || ips
                .iter()
                .any(|ip: &IpAddr| ip.is_ipv4() == address.is_ipv4())
        {
            return None;
        }
        ips.push(address.ip());
        addresses.push(text.to_owned());
    }
    if explicit.is_none() && target.address_family == Some(AddressFamily::Both) && ips.len() != 2 {
        return None;
    }
    Some(addresses)
}

#[cfg(test)]
mod tests;
