//! UPnP listener selection and owned gateway-mapping lifecycle.
use amaterasu_module_sdk::{Command, Response, RuntimeClient};
use amaterasu_network_policy::GameStreamPorts;
use amaterasu_upnp::{
    Gateway, IgdGateway, MappingEndpoint, MappingManager, Protocol, RECOMMENDED_REFRESH_INTERVAL,
    discover_gateway,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MANAGEMENT_SERVICE: &str = "amaterasu.management/1";
const EXPOSURE_REFRESH_INTERVAL: Duration = Duration::from_secs(2);
const EXPOSURE_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const CLEANUP_RETRY_INTERVAL: Duration = Duration::from_secs(5);
const MAX_RUNTIME_ERROR_CHARS: usize = 256;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ManagementExposureSnapshot {
    pub(crate) wan_enabled: bool,
    pub(crate) tls_address: Option<SocketAddr>,
}

/// Polls the management module for the live WAN policy and TLS socket.
pub(crate) struct ManagementExposure {
    pending: Option<u64>,
    cancelling: bool,
    sequence: u64,
    next_request: Instant,
    snapshot: ManagementExposureSnapshot,
}

impl Default for ManagementExposure {
    fn default() -> Self {
        Self {
            pending: None,
            cancelling: false,
            sequence: 0,
            next_request: Instant::now(),
            snapshot: ManagementExposureSnapshot::default(),
        }
    }
}

impl ManagementExposure {
    pub(crate) fn tick(&mut self, runtime: &RuntimeClient) {
        if let Some(request) = self.pending {
            if self.cancelling {
                self.cancel_pending(runtime, request);
                return;
            }
            match runtime.send_ephemeral(Command::TakeResult { request }) {
                Ok(Response::Pending) => return,
                Ok(Response::Result { payload }) => {
                    self.snapshot = parse_management_exposure(&payload);
                    self.pending = None;
                    self.next_request = Instant::now() + EXPOSURE_REFRESH_INTERVAL;
                }
                Ok(Response::Error { code, .. }) if code == "not_found" => {
                    self.snapshot = ManagementExposureSnapshot::default();
                    self.pending = None;
                    self.next_request = Instant::now() + EXPOSURE_REFRESH_INTERVAL;
                }
                _ => {
                    self.snapshot = ManagementExposureSnapshot::default();
                    self.cancelling = true;
                    self.cancel_pending(runtime, request);
                    return;
                }
            }
            return;
        }

        if Instant::now() < self.next_request {
            return;
        }
        let Some(sequence) = self.sequence.checked_add(1) else {
            self.snapshot = ManagementExposureSnapshot::default();
            self.next_request = Instant::now() + EXPOSURE_REFRESH_INTERVAL;
            return;
        };
        self.sequence = sequence;
        let command = Command::Request {
            service: MANAGEMENT_SERVICE.into(),
            payload: json!({"action":"upnp_exposure"}),
            timeout_ms: EXPOSURE_REQUEST_TIMEOUT.as_millis() as u64,
            operation_id: format!("nvhttp.upnp.exposure.{sequence}"),
            parent: None,
        };
        match runtime.send(command) {
            Ok(Response::Accepted { id }) => self.pending = Some(id),
            _ => {
                self.snapshot = ManagementExposureSnapshot::default();
                self.next_request = Instant::now() + EXPOSURE_REFRESH_INTERVAL;
            }
        }
    }

    pub(crate) fn snapshot(&self) -> ManagementExposureSnapshot {
        self.snapshot
    }

    fn cancel_pending(&mut self, runtime: &RuntimeClient, request: u64) {
        for command in [
            Command::Cancel { request },
            Command::ReleaseResult { request },
        ] {
            match runtime.send(command) {
                Ok(Response::Ok) => {}
                Ok(Response::Error { code, .. }) if code == "not_found" => {}
                _ => return,
            }
        }
        self.pending = None;
        self.cancelling = false;
        self.next_request = Instant::now() + EXPOSURE_REFRESH_INTERVAL;
    }
}

fn parse_management_exposure(payload: &Value) -> ManagementExposureSnapshot {
    if payload.get("ok").and_then(Value::as_bool) != Some(true)
        || payload.get("wan_enabled").and_then(Value::as_bool) != Some(true)
    {
        return ManagementExposureSnapshot::default();
    }
    let tls_address = payload
        .get("tls_address")
        .and_then(Value::as_str)
        .and_then(|address| address.parse().ok());
    ManagementExposureSnapshot {
        wan_enabled: tls_address.is_some(),
        tls_address,
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct DesiredMappings {
    enabled: bool,
    ipv6_enabled: bool,
    endpoints: Vec<MappingEndpoint>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UpnpRuntimeStatus {
    pub(crate) status: String,
    pub(crate) error: Option<String>,
}

impl Default for UpnpRuntimeStatus {
    fn default() -> Self {
        Self {
            status: "disabled".into(),
            error: None,
        }
    }
}

enum LifecycleCommand {
    Configure(DesiredMappings),
    Shutdown,
}

/// Owns the UPnP worker and guarantees an orderly best-effort cleanup on drop.
pub(crate) struct UpnpLifecycle {
    commands: Sender<LifecycleCommand>,
    statuses: Receiver<UpnpRuntimeStatus>,
    worker: Option<JoinHandle<()>>,
    ipv6_lifecycle: crate::upnp_ipv6::Ipv6PinholeLifecycle,
    last_desired: Option<DesiredMappings>,
    ipv4_status: UpnpRuntimeStatus,
    ipv6_status: UpnpRuntimeStatus,
    status: UpnpRuntimeStatus,
}

impl UpnpLifecycle {
    pub(crate) fn new() -> Self {
        let (command_tx, command_rx) = mpsc::channel();
        let (status_tx, status_rx) = mpsc::channel();
        let worker = thread::Builder::new()
            .name("amaterasu-upnp".into())
            .spawn(move || run_worker(command_rx, status_tx))
            .ok();
        let status = if worker.is_some() {
            UpnpRuntimeStatus::default()
        } else {
            UpnpRuntimeStatus {
                status: "error".into(),
                error: Some("UPnP lifecycle worker could not be started".into()),
            }
        };
        let ipv6_lifecycle = crate::upnp_ipv6::Ipv6PinholeLifecycle::new();
        let ipv6_status = ipv6_lifecycle.status().clone();
        Self {
            commands: command_tx,
            statuses: status_rx,
            worker,
            ipv6_lifecycle,
            last_desired: None,
            ipv4_status: status.clone(),
            ipv6_status,
            status,
        }
    }

    pub(crate) fn update(&mut self, desired: DesiredMappings) {
        if self.last_desired.as_ref() != Some(&desired) {
            if self
                .commands
                .send(LifecycleCommand::Configure(desired.clone()))
                .is_ok()
            {
                self.last_desired = Some(desired.clone());
            } else {
                self.status = UpnpRuntimeStatus {
                    status: "error".into(),
                    error: Some("UPnP lifecycle worker stopped unexpectedly".into()),
                };
            }
        }
        while let Ok(status) = self.statuses.try_recv() {
            self.ipv4_status = status;
        }
        self.ipv6_lifecycle
            .update(desired.enabled, desired.ipv6_enabled, &desired.endpoints);
        self.ipv6_status = self.ipv6_lifecycle.status().clone();
        self.status = merge_runtime_status(&self.ipv4_status, &self.ipv6_status);
    }

    pub(crate) fn status(&self) -> &UpnpRuntimeStatus {
        &self.status
    }

    pub(crate) fn shutdown(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = self.commands.send(LifecycleCommand::Shutdown);
            let _ = worker.join();
        }
        while let Ok(status) = self.statuses.try_recv() {
            self.ipv4_status = status;
        }
        self.ipv6_lifecycle.shutdown();
        self.ipv6_status = self.ipv6_lifecycle.status().clone();
        self.status = merge_runtime_status(&self.ipv4_status, &self.ipv6_status);
    }
}

impl Drop for UpnpLifecycle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub(crate) fn build_desired_mappings(
    enabled: bool,
    http_addresses: &[SocketAddr],
    https_addresses: &[SocketAddr],
    rtsp_base_port: Option<u16>,
    rtsp_addresses: &[String],
    management: ManagementExposureSnapshot,
    address_family_includes_ipv6: bool,
) -> DesiredMappings {
    if !enabled {
        return DesiredMappings::default();
    }

    let mut endpoints = Vec::new();
    if let Some(http_base_port) = http_addresses.first().map(SocketAddr::port)
        && let Ok(ports) = GameStreamPorts::new(http_base_port)
    {
        append_listener_endpoints(
            &mut endpoints,
            http_addresses,
            ports.http(),
            ports.http(),
            Protocol::Tcp,
        );
        append_listener_endpoints(
            &mut endpoints,
            https_addresses,
            ports.https(),
            ports.https(),
            Protocol::Tcp,
        );
    }

    if let Some(base_port) = rtsp_base_port
        && let Ok(ports) = GameStreamPorts::new(base_port)
    {
        let rtsp_addresses = parse_addresses(rtsp_addresses);
        append_listener_endpoints(
            &mut endpoints,
            &rtsp_addresses,
            ports.rtsp(),
            ports.rtsp(),
            Protocol::Tcp,
        );
        for port in [ports.video(), ports.audio(), ports.control()] {
            append_listener_endpoints(
                &mut endpoints,
                &rtsp_addresses,
                ports.rtsp(),
                port,
                Protocol::Udp,
            );
        }
    }

    if management.wan_enabled
        && let Some(address) = management.tls_address
    {
        endpoints.push(MappingEndpoint::new(
            address.ip(),
            address.port(),
            Protocol::Tcp,
            true,
        ));
    }

    DesiredMappings {
        enabled: true,
        ipv6_enabled: address_family_includes_ipv6,
        endpoints,
    }
}

fn merge_runtime_status(ipv4: &UpnpRuntimeStatus, ipv6: &UpnpRuntimeStatus) -> UpnpRuntimeStatus {
    let error = combine_runtime_errors(ipv4.error.iter().chain(ipv6.error.iter()).cloned());
    if ipv4.status == "active" || ipv6.status == "active" {
        return UpnpRuntimeStatus {
            status: "active".into(),
            error,
        };
    }
    if let Some(error) = error {
        return UpnpRuntimeStatus {
            status: "error".into(),
            error: Some(error),
        };
    }
    let status = if ipv4.status == "waiting_for_gateway_route"
        || ipv6.status == "waiting_for_gateway_route"
    {
        "waiting_for_gateway_route"
    } else if ipv4.status == "waiting_for_ipv4_listener"
        || ipv6.status == "waiting_for_ipv4_listener"
    {
        "waiting_for_ipv4_listener"
    } else if ipv4.status == "waiting_for_listener" || ipv6.status == "waiting_for_listener" {
        "waiting_for_listener"
    } else {
        "disabled"
    };
    UpnpRuntimeStatus {
        status: status.into(),
        error: None,
    }
}

fn parse_addresses(addresses: &[String]) -> Vec<SocketAddr> {
    addresses
        .iter()
        .filter_map(|address| address.parse().ok())
        .collect()
}

fn append_listener_endpoints(
    endpoints: &mut Vec<MappingEndpoint>,
    addresses: &[SocketAddr],
    expected_listener_port: u16,
    mapped_port: u16,
    protocol: Protocol,
) {
    endpoints.extend(
        addresses
            .iter()
            .filter(|address| address.port() == expected_listener_port)
            .map(|address| MappingEndpoint::new(address.ip(), mapped_port, protocol, true)),
    );
}

fn run_worker(commands: Receiver<LifecycleCommand>, statuses: Sender<UpnpRuntimeStatus>) {
    let mut desired = DesiredMappings::default();
    let mut gateways: BTreeMap<String, GatewayOwner<IgdGateway>> = BTreeMap::new();
    let mut active_gateway: Option<String> = None;
    let mut next_discovery = Instant::now();
    let mut next_retry = Instant::now();
    let mut configuration_changed = true;
    let mut last_discovery_error = None;

    loop {
        let now = Instant::now();
        let has_candidate = desired.enabled && has_ipv4_candidate(&desired.endpoints);
        let next_wakeup = next_worker_wakeup(has_candidate, next_discovery, next_retry);
        let timeout = next_wakeup.saturating_duration_since(now);
        let mut shutdown = false;
        match commands.recv_timeout(timeout) {
            Ok(LifecycleCommand::Configure(next)) => {
                configuration_changed |= next != desired;
                desired = next;
            }
            Ok(LifecycleCommand::Shutdown) | Err(RecvTimeoutError::Disconnected) => {
                shutdown = true;
            }
            Err(RecvTimeoutError::Timeout) => {}
        }

        if shutdown {
            if let Some(error) = shutdown_gateways(&mut gateways) {
                let _ = statuses.send(UpnpRuntimeStatus {
                    status: "error".into(),
                    error: Some(error),
                });
            } else {
                let _ = statuses.send(UpnpRuntimeStatus::default());
            }
            break;
        }

        let now = Instant::now();
        let refresh_due = now >= next_discovery;
        let has_candidate = desired.enabled && has_ipv4_candidate(&desired.endpoints);
        let rediscover =
            should_rediscover(has_candidate, configuration_changed, now, next_discovery);
        let status;
        if desired.enabled && !desired.endpoints.is_empty() {
            if !has_ipv4_candidate(&desired.endpoints) {
                let cleanup_error = cleanup_gateways(&mut gateways, &mut active_gateway);
                next_retry = Instant::now() + CLEANUP_RETRY_INTERVAL;
                status = cleanup_status_or(
                    cleanup_error,
                    UpnpRuntimeStatus {
                        status: "waiting_for_ipv4_listener".into(),
                        error: None,
                    },
                );
            } else {
                let mut discovery_error = last_discovery_error.clone();
                if rediscover {
                    configuration_changed = false;
                    match discover_gateway() {
                        Ok(gateway) => {
                            last_discovery_error = None;
                            discovery_error = None;
                            let identity = gateway.identity();
                            let internal_address = gateway.internal_address();
                            if active_gateway.as_ref() != Some(&identity)
                                && let Some(previous) = active_gateway.as_ref()
                                && let Some(manager) = gateways.get_mut(previous)
                            {
                                let _ = manager.manager.shutdown();
                            }
                            match gateways.get_mut(&identity) {
                                Some(owner) => {
                                    owner.manager.replace_gateway_adapter(gateway);
                                    owner.internal_address = internal_address;
                                }
                                None => {
                                    gateways.insert(
                                        identity.clone(),
                                        GatewayOwner {
                                            manager: MappingManager::new(gateway),
                                            internal_address,
                                        },
                                    );
                                }
                            }
                            active_gateway = Some(identity);
                        }
                        Err(error) => {
                            let error = bounded_runtime_error(error);
                            last_discovery_error = Some(error.clone());
                            discovery_error = Some(error);
                        }
                    }
                    next_discovery = Instant::now() + RECOMMENDED_REFRESH_INTERVAL;
                }

                if let Some(identity) = active_gateway.as_ref()
                    && let Some(owner) = gateways.get_mut(identity)
                {
                    let gateway_endpoints =
                        materialize_gateway_endpoints(&desired.endpoints, owner.internal_address);
                    let mut error = discovery_error;
                    if refresh_due && let Err(refresh_error) = owner.manager.refresh_owned() {
                        error.get_or_insert_with(|| bounded_runtime_error(refresh_error));
                    }
                    if let Err(reconcile_error) =
                        owner.manager.reconcile_protocols(&gateway_endpoints)
                    {
                        error.get_or_insert_with(|| bounded_runtime_error(reconcile_error));
                    }
                    let cleanup_error =
                        cleanup_inactive_gateways(&mut gateways, active_gateway.as_deref());
                    if let Some(cleanup_error) = cleanup_error {
                        error.get_or_insert(cleanup_error);
                    }
                    status = if let Some(error) = error {
                        next_retry = Instant::now() + CLEANUP_RETRY_INTERVAL;
                        UpnpRuntimeStatus {
                            status: "error".into(),
                            error: Some(error),
                        }
                    } else if gateway_endpoints.is_empty() {
                        next_retry = next_discovery;
                        UpnpRuntimeStatus {
                            status: "waiting_for_gateway_route".into(),
                            error: None,
                        }
                    } else {
                        next_retry = next_discovery;
                        UpnpRuntimeStatus {
                            status: "active".into(),
                            error: None,
                        }
                    };
                } else {
                    let cleanup_error = cleanup_gateways(&mut gateways, &mut active_gateway);
                    next_retry = if cleanup_error.is_some() {
                        Instant::now() + CLEANUP_RETRY_INTERVAL
                    } else {
                        next_discovery
                    };
                    status = UpnpRuntimeStatus {
                        status: "error".into(),
                        error: Some(
                            combine_runtime_errors(
                                discovery_error
                                    .into_iter()
                                    .chain(cleanup_error)
                                    .chain(std::iter::once("no UPnP gateway is available".into())),
                            )
                            .expect("the no-gateway message is always present"),
                        ),
                    };
                }
            }
        } else {
            let cleanup_error = cleanup_gateways(&mut gateways, &mut active_gateway);
            next_retry = Instant::now() + CLEANUP_RETRY_INTERVAL;
            let fallback = if desired.enabled {
                UpnpRuntimeStatus {
                    status: "waiting_for_listener".into(),
                    error: None,
                }
            } else {
                UpnpRuntimeStatus::default()
            };
            status = cleanup_status_or(cleanup_error, fallback);
        }
        let _ = statuses.send(status.clone());
    }
}

fn has_ipv4_candidate(endpoints: &[MappingEndpoint]) -> bool {
    endpoints.iter().any(|endpoint| {
        endpoint.active
            && matches!(endpoint.address, IpAddr::V4(address) if address.is_unspecified() || !address.is_loopback())
    })
}

fn should_rediscover(
    has_candidate: bool,
    configuration_changed: bool,
    now: Instant,
    next_discovery: Instant,
) -> bool {
    has_candidate && (configuration_changed || now >= next_discovery)
}

fn next_worker_wakeup(
    has_candidate: bool,
    next_discovery: Instant,
    next_retry: Instant,
) -> Instant {
    if has_candidate {
        next_discovery.min(next_retry)
    } else {
        next_retry
    }
}

fn bounded_runtime_error(error: impl std::fmt::Display) -> String {
    let rendered = error.to_string();
    let mut bounded = String::with_capacity(MAX_RUNTIME_ERROR_CHARS);
    let mut previous_was_space = true;
    let mut character_count = 0;

    for character in rendered.chars().take(MAX_RUNTIME_ERROR_CHARS * 4) {
        let normalized = if character.is_whitespace() || character.is_control() {
            ' '
        } else {
            character
        };
        if normalized == ' ' {
            if !previous_was_space {
                bounded.push(' ');
                character_count += 1;
                previous_was_space = true;
            }
        } else {
            bounded.push(normalized);
            character_count += 1;
            previous_was_space = false;
        }
        if character_count >= MAX_RUNTIME_ERROR_CHARS {
            break;
        }
    }

    if bounded.ends_with(' ') {
        bounded.pop();
    }
    if bounded.is_empty() {
        "UPnP gateway returned an empty error".into()
    } else {
        bounded
    }
}

fn materialize_gateway_endpoints(
    endpoints: &[MappingEndpoint],
    gateway_address: Ipv4Addr,
) -> Vec<MappingEndpoint> {
    endpoints
        .iter()
        .filter_map(|endpoint| {
            if !endpoint.active {
                return None;
            }
            let IpAddr::V4(address) = endpoint.address else {
                return None;
            };
            if address.is_unspecified() || address == gateway_address {
                Some(MappingEndpoint::new(
                    IpAddr::V4(gateway_address),
                    endpoint.port,
                    endpoint.protocol,
                    true,
                ))
            } else {
                None
            }
        })
        .collect()
}

struct GatewayOwner<G: Gateway> {
    manager: MappingManager<G>,
    internal_address: Ipv4Addr,
}

fn cleanup_gateways<G: Gateway>(
    gateways: &mut BTreeMap<String, GatewayOwner<G>>,
    active_gateway: &mut Option<String>,
) -> Option<String> {
    let mut errors = Vec::new();
    for owner in gateways.values_mut() {
        if let Err(error) = owner.manager.shutdown() {
            errors.push(bounded_runtime_error(error));
        }
    }
    gateways.retain(|_, owner| owner.manager.owned_mappings().next().is_some());
    let retained_mappings = gateways
        .values()
        .map(|owner| owner.manager.owned_mappings().count())
        .sum::<usize>();
    if retained_mappings > 0 {
        errors.push(format!(
            "{retained_mappings} owned mapping(s) remain pending cleanup"
        ));
    }
    *active_gateway = None;
    combine_runtime_errors(errors)
}

fn cleanup_inactive_gateways<G: Gateway>(
    gateways: &mut BTreeMap<String, GatewayOwner<G>>,
    active_gateway: Option<&str>,
) -> Option<String> {
    let mut errors = Vec::new();
    let inactive: Vec<_> = gateways
        .keys()
        .filter(|identity| Some(identity.as_str()) != active_gateway)
        .cloned()
        .collect();
    for identity in inactive {
        let empty = if let Some(owner) = gateways.get_mut(&identity) {
            if let Err(error) = owner.manager.shutdown() {
                errors.push(bounded_runtime_error(error));
            }
            owner.manager.owned_mappings().next().is_none()
        } else {
            false
        };
        if empty {
            gateways.remove(&identity);
        }
    }
    let retained_mappings = gateways
        .iter()
        .filter(|(identity, _)| Some(identity.as_str()) != active_gateway)
        .map(|(_, owner)| owner.manager.owned_mappings().count())
        .sum::<usize>();
    if retained_mappings > 0 {
        errors.push(format!(
            "{retained_mappings} owned mapping(s) remain pending cleanup"
        ));
    }
    combine_runtime_errors(errors)
}

fn shutdown_gateways<G: Gateway>(
    gateways: &mut BTreeMap<String, GatewayOwner<G>>,
) -> Option<String> {
    let mut last_errors = Vec::new();
    for _ in 0..3 {
        let mut attempt_errors = Vec::new();
        for owner in gateways.values_mut() {
            if let Err(error) = owner.manager.shutdown() {
                attempt_errors.push(bounded_runtime_error(error));
            }
        }
        let retained_mappings = gateways
            .values()
            .map(|owner| owner.manager.owned_mappings().count())
            .sum::<usize>();
        if retained_mappings == 0 {
            return None;
        }
        last_errors = attempt_errors;
    }
    let retained_mappings = gateways
        .values()
        .map(|owner| owner.manager.owned_mappings().count())
        .sum::<usize>();
    let last_error = last_errors
        .first()
        .map(String::as_str)
        .unwrap_or("gateway cleanup did not complete");
    Some(bounded_runtime_error(format!(
        "Could not remove {retained_mappings} owned mapping(s) after three shutdown attempts; leases may remain active for up to 3600 seconds. Last error: {last_error}"
    )))
}

fn combine_runtime_errors(errors: impl IntoIterator<Item = String>) -> Option<String> {
    let errors: Vec<_> = errors.into_iter().collect();
    (!errors.is_empty()).then(|| bounded_runtime_error(errors.join("; ")))
}

fn cleanup_status_or(error: Option<String>, fallback: UpnpRuntimeStatus) -> UpnpRuntimeStatus {
    error.map_or(fallback, |error| UpnpRuntimeStatus {
        status: "error".into(),
        error: Some(error),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use amaterasu_module_sdk::abi::{self, AbiHeader, BorrowedBytes, HostApi, ReplySink};
    use amaterasu_upnp::{GatewayError, Mapping, MappingKey, RefreshOutcome, RemovalOutcome};
    use std::{
        ffi::c_void,
        sync::{Arc, Mutex},
    };

    #[derive(Default)]
    struct ExposureEndpointState {
        commands: Vec<Command>,
        result: Value,
        release_failures_remaining: usize,
    }

    #[derive(Default)]
    struct FakeCleanupGatewayState {
        mappings: BTreeMap<MappingKey, Mapping>,
        remove_failures_remaining: usize,
    }

    #[derive(Clone)]
    struct FakeCleanupGateway {
        state: Arc<Mutex<FakeCleanupGatewayState>>,
    }

    impl Gateway for FakeCleanupGateway {
        fn find_mappings(&mut self, key: MappingKey) -> Result<Vec<Mapping>, GatewayError> {
            Ok(self
                .state
                .lock()
                .unwrap()
                .mappings
                .get(&key)
                .cloned()
                .into_iter()
                .collect())
        }

        fn create_if_absent(&mut self, mapping: &Mapping) -> Result<(), GatewayError> {
            let mut state = self.state.lock().unwrap();
            if state.mappings.contains_key(&mapping.key()) {
                return Err(GatewayError::new("mapping already exists"));
            }
            state.mappings.insert(mapping.key(), mapping.clone());
            Ok(())
        }

        fn remove_if_matches(&mut self, mapping: &Mapping) -> Result<RemovalOutcome, GatewayError> {
            let mut state = self.state.lock().unwrap();
            if state.remove_failures_remaining > 0 {
                state.remove_failures_remaining -= 1;
                return Err(GatewayError::new("temporary gateway cleanup failure"));
            }
            let Some(existing) = state.mappings.get(&mapping.key()) else {
                return Ok(RemovalOutcome::Missing);
            };
            if !existing.has_same_owned_attributes(mapping) {
                return Ok(RemovalOutcome::Changed);
            }
            state.mappings.remove(&mapping.key());
            Ok(RemovalOutcome::Removed)
        }

        fn refresh_if_matches(
            &mut self,
            mapping: &Mapping,
        ) -> Result<RefreshOutcome, GatewayError> {
            let state = self.state.lock().unwrap();
            let Some(existing) = state.mappings.get(&mapping.key()) else {
                return Ok(RefreshOutcome::Missing);
            };
            if existing.has_same_owned_attributes(mapping) {
                Ok(RefreshOutcome::Refreshed)
            } else {
                Ok(RefreshOutcome::Changed)
            }
        }
    }

    fn owned_fake_gateway(
        remove_failures_remaining: usize,
    ) -> (
        GatewayOwner<FakeCleanupGateway>,
        Arc<Mutex<FakeCleanupGatewayState>>,
    ) {
        let state = Arc::new(Mutex::new(FakeCleanupGatewayState::default()));
        let gateway = FakeCleanupGateway {
            state: state.clone(),
        };
        let mut manager = MappingManager::new(gateway);
        manager
            .reconcile_protocols(&[MappingEndpoint::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                47_989,
                Protocol::Tcp,
                true,
            )])
            .unwrap();
        state.lock().unwrap().remove_failures_remaining = remove_failures_remaining;
        (
            GatewayOwner {
                manager,
                internal_address: Ipv4Addr::new(192, 168, 1, 10),
            },
            state,
        )
    }

    unsafe extern "C" fn exposure_invoke(
        context: *mut c_void,
        input: BorrowedBytes,
        reply: ReplySink,
    ) -> abi::Status {
        // SAFETY: each test retains the Arc that owns this mutex for the runtime lifetime.
        let state = unsafe { &*context.cast::<Mutex<ExposureEndpointState>>() };
        let Ok(bytes) = (unsafe { input.read() }) else {
            return abi::STATUS_INVALID_ARGUMENT;
        };
        let Ok(command) = serde_json::from_slice::<Command>(bytes) else {
            return abi::STATUS_INVALID_ARGUMENT;
        };
        let mut state = state.lock().unwrap();
        state.commands.push(command.clone());
        let response = match command {
            Command::Request { .. } => Response::Accepted { id: 41 },
            Command::TakeResult { request: 41 } => Response::Result {
                payload: state.result.clone(),
            },
            Command::ReleaseResult { request: 41 } if state.release_failures_remaining > 0 => {
                state.release_failures_remaining -= 1;
                Response::error("unavailable", "injected release failure")
            }
            Command::ReleaseResult { request: 41 } | Command::Cancel { request: 41 } => {
                Response::Ok
            }
            unexpected => panic!("unexpected management exposure command: {unexpected:?}"),
        };
        let output = serde_json::to_vec(&response).expect("test response");
        // SAFETY: the synchronous reply sink copies output bytes before returning.
        unsafe { reply.send(&output) };
        abi::STATUS_OK
    }

    fn exposure_runtime(state: Arc<Mutex<ExposureEndpointState>>) -> RuntimeClient {
        let api = HostApi {
            header: AbiHeader::of::<HostApi>(),
            context: Arc::as_ptr(&state).cast_mut().cast(),
            invoke: exposure_invoke,
        };
        // SAFETY: the caller retains the Arc containing the callback context.
        unsafe { RuntimeClient::from_endpoint(api) }
    }

    fn address(value: &str) -> SocketAddr {
        value.parse().unwrap()
    }

    #[test]
    fn endpoint_plan_maps_only_live_gamestream_and_wan_management_ports() {
        let plan = build_desired_mappings(
            true,
            &[address("0.0.0.0:47989")],
            &[address("0.0.0.0:47984")],
            Some(47_989),
            &["0.0.0.0:48010".into()],
            ManagementExposureSnapshot {
                wan_enabled: true,
                tls_address: Some(address("0.0.0.0:49999")),
            },
            false,
        );
        let ports = plan
            .endpoints
            .iter()
            .map(|endpoint| (endpoint.port, endpoint.protocol))
            .collect::<Vec<_>>();
        assert_eq!(
            ports,
            [
                (47_989, Protocol::Tcp),
                (47_984, Protocol::Tcp),
                (48_010, Protocol::Tcp),
                (47_998, Protocol::Udp),
                (48_000, Protocol::Udp),
                (47_999, Protocol::Udp),
                (49_999, Protocol::Tcp),
            ]
        );
    }

    #[test]
    fn endpoint_plan_omits_stale_listeners_and_non_wan_management() {
        let plan = build_desired_mappings(
            true,
            &[address("0.0.0.0:47989")],
            &[address("0.0.0.0:47983")],
            Some(47_989),
            &["0.0.0.0:48011".into()],
            ManagementExposureSnapshot {
                wan_enabled: false,
                tls_address: Some(address("0.0.0.0:49999")),
            },
            false,
        );
        assert_eq!(
            plan.endpoints
                .iter()
                .map(|endpoint| endpoint.port)
                .collect::<Vec<_>>(),
            [47_989]
        );
    }

    #[test]
    fn endpoint_plan_keeps_ipv6_family_gate_separate_from_active_listeners() {
        let plan = build_desired_mappings(
            true,
            &[address("0.0.0.0:47989"), address("[::]:47989")],
            &[address("0.0.0.0:47984"), address("[::]:47984")],
            Some(47_989),
            &["0.0.0.0:48010".into(), "[::]:48010".into()],
            ManagementExposureSnapshot::default(),
            true,
        );

        assert!(plan.ipv6_enabled);
        assert!(
            plan.endpoints
                .iter()
                .any(|endpoint| endpoint.address.is_ipv6())
        );
        assert!(
            plan.endpoints
                .iter()
                .any(|endpoint| endpoint.address.is_ipv4())
        );
    }

    #[test]
    fn only_wildcard_or_gateway_interface_listeners_are_materialized() {
        let gateway = Ipv4Addr::new(192, 168, 1, 10);
        let endpoints = [
            MappingEndpoint::new("0.0.0.0".parse().unwrap(), 47989, Protocol::Tcp, true),
            MappingEndpoint::new("192.168.1.10".parse().unwrap(), 47984, Protocol::Tcp, true),
            MappingEndpoint::new("192.168.1.11".parse().unwrap(), 48010, Protocol::Tcp, true),
            MappingEndpoint::new("127.0.0.1".parse().unwrap(), 47989, Protocol::Tcp, true),
            MappingEndpoint::new("::".parse().unwrap(), 47989, Protocol::Tcp, true),
        ];
        let mapped = materialize_gateway_endpoints(&endpoints, gateway);
        assert_eq!(mapped.len(), 2);
        assert!(
            mapped
                .iter()
                .all(|endpoint| endpoint.address == IpAddr::V4(gateway))
        );
        assert_eq!(mapped[0].port, 47_989);
        assert_eq!(mapped[1].port, 47_984);
    }

    #[test]
    fn management_exposure_requires_a_wan_gate_and_a_tls_socket() {
        assert_eq!(
            parse_management_exposure(&json!({
                "ok":true,"wan_enabled":true,"tls_address":"0.0.0.0:49999"
            })),
            ManagementExposureSnapshot {
                wan_enabled: true,
                tls_address: Some(address("0.0.0.0:49999")),
            }
        );
        for response in [
            json!({"ok":true,"wan_enabled":false,"tls_address":"0.0.0.0:49999"}),
            json!({"ok":true,"wan_enabled":true,"tls_address":null}),
            json!({"ok":false,"wan_enabled":true,"tls_address":"0.0.0.0:49999"}),
        ] {
            assert_eq!(
                parse_management_exposure(&response),
                ManagementExposureSnapshot::default()
            );
        }
    }

    #[test]
    fn management_exposure_releases_completed_runtime_results() {
        let state = Arc::new(Mutex::new(ExposureEndpointState {
            result: json!({
                "ok":true,
                "wan_enabled":true,
                "tls_address":"0.0.0.0:49999"
            }),
            ..ExposureEndpointState::default()
        }));
        let runtime = exposure_runtime(state.clone());
        let mut exposure = ManagementExposure::default();

        exposure.tick(&runtime);
        exposure.tick(&runtime);

        assert_eq!(
            exposure.snapshot(),
            ManagementExposureSnapshot {
                wan_enabled: true,
                tls_address: Some(address("0.0.0.0:49999")),
            }
        );
        let commands = &state.lock().unwrap().commands;
        assert_eq!(
            commands
                .iter()
                .filter(|command| matches!(command, Command::ReleaseResult { request: 41 }))
                .count(),
            1
        );
    }

    #[test]
    fn management_exposure_retries_cleanup_after_result_release_failure() {
        let state = Arc::new(Mutex::new(ExposureEndpointState {
            result: json!({
                "ok":true,
                "wan_enabled":true,
                "tls_address":"0.0.0.0:49999"
            }),
            release_failures_remaining: 1,
            ..ExposureEndpointState::default()
        }));
        let runtime = exposure_runtime(state.clone());
        let mut exposure = ManagementExposure::default();

        exposure.tick(&runtime);
        exposure.tick(&runtime);

        assert_eq!(exposure.snapshot(), ManagementExposureSnapshot::default());
        let commands = &state.lock().unwrap().commands;
        assert_eq!(
            commands
                .iter()
                .filter(|command| matches!(command, Command::ReleaseResult { request: 41 }))
                .count(),
            2
        );
        assert_eq!(
            commands
                .iter()
                .filter(|command| matches!(command, Command::Cancel { request: 41 }))
                .count(),
            1
        );
    }

    #[test]
    fn runtime_errors_are_normalized_and_bounded_before_publication() {
        let error = bounded_runtime_error(format!(
            "  gateway\r\n error\t{}  ",
            "x".repeat(MAX_RUNTIME_ERROR_CHARS * 8)
        ));

        assert!(error.starts_with("gateway error x"));
        assert_eq!(error.chars().count(), MAX_RUNTIME_ERROR_CHARS);
        assert!(!error.chars().any(char::is_control));
        assert!(!error.contains("  "));
    }

    #[test]
    fn cleanup_retries_do_not_accelerate_gateway_rediscovery() {
        let now = Instant::now();
        let next_discovery = now + RECOMMENDED_REFRESH_INTERVAL;

        assert!(!should_rediscover(
            true,
            false,
            now + CLEANUP_RETRY_INTERVAL,
            next_discovery,
        ));
        assert!(should_rediscover(
            true,
            true,
            now + CLEANUP_RETRY_INTERVAL,
            next_discovery,
        ));
        assert!(should_rediscover(
            true,
            false,
            next_discovery,
            next_discovery,
        ));
        assert!(!should_rediscover(
            false,
            true,
            next_discovery,
            next_discovery,
        ));
    }

    #[test]
    fn cleanup_failure_is_reported_and_retried_while_mapping_remains_owned() {
        let (owner, state) = owned_fake_gateway(1);
        let mut gateways = BTreeMap::from([("gateway".into(), owner)]);
        let mut active_gateway = Some("gateway".into());
        let waiting = UpnpRuntimeStatus {
            status: "waiting_for_ipv4_listener".into(),
            error: None,
        };

        let first_status = cleanup_status_or(
            cleanup_gateways(&mut gateways, &mut active_gateway),
            waiting.clone(),
        );
        assert_eq!(first_status.status, "error");
        assert!(
            first_status
                .error
                .as_deref()
                .is_some_and(|error| error.contains("mapping cleanup failure"))
        );
        assert_eq!(active_gateway, None);
        assert_eq!(state.lock().unwrap().mappings.len(), 1);
        assert_eq!(gateways["gateway"].manager.owned_mappings().count(), 1);

        let retry_status = cleanup_status_or(
            cleanup_gateways(&mut gateways, &mut active_gateway),
            waiting.clone(),
        );
        assert_eq!(retry_status, waiting);
        assert!(gateways.is_empty());
        assert!(state.lock().unwrap().mappings.is_empty());
    }

    #[test]
    fn shutdown_cleanup_failure_reports_retained_mapping_lease_expiry() {
        let (owner, state) = owned_fake_gateway(3);
        let mut gateways = BTreeMap::from([("gateway".into(), owner)]);

        let error = shutdown_gateways(&mut gateways).unwrap();

        assert!(error.contains("three shutdown attempts"));
        assert!(error.contains("3600 seconds"));
        assert!(error.contains("mapping cleanup failure"));
        assert_eq!(state.lock().unwrap().mappings.len(), 1);
        assert_eq!(gateways["gateway"].manager.owned_mappings().count(), 1);
    }

    #[test]
    fn loopback_listener_does_not_spin_on_an_overdue_discovery_deadline() {
        let now = Instant::now();
        let next_retry = now + CLEANUP_RETRY_INTERVAL;
        let overdue_discovery = now - Duration::from_secs(1);
        let endpoints = [MappingEndpoint::new(
            "127.0.0.1".parse().unwrap(),
            47_989,
            Protocol::Tcp,
            true,
        )];

        assert_eq!(
            next_worker_wakeup(
                has_ipv4_candidate(&endpoints),
                overdue_discovery,
                next_retry,
            ),
            next_retry
        );
        assert_eq!(
            next_worker_wakeup(true, overdue_discovery, next_retry),
            overdue_discovery
        );
    }
}
