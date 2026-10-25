use super::*;
use amaterasu_module_sdk::abi::{self, AbiHeader, BorrowedBytes, HostApi, ReplySink};
use std::{
    ffi::c_void,
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct EndpointState {
    commands: Vec<Command>,
    result: Value,
    release_failures_remaining: usize,
    request_transport_failures_remaining: usize,
}

unsafe extern "C" fn invoke(
    context: *mut c_void,
    input: BorrowedBytes,
    reply: ReplySink,
) -> abi::Status {
    // SAFETY: each test retains the Arc that owns this mutex for the runtime lifetime.
    let state = unsafe { &*context.cast::<Mutex<EndpointState>>() };
    let Ok(bytes) = (unsafe { input.read() }) else {
        return abi::STATUS_INVALID_ARGUMENT;
    };
    let Ok(command) = serde_json::from_slice::<Command>(bytes) else {
        return abi::STATUS_INVALID_ARGUMENT;
    };
    let mut state = state.lock().unwrap();
    state.commands.push(command.clone());
    if matches!(command, Command::Request { .. }) && state.request_transport_failures_remaining > 0
    {
        state.request_transport_failures_remaining -= 1;
        return abi::STATUS_INTERNAL_ERROR;
    }
    let response = match command {
        Command::Request { .. } => Response::Accepted { id: 71 },
        Command::TakeResult { .. } => Response::Result {
            payload: state.result.clone(),
        },
        Command::ReleaseResult { .. } if state.release_failures_remaining > 0 => {
            state.release_failures_remaining -= 1;
            Response::error("unavailable", "injected release failure")
        }
        Command::ReleaseResult { .. } => Response::Ok,
        unexpected => panic!("unexpected network settings command: {unexpected:?}"),
    };
    let output = serde_json::to_vec(&response).expect("test response");
    // SAFETY: the synchronous reply sink copies output bytes before returning.
    unsafe { reply.send(&output) };
    abi::STATUS_OK
}

fn runtime(state: Arc<Mutex<EndpointState>>) -> RuntimeClient {
    let api = HostApi {
        header: AbiHeader::of::<HostApi>(),
        context: Arc::as_ptr(&state).cast_mut().cast(),
        invoke,
    };
    // SAFETY: the caller retains the Arc containing the callback context.
    unsafe { RuntimeClient::from_endpoint(api) }
}

fn applied(port: u16) -> Value {
    json!({
        "ok":true,
        "desired_port":port,
        "desired_address_family":null,
        "desired_bind_address":null,
        "active_base_port":port,
        "active_address_family":null,
        "active_bind_address":null,
        "rtsp_addresses":[format!("127.0.0.1:{}", port + 21)],
        "active":true,
        "pending":false,
        "udp_binds_preflighted":true,
        "error":null,
    })
}

fn pending(port: u16, active_port: Option<u16>) -> Value {
    let addresses = active_port
        .map(|port| vec![format!("127.0.0.1:{}", port + 21)])
        .unwrap_or_default();
    json!({
        "ok":true,
        "desired_port":port,
        "desired_address_family":null,
        "desired_bind_address":null,
        "active_base_port":active_port,
        "active_address_family":null,
        "active_bind_address":null,
        "rtsp_addresses":addresses,
        "active":false,
        "pending":true,
        "udp_binds_preflighted":false,
        "error":null,
    })
}

fn listener_without_udp_preflight(port: u16) -> Value {
    json!({
        "ok":true,
        "desired_port":port,
        "desired_address_family":null,
        "desired_bind_address":null,
        "active_base_port":port,
        "active_address_family":null,
        "active_bind_address":null,
        "rtsp_addresses":[format!("127.0.0.1:{}", port + 21)],
        "active":true,
        "pending":false,
        "udp_binds_preflighted":false,
        "error":null,
    })
}

fn tick_until_idle(
    network: &mut NetworkSettings,
    runtime: &RuntimeClient,
    port: u16,
    settings: &mut ProductSettings,
) {
    for _ in 0..4 {
        network.tick(runtime, port, settings).unwrap();
        if network.pending.is_none() {
            break;
        }
    }
}

#[test]
fn a_fresh_runtime_reconciles_the_persisted_port_after_restart() {
    let port = 48_000;
    let state = Arc::new(Mutex::new(EndpointState {
        result: applied(port),
        ..EndpointState::default()
    }));
    let runtime = runtime(state.clone());
    let mut network = NetworkSettings::default();
    let mut settings = ProductSettings::new("Bootstrap".into(), 47_989);

    network.tick(&runtime, port, &mut settings).unwrap();
    tick_until_idle(&mut network, &runtime, port, &mut settings);

    let state = state.lock().unwrap();
    let request = state
        .commands
        .iter()
        .find_map(|command| match command {
            Command::Request {
                service,
                payload,
                parent,
                ..
            } => Some((service, payload, parent)),
            _ => None,
        })
        .expect("startup reconciliation request");
    assert_eq!(request.0, RTSP_SERVICE);
    assert_eq!(
        request.1,
        &json!({
            "action":"network_configure",
            "port":port,
            "address_family":null,
            "bind_address":null,
        })
    );
    assert_eq!(*request.2, None, "startup has no management parent");
    assert_eq!(network.active_base_port(), Some(port));
    assert_eq!(settings.active_rtsp_base_port(), Some(port));
    assert!(
        state
            .commands
            .iter()
            .any(|command| matches!(command, Command::ReleaseResult { request: 71 }))
    );
}

#[test]
fn pending_stream_apply_is_reported_as_persisted_and_retried_after_idle() {
    let port = 48_000;
    let old_port = 47_989;
    let state = Arc::new(Mutex::new(EndpointState {
        result: pending(port, Some(old_port)),
        ..EndpointState::default()
    }));
    let runtime = runtime(state.clone());
    let mut network = NetworkSettings::default();
    let mut settings = ProductSettings::new("Bootstrap".into(), old_port);
    settings.set_active_ports(Some(port), Some(crate::settings::https_port(port)));
    settings.queue_update_completion(
        88,
        json!({"ok":true,"hostname":"New Host","revision":4}),
        Some(port),
        Some(port),
    );

    network.tick(&runtime, port, &mut settings).unwrap();
    let request = settings.rtsp_completion_request(port);
    assert_eq!(
        request,
        Some(88),
        "admin request remains held until apply result"
    );
    network.tick(&runtime, port, &mut settings).unwrap();
    network.tick(&runtime, port, &mut settings).unwrap();
    assert_eq!(network.active_base_port(), Some(old_port));
    assert_eq!(settings.active_rtsp_base_port(), Some(old_port));
    assert_eq!(settings.rtsp_completion_request(port), None);
    let completion = settings.rtsp_completion_payload(88).unwrap();
    assert_eq!(completion["ok"], false);
    assert_eq!(completion["code"], "listener_apply_pending");
    assert_eq!(completion["persisted"], true);

    state.lock().unwrap().result = applied(port);
    network.next_retry = Instant::now();
    tick_until_idle(&mut network, &runtime, port, &mut settings);
    assert_eq!(network.active_base_port(), Some(port));
    assert_eq!(settings.active_rtsp_base_port(), Some(port));
    assert_eq!(settings.rtsp_listener_error(), None);

    let state = state.lock().unwrap();
    let requests: Vec<_> = state
        .commands
        .iter()
        .filter_map(|command| match command {
            Command::Request { parent, .. } => Some(*parent),
            _ => None,
        })
        .collect();
    assert_eq!(requests, [Some(88), None]);
}

#[test]
fn failed_result_release_retries_cleanup_without_replaying_network_update() {
    let port = 48_000;
    let state = Arc::new(Mutex::new(EndpointState {
        result: applied(port),
        release_failures_remaining: 1,
        ..EndpointState::default()
    }));
    let runtime = runtime(state.clone());
    let mut network = NetworkSettings::default();
    let mut settings = ProductSettings::new("Bootstrap".into(), port);

    network.tick(&runtime, port, &mut settings).unwrap();
    network.tick(&runtime, port, &mut settings).unwrap();
    network.tick(&runtime, port, &mut settings).unwrap();
    assert!(matches!(
        network.pending.as_ref().map(|pending| &pending.state),
        Some(CallState::Releasing { .. })
    ));
    network.tick(&runtime, port, &mut settings).unwrap();

    let state = state.lock().unwrap();
    assert_eq!(
        state
            .commands
            .iter()
            .filter(|command| matches!(command, Command::Request { .. }))
            .count(),
        1
    );
    assert_eq!(
        state
            .commands
            .iter()
            .filter(|command| matches!(command, Command::ReleaseResult { request: 71 }))
            .count(),
        2
    );
    assert_eq!(network.active_base_port(), Some(port));
}

#[test]
fn listener_success_without_udp_preflight_is_not_reported_as_applied() {
    let port = 48_000;
    let old_port = 47_989;
    let state = Arc::new(Mutex::new(EndpointState {
        result: listener_without_udp_preflight(port),
        ..EndpointState::default()
    }));
    let runtime = runtime(state.clone());
    let mut network = NetworkSettings {
        active_base_port: Some(old_port),
        ..NetworkSettings::default()
    };
    let mut settings = ProductSettings::new("Bootstrap".into(), port);
    settings.set_active_rtsp_base_port(Some(old_port));
    settings.queue_update_completion(
        89,
        json!({"ok":true,"hostname":"New Host","revision":5}),
        Some(port),
        Some(port),
    );

    network.tick(&runtime, port, &mut settings).unwrap();
    network.tick(&runtime, port, &mut settings).unwrap();
    network.tick(&runtime, port, &mut settings).unwrap();

    assert_eq!(network.active_base_port(), Some(port));
    assert_eq!(settings.active_rtsp_base_port(), Some(port));
    assert_eq!(network.active_target, None);
    assert_eq!(
        network.active_addresses.as_deref(),
        Some([format!("127.0.0.1:{}", port + 21)].as_slice())
    );
    assert_eq!(settings.rtsp_completion_request(port), None);
    let completion = settings.rtsp_completion_payload(89).unwrap();
    assert_eq!(completion["ok"], false);
    assert_eq!(completion["code"], "listener_apply_pending");
    assert_eq!(completion["persisted"], true);
}

#[test]
fn ambiguous_request_submission_retries_the_same_idempotency_key() {
    let port = 48_000;
    let state = Arc::new(Mutex::new(EndpointState {
        result: applied(port),
        request_transport_failures_remaining: 1,
        ..EndpointState::default()
    }));
    let runtime = runtime(state.clone());
    let mut network = NetworkSettings::default();
    let mut settings = ProductSettings::new("Bootstrap".into(), port);

    network.tick(&runtime, port, &mut settings).unwrap();
    network.tick(&runtime, port, &mut settings).unwrap();
    tick_until_idle(&mut network, &runtime, port, &mut settings);

    let state = state.lock().unwrap();
    let operations: Vec<_> = state
        .commands
        .iter()
        .filter_map(|command| match command {
            Command::Request { operation_id, .. } => Some(operation_id),
            _ => None,
        })
        .collect();
    assert_eq!(operations.len(), 2);
    assert_eq!(operations[0], operations[1]);
    assert_eq!(network.active_base_port(), Some(port));
}

fn assert_rejected_active_addresses(addresses: Option<Value>) {
    let port = 48_000;
    let request = 90;
    let mut result = applied(port);
    let fields = result.as_object_mut().unwrap();
    match addresses {
        Some(addresses) => {
            fields.insert("rtsp_addresses".into(), addresses);
        }
        None => {
            fields.remove("rtsp_addresses");
        }
    }
    let state = Arc::new(Mutex::new(EndpointState {
        result,
        ..EndpointState::default()
    }));
    let runtime = runtime(state.clone());
    let mut network = NetworkSettings::default();
    let mut settings = ProductSettings::new("Bootstrap".into(), 47_989);
    network.finish(
        &settings.rtsp_target(),
        ChildOutcome::Payload(applied(47_989)),
        &mut settings,
    );
    network.next_retry = Instant::now();
    settings.queue_update_completion(
        request,
        json!({"ok":true,"hostname":"New Host","revision":6}),
        None,
        Some(port),
    );

    tick_until_idle(&mut network, &runtime, port, &mut settings);

    assert_eq!(network.active_base_port(), None);
    assert_eq!(network.active_target, None);
    assert_eq!(settings.active_rtsp_base_port(), None);
    assert!(settings.rtsp_listener_error().is_some());
    let completion = settings.rtsp_completion_payload(request).unwrap();
    assert_eq!(completion["ok"], false);
    assert_eq!(completion["persisted"], true);
    assert!(
        state
            .lock()
            .unwrap()
            .commands
            .iter()
            .any(|command| matches!(command, Command::ReleaseResult { request: 71 }))
    );
}

#[test]
fn missing_active_rtsp_addresses_cannot_confirm_listener_application() {
    assert_rejected_active_addresses(None);
}

#[test]
fn missing_active_policy_fields_cannot_confirm_listener_application() {
    for field in ["active_address_family", "active_bind_address"] {
        let port = 48_000;
        let mut result = applied(port);
        result.as_object_mut().unwrap().remove(field);
        let state = Arc::new(Mutex::new(EndpointState {
            result,
            ..EndpointState::default()
        }));
        let runtime = runtime(state);
        let mut network = NetworkSettings::default();
        let mut settings = ProductSettings::new("Bootstrap".into(), port);

        tick_until_idle(&mut network, &runtime, port, &mut settings);

        assert_eq!(network.active_target, None, "missing {field}");
        assert_eq!(network.active_base_port(), None, "missing {field}");
        assert!(network.error.is_some(), "missing {field}");
    }
}

#[test]
fn empty_active_rtsp_addresses_cannot_confirm_listener_application() {
    assert_rejected_active_addresses(Some(json!([])));
}

#[test]
fn malformed_active_rtsp_addresses_cannot_confirm_listener_application() {
    for addresses in [
        json!(null),
        json!("127.0.0.1:48021"),
        json!(["not-an-endpoint"]),
        json!([null]),
        json!(["127.0.0.1:48021", null]),
        json!(["127.0.0.1:48021", "not-an-endpoint"]),
    ] {
        assert_rejected_active_addresses(Some(addresses));
    }
}

#[test]
fn wrong_port_active_rtsp_addresses_cannot_confirm_listener_application() {
    for addresses in [
        json!(["127.0.0.1:48000"]),
        json!(["127.0.0.1:0"]),
        json!(["127.0.0.1:48021", "[::1]:48022"]),
    ] {
        assert_rejected_active_addresses(Some(addresses));
    }
}

#[test]
fn explicitly_lost_rtsp_endpoints_clear_cached_state_and_retry_the_old_desired_policy() {
    let old_port = 47_989;
    let failed_port = 48_000;
    let state = Arc::new(Mutex::new(EndpointState {
        result: applied(old_port),
        ..EndpointState::default()
    }));
    let runtime = runtime(state.clone());
    let mut network = NetworkSettings::default();
    let mut settings = ProductSettings::new("Bootstrap".into(), old_port);
    let mut old_target = settings.rtsp_target();
    old_target.port = old_port;
    network.finish(
        &old_target,
        ChildOutcome::Payload(applied(old_port)),
        &mut settings,
    );
    assert_eq!(network.active_base_port(), Some(old_port));

    let mut failed_target = old_target;
    failed_target.port = failed_port;
    let mut lost = pending(failed_port, None);
    lost["error"] = json!("tcp_rebind_rollback_failed");
    network.finish(&failed_target, ChildOutcome::Payload(lost), &mut settings);

    assert_eq!(network.active_base_port(), None);
    assert_eq!(network.active_target, None);
    assert!(network.active_addresses.as_ref().is_none_or(Vec::is_empty));
    assert_eq!(settings.active_rtsp_base_port(), None);

    network.next_retry = Instant::now();
    tick_until_idle(&mut network, &runtime, old_port, &mut settings);

    let state = state.lock().unwrap();
    let requests: Vec<_> = state
        .commands
        .iter()
        .filter_map(|command| match command {
            Command::Request { payload, .. } => Some(payload),
            _ => None,
        })
        .collect();
    assert_eq!(requests.len(), 1, "the old cached target must be reapplied");
    assert_eq!(requests[0]["port"], old_port);
    assert_eq!(network.active_base_port(), Some(old_port));
    assert_eq!(settings.active_rtsp_base_port(), Some(old_port));
}

#[test]
fn incomplete_same_policy_response_invalidates_cached_application_and_retries() {
    let port = 47_989;
    let state = Arc::new(Mutex::new(EndpointState {
        result: applied(port),
        ..EndpointState::default()
    }));
    let runtime = runtime(state.clone());
    let mut network = NetworkSettings::default();
    let mut settings = ProductSettings::new("Bootstrap".into(), port);
    let target = settings.rtsp_target();
    network.finish(&target, ChildOutcome::Payload(applied(port)), &mut settings);
    assert_eq!(network.active_target.as_ref(), Some(&target));

    network.finish(
        &target,
        ChildOutcome::Payload(listener_without_udp_preflight(port)),
        &mut settings,
    );

    assert_eq!(network.active_base_port(), Some(port));
    assert_eq!(settings.active_rtsp_base_port(), Some(port));
    assert_eq!(network.active_target, None);
    assert_eq!(
        network.active_addresses.as_deref(),
        Some([format!("127.0.0.1:{}", port + 21)].as_slice())
    );
    assert!(settings.rtsp_listener_error().is_some());

    network.next_retry = Instant::now();
    tick_until_idle(&mut network, &runtime, port, &mut settings);

    let state = state.lock().unwrap();
    assert_eq!(
        state
            .commands
            .iter()
            .filter(|command| matches!(command, Command::Request { .. }))
            .count(),
        1,
        "an incomplete observation must not trigger the active-target shortcut"
    );
    assert_eq!(network.active_target.as_ref(), Some(&target));
    assert_eq!(settings.rtsp_listener_error(), None);
}

#[test]
fn reverting_pending_policy_reconfigures_the_owner_before_qualifying_old_endpoints() {
    let old_port = 47_989;
    let pending_port = 48_000;
    let state = Arc::new(Mutex::new(EndpointState {
        result: applied(old_port),
        ..EndpointState::default()
    }));
    let runtime = runtime(state.clone());
    let mut network = NetworkSettings::default();
    let mut settings = ProductSettings::new("Bootstrap".into(), old_port);
    let old_target = settings.rtsp_target();
    network.finish(
        &old_target,
        ChildOutcome::Payload(applied(old_port)),
        &mut settings,
    );
    assert_eq!(network.active_target.as_ref(), Some(&old_target));

    let mut pending_target = old_target.clone();
    pending_target.port = pending_port;
    network.finish(
        &pending_target,
        ChildOutcome::Payload(pending(pending_port, Some(old_port))),
        &mut settings,
    );

    assert_eq!(network.active_base_port(), Some(old_port));
    assert_eq!(settings.active_rtsp_base_port(), Some(old_port));
    assert_eq!(
        network.active_addresses.as_deref(),
        Some([format!("127.0.0.1:{}", old_port + 21)].as_slice())
    );
    assert_eq!(network.active_target, None);

    network.next_retry = Instant::now();
    network.tick(&runtime, old_port, &mut settings).unwrap();
    assert_eq!(network.active_target, None);
    assert!(network.pending.is_some());
    assert!(state.lock().unwrap().commands.is_empty());
    network.tick(&runtime, old_port, &mut settings).unwrap();
    assert_eq!(network.active_target, None);

    {
        let state = state.lock().unwrap();
        let requests: Vec<_> = state
            .commands
            .iter()
            .filter_map(|command| match command {
                Command::Request { payload, .. } => Some(payload),
                _ => None,
            })
            .collect();
        assert_eq!(
            requests.len(),
            1,
            "the owner's pending policy must be replaced"
        );
        assert_eq!(requests[0]["port"], old_port);
    }

    tick_until_idle(&mut network, &runtime, old_port, &mut settings);
    assert_eq!(network.active_target.as_ref(), Some(&old_target));
    assert_eq!(settings.rtsp_listener_error(), None);
}
