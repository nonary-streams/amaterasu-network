use super::*;
use amaterasu_gamestream::{
    rtsp::Method,
    sdp::{Announce, parse_announce},
};
use amaterasu_module_sdk::abi::{self, AbiHeader, BorrowedBytes, HostApi, ReplySink};
use std::{
    ffi::c_void,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener, TcpStream, UdpSocket},
    sync::{
        Mutex,
        atomic::{AtomicU16, Ordering},
    },
};

static NETWORK_TEST_LOCK: Mutex<()> = Mutex::new(());
static NEXT_TEST_BASE_PORT: AtomicU16 = AtomicU16::new(0);
const TEST_BASE_PORT: u16 = 47_989;

#[derive(Default)]
struct Endpoint {
    commands: Vec<Command>,
    completions: Vec<(u64, Value)>,
    active_request: bool,
    verifier_reply: Option<Value>,
    deny_launch: bool,
    deny_settlement: bool,
    recovery_results: VecDeque<Option<Value>>,
    recovery_requests: BTreeMap<u64, Option<Value>>,
    next_recovery_request: u64,
}

impl Endpoint {
    fn dispatch(&mut self, command: &Command) -> Response {
        match command {
            Command::CheckRequest { .. } if self.active_request => Response::Ok,
            Command::CheckRequest { .. } => Response::error("request_ended", "cancelled"),
            Command::Request { service, .. }
                if self.deny_launch && service == "amaterasu.launch/1" =>
            {
                Response::error("permission_denied", "no Launch grant")
            }
            Command::Request { service, .. }
                if service == "amaterasu.stream-session/1" && !self.recovery_results.is_empty() =>
            {
                self.next_recovery_request += 1;
                let id = 700 + self.next_recovery_request;
                self.recovery_requests
                    .insert(id, self.recovery_results.pop_front().expect("nonempty"));
                Response::Accepted { id }
            }
            Command::Request { .. } => Response::Accepted { id: 71 },
            Command::TakeResult { request }
                if let Some(Some(payload)) = self.recovery_requests.get(request) =>
            {
                Response::Result {
                    payload: payload.clone(),
                }
            }
            Command::TakeResult { request } if self.recovery_requests.contains_key(request) => {
                Response::Pending
            }
            Command::TakeResult { .. } if self.verifier_reply.is_some() => Response::Result {
                payload: self.verifier_reply.clone().unwrap(),
            },
            Command::Complete { request, payload } => {
                self.completions.push((*request, payload.clone()));
                Response::Ok
            }
            Command::Cancel { .. } | Command::ReleaseResult { .. } if self.deny_settlement => {
                Response::error("unavailable", "deliberate settlement failure")
            }
            _ => Response::Ok,
        }
    }
}

unsafe extern "C" fn invoke(
    context: *mut c_void,
    input: BorrowedBytes,
    reply: ReplySink,
) -> abi::Status {
    // SAFETY: the test keeps Endpoint exclusively alive for the client lifetime.
    let endpoint = unsafe { &mut *context.cast::<Endpoint>() };
    let Ok(bytes) = (unsafe { input.read() }) else {
        return abi::STATUS_INVALID_ARGUMENT;
    };
    let Ok(command) = serde_json::from_slice::<Command>(bytes) else {
        return abi::STATUS_INVALID_ARGUMENT;
    };
    endpoint.commands.push(command.clone());
    let output = serde_json::to_vec(&endpoint.dispatch(&command)).expect("test response");
    // SAFETY: the synchronous SDK reply sink copies these bytes before return.
    unsafe { reply.send(&output) };
    abi::STATUS_OK
}

fn client(endpoint: &mut Endpoint) -> RuntimeClient {
    let api = HostApi {
        header: AbiHeader::of::<HostApi>(),
        context: (endpoint as *mut Endpoint).cast(),
        invoke,
    };
    // SAFETY: caller retains endpoint for the synchronous test lifetime.
    unsafe { RuntimeClient::from_endpoint(api) }
}

fn open() -> Open {
    serde_json::from_value(json!({
        "operation_id":"caller-operation",
        "peer_ip":"127.0.0.1",
        "video_port":50000,
        "audio_port":50002,
        "key_hex":"00112233445566778899aabbccddeeff",
        "key_id":1,
        "connect_data":2,
        "capture":{
            "capture_provider":"dxgi",
            "output":"display",
            "encoder":1,
            "audio_endpoint":"default"
        }
    }))
    .expect("valid open")
}

fn startup_recovery_pending(controller: &mut Controller, deadline: u64) {
    controller.startup_recovery = StartupRecovery::new(0x1234, deadline);
}

fn listed_stream_sessions(sessions: Value, total: usize) -> Value {
    json!({"ok":true,"sessions":sessions,"total":total,"truncated":false})
}

#[test]
fn startup_reconciliation_stops_only_sessions_in_rtsp_scoped_status_and_waits_terminal() {
    let mut controller = Controller::new(Settings::default()).unwrap();
    startup_recovery_pending(&mut controller, 45_000);
    let mut endpoint = Endpoint {
        recovery_results: VecDeque::from([
            Some(listed_stream_sessions(
                json!([{"session":23,"state":"active","cleanup_error":null}]),
                1,
            )),
            Some(json!({"ok":true,"session":23,"state":"stopping","cleanup_error":null})),
            Some(json!({"ok":true,"session":23,"state":"stopped","cleanup_error":null})),
        ]),
        ..Endpoint::default()
    };
    let runtime = client(&mut endpoint);

    for now in [0, 1, 2, 3, 253, 254, 255] {
        controller.advance_startup_recovery(&runtime, now);
    }

    assert!(controller.startup_recovery.ready());
    let actions: Vec<_> = endpoint
        .commands
        .iter()
        .filter_map(|command| match command {
            Command::Request {
                service, payload, ..
            } if service == "amaterasu.stream-session/1" => Some(payload),
            _ => None,
        })
        .collect();
    assert_eq!(actions[0]["action"], "status");
    assert!(actions[0]["session"].is_null());
    assert_eq!(actions[1]["action"], "stop");
    assert_eq!(actions[1]["session"], 23);
    assert_eq!(actions[2]["action"], "status");
    assert_eq!(actions[2]["session"], 23);
    assert!(!actions.iter().any(|action| action["session"] == 24));
}

#[test]
fn startup_reconciliation_clean_status_admits_new_launch_without_stop() {
    let settings: Settings = serde_json::from_value(json!({
        "enabled":true,
        "bind":"127.0.0.1:0",
        "allowed_principals":["amaterasu.nvhttp"]
    }))
    .unwrap();
    let mut controller = Controller::new(settings).unwrap();
    startup_recovery_pending(&mut controller, 45_000);
    let mut endpoint = Endpoint {
        recovery_results: VecDeque::from([Some(listed_stream_sessions(json!([]), 0))]),
        ..Endpoint::default()
    };
    let runtime = client(&mut endpoint);

    controller.advance_startup_recovery(&runtime, 0);
    controller.advance_startup_recovery(&runtime, 1);

    assert!(controller.startup_recovery.ready());
    assert!(endpoint.commands.iter().all(|command| !matches!(command,
        Command::Request { payload, .. } if payload["action"] == "stop")));
    controller.open(
        OpenRequest {
            request: 19,
            caller: "amaterasu.nvhttp".into(),
            config: open(),
            deadline: 5_000,
            display_preflight_deadline: None,
        },
        2,
        &runtime,
        false,
    );
    assert!(controller.job.is_some());
    controller.advance_job(&runtime, 3);
    assert!(endpoint.commands.iter().any(|command| matches!(command,
        Command::Request { service, payload, .. }
            if service == "amaterasu.stream-session/1" && payload["action"] == "prepare")));
}

#[test]
fn restart_reconciliation_stops_old_lease_before_fresh_resume_open() {
    let settings: Settings = serde_json::from_value(json!({
        "enabled":true,
        "bind":"127.0.0.1:0",
        "allowed_principals":["amaterasu.nvhttp"]
    }))
    .unwrap();
    let mut controller = Controller::new(settings).unwrap();
    // A new RTSP controller instance has no ticket records. The stream-session
    // broker still owns the previous in-memory Desktop lease.
    startup_recovery_pending(&mut controller, 45_000);
    let mut endpoint = Endpoint {
        active_request: true,
        recovery_results: VecDeque::from([
            Some(listed_stream_sessions(
                json!([{"session":23,"state":"active","cleanup_error":null}]),
                1,
            )),
            Some(json!({"ok":true,"session":23,"state":"stopped","cleanup_error":null})),
            Some(json!({
                "ok":true,
                "session":24,
                "state":"prepared",
                "audio_local":"127.0.0.1:51000",
                "video_local":"127.0.0.1:51002",
                "control_local":"127.0.0.1:51004",
                "history_activity_id":null,
                "rtsp_operation_id":null
            })),
        ]),
        ..Endpoint::default()
    };
    let runtime = client(&mut endpoint);

    let mut resumed = open();
    resumed.operation_id = "nvhttp-resume-fresh".into();
    controller.open(
        OpenRequest {
            request: 19,
            caller: "amaterasu.nvhttp".into(),
            config: resumed.clone(),
            deadline: 10_000,
            display_preflight_deadline: None,
        },
        0,
        &runtime,
        false,
    );
    assert_eq!(
        endpoint.completions.last().unwrap().1["code"],
        "startup_reconciliation_pending"
    );
    assert!(!endpoint.commands.iter().any(|command| matches!(command,
        Command::Request { payload, .. } if payload["action"] == "prepare")));

    for now in [1, 2, 3, 4, 5] {
        controller.advance_startup_recovery(&runtime, now);
    }
    assert!(controller.startup_recovery.ready());

    controller.open(
        OpenRequest {
            request: 20,
            caller: "amaterasu.nvhttp".into(),
            config: resumed,
            deadline: 10_000,
            display_preflight_deadline: None,
        },
        6,
        &runtime,
        false,
    );
    for now in 7..11 {
        controller.advance_job(&runtime, now);
    }

    assert_eq!(endpoint.completions.last().unwrap().0, 20);
    assert_eq!(endpoint.completions.last().unwrap().1["ok"], true);
    let requests: Vec<_> = endpoint
        .commands
        .iter()
        .filter_map(|command| match command {
            Command::Request {
                service,
                payload,
                operation_id,
                ..
            } if service == "amaterasu.stream-session/1" => Some((payload, operation_id.as_str())),
            _ => None,
        })
        .collect();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].0["action"], "status");
    assert_eq!(requests[1].0["action"], "stop");
    assert_eq!(requests[1].0["session"], 23);
    assert_eq!(requests[2].0["action"], "prepare");
    let new_ticket = controller
        .records
        .values()
        .find(|record| record.config.operation_id == "nvhttp-resume-fresh")
        .expect("fresh resume ticket")
        .id;
    assert_eq!(
        requests[2].0["operation_id"],
        format!("rtsp-{new_ticket:016x}")
    );
    assert_ne!(requests[1].1, requests[2].1);
    assert!(controller.records.values().any(|record| {
        record.config.operation_id == "nvhttp-resume-fresh"
            && record.session == Some(24)
            && record.state == State::Ready
    }));
    assert!(
        !requests
            .iter()
            .any(|(payload, _)| payload["action"] == "stop" && payload["session"] == 24)
    );
}

#[test]
fn startup_reconciliation_timeout_after_partial_stop_keeps_launch_fail_closed() {
    let mut controller = Controller::new(Settings::default()).unwrap();
    startup_recovery_pending(&mut controller, 300);
    let mut endpoint = Endpoint {
        recovery_results: VecDeque::from([
            Some(listed_stream_sessions(
                json!([{"session":23,"state":"active","cleanup_error":null}]),
                1,
            )),
            Some(json!({"ok":true,"session":23,"state":"stopping","cleanup_error":null})),
            None,
        ]),
        ..Endpoint::default()
    };
    let runtime = client(&mut endpoint);

    for now in [0, 1, 2, 3, 253, 299, 300] {
        controller.advance_startup_recovery(&runtime, now);
    }

    assert!(controller.startup_recovery.blocked());
    assert!(!controller.startup_recovery.ready());
    let mut config = open();
    config.operation_id = "new-launch".into();
    controller.open(
        OpenRequest {
            request: 19,
            caller: "amaterasu.nvhttp".into(),
            config,
            deadline: 1_000,
            display_preflight_deadline: None,
        },
        301,
        &runtime,
        false,
    );
    assert!(
        endpoint
            .completions
            .iter()
            .any(|(_, reply)| { reply["code"] == "startup_reconciliation_timeout" })
    );
    assert!(!endpoint.commands.iter().any(|command| matches!(command,
        Command::Request { payload, .. } if payload["action"] == "prepare")));
}

fn record(state: State) -> Record {
    Record {
        id: 5,
        owner: "caller".into(),
        config: open(),
        state,
        session: Some(23),
        negotiation: None,
        negotiated_encryption: None,
        negotiated_slices_per_frame: None,
        negotiated_video_stream_format: None,
        client_feature_flags: None,
        negotiated_color: None,
        negotiated_video: None,
        url: "rtspenc://127.0.0.1:48010/launch-5".into(),
        session_token: "00112233445566778899aabbccddeeff".into(),
        udp_discovery: None,
        local: "127.0.0.1:48010".parse().expect("literal"),
        expires: 5_000,
        next_status: 5_000,
        failure: None,
        cleanup_error: None,
        cleanup_retry_count: 0,
        cleanup_retry_at: None,
        uncertain: None,
        uncertain_phase: None,
        needs_lookup: false,
        stream_state: Some("stopping".into()),
        display_applied: false,
        display_preflight_deadline: None,
        display_lease_ready_until: None,
        display_prepare_timeout_ms: None,
        revoke_after: None,
        cleanup_confirmed: false,
    }
}

#[test]
fn response_echoes_frozen_display_policy_for_authenticated_launch_readback() {
    let mut record = record(State::Ready);
    let snapshot = json!({
        "global_revision": 7,
        "application_overrides": {"dd_configuration_option":"verify_only"},
        "virtual_display_intent": null,
    });
    record.config.display_policy_snapshot = Some(snapshot.clone());

    assert_eq!(record.response()["display_policy_snapshot"], snapshot);
}

fn attested_open() -> Open {
    serde_json::from_value(json!({
        "operation_id":"rtsp-one","application_operation_id":"launch-one",
        "display_admission_token":"ab".repeat(32),
        "display_policy_snapshot":{"global_revision":1,"global_overrides":{},
            "catalog_revision":0,"certificate_id":"cd".repeat(32),
            "application_overrides":{},"client_overrides":{},"effective_overrides":{}},
        "display_request":{"expected_topology_revision":"aa".repeat(16),"configuration":{"displays":[
            {"id":"one","width":1920,"height":1080,"refresh":{"numerator":60,"denominator":1},"x":0,"y":0}
        ]},"mode_policy":{"display_id":"one","configuration_option":"ensure_only_display","remapping":{},"context":{
            "resolution_is_automatic":true,"refresh_rate_is_automatic":true,
            "client_display_mode_override":false,"optimize_game_settings":false}}},
        "peer_ip":"127.0.0.1","video_port":50000,"audio_port":50002,
        "key_hex":"00112233445566778899aabbccddeeff","key_id":1,"connect_data":2,
        "capture":{"capture_provider":"dxgi","output":"display","encoder":1,"audio_endpoint":"default"}
    })).unwrap()
}

#[test]
fn display_verifier_runs_before_ticket_or_stream_prepare() {
    let settings: Settings = serde_json::from_value(json!({
        "enabled":true,"bind":"127.0.0.1:0",
        "allowed_principals":["amaterasu.nvhttp","other"]
    }))
    .unwrap();
    let mut controller = Controller::new(settings).unwrap();
    let mut config = attested_open();
    config.ping_timeout_ms = 1_000;
    let retry_config = config.clone();
    let digest = config.display_request_sha256().unwrap();
    let snapshot = config.display_policy_snapshot.clone().unwrap();
    let mut endpoint = Endpoint {
        active_request: true,
        verifier_reply: Some(json!({"ok":true,"verified":true,
            "rtsp_operation_id":"rtsp-one","request_sha256":digest,
            "preflight_remaining_ms":10_000})),
        ..Endpoint::default()
    };
    let runtime = client(&mut endpoint);
    controller.open(
        OpenRequest {
            request: 19,
            caller: "amaterasu.nvhttp".into(),
            config,
            deadline: 5_000,
            display_preflight_deadline: None,
        },
        0,
        &runtime,
        false,
    );
    assert!(controller.records.is_empty());
    assert!(controller.job.is_none());
    controller.advance_display_admission(&runtime, 1);
    assert!(controller.records.is_empty());
    controller.advance_display_admission(&runtime, 2);
    assert!(controller.records.is_empty());
    controller.advance_display_admission(&runtime, 3);
    assert_eq!(controller.records.len(), 1);
    let admitted = controller.records.values().next().unwrap();
    assert_eq!(admitted.display_preflight_deadline, Some(10_000));
    assert_eq!(admitted.display_lease_ready_until, Some(5_000));
    assert_eq!(admitted.expires, 5_000);
    controller.advance_job(&runtime, 4);
    let prepare = endpoint
        .commands
        .iter()
        .find_map(|command| match command {
            Command::Request {
                service, payload, ..
            } if service == "amaterasu.stream-session/1" => Some(payload),
            _ => None,
        })
        .unwrap();
    assert_eq!(prepare["ping_timeout_ms"], 1_000);
    assert_eq!(prepare["display_prepare_timeout_ms"], 4_997);
    let verify = endpoint
        .commands
        .iter()
        .find_map(|command| match command {
            Command::Request {
                service, payload, ..
            } if service == "amaterasu.launch/1" => Some(payload),
            _ => None,
        })
        .unwrap();
    assert_eq!(verify["action"], "verify_display_admission");
    assert_eq!(verify["display_policy_snapshot"], snapshot);
    assert_eq!(verify["request_sha256"], digest);
    assert_eq!(verify["catalog_revision"], 0);
    let verifier_operation = endpoint
        .commands
        .iter()
        .find_map(|command| match command {
            Command::Request {
                service,
                operation_id,
                ..
            } if service == "amaterasu.launch/1" => Some(operation_id),
            _ => None,
        })
        .unwrap();
    assert!(!verifier_operation.contains("abababababababab"));
    assert!(
        endpoint
            .commands
            .iter()
            .any(|command| matches!(command, Command::ReleaseResult { request: 71 }))
    );
    assert!(
        controller
            .records
            .values()
            .next()
            .unwrap()
            .response()
            .get("display_admission_token")
            .is_none()
    );
    assert!(
        controller.job.is_some(),
        "stream Prepare starts only after verification"
    );
    let frozen = controller.records.values().next().unwrap().response();
    assert_eq!(
        frozen["display_request"]["mode_policy"]["configuration_option"],
        "ensure_only_display"
    );
    controller.open(
        OpenRequest {
            request: 20,
            caller: "amaterasu.nvhttp".into(),
            config: retry_config.clone(),
            deadline: 5_000,
            display_preflight_deadline: None,
        },
        4,
        &runtime,
        false,
    );
    assert!(
        endpoint
            .completions
            .iter()
            .any(|(request, response)| *request == 20 && *response == frozen)
    );
    let mut changed = retry_config;
    changed.display_request.as_mut().unwrap()["expected_topology_revision"] =
        json!("bb".repeat(16));
    controller.open(
        OpenRequest {
            request: 21,
            caller: "amaterasu.nvhttp".into(),
            config: changed,
            deadline: 5_000,
            display_preflight_deadline: None,
        },
        4,
        &runtime,
        false,
    );
    assert!(
        endpoint
            .completions
            .iter()
            .any(|(request, response)| *request == 21 && response["code"] == "operation_conflict")
    );
    assert_eq!(controller.records.len(), 1);
}

#[test]
fn frozen_display_prepare_requires_owned_applied_readback_before_ticket_ready() {
    for failure in [
        "missing_lease",
        "wrong_request",
        "missing_timeout",
        "expired",
        "valid",
    ] {
        let settings: Settings = serde_json::from_value(json!({
            "enabled":true,"bind":"127.0.0.1:0","allowed_principals":["caller"]
        }))
        .unwrap();
        let mut controller = Controller::new(settings).unwrap();
        let mut record = record(State::Preparing);
        record.config = attested_open();
        record.display_preflight_deadline = Some(100);
        record.display_lease_ready_until = Some(50);
        record.display_prepare_timeout_ms = Some(40);
        let job = Job {
            ticket: record.id,
            phase: Phase::Prepare,
            call: Call::new(json!({"action":"prepare"}), "prepare".into(), Some(19)),
            caller: Some(19),
            network: None,
            deadline: 5_000,
        };
        let mut prepared = json!({
            "ok":true,"state":"prepared","session":23,
            "audio_local":"127.0.0.1:51000","video_local":"127.0.0.1:51002",
            "control_local":"127.0.0.1:51004",
            "display_request":record.config.display_request,
            "display_applied":true,"display_state":"applied",
            "display_prepare_timeout_ms":40,
        });
        match failure {
            "missing_lease" => prepared["display_applied"] = json!(false),
            "wrong_request" => {
                prepared["display_request"]["expected_topology_revision"] = json!("bb".repeat(16))
            }
            "missing_timeout" => prepared["display_prepare_timeout_ms"] = Value::Null,
            _ => {}
        }
        let now = if failure == "expired" { 100 } else { 10 };
        let mut endpoint = Endpoint {
            active_request: true,
            ..Endpoint::default()
        };
        let runtime = client(&mut endpoint);
        controller.prepared(&mut record, job, &prepared, now, &runtime);
        if failure == "valid" {
            assert!(record.state == State::Ready);
            assert_eq!(record.response()["display_applied"], true);
            assert_eq!(record.expires, 50);
            let exact_retry = record.config.clone();
            finish_record(&mut record);
            assert_eq!(record.response()["display_applied"], false);
            controller.records.insert(record.id, record);
            controller.open(
                OpenRequest {
                    request: 20,
                    caller: "caller".into(),
                    config: exact_retry,
                    deadline: 5_000,
                    display_preflight_deadline: None,
                },
                20,
                &runtime,
                false,
            );
            assert!(endpoint.completions.iter().any(|(request, response)| {
                *request == 20
                    && response["state"] == "closed"
                    && response["display_applied"] == false
            }));
        } else {
            assert!(record.state == State::Closing, "{failure}");
            assert_eq!(record.response()["display_applied"], false);
            assert!(record.failure.is_some());
        }
    }
}

#[test]
fn nearly_expired_staged_admission_never_allocates_a_stream() {
    let settings: Settings = serde_json::from_value(json!({
        "enabled":true,"bind":"127.0.0.1:0","allowed_principals":["amaterasu.nvhttp"]
    }))
    .unwrap();
    let mut controller = Controller::new(settings).unwrap();
    let config = attested_open();
    let digest = config.display_request_sha256().unwrap();
    let mut endpoint = Endpoint {
        active_request: true,
        verifier_reply: Some(json!({
            "ok":true,"verified":true,"rtsp_operation_id":config.operation_id,
            "request_sha256":digest,"preflight_remaining_ms":5_000
        })),
        ..Endpoint::default()
    };
    let runtime = client(&mut endpoint);
    controller.open(
        OpenRequest {
            request: 19,
            caller: "amaterasu.nvhttp".into(),
            config,
            deadline: 5_000,
            display_preflight_deadline: None,
        },
        0,
        &runtime,
        false,
    );
    for now in 1..=3 {
        controller.advance_display_admission(&runtime, now);
    }
    assert!(controller.records.is_empty());
    assert!(controller.job.is_none());
    assert!(
        endpoint
            .completions
            .iter()
            .any(|(_, response)| { response["code"] == "display_admission_expired" })
    );
}

#[test]
fn staged_ready_expiry_rejects_play_before_negotiation_and_arm_uses_ping_window() {
    let mut controller = Controller::new(Settings::default()).unwrap();
    let mut expired = record(State::Ready);
    expired.expires = 100;
    controller.records.insert(expired.id, expired);
    controller.handle_network(77, 5, request(Method::Play, "/", 7, true), 100);
    let expired = &controller.records[&5];
    assert!(expired.state == State::Closing);
    assert_eq!(expired.failure, Some("prepare_expired"));
    assert!(controller.job.is_none());

    let mut accepted = record(State::Ready);
    accepted.expires = 100;
    accepted.config.ping_timeout_ms = 10_000;
    let deadline = accepted.begin_arm(99);
    assert_eq!(deadline, 10_099);
    assert_eq!(accepted.expires, deadline);
    assert!(accepted.state == State::Arming);
}

#[test]
fn confirmed_stop_clears_display_readback_while_teardown_reply_is_pending() {
    let mut controller = Controller::new(Settings::default()).unwrap();
    let mut record = record(State::Closing);
    record.display_applied = true;
    record.cleanup_confirmed = true;
    record.revoke_after = Some(77);
    let job = Job {
        ticket: record.id,
        phase: Phase::Stop,
        call: Call::new(json!({"action":"stop"}), "stop".into(), None),
        caller: None,
        network: None,
        deadline: 5_000,
    };
    let mut endpoint = Endpoint::default();
    let runtime = client(&mut endpoint);
    controller.finish_cleanup_reply(&mut record, job, &runtime);
    assert!(record.state == State::Closing);
    assert_eq!(record.response()["display_applied"], false);
    assert!(record.cleanup_confirmed);
}

#[test]
fn malformed_topology_revision_never_reaches_verifier_or_stream_prepare() {
    for malformed in [
        serde_json::Value::Null,
        json!("AA".repeat(16)),
        json!("aa".repeat(15)),
    ] {
        let settings: Settings = serde_json::from_value(json!({
            "enabled":true,"bind":"127.0.0.1:0",
            "allowed_principals":["amaterasu.nvhttp"]
        }))
        .unwrap();
        let mut controller = Controller::new(settings).unwrap();
        let mut config = attested_open();
        config.display_request.as_mut().unwrap()["expected_topology_revision"] = malformed;
        let mut endpoint = Endpoint {
            active_request: true,
            ..Endpoint::default()
        };
        let runtime = client(&mut endpoint);
        controller.open(
            OpenRequest {
                request: 19,
                caller: "amaterasu.nvhttp".into(),
                config,
                deadline: 5_000,
                display_preflight_deadline: None,
            },
            0,
            &runtime,
            false,
        );
        assert!(controller.records.is_empty());
        assert!(controller.job.is_none());
        assert!(controller.display_admission.is_none());
        assert!(
            !endpoint
                .commands
                .iter()
                .any(|command| matches!(command, Command::Request { .. }))
        );
        assert!(
            endpoint
                .completions
                .iter()
                .any(|(_, response)| response["code"] == "display_request_unattested")
        );
    }
}

#[test]
fn invalid_configuration_option_never_reaches_verifier_or_stream_prepare() {
    for invalid in [json!("ensure_everything"), json!("Ensure_Active"), json!(7)] {
        let settings: Settings = serde_json::from_value(json!({
            "enabled":true,"bind":"127.0.0.1:0",
            "allowed_principals":["amaterasu.nvhttp"]
        }))
        .unwrap();
        let mut controller = Controller::new(settings).unwrap();
        let mut config = attested_open();
        config.display_request.as_mut().unwrap()["mode_policy"]["configuration_option"] = invalid;
        let mut endpoint = Endpoint {
            active_request: true,
            ..Endpoint::default()
        };
        let runtime = client(&mut endpoint);
        controller.open(
            OpenRequest {
                request: 19,
                caller: "amaterasu.nvhttp".into(),
                config,
                deadline: 5_000,
                display_preflight_deadline: None,
            },
            0,
            &runtime,
            false,
        );
        assert!(controller.records.is_empty());
        assert!(controller.job.is_none());
        assert!(controller.display_admission.is_none());
        assert!(
            !endpoint
                .commands
                .iter()
                .any(|command| matches!(command, Command::Request { .. }))
        );
        assert!(
            endpoint
                .completions
                .iter()
                .any(|(_, response)| response["code"] == "display_request_unattested")
        );
    }
}

#[test]
fn forged_or_unavailable_display_admission_never_creates_a_ticket() {
    for failure in [
        "wrong_caller",
        "wrong_hash",
        "wrong_revision_digest",
        "rejected",
        "missing_grant",
    ] {
        let settings: Settings = serde_json::from_value(json!({
            "enabled":true,"bind":"127.0.0.1:0",
            "allowed_principals":["amaterasu.nvhttp","other"]
        }))
        .unwrap();
        let mut controller = Controller::new(settings).unwrap();
        let mut config = attested_open();
        let digest = config.display_request_sha256().unwrap();
        if failure == "wrong_revision_digest" {
            config.display_request.as_mut().unwrap()["expected_topology_revision"] =
                json!("bb".repeat(16));
            assert_ne!(config.display_request_sha256().unwrap(), digest);
        }
        let mut endpoint = Endpoint {
            active_request: true,
            verifier_reply: Some(json!({"ok":true,"verified":true,
                "rtsp_operation_id":"rtsp-one","request_sha256":if failure == "wrong_hash" { "00".repeat(32) } else { digest } })),
            deny_launch: failure == "missing_grant",
            ..Endpoint::default()
        };
        if failure == "rejected" {
            endpoint.verifier_reply = Some(json!({"ok":false,"code":"display_admission_denied"}));
        }
        let runtime = client(&mut endpoint);
        controller.open(
            OpenRequest {
                request: 19,
                caller: if failure == "wrong_caller" {
                    "other"
                } else {
                    "amaterasu.nvhttp"
                }
                .into(),
                config,
                deadline: 5_000,
                display_preflight_deadline: None,
            },
            0,
            &runtime,
            false,
        );
        for now in 1..4 {
            controller.advance_display_admission(&runtime, now);
        }
        assert!(controller.records.is_empty(), "{failure}");
        assert!(controller.job.is_none(), "{failure}");
        assert!(
            !endpoint.commands.iter().any(|command| matches!(command,
            Command::Request { service, .. } if service == "amaterasu.stream-session/1")),
            "{failure}"
        );
        assert!(
            endpoint
                .completions
                .iter()
                .any(|(_, reply)| reply["ok"] == false),
            "{failure}"
        );
    }
}

#[test]
fn uncertain_verifier_settlement_keeps_child_identity_until_release() {
    let settings: Settings = serde_json::from_value(json!({
        "enabled":true,"bind":"127.0.0.1:0",
        "allowed_principals":["amaterasu.nvhttp"]
    }))
    .unwrap();
    let mut controller = Controller::new(settings).unwrap();
    let config = attested_open();
    let digest = config.display_request_sha256().unwrap();
    let mut endpoint = Endpoint {
        active_request: true,
        verifier_reply: Some(json!({"ok":true,"verified":true,
            "rtsp_operation_id":"rtsp-one","request_sha256":digest})),
        deny_settlement: true,
        ..Endpoint::default()
    };
    let runtime = client(&mut endpoint);
    controller.open(
        OpenRequest {
            request: 19,
            caller: "amaterasu.nvhttp".into(),
            config,
            deadline: 5,
            display_preflight_deadline: None,
        },
        0,
        &runtime,
        false,
    );
    for now in 1..=5 {
        controller.advance_display_admission(&runtime, now);
    }
    assert!(controller.display_admission.is_none());
    assert_eq!(controller.display_cleanup.len(), 1);
    assert!(controller.records.is_empty());
    assert!(controller.job.is_none());
    endpoint.deny_settlement = false;
    controller.advance_display_cleanup(&runtime);
    assert!(controller.display_cleanup.is_empty());
    assert!(
        endpoint
            .commands
            .iter()
            .any(|command| matches!(command, Command::ReleaseResult { request: 71 }))
    );
    assert!(
        endpoint
            .completions
            .iter()
            .any(|(request, response)| *request == 19 && response["ok"] == false)
    );
}

#[test]
fn ticket_readback_keeps_the_admitted_frame_limiter_snapshot() {
    let mut record = record(State::Preparing);
    let snapshot = serde_json::json!({"version":1,"settings":{"frame_limiter_provider":"rtss"}});
    record.config.frame_limiter_settings = Some(snapshot.clone());
    record.config.frame_limiter_executable_path = Some("C:\\Games\\Example.exe".into());
    for state in [
        State::Preparing,
        State::Ready,
        State::Playing,
        State::Closing,
    ] {
        record.state = state;
        let response = record.response();
        assert_eq!(response["frame_limiter_settings"], snapshot);
        assert_eq!(
            response["frame_limiter_executable_path"],
            "C:\\Games\\Example.exe"
        );
    }
}

#[test]
fn stream_prepare_must_read_back_the_frozen_frame_limiter_snapshot() {
    let snapshot = json!({
        "version":1,
        "settings":{
            "frame_limiter_enable":true,
            "frame_limiter_fps_limit_millihz":60000,
            "frame_limiter_provider":"rtss",
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
    for response in ["missing", "changed", "wrong_path", "exact"] {
        let settings: Settings = serde_json::from_value(json!({
            "enabled":true,"bind":"127.0.0.1:0","allowed_principals":["caller"]
        }))
        .unwrap();
        let mut controller = Controller::new(settings).unwrap();
        let mut record = record(State::Preparing);
        record.config.frame_limiter_settings = Some(snapshot.clone());
        record.config.frame_limiter_executable_path = Some("C:\\Games\\Example.exe".into());
        record.config.application_operation_id = Some("launch-one".into());
        record.config.app_id = Some("app-0000000000000001".into());
        record.config.catalog_revision = Some(1);
        let job = Job {
            ticket: record.id,
            phase: Phase::Prepare,
            call: Call::new(json!({"action":"prepare"}), "prepare".into(), Some(19)),
            caller: Some(19),
            network: None,
            deadline: 5_000,
        };
        let mut prepared = json!({
            "ok":true,"state":"prepared","session":23,
            "audio_local":"127.0.0.1:51000","video_local":"127.0.0.1:51002",
            "control_local":"127.0.0.1:51004",
            "frame_limiter_settings":snapshot,
            "frame_limiter_executable_path":"C:\\Games\\Example.exe",
        });
        match response {
            "missing" => {
                prepared
                    .as_object_mut()
                    .unwrap()
                    .remove("frame_limiter_settings");
            }
            "changed" => {
                prepared["frame_limiter_settings"]["settings"]["rtss_frame_limit_type"] =
                    json!("async");
            }
            "wrong_path" => {
                prepared["frame_limiter_executable_path"] = json!("C:\\Games\\Other.exe");
            }
            _ => {}
        }
        let mut endpoint = Endpoint {
            active_request: true,
            ..Endpoint::default()
        };
        let runtime = client(&mut endpoint);
        controller.prepared(&mut record, job, &prepared, 10, &runtime);
        if response == "exact" {
            assert!(record.state == State::Ready);
            assert_eq!(record.response()["frame_limiter_settings"], snapshot);
        } else {
            assert!(record.state == State::Closing, "{response}");
            assert_eq!(record.failure, Some("frame_limiter_snapshot_unverified"));
        }
    }
}

#[test]
fn cancelled_parent_reaches_cleanup_failed_when_settlement_stays_unavailable() {
    let mut controller = Controller::new(Settings::default()).expect("disabled controller");
    let config = open();
    let record = Record {
        id: 5,
        owner: "caller".into(),
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
        url: "rtspenc://127.0.0.1:48010/launch-5".into(),
        session_token: "00112233445566778899aabbccddeeff".into(),
        udp_discovery: None,
        local: "127.0.0.1:48010".parse().expect("literal"),
        expires: 5_000,
        next_status: 5_000,
        failure: None,
        cleanup_error: None,
        cleanup_retry_count: 0,
        cleanup_retry_at: None,
        uncertain: None,
        uncertain_phase: None,
        needs_lookup: true,
        stream_state: None,
        display_applied: false,
        display_preflight_deadline: None,
        display_lease_ready_until: None,
        display_prepare_timeout_ms: None,
        revoke_after: None,
        cleanup_confirmed: false,
    };
    let payload = record.config.prepare(&record.operation(), None);
    controller.records.insert(record.id, record);
    controller.job = Some(Job {
        ticket: 5,
        phase: Phase::Prepare,
        call: Call::new(payload, "prepare-request".into(), Some(17)),
        caller: Some(17),
        network: None,
        deadline: 5_000,
    });
    let mut endpoint = Endpoint {
        deny_settlement: true,
        ..Endpoint::default()
    };
    let runtime = client(&mut endpoint);

    for now in 0..5 {
        controller.advance_job(&runtime, now);
    }

    let record = &controller.records[&5];
    assert!(record.state == State::CleanupFailed);
    assert_eq!(
        record.cleanup_error,
        Some("request_cancellation_unconfirmed")
    );
    assert!(record.uncertain.is_some());
    assert_eq!(
        endpoint
            .commands
            .iter()
            .filter(|command| matches!(command, Command::Request { .. }))
            .count(),
        1,
        "settlement retries must not resubmit an admitted mutation"
    );
}

#[test]
fn cleanup_status_polling_preserves_one_deadline() {
    let mut controller = Controller::new(Settings::default()).expect("disabled controller");
    let mut record = record(State::Closing);
    let mut endpoint = Endpoint::default();
    let runtime = client(&mut endpoint);
    let stopping = json!({
        "ok":true,
        "session":23,
        "state":"stopping",
        "cleanup_error":null
    });
    let job = Job {
        ticket: 5,
        phase: Phase::Status,
        call: Call::new(json!({"action":"status"}), "status-1".into(), None),
        caller: None,
        network: None,
        deadline: 99,
    };

    controller.status_result(&mut record, job, &stopping, 10, &runtime);
    let job = controller.job.take().expect("next status poll");
    assert_eq!(job.deadline, 99);
    controller.status_result(&mut record, job, &stopping, 50, &runtime);
    let job = controller.job.take().expect("next status poll");
    assert_eq!(job.deadline, 99);

    controller.records.insert(record.id, record);
    controller.job = Some(job);
    controller.advance_job(&runtime, 99);
    let record = &controller.records[&5];
    assert!(record.state == State::CleanupFailed);
    assert_eq!(record.cleanup_error, Some("cleanup_deadline"));
    assert!(record.uncertain.is_some());
}

#[test]
fn configured_ipv6_listener_and_media_binds_use_the_selected_family() {
    let settings: Settings = serde_json::from_value(json!({
        "enabled": true,
        "address_family": "both",
        "bind_address": "::1",
        "bind": "[::1]:0"
    }))
    .unwrap();
    let controller = Controller::new(settings).expect("IPv6 RTSP listener");
    let local = controller.local.expect("bound RTSP listener");
    assert_eq!(local.ip(), "::1".parse::<IpAddr>().unwrap());
    assert!(TcpStream::connect(local).is_ok());

    let binds = controller
        .settings
        .media_binds(TEST_BASE_PORT)
        .expect("IPv6 media listeners");
    assert_eq!(binds.video.ip(), local.ip());
    assert_eq!(binds.control.ip(), local.ip());
    assert_eq!(binds.audio.ip(), local.ip());
}

#[test]
#[ignore = "opens a wildcard listener; run explicitly when testing remote binding"]
fn wildcard_listener_advertises_the_peer_route_and_uses_it_for_udp_binds() {
    let settings: Settings = serde_json::from_value(json!({
        "enabled": true,
        "allow_remote": true,
        "address_family": "ipv4",
        "bind_address": "",
        "bind": "127.0.0.1:0"
    }))
    .unwrap();
    let controller = Controller::new(settings).expect("wildcard RTSP listener");
    let listener = controller.local.expect("bound RTSP listener");
    assert!(listener.ip().is_unspecified());

    let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let advertised = controller
        .advertised_local_for_peer(peer)
        .expect("route to loopback peer");
    assert_eq!(advertised.ip(), peer);
    assert_eq!(advertised.port(), listener.port());
    let binds = controller
        .settings
        .media_binds_on(TEST_BASE_PORT, advertised.ip())
        .expect("per-stream UDP binds");
    assert_eq!(binds.video.ip(), peer);
    assert_eq!(binds.control.ip(), peer);
    assert_eq!(binds.audio.ip(), peer);
    assert_eq!(
        controller.advertised_local_for_peer(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        Err("peer_family_mismatch")
    );
}

#[test]
fn loopback_family_listeners_accept_v4_and_v6_and_keep_each_stream_family_aligned() {
    assert_both_family_listeners_accept_v4_and_v6(false);
}

#[test]
#[ignore = "opens wildcard listeners; run explicitly when testing remote binding"]
fn wildcard_family_listeners_accept_v4_and_v6_and_keep_each_stream_family_aligned() {
    assert_both_family_listeners_accept_v4_and_v6(true);
}

fn assert_both_family_listeners_accept_v4_and_v6(allow_remote: bool) {
    let settings: Settings = serde_json::from_value(json!({
        "enabled": true,
        "allow_remote": allow_remote,
        "address_family": "both",
        "bind_address": "",
        "bind": "127.0.0.1:0"
    }))
    .unwrap();
    let controller = Controller::new(settings).expect("dual-family RTSP listeners");
    assert_eq!(controller.locals.len(), 2);
    assert_eq!(controller.locals[0].port(), controller.locals[1].port());

    for listener in &controller.locals {
        let peer_ip = if listener.is_ipv4() {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        } else {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        };
        assert_eq!(listener.ip().is_loopback(), !allow_remote);
        let destination = SocketAddr::new(
            if listener.ip().is_unspecified() {
                peer_ip
            } else {
                listener.ip()
            },
            listener.port(),
        );
        assert!(TcpStream::connect(destination).is_ok());

        let advertised = controller
            .advertised_local_for_peer(peer_ip)
            .expect("family-matched local route");
        assert_eq!(advertised.ip(), peer_ip);
        assert_eq!(advertised.port(), listener.port());
        let media = controller
            .settings
            .media_binds_on(TEST_BASE_PORT, advertised.ip())
            .expect("peer-family UDP binds");
        assert_eq!(media.video.ip(), peer_ip);
        assert_eq!(media.control.ip(), peer_ip);
        assert_eq!(media.audio.ip(), peer_ip);
    }
}

#[test]
fn status_reports_all_bound_families_and_keeps_legacy_local_field() {
    let settings: Settings = serde_json::from_value(json!({
        "enabled": true,
        "address_family": "both",
        "bind_address": "",
        "bind": "127.0.0.1:0"
    }))
    .unwrap();
    let controller = Controller::new(settings).expect("dual-family RTSP listeners");
    let mut endpoint = Endpoint::default();
    let runtime = client(&mut endpoint);

    controller.status(99, "caller", None, &runtime);

    let (_, response) = endpoint.completions.pop().expect("status completion");
    assert_eq!(response["local"], json!(controller.local));
    assert_eq!(response["locals"], json!(controller.locals));
    assert_eq!(response["locals"].as_array().unwrap().len(), 2);
}

fn free_base_port() -> u16 {
    // On Windows, an ephemeral TCP port can sit in an excluded UDP range.
    // Probe the actual RTSP and media ports before returning a base port.
    let start = u32::from(NEXT_TEST_BASE_PORT.fetch_add(37, Ordering::Relaxed))
        + std::process::id() % 18_000;
    for offset in 0..1_000_u32 {
        let base = 22_000 + ((start + offset * 37) % 18_000) as u16;
        let rtsp_port = base + 21;
        let Ok(_tcp_v4) = TcpListener::bind((Ipv4Addr::LOCALHOST, rtsp_port)) else {
            continue;
        };
        let Ok(_tcp_v6) = TcpListener::bind((Ipv6Addr::LOCALHOST, rtsp_port)) else {
            continue;
        };
        let udp_v4 = (9..=11)
            .map(|offset| UdpSocket::bind((Ipv4Addr::LOCALHOST, base + offset)))
            .collect::<std::io::Result<Vec<_>>>();
        let Ok(_udp_v4) = udp_v4 else {
            continue;
        };
        let udp_v6 = (9..=11)
            .map(|offset| UdpSocket::bind((Ipv6Addr::LOCALHOST, base + offset)))
            .collect::<std::io::Result<Vec<_>>>();
        if udp_v6.is_ok() {
            return base;
        }
    }
    panic!("no free RTSP test port range");
}

#[test]
fn network_port_updates_rebind_rtsp_and_defer_until_the_stream_is_idle() {
    let _guard = NETWORK_TEST_LOCK.lock().unwrap();
    let settings = Settings {
        enabled: true,
        bind: "127.0.0.1:0".parse().unwrap(),
        ..Settings::default()
    };
    let mut controller = Controller::new(settings).expect("enabled RTSP listener");
    let old_port = free_base_port();
    let mut port = free_base_port();
    while port == old_port {
        port = free_base_port();
    }
    let old_status = controller
        .configure_network_port(old_port, 1)
        .expect("initial base port applied");
    assert_eq!(old_status["active"], true);
    let old_local = controller.local.expect("bound listener");

    controller.records.insert(5, record(State::Playing));
    let pending = controller
        .configure_network_port(port, 10)
        .expect("configuration accepted");
    assert_eq!(pending["ok"], true);
    assert_eq!(pending["active"], false);
    assert_eq!(pending["pending"], true);
    assert_eq!(pending["udp_binds_preflighted"], false);
    assert_eq!(pending["active_base_port"], old_port);
    assert_eq!(controller.local, Some(old_local));
    let deferred_binds = controller
        .media_binds_for_open(IpAddr::V4(Ipv4Addr::LOCALHOST))
        .unwrap();
    assert_eq!(deferred_binds.video.port(), old_port + 9);
    assert_eq!(deferred_binds.control.port(), old_port + 10);
    assert_eq!(deferred_binds.audio.port(), old_port + 11);

    controller.records.get_mut(&5).unwrap().state = State::Closed;
    controller.reconcile_network_port(11);
    let active = controller.local.expect("rebound listener");
    assert_eq!(active.ip(), old_local.ip(), "preserve configured bind IP");
    assert_eq!(
        active.port(),
        port + 21,
        "port={port}, network_error={:?}",
        controller.network_error
    );
    assert_eq!(controller.active_network_base_port, Some(port));
    let applied_binds = controller
        .media_binds_for_open(IpAddr::V4(Ipv4Addr::LOCALHOST))
        .unwrap();
    assert_eq!(applied_binds.video.port(), port + 9);
    assert_eq!(applied_binds.control.port(), port + 10);
    assert_eq!(applied_binds.audio.port(), port + 11);

    let binds = controller.settings.media_binds(port).unwrap();
    assert_eq!(binds.video, SocketAddr::new(active.ip(), port + 9));
    assert_eq!(binds.control, SocketAddr::new(active.ip(), port + 10));
    assert_eq!(binds.audio, SocketAddr::new(active.ip(), port + 11));
}

#[test]
fn network_port_update_rebinds_both_family_listeners_and_udp_policy() {
    let _guard = NETWORK_TEST_LOCK.lock().unwrap();
    let settings: Settings = serde_json::from_value(json!({
        "enabled": true,
        "address_family": "both",
        "bind_address": "",
        "bind": "127.0.0.1:0"
    }))
    .unwrap();
    let mut controller = Controller::new(settings).expect("dual-family bootstrap listener");
    let base_port = free_base_port();

    let response = controller
        .configure_network_port(base_port, 1)
        .expect("dual-family network port applies");

    assert_eq!(response["active"], true);
    assert_eq!(controller.locals.len(), 2);
    assert_eq!(controller.locals[0].ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(controller.locals[1].ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
    assert_eq!(controller.locals[0].port(), base_port + 21);
    assert_eq!(controller.locals[1].port(), base_port + 21);
    for peer in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ] {
        let binds = controller
            .media_binds_for_open(peer)
            .expect("family-matched UDP policy");
        assert_eq!(binds.video.ip(), peer);
        assert_eq!(binds.video.port(), base_port + 9);
        assert_eq!(binds.control.ip(), peer);
        assert_eq!(binds.control.port(), base_port + 10);
        assert_eq!(binds.audio.ip(), peer);
        assert_eq!(binds.audio.port(), base_port + 11);
    }
}

#[test]
fn network_policy_update_activates_requested_family_and_empty_bind_address() {
    let _guard = NETWORK_TEST_LOCK.lock().unwrap();
    let settings = Settings {
        enabled: true,
        bind: "127.0.0.1:0".parse().unwrap(),
        ..Settings::default()
    };
    let mut controller = Controller::new(settings).expect("initial loopback listener");
    let port = free_base_port();

    let status = controller
        .configure_network_policy(
            port,
            Some(crate::model::AddressFamily::Both),
            Some(String::new()),
            0,
        )
        .unwrap();

    assert_eq!(status["active"], true);
    assert_eq!(status["udp_binds_preflighted"], true);
    assert_eq!(status["active_address_family"], "both");
    assert_eq!(status["active_bind_address"], "");
    assert_eq!(controller.locals.len(), 2);
    assert!(controller.locals.iter().any(|address| address.is_ipv4()));
    assert!(controller.locals.iter().any(|address| address.is_ipv6()));
    assert_eq!(
        controller
            .media_binds_for_open(IpAddr::V6(Ipv6Addr::LOCALHOST))
            .unwrap()
            .video
            .ip(),
        IpAddr::V6(Ipv6Addr::LOCALHOST)
    );
}

#[test]
fn network_policy_update_defers_family_and_bind_address_until_stream_is_terminal() {
    let _guard = NETWORK_TEST_LOCK.lock().unwrap();
    let port = free_base_port();
    let settings = Settings {
        enabled: true,
        bind: "127.0.0.1:0".parse().unwrap(),
        address_family: Some(crate::model::AddressFamily::Ipv4),
        bind_address: Some("127.0.0.1".into()),
        ..Settings::default()
    };
    let mut controller = Controller::new(settings).expect("IPv4 loopback listener");
    let initial = controller
        .configure_network_policy(
            port,
            Some(crate::model::AddressFamily::Ipv4),
            Some("127.0.0.1".into()),
            1,
        )
        .expect("initial IPv4 policy applies");
    assert_eq!(initial["active"], true);
    assert_eq!(initial["active_address_family"], "ipv4");
    assert_eq!(initial["active_bind_address"], "127.0.0.1");

    let old_listener = controller.local.expect("bound IPv4 listener");
    assert_eq!(old_listener.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(old_listener.port(), port + 21);
    assert!(TcpStream::connect(old_listener).is_ok());

    controller.records.insert(5, record(State::Playing));
    let pending = controller
        .configure_network_policy(
            port,
            Some(crate::model::AddressFamily::Both),
            Some(String::new()),
            2,
        )
        .expect("desired policy is accepted");

    assert_eq!(pending["ok"], true);
    assert_eq!(pending["active"], false);
    assert_eq!(pending["pending"], true);
    assert_eq!(pending["udp_binds_preflighted"], false);
    assert_eq!(pending["desired_port"], port);
    assert_eq!(pending["desired_address_family"], "both");
    assert_eq!(pending["desired_bind_address"], "");
    assert_eq!(pending["active_base_port"], port);
    assert_eq!(pending["active_address_family"], "ipv4");
    assert_eq!(pending["active_bind_address"], "127.0.0.1");
    assert_eq!(pending["rtsp_addresses"], json!([old_listener.to_string()]));
    assert_eq!(controller.local, Some(old_listener));
    assert_eq!(controller.locals, vec![old_listener]);
    assert!(TcpStream::connect(old_listener).is_ok());

    let old_media_binds = controller
        .media_binds_for_open(IpAddr::V4(Ipv4Addr::LOCALHOST))
        .expect("old IPv4 media binds remain active");
    assert_eq!(
        old_media_binds.video,
        SocketAddr::new(old_listener.ip(), port + 9)
    );
    assert_eq!(
        old_media_binds.control,
        SocketAddr::new(old_listener.ip(), port + 10)
    );
    assert_eq!(
        old_media_binds.audio,
        SocketAddr::new(old_listener.ip(), port + 11)
    );

    controller.records.get_mut(&5).unwrap().state = State::Closed;
    controller.reconcile_network_port(3);

    assert_eq!(controller.locals.len(), 2);
    let v4_listener = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port + 21);
    let v6_listener = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port + 21);
    assert!(controller.locals.contains(&v4_listener));
    assert!(controller.locals.contains(&v6_listener));
    assert!(TcpStream::connect(v4_listener).is_ok());
    assert!(TcpStream::connect(v6_listener).is_ok());
    assert_eq!(controller.active_network_base_port, Some(port));
    assert_eq!(
        controller.active_address_family,
        Some(crate::model::AddressFamily::Both)
    );
    assert_eq!(controller.active_bind_address.as_deref(), Some(""));

    for peer in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ] {
        let media_binds = controller
            .media_binds_for_open(peer)
            .expect("family-matched media binds after reconciliation");
        assert_eq!(media_binds.video, SocketAddr::new(peer, port + 9));
        assert_eq!(media_binds.control, SocketAddr::new(peer, port + 10));
        assert_eq!(media_binds.audio, SocketAddr::new(peer, port + 11));
    }
}

#[test]
fn null_network_overrides_confirm_rtsp_startup_policy_without_fabricating_overrides() {
    let _guard = NETWORK_TEST_LOCK.lock().unwrap();
    let base = free_base_port();
    let settings = Settings {
        enabled: true,
        bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), base + 21),
        address_family: Some(crate::model::AddressFamily::Ipv4),
        bind_address: Some(String::new()),
        ..Settings::default()
    };
    let mut controller = Controller::new(settings).expect("startup policy listener");

    let status = controller
        .configure_network_policy(base, None, None, 0)
        .unwrap();

    assert_eq!(status["active"], true);
    assert_eq!(status["active_address_family"], Value::Null);
    assert_eq!(status["active_bind_address"], Value::Null);
    assert_eq!(status["rtsp_addresses"].as_array().unwrap().len(), 1);
    assert_eq!(controller.locals[0].ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
}

#[test]
fn failed_startup_rebind_keeps_media_binds_aligned_with_the_bootstrap_listener() {
    let _guard = NETWORK_TEST_LOCK.lock().unwrap();
    let old_port = free_base_port();
    let mut desired_port = free_base_port();
    while desired_port == old_port {
        desired_port = free_base_port();
    }
    let settings = Settings {
        enabled: true,
        bind: SocketAddr::from(([127, 0, 0, 1], old_port + 21)),
        ..Settings::default()
    };
    let mut controller = Controller::new(settings).expect("bootstrap listener binds");
    assert_eq!(controller.local.unwrap().port(), old_port + 21);
    assert_eq!(controller.active_network_base_port, None);

    let _occupied_video_port =
        UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], desired_port + 9)))
            .expect("reserve desired video UDP port");
    let pending = controller
        .configure_network_port(desired_port, 0)
        .expect("desired base port is persisted for reconciliation");
    assert_eq!(pending["active"], false);
    assert_eq!(pending["error"], "udp_bind_failed");
    assert_eq!(controller.local.unwrap().port(), old_port + 21);

    let binds = controller
        .media_binds_for_open(IpAddr::V4(Ipv4Addr::LOCALHOST))
        .expect("bootstrap listener has its own base port");
    assert_eq!(binds.video.port(), old_port + 9);
    assert_eq!(binds.control.port(), old_port + 10);
    assert_eq!(binds.audio.port(), old_port + 11);
    assert_ne!(binds.video.port(), desired_port + 9);
}

#[test]
fn network_configuration_is_restricted_to_nvhttp_and_reports_disabled_listener_state() {
    let _guard = NETWORK_TEST_LOCK.lock().unwrap();
    let settings = Settings {
        enabled: true,
        bind: "127.0.0.1:0".parse().unwrap(),
        ..Settings::default()
    };
    let mut controller = Controller::new(settings).expect("listener");
    let mut endpoint = Endpoint::default();
    let runtime = client(&mut endpoint);
    let port = free_base_port();

    controller.receive(
        10,
        "amaterasu.management".into(),
        Operation::NetworkConfigure {
            port,
            address_family: None,
            bind_address: None,
        },
        0,
        5_000,
        &runtime,
    );
    assert_eq!(endpoint.completions[0].1["code"], "permission_denied");
    assert_eq!(controller.network_base_port, None);

    controller.receive(
        11,
        "amaterasu.nvhttp".into(),
        Operation::NetworkConfigure {
            port,
            address_family: None,
            bind_address: None,
        },
        0,
        5_000,
        &runtime,
    );
    assert_eq!(endpoint.completions[1].1["ok"], true);
    assert_eq!(endpoint.completions[1].1["active"], true);
    assert_eq!(endpoint.completions[1].1["active_base_port"], port);
}

#[test]
fn network_port_update_rejects_occupied_tcp_and_udp_targets_then_retries() {
    let _guard = NETWORK_TEST_LOCK.lock().unwrap();
    for occupied_udp_offset in [None, Some(9), Some(10), Some(11)] {
        let settings = Settings {
            enabled: true,
            bind: "127.0.0.1:0".parse().unwrap(),
            ..Settings::default()
        };
        let mut controller = Controller::new(settings).expect("enabled RTSP listener");
        let old_local = controller.local.expect("bound listener");
        let port = free_base_port();
        let tcp_reservation = if occupied_udp_offset.is_none() {
            Some(
                TcpListener::bind(SocketAddr::new(old_local.ip(), port + 21))
                    .expect("reserve target TCP port"),
            )
        } else {
            None
        };
        let udp_reservation = occupied_udp_offset
            .map(|offset| UdpSocket::bind(SocketAddr::new(old_local.ip(), port + offset)).unwrap());

        let pending = controller
            .configure_network_port(port, 0)
            .expect("desired port is accepted");
        assert_eq!(pending["active"], false);
        assert_eq!(
            pending["error"],
            if occupied_udp_offset.is_none() {
                "tcp_bind_failed"
            } else {
                "udp_bind_failed"
            }
        );
        assert_eq!(controller.local, Some(old_local));

        drop(tcp_reservation);
        drop(udp_reservation);
        controller.reconcile_network_port(1_000);
        assert_eq!(controller.local.unwrap().port(), port + 21);
        assert_eq!(controller.active_network_base_port, Some(port));
    }
}

#[test]
fn accepted_rtsp_connections_are_kept_on_the_old_listener_until_it_is_idle() {
    let _guard = NETWORK_TEST_LOCK.lock().unwrap();
    let settings = Settings {
        enabled: true,
        bind: "127.0.0.1:0".parse().unwrap(),
        ..Settings::default()
    };
    let mut controller = Controller::new(settings).expect("enabled RTSP listener");
    let old_local = controller.local.expect("bound listener");
    controller
        .transport
        .as_mut()
        .unwrap()
        .add_ticket(23, old_local.ip(), &[7; 16])
        .unwrap();
    let connection = TcpStream::connect(old_local).unwrap();
    controller.transport.as_mut().unwrap().poll(1);
    assert_eq!(controller.transport.as_ref().unwrap().connection_count(), 1);

    let port = free_base_port();
    let pending = controller
        .configure_network_port(port, 2)
        .expect("configuration accepted");
    assert_eq!(pending["active"], false);
    assert_eq!(controller.local, Some(old_local));

    drop(connection);
    controller.transport.as_mut().unwrap().poll(3);
    assert_eq!(controller.transport.as_ref().unwrap().connection_count(), 0);
    controller.reconcile_network_port(4);
    assert_eq!(controller.local.unwrap().port(), port + 21);
}

fn request(method: Method, target: &str, cseq: u32, session: bool) -> Request {
    let mut headers = Vec::new();
    if session {
        headers.push(("session".into(), "00112233445566778899aabbccddeeff".into()));
    }
    Request {
        method,
        target: target.into(),
        cseq,
        headers,
        body: Vec::new(),
    }
}

fn pending_play(record: &Record) -> (Negotiation, u64) {
    let mut negotiation = Negotiation::new(
        TrustedLaunch {
            epoch: record.id,
            rtsp_target: record.url.clone(),
            session_token: record.session_token.clone(),
            encrypted_rtsp: true,
            audio_port: 49_000,
            video_port: 49_002,
            control_port: 49_004,
            control_connect_data: record.config.connect_data,
            udp_discovery: None,
        },
        record.capabilities(),
    )
    .expect("valid negotiation");
    let target = record.url.as_str();
    negotiation
        .handle(record.id, &request(Method::Options, target, 1, false))
        .expect("options");
    let mut describe = request(Method::Describe, target, 2, false);
    describe
        .headers
        .push(("accept".into(), "application/sdp".into()));
    negotiation.handle(record.id, &describe).expect("describe");
    for (cseq, target) in [
        (3, "streamid=audio/0/0"),
        (4, "streamid=video/0/0"),
        (5, "streamid=control/13/0"),
    ] {
        let mut setup = request(Method::Setup, target, cseq, cseq > 3);
        setup.headers.push((
            "transport".into(),
            "unicast;X-GS-ClientPort=50000-50001".into(),
        ));
        negotiation.handle(record.id, &setup).expect("setup");
    }
    let mut announce = request(Method::Announce, "streamid=control/13/0", 6, true);
    announce
        .headers
        .push(("content-type".into(), "application/sdp".into()));
    announce.body = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/moonlight-h264.sdp"
    ))
    .replace(
        "x-ss-general.encryptionEnabled:0",
        "x-ss-general.encryptionEnabled:1",
    )
    .into_bytes();
    let NegotiationStep::Action { ticket, .. } =
        negotiation.handle(record.id, &announce).expect("announce")
    else {
        panic!("announce action");
    };
    negotiation
        .complete(record.id, ticket, true)
        .expect("announce accepted");
    let NegotiationStep::Action { ticket, .. } = negotiation
        .handle(record.id, &request(Method::Play, "/", 7, true))
        .expect("play")
    else {
        panic!("play action");
    };
    (negotiation, ticket)
}

fn announced_profile_record() -> (Record, Announce) {
    let announcement = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/moonlight-h264.sdp"
    ))
    .replace(
        "x-ss-general.encryptionEnabled:0",
        "x-ss-general.encryptionEnabled:7",
    );
    let announce = parse_announce(announcement.as_bytes()).expect("valid encrypted ANNOUNCE");
    let mut record = record(State::Ready);
    let profile = &mut record.config.profile;
    profile.width = announce.video.width;
    profile.height = announce.video.height;
    profile.fps = announce.video.fps;
    profile.bitrate_kbps = announce.video.bitrate_kbps;
    profile.max_reference_frames = announce.video.max_reference_frames;
    profile.packet_size = announce.packet_size as usize;
    profile.packet_ms = announce.audio.packet_duration_ms;
    profile.min_parity_shards = announce.fec.minimum_packets as u8;
    profile.encrypt_video = announce.encryption.video;
    profile.encrypt_audio = announce.encryption.audio;
    if let Some(repair_percent) = announce.fec.repair_percent {
        profile.fec_percentage = repair_percent as u8;
    }
    (record, announce)
}

#[test]
fn accepted_announce_encryption_flows_into_authenticated_play_start() {
    let (mut record, announce) = announced_profile_record();
    assert!(record.accept_announce(&announce));

    let payload = record
        .authenticated_start_payload(23)
        .expect("accepted ANNOUNCE enables authenticated start");

    assert_eq!(payload["action"], "start_when_authenticated");
    assert_eq!(payload["session"], 23);
    assert_eq!(
        payload["configuration"]["encrypt_video"],
        announce.encryption.video
    );
    assert_eq!(
        payload["configuration"]["encrypt_audio"],
        announce.encryption.audio
    );
    assert_eq!(
        payload["configuration"]["client_feature_flags"],
        announce.client_feature_flags
    );
    assert_eq!(
        payload["configuration"]["configuration"]["slices_per_frame"],
        announce.video.slices_per_frame
    );
    assert!(
        record.config.arm(23)["configuration"]
            .get("encrypt_video")
            .is_none()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn accepted_color_survives_authenticated_start() {
    let (mut record, mut announce) = announced_profile_record();
    announce.video.color = amaterasu_gamestream::sdp::ColorMode::Bt601Full;
    assert!(record.accept_announce(&announce));
    let payload = record
        .authenticated_start_payload(23)
        .expect("accepted color");
    assert_eq!(
        payload["configuration"]["configuration"]["color_mode"],
        "bt601_full"
    );
    assert!(
        record.config.arm(23)["configuration"]["configuration"]
            .get("color_mode")
            .is_none()
    );
}

#[test]
fn negotiated_video_is_owned_by_its_rtsp_ticket() {
    let (mut low_ticket, mut low_announce) = announced_profile_record();
    low_ticket.id = 5;
    low_ticket.session = Some(23);
    low_ticket.config.profile.width = 1280;
    low_ticket.config.profile.height = 720;
    low_ticket.config.profile.fps = 30;
    low_ticket.config.max_bitrate_kbps = Some(8_000);
    low_ticket.config.negotiation_bounds = Some(crate::model::NegotiationBounds {
        max_width: 1280,
        max_height: 720,
        max_fps: 30,
        max_bitrate_kbps: 8_000,
        max_reference_frames: 1,
    });
    low_announce.video.width = 1280;
    low_announce.video.height = 720;
    low_announce.video.fps = 30;
    low_announce.video.bitrate_kbps = 8_000;
    low_announce.video.max_reference_frames = 0;

    let (mut high_ticket, high_announce) = announced_profile_record();
    high_ticket.id = 6;
    high_ticket.session = Some(24);
    high_ticket.config.negotiation_bounds = Some(crate::model::NegotiationBounds {
        max_width: 2560,
        max_height: 1440,
        max_fps: 120,
        max_bitrate_kbps: 20_000,
        max_reference_frames: 1,
    });

    assert!(low_ticket.accept_announce(&low_announce));
    assert!(high_ticket.accept_announce(&high_announce));
    let low_start = low_ticket.authenticated_start_payload(23).unwrap();
    let high_start = high_ticket.authenticated_start_payload(24).unwrap();
    let expected_video = json!({"width":1280,"height":720,"fps":30,"bitrate":8_000_000,"max_reference_frames":0,"color_mode":"bt709_limited", "slices_per_frame": 1, "video_stream_format": low_announce.video.format});
    for (field, expected) in expected_video.as_object().unwrap() {
        assert_eq!(
            &low_start["configuration"]["configuration"][field], expected,
            "{field}"
        );
    }
    assert_eq!(high_start["configuration"]["configuration"]["width"], 1920);
    assert_eq!(high_start["configuration"]["configuration"]["height"], 1080);
    assert_eq!(high_start["configuration"]["configuration"]["fps"], 60);

    assert!(!low_ticket.accept_announce(&high_announce));
    assert!(low_ticket.authenticated_start_payload(23).is_none());
    assert!(high_ticket.authenticated_start_payload(24).is_some());
}

#[test]
fn authenticated_start_keeps_the_exact_ticket_codec() {
    let (mut record, mut announce) = announced_profile_record();
    record.config.profile.codec = amaterasu_media::VideoCodec::Hevc;
    announce.video.format.codec = amaterasu_gamestream::sdp::VideoCodec::Hevc;
    announce.video.color = amaterasu_gamestream::sdp::ColorMode::Bt709Limited;
    assert!(record.accept_announce(&announce));
    let start = record.authenticated_start_payload(23).unwrap();
    assert_eq!(start["configuration"]["configuration"]["codec"], "hevc");
    assert_eq!(
        record.config.prepare("hevc-prepare", None)["video"]["codec"],
        "hevc"
    );
}

#[test]
fn codec_offer_drives_describe_markers_announce_and_start_codec() {
    let (mut record, mut announce) = announced_profile_record();
    let only_h264 = record.capabilities().transport;
    assert!(!only_h264.hevc && !only_h264.av1);

    record.config.profile.codecs = vec![
        amaterasu_media::VideoCodec::H264,
        amaterasu_media::VideoCodec::Av1,
    ];
    let offered = record.capabilities().transport;
    assert!(offered.av1 && !offered.hevc);
    let prepared = record.config.prepare("offer-prepare", None);
    assert_eq!(prepared["video"]["codecs"], json!(["h264", "av1"]));
    assert!(prepared["video"].get("codec").is_none());

    announce.video.color = amaterasu_gamestream::sdp::ColorMode::Bt709Limited;
    announce.video.format.codec = amaterasu_gamestream::sdp::VideoCodec::Hevc;
    assert!(!record.accept_announce(&announce), "HEVC was not offered");
    announce.video.format.codec = amaterasu_gamestream::sdp::VideoCodec::Av1;
    assert!(record.accept_announce(&announce));
    let start = record.authenticated_start_payload(23).unwrap();
    assert_eq!(start["configuration"]["configuration"]["codec"], "av1");

    announce.video.format.codec = amaterasu_gamestream::sdp::VideoCodec::H264;
    assert!(record.accept_announce(&announce));
    let start = record.authenticated_start_payload(24).unwrap();
    assert!(
        start["configuration"]["configuration"]
            .get("codec")
            .is_none()
    );
}

#[test]
fn codec_offers_must_name_each_codec_once_and_replace_the_single_codec() {
    let (mut record, _) = announced_profile_record();
    record.config.profile.codecs = vec![
        amaterasu_media::VideoCodec::Hevc,
        amaterasu_media::VideoCodec::Av1,
    ];
    assert!(record.config.validate(false).is_ok());
    record
        .config
        .profile
        .codecs
        .push(amaterasu_media::VideoCodec::Av1);
    assert_eq!(record.config.validate(false), Err("invalid_profile"));
    record.config.profile.codecs = vec![amaterasu_media::VideoCodec::Hevc];
    record.config.profile.codec = amaterasu_media::VideoCodec::Hevc;
    assert_eq!(record.config.validate(false), Err("invalid_profile"));
}

#[test]
fn accepted_announce_freezes_pcm_haptics_flag_into_authenticated_start() {
    let (mut record, mut announce) = announced_profile_record();
    announce.client_feature_flags |= amaterasu_gamestream::sdp::CLIENT_FEATURE_HAPTICS_PCM;
    assert!(record.accept_announce(&announce));
    let payload = record.authenticated_start_payload(23).unwrap();
    assert_eq!(payload["configuration"]["client_feature_flags"], 7);
    assert_eq!(
        payload["configuration"]["configuration"]["video_stream_format"],
        serde_json::to_value(announce.video.format).unwrap()
    );
}

#[test]
fn unsupported_negotiated_codec_cannot_arm_h264_start_configuration() {
    let (mut record, mut announce) = announced_profile_record();
    announce.video.format = amaterasu_module_sdk::VideoStreamFormat {
        codec: amaterasu_module_sdk::VideoCodec::Hevc,
        bit_depth: 8,
        dynamic_range: amaterasu_module_sdk::DynamicRange::Sdr,
    };

    assert!(!record.accept_announce(&announce));
    assert!(record.negotiated_video_stream_format.is_none());
    assert!(record.authenticated_start_payload(23).is_none());
}

#[test]
fn rejected_announce_cannot_produce_an_authenticated_play_start() {
    let (mut record, announce) = announced_profile_record();
    record.config.profile.encrypt_audio = false;
    record.negotiated_encryption = Some(crate::model::EncryptionSnapshot {
        video: true,
        audio: true,
    });

    assert!(!record.accept_announce(&announce));
    assert!(record.negotiated_encryption.is_none());
    assert!(record.client_feature_flags.is_none());
    assert!(record.negotiated_color.is_none());
    assert!(record.negotiated_video.is_none());
    assert!(record.authenticated_start_payload(23).is_none());
}

#[test]
fn play_verifies_the_frozen_launch_snapshot_before_starting_the_stream() {
    let snapshot = json!({"version":1,"settings":{"frame_limiter_provider":"rtss"}});
    for case in [
        "exact",
        "wrong_operation",
        "wrong_app",
        "wrong_revision",
        "wrong_snapshot",
        "wrong_path",
        "unavailable",
    ] {
        let mut controller = Controller::new(Settings::default()).unwrap();
        let mut record = record(State::Ready);
        record.config.profile.bitrate_kbps = 20_000;
        record.config.profile.packet_size = 1_392;
        record.config.profile.packet_ms = 5;
        record.config.profile.encrypt_video = false;
        record.config.profile.encrypt_audio = false;
        record.negotiated_encryption = Some(crate::model::EncryptionSnapshot {
            video: true,
            audio: false,
        });
        record.negotiated_slices_per_frame = Some(1);
        record.negotiated_video_stream_format =
            Some(amaterasu_module_sdk::VideoStreamFormat::H264_SDR);
        record.client_feature_flags = Some(3);
        record.negotiated_color = Some(amaterasu_gamestream::sdp::ColorMode::Bt709Limited);
        record.negotiated_video = Some(crate::model::NegotiatedVideo {
            codec: amaterasu_media::VideoCodec::H264,
            width: record.config.profile.width,
            height: record.config.profile.height,
            fps: record.config.profile.fps,
            bitrate_kbps: record.config.profile.bitrate_kbps,
            max_reference_frames: record.config.profile.max_reference_frames,
        });
        record.config.frame_limiter_settings = Some(snapshot.clone());
        record.config.frame_limiter_executable_path = Some("C:\\Games\\Example.exe".into());
        record.config.application_operation_id = Some("launch-one".into());
        record.config.app_id = Some("app-0000000000000001".into());
        record.config.catalog_revision = Some(7);
        let (negotiation, action_ticket) = pending_play(&record);
        record.negotiation = Some(negotiation);
        let ticket = record.id;
        controller.schedule_frame_limiter_verification(&record, 999, action_ticket, 0);
        controller.records.insert(ticket, record);
        assert!(
            controller
                .job
                .as_ref()
                .is_some_and(|job| job.phase == Phase::VerifyFrameLimiter)
        );

        let mut reply = json!({
            "ok":true,"verified":true,
            "application_operation_id":"launch-one",
            "app_id":"app-0000000000000001",
            "catalog_revision":7,
            "frame_limiter_settings":snapshot,
            "frame_limiter_executable_path":"C:\\Games\\Example.exe",
        });
        match case {
            "wrong_operation" => reply["application_operation_id"] = json!("other-launch"),
            "wrong_app" => reply["app_id"] = json!("app-0000000000000002"),
            "wrong_revision" => reply["catalog_revision"] = json!(8),
            "wrong_snapshot" => reply["frame_limiter_settings"]["version"] = json!(2),
            "wrong_path" => reply["frame_limiter_executable_path"] = json!("C:\\Games\\Other.exe"),
            _ => {}
        }
        let mut endpoint = Endpoint {
            verifier_reply: Some(reply),
            deny_launch: case == "unavailable",
            ..Endpoint::default()
        };
        let runtime = client(&mut endpoint);
        controller.advance_job(&runtime, 1);
        let launch_request = endpoint.commands.iter().find_map(|command| match command {
            Command::Request {
                service, payload, ..
            } if service == "amaterasu.launch/1" => Some(payload),
            _ => None,
        });
        let launch_request = launch_request.expect("Launch verification precedes stream start");
        assert_eq!(launch_request["action"], "verify_frame_limiter_snapshot");
        assert_eq!(launch_request["app_id"], "app-0000000000000001");
        assert_eq!(launch_request["catalog_revision"], 7);
        assert!(!endpoint.commands.iter().any(|command| matches!(command,
            Command::Request { service, payload, .. }
                if service == "amaterasu.stream-session/1"
                    && payload["action"] == "start_when_authenticated")));

        if case != "unavailable" {
            controller.advance_job(&runtime, 2);
        }
        if case == "exact" {
            assert!(
                controller
                    .job
                    .as_ref()
                    .is_some_and(|job| job.phase == Phase::Arm)
            );
            controller.advance_job(&runtime, 3);
            assert!(endpoint.commands.iter().any(|command| matches!(command,
                Command::Request { service, payload, .. }
                    if service == "amaterasu.stream-session/1"
                        && payload["action"] == "start_when_authenticated")));
        } else {
            assert!(controller.job.is_none());
            assert!(controller.records[&ticket].state == State::Closing);
            assert_eq!(
                controller.records[&ticket].failure,
                Some(if case == "unavailable" {
                    "frame_limiter_verification_unavailable"
                } else {
                    "frame_limiter_snapshot_denied"
                })
            );
            assert!(!endpoint.commands.iter().any(|command| matches!(command,
                Command::Request { service, payload, .. }
                    if service == "amaterasu.stream-session/1"
                        && payload["action"] == "start_when_authenticated")));
        }
    }
}

#[test]
fn unavailable_play_response_never_marks_the_ticket_playing() {
    let mut controller = Controller::new(Settings::default()).expect("disabled controller");
    let mut record = record(State::Arming);
    record.config.profile.bitrate_kbps = 20_000;
    record.config.profile.packet_size = 1_392;
    record.config.profile.packet_ms = 5;
    record.config.profile.encrypt_video = false;
    record.config.profile.encrypt_audio = false;
    let (negotiation, action_ticket) = pending_play(&record);
    record.negotiation = Some(negotiation);
    let job = Job {
        ticket: record.id,
        phase: Phase::Arm,
        call: Call::new(
            json!({"action":"start_when_authenticated"}),
            "arm".into(),
            None,
        ),
        caller: None,
        network: Some((999, action_ticket)),
        deadline: 5_000,
    };

    controller.armed(
        &mut record,
        job,
        &json!({"ok":true,"session":23,"state":"armed","cleanup_error":null}),
        10,
    );

    assert!(record.state == State::Closing);
    assert_eq!(record.failure, Some("start_rejected"));
}
