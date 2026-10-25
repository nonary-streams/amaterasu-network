use super::*;
use amaterasu_gamestream::{rtsp::Method, sdp::parse_announce};
use amaterasu_module_sdk::abi::{self, AbiHeader, BorrowedBytes, HostApi, ReplySink};
use std::{
    collections::BTreeSet,
    ffi::c_void,
    time::{Duration, Instant},
};

const SESSION: u64 = 23;

struct CallerRequest {
    id: u64,
    caller: &'static str,
    payload: Value,
}

#[derive(Default)]
struct Endpoint {
    callers: VecDeque<CallerRequest>,
    active: BTreeSet<u64>,
    commands: Vec<Command>,
    completion_attempts: Vec<(u64, Value)>,
    downstream_actions: BTreeMap<u64, String>,
    downstream_payloads: BTreeMap<u64, Value>,
    next_downstream: u64,
    rejected_completions: BTreeSet<u64>,
    lose_prepare_result_once: bool,
    prepare_result_lost: bool,
    cleanup_fails: bool,
    reject_prepare: bool,
    wrong_history_reply: bool,
    stop_pending_for: Duration,
    stop_pending_until: Option<Instant>,
}

impl Endpoint {
    fn enqueue(&mut self, id: u64, caller: &'static str, payload: Value) {
        self.active.insert(id);
        self.callers.push_back(CallerRequest {
            id,
            caller,
            payload,
        });
    }

    fn enqueue_cancelled(&mut self, id: u64, caller: &'static str, payload: Value) {
        self.callers.push_back(CallerRequest {
            id,
            caller,
            payload,
        });
    }

    fn response(&mut self, command: &Command) -> Response {
        match command {
            Command::Poll {} => self
                .callers
                .pop_front()
                .map_or(Response::Pending, |request| Response::Request {
                    id: request.id,
                    caller: request.caller.into(),
                    initiator: request.caller.into(),
                    service: crate::SERVICE.into(),
                    payload: request.payload,
                    remaining_ms: 5_000,
                }),
            Command::CheckRequest { request } if self.active.contains(request) => Response::Ok,
            Command::CheckRequest { .. } => Response::error("request_ended", "cancelled"),
            Command::Complete { request, payload } => {
                self.completion_attempts.push((*request, payload.clone()));
                if self.rejected_completions.contains(request) {
                    Response::error("unavailable", "lost completion")
                } else {
                    self.active.remove(request);
                    Response::Ok
                }
            }
            Command::Request { payload, .. } => {
                self.next_downstream += 1;
                let request = 1_000 + self.next_downstream;
                self.downstream_actions.insert(
                    request,
                    payload["action"]
                        .as_str()
                        .expect("downstream action")
                        .into(),
                );
                self.downstream_payloads.insert(request, payload.clone());
                Response::Accepted { id: request }
            }
            Command::TakeResult { request } => {
                let action = self
                    .downstream_actions
                    .get(request)
                    .map(String::as_str)
                    .expect("known downstream request");
                if action == "stop" && !self.stop_pending_for.is_zero() {
                    let until = *self
                        .stop_pending_until
                        .get_or_insert_with(|| Instant::now() + self.stop_pending_for);
                    if Instant::now() < until {
                        return Response::Pending;
                    }
                }
                Response::Result {
                    payload: self.downstream_result(*request, action),
                }
            }
            Command::Cancel { .. } | Command::ReleaseResult { .. } => Response::Ok,
            unexpected => panic!("unexpected command: {unexpected:?}"),
        }
    }

    fn downstream_result(&self, request: u64, action: &str) -> Value {
        match action {
            "prepare" if self.reject_prepare => json!({
                "ok": false, "session": SESSION, "state": "failed", "code": "invalid_audio_configuration"
            }),
            "prepare" => {
                let sent = &self.downstream_payloads[&request];
                json!({
                    "ok": true,
                    "session": SESSION,
                    "state": "prepared",
                    "audio_local": "127.0.0.1:51000",
                    "video_local": "127.0.0.1:51002",
                    "control_local": "127.0.0.1:51004",
                    "history_activity_id":if self.wrong_history_reply { json!("foreign-operation") } else { sent["history_activity_id"].clone() },
                    "rtsp_operation_id":sent["rtsp_operation_id"]
                })
            }
            "lookup" => json!({"ok": true, "session": SESSION, "state": "prepared"}),
            "start_when_authenticated" => json!({"ok": true, "session": SESSION,
                "state": "armed", "cleanup_error": null}),
            "stop" if self.cleanup_fails => json!({
                "ok": true,
                "session": SESSION,
                "state": "cleanup_failed",
                "cleanup_error": "provider_cleanup_failed"
            }),
            "status" if self.cleanup_fails => json!({
                "ok": true,
                "session": SESSION,
                "state": "cleanup_failed",
                "cleanup_error": "provider_cleanup_failed"
            }),
            "stop" | "status" => json!({
                "ok": true,
                "session": SESSION,
                "state": "stopped",
                "cleanup_error": null
            }),
            action => panic!("unexpected downstream action: {action}"),
        }
    }

    fn should_lose_reply(&mut self, command: &Command) -> bool {
        let Command::TakeResult { request } = command else {
            return false;
        };
        if self.lose_prepare_result_once
            && !self.prepare_result_lost
            && self.downstream_actions.get(request).map(String::as_str) == Some("prepare")
        {
            self.prepare_result_lost = true;
            return true;
        }
        false
    }

    fn completed(&self, request: u64) -> &Value {
        &self
            .completion_attempts
            .iter()
            .find(|(completed, _)| *completed == request)
            .unwrap_or_else(|| panic!("request {request} was not completed"))
            .1
    }

    fn downstream_requests(&self) -> Vec<(&str, &str, Option<u64>)> {
        self.commands
            .iter()
            .filter_map(|command| match command {
                Command::Request {
                    payload,
                    operation_id,
                    parent,
                    ..
                } => Some((
                    payload["action"].as_str().expect("downstream action"),
                    operation_id.as_str(),
                    *parent,
                )),
                _ => None,
            })
            .collect()
    }
}

unsafe extern "C" fn invoke(
    context: *mut c_void,
    input: BorrowedBytes,
    reply: ReplySink,
) -> abi::Status {
    // SAFETY: every test keeps the endpoint alive and uses the client synchronously.
    let endpoint = unsafe { &mut *context.cast::<Endpoint>() };
    let Ok(bytes) = (unsafe { input.read() }) else {
        return abi::STATUS_INVALID_ARGUMENT;
    };
    let Ok(command) = serde_json::from_slice::<Command>(bytes) else {
        return abi::STATUS_INVALID_ARGUMENT;
    };
    endpoint.commands.push(command.clone());
    if endpoint.should_lose_reply(&command) {
        return abi::STATUS_INTERNAL_ERROR;
    }
    let output = serde_json::to_vec(&endpoint.response(&command)).expect("test response");
    // SAFETY: the synchronous SDK reply sink copies these bytes before return.
    unsafe { reply.send(&output) };
    abi::STATUS_OK
}

fn runtime(endpoint: &mut Endpoint) -> RuntimeClient {
    let api = HostApi {
        header: AbiHeader::of::<HostApi>(),
        context: (endpoint as *mut Endpoint).cast(),
        invoke,
    };
    // SAFETY: callers retain the endpoint and use the client synchronously.
    unsafe { RuntimeClient::from_endpoint(api) }
}

fn settings(enabled: bool, allowed_principals: &[&str]) -> Settings {
    Settings {
        enabled,
        allow_remote: false,
        bind: "127.0.0.1:0".parse().expect("literal"),
        allowed_principals: allowed_principals
            .iter()
            .map(|principal| (*principal).into())
            .collect(),
        ..Settings::default()
    }
}

fn open(operation_id: &str) -> Value {
    json!({
        "action": "open",
        "operation_id": operation_id,
        "peer_ip": "127.0.0.1",
        "video_port": 50000,
        "audio_port": 50002,
        "key_hex": "00112233445566778899aabbccddeeff",
        "key_id": 1,
        "connect_data": 2,
        "capture": {
            "capture_provider": "dxgi",
            "output": "display",
            "encoder": 1,
            "audio_endpoint": "default"
        }
    })
}

fn discovery_open(operation_id: &str) -> Value {
    let mut value = open(operation_id);
    value["video_port"] = json!(0);
    value["audio_port"] = json!(0);
    value["discover_peers"] = json!(true);
    value
}

fn tick(controller: &mut Controller, runtime: &RuntimeClient, now: u64) {
    controller.tick(runtime, now).expect("controller tick");
}

fn finish_prepare(controller: &mut Controller, runtime: &RuntimeClient) {
    for now in 0..3 {
        tick(controller, runtime, now);
    }
}

#[test]
fn authenticated_disconnect_revokes_ticket_and_stops_its_session() {
    let mut endpoint = Endpoint::default();
    endpoint.enqueue(1, "owner", open("disconnect-cleanup"));
    let runtime = runtime(&mut endpoint);
    let mut controller = Controller::new(settings(true, &["owner"])).unwrap();
    finish_prepare(&mut controller, &runtime);
    let ticket = endpoint.completed(1)["ticket"].as_u64().unwrap();

    controller.disconnected(77, Some(ticket), "peer_closed");
    assert_eq!(controller.records[&ticket].state, State::Closing);
    for now in 3..10 {
        tick(&mut controller, &runtime, now);
    }

    let stops: Vec<_> = endpoint
        .commands
        .iter()
        .filter_map(|command| match command {
            Command::Request {
                service, payload, ..
            } if service == "amaterasu.stream-session/1" && payload["action"] == "stop" => {
                Some(payload)
            }
            _ => None,
        })
        .collect();
    assert_eq!(stops.len(), 1);
    assert_eq!(stops[0]["session"], SESSION);
    assert!(controller.records[&ticket].cleanup_confirmed);
    assert_eq!(controller.records[&ticket].state, State::Failed);
}

#[test]
fn transient_cleanup_failure_retries_owned_stop_and_confirms_cleanup() {
    let mut endpoint = Endpoint {
        cleanup_fails: true,
        ..Endpoint::default()
    };
    endpoint.enqueue(1, "owner", open("disconnect-retry-cleanup"));
    let runtime = runtime(&mut endpoint);
    let mut controller = Controller::new(settings(true, &["owner"])).unwrap();
    finish_prepare(&mut controller, &runtime);
    let ticket = endpoint.completed(1)["ticket"].as_u64().unwrap();

    controller.disconnected(77, Some(ticket), "peer_closed");
    for now in 3..10 {
        tick(&mut controller, &runtime, now);
    }
    assert_eq!(controller.records[&ticket].state, State::CleanupFailed);
    assert!(!controller.records[&ticket].cleanup_confirmed);

    // Model the provider recovering after its first idempotent cleanup attempt.
    endpoint.cleanup_fails = false;
    for now in 10..400 {
        tick(&mut controller, &runtime, now);
        if controller.records[&ticket].cleanup_confirmed {
            break;
        }
    }

    assert!(controller.records[&ticket].cleanup_confirmed);
    assert_eq!(controller.records[&ticket].state, State::Failed);
    let stop_count = endpoint
        .downstream_requests()
        .iter()
        .filter(|(action, _, _)| *action == "stop")
        .count();
    assert_eq!(stop_count, 2, "recovery should issue one bounded retry");
    assert!(
        endpoint
            .downstream_requests()
            .iter()
            .all(|(action, _, parent)| { *action != "stop" || parent.is_none() })
    );
}

#[test]
fn cleanup_retry_budget_exhaustion_keeps_session_fail_closed() {
    let mut endpoint = Endpoint {
        cleanup_fails: true,
        ..Endpoint::default()
    };
    endpoint.enqueue(1, "owner", open("disconnect-cleanup-retry-exhausted"));
    let runtime = runtime(&mut endpoint);
    let mut controller = Controller::new(settings(true, &["owner"])).unwrap();
    finish_prepare(&mut controller, &runtime);
    let ticket = endpoint.completed(1)["ticket"].as_u64().unwrap();

    controller.disconnected(77, Some(ticket), "peer_closed");
    for now in 3..5_000 {
        tick(&mut controller, &runtime, now);
    }

    let record = &controller.records[&ticket];
    assert_eq!(record.state, State::CleanupFailed);
    assert!(!record.cleanup_confirmed);
    assert_eq!(record.cleanup_retry_count, MAX_CLEANUP_RETRIES);
    assert!(record.cleanup_error.is_some());
    let stop_count = endpoint
        .downstream_requests()
        .iter()
        .filter(|(action, _, _)| *action == "stop")
        .count();
    assert_eq!(stop_count, usize::from(MAX_CLEANUP_RETRIES) + 1);

    for now in 5_000..5_500 {
        tick(&mut controller, &runtime, now);
    }
    let later_stop_count = endpoint
        .downstream_requests()
        .iter()
        .filter(|(action, _, _)| *action == "stop")
        .count();
    assert_eq!(
        later_stop_count, stop_count,
        "exhausted cleanup is not retried forever"
    );
}

#[test]
fn orderly_module_shutdown_requests_replay_safe_stop_for_owned_sessions() {
    let mut endpoint = Endpoint::default();
    endpoint.enqueue(1, "owner", open("module-shutdown-cleanup"));
    let runtime = runtime(&mut endpoint);
    let mut controller = Controller::new(settings(true, &["owner"])).unwrap();
    finish_prepare(&mut controller, &runtime);
    let ticket = endpoint.completed(1)["ticket"].as_u64().unwrap();

    controller.shutdown(&runtime);
    controller.shutdown(&runtime);

    let stops: Vec<_> = endpoint
        .commands
        .iter()
        .filter_map(|command| match command {
            Command::Request {
                service,
                payload,
                operation_id,
                parent,
                ..
            } if service == "amaterasu.stream-session/1" && payload["action"] == "stop" => {
                Some((payload, operation_id, parent))
            }
            _ => None,
        })
        .collect();
    assert_eq!(stops.len(), 1);
    assert!(
        stops
            .iter()
            .all(|(payload, _, parent)| { payload["session"] == SESSION && parent.is_none() })
    );
    assert_eq!(controller.records[&ticket].state, State::Failed);
    assert!(controller.records[&ticket].cleanup_confirmed);
}

#[test]
fn orderly_module_shutdown_waits_for_delayed_stop_result_within_aggregate_budget() {
    let pending_for = Duration::from_millis(120);
    let mut endpoint = Endpoint {
        stop_pending_for: pending_for,
        ..Endpoint::default()
    };
    endpoint.enqueue(1, "owner", open("module-shutdown-delayed-stop"));
    let runtime = runtime(&mut endpoint);
    let mut controller = Controller::new(settings(true, &["owner"])).unwrap();
    finish_prepare(&mut controller, &runtime);
    let ticket = endpoint.completed(1)["ticket"].as_u64().unwrap();

    let started = Instant::now();
    controller.shutdown(&runtime);
    let elapsed = started.elapsed();

    assert!(elapsed >= pending_for);
    assert!(elapsed < Duration::from_secs(2));
    assert!(controller.records[&ticket].cleanup_confirmed);
}

#[test]
fn orderly_module_shutdown_keeps_cleanup_failed_when_provider_stop_is_uncertain() {
    let mut endpoint = Endpoint {
        cleanup_fails: true,
        ..Endpoint::default()
    };
    endpoint.enqueue(1, "owner", open("module-shutdown-failure"));
    let runtime = runtime(&mut endpoint);
    let mut controller = Controller::new(settings(true, &["owner"])).unwrap();
    finish_prepare(&mut controller, &runtime);
    let ticket = endpoint.completed(1)["ticket"].as_u64().unwrap();

    controller.shutdown(&runtime);

    assert!(!controller.records[&ticket].cleanup_confirmed);
    assert_eq!(controller.records[&ticket].state, State::CleanupFailed);
    assert_eq!(
        controller.records[&ticket].cleanup_error,
        Some("shutdown_stop_rejected")
    );
}

#[test]
fn orderly_module_shutdown_recovers_and_stops_an_uncertain_prepare() {
    let mut endpoint = Endpoint::default();
    endpoint.enqueue(1, "owner", open("interrupted-prepare"));
    let runtime = runtime(&mut endpoint);
    let mut controller = Controller::new(settings(true, &["owner"])).unwrap();
    tick(&mut controller, &runtime, 0);
    tick(&mut controller, &runtime, 1);
    let ticket = *controller.records.keys().next().expect("preparing ticket");
    assert!(controller.records[&ticket].needs_lookup);

    controller.shutdown(&runtime);

    assert!(controller.records[&ticket].cleanup_confirmed);
    assert_eq!(controller.records[&ticket].state, State::Failed);
    assert_eq!(
        endpoint
            .downstream_requests()
            .iter()
            .map(|entry| entry.0)
            .collect::<Vec<_>>(),
        ["prepare", "lookup", "stop"]
    );
    assert_eq!(endpoint.downstream_requests()[1].2, None);
    assert_eq!(endpoint.downstream_requests()[2].2, None);
}

fn surround_announcement(channels: u32, packet_ms: u32) -> String {
    let (mask, enabled) = match channels {
        6 => (63, 1),
        8 => (1599, 1),
        _ => (3, 0),
    };
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/moonlight-h264.sdp"
    ))
    .replace(
        "x-ss-general.encryptionEnabled:0",
        "x-ss-general.encryptionEnabled:7",
    )
    .replace(
        "x-nv-audio.surround.numChannels:2",
        &format!("x-nv-audio.surround.numChannels:{channels}"),
    )
    .replace(
        "x-nv-audio.surround.channelMask:3",
        &format!("x-nv-audio.surround.channelMask:{mask}"),
    )
    .replace(
        "x-nv-audio.surround.enable:0",
        &format!("x-nv-audio.surround.enable:{enabled}"),
    )
    .replace(
        "x-nv-aqos.packetDuration:5",
        &format!("x-nv-aqos.packetDuration:{packet_ms}"),
    )
}

fn surround_open(operation: &str, channels: u32, packet_ms: u32, bitrate: u32) -> Value {
    let announcement = parse_announce(surround_announcement(channels, packet_ms).as_bytes())
        .expect("supported surround SDP");
    let mut request = open(operation);
    request["capture"]["audio_endpoint"] = json!("");
    request["virtual_sink"] = json!("Steam Streaming Speakers");
    request["channels"] = json!(channels);
    request["profile"] = json!({
        "width": announcement.video.width,
        "height": announcement.video.height,
        "fps": announcement.video.fps,
        "bitrate_kbps": announcement.video.bitrate_kbps,
        "max_reference_frames": announcement.video.max_reference_frames,
        "packet_size": announcement.packet_size,
        "min_parity_shards": announcement.fec.minimum_packets,
        "packet_ms": packet_ms,
        "audio_bitrate": bitrate,
        "encrypt_video": announcement.encryption.video,
        "encrypt_audio": announcement.encryption.audio,
    });
    request
}

fn negotiation_request(method: Method, target: &str, cseq: u32, session: Option<&str>) -> Request {
    let mut headers = Vec::new();
    if let Some(session) = session {
        headers.push(("session".into(), session.into()));
    }
    Request {
        method,
        target: target.into(),
        cseq,
        headers,
        body: Vec::new(),
    }
}

fn negotiate_announce(record: &mut Record, body: &str) -> bool {
    let ticket = record.id;
    let target = record.url.clone();
    let session = record.session_token.clone();
    let negotiation = record.negotiation.as_mut().expect("prepared negotiation");
    negotiation
        .handle(
            ticket,
            &negotiation_request(Method::Options, &target, 1, None),
        )
        .expect("options");
    let mut describe = negotiation_request(Method::Describe, &target, 2, None);
    describe
        .headers
        .push(("accept".into(), "application/sdp".into()));
    negotiation.handle(ticket, &describe).expect("describe");
    for (cseq, target) in [
        (3, "streamid=audio/0/0"),
        (4, "streamid=video/0/0"),
        (5, "streamid=control/13/0"),
    ] {
        let mut setup = negotiation_request(
            Method::Setup,
            target,
            cseq,
            (cseq > 3).then_some(session.as_str()),
        );
        setup.headers.push((
            "transport".into(),
            "unicast;X-GS-ClientPort=50000-50001".into(),
        ));
        negotiation.handle(ticket, &setup).expect("setup");
    }
    let mut announce =
        negotiation_request(Method::Announce, "streamid=control/13/0", 6, Some(&session));
    announce
        .headers
        .push(("content-type".into(), "application/sdp".into()));
    announce.body = body.as_bytes().to_vec();
    let NegotiationStep::Action {
        ticket: action_ticket,
        action: Action::Announce(parsed),
    } = negotiation
        .handle(ticket, &announce)
        .expect("parsed ANNOUNCE")
    else {
        panic!("expected ANNOUNCE action");
    };
    let accepted = record.accept_announce(&parsed);
    record
        .negotiation
        .as_mut()
        .unwrap()
        .complete(ticket, action_ticket, accepted)
        .expect("ANNOUNCE completion");
    accepted
}

#[test]
fn surround_open_prepare_announce_and_authenticated_start_use_exact_layout() {
    for (channels, mask, layout, packet_ms, bitrate) in
        [(6, 63, "5.1", 5, 256_000), (8, 1599, "7.1", 10, 512_000)]
    {
        let mut endpoint = Endpoint::default();
        let opened = surround_open("surround", channels, packet_ms, bitrate);
        endpoint.enqueue(1, "owner", opened.clone());
        let runtime = runtime(&mut endpoint);
        let mut controller = Controller::new(settings(true, &["owner"])).unwrap();
        finish_prepare(&mut controller, &runtime);
        let ticket = endpoint.completed(1)["ticket"].as_u64().unwrap();
        let prepares: Vec<_> = endpoint
            .commands
            .iter()
            .filter_map(|command| match command {
                Command::Request { payload, .. } if payload["action"] == "prepare" => Some(payload),
                _ => None,
            })
            .collect();
        assert_eq!(prepares.len(), 1);
        assert_eq!(
            prepares[0]["audio"],
            json!({"channels":channels,"channel_mask":mask,
            "layout":layout,"packet_ms":packet_ms,"bitrate":bitrate})
        );
        endpoint.enqueue(2, "owner", opened.clone());
        let mut changed = opened;
        changed["channels"] = json!(if channels == 6 { 8 } else { 6 });
        if channels == 6 {
            changed["profile"]["audio_bitrate"] = json!(512_000);
        }
        endpoint.enqueue(3, "owner", changed);
        tick(&mut controller, &runtime, 3);
        tick(&mut controller, &runtime, 4);
        assert_eq!(endpoint.completed(2), endpoint.completed(1));
        assert_eq!(endpoint.completed(3)["code"], "operation_conflict");
        assert_eq!(
            endpoint
                .downstream_requests()
                .iter()
                .filter(|(action, _, _)| *action == "prepare")
                .count(),
            1
        );

        let record = controller.records.get_mut(&ticket).unwrap();
        let body = surround_announcement(channels, packet_ms);
        assert!(negotiate_announce(record, &body));
        let start = record
            .authenticated_start_payload(SESSION)
            .expect("accepted ANNOUNCE");
        assert_eq!(start["configuration"]["channels"], channels);
        assert_eq!(
            start["configuration"]["virtual_sink"],
            "Steam Streaming Speakers"
        );
        controller.job = Some(Job {
            ticket,
            phase: Phase::Arm,
            call: Call::new(start, format!("surround-arm-{channels}"), None),
            caller: None,
            network: Some((0, 0)),
            deadline: 5_000,
        });
        tick(&mut controller, &runtime, 5);
        let started = endpoint
            .commands
            .iter()
            .find_map(|command| match command {
                Command::Request { payload, .. }
                    if payload["action"] == "start_when_authenticated" =>
                {
                    Some(payload)
                }
                _ => None,
            })
            .expect("stream-session Start request");
        assert_eq!(started["configuration"]["channels"], channels);
        assert_eq!(
            started["configuration"]["virtual_sink"],
            "Steam Streaming Speakers"
        );
        for now in 6..11 {
            tick(&mut controller, &runtime, now);
        }
        assert!(
            endpoint
                .downstream_requests()
                .iter()
                .any(|(action, _, _)| *action == "stop")
        );
    }
}

#[test]
fn surround_wrong_announce_cannot_arm_and_failed_prepare_stops_owned_stream() {
    for (announced_channels, announced_ms) in [(8, 5), (6, 10)] {
        let mut endpoint = Endpoint::default();
        endpoint.enqueue(1, "owner", surround_open("wrong-announce", 6, 5, 256_000));
        let first_runtime = runtime(&mut endpoint);
        let mut controller = Controller::new(settings(true, &["owner"])).unwrap();
        finish_prepare(&mut controller, &first_runtime);
        let ticket = endpoint.completed(1)["ticket"].as_u64().unwrap();
        let record = controller.records.get_mut(&ticket).unwrap();
        assert!(!negotiate_announce(
            record,
            &surround_announcement(announced_channels, announced_ms)
        ));
        assert!(record.authenticated_start_payload(SESSION).is_none());
        assert!(
            !endpoint
                .downstream_requests()
                .iter()
                .any(|(action, _, _)| *action == "start_when_authenticated")
        );
    }
    for (name, original, changed) in [("channelMask", "63", "3"), ("enable", "1", "0")] {
        let body = surround_announcement(6, 5).replace(
            &format!("x-nv-audio.surround.{name}:{original}"),
            &format!("x-nv-audio.surround.{name}:{changed}"),
        );
        assert!(parse_announce(body.as_bytes()).is_err());
    }

    let mut endpoint = Endpoint {
        reject_prepare: true,
        ..Endpoint::default()
    };
    endpoint.enqueue(1, "owner", surround_open("failed-prepare", 8, 10, 512_000));
    let runtime = runtime(&mut endpoint);
    let mut controller = Controller::new(settings(true, &["owner"])).unwrap();
    for now in 0..8 {
        tick(&mut controller, &runtime, now);
    }
    assert_eq!(endpoint.completed(1)["state"], "failed");
    assert_eq!(
        endpoint
            .downstream_requests()
            .iter()
            .map(|(action, _, _)| *action)
            .collect::<Vec<_>>(),
        ["prepare", "stop"]
    );
    assert!(
        controller
            .records
            .values()
            .all(|record| record.cleanup_confirmed)
    );
}

#[test]
fn disabled_unauthorized_and_cancelled_admissions_never_allocate() {
    let cases = [
        (settings(false, &["owner"]), true, "disabled"),
        (settings(true, &["someone-else"]), true, "permission_denied"),
        (settings(true, &["owner"]), false, "cancelled"),
    ];

    for (settings, active, expected) in cases {
        let mut endpoint = Endpoint::default();
        if active {
            endpoint.enqueue(1, "owner", open("admission"));
        } else {
            endpoint.enqueue_cancelled(1, "owner", open("admission"));
        }
        let runtime = runtime(&mut endpoint);
        let mut controller = Controller::new(settings).expect("controller");
        tick(&mut controller, &runtime, 0);

        assert!(controller.records.is_empty(), "{expected}");
        assert!(endpoint.downstream_requests().is_empty(), "{expected}");
        if active {
            assert_eq!(endpoint.completed(1)["code"], expected);
        } else {
            assert!(
                endpoint
                    .completion_attempts
                    .iter()
                    .all(|(request, _)| *request != 1)
            );
        }
    }
}

#[test]
fn unreachable_peer_address_family_never_allocates_a_ticket() {
    let mut endpoint = Endpoint::default();
    let mut payload = open("wrong-address-family");
    payload["peer_ip"] = json!("::1");
    endpoint.enqueue(1, "owner", payload);
    let runtime = runtime(&mut endpoint);
    let mut controller = Controller::new(settings(true, &["owner"])).unwrap();
    tick(&mut controller, &runtime, 0);
    assert_eq!(endpoint.completed(1)["code"], "peer_family_mismatch");
    assert!(controller.records.is_empty());
    assert!(endpoint.downstream_requests().is_empty());
}

#[test]
fn successful_prepare_and_exact_retry_share_one_owned_allocation() {
    let mut endpoint = Endpoint::default();
    endpoint.enqueue(1, "owner", open("same-operation"));
    endpoint.enqueue(2, "owner", open("same-operation"));
    let runtime = runtime(&mut endpoint);
    let mut controller = Controller::new(settings(true, &["owner"])).expect("controller");

    finish_prepare(&mut controller, &runtime);

    let first = endpoint.completed(1);
    let second = endpoint.completed(2);
    assert_eq!(first["ok"], true);
    assert_eq!(first["state"], "ready");
    assert_eq!(second, first);
    assert_eq!(controller.records.len(), 1);
    assert_eq!(endpoint.downstream_requests().len(), 1);
    assert_eq!(endpoint.downstream_requests()[0].0, "prepare");
    assert_eq!(endpoint.downstream_requests()[0].2, Some(1));
}

#[test]
fn history_activity_attaches_to_the_exact_signed_rtsp_operation() {
    let mut endpoint = Endpoint::default();
    let mut tagged = open("nvhttp-activity-one");
    tagged["history_activity_id"] = json!("nvhttp-activity-one");
    endpoint.enqueue(1, "amaterasu.nvhttp", tagged.clone());
    endpoint.enqueue(2, "amaterasu.nvhttp", tagged.clone());
    let mut changed = tagged.clone();
    changed["history_activity_id"] = json!("foreign-operation");
    endpoint.enqueue(3, "amaterasu.nvhttp", changed);
    endpoint.enqueue(4, "owner", tagged);
    endpoint.enqueue(5, "amaterasu.nvhttp", open("nvhttp-activity-one"));
    let runtime = runtime(&mut endpoint);
    let mut controller = Controller::new(settings(true, &["amaterasu.nvhttp", "owner"])).unwrap();

    for now in 0..10 {
        tick(&mut controller, &runtime, now);
    }

    assert_eq!(endpoint.completed(1)["state"], "ready");
    assert_eq!(endpoint.completed(1), endpoint.completed(2));
    assert_eq!(
        endpoint.completed(1)["history_activity_id"],
        "nvhttp-activity-one"
    );
    assert_eq!(endpoint.completed(3)["code"], "history_activity_denied");
    assert_eq!(endpoint.completed(4)["code"], "history_activity_denied");
    assert_eq!(endpoint.completed(5)["code"], "operation_conflict");
    let prepares: Vec<_> = endpoint
        .commands
        .iter()
        .filter_map(|command| match command {
            Command::Request { payload, .. } if payload["action"] == "prepare" => Some(payload),
            _ => None,
        })
        .collect();
    assert_eq!(prepares.len(), 1);
    assert_eq!(prepares[0]["history_activity_id"], "nvhttp-activity-one");
    assert_eq!(prepares[0]["rtsp_operation_id"], "nvhttp-activity-one");
    assert_eq!(controller.records.len(), 1);
    let ticket = endpoint.completed(1)["ticket"].clone();
    endpoint.enqueue(
        6,
        "amaterasu.nvhttp",
        json!({"action":"status","ticket":ticket}),
    );
    tick(&mut controller, &runtime, 10);
    assert_eq!(
        endpoint.completed(6)["history_activity_id"],
        "nvhttp-activity-one"
    );
}

#[test]
fn history_prepare_mismatch_cleans_up_and_legacy_open_omits_identity() {
    let mut endpoint = Endpoint {
        wrong_history_reply: true,
        ..Endpoint::default()
    };
    let mut tagged = open("nvhttp-activity-two");
    tagged["history_activity_id"] = json!("nvhttp-activity-two");
    endpoint.enqueue(1, "amaterasu.nvhttp", tagged);
    let runtime_client = runtime(&mut endpoint);
    let mut controller = Controller::new(settings(true, &["amaterasu.nvhttp"])).unwrap();
    for now in 0..6 {
        tick(&mut controller, &runtime_client, now);
    }
    assert_eq!(
        endpoint.completed(1)["failure"],
        "history_activity_unverified"
    );
    assert!(
        endpoint
            .downstream_requests()
            .iter()
            .any(|(action, _, _)| *action == "stop")
    );

    let mut endpoint = Endpoint::default();
    endpoint.enqueue(1, "owner", open("legacy-operation"));
    let runtime = runtime(&mut endpoint);
    let mut controller = Controller::new(settings(true, &["owner"])).unwrap();
    finish_prepare(&mut controller, &runtime);
    assert_eq!(endpoint.completed(1)["state"], "ready");
    assert!(endpoint.completed(1)["history_activity_id"].is_null());
    let prepare = endpoint
        .commands
        .iter()
        .find_map(|command| match command {
            Command::Request { payload, .. } if payload["action"] == "prepare" => Some(payload),
            _ => None,
        })
        .unwrap();
    assert!(prepare.get("history_activity_id").is_none());
    assert!(prepare.get("rtsp_operation_id").is_none());
}

#[test]
fn unattested_display_request_never_prepares_a_stream_or_mutates_a_display() {
    let mut endpoint = Endpoint::default();
    let mut request = open("display-without-snapshot");
    request["display_request"] = json!({
        "configuration":{"displays":[{
            "id":"monitor.one","width":1920,"height":1080,
            "refresh":{"numerator":60,"denominator":1},"x":0,"y":0
        }]},
        "mode_policy":{"display_id":"monitor.one","remapping":{},"context":{
            "resolution_is_automatic":true,"refresh_rate_is_automatic":true,
            "client_display_mode_override":false,"optimize_game_settings":false
        }}
    });
    endpoint.enqueue(1, "owner", request.clone());
    request["operation_id"] = json!("display-with-snapshot");
    request["display_policy_snapshot"] = json!({
        "catalog_revision":7,
        "certificate_id":"ab".repeat(32),
        "application_overrides":{},
        "client_overrides":{},
        "effective_overrides":{}
    });
    endpoint.enqueue(2, "owner", request);
    let runtime = runtime(&mut endpoint);
    let mut controller = Controller::new(settings(true, &["owner"])).unwrap();
    tick(&mut controller, &runtime, 0);
    tick(&mut controller, &runtime, 1);

    assert_eq!(endpoint.completed(1)["code"], "display_request_unattested");
    assert_eq!(endpoint.completed(2)["code"], "display_request_unattested");
    assert!(controller.records.is_empty());
    assert!(endpoint.downstream_requests().is_empty());
}

#[test]
fn ready_ticket_uses_configured_ping_timeout_after_preparation() {
    for timeout in [250, 10_000] {
        let mut endpoint = Endpoint::default();
        let mut request = open("timeout-operation");
        request["ping_timeout_ms"] = json!(timeout);
        endpoint.enqueue(1, "owner", request);
        let runtime = runtime(&mut endpoint);
        let mut controller = Controller::new(settings(true, &["owner"])).unwrap();

        finish_prepare(&mut controller, &runtime);

        let record = controller.records.values().next().expect("prepared ticket");
        assert!(record.state == State::Ready);
        assert!((timeout..=timeout + 2).contains(&record.expires));
    }
}

#[test]
fn ready_ticket_uses_default_ping_timeout_after_preparation() {
    let admission_time = 0_u64;
    let request = open("default-timeout-operation");
    assert!(request.get("ping_timeout_ms").is_none());
    let Operation::Open(config) =
        serde_json::from_value(request.clone()).expect("valid open request")
    else {
        panic!("open helper should deserialize as an open operation");
    };
    assert_eq!(config.ping_timeout_ms, 10_000);

    let mut endpoint = Endpoint::default();
    endpoint.enqueue(1, "owner", request);
    let runtime = runtime(&mut endpoint);
    let mut controller = Controller::new(settings(true, &["owner"])).expect("controller");

    finish_prepare(&mut controller, &runtime);

    let record = controller.records.values().next().expect("prepared ticket");
    assert!(record.state == State::Ready);
    assert_eq!(record.config.ping_timeout_ms, 10_000);
    let expected_expiry = admission_time + 10_000;
    assert!((expected_expiry..=expected_expiry + 2).contains(&record.expires));
}

#[test]
fn discovery_tokens_are_fresh_per_ticket_stable_on_retry_and_never_public() {
    let mut endpoint = Endpoint::default();
    endpoint.enqueue(1, "owner", discovery_open("discovery-one"));
    endpoint.enqueue(2, "owner", discovery_open("discovery-one"));
    endpoint.enqueue(3, "owner", discovery_open("discovery-two"));
    let runtime = runtime(&mut endpoint);
    let mut controller = Controller::new(settings(true, &["owner"])).expect("controller");

    for now in 0..8 {
        tick(&mut controller, &runtime, now);
    }

    assert_eq!(controller.records.len(), 2);
    assert_eq!(endpoint.completed(1), endpoint.completed(2));
    let prepares: Vec<_> = endpoint
        .commands
        .iter()
        .filter_map(|command| match command {
            Command::Request { payload, .. } if payload["action"] == "prepare" => Some(payload),
            _ => None,
        })
        .collect();
    assert_eq!(prepares.len(), 2);

    let mut all_tokens = BTreeSet::new();
    for prepare in prepares {
        assert!(prepare.get("video_port").is_none());
        assert!(prepare.get("audio_port").is_none());
        for lane in ["audio_ping_payload", "video_ping_payload"] {
            let token = prepare["discovery"][lane].as_str().expect("token");
            assert_eq!(token.len(), 16);
            assert!(
                token
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            );
            assert!(all_tokens.insert(token.to_owned()), "reused {lane} token");
        }
    }

    for request in 1..=3 {
        let public = endpoint.completed(request).to_string();
        assert!(all_tokens.iter().all(|token| !public.contains(token)));
        assert!(!public.contains("ping_payload"));
    }
}

#[test]
fn foreign_status_lookup_and_close_cannot_observe_or_stop_an_owned_record() {
    let mut endpoint = Endpoint::default();
    endpoint.enqueue(1, "owner", open("private-operation"));
    let runtime = runtime(&mut endpoint);
    let mut controller = Controller::new(settings(true, &["owner"])).expect("controller");
    finish_prepare(&mut controller, &runtime);

    let ticket = endpoint.completed(1)["ticket"].as_u64().unwrap();
    endpoint.enqueue(2, "intruder", json!({"action": "status", "ticket": ticket}));
    endpoint.enqueue(
        3,
        "intruder",
        json!({"action": "lookup", "operation_id": "private-operation"}),
    );
    endpoint.enqueue(4, "intruder", json!({"action": "close", "ticket": ticket}));
    endpoint.enqueue(5, "owner", json!({"action": "status", "ticket": ticket}));
    for now in 3..7 {
        tick(&mut controller, &runtime, now);
    }

    for request in 2..=4 {
        assert_eq!(endpoint.completed(request)["code"], "ticket_not_found");
    }
    assert_eq!(endpoint.completed(5)["ticket"], ticket);
    assert_eq!(endpoint.completed(5)["state"], "ready");
    assert_eq!(controller.records.len(), 1);
    assert_eq!(endpoint.downstream_requests().len(), 1);
}

fn lost_completion_result(cleanup_fails: bool) -> (Endpoint, Value, Vec<String>) {
    let mut endpoint = Endpoint {
        cleanup_fails,
        ..Endpoint::default()
    };
    endpoint.rejected_completions.insert(1);
    endpoint.enqueue(1, "owner", open("lost-completion"));
    let runtime = runtime(&mut endpoint);
    let mut controller = Controller::new(settings(true, &["owner"])).expect("controller");

    for now in 0..8 {
        tick(&mut controller, &runtime, now);
        if controller
            .records
            .values()
            .all(|record| matches!(record.state, State::Failed | State::CleanupFailed))
        {
            break;
        }
    }
    let record = controller.records.values().next().expect("retained record");
    let response = record.response();
    let actions = endpoint
        .downstream_requests()
        .iter()
        .map(|(action, _, _)| (*action).to_owned())
        .collect();
    drop(controller);
    (endpoint, response, actions)
}

#[test]
fn lost_prepare_completion_stops_only_its_session_and_retains_cleanup_outcome() {
    let (endpoint, terminal, actions) = lost_completion_result(false);
    assert_eq!(actions, ["prepare", "stop"]);
    assert_eq!(terminal["state"], "failed");
    assert_eq!(terminal["failure"], "completion_unavailable");
    assert!(terminal["cleanup_error"].is_null());
    assert_eq!(
        endpoint.downstream_requests()[1].2,
        None,
        "cleanup must not inherit authority from a lost caller"
    );

    let (_, cleanup_failed, actions) = lost_completion_result(true);
    assert_eq!(actions, ["prepare", "stop", "status"]);
    assert_eq!(cleanup_failed["state"], "cleanup_failed");
    assert_eq!(cleanup_failed["failure"], "completion_unavailable");
    assert_eq!(cleanup_failed["cleanup_error"], "stream_cleanup_failed");
}

#[test]
fn post_commit_lost_prepare_result_settles_before_lookup_and_owned_stop() {
    let mut endpoint = Endpoint {
        lose_prepare_result_once: true,
        ..Endpoint::default()
    };
    endpoint.enqueue(1, "owner", open("lost-result"));
    let runtime = runtime(&mut endpoint);
    let mut controller = Controller::new(settings(true, &["owner"])).expect("controller");

    for now in 0..9 {
        tick(&mut controller, &runtime, now);
    }

    let requests = endpoint.downstream_requests();
    assert_eq!(
        requests
            .iter()
            .map(|(action, _, _)| *action)
            .collect::<Vec<_>>(),
        ["prepare", "lookup", "stop"]
    );
    assert_eq!(requests[0].2, Some(1));
    assert_eq!(requests[1].2, None);
    assert_eq!(requests[2].2, None);

    let cancelled = endpoint
        .commands
        .iter()
        .position(|command| matches!(command, Command::Cancel { request: 1001 }))
        .expect("prepare cancellation");
    let released = endpoint
        .commands
        .iter()
        .rposition(|command| matches!(command, Command::ReleaseResult { request: 1001 }))
        .expect("prepare release");
    let lookup = endpoint
        .commands
        .iter()
        .position(|command| {
            matches!(command, Command::Request { payload, .. } if payload["action"] == "lookup")
        })
        .expect("lookup request");
    assert!(cancelled < lookup && released < lookup);

    let record = controller.records.values().next().expect("retained record");
    assert_eq!(record.response()["state"], "failed");
    assert_eq!(record.response()["failure"], "dependency_unavailable");
    assert!(record.response()["cleanup_error"].is_null());
}
