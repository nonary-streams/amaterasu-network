use super::*;
use amaterasu_module_sdk::abi::*;
use std::{collections::VecDeque, ffi::c_void, net::UdpSocket};

struct Host {
    responses: VecDeque<Response>,
    completed: Vec<serde_json::Value>,
}

unsafe extern "C" fn invoke(
    context: *mut c_void,
    input: BorrowedBytes,
    output: ReplySink,
) -> Status {
    // SAFETY: test host and borrowed arguments remain live through invocation.
    let host = unsafe { &mut *context.cast::<Host>() };
    let command: Command = serde_json::from_slice(unsafe { input.read().unwrap() }).unwrap();
    if let Command::Complete { payload, .. } = command {
        host.completed.push(payload);
    }
    let response = host.responses.pop_front().expect("unexpected runtime call");
    unsafe { output.send(&serde_json::to_vec(&response).unwrap()) };
    STATUS_OK
}

fn start(host: &mut Host) -> ControlTransport {
    host.responses.extend([
        Response::Result {
            payload: json!({"enabled": true, "allowed_principals": ["alice"]}),
        },
        Response::Ok,
        Response::Ok,
    ]);
    let api = HostApi {
        header: AbiHeader::of::<HostApi>(),
        context: (host as *mut Host).cast(),
        invoke,
    };
    // SAFETY: each test keeps its host alive until the module is dropped.
    ControlTransport::start(unsafe { RuntimeClient::from_endpoint(api) }).unwrap()
}

fn open_request() -> Response {
    Response::Request {
        id: 1,
        caller: "alice".into(),
        initiator: "untrusted-initiator".into(),
        service: SERVICE.into(),
        remaining_ms: 1000,
        payload: json!({
            "action": "open",
            "peer_ip": "127.0.0.1",
            "connect_data": 17,
            "key_hex": "0123456789abcdef0123456789abcdef",
            "operation_id": "first"
        }),
    }
}

fn ended() -> Response {
    Response::Error {
        code: "request_ended".into(),
        message: "ended".into(),
    }
}

#[test]
fn cancellation_before_open_or_after_allocation_leaves_no_hidden_port() {
    for before in [true, false] {
        let mut host = Host {
            responses: VecDeque::new(),
            completed: Vec::new(),
        };
        let mut module = start(&mut host);
        host.responses
            .extend([open_request(), if before { ended() } else { Response::Ok }]);
        if !before {
            host.responses.push_back(ended());
        }
        module.tick().unwrap();
        assert!(host.responses.is_empty());
        let status = module
            .dispatch("alice", SERVICE, json!({"action": "status"}))
            .unwrap();
        assert_eq!(status.payload["streams"], json!([]));
        if let Some(reply) = host.completed.first() {
            assert!(UdpSocket::bind(reply["local"].as_str().unwrap()).is_ok());
        } else {
            assert!(before);
        }
    }
}

#[test]
fn lost_replay_completion_preserves_the_original_owned_stream() {
    let mut host = Host {
        responses: VecDeque::new(),
        completed: Vec::new(),
    };
    let mut module = start(&mut host);
    host.responses
        .extend([open_request(), Response::Ok, Response::Ok]);
    module.tick().unwrap();
    let first = host.completed[0].clone();
    host.responses
        .extend([open_request(), Response::Ok, ended()]);
    module.tick().unwrap();
    let status = module
        .dispatch("alice", SERVICE, json!({"action": "status"}))
        .unwrap();
    assert_eq!(status.payload["streams"][0]["stream"], first["stream"]);
    assert!(UdpSocket::bind(first["local"].as_str().unwrap()).is_err());
    drop(module);
    assert!(UdpSocket::bind(first["local"].as_str().unwrap()).is_ok());
}

#[test]
fn poisoned_controller_teardown_closes_sockets_even_with_retained_binding_state() {
    let mut host = Host {
        responses: VecDeque::new(),
        completed: Vec::new(),
    };
    let mut module = start(&mut host);
    host.responses
        .extend([open_request(), Response::Ok, Response::Ok]);
    module.tick().unwrap();
    let local = host.completed[0]["local"].as_str().unwrap().to_owned();
    let retained = module.controller.clone();
    let _ = std::panic::catch_unwind(|| {
        let _lock = retained.lock().unwrap();
        panic!("simulated controller failure");
    });
    assert!(
        module
            .dispatch("alice", SERVICE, json!({"action": "status"}))
            .is_err()
    );
    drop(module);
    assert!(UdpSocket::bind(local).is_ok());
    let mut controller = retained.lock().err().expect("poisoned lock").into_inner();
    assert_eq!(
        controller
            .handle("alice", Operation::Status { stream: None })
            .unwrap()
            .payload["streams"],
        json!([])
    );
}
