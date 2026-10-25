use super::*;
use amaterasu_module_sdk::abi::*;
use std::{collections::VecDeque, ffi::c_void, net::UdpSocket};

struct Host {
    replies: VecDeque<Response>,
    complete: Option<serde_json::Value>,
}

unsafe extern "C" fn invoke(
    context: *mut c_void,
    input: BorrowedBytes,
    output: ReplySink,
) -> Status {
    // SAFETY: the test endpoint context and message allocations outlive invocation.
    let host = unsafe { &mut *context.cast::<Host>() };
    let command: Command = serde_json::from_slice(unsafe { input.read().unwrap() }).unwrap();
    if let Command::Complete { payload, .. } = command {
        host.complete = Some(payload);
    }
    let response = host.replies.pop_front().expect("unexpected endpoint call");
    unsafe { output.send(&serde_json::to_vec(&response).unwrap()) };
    STATUS_OK
}

#[test]
fn cancelled_open_releases_udp_ports_and_cannot_leave_a_hidden_sender() {
    for before in [true, false] {
        let ended = Response::Error {
            code: "request_ended".into(),
            message: "ended".into(),
        };
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = peer.local_addr().unwrap().port();
        let request = Response::Request {
            id: 1,
            caller: "consumer".into(),
            initiator: "consumer".into(),
            service: SERVICE.into(),
            remaining_ms: 1000,
            payload: json!({"action":"open","peer_ip":"127.0.0.1","video_port":port,"audio_port":port,"audio":{"channels":2,"packet_ms":10,"wire_payload_bytes":4}}),
        };
        let mut host = Host {
            replies: VecDeque::from([
                Response::Result {
                    payload: json!({"enabled":true,"allowed_principals":["consumer"]}),
                },
                Response::Ok,
                Response::Ok,
                request,
                if before { ended.clone() } else { Response::Ok },
            ]),
            complete: None,
        };
        if !before {
            host.replies.push_back(ended);
        }
        let api = HostApi {
            header: AbiHeader::of::<HostApi>(),
            context: (&mut host as *mut Host).cast(),
            invoke,
        };
        // SAFETY: host state outlives module and all runtime endpoint calls.
        let mut module =
            MediaTransportModule::start(unsafe { RuntimeClient::from_endpoint(api) }).unwrap();
        module.tick().unwrap();
        assert!(host.replies.is_empty());
        let status = module
            .controller
            .lock()
            .unwrap()
            .handle("consumer", Operation::Status { stream: None })
            .unwrap()
            .payload;
        assert_eq!(status["streams"], json!([]));
        if let Some(reply) = &host.complete {
            assert!(UdpSocket::bind(reply["video_local"].as_str().unwrap()).is_ok());
            assert!(UdpSocket::bind(reply["audio_local"].as_str().unwrap()).is_ok());
        } else {
            assert!(before);
        }
    }
}
