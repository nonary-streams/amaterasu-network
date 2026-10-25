use super::*;
use amaterasu_module_sdk::abi::{self, AbiHeader, BorrowedBytes, HostApi, ReplySink};
use std::{
    ffi::c_void,
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct Endpoint {
    commands: Vec<Command>,
    result: Value,
    pending_results: usize,
}

unsafe extern "C" fn invoke(
    context: *mut c_void,
    input: BorrowedBytes,
    reply: ReplySink,
) -> abi::Status {
    // SAFETY: each test retains the Arc that owns this mutex for the runtime lifetime.
    let state = unsafe { &*context.cast::<Mutex<Endpoint>>() };
    // SAFETY: the runtime passes a live borrowed command for this call.
    let Ok(bytes) = (unsafe { input.read() }) else {
        return abi::STATUS_INVALID_ARGUMENT;
    };
    let Ok(command) = serde_json::from_slice::<Command>(bytes) else {
        return abi::STATUS_INVALID_ARGUMENT;
    };
    let mut state = state.lock().unwrap();
    state.commands.push(command.clone());
    let response = match command {
        Command::Request { .. } => Response::Accepted { id: 9 },
        Command::TakeResult { .. } if state.pending_results > 0 => {
            state.pending_results -= 1;
            Response::Pending
        }
        Command::TakeResult { .. } => Response::Result {
            payload: state.result.clone(),
        },
        Command::ReleaseResult { .. } => Response::Ok,
        unexpected => panic!("unexpected encoder refresh command: {unexpected:?}"),
    };
    let output = serde_json::to_vec(&response).expect("test response");
    // SAFETY: the synchronous reply sink copies output bytes before returning.
    unsafe { reply.send(&output) };
    abi::STATUS_OK
}

fn runtime(state: &Arc<Mutex<Endpoint>>) -> RuntimeClient {
    let api = HostApi {
        header: AbiHeader::of::<HostApi>(),
        context: Arc::as_ptr(state).cast_mut().cast(),
        invoke,
    };
    // SAFETY: the caller retains the Arc containing the callback context.
    unsafe { RuntimeClient::from_endpoint(api) }
}

fn enumerated() -> Value {
    json!({"ok":true,"enabled":true,"encoders":[
        {"identity":{"clsid":"amaterasu.hardware.nvenc-cuda.av1","hardware_url":null,
            "friendly_name":"NVENC AV1"},"name":"NVENC AV1","codec":"av1","hardware":true,
            "vendor_id":4318}
    ]})
}

#[test]
fn startup_enumeration_publishes_one_snapshot_and_then_waits() {
    let state = Arc::new(Mutex::new(Endpoint {
        result: enumerated(),
        pending_results: 1,
        ..Endpoint::default()
    }));
    let runtime = runtime(&state);
    let mut refresh = EncoderRefresh::default();
    refresh.tick(&runtime, false);
    refresh.tick(&runtime, false);
    assert!(refresh.take_update().is_none());
    refresh.tick(&runtime, false);
    let snapshot = refresh.take_update().expect("parsed snapshot");
    assert_eq!(snapshot.advertisement().codec_mode_support, 0x10001);
    assert!(refresh.take_update().is_none());
    // The next refresh is minutes away.
    refresh.tick(&runtime, false);
    let commands = &state.lock().unwrap().commands;
    assert_eq!(commands.len(), 4, "request, pending, result, release");
    assert!(matches!(
        &commands[0],
        Command::Request { service, payload, .. }
            if service == ENCODE_SERVICE && payload == &json!({"action":"enumerate"})
    ));
    assert!(matches!(commands[3], Command::ReleaseResult { request: 9 }));
}

#[test]
fn no_enumeration_starts_while_a_stream_is_active() {
    let state = Arc::new(Mutex::new(Endpoint {
        result: enumerated(),
        ..Endpoint::default()
    }));
    let runtime = runtime(&state);
    let mut refresh = EncoderRefresh::default();
    refresh.tick(&runtime, true);
    assert!(state.lock().unwrap().commands.is_empty());
}

#[test]
fn a_failed_enumeration_publishes_nothing_and_backs_off() {
    let state = Arc::new(Mutex::new(Endpoint {
        result: json!({"ok":false,"code":"encoder_worker_failed"}),
        ..Endpoint::default()
    }));
    let runtime = runtime(&state);
    let mut refresh = EncoderRefresh::default();
    refresh.tick(&runtime, false);
    refresh.tick(&runtime, false);
    assert!(refresh.take_update().is_none());
    assert!(refresh.next_refresh > Instant::now());
    assert_eq!(refresh.retry_delay, INITIAL_RETRY_DELAY * 2);
    refresh.tick(&runtime, false);
    assert_eq!(state.lock().unwrap().commands.len(), 3);
}
