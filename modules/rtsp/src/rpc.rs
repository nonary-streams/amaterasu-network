//! Broker calls retain exact admission identity until cancellation is confirmed.
use amaterasu_module_sdk::{Command, Response, RuntimeClient};
use serde_json::Value;

pub enum Outcome {
    Waiting,
    Result(Value),
    SettledFailure,
    Uncertain,
}

pub struct Call {
    command: Command,
    request: Option<u64>,
    cancelling: bool,
    failures: u8,
}

impl Call {
    pub fn new(payload: Value, operation: String, parent: Option<u64>) -> Self {
        Self::for_service("amaterasu.stream-session/1", payload, operation, parent)
    }

    pub fn for_service(
        service: &str,
        payload: Value,
        operation: String,
        parent: Option<u64>,
    ) -> Self {
        Self {
            command: Command::Request {
                service: service.into(),
                payload,
                operation_id: operation,
                parent,
                timeout_ms: 15_000,
            },
            request: None,
            cancelling: false,
            failures: 0,
        }
    }

    pub fn cancel(&mut self) {
        self.cancelling = true;
        self.failures = 0;
    }

    pub fn retry_settlement(&mut self) {
        self.cancelling = true;
        self.failures = 0;
    }

    pub fn poll(&mut self, runtime: &RuntimeClient) -> Outcome {
        if self.failures >= 3 {
            return Outcome::Uncertain;
        }
        let Some(request) = self.request else {
            return match runtime.send_ephemeral(self.command.clone()) {
                Ok(Response::Accepted { id }) => {
                    self.request = Some(id);
                    self.failures = 0;
                    Outcome::Waiting
                }
                Ok(Response::Error { .. }) => Outcome::SettledFailure,
                _ => {
                    // The command may have reached the broker. Resubmit this exact
                    // operation only to recover its request ID, then settle it.
                    self.cancelling = true;
                    self.failures += 1;
                    Outcome::Waiting
                }
            };
        };
        if self.cancelling {
            if settle(runtime, request) {
                return Outcome::SettledFailure;
            }
            self.failures += 1;
            return Outcome::Waiting;
        }
        match runtime.send_ephemeral(Command::TakeResult { request }) {
            Ok(Response::Pending) => Outcome::Waiting,
            Ok(Response::Result { payload }) => Outcome::Result(payload),
            _ => {
                self.cancelling = true;
                Outcome::Waiting
            }
        }
    }

    pub fn shutdown(&mut self, runtime: &RuntimeClient) {
        self.cancel();
        for _ in 0..4 {
            if !matches!(self.poll(runtime), Outcome::Waiting) {
                break;
            }
        }
    }
}

fn settle(runtime: &RuntimeClient, request: u64) -> bool {
    for command in [
        Command::Cancel { request },
        Command::ReleaseResult { request },
    ] {
        match runtime.send_ephemeral(command) {
            Ok(Response::Ok) => {}
            Ok(Response::Error { code, .. }) if code == "not_found" => {}
            _ => return false,
        }
    }
    true
}

pub fn active(runtime: &RuntimeClient, request: u64) -> bool {
    matches!(
        runtime.send_ephemeral(Command::CheckRequest { request }),
        Ok(Response::Ok)
    )
}
pub fn complete(runtime: &RuntimeClient, request: u64, payload: Value) -> bool {
    matches!(
        runtime.send_ephemeral(Command::Complete { request, payload }),
        Ok(Response::Ok)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use amaterasu_module_sdk::abi::{self, AbiHeader, BorrowedBytes, HostApi, ReplySink};
    use serde_json::json;
    use std::ffi::c_void;

    #[derive(Default)]
    struct Endpoint {
        commands: Vec<Command>,
        lose_first_admission: bool,
        fail_settlement: bool,
    }

    impl Endpoint {
        fn dispatch(&self, command: &Command) -> Response {
            match command {
                Command::Request { .. } => Response::Accepted { id: 41 },
                Command::Cancel { .. } | Command::ReleaseResult { .. } if self.fail_settlement => {
                    Response::error("unavailable", "deliberate settlement failure")
                }
                Command::Cancel { .. } | Command::ReleaseResult { .. } => Response::Ok,
                _ => Response::error("unexpected", "unexpected test command"),
            }
        }
    }

    unsafe extern "C" fn invoke(
        context: *mut c_void,
        input: BorrowedBytes,
        reply: ReplySink,
    ) -> abi::Status {
        // SAFETY: each test keeps Endpoint exclusively alive for the client lifetime.
        let endpoint = unsafe { &mut *context.cast::<Endpoint>() };
        let Ok(bytes) = (unsafe { input.read() }) else {
            return abi::STATUS_INVALID_ARGUMENT;
        };
        let Ok(command) = serde_json::from_slice::<Command>(bytes) else {
            return abi::STATUS_INVALID_ARGUMENT;
        };
        endpoint.commands.push(command.clone());
        if endpoint.lose_first_admission
            && endpoint.commands.len() == 1
            && matches!(command, Command::Request { .. })
        {
            return abi::STATUS_INTERNAL_ERROR;
        }
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
        // SAFETY: callers keep endpoint alive and use the client synchronously.
        unsafe { RuntimeClient::from_endpoint(api) }
    }

    #[test]
    fn lost_admission_recovers_the_same_operation_before_settlement() {
        let mut endpoint = Endpoint {
            lose_first_admission: true,
            ..Endpoint::default()
        };
        let runtime = client(&mut endpoint);
        let payload = json!({"action":"prepare","operation_id":"allocation"});
        let mut call = Call::new(payload.clone(), "broker-operation".into(), Some(9));

        assert!(matches!(call.poll(&runtime), Outcome::Waiting));
        assert!(matches!(call.poll(&runtime), Outcome::Waiting));
        assert!(matches!(call.poll(&runtime), Outcome::SettledFailure));

        let requests: Vec<_> = endpoint
            .commands
            .iter()
            .filter_map(|command| match command {
                Command::Request {
                    payload,
                    operation_id,
                    parent,
                    ..
                } => Some((payload, operation_id, parent)),
                _ => None,
            })
            .collect();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0], requests[1]);
        assert_eq!(requests[0].0, &payload);
        assert_eq!(requests[0].1, "broker-operation");
        assert_eq!(*requests[0].2, Some(9));
        assert!(matches!(
            endpoint.commands[2],
            Command::Cancel { request: 41 }
        ));
        assert!(matches!(
            endpoint.commands[3],
            Command::ReleaseResult { request: 41 }
        ));
    }

    #[test]
    fn unconfirmed_settlement_is_retained_and_can_be_retried() {
        let mut endpoint = Endpoint {
            fail_settlement: true,
            ..Endpoint::default()
        };
        let runtime = client(&mut endpoint);
        let mut call = Call::new(json!({"action":"stop"}), "stop-operation".into(), None);
        assert!(matches!(call.poll(&runtime), Outcome::Waiting));
        call.cancel();
        for _ in 0..3 {
            assert!(matches!(call.poll(&runtime), Outcome::Waiting));
        }
        assert!(matches!(call.poll(&runtime), Outcome::Uncertain));

        endpoint.fail_settlement = false;
        call.retry_settlement();
        assert!(matches!(call.poll(&runtime), Outcome::SettledFailure));
        assert_eq!(
            endpoint
                .commands
                .iter()
                .filter(|command| matches!(command, Command::Request { .. }))
                .count(),
            1
        );
    }
}
