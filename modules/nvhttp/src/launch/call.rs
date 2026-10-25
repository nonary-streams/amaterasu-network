use super::Send;
use amaterasu_module_sdk::{Command, Response};
use serde_json::Value;

pub enum Outcome {
    Waiting,
    Result(Value),
    Rejected,
    Settled,
    Uncertain,
}

pub struct Call {
    command: Command,
    request: Option<u64>,
    cancelling: bool,
    failures: u8,
}

impl Call {
    pub fn new(service: &str, payload: Value, operation_id: String, timeout_ms: u64) -> Self {
        Self {
            command: Command::Request {
                service: service.into(),
                payload,
                timeout_ms,
                operation_id,
                parent: None,
            },
            request: None,
            cancelling: false,
            failures: 0,
        }
    }

    pub fn cancel(&mut self) {
        if !self.cancelling {
            self.cancelling = true;
            self.failures = 0;
        }
    }

    pub fn retry_settlement(&mut self) {
        self.cancelling = true;
        self.failures = 0;
    }

    pub fn poll(&mut self, send: &mut Send<'_>) -> Outcome {
        if self.failures >= 3 {
            return Outcome::Uncertain;
        }
        let Some(request) = self.request else {
            return match send(self.command.clone()) {
                Ok(Response::Accepted { id }) => {
                    self.request = Some(id);
                    self.failures = 0;
                    Outcome::Waiting
                }
                Ok(Response::Error { .. }) => Outcome::Rejected,
                _ => {
                    // Admission may have committed. Resubmit the exact command
                    // only to recover its broker request ID, then settle it.
                    self.cancelling = true;
                    self.failures += 1;
                    Outcome::Waiting
                }
            };
        };
        if self.cancelling {
            if settle(request, send) {
                return Outcome::Settled;
            }
            self.failures += 1;
            return Outcome::Waiting;
        }
        match send(Command::TakeResult { request }) {
            Ok(Response::Pending) => Outcome::Waiting,
            Ok(Response::Result { payload }) => Outcome::Result(payload),
            _ => {
                self.cancelling = true;
                Outcome::Waiting
            }
        }
    }

    pub fn shutdown(&mut self, send: &mut Send<'_>) {
        self.cancel();
        for _ in 0..4 {
            if !matches!(self.poll(send), Outcome::Waiting) {
                break;
            }
        }
    }
}

fn settle(request: u64, send: &mut Send<'_>) -> bool {
    for command in [
        Command::Cancel { request },
        Command::ReleaseResult { request },
    ] {
        match send(command) {
            Ok(Response::Ok) => {}
            Ok(Response::Error { code, .. }) if code == "not_found" => {}
            _ => return false,
        }
    }
    true
}
