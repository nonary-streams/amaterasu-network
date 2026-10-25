//! Applies the durable NVHTTP policy to the audio provider without blocking
//! listener, streaming, or management work on native driver installation.
use amaterasu_module_sdk::{Command, ModuleResult, Response, RuntimeClient};
use serde_json::{Value, json};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const AUDIO_SERVICE: &str = "amaterasu.audio/1";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const RETRY_DELAY: Duration = Duration::from_secs(5);

pub(crate) struct AudioDriverInstallSync {
    sequence: u64,
    last_applied: Option<(u64, bool)>,
    pending: Option<PendingCall>,
    retry_at: Instant,
    last_error: Option<String>,
}

struct PendingCall {
    operation_id: String,
    revision: u64,
    enabled: bool,
    state: CallState,
}

enum CallState {
    Submitting,
    Waiting { child: u64 },
    Releasing { child: u64, applied: bool },
}

impl Default for AudioDriverInstallSync {
    fn default() -> Self {
        Self {
            sequence: 0,
            last_applied: None,
            pending: None,
            retry_at: Instant::now(),
            last_error: None,
        }
    }
}

impl AudioDriverInstallSync {
    pub(crate) fn tick(
        &mut self,
        runtime: &RuntimeClient,
        loaded: bool,
        revision: Option<u64>,
        enabled: bool,
    ) -> ModuleResult<()> {
        if let Some(pending) = self.pending.take() {
            self.advance(pending, runtime)?;
            return Ok(());
        }
        let Some(revision) = revision.filter(|_| loaded) else {
            return Ok(());
        };
        if self.last_applied == Some((revision, enabled)) || Instant::now() < self.retry_at {
            return Ok(());
        }
        self.sequence = self.sequence.saturating_add(1);
        let epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        self.pending = Some(PendingCall {
            operation_id: format!("nvhttp.steam-audio-install.{epoch}.{}", self.sequence),
            revision,
            enabled,
            state: CallState::Submitting,
        });
        let pending = self.pending.take().expect("just created audio update");
        self.advance(pending, runtime)
    }

    fn advance(&mut self, mut pending: PendingCall, runtime: &RuntimeClient) -> ModuleResult<()> {
        match &mut pending.state {
            CallState::Submitting => match runtime.send(Command::Request {
                service: AUDIO_SERVICE.into(),
                payload: json!({
                    "action":"configure_steam_driver_install",
                    "enabled":pending.enabled,
                    "revision":pending.revision,
                }),
                timeout_ms: REQUEST_TIMEOUT.as_millis() as u64,
                operation_id: pending.operation_id.clone(),
                parent: None,
            }) {
                Ok(Response::Accepted { id }) => {
                    pending.state = CallState::Waiting { child: id };
                }
                Ok(Response::Error { code, message }) => {
                    self.retry(&code, &message);
                    return Ok(());
                }
                Ok(response) => {
                    self.pending = Some(pending);
                    self.last_error = Some(format!(
                        "unexpected audio configuration response: {response:?}"
                    ));
                    return Ok(());
                }
                Err(error) => {
                    self.pending = Some(pending);
                    self.last_error = Some(error);
                    return Ok(());
                }
            },
            CallState::Waiting { child } => match runtime
                .send(Command::TakeResult { request: *child })
            {
                Ok(Response::Pending) => {
                    self.pending = Some(pending);
                    return Ok(());
                }
                Ok(Response::Result { payload }) => {
                    let applied = payload.get("ok").and_then(Value::as_bool) == Some(true);
                    if applied {
                        self.last_applied = Some((pending.revision, pending.enabled));
                        self.last_error = None;
                    } else {
                        self.last_error = Some(format!("audio configuration rejected: {payload}"));
                    }
                    pending.state = CallState::Releasing {
                        child: *child,
                        applied,
                    };
                }
                Ok(Response::Error { code, message }) if code == "not_found" => {
                    self.retry(&code, &message);
                    return Ok(());
                }
                Ok(Response::Error { code, message }) => {
                    pending.state = CallState::Releasing {
                        child: *child,
                        applied: false,
                    };
                    self.last_error =
                        Some(format!("audio configuration failed: {code}: {message}"));
                }
                Ok(response) => {
                    self.pending = Some(pending);
                    self.last_error = Some(format!(
                        "unexpected audio configuration result: {response:?}"
                    ));
                    return Ok(());
                }
                Err(error) => {
                    self.pending = Some(pending);
                    self.last_error = Some(error);
                    return Ok(());
                }
            },
            CallState::Releasing { .. } => {}
        }

        let CallState::Releasing { child, applied } = pending.state else {
            self.pending = Some(pending);
            return Ok(());
        };
        match runtime.send(Command::ReleaseResult { request: child }) {
            Ok(Response::Ok) => {
                if !applied {
                    self.retry_at = Instant::now() + RETRY_DELAY;
                }
            }
            Ok(Response::Error { code, .. }) if code == "not_found" => {
                if !applied {
                    self.retry_at = Instant::now() + RETRY_DELAY;
                }
            }
            Ok(response) => {
                pending.state = CallState::Releasing { child, applied };
                self.pending = Some(pending);
                self.last_error = Some(format!("audio result release returned {response:?}"));
            }
            Err(error) => {
                pending.state = CallState::Releasing { child, applied };
                self.pending = Some(pending);
                self.last_error = Some(error);
            }
        }
        Ok(())
    }

    fn retry(&mut self, code: &str, message: &str) {
        self.last_error = Some(format!("{code}: {message}"));
        self.retry_at = Instant::now() + RETRY_DELAY;
    }

    #[cfg(test)]
    fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use amaterasu_module_sdk::abi::{self, AbiHeader, BorrowedBytes, HostApi, ReplySink};
    use std::{
        ffi::c_void,
        sync::{Arc, Mutex},
    };

    #[derive(Default)]
    struct State {
        commands: Vec<Command>,
        response: Option<Response>,
    }

    unsafe extern "C" fn invoke(
        context: *mut c_void,
        input: BorrowedBytes,
        reply: ReplySink,
    ) -> abi::Status {
        // SAFETY: the RuntimeClient retains an Arc owner in each test.
        let state = unsafe { &*context.cast::<Mutex<State>>() };
        let Ok(bytes) = (unsafe { input.read() }) else {
            return abi::STATUS_INVALID_ARGUMENT;
        };
        let Ok(command) = serde_json::from_slice::<Command>(bytes) else {
            return abi::STATUS_INVALID_ARGUMENT;
        };
        let mut state = state.lock().unwrap();
        state.commands.push(command.clone());
        let response = state.response.clone().unwrap_or_else(|| match command {
            Command::Request { .. } => Response::Accepted { id: 9 },
            Command::TakeResult { .. } => Response::Result {
                payload: json!({"ok":true,"state":"checking"}),
            },
            Command::ReleaseResult { .. } => Response::Ok,
            unexpected => panic!("unexpected audio install sync command: {unexpected:?}"),
        });
        // SAFETY: the synchronous sink copies response bytes before returning.
        unsafe { reply.send(&serde_json::to_vec(&response).unwrap()) };
        abi::STATUS_OK
    }

    fn runtime(state: Arc<Mutex<State>>) -> RuntimeClient {
        let api = HostApi {
            header: AbiHeader::of::<HostApi>(),
            context: Arc::as_ptr(&state).cast_mut().cast(),
            invoke,
        };
        // SAFETY: the caller retains the Arc containing the callback context.
        unsafe { RuntimeClient::from_endpoint(api) }
    }

    #[test]
    fn missing_product_configuration_does_not_send_audio_changes() {
        let state = Arc::new(Mutex::new(State::default()));
        let runtime = runtime(state.clone());
        let mut sync = AudioDriverInstallSync::default();

        sync.tick(&runtime, false, None, true).unwrap();

        assert!(state.lock().unwrap().commands.is_empty());
    }

    #[test]
    fn loaded_default_true_policy_is_sent_and_settled() {
        let state = Arc::new(Mutex::new(State::default()));
        let runtime = runtime(state.clone());
        let mut sync = AudioDriverInstallSync::default();

        sync.tick(&runtime, true, Some(4), true).unwrap();
        sync.tick(&runtime, true, Some(4), true).unwrap();
        sync.tick(&runtime, true, Some(4), true).unwrap();

        let state = state.lock().unwrap();
        assert!(state.commands.iter().any(|command| matches!(command,
            Command::Request { service, payload, .. }
                if service == AUDIO_SERVICE
                    && payload["action"] == "configure_steam_driver_install"
                    && payload["enabled"] == true
                    && payload["revision"] == 4)));
        assert!(
            state
                .commands
                .iter()
                .any(|command| matches!(command, Command::ReleaseResult { request: 9 }))
        );
        assert_eq!(sync.last_error(), None);
    }

    #[test]
    fn audio_provider_rejection_is_retried_without_failing_nvhttp() {
        let state = Arc::new(Mutex::new(State {
            response: Some(Response::error("unavailable", "provider starting")),
            ..State::default()
        }));
        let runtime = runtime(state.clone());
        let mut sync = AudioDriverInstallSync::default();

        sync.tick(&runtime, true, Some(4), true).unwrap();

        assert_eq!(sync.last_error(), Some("unavailable: provider starting"));
    }
}
