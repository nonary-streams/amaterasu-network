//! Managed encrypted RTSP endpoint. Network data never supplies broker authority.
#![recursion_limit = "256"]

mod controller;
mod model;
mod rpc;
mod transport;

use amaterasu_module_sdk::{Command, ManagedModule, ModuleResult, Response, RuntimeClient};
use controller::Controller;
use model::Settings;
use std::time::Instant;

const SERVICE: &str = "amaterasu.rtsp/1";
struct RtspModule {
    runtime: RuntimeClient,
    controller: Controller,
    started: Instant,
}

impl ManagedModule for RtspModule {
    fn start(runtime: RuntimeClient) -> ModuleResult<Self> {
        let Response::Result { payload } = runtime.send(Command::GetSettings {})? else {
            return Err("RTSP settings unavailable".into());
        };
        let settings: Settings =
            serde_json::from_value(payload).map_err(|_| "invalid RTSP settings")?;
        let controller = Controller::new(settings)?;
        runtime.require_success(Command::Register {
            service: SERVICE.into(),
        })?;
        Ok(Self {
            runtime,
            controller,
            started: Instant::now(),
        })
    }

    fn tick(&mut self) -> ModuleResult<()> {
        let now = self.started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        self.controller.tick(&self.runtime, now)
    }
}

impl Drop for RtspModule {
    fn drop(&mut self) {
        self.controller.shutdown(&self.runtime);
    }
}

amaterasu_module_sdk::export_module!(RtspModule);
