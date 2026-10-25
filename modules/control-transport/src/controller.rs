use crate::{model::*, stream::Stream};
use amaterasu_media::{ControlMessage, ControlMessageSink, MEDIA_CLOSED};
use amaterasu_module_sdk::abi::Status;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

pub struct Reply {
    pub payload: Value,
    pub created: Option<u64>,
}

struct OperationRecord {
    stream: u64,
    specification: Open,
}

pub struct Controller {
    settings: Settings,
    streams: BTreeMap<u64, Stream>,
    operations: BTreeMap<(String, String), OperationRecord>,
    issued_ids: BTreeSet<u64>,
    used_keys: Vec<[u8; 16]>,
    epoch: Instant,
}

impl Controller {
    pub fn new(settings: Settings) -> Self {
        Self {
            settings,
            streams: BTreeMap::new(),
            operations: BTreeMap::new(),
            issued_ids: BTreeSet::new(),
            used_keys: Vec::new(),
            epoch: Instant::now(),
        }
    }

    pub fn handle(&mut self, owner: &str, operation: Operation) -> ControlResult<Reply> {
        let (payload, created) = match operation {
            Operation::Open(request) => return self.open(owner, request),
            Operation::Close { stream } => (self.close(owner, stream)?, None),
            Operation::Lookup { operation_id } => {
                if !valid_name(&operation_id) {
                    return Err("invalid_operation_id");
                }
                let record = self
                    .operations
                    .get(&(owner.into(), operation_id))
                    .ok_or("stream_not_found")?;
                (
                    self.owned(owner, record.stream)?.metadata(record.stream),
                    None,
                )
            }
            Operation::Status { stream } => (self.status(owner, stream), None),
        };
        Ok(Reply { payload, created })
    }

    fn open(&mut self, owner: &str, request: Open) -> ControlResult<Reply> {
        if !self.settings.enabled {
            return Err("disabled");
        }
        if !self
            .settings
            .allowed_principals
            .iter()
            .any(|allowed| allowed == owner)
        {
            return Err("forbidden");
        }
        let key = request.validate(self.settings.allow_remote)?;
        if let Some(operation) = &request.operation_id {
            if let Some(record) = self.operations.get(&(owner.into(), operation.clone())) {
                if record.specification != request {
                    return Err("operation_conflict");
                }
                let stream = self.streams.get(&record.stream).ok_or("stream_closed")?;
                return Ok(Reply {
                    payload: stream.metadata(record.stream),
                    created: None,
                });
            }
            if self.operations.len() >= 128 {
                return Err("operation_limit");
            }
        }
        self.admit(owner, &key)?;
        let id = self.new_id()?;
        let stream = Stream::open(owner, &request, &key, self.now())?;
        let payload = stream.metadata(id);
        self.streams.insert(id, stream);
        self.issued_ids.insert(id);
        self.used_keys.push(key);
        if let Some(operation) = &request.operation_id {
            self.operations.insert(
                (owner.into(), operation.clone()),
                OperationRecord {
                    stream: id,
                    specification: request,
                },
            );
        }
        Ok(Reply {
            payload,
            created: Some(id),
        })
    }

    fn admit(&self, owner: &str, key: &[u8; 16]) -> ControlResult<()> {
        if self.streams.len() >= 4
            || self
                .streams
                .values()
                .filter(|stream| stream.owner == owner)
                .count()
                >= 2
        {
            return Err("stream_limit");
        }
        if self.issued_ids.len() >= 1024 {
            return Err("stream_history_limit");
        }
        if self.used_keys.contains(key) {
            return Err("key_reuse_forbidden");
        }
        if self.used_keys.len() >= 128 {
            return Err("key_history_limit");
        }
        Ok(())
    }

    fn new_id(&self) -> ControlResult<u64> {
        for _ in 0..16 {
            let mut bytes = [0; 8];
            getrandom::fill(&mut bytes).map_err(|_| "randomness_unavailable")?;
            let id = u64::from_ne_bytes(bytes);
            if id != 0 && !self.issued_ids.contains(&id) {
                return Ok(id);
            }
        }
        Err("randomness_unavailable")
    }

    fn owned(&self, owner: &str, id: u64) -> ControlResult<&Stream> {
        self.streams
            .get(&id)
            .filter(|stream| stream.owner == owner)
            .ok_or("stream_not_found")
    }

    fn owned_mut(&mut self, owner: &str, id: u64) -> Option<&mut Stream> {
        self.streams
            .get_mut(&id)
            .filter(|stream| stream.owner == owner)
    }

    pub fn close(&mut self, owner: &str, id: u64) -> ControlResult<Value> {
        self.owned(owner, id)?;
        self.streams.remove(&id);
        Ok(json!({"ok": true}))
    }

    fn status(&self, owner: &str, requested: Option<u64>) -> Value {
        let streams: Vec<_> = self
            .streams
            .iter()
            .filter(|(id, stream)| {
                stream.owner == owner && requested.is_none_or(|requested| requested == **id)
            })
            .map(|(id, stream)| stream.metadata(*id))
            .collect();
        json!({"ok": true, "enabled": self.settings.enabled, "streams": streams})
    }

    fn now(&self) -> u64 {
        self.epoch.elapsed().as_millis().min(u64::MAX.into()) as u64
    }

    pub fn tick(&mut self) {
        let now = self.now();
        for stream in self.streams.values_mut() {
            stream.tick(now);
        }
    }

    pub fn shutdown(&mut self) {
        self.settings.enabled = false;
        self.streams.clear();
    }

    /// # Safety
    /// Message header and its immutable initialized allocation remain live until return.
    pub unsafe fn send(&mut self, owner: &str, id: u64, message: &ControlMessage) -> Status {
        let now = self.now();
        match self.owned_mut(owner, id) {
            // SAFETY: allocation obligations are forwarded to the owned stream.
            Some(stream) => unsafe { stream.send(message, now) },
            None => MEDIA_CLOSED,
        }
    }

    /// # Safety
    /// Sink context and function remain live for the synchronous callback.
    pub unsafe fn receive(&mut self, owner: &str, id: u64, sink: ControlMessageSink) -> Status {
        match self.owned_mut(owner, id) {
            // SAFETY: sink is borrowed only for this synchronous call.
            Some(stream) => unsafe { stream.receive(sink) },
            None => MEDIA_CLOSED,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
