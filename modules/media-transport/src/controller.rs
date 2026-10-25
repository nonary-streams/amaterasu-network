use crate::{model::*, stream::Stream};
use amaterasu_media::{EncodedAudioPacket, EncodedPacket, MEDIA_CLOSED};
use amaterasu_module_sdk::abi::Status;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub struct ControlReply {
    pub payload: Value,
    pub created: Option<u64>,
}
struct Record {
    stream: u64,
    request: Open,
}

pub struct Controller {
    settings: Settings,
    streams: BTreeMap<u64, Stream>,
    operations: BTreeMap<(String, String), Record>,
    issued: BTreeSet<u64>,
    used_keys: Vec<[u8; 16]>,
    used_discoveries: Vec<DiscoveryTokens>,
    tick_cursor: usize,
}

impl Controller {
    pub fn new(settings: Settings) -> Self {
        Self {
            settings,
            streams: BTreeMap::new(),
            operations: BTreeMap::new(),
            issued: BTreeSet::new(),
            used_keys: Vec::new(),
            used_discoveries: Vec::new(),
            tick_cursor: 0,
        }
    }

    pub fn handle(&mut self, owner: &str, operation: Operation) -> TransportResult<ControlReply> {
        let (payload, created) = match operation {
            Operation::Open(request) => self.open(owner, request)?,
            Operation::ConfigureVideoFormat {
                stream,
                video_stream_format,
            } => (
                self.configure_video_format(owner, stream, video_stream_format)?,
                None,
            ),
            Operation::Lookup { operation_id } => {
                validate_operation(&operation_id)?;
                let record = self
                    .operations
                    .get(&(owner.into(), operation_id))
                    .ok_or("stream_not_found")?;
                (
                    metadata(record.stream, self.owned(owner, record.stream)?),
                    None,
                )
            }
            Operation::Close { stream } => (self.close(owner, stream)?, None),
            Operation::Status { stream } => (self.status(owner, stream), None),
        };
        Ok(ControlReply { payload, created })
    }

    fn open(&mut self, owner: &str, request: Open) -> TransportResult<(Value, Option<u64>)> {
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
        request.validate(self.settings.allow_remote)?;
        if let Some(operation) = &request.operation_id {
            if let Some(record) = self.operations.get(&(owner.into(), operation.clone())) {
                if record.request != request {
                    return Err("operation_conflict");
                }
                let stream = self.streams.get(&record.stream).ok_or("stream_closed")?;
                return Ok((metadata(record.stream, stream), None));
            }
            if self.operations.len() >= 128 {
                return Err("operation_limit");
            }
        }
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
        if self.issued.len() >= 1024 {
            return Err("stream_history_limit");
        }
        let key = request
            .encryption
            .as_ref()
            .map(Encryption::key)
            .transpose()?;
        let discovery = request
            .discovery
            .as_ref()
            .map(|discovery| discovery.tokens())
            .transpose()?;
        if let Some(key) = &key {
            if self.used_keys.contains(key) {
                return Err("key_reuse_forbidden");
            }
            if self.used_keys.len() >= 128 {
                return Err("key_history_limit");
            }
        }
        if let Some(tokens) = &discovery {
            if self.used_discoveries.iter().any(|used| {
                [tokens.video, tokens.audio]
                    .iter()
                    .any(|token| *token == used.video || *token == used.audio)
            }) {
                return Err("ping_payload_reuse_forbidden");
            }
            if self.used_discoveries.len() >= 128 {
                return Err("ping_payload_history_limit");
            }
        }
        let id = self.random_id()?;
        let stream = Stream::open(owner, &request)?;
        let reply = metadata(id, &stream);
        if let Some(key) = key {
            self.used_keys.push(key);
        }
        if let Some(tokens) = discovery {
            self.used_discoveries.push(tokens);
        }
        self.issued.insert(id);
        self.streams.insert(id, stream);
        if let Some(operation) = &request.operation_id {
            self.operations.insert(
                (owner.into(), operation.clone()),
                Record {
                    stream: id,
                    request,
                },
            );
        }
        Ok((reply, Some(id)))
    }

    fn random_id(&self) -> TransportResult<u64> {
        for _ in 0..16 {
            let mut bytes = [0u8; 8];
            getrandom::fill(&mut bytes).map_err(|_| "randomness_unavailable")?;
            let id = u64::from_ne_bytes(bytes);
            if id != 0 && !self.issued.contains(&id) {
                return Ok(id);
            }
        }
        Err("randomness_unavailable")
    }

    fn owned(&self, owner: &str, id: u64) -> TransportResult<&Stream> {
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

    pub fn close(&mut self, owner: &str, id: u64) -> TransportResult<Value> {
        self.owned(owner, id)?;
        self.streams.remove(&id);
        Ok(json!({"ok":true}))
    }

    fn status(&self, owner: &str, requested: Option<u64>) -> Value {
        let streams: Vec<_> = self
            .streams
            .iter()
            .filter(|(id, stream)| {
                stream.owner == owner && requested.is_none_or(|requested| requested == **id)
            })
            .map(|(id, stream)| status(*id, stream))
            .collect();
        json!({"ok":true,"enabled":self.settings.enabled,"streams":streams})
    }

    pub fn tick(&mut self) {
        let stream_ids: Vec<_> = self.streams.keys().copied().collect();
        let stream_count = stream_ids.len();
        if stream_count == 0 {
            return;
        }
        let start = self.tick_cursor % stream_count;
        self.tick_cursor = (start + 1) % stream_count;
        let base_budget = SENDS_PER_TICK / stream_count;
        let extra_sends = SENDS_PER_TICK % stream_count;
        // Rotate the remainder so stream order cannot claim the same extra
        // allowance on every tick. The aggregate never exceeds 64 sends.
        for offset in 0..stream_count {
            let index = (start + offset) % stream_count;
            let budget = base_budget + usize::from(offset < extra_sends);
            if let Some(stream) = self.streams.get_mut(&stream_ids[index]) {
                stream.delivery.tick_with_limit(budget);
            }
        }
    }

    pub fn shutdown(&mut self) {
        self.settings.enabled = false;
        self.streams.clear();
    }

    /// # Safety
    /// Caller keeps the packet and initialized immutable bytes alive through submit.
    pub unsafe fn submit_video(&mut self, owner: &str, id: u64, packet: &EncodedPacket) -> Status {
        match self.owned_mut(owner, id) {
            Some(stream) => unsafe { stream.submit_video(packet) },
            None => MEDIA_CLOSED,
        }
    }

    /// # Safety
    /// Caller keeps the packet and initialized immutable bytes alive through submit.
    pub unsafe fn submit_audio(
        &mut self,
        owner: &str,
        id: u64,
        packet: &EncodedAudioPacket,
    ) -> Status {
        match self.owned_mut(owner, id) {
            Some(stream) => unsafe { stream.submit_audio(packet) },
            None => MEDIA_CLOSED,
        }
    }

    pub fn drain(&mut self, owner: &str, id: u64) -> Status {
        self.owned_mut(owner, id)
            .map_or(MEDIA_CLOSED, Stream::drain)
    }

    fn configure_video_format(
        &mut self,
        owner: &str,
        id: u64,
        format: amaterasu_module_sdk::VideoStreamFormat,
    ) -> TransportResult<Value> {
        let stream = self.owned_mut(owner, id).ok_or("stream_not_found")?;
        stream.configure_video_format(format)?;
        Ok(json!({"ok":true,"stream":id,"video_stream_format":format}))
    }
}

fn metadata(id: u64, stream: &Stream) -> Value {
    let (video_encrypted, audio_encrypted) = stream.encryption();
    json!({
        "ok":true,
        "stream":id,
        "peer_ip":stream.peer,
        "video_port":stream.peer_port(crate::datagrams::Medium::Video),
        "audio_port":stream.peer_port(crate::datagrams::Medium::Audio),
        "peer_discovery":stream.peer_discovery(),
        "ready":stream.ready(),
        "video_local":stream.video_local,
        "audio_local":stream.audio_local,
        "video":stream.video_settings,
        "video_codec":stream.video_codec(),
        "video_batch_size_fallback":stream.video_batch_size_fallback,
        "audio":stream.audio_settings,
        "stream_audio":stream.stream_audio,
        "ping_timeout_ms":stream.ping_timeout_ms,
        "video_encrypted":video_encrypted,
        "audio_encrypted":audio_encrypted,
        "permit_legacy_audio_iv_wrap":stream.permit_legacy_audio_iv_wrap
    })
}

fn status(id: u64, stream: &Stream) -> Value {
    let mut reply = metadata(id, stream);
    let object = reply.as_object_mut().expect("metadata object");
    object.remove("ok");
    object.insert("state".into(), json!(stream.state()));
    object.insert(
        "audio_iv_reuse_started".into(),
        json!(stream.audio_iv_reuse_started()),
    );
    object.insert("failure".into(), json!(stream.delivery.failure));
    object.insert("queued_datagrams".into(), json!(stream.delivery.queued()));
    object.insert("queued_bytes".into(), json!(stream.delivery.queued_bytes()));
    object.insert(
        "sent_datagrams".into(),
        json!(stream.delivery.sent_datagrams),
    );
    object.insert(
        "discarded_datagrams".into(),
        json!(stream.delivery.discarded_datagrams),
    );
    object.insert(
        "discarded_audio_fec_shards".into(),
        json!(stream.discarded_audio_fec_shards),
    );
    reply
}

#[cfg(test)]
mod tests;
