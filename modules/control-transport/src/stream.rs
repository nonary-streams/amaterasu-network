mod socket;

use crate::model::{ControlResult, Open, validate_ping_timeout_ms};
use amaterasu_gamestream::{
    crypto::{ControlOpener, ControlOrdering, ControlProfile, ControlSealer, Direction},
    enet::peer::{Config, Delivery, Event, Peer, PeerError, State},
};
use amaterasu_media::*;
use amaterasu_module_sdk::abi::{STATUS_INVALID_ARGUMENT, STATUS_OK, Status};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    net::{IpAddr, SocketAddr, UdpSocket},
};

const MAX_MESSAGES: usize = 256;
const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

struct Received {
    kind: u16,
    channel: u8,
    delivery: Delivery,
    sequence: u32,
    bytes: Vec<u8>,
}

pub struct Stream {
    pub owner: String,
    socket: Option<UdpSocket>,
    local: SocketAddr,
    authorized_ip: IpAddr,
    authorized_port: Option<u16>,
    remote: Option<SocketAddr>,
    peer: Peer,
    sealer: ControlSealer,
    opener: ControlOpener,
    pending_datagram: Option<Vec<u8>>,
    incoming: VecDeque<Received>,
    incoming_bytes: usize,
    opened: u64,
    ping_timeout_ms: u64,
    authenticated_at: Option<u64>,
    failure: Option<&'static str>,
    sent_messages: u64,
    received_messages: u64,
    rejected_datagrams: u64,
    rejected_messages: u64,
    sent_datagrams: u64,
}

impl Stream {
    pub fn open(owner: &str, request: &Open, key: &[u8; 16], now: u64) -> ControlResult<Self> {
        let ping_timeout_ms = validate_ping_timeout_ms(request.ping_timeout_ms)?;
        let defaults = Config::default();
        let peer = Peer::new(
            Config {
                expected_connect_data: request.connect_data,
                handshake_timeout_ms: ping_timeout_ms.max(defaults.retransmit_ms),
                idle_timeout_ms: ping_timeout_ms.max(defaults.ping_interval_ms),
                ..defaults
            },
            now,
        )
        .map_err(|_| "invalid_peer_configuration")?;
        let sealer = ControlSealer::new(key, ControlProfile::SunshineV2, Direction::HostToClient)
            .map_err(|_| "encryption_failed")?;
        let opener = ControlOpener::new(
            key,
            ControlProfile::SunshineV2,
            Direction::ClientToHost,
            ControlOrdering::MultipleChannels,
        )
        .map_err(|_| "encryption_failed")?;
        let socket =
            amaterasu_network_policy::bind_udp(request.local()).map_err(|_| "udp_bind_failed")?;
        let local = socket
            .local_addr()
            .map_err(|_| "udp_configuration_failed")?;
        Ok(Self {
            owner: owner.into(),
            socket: Some(socket),
            local,
            authorized_ip: request.peer_ip,
            authorized_port: request.peer_port,
            remote: None,
            peer,
            sealer,
            opener,
            pending_datagram: None,
            incoming: VecDeque::new(),
            incoming_bytes: 0,
            opened: now,
            ping_timeout_ms,
            authenticated_at: None,
            failure: None,
            sent_messages: 0,
            received_messages: 0,
            rejected_datagrams: 0,
            rejected_messages: 0,
            sent_datagrams: 0,
        })
    }

    pub fn metadata(&self, id: u64) -> Value {
        json!({
            "ok": true,
            "stream": id,
            "local": self.local,
            "peer_ip": self.authorized_ip,
            "peer": self.remote,
            "state": self.state(),
            "authenticated": self.failure.is_none() && self.authenticated_at.is_some() && self.peer.state() == State::Connected,
            "ping_timeout_ms": self.ping_timeout_ms,
            "failure": self.failure,
            "queued_messages": self.incoming.len(),
            "queued_bytes": self.incoming_bytes,
            "sent_messages": self.sent_messages,
            "received_messages": self.received_messages,
            "rejected_messages": self.rejected_messages,
            "rejected_datagrams": self.rejected_datagrams,
            "sent_datagrams": self.sent_datagrams,
        })
    }

    fn state(&self) -> &'static str {
        if self.failure.is_some() {
            return "failed";
        }
        match self.peer.state() {
            State::Listening => "listening",
            State::AwaitingVerifyAck => "connecting",
            State::Connected if self.authenticated_at.is_some() => "active",
            State::Connected => "awaiting_authentication",
            State::Disconnecting => "disconnecting",
            State::Disconnected => "disconnected",
            State::TimedOut => "timed_out",
        }
    }

    pub fn tick(&mut self, now: u64) {
        if self.failure.is_some() {
            return;
        }
        self.flush_socket();
        self.read_socket(now);
        if self.failure.is_some() {
            return;
        }
        if let Err(error) = self.peer.poll(now)
            && error != PeerError::Busy
        {
            self.fail(peer_poll_failure(error));
        }
        self.collect_messages(now);
        self.flush_socket();
        self.check_timeout(now);
    }

    fn check_timeout(&mut self, now: u64) {
        if now >= self.timeout_deadline() {
            self.fail(self.timeout_failure());
        }
    }

    fn timeout_deadline(&self) -> u64 {
        self.authenticated_at
            .unwrap_or(self.opened)
            .saturating_add(self.ping_timeout_ms)
    }

    fn timeout_failure(&self) -> &'static str {
        if self.authenticated_at.is_some() {
            "authenticated_peer_idle"
        } else {
            "authentication_timeout"
        }
    }

    fn collect_messages(&mut self, now: u64) {
        while let Some(event) = self.peer.pop_event() {
            match event {
                Event::Receive {
                    channel,
                    delivery,
                    data,
                } => {
                    self.accept_control(channel, delivery, &data, now);
                    if self.failure.is_some() {
                        return;
                    }
                }
                Event::Connected { .. } => {}
                Event::Disconnected { .. } => {
                    self.fail("peer_disconnected");
                    return;
                }
                Event::TimedOut => {
                    self.fail(if now >= self.timeout_deadline() {
                        self.timeout_failure()
                    } else {
                        "peer_timeout"
                    });
                    return;
                }
            }
        }
    }

    fn accept_control(&mut self, channel: u8, delivery: Delivery, data: &[u8], now: u64) {
        let Ok(message) = self.opener.open(data) else {
            self.rejected_messages = self.rejected_messages.saturating_add(1);
            return;
        };
        if self.incoming.len() >= MAX_MESSAGES
            || self.incoming_bytes + message.payload.len() > MAX_MESSAGE_BYTES
        {
            self.fail("consumer_queue_full");
            return;
        }
        self.authenticated_at = Some(now);
        self.received_messages = self.received_messages.saturating_add(1);
        self.incoming_bytes += message.payload.len();
        self.incoming.push_back(Received {
            kind: message.kind,
            channel,
            delivery,
            sequence: message.sequence,
            bytes: message.payload,
        });
    }

    /// # Safety
    /// The message and its declared initialized immutable bytes live until return.
    pub unsafe fn send(&mut self, message: &ControlMessage, now: u64) -> Status {
        if self.failure.is_some() {
            return MEDIA_BACKEND_ERROR;
        }
        if self.authenticated_at.is_none() {
            return MEDIA_PENDING;
        }
        if let Err(status) = message.validate() {
            return status;
        }
        let delivery = match delivery(message.delivery) {
            Some(delivery) => delivery,
            None => return STATUS_INVALID_ARGUMENT,
        };
        let channel = message.channel as u8;
        match self.peer.can_send(channel, message.len + 28, delivery) {
            Ok(()) => {}
            Err(PeerError::Busy) => return MEDIA_BUSY,
            Err(PeerError::NotConnected) => return MEDIA_CLOSED,
            Err(_) => return STATUS_INVALID_ARGUMENT,
        }
        // SAFETY: allocation validity is the native consumer's obligation.
        let payload = unsafe { message.bytes().expect("validated metadata") };
        let encrypted = match self.sealer.seal(message.message_type as u16, payload) {
            Ok(encrypted) => encrypted,
            Err(_) => {
                self.fail("encryption_failed");
                return MEDIA_BACKEND_ERROR;
            }
        };
        if let Err(error) = self.peer.send(channel, &encrypted, delivery, now) {
            // Admission and enqueue are exclusive under one controller lock. Any
            // unexpected failure after sealing ends the stream; never rewind a nonce.
            self.fail(peer_enqueue_failure(error));
            return MEDIA_BACKEND_ERROR;
        }
        self.sent_messages = self.sent_messages.saturating_add(1);
        STATUS_OK
    }

    /// # Safety
    /// Sink function/context remain live through the synchronous callback.
    pub unsafe fn receive(&mut self, sink: ControlMessageSink) -> Status {
        let Some(write) = sink.write else {
            return STATUS_INVALID_ARGUMENT;
        };
        if self.failure.is_some() {
            return MEDIA_BACKEND_ERROR;
        }
        let Some(received) = self.incoming.front() else {
            return MEDIA_PENDING;
        };
        let message = ControlMessage {
            message_type: received.kind.into(),
            channel: received.channel.into(),
            delivery: delivery_code(received.delivery),
            reserved: 0,
            data: received.bytes.as_ptr(),
            len: received.bytes.len(),
            sequence: received.sequence.into(),
        };
        // SAFETY: local header and queue allocation stay live and immutable while
        // the synchronous sink borrows them. Reentrant native calls return BUSY.
        let result = unsafe { write(sink.context, &message) };
        if result == STATUS_OK {
            self.incoming_bytes -= self
                .incoming
                .pop_front()
                .expect("borrowed front")
                .bytes
                .len();
        }
        result
    }

    fn fail(&mut self, code: &'static str) {
        if self.failure.is_none() {
            self.failure = Some(code);
            // `code` comes only from fixed internal call sites and never includes
            // peer addresses, control payloads, keys, or other session material.
            eprintln!("amaterasu control transport failed code={code}");
        }
        self.socket = None;
        self.pending_datagram = None;
        self.incoming.clear();
        self.incoming_bytes = 0;
    }
}

fn peer_poll_failure(error: PeerError) -> &'static str {
    match error {
        PeerError::InvalidConfig => "peer_poll_invalid_config",
        PeerError::InvalidChannel => "peer_poll_invalid_channel",
        PeerError::MessageTooLarge => "peer_poll_message_too_large",
        PeerError::Busy => "peer_poll_busy",
        PeerError::NotConnected => "peer_poll_not_connected",
        PeerError::InvalidPacket => "peer_poll_invalid_packet",
        PeerError::ClockRegression => "peer_poll_clock_regression",
        PeerError::Unsupported => "peer_poll_unsupported",
    }
}

fn peer_enqueue_failure(error: PeerError) -> &'static str {
    match error {
        PeerError::InvalidConfig => "peer_enqueue_invalid_config",
        PeerError::InvalidChannel => "peer_enqueue_invalid_channel",
        PeerError::MessageTooLarge => "peer_enqueue_message_too_large",
        PeerError::Busy => "peer_enqueue_busy_after_admission",
        PeerError::NotConnected => "peer_enqueue_not_connected",
        PeerError::InvalidPacket => "peer_enqueue_invalid_packet",
        PeerError::ClockRegression => "peer_enqueue_clock_regression",
        PeerError::Unsupported => "peer_enqueue_unsupported",
    }
}

fn delivery(value: u32) -> Option<Delivery> {
    match value {
        CONTROL_RELIABLE => Some(Delivery::Reliable),
        CONTROL_UNRELIABLE => Some(Delivery::Unreliable),
        CONTROL_UNSEQUENCED => Some(Delivery::Unsequenced),
        _ => None,
    }
}

fn delivery_code(delivery: Delivery) -> u32 {
    match delivery {
        Delivery::Reliable => CONTROL_RELIABLE,
        Delivery::Unreliable => CONTROL_UNRELIABLE,
        Delivery::Unsequenced => CONTROL_UNSEQUENCED,
    }
}

#[cfg(test)]
mod tests;
