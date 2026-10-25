use super::{TransportResult, tickets::Tickets};
use amaterasu_gamestream::{
    crypto::RtspEnvelopeDecoder,
    rtsp::{Decoder, Request},
};
use std::{
    io::{self, Read, Write},
    net::{IpAddr, TcpStream},
};

const IO_BUDGET: usize = 16 * 1024;
const IO_DEADLINE_MS: u64 = 10_000;
const ROUTER_DEADLINE_MS: u64 = 15_000;

pub(super) enum Step {
    Pending,
    Request { ticket: u64, request: Request },
    Close(&'static str),
}

enum State {
    Reading(RtspEnvelopeDecoder),
    Waiting,
    Writing { bytes: Vec<u8>, offset: usize },
}

pub(super) struct Connection {
    socket: TcpStream,
    peer: IpAddr,
    ticket: Option<u64>,
    deadline: u64,
    state: State,
}

impl Connection {
    pub(super) fn new(socket: TcpStream, peer: IpAddr, now: u64) -> TransportResult<Self> {
        socket
            .set_nonblocking(true)
            .map_err(|_| "tcp_configuration_failed")?;
        socket
            .set_nodelay(true)
            .map_err(|_| "tcp_configuration_failed")?;
        Ok(Self {
            socket,
            peer,
            ticket: None,
            deadline: now.saturating_add(IO_DEADLINE_MS),
            state: State::Reading(RtspEnvelopeDecoder::default()),
        })
    }
    pub(super) fn peer(&self) -> IpAddr {
        self.peer
    }
    pub(super) fn ticket(&self) -> Option<u64> {
        self.ticket
    }
    pub(super) fn awaiting_reply(&self) -> bool {
        matches!(self.state, State::Waiting)
    }

    pub(super) fn reply(&mut self, bytes: Vec<u8>, now: u64) {
        self.state = State::Writing { bytes, offset: 0 };
        self.deadline = now.saturating_add(IO_DEADLINE_MS);
    }

    pub(super) fn step(&mut self, tickets: &mut Tickets, now: u64) -> Step {
        if now >= self.deadline {
            return Step::Close("connection_deadline");
        }
        match &mut self.state {
            State::Reading(_) => self.read(tickets, now),
            State::Waiting => self.check_disconnect(),
            State::Writing { bytes, offset } => {
                let end = (*offset + IO_BUDGET).min(bytes.len());
                match self.socket.write(&bytes[*offset..end]) {
                    Ok(0) => Step::Close("peer_closed"),
                    Ok(length) => {
                        *offset += length;
                        if *offset == bytes.len() {
                            Step::Close("response_complete")
                        } else {
                            Step::Pending
                        }
                    }
                    Err(error) if retryable(&error) => Step::Pending,
                    Err(_) => Step::Close("tcp_write_failed"),
                }
            }
        }
    }

    fn read(&mut self, tickets: &mut Tickets, now: u64) -> Step {
        let mut buffer = [0; IO_BUDGET];
        let length = match self.socket.read(&mut buffer) {
            Ok(0) => return Step::Close("peer_closed"),
            Ok(length) => length,
            Err(error) if retryable(&error) => return Step::Pending,
            Err(_) => return Step::Close("tcp_read_failed"),
        };
        let State::Reading(decoder) = &mut self.state else {
            unreachable!("read state");
        };
        if decoder.push(&buffer[..length]).is_err() {
            return Step::Close("invalid_encrypted_frame");
        }
        let envelope = match decoder.next_frame() {
            Ok(Some(envelope)) => envelope,
            Ok(None) => return Step::Pending,
            Err(_) => return Step::Close("invalid_encrypted_frame"),
        };
        if decoder.finish().is_err() {
            return Step::Close("multiple_encrypted_frames");
        }
        let (ticket, plaintext) = match tickets.authenticate(self.peer, &envelope) {
            Ok(authenticated) => authenticated,
            Err(error) => return Step::Close(error),
        };
        self.ticket = Some(ticket);
        let request = match decode_request(&plaintext) {
            Ok(request) => request,
            Err(error) => return Step::Close(error),
        };
        self.state = State::Waiting;
        self.deadline = now.saturating_add(ROUTER_DEADLINE_MS);
        Step::Request { ticket, request }
    }

    fn check_disconnect(&mut self) -> Step {
        let mut extra = [0];
        match self.socket.read(&mut extra) {
            Ok(0) => Step::Close("peer_closed"),
            Ok(_) => Step::Close("unexpected_pipelined_data"),
            Err(error) if retryable(&error) => Step::Pending,
            Err(_) => Step::Close("tcp_read_failed"),
        }
    }
}

fn decode_request(plaintext: &[u8]) -> TransportResult<Request> {
    let mut decoder = Decoder::default();
    decoder
        .push(plaintext)
        .map_err(|_| "invalid_rtsp_request")?;
    let request = decoder
        .next_request()
        .map_err(|_| "invalid_rtsp_request")?
        .ok_or("incomplete_rtsp_request")?;
    decoder.finish().map_err(|_| "multiple_rtsp_requests")?;
    Ok(request)
}

fn retryable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}
