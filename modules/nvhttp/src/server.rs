//! Single-threaded nonblocking sockets with bounded request and response buffers.
use crate::{
    settings::Settings,
    wire::{Reply, Request},
};
use rustls::{ServerConfig, ServerConnection};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
#[cfg(test)]
use std::net::{Ipv4Addr, Ipv6Addr};
use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
    net::{IpAddr, SocketAddr, TcpListener, TcpStream},
    sync::Arc,
    time::{Duration, Instant},
};

const MAX_CONNECTIONS: usize = 32;
const MAX_PER_PEER: usize = 8;
const MAX_REQUEST: usize = 32 * 1024;
const MAX_REPLY: usize = 1024 * 1024;
const IO_BUDGET: usize = 16 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const ROUTE_TIMEOUT: Duration = Duration::from_secs(130);

pub struct Incoming {
    pub id: u64,
    pub request: Request,
    pub secure: bool,
    pub remote: IpAddr,
    pub peer_certificate: Option<Vec<u8>>,
}

pub struct Events {
    pub requests: Vec<Incoming>,
    pub closed: Vec<Closed>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Closed {
    pub id: u64,
    pub response_delivered: bool,
}

pub struct Server {
    http: Vec<TcpListener>,
    https: Vec<TcpListener>,
    connections: BTreeMap<u64, Connection>,
    next_id: u64,
    configuration: Option<Arc<ServerConfig>>,
    tls_ready: bool,
}

impl Server {
    pub fn bind(settings: &Settings) -> Result<Self, String> {
        let http = bind_listeners(
            settings.resolved_http_binds().map_err(str::to_owned)?,
            "HTTP",
        )?;
        let https = bind_listeners(
            settings.resolved_https_binds().map_err(str::to_owned)?,
            "HTTPS",
        )?;
        Ok(Self {
            http,
            https,
            connections: BTreeMap::new(),
            next_id: 0,
            configuration: None,
            tls_ready: false,
        })
    }

    pub fn http_address(&self) -> SocketAddr {
        self.http_addresses()[0]
    }
    pub fn https_address(&self) -> SocketAddr {
        self.https_addresses()[0]
    }

    pub fn http_addresses(&self) -> Vec<SocketAddr> {
        self.http
            .iter()
            .map(|listener| listener.local_addr().expect("bound HTTP listener"))
            .collect()
    }

    pub fn https_addresses(&self) -> Vec<SocketAddr> {
        self.https
            .iter()
            .map(|listener| listener.local_addr().expect("bound HTTPS listener"))
            .collect()
    }

    /// Rebinds the HTTP pair while retaining existing accepted connections.
    /// Both replacement sockets are prepared before either current listener is dropped.
    #[cfg(test)]
    pub fn rebind_port(&mut self, http_port: u16) -> Result<(), String> {
        crate::settings::validate_port(http_port).map_err(str::to_owned)?;
        let https_port = crate::settings::https_port(http_port);
        let old_http_addresses = self.http_addresses();
        let old_https_addresses = self.https_addresses();
        if old_http_addresses
            .iter()
            .all(|address| address.port() == http_port)
            && old_https_addresses
                .iter()
                .all(|address| address.port() == https_port)
        {
            return Ok(());
        }

        let http_addresses = old_http_addresses
            .iter()
            .map(|address| SocketAddr::new(address.ip(), http_port))
            .collect::<Vec<_>>();
        let https_addresses = old_https_addresses
            .iter()
            .map(|address| SocketAddr::new(address.ip(), https_port))
            .collect::<Vec<_>>();
        let http = replacement_listeners(&http_addresses, &self.http, &self.https, "HTTP")?;
        let https = replacement_listeners(&https_addresses, &self.http, &self.https, "HTTPS")?;

        self.http = http;
        self.https = https;
        Ok(())
    }

    /// Rebinds both protocols and all requested address families as one swap.
    /// Existing accepted connections keep their original sockets and state.
    pub fn rebind_settings(&mut self, settings: &Settings) -> Result<(), String> {
        settings.validate().map_err(str::to_owned)?;
        let http_addresses = settings.resolved_http_binds().map_err(str::to_owned)?;
        let https_addresses = settings.resolved_https_binds().map_err(str::to_owned)?;
        let old_http_addresses = self.http_addresses();
        let old_https_addresses = self.https_addresses();
        if old_http_addresses == http_addresses && old_https_addresses == https_addresses {
            return Ok(());
        }

        let preflight = (|| {
            let http = replacement_listeners(&http_addresses, &self.http, &self.https, "HTTP")?;
            let https = replacement_listeners(&https_addresses, &self.http, &self.https, "HTTPS")?;
            Ok::<_, String>((http, https))
        })();
        match preflight {
            Ok((http, https)) => {
                self.http = http;
                self.https = https;
                Ok(())
            }
            Err(preflight_error) => {
                if !listener_sets_overlap(
                    [&old_http_addresses, &old_https_addresses],
                    [&http_addresses, &https_addresses],
                ) {
                    Err(preflight_error)
                } else {
                    // Some operating systems reject a wildcard bind while a more
                    // specific old listener owns the same port. Release both old
                    // groups together, then either install the complete replacement
                    // or restore the complete old pair before returning.
                    drop(std::mem::take(&mut self.http));
                    drop(std::mem::take(&mut self.https));
                    let replacement = (|| {
                        let http = bind_listeners(http_addresses, "HTTP")?;
                        let https = bind_listeners(https_addresses, "HTTPS")?;
                        Ok::<_, String>((http, https))
                    })();
                    match replacement {
                        Ok((http, https)) => {
                            self.http = http;
                            self.https = https;
                            Ok(())
                        }
                        Err(replacement_error) => {
                            let restored = (|| {
                                let http = bind_listeners(old_http_addresses, "HTTP rollback")?;
                                let https = bind_listeners(old_https_addresses, "HTTPS rollback")?;
                                Ok::<_, String>((http, https))
                            })();
                            match restored {
                                Ok((http, https)) => {
                                    self.http = http;
                                    self.https = https;
                                    Err(replacement_error)
                                }
                                Err(rollback_error) => Err(format!(
                                    "listener replacement failed ({replacement_error}); rollback failed ({rollback_error}); preflight was ({preflight_error})"
                                )),
                            }
                        }
                    }
                }
            }
        }
    }

    pub fn connections(&self) -> usize {
        self.connections.len()
    }
    pub fn tls_ready(&self) -> bool {
        self.tls_ready
    }

    pub fn set_ready(&mut self, ready: bool) {
        self.tls_ready = ready && self.configuration.is_some();
    }

    pub fn replace_tls(&mut self, configuration: Arc<ServerConfig>) -> Vec<u64> {
        self.configuration = Some(configuration);
        self.tls_ready = true;
        let closed: Vec<_> = self
            .connections
            .iter()
            .filter(|(_, connection)| connection.tls.is_some())
            .map(|(id, _)| *id)
            .collect();
        for id in &closed {
            self.connections.remove(id);
        }
        closed
    }

    pub fn tick(&mut self) -> Events {
        self.accept(false);
        self.accept(true);
        let mut events = Events {
            requests: Vec::new(),
            closed: Vec::new(),
        };
        let now = Instant::now();
        for (id, connection) in &mut self.connections {
            if now >= connection.deadline {
                events.closed.push(Closed {
                    id: *id,
                    response_delivered: false,
                });
                continue;
            }
            match connection.tick() {
                Ok(Some(request)) => events.requests.push(Incoming {
                    id: *id,
                    request,
                    secure: connection.tls.is_some(),
                    remote: connection.remote,
                    peer_certificate: connection.peer_certificate(),
                }),
                Ok(None) if connection.finished => events.closed.push(Closed {
                    id: *id,
                    response_delivered: connection.response_delivered,
                }),
                Ok(None) => {}
                Err(_) => events.closed.push(Closed {
                    id: *id,
                    response_delivered: false,
                }),
            }
        }
        for closed in &events.closed {
            self.connections.remove(&closed.id);
        }
        events
    }

    fn accept(&mut self, secure: bool) {
        let listeners = if secure { &self.https } else { &self.http };
        for listener in listeners {
            for _ in 0..4 {
                let (socket, remote) = match listener.accept() {
                    Ok(value) => value,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                };
                let remote = normalize_ip(remote.ip());
                let peer_count = self
                    .connections
                    .values()
                    .filter(|connection| connection.remote == remote)
                    .count();
                if self.connections.len() >= MAX_CONNECTIONS
                    || peer_count >= MAX_PER_PEER
                    || (secure && !self.tls_ready)
                {
                    continue;
                }
                if socket.set_nonblocking(true).is_err() {
                    continue;
                }
                let _ = socket.set_nodelay(true);
                let tls = if secure {
                    let Some(configuration) = &self.configuration else {
                        continue;
                    };
                    let Ok(mut connection) = ServerConnection::new(configuration.clone()) else {
                        continue;
                    };
                    connection.set_buffer_limit(Some(MAX_REQUEST));
                    Some(connection)
                } else {
                    None
                };
                let Some(id) = self.next_id.checked_add(1) else {
                    break;
                };
                self.next_id = id;
                self.connections.insert(
                    id,
                    Connection {
                        socket,
                        remote,
                        tls,
                        input: Vec::new(),
                        output: None,
                        waiting: false,
                        finished: false,
                        closing: false,
                        response_delivered: false,
                        deadline: Instant::now() + IO_TIMEOUT,
                    },
                );
            }
        }
    }

    pub fn respond_checked(
        &mut self,
        id: u64,
        reply: Reply,
        verify: impl FnOnce(&[u8]) -> bool,
    ) -> bool {
        let paired = if reply.requires_paired_tls {
            self.connections
                .get(&id)
                .and_then(|connection| connection.tls.as_ref())
                .filter(|tls| !tls.is_handshaking())
                .and_then(|tls| tls.peer_certificates())
                .and_then(|certificates| certificates.first())
                .is_some_and(|certificate| verify(certificate.as_ref()))
        } else {
            false
        };
        let authorized = !reply.requires_paired_tls || paired;
        self.respond(id, reply.authorize(paired)) && authorized
    }

    pub fn respond(&mut self, id: u64, reply: Reply) -> bool {
        if let Some(connection) = self.connections.get_mut(&id) {
            connection.respond(reply);
            true
        } else {
            false
        }
    }

    pub fn close_all(&mut self) -> Vec<u64> {
        let ids = self.connections.keys().copied().collect();
        self.connections.clear();
        ids
    }

    pub fn close(&mut self, id: u64) -> bool {
        self.connections.remove(&id).is_some()
    }
}

fn bind_listener(address: SocketAddr, name: &str) -> Result<TcpListener, String> {
    let domain = Domain::for_address(address);
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .map_err(|_| format!("{name} socket unavailable"))?;
    // Unix keeps actively closed connections in TIME_WAIT after host shutdown.
    // Address reuse permits restart after that listener closes; an existing
    // live listener still owns its endpoint. Windows has different semantics.
    #[cfg(unix)]
    socket
        .set_reuse_address(true)
        .map_err(|_| format!("{name} address reuse configuration failed"))?;
    if address.is_ipv6() {
        socket
            .set_only_v6(true)
            .map_err(|_| format!("{name} IPv6 configuration failed"))?;
    }
    socket
        .bind(&SockAddr::from(address))
        .map_err(|_| format!("{name} listener unavailable"))?;
    socket
        .listen(128)
        .map_err(|_| format!("{name} listen failed"))?;
    socket
        .set_nonblocking(true)
        .map_err(|_| format!("{name} nonblocking setup failed"))?;
    Ok(socket.into())
}

fn bind_listeners(addresses: Vec<SocketAddr>, name: &str) -> Result<Vec<TcpListener>, String> {
    let mut listeners = Vec::with_capacity(addresses.len());
    let mut selected_port = None;
    for mut address in addresses {
        if address.port() == 0
            && let Some(port) = selected_port
        {
            address.set_port(port);
        }
        let listener = bind_listener(address, name)?;
        selected_port.get_or_insert_with(|| listener.local_addr().expect("bound listener").port());
        listeners.push(listener);
    }
    Ok(listeners)
}

fn replacement_listeners(
    addresses: &[SocketAddr],
    old_http: &[TcpListener],
    old_https: &[TcpListener],
    name: &str,
) -> Result<Vec<TcpListener>, String> {
    let mut replacements = Vec::with_capacity(addresses.len());
    for address in addresses {
        // A TCP listener is protocol-neutral; TLS/plain handling is chosen by
        // the accept call. Reusing a same-address listener for the other role is
        // safe while existing accepted streams retain their own connection state.
        let existing = old_http
            .iter()
            .chain(old_https)
            .find(|listener| listener.local_addr().ok() == Some(*address));
        let listener = match existing {
            Some(listener) => listener
                .try_clone()
                .map_err(|_| format!("{name} listener clone failed"))?,
            None => bind_listener(*address, name)?,
        };
        replacements.push(listener);
    }
    Ok(replacements)
}

fn listener_sets_overlap<const OLD: usize, const NEW: usize>(
    old_groups: [&[SocketAddr]; OLD],
    new_groups: [&[SocketAddr]; NEW],
) -> bool {
    let old_addresses = old_groups
        .iter()
        .flat_map(|group| group.iter())
        .collect::<Vec<_>>();
    new_groups
        .iter()
        .flat_map(|group| group.iter())
        .filter(|new| !old_addresses.contains(new))
        .any(|new| {
            old_addresses.iter().any(|old| {
                old.port() == new.port()
                    && old.is_ipv4() == new.is_ipv4()
                    && (old.ip() == new.ip()
                        || old.ip().is_unspecified()
                        || new.ip().is_unspecified())
            })
        })
}

fn normalize_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        IpAddr::V4(address) => IpAddr::V4(address),
    }
}

struct Output {
    bytes: Vec<u8>,
    offset: usize,
}
struct Connection {
    socket: TcpStream,
    remote: IpAddr,
    tls: Option<ServerConnection>,
    input: Vec<u8>,
    output: Option<Output>,
    waiting: bool,
    finished: bool,
    closing: bool,
    response_delivered: bool,
    deadline: Instant,
}

impl Connection {
    fn tick(&mut self) -> io::Result<Option<Request>> {
        if self.tls.is_some() {
            self.tls_io()?;
        }
        if self.finished {
            return Ok(None);
        }
        if self.output.is_some() {
            self.write_response()?;
            return Ok(None);
        }
        if self.waiting {
            if matches!(self.socket.peek(&mut [0; 1]), Ok(0)) {
                self.finished = true;
            }
            return Ok(None);
        }
        if self.tls.as_ref().is_some_and(|tls| tls.is_handshaking()) {
            return Ok(None);
        }
        let mut buffer = [0u8; IO_BUDGET];
        let read = match &mut self.tls {
            Some(tls) => tls.reader().read(&mut buffer),
            None => self.socket.read(&mut buffer),
        };
        match read {
            Ok(0) => {
                self.finished = true;
                return Ok(None);
            }
            Ok(length) => {
                if self.input.len() + length > MAX_REQUEST {
                    self.respond(simple_reply(413, "request too large"));
                    return Ok(None);
                }
                self.input.extend_from_slice(&buffer[..length]);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) => return Err(error),
        }
        match parse_request(&self.input) {
            Ok(Some(request)) => {
                self.input.clear();
                self.waiting = true;
                self.deadline = Instant::now() + ROUTE_TIMEOUT;
                Ok(Some(request))
            }
            Ok(None) => Ok(None),
            Err(status) => {
                self.respond(simple_reply(status, "invalid request"));
                Ok(None)
            }
        }
    }

    fn tls_io(&mut self) -> io::Result<()> {
        let tls = self.tls.as_mut().expect("TLS connection");
        // One bounded socket read and write per tick, never complete_io's loop.
        // Application plaintext is read only while parsing the single request.
        if tls.wants_read() && self.output.is_none() {
            let read = tls.read_tls(&mut (&mut self.socket).take(IO_BUDGET as u64));
            match read {
                Ok(0) => self.finished = true,
                Ok(_) => {
                    let state = tls
                        .process_new_packets()
                        .map_err(|_| io::Error::other("TLS protocol failure"))?;
                    if state.peer_has_closed() {
                        self.finished = true;
                    }
                    if self.waiting && state.plaintext_bytes_to_read() > 0 {
                        return Err(io::Error::other("HTTP pipelining unsupported"));
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        if tls.wants_write() {
            let mut output = BoundedWriter {
                socket: &mut self.socket,
                remaining: IO_BUDGET,
            };
            match tls.write_tls(&mut output) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn peer_certificate(&self) -> Option<Vec<u8>> {
        self.tls
            .as_ref()?
            .peer_certificates()?
            .first()
            .map(|certificate| certificate.as_ref().to_vec())
    }

    fn respond(&mut self, reply: Reply) {
        let reply = if reply.body.len() > MAX_REPLY || reply.content_type.contains(['\r', '\n']) {
            simple_reply(500, "response unavailable")
        } else {
            reply
        };
        if reply.status >= 400 {
            eprintln!("amaterasu nvhttp response status={}", reply.status);
        }
        let reason = match reply.status {
            200 => "OK",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            408 => "Request Timeout",
            409 => "Conflict",
            413 => "Content Too Large",
            429 => "Too Many Requests",
            501 => "Not Implemented",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            504 => "Gateway Timeout",
            _ => "Error",
        };
        let mut bytes=format!("HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",reply.status,reason,reply.content_type,reply.body.len()).into_bytes();
        bytes.extend_from_slice(&reply.body);
        self.output = Some(Output { bytes, offset: 0 });
        self.input.clear();
        self.waiting = false;
        self.response_delivered = false;
        self.deadline = Instant::now() + IO_TIMEOUT;
    }

    fn write_response(&mut self) -> io::Result<()> {
        let output = self.output.as_mut().expect("pending response");
        if output.offset < output.bytes.len() {
            let end = (output.offset + IO_BUDGET).min(output.bytes.len());
            let result = match &mut self.tls {
                Some(tls) => tls.writer().write(&output.bytes[output.offset..end]),
                None => self.socket.write(&output.bytes[output.offset..end]),
            };
            match result {
                Ok(0) if self.tls.is_some() => {}
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(length) => output.offset += length,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
        if output.offset == output.bytes.len() {
            if let Some(tls) = &mut self.tls {
                if !tls.wants_write() {
                    if self.closing {
                        self.response_delivered = true;
                        self.finished = true;
                    } else {
                        tls.send_close_notify();
                        self.closing = true;
                    }
                }
            } else {
                self.response_delivered = true;
                self.finished = true;
            }
        }
        Ok(())
    }
}

struct BoundedWriter<'a> {
    socket: &'a mut TcpStream,
    remaining: usize,
}
impl Write for BoundedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let length = self
            .socket
            .write(&bytes[..bytes.len().min(self.remaining)])?;
        self.remaining -= length;
        Ok(length)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn parse_request(bytes: &[u8]) -> Result<Option<Request>, u16> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut request = httparse::Request::new(&mut headers);
    let offset = match request.parse(bytes).map_err(|_| 400u16)? {
        httparse::Status::Partial => return Ok(None),
        httparse::Status::Complete(offset) => offset,
    };
    let method = request.method.ok_or(400u16)?;
    let target = request.path.ok_or(400u16)?;
    if !target.starts_with('/') || target.len() > 24 * 1024 {
        return Err(400);
    }
    let mut length = None;
    let mut host = false;
    for header in request.headers.iter() {
        if header.name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(400);
        }
        if header.name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err(400);
            }
            let text = std::str::from_utf8(header.value)
                .map_err(|_| 400u16)?
                .trim();
            if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(400);
            }
            length = Some(text.parse::<usize>().map_err(|_| 413u16)?);
        }
        if header.name.eq_ignore_ascii_case("host") {
            if host {
                return Err(400);
            }
            host = true;
        }
    }
    if request.version == Some(1) && !host {
        return Err(400);
    }
    let total = offset
        .checked_add(length.unwrap_or(0))
        .filter(|total| *total <= MAX_REQUEST)
        .ok_or(413u16)?;
    if bytes.len() < total {
        return Ok(None);
    }
    if bytes.len() != total {
        return Err(400);
    }
    Ok(Some(Request {
        method: method.into(),
        target: target.into(),
        body: bytes[offset..total].to_vec(),
    }))
}

fn simple_reply(status: u16, message: &str) -> Reply {
    Reply {
        status,
        content_type: "text/plain; charset=utf-8",
        body: message.as_bytes().to_vec(),
        requires_paired_tls: false,
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn closed_loopback_connection_allows_immediate_listener_restart() {
        use std::io::Read;
        use std::net::{Shutdown, TcpStream};
        use std::time::Duration;

        let listener = super::bind_listener("127.0.0.1:0".parse().unwrap(), "test").unwrap();
        let address = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (accepted, _) = listener.accept().unwrap();
        // The server actively closes first, leaving its endpoint in TIME_WAIT.
        accepted.shutdown(Shutdown::Write).unwrap();
        let mut byte = [0];
        assert_eq!(client.read(&mut byte).unwrap(), 0);
        drop(client);
        drop(accepted);
        drop(listener);
        let restarted = super::bind_listener(address, "restart").unwrap();
        assert_eq!(restarted.local_addr().unwrap(), address);
        assert!(super::bind_listener(address, "occupied").is_err());
    }

    use super::*;
    use std::sync::Mutex;

    static FIXED_PORT_LOCK: Mutex<()> = Mutex::new(());

    #[cfg(unix)]
    #[test]
    fn closed_loopback_listener_can_restart_without_sharing_a_live_port() {
        use std::{
            io::Read,
            net::{Shutdown, TcpStream},
            time::Duration,
        };

        let listener = bind_listener("127.0.0.1:0".parse().unwrap(), "test").unwrap();
        let address = listener.local_addr().unwrap();
        assert!(bind_listener(address, "occupied").is_err());

        let mut client = TcpStream::connect(address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (accepted, _) = listener.accept().unwrap();
        // Close the accepted side first. After the client observes EOF and
        // closes, the server-side connection enters TIME_WAIT on this port.
        accepted.shutdown(Shutdown::Write).unwrap();
        let mut byte = [0];
        assert_eq!(client.read(&mut byte).unwrap(), 0);
        drop(client);
        drop(accepted);
        drop(listener);

        let restarted = bind_listener(address, "restart").unwrap();
        assert_eq!(restarted.local_addr().unwrap(), address);
    }

    #[test]
    fn strict_http_framing_rejects_smuggling_and_waits_for_complete_bodies() {
        assert!(
            parse_request(b"GET /serverinfo HTTP/1.1\r\nHost: test\r\n\r\n")
                .unwrap()
                .is_some()
        );
        assert!(
            parse_request(b"POST /pair HTTP/1.1\r\nHost: test\r\nContent-Length: 2\r\n\r\nx")
                .unwrap()
                .is_none()
        );
        for bytes in [
            &b"GET / HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n"[..],
            &b"GET / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"[..],
            &b"GET / HTTP/1.1\r\nHost: a\r\n\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n"[..],
        ] {
            assert!(parse_request(bytes).is_err());
        }
    }
    #[test]
    fn real_socket_dispatches_one_request_and_closes_after_reply() {
        let settings = Settings {
            enabled: true,
            http_bind: "127.0.0.1:0".parse().unwrap(),
            https_bind: "127.0.0.1:0".parse().unwrap(),
            ..Settings::default()
        };
        let mut server = Server::bind(&settings).unwrap();
        let mut client = TcpStream::connect(server.http_address()).unwrap();
        client.set_nonblocking(true).unwrap();
        client
            .write_all(b"GET /serverinfo HTTP/1.1\r\nHost: test\r\n\r\n")
            .unwrap();
        let mut response = Vec::new();
        let mut delivered = false;
        for _ in 0..100 {
            let events = server.tick();
            delivered |= events.closed.iter().any(|closed| closed.response_delivered);
            for incoming in events.requests {
                assert!(!incoming.secure);
                server.respond(incoming.id, simple_reply(200, "hello"));
            }
            let mut bytes = [0; 512];
            match client.read(&mut bytes) {
                Ok(0) => break,
                Ok(length) => response.extend_from_slice(&bytes[..length]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("{error}"),
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(response.ends_with(b"hello"));
        assert!(delivered);
        assert_eq!(server.connections(), 0);
    }

    #[test]
    fn configured_ipv6_bind_address_is_used_by_both_live_listeners() {
        let settings: Settings = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "address_family": "both",
            "bind_address": "::1",
            "http_bind": "127.0.0.1:0",
            "https_bind": "127.0.0.1:0"
        }))
        .unwrap();
        settings.validate().unwrap();

        let server = Server::bind(&settings).expect("bind IPv6 HTTP pair");
        assert_eq!(server.http_address().ip(), "::1".parse::<IpAddr>().unwrap());
        assert_eq!(
            server.https_address().ip(),
            "::1".parse::<IpAddr>().unwrap()
        );
        assert!(TcpStream::connect(server.http_address()).is_ok());
    }

    #[test]
    fn omitted_bind_address_uses_explicit_ipv4_family_for_live_listeners() {
        assert_explicit_ipv4_family_for_live_listeners(false);
    }

    #[test]
    #[ignore = "opens wildcard listeners; run explicitly when testing remote binding"]
    fn omitted_bind_address_uses_explicit_ipv4_family_for_remote_listeners() {
        assert_explicit_ipv4_family_for_live_listeners(true);
    }

    fn assert_explicit_ipv4_family_for_live_listeners(allow_remote: bool) {
        let settings = Settings {
            enabled: true,
            address_family: Some(crate::settings::AddressFamily::Ipv4),
            allow_remote,
            http_bind: "127.0.0.1:0".parse().unwrap(),
            https_bind: "127.0.0.1:0".parse().unwrap(),
            ..Settings::default()
        };
        let server = Server::bind(&settings).expect("bind explicit IPv4 family");
        let expected_ip = if allow_remote {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        };
        let bound_addresses = server
            .http_addresses()
            .into_iter()
            .chain(server.https_addresses())
            .collect::<Vec<_>>();

        for address in bound_addresses {
            assert_eq!(address.ip(), expected_ip);
            assert!(
                TcpStream::connect(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    address.port(),
                ))
                .is_ok()
            );
        }
    }

    #[test]
    fn both_loopback_families_accept_ipv4_and_ipv6() {
        assert_both_families_accept_ipv4_and_ipv6(false);
    }

    #[test]
    #[ignore = "opens wildcard listeners; run explicitly when testing remote binding"]
    fn both_remote_families_accept_ipv4_and_ipv6() {
        assert_both_families_accept_ipv4_and_ipv6(true);
    }

    fn assert_both_families_accept_ipv4_and_ipv6(allow_remote: bool) {
        let settings: Settings = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "allow_remote": allow_remote,
            "address_family": "both",
            "bind_address": "",
            "http_bind": "127.0.0.1:0",
            "https_bind": "127.0.0.1:0"
        }))
        .unwrap();
        let mut server = Server::bind(&settings).expect("bind both address families");
        let http_addresses = server.http_addresses();
        let https_addresses = server.https_addresses();
        assert_eq!(http_addresses.len(), 2);
        assert_eq!(https_addresses.len(), 2);
        let (expected_v4, expected_v6) = if allow_remote {
            (
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            )
        } else {
            (
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            )
        };
        assert_eq!(http_addresses[0].ip(), expected_v4);
        assert_eq!(http_addresses[1].ip(), expected_v6);
        assert_eq!(http_addresses[0].port(), http_addresses[1].port());
        assert_eq!(https_addresses[0].port(), https_addresses[1].port());
        assert!(https_addresses.iter().all(|address| {
            if allow_remote {
                address.ip().is_unspecified()
            } else {
                address.ip().is_loopback()
            }
        }));

        let tls_configuration =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(rustls::server::ResolvesServerCertUsingSni::new()));
        server.replace_tls(Arc::new(tls_configuration));

        let mut clients = Vec::new();
        for address in &http_addresses {
            let destination = SocketAddr::new(
                if address.is_ipv4() {
                    IpAddr::V4(Ipv4Addr::LOCALHOST)
                } else {
                    IpAddr::V6(Ipv6Addr::LOCALHOST)
                },
                address.port(),
            );
            let mut client = TcpStream::connect(destination).unwrap();
            client
                .write_all(b"GET /serverinfo HTTP/1.1\r\nHost: test\r\n\r\n")
                .unwrap();
            clients.push(client);
        }
        let mut tls_clients = Vec::new();
        for address in https_addresses {
            let destination = SocketAddr::new(
                if address.is_ipv4() {
                    IpAddr::V4(Ipv4Addr::LOCALHOST)
                } else {
                    IpAddr::V6(Ipv6Addr::LOCALHOST)
                },
                address.port(),
            );
            tls_clients.push(TcpStream::connect(destination).unwrap());
        }

        let requests = server.tick().requests;
        assert_eq!(requests.len(), 2);
        assert_eq!(server.connections(), 4, "both HTTPS families were accepted");
        let peers = requests
            .into_iter()
            .map(|request| request.remote)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            peers,
            [
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST)
            ]
            .into_iter()
            .collect()
        );
        drop(clients);
        drop(tls_clients);
    }

    #[test]
    fn port_rebind_retains_both_listener_families() {
        let _lock = FIXED_PORT_LOCK.lock().unwrap();
        let settings: Settings = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "address_family": "both",
            "bind_address": "",
            "http_bind": "127.0.0.1:0",
            "https_bind": "127.0.0.1:0"
        }))
        .unwrap();
        let mut server = Server::bind(&settings).unwrap();
        let base_port = available_port_pair();

        server.rebind_port(base_port).unwrap();

        let http = server.http_addresses();
        let https = server.https_addresses();
        assert_eq!(http.len(), 2);
        assert_eq!(https.len(), 2);
        assert_eq!(http[0].port(), base_port);
        assert_eq!(http[1].port(), base_port);
        assert_eq!(https[0].port(), crate::settings::https_port(base_port));
        assert_eq!(https[1].port(), crate::settings::https_port(base_port));

        let mut clients = Vec::new();
        for address in &http {
            let peer = if address.is_ipv4() {
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            } else {
                IpAddr::V6(Ipv6Addr::LOCALHOST)
            };
            let mut client = TcpStream::connect(SocketAddr::new(peer, address.port())).unwrap();
            client
                .write_all(b"GET /serverinfo HTTP/1.1\r\nHost: test\r\n\r\n")
                .unwrap();
            clients.push(client);
        }
        let requests = server.tick().requests;
        assert_eq!(requests.len(), 2);
        let peers = requests
            .into_iter()
            .map(|request| request.remote)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            peers,
            [
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST)
            ]
            .into_iter()
            .collect()
        );
        drop(clients);
    }

    #[test]
    fn port_rebind_changes_both_live_listeners_and_preserves_accepted_connections() {
        let _lock = FIXED_PORT_LOCK.lock().unwrap();
        let settings = Settings {
            enabled: true,
            http_bind: "127.0.0.1:0".parse().unwrap(),
            https_bind: "127.0.0.1:0".parse().unwrap(),
            ..Settings::default()
        };
        let mut server = Server::bind(&settings).unwrap();
        let old_http = server.http_address();
        let mut existing_client = TcpStream::connect(old_http).unwrap();
        existing_client
            .write_all(b"GET /serverinfo HTTP/1.1\r\nHost: test\r\n\r\n")
            .unwrap();
        let existing_request = server.tick().requests.pop().unwrap();

        let base_port = available_port_pair();
        server.rebind_port(base_port).unwrap();

        assert_eq!(server.http_address().port(), base_port);
        assert_eq!(
            server.https_address().port(),
            crate::settings::https_port(base_port)
        );
        assert_eq!(server.connections(), 1);

        let mut new_client = TcpStream::connect(server.http_address()).unwrap();
        new_client
            .write_all(b"GET /serverinfo HTTP/1.1\r\nHost: test\r\n\r\n")
            .unwrap();
        let requests = server.tick().requests;
        assert_eq!(requests.len(), 1);
        assert_ne!(requests[0].id, existing_request.id);
        assert_ne!(old_http.port(), base_port);
    }

    #[test]
    fn overlapping_port_moves_reuse_old_listener_sockets_in_both_directions() {
        let _lock = FIXED_PORT_LOCK.lock().unwrap();
        let base_port = available_port_pair();
        let settings = Settings {
            enabled: true,
            http_bind: SocketAddr::from(([127, 0, 0, 1], base_port)),
            https_bind: SocketAddr::from(([127, 0, 0, 1], crate::settings::https_port(base_port))),
            ..Settings::default()
        };
        let mut server = Server::bind(&settings).unwrap();
        let mut accepted_client = TcpStream::connect(server.http_address()).unwrap();
        accepted_client
            .write_all(b"GET /serverinfo HTTP/1.1\r\nHost: test\r\n\r\n")
            .unwrap();
        let accepted_request = server.tick().requests.pop().unwrap();

        let raised_base_port = base_port + crate::settings::HTTPS_PORT_OFFSET;
        server.rebind_port(raised_base_port).unwrap();
        assert_eq!(server.http_address().port(), raised_base_port);
        assert_eq!(server.https_address().port(), base_port);
        assert!(server.connections.contains_key(&accepted_request.id));

        server.rebind_port(base_port).unwrap();
        assert_eq!(server.http_address().port(), base_port);
        assert_eq!(
            server.https_address().port(),
            crate::settings::https_port(base_port)
        );
        assert!(server.connections.contains_key(&accepted_request.id));
    }

    #[test]
    fn failed_second_listener_bind_keeps_the_current_pair_intact() {
        let _lock = FIXED_PORT_LOCK.lock().unwrap();
        let settings = Settings {
            enabled: true,
            http_bind: "127.0.0.1:0".parse().unwrap(),
            https_bind: "127.0.0.1:0".parse().unwrap(),
            ..Settings::default()
        };
        let mut server = Server::bind(&settings).unwrap();
        let old_http = server.http_address();
        let old_https = server.https_address();
        let (_occupied_https, base_port) = (0..100)
            .find_map(|_| {
                let listener = TcpListener::bind("127.0.0.1:0").ok()?;
                let base_port = listener
                    .local_addr()
                    .ok()?
                    .port()
                    .checked_add(crate::settings::HTTPS_PORT_OFFSET)?;
                if crate::settings::validate_port(base_port).is_err() {
                    return None;
                }
                let http_probe =
                    TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], base_port))).ok()?;
                drop(http_probe);
                Some((listener, base_port))
            })
            .expect("find a valid HTTPS port for the occupied-pair test");

        assert!(server.rebind_port(base_port).is_err());
        assert_eq!(server.http_address(), old_http);
        assert_eq!(server.https_address(), old_https);
    }

    #[test]
    #[ignore = "opens wildcard listeners; run explicitly when testing remote binding"]
    fn same_port_wildcard_expansion_rebinds_all_families_before_reporting_active() {
        let _lock = FIXED_PORT_LOCK.lock().unwrap();
        let base_port = available_port_pair();
        let startup = Settings {
            enabled: true,
            allow_remote: true,
            http_bind: SocketAddr::from(([127, 0, 0, 1], base_port)),
            https_bind: SocketAddr::from(([127, 0, 0, 1], crate::settings::https_port(base_port))),
            ..Settings::default()
        };
        let mut server = Server::bind(&startup).unwrap();
        let mut target = startup.clone();
        target.address_family = Some(crate::settings::AddressFamily::Both);
        target.bind_address = Some(String::new());

        server.rebind_settings(&target).unwrap();

        assert!(
            server
                .http_addresses()
                .iter()
                .any(|address| address.is_ipv4())
        );
        assert!(
            server
                .http_addresses()
                .iter()
                .any(|address| address.is_ipv6())
        );
        assert!(
            server
                .http_addresses()
                .iter()
                .all(|address| address.ip().is_unspecified())
        );
        assert!(
            server
                .https_addresses()
                .iter()
                .all(|address| address.ip().is_unspecified())
        );
        let clients = [
            TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], base_port))).unwrap(),
            TcpStream::connect(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), base_port))
                .unwrap(),
        ];
        let _ = server.tick();
        assert_eq!(server.connections(), 2);
        drop(clients);
    }

    #[test]
    fn failed_overlapping_loopback_expansion_restores_both_listener_sets() {
        assert_failed_overlapping_expansion_restores_both_listener_sets(false);
    }

    #[test]
    #[ignore = "opens a wildcard listener; run explicitly when testing remote binding"]
    fn failed_overlapping_wildcard_expansion_restores_both_listener_sets() {
        assert_failed_overlapping_expansion_restores_both_listener_sets(true);
    }

    fn assert_failed_overlapping_expansion_restores_both_listener_sets(allow_remote: bool) {
        let _lock = FIXED_PORT_LOCK.lock().unwrap();
        let (_occupied_ipv6, startup, mut server) = (0..100)
            .find_map(|_| {
                let occupied_ipv6 = bind_listener(
                    SocketAddr::new(
                        IpAddr::V6(if allow_remote {
                            Ipv6Addr::UNSPECIFIED
                        } else {
                            Ipv6Addr::LOCALHOST
                        }),
                        0,
                    ),
                    "IPv6 rollback blocker",
                )
                .ok()?;
                let http_port = occupied_ipv6.local_addr().ok()?.port();
                let https_port = http_port.checked_sub(crate::settings::HTTPS_PORT_OFFSET)?;
                if crate::settings::validate_port(http_port).is_err()
                    || crate::settings::validate_port(https_port).is_err()
                {
                    return None;
                }

                let startup = Settings {
                    enabled: true,
                    http_bind: SocketAddr::from(([127, 0, 0, 1], http_port)),
                    https_bind: SocketAddr::from(([127, 0, 0, 1], https_port)),
                    ..Settings::default()
                };
                let server = Server::bind(&startup).ok()?;
                Some((occupied_ipv6, startup, server))
            })
            .expect("find an IPv6-blocked port pair for the rollback test");
        let old_http = server.http_addresses();
        let old_https = server.https_addresses();
        let mut target = startup;
        target.allow_remote = allow_remote;
        target.address_family = Some(crate::settings::AddressFamily::Both);
        target.bind_address = Some(String::new());

        assert!(server.rebind_settings(&target).is_err());
        assert_eq!(server.http_addresses(), old_http);
        assert_eq!(server.https_addresses(), old_https);
    }

    #[test]
    fn unrelated_occupied_target_port_does_not_drop_current_listeners() {
        let _lock = FIXED_PORT_LOCK.lock().unwrap();
        let startup = Settings {
            enabled: true,
            http_bind: "127.0.0.1:0".parse().unwrap(),
            https_bind: "127.0.0.1:0".parse().unwrap(),
            ..Settings::default()
        };
        let mut server = Server::bind(&startup).unwrap();
        let old_http = server.http_addresses();
        let old_https = server.https_addresses();
        let target_port = available_port_pair();
        let occupied = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], target_port))).unwrap();
        let mut target = startup;
        target.http_bind.set_port(target_port);
        target
            .https_bind
            .set_port(crate::settings::https_port(target_port));

        assert!(server.rebind_settings(&target).is_err());
        assert_eq!(server.http_addresses(), old_http);
        assert_eq!(server.https_addresses(), old_https);
        drop(occupied);
    }

    #[test]
    fn unchanged_listener_does_not_trigger_release_for_unrelated_occupied_peer_port() {
        let _lock = FIXED_PORT_LOCK.lock().unwrap();
        let base_port = available_port_pair();
        let startup = Settings {
            enabled: true,
            http_bind: SocketAddr::from(([127, 0, 0, 1], base_port)),
            https_bind: SocketAddr::from(([127, 0, 0, 1], crate::settings::https_port(base_port))),
            ..Settings::default()
        };
        let mut server = Server::bind(&startup).unwrap();
        let old_http = server.http_addresses();
        let old_https = server.https_addresses();
        let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut target = startup;
        target
            .https_bind
            .set_port(occupied.local_addr().unwrap().port());

        assert!(server.rebind_settings(&target).is_err());
        assert_eq!(server.http_addresses(), old_http);
        assert_eq!(server.https_addresses(), old_https);
        drop(occupied);
    }

    fn available_port_pair() -> u16 {
        for _ in 0..100 {
            let https = TcpListener::bind("127.0.0.1:0").unwrap();
            let Some(base) = https
                .local_addr()
                .unwrap()
                .port()
                .checked_add(crate::settings::HTTPS_PORT_OFFSET)
            else {
                continue;
            };
            if crate::settings::validate_port(base).is_err() {
                continue;
            }
            let Some(raised_base) = base.checked_add(crate::settings::HTTPS_PORT_OFFSET) else {
                continue;
            };
            if crate::settings::validate_port(raised_base).is_err() {
                continue;
            }
            let Ok(http) = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], base))) else {
                continue;
            };
            let Ok(raised_http) =
                TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], raised_base)))
            else {
                continue;
            };
            drop((http, raised_http, https));
            return base;
        }
        panic!("could not reserve an unused local listener port pair");
    }
    #[test]
    fn deferred_request_has_pin_allowance_then_expires_and_reports_cancellation() {
        let settings = Settings {
            enabled: true,
            http_bind: "127.0.0.1:0".parse().unwrap(),
            https_bind: "127.0.0.1:0".parse().unwrap(),
            ..Settings::default()
        };
        let mut server = Server::bind(&settings).unwrap();
        let mut client = TcpStream::connect(server.http_address()).unwrap();
        client
            .write_all(b"GET /pair HTTP/1.1\r\nHost: test\r\n\r\n")
            .unwrap();
        let incoming = server
            .tick()
            .requests
            .pop()
            .expect("complete local request");
        let connection = server.connections.get_mut(&incoming.id).unwrap();
        assert!(connection.waiting);
        assert!(
            connection
                .deadline
                .saturating_duration_since(Instant::now())
                > Duration::from_secs(120)
        );
        connection.deadline = Instant::now();
        assert_eq!(
            server.tick().closed,
            vec![Closed {
                id: incoming.id,
                response_delivered: false,
            }]
        );
        assert_eq!(server.connections(), 0);
    }

    #[test]
    fn saturated_rustls_plaintext_buffer_retains_the_response_for_retry() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let _peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (socket, remote) = listener.accept().unwrap();
        let configuration =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(rustls::server::ResolvesServerCertUsingSni::new()));
        let mut tls = ServerConnection::new(Arc::new(configuration)).unwrap();
        tls.set_buffer_limit(Some(1));
        assert_eq!(tls.writer().write(b"x").unwrap(), 1);
        let mut connection = Connection {
            socket,
            remote: remote.ip(),
            tls: Some(tls),
            input: Vec::new(),
            output: Some(Output {
                bytes: b"response".to_vec(),
                offset: 0,
            }),
            waiting: false,
            finished: false,
            closing: false,
            response_delivered: false,
            deadline: Instant::now() + IO_TIMEOUT,
        };
        connection.write_response().unwrap();
        assert_eq!(connection.output.as_ref().unwrap().offset, 0);
        assert!(!connection.finished);
    }
}
