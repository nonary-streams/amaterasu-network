//! Socket admission keeps the trusted destination policy outside ENet parsing.
use super::*;
use std::io;

impl Stream {
    pub(super) fn read_socket(&mut self, now: u64) {
        // Receive the entire standard UDP payload before parsing. A short buffer
        // makes Windows report WSAEMSGSIZE before the sender can be filtered.
        let mut buffer = [0; 65_536];
        for _ in 0..32 {
            let Some(socket) = self.socket.as_ref() else {
                return;
            };
            let (length, sender) = match socket.recv_from(&mut buffer) {
                Ok(received) => received,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if ignorable_datagram_error(&error) => {
                    self.rejected_datagrams = self.rejected_datagrams.saturating_add(1);
                    continue;
                }
                Err(_) => {
                    self.fail("udp_receive_failed");
                    return;
                }
            };
            if sender.ip() != self.authorized_ip
                || self
                    .authorized_port
                    .is_some_and(|port| sender.port() != port)
                || self.remote.is_some_and(|remote| remote != sender)
            {
                self.rejected_datagrams = self.rejected_datagrams.saturating_add(1);
                continue;
            }
            match self.peer.receive(&buffer[..length], now) {
                Ok(status) if status.associated => {
                    // CONNECT data is only an admission hint. No control plaintext
                    // is delivered and no native send is allowed until GCM verifies.
                    self.remote.get_or_insert(sender);
                }
                Ok(_) | Err(_) => {
                    self.rejected_datagrams = self.rejected_datagrams.saturating_add(1);
                }
            }
        }
    }

    pub(super) fn flush_socket(&mut self) {
        let Some(remote) = self.remote else {
            return;
        };
        for _ in 0..32 {
            let Some(socket) = self.socket.as_ref() else {
                return;
            };
            if self.pending_datagram.is_none() {
                self.pending_datagram = self.peer.pop_datagram();
            }
            let Some(packet) = self.pending_datagram.as_ref() else {
                return;
            };
            match socket.send_to(packet, remote) {
                Ok(length) if length == packet.len() => {
                    self.pending_datagram = None;
                    self.sent_datagrams = self.sent_datagrams.saturating_add(1);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {
                    return;
                }
                _ => {
                    self.fail("udp_send_failed");
                    return;
                }
            }
        }
    }
}

fn ignorable_datagram_error(error: &io::Error) -> bool {
    // Windows can surface delayed UDP ICMP errors on recv_from. They are not
    // authenticated peer messages; authenticated idle/handshake deadlines still
    // bound resource lifetime. Also tolerate oversized IPv6/jumbo datagrams.
    cfg!(windows) && matches!(error.raw_os_error(), Some(10040 | 10054))
}
