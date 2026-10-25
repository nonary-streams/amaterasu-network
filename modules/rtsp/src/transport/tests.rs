use super::*;
#[cfg(unix)]
#[test]
fn closed_loopback_connection_allows_immediate_transport_restart() {
    use std::io::Read;
    use std::net::{Shutdown, TcpStream};
    use std::time::Duration;

    let transport = Transport::bind("127.0.0.1:0".parse().unwrap(), false).unwrap();
    let address = transport.local_addr().unwrap();
    let mut client = TcpStream::connect(address).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let (accepted, _) = transport.listeners[0].accept().unwrap();
    accepted.shutdown(Shutdown::Write).unwrap();
    let mut byte = [0];
    assert_eq!(client.read(&mut byte).unwrap(), 0);
    drop(client);
    drop(accepted);
    drop(transport);
    let restarted = Transport::bind(address, false).unwrap();
    assert_eq!(restarted.local_addr().unwrap(), address);
    assert!(Transport::bind(address, false).is_err());
}
use amaterasu_gamestream::{
    crypto::{Direction, RtspOpener, RtspSealer},
    rtsp::serialize_response,
};
use std::{
    io::{Read, Write},
    net::TcpStream,
    time::{Duration, Instant},
};

fn server() -> Transport {
    Transport::bind("127.0.0.1:0".parse().unwrap(), false).unwrap()
}

#[cfg(unix)]
#[test]
fn configured_loopback_port_restarts_without_sharing_an_existing_listener() {
    let server = server();
    let address = server.local_addr().unwrap();
    assert!(Transport::bind(address, false).is_err());
    drop(server);

    let restarted = Transport::bind(address, false).unwrap();
    assert_eq!(restarted.local_addr().unwrap(), address);
}

fn request(cseq: u32) -> Vec<u8> {
    format!("OPTIONS rtsp://localhost/ RTSP/1.0\r\nCSeq: {cseq}\r\n\r\n").into_bytes()
}
fn connect(server: &Transport, bytes: &[u8]) -> TcpStream {
    let mut client =
        TcpStream::connect_timeout(&server.local_addr().unwrap(), Duration::from_secs(1)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    client.write_all(bytes).unwrap();
    client
}
fn next_event(server: &mut Transport) -> Event {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let mut events = server.poll(1);
        if !events.is_empty() {
            assert_eq!(events.len(), 1);
            return events.remove(0);
        }
        assert!(Instant::now() < deadline, "bounded event wait");
        std::thread::sleep(Duration::from_millis(1));
    }
}
fn authenticated(server: &mut Transport) -> (u64, u64, Request) {
    let Event::Request {
        connection,
        ticket,
        request,
    } = next_event(server)
    else {
        panic!("expected request");
    };
    (connection, ticket, request)
}
fn disconnected(server: &mut Transport) -> (&'static str, Option<u64>) {
    let Event::Disconnected { reason, ticket, .. } = next_event(server) else {
        panic!("unexpected request");
    };
    (reason, ticket)
}

#[test]
fn real_tcp_transactions_share_response_sequence_and_replay_state() {
    let mut server = server();
    let key = [31; 16];
    server
        .add_ticket(7, "127.0.0.1".parse().unwrap(), &key)
        .unwrap();
    let mut client_sealer = RtspSealer::new(&key, Direction::ClientToHost).unwrap();
    let mut client_opener = RtspOpener::new(&key, Direction::HostToClient).unwrap();
    let first = client_sealer.seal(&request(1)).unwrap();
    for sequence in 1..=2 {
        let envelope = if sequence == 1 {
            first.clone()
        } else {
            client_sealer.seal(&request(sequence)).unwrap()
        };
        let mut client = connect(&server, &envelope);
        let (connection, ticket, decoded) = authenticated(&mut server);
        assert_eq!((ticket, decoded.cseq), (7, sequence));
        let response = serialize_response(200, sequence, &[], b"ok").unwrap();
        server.reply(connection, &response).unwrap();
        assert_eq!(
            server.reply(connection, &response),
            Err("connection_not_waiting")
        );
        assert_eq!(disconnected(&mut server), ("response_complete", Some(7)));
        let mut received = Vec::new();
        client.read_to_end(&mut received).unwrap();
        let message = client_opener.open(&received).unwrap();
        assert_eq!(message.sequence, sequence);
        assert_eq!(message.plaintext, response);
    }
    let _replay = connect(&server, &first);
    assert_eq!(
        disconnected(&mut server),
        ("request_authentication_failed", None)
    );
}

#[test]
fn dual_family_transport_accepts_v4_and_v6_on_the_same_port() {
    let mut server = Transport::bind_all(
        vec!["127.0.0.1:0".parse().unwrap(), "[::1]:0".parse().unwrap()],
        false,
    )
    .unwrap();
    let addresses = server.local_addrs().unwrap();
    assert_eq!(addresses.len(), 2);
    assert_eq!(addresses[0].port(), addresses[1].port());

    for (ticket, address, peer, key) in [
        (11, addresses[0], "127.0.0.1".parse().unwrap(), [11; 16]),
        (12, addresses[1], "::1".parse().unwrap(), [12; 16]),
    ] {
        server.add_ticket(ticket, peer, &key).unwrap();
        let envelope = RtspSealer::new(&key, Direction::ClientToHost)
            .unwrap()
            .seal(&request(ticket as u32))
            .unwrap();
        let mut client = TcpStream::connect_timeout(&address, Duration::from_secs(1)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        client.write_all(&envelope).unwrap();
        let (connection, accepted_ticket, decoded) = authenticated(&mut server);
        assert_eq!(accepted_ticket, ticket);
        assert_eq!(decoded.cseq, ticket as u32);
        let response = serialize_response(200, ticket as u32, &[], b"family ok").unwrap();
        server.reply(connection, &response).unwrap();
        assert_eq!(
            disconnected(&mut server),
            ("response_complete", Some(ticket))
        );
        let mut received = Vec::new();
        client.read_to_end(&mut received).unwrap();
        assert_eq!(
            RtspOpener::new(&key, Direction::HostToClient)
                .unwrap()
                .open(&received)
                .unwrap()
                .plaintext,
            response
        );
    }
}

#[test]
fn same_ip_candidates_require_decryption_and_failed_trial_preserves_valid_sequence() {
    let mut server = server();
    for id in 1..=2 {
        server
            .add_ticket(id, "127.0.0.1".parse().unwrap(), &[id as u8; 16])
            .unwrap();
    }
    let mut second = RtspSealer::new(&[2; 16], Direction::ClientToHost).unwrap();
    let valid = second.seal(&request(9)).unwrap();
    let mut corrupt = valid.clone();
    corrupt[8] ^= 1;
    let _corrupt = connect(&server, &corrupt);
    assert_eq!(disconnected(&mut server).0, "request_authentication_failed");
    let _client = connect(&server, &valid);
    let (_, ticket, request) = authenticated(&mut server);
    assert_eq!((ticket, request.cseq), (2, 9));
}

#[test]
fn plaintext_and_authenticated_trailing_requests_never_dispatch() {
    for plaintext_mode in [true, false] {
        let mut server = server();
        let key = [4; 16];
        server
            .add_ticket(1, "127.0.0.1".parse().unwrap(), &key)
            .unwrap();
        let bytes = if plaintext_mode {
            request(1)
        } else {
            let mut trailing = request(1);
            trailing.extend_from_slice(&request(2));
            RtspSealer::new(&key, Direction::ClientToHost)
                .unwrap()
                .seal(&trailing)
                .unwrap()
        };
        let mut client = connect(&server, &bytes);
        let (reason, ticket) = disconnected(&mut server);
        assert_eq!(
            reason,
            if plaintext_mode {
                "invalid_encrypted_frame"
            } else {
                "multiple_rtsp_requests"
            }
        );
        assert_eq!(ticket, if plaintext_mode { None } else { Some(1) });
        let mut output = Vec::new();
        let _ = client.read_to_end(&mut output);
        assert!(output.is_empty());
    }
}

#[test]
fn fragmented_tcp_input_dispatches_only_after_complete_envelope() {
    let mut server = server();
    server
        .add_ticket(1, "127.0.0.1".parse().unwrap(), &[5; 16])
        .unwrap();
    let envelope = RtspSealer::new(&[5; 16], Direction::ClientToHost)
        .unwrap()
        .seal(&request(8))
        .unwrap();
    let mut client = connect(&server, &envelope[..3]);
    assert!(server.poll(0).is_empty());
    client.write_all(&envelope[3..]).unwrap();
    assert_eq!(authenticated(&mut server).2.cseq, 8);
}

#[test]
fn disconnect_revocation_and_deadlines_produce_cancellation_events() {
    for mode in 0..3 {
        let mut server = server();
        server
            .add_ticket(1, "127.0.0.1".parse().unwrap(), &[6; 16])
            .unwrap();
        let envelope = RtspSealer::new(&[6; 16], Direction::ClientToHost)
            .unwrap()
            .seal(&request(1))
            .unwrap();
        let client = connect(&server, &envelope);
        let (connection, _, _) = authenticated(&mut server);
        let event = match mode {
            0 => {
                drop(client);
                next_event(&mut server)
            }
            1 => server.remove_ticket(1).remove(0),
            _ => server.poll(15_001).remove(0),
        };
        let Event::Disconnected {
            connection: closed,
            ticket,
            reason,
        } = event
        else {
            panic!("expected close");
        };
        assert_eq!((closed, ticket), (connection, Some(1)));
        assert_eq!(
            reason,
            ["peer_closed", "ticket_revoked", "connection_deadline"][mode]
        );
        assert_eq!(server.connection_count(), 0);
        assert_eq!(
            server.reply(connection, b"late"),
            Err("connection_not_found")
        );
    }
}

#[test]
fn ticket_limits_peer_binding_and_history_prevent_nonce_reset() {
    let mut tickets = Tickets::default();
    let peer = "127.0.0.1".parse().unwrap();
    tickets.add(1, peer, &[1; 16]).unwrap();
    let envelope = RtspSealer::new(&[1; 16], Direction::ClientToHost)
        .unwrap()
        .seal(&request(1))
        .unwrap();
    assert!(
        tickets
            .authenticate("127.0.0.2".parse().unwrap(), &envelope)
            .is_err()
    );
    assert_eq!(tickets.authenticate(peer, &envelope).unwrap().0, 1);
    tickets.remove(1);
    assert_eq!(tickets.add(1, peer, &[2; 16]), Err("ticket_id_reused"));
    assert_eq!(tickets.add(2, peer, &[1; 16]), Err("ticket_key_reused"));
    for id in 2..=128 {
        tickets.add(id, peer, &[id as u8; 16]).unwrap();
        tickets.remove(id);
    }
    assert_eq!(
        tickets.add(129, peer, &[129; 16]),
        Err("ticket_history_limit")
    );
    assert!(Transport::bind("0.0.0.0:0".parse().unwrap(), false).is_err());
}

#[test]
fn uncompleted_input_and_connection_flood_stay_bounded() {
    let mut server = server();
    server
        .add_ticket(1, "127.0.0.1".parse().unwrap(), &[7; 16])
        .unwrap();
    let _clients: Vec<_> = (0..12).map(|_| connect(&server, &[0x80])).collect();
    for _ in 0..4 {
        assert!(server.poll(0).is_empty());
    }
    assert_eq!(server.connection_count(), MAX_CONNECTIONS_PER_IP);
    let events = server.poll(10_000);
    assert_eq!(events.len(), MAX_CONNECTIONS_PER_IP);
    assert!(events.iter().all(|event| matches!(
        event,
        Event::Disconnected {
            reason: "connection_deadline",
            ..
        }
    )));
    assert_eq!(server.connection_count(), 0);
}

#[test]
fn response_admission_and_write_deadline_are_bounded() {
    let mut server = server();
    server
        .add_ticket(1, "127.0.0.1".parse().unwrap(), &[8; 16])
        .unwrap();
    let envelope = RtspSealer::new(&[8; 16], Direction::ClientToHost)
        .unwrap()
        .seal(&request(1))
        .unwrap();
    let _client = connect(&server, &envelope);
    let (connection, _, _) = authenticated(&mut server);
    assert_eq!(server.reply(connection, &[]), Err("invalid_response_size"));
    assert_eq!(
        server.reply(connection, &vec![0; MAX_RTSP_PLAINTEXT_BYTES + 1]),
        Err("invalid_response_size")
    );
    let response = serialize_response(200, 1, &[], &vec![1; 64 * 1024]).unwrap();
    server.reply(connection, &response).unwrap();
    // One tick writes at most 16 KiB, so the response cannot finish this tick even
    // when the kernel would accept the whole message without backpressure.
    assert!(server.poll(2).is_empty());
    assert_eq!(server.connection_count(), 1);
    let events = server.poll(10_001);
    assert!(matches!(
        events.as_slice(),
        [Event::Disconnected {
            reason: "connection_deadline",
            ..
        }]
    ));
}
