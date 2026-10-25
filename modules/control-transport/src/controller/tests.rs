use super::*;
use std::net::UdpSocket;

pub(crate) fn configured() -> Controller {
    Controller::new(Settings {
        enabled: true,
        allow_remote: false,
        allowed_principals: vec!["alice".into(), "bob".into()],
    })
}

pub(crate) fn request() -> Open {
    serde_json::from_value(json!({
        "peer_ip": "127.0.0.1",
        "connect_data": 17,
        "key_hex": "0123456789abcdef0123456789abcdef",
        "operation_id": "first"
    }))
    .unwrap()
}

#[test]
fn defaults_and_principal_policy_reject_before_allocating() {
    let mut disabled = Controller::new(Settings::default());
    assert_eq!(disabled.open("alice", request()).err(), Some("disabled"));
    let mut controller = configured();
    assert_eq!(
        controller.open("mallory", request()).err(),
        Some("forbidden")
    );
    assert!(controller.streams.is_empty());
    assert!(controller.used_keys.is_empty());
}

#[test]
fn ping_timeout_defaults_and_accepts_only_the_signed_integer_range() {
    let mut request = request();
    assert_eq!(request.ping_timeout_ms, 10_000);
    assert!(request.validate(false).is_ok());

    for value in [0, i32::MAX as i64] {
        request.ping_timeout_ms = value;
        assert!(request.validate(false).is_ok());
    }
    for value in [-1, i32::MAX as i64 + 1] {
        request.ping_timeout_ms = value;
        assert_eq!(request.validate(false), Err("invalid_ping_timeout"));
    }
}

#[test]
fn replay_is_owned_and_closed_identifiers_never_allocate_again() {
    let mut controller = configured();
    let reply = controller.open("alice", request()).unwrap();
    let id = reply.created.unwrap();
    let local = reply.payload["local"].as_str().unwrap().to_owned();
    assert!(!reply.payload.to_string().contains(&request().key_hex));
    let replay = controller.open("alice", request()).unwrap();
    assert_eq!(replay.created, None);
    assert_eq!(replay.payload["stream"], id);
    assert_eq!(controller.close("bob", id), Err("stream_not_found"));
    assert_eq!(controller.status("bob", None)["streams"], json!([]));
    assert!(
        controller
            .handle(
                "bob",
                Operation::Lookup {
                    operation_id: "first".into()
                }
            )
            .is_err()
    );
    let mut conflicting = request();
    conflicting.connect_data += 1;
    assert_eq!(
        controller.open("alice", conflicting).err(),
        Some("operation_conflict")
    );
    controller.close("alice", id).unwrap();
    assert!(UdpSocket::bind(local).is_ok());
    assert_eq!(
        controller.open("alice", request()).err(),
        Some("stream_closed")
    );
    let mut fresh_operation = request();
    fresh_operation.operation_id = Some("second".into());
    assert_eq!(
        controller.open("bob", fresh_operation).err(),
        Some("key_reuse_forbidden")
    );
}

#[test]
fn failed_socket_allocation_does_not_consume_operation_or_key() {
    let occupied = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut specification = request();
    specification.local_bind = Some(occupied.local_addr().unwrap());
    let mut controller = configured();
    assert_eq!(
        controller.open("alice", specification.clone()).err(),
        Some("udp_bind_failed")
    );
    assert!(controller.operations.is_empty());
    assert!(controller.issued_ids.is_empty());
    assert!(controller.used_keys.is_empty());
    drop(occupied);
    assert!(
        controller
            .open("alice", specification)
            .unwrap()
            .created
            .is_some()
    );
}

#[test]
fn invalid_remote_bind_and_key_inputs_fail_before_resource_admission() {
    let mut controller = configured();
    for (field, value, expected) in [
        ("peer_ip", "192.0.2.1", "remote_disabled"),
        ("peer_ip", "::ffff:127.0.0.1", "invalid_peer"),
        ("peer_ip", "239.1.2.3", "invalid_peer"),
        ("local_bind", "0.0.0.0:0", "invalid_bind"),
        ("local_bind", "[::1]:0", "invalid_bind"),
        ("key_hex", "not a key", "invalid_key"),
        ("operation_id", "bad\nname", "invalid_operation_id"),
    ] {
        let mut payload = json!({
            "peer_ip": "127.0.0.1",
            "connect_data": 17,
            "key_hex": "0123456789abcdef0123456789abcdef"
        });
        payload[field] = value.into();
        let request = serde_json::from_value(payload).unwrap();
        assert_eq!(controller.open("alice", request).err(), Some(expected));
    }
    assert!(controller.streams.is_empty());
    assert!(controller.operations.is_empty());
    assert!(controller.used_keys.is_empty());
}

#[test]
fn remote_opt_in_does_not_admit_broadcast_multicast_mapped_or_mismatched_binds() {
    let mut controller = configured();
    controller.settings.allow_remote = true;
    for (peer, local) in [
        ("127.0.0.1", "255.255.255.255:0"),
        ("127.0.0.1", "239.1.2.3:0"),
        ("127.0.0.1", "[::1]:0"),
        ("::1", "[ff02::1]:0"),
        ("::1", "[::ffff:127.0.0.1]:0"),
        ("::1", "127.0.0.1:0"),
    ] {
        let mut specification = request();
        specification.peer_ip = peer.parse().unwrap();
        specification.local_bind = Some(local.parse().unwrap());
        assert_eq!(
            controller.open("alice", specification).err(),
            Some("invalid_bind")
        );
    }
    assert!(controller.streams.is_empty());
    assert!(controller.operations.is_empty());
    assert!(controller.issued_ids.is_empty());
    assert!(controller.used_keys.is_empty());
}
