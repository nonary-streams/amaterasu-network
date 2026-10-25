use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};

use super::*;
use crate::PINHOLE_LEASE_SECONDS;

#[test]
fn ssdp_location_keeps_interface_scope_for_link_local_control() {
    let location = "http://[fe80::1234%25eth0]:49152/root/device.xml";
    let (address, path) = parse_ipv6_http_location(location, 7).unwrap();

    assert_eq!(address.ip(), &"fe80::1234".parse::<Ipv6Addr>().unwrap());
    assert_eq!(address.port(), 49152);
    assert_eq!(address.scope_id(), 7);
    assert_eq!(path, "/root/device.xml");
}

#[test]
fn ssdp_description_finds_ipv6_firewall_service_and_resolves_relative_control_url() {
    let description = Element::parse(
        r#"<root xmlns="urn:schemas-upnp-org:device-1-0"><device><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPv6FirewallControl:1</serviceType><controlURL>control/firewall</controlURL></service></serviceList></device></root>"#.as_bytes(),
    )
    .unwrap();
    let control = find_control_url(&description).unwrap();
    assert_eq!(
        resolve_control_path("/root/device.xml", &control).as_deref(),
        Some("/root/control/firewall")
    );
}

#[test]
fn ssdp_description_url_base_resolves_relative_control_on_same_gateway() {
    let description = Element::parse(
        r#"<root xmlns="urn:schemas-upnp-org:device-1-0"><URLBase>http://[fe80::1%257]:49153/base/</URLBase><device><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPv6FirewallControl:1</serviceType><controlURL>control/firewall</controlURL></service></serviceList></device></root>"#.as_bytes(),
    )
    .unwrap();
    let device_address = SocketAddrV6::new("fe80::1".parse().unwrap(), 49152, 0, 7);
    let control_url = find_control_url(&description).unwrap();

    let (control_address, path) = resolve_control_target(
        &description,
        device_address,
        "/root/device.xml",
        7,
        &control_url,
    )
    .unwrap();

    assert_eq!(
        control_address,
        SocketAddrV6::new("fe80::1".parse().unwrap(), 49153, 0, 7)
    );
    assert_eq!(path, "/base/control/firewall");
}

#[test]
fn ssdp_description_rejects_url_base_on_a_different_gateway() {
    let description = Element::parse(
        r#"<root xmlns="urn:schemas-upnp-org:device-1-0"><URLBase>http://[fe80::2]:49153/base/</URLBase><device><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPv6FirewallControl:1</serviceType><controlURL>control/firewall</controlURL></service></serviceList></device></root>"#.as_bytes(),
    )
    .unwrap();
    let device_address = SocketAddrV6::new("fe80::1".parse().unwrap(), 49152, 0, 7);
    let control_url = find_control_url(&description).unwrap();

    assert!(
        resolve_control_target(
            &description,
            device_address,
            "/root/device.xml",
            7,
            &control_url,
        )
        .is_none()
    );
}

#[test]
fn ipv6_ssdp_fixture_uses_same_source_and_location_gateway() {
    let response = format!(
        "HTTP/1.1 200 OK\r\nST: {IGD_DEVICE_TYPE}\r\nLOCATION: http://[fe80::1%253]:49152/root.xml\r\n\r\n"
    );
    let source = SocketAddr::V6(SocketAddrV6::new("fe80::1".parse().unwrap(), 1900, 0, 3));
    let extracted = parse_ssdp_advertisement(response.as_bytes());
    assert_eq!(
        extracted,
        Some((IGD_DEVICE_TYPE, "http://[fe80::1%253]:49152/root.xml"))
    );
    assert!(source_matches_location(
        source,
        "fe80::1".parse::<Ipv6Addr>().unwrap()
    ));
}

#[test]
fn soap_requests_encode_reference_protocol_numbers_and_arguments() {
    let endpoint = PinholeEndpoint::new("2001:db8::9".parse().unwrap(), 47998, Protocol::Udp);
    let xml = soap_envelope(
        "AddPinhole",
        &[
            ("RemoteHost", "".to_owned()),
            ("RemotePort", "0".to_owned()),
            ("InternalClient", endpoint.internal_client.to_string()),
            ("InternalPort", endpoint.internal_port.to_string()),
            ("Protocol", protocol_number(endpoint.protocol).to_owned()),
            ("LeaseTime", PINHOLE_LEASE_SECONDS.to_string()),
        ],
    );

    assert!(xml.contains("<NewProtocol>17</NewProtocol>"));
    assert!(xml.contains("<NewInternalClient>2001:db8::9</NewInternalClient>"));
    assert!(xml.contains("<NewLeaseTime>3600</NewLeaseTime>"));
    assert!(xml.contains(IPV6_FIREWALL_SERVICE));
}

#[test]
fn status_and_unique_id_soap_values_parse_from_response_fixture() {
    let response = Element::parse(
        br#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:GetFirewallStatusResponse xmlns:u="urn:schemas-upnp-org:service:WANIPv6FirewallControl:1"><NewFirewallEnabled>0</NewFirewallEnabled><NewInboundPinholeAllowed>1</NewInboundPinholeAllowed></u:GetFirewallStatusResponse></s:Body></s:Envelope>"#.as_slice(),
    )
    .unwrap();

    assert!(!xml_boolean(&response, "NewFirewallEnabled").unwrap());
    assert!(xml_boolean(&response, "NewInboundPinholeAllowed").unwrap());
    let id = Element::parse(
        br#"<AddPinholeResponse><NewUniqueID>47</NewUniqueID></AddPinholeResponse>"#.as_slice(),
    )
    .unwrap();
    assert_eq!(
        xml_value(&id, "NewUniqueID")
            .unwrap()
            .parse::<u16>()
            .unwrap(),
        47
    );
}

#[test]
fn content_length_and_path_validation_are_bounded() {
    assert_eq!(
        parse_content_length(b"HTTP/1.1 200 OK\r\nContent-Length: 37\r\n\r\n"),
        Some(37)
    );
    assert!(valid_http_path("/root/control"));
    assert!(!valid_http_path("//other-host/control"));
    assert!(!valid_http_path("/root/\r\nInjected: true"));
}
