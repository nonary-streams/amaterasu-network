use std::io::{self, Read, Write};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol as SocketProtocol, SockAddr, Socket, Type};
use xmltree::{Element, XMLNode};

use crate::{
    GatewayError, Ipv6FirewallControl, PinholeDeleteOutcome, PinholeEndpoint,
    PinholeRefreshOutcome, Protocol,
};

/// Maximum time spent waiting for responses on one IPv6 interface.
pub const IPV6_SEARCH_TIMEOUT: Duration = Duration::from_secs(2);

const SSDP_GROUP: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x000c);
const SSDP_PORT: u16 = 1900;
const IGD_DEVICE_TYPE: &str = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";
const IPV6_FIREWALL_SERVICE: &str = "urn:schemas-upnp-org:service:WANIPv6FirewallControl:1";
const MAX_SSDP_RESPONSE_BYTES: usize = 8 * 1024;
const MAX_DESCRIPTION_BYTES: usize = 256 * 1024;
const MAX_SOAP_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_HTTP_HEADER_BYTES: usize = 16 * 1024;
const HTTP_TIMEOUT: Duration = Duration::from_secs(3);

/// A non-loopback IPv6 address and the interface needed to scope link-local multicast.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Ipv6InterfaceAddress {
    pub address: Ipv6Addr,
    pub interface_index: u32,
}

/// A discovered WANIPv6FirewallControl service on one LAN interface.
pub struct IgdIpv6Firewall {
    control_address: SocketAddrV6,
    control_path: String,
    internal_addresses: Vec<Ipv6Addr>,
    identity: String,
}

impl IgdIpv6Firewall {
    /// Preferred host IPv6 address for wildcard listeners on this interface.
    pub fn internal_address(&self) -> Ipv6Addr {
        self.internal_addresses[0]
    }

    /// Routable host IPv6 addresses available on the discovered interface.
    pub fn internal_addresses(&self) -> &[Ipv6Addr] {
        &self.internal_addresses
    }

    /// Stable identity used to retain IDs only for the same gateway service.
    pub fn identity(&self) -> &str {
        &self.identity
    }
}

/// Enumerates routable IPv6 unicast addresses and their interface scopes.
pub fn ipv6_interface_addresses() -> Result<Vec<Ipv6InterfaceAddress>, GatewayError> {
    platform::ipv6_interface_addresses()
}

/// Discovers IPv6 IGDs separately with scoped `ff02::c` SSDP searches.
pub fn discover_ipv6_firewalls() -> Result<Vec<IgdIpv6Firewall>, GatewayError> {
    let addresses = ipv6_interface_addresses()?;
    let mut interface_addresses = std::collections::BTreeMap::<u32, Vec<Ipv6Addr>>::new();
    for entry in addresses {
        if entry.address.is_unspecified()
            || entry.address.is_loopback()
            || entry.address.is_multicast()
            || entry.address.is_unicast_link_local()
            || entry.interface_index == 0
        {
            continue;
        }
        interface_addresses
            .entry(entry.interface_index)
            .or_default()
            .push(entry.address);
    }

    let mut discovered = Vec::new();
    let mut interface_errors = Vec::new();
    for (interface_index, mut internal_addresses) in interface_addresses {
        internal_addresses.sort();
        internal_addresses.dedup();
        let Some(internal_address) = internal_addresses.first().copied() else {
            continue;
        };
        match discover_on_interface(interface_index, internal_address, &internal_addresses) {
            Ok(Some(firewall))
                if !discovered
                    .iter()
                    .any(|existing: &IgdIpv6Firewall| existing.identity == firewall.identity) =>
            {
                discovered.push(firewall);
            }
            Ok(Some(_)) | Ok(None) => {}
            Err(error) => interface_errors.push(error.to_string()),
        }
    }
    if discovered.is_empty() && !interface_errors.is_empty() {
        return Err(GatewayError::new(format!(
            "IPv6 IGD discovery failed on {} interface(s): {}",
            interface_errors.len(),
            interface_errors.join("; ")
        )));
    }
    Ok(discovered)
}

fn discover_on_interface(
    interface_index: u32,
    internal_address: Ipv6Addr,
    internal_addresses: &[Ipv6Addr],
) -> Result<Option<IgdIpv6Firewall>, GatewayError> {
    let socket = create_ssdp_socket(interface_index, internal_address)?;
    let request = format!(
        "M-SEARCH * HTTP/1.1\r\nHOST: [FF02::C]:{SSDP_PORT}\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {IGD_DEVICE_TYPE}\r\n\r\n"
    );
    let destination = SocketAddr::V6(SocketAddrV6::new(SSDP_GROUP, SSDP_PORT, 0, interface_index));
    socket
        .send_to(request.as_bytes(), destination)
        .map_err(|error| GatewayError::new(format!("IPv6 IGD search failed: {error}")))?;

    let deadline = Instant::now() + IPV6_SEARCH_TIMEOUT;
    let mut response_buffer = [0u8; MAX_SSDP_RESPONSE_BYTES];
    while Instant::now() < deadline {
        socket
            .set_read_timeout(Some(deadline.saturating_duration_since(Instant::now())))
            .map_err(|error| GatewayError::new(format!("IPv6 IGD search failed: {error}")))?;
        let (read, source) = match socket.recv_from(&mut response_buffer) {
            Ok(response) => response,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(None);
            }
            Err(error) => {
                return Err(GatewayError::new(format!(
                    "IPv6 IGD response read failed: {error}"
                )));
            }
        };
        let response = &response_buffer[..read];
        if let Some(firewall) = parse_ssdp_response(
            response,
            source,
            interface_index,
            internal_address,
            internal_addresses,
        )? {
            return Ok(Some(firewall));
        }
    }
    Ok(None)
}

fn create_ssdp_socket(
    interface_index: u32,
    internal_address: Ipv6Addr,
) -> Result<UdpSocket, GatewayError> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(SocketProtocol::UDP))
        .map_err(|error| GatewayError::new(format!("IPv6 IGD socket failed: {error}")))?;
    socket
        .set_only_v6(true)
        .map_err(|error| GatewayError::new(format!("IPv6 IGD socket failed: {error}")))?;
    socket
        .set_multicast_if_v6(interface_index)
        .map_err(|error| GatewayError::new(format!("IPv6 interface selection failed: {error}")))?;
    socket
        .set_multicast_hops_v6(2)
        .map_err(|error| GatewayError::new(format!("IPv6 IGD socket failed: {error}")))?;
    socket
        .bind(&SockAddr::from(SocketAddrV6::new(
            internal_address,
            0,
            0,
            interface_index,
        )))
        .map_err(|error| GatewayError::new(format!("IPv6 IGD socket bind failed: {error}")))?;
    socket
        .join_multicast_v6(&SSDP_GROUP, interface_index)
        .map_err(|error| GatewayError::new(format!("IPv6 IGD multicast join failed: {error}")))?;
    let socket: UdpSocket = socket.into();
    Ok(socket)
}

fn parse_ssdp_response(
    response: &[u8],
    source: SocketAddr,
    interface_index: u32,
    internal_address: Ipv6Addr,
    internal_addresses: &[Ipv6Addr],
) -> Result<Option<IgdIpv6Firewall>, GatewayError> {
    let Some((target, location)) = parse_ssdp_advertisement(response) else {
        return Ok(None);
    };
    if target != IGD_DEVICE_TYPE {
        return Ok(None);
    }
    let Some((device_address, device_path)) = parse_ipv6_http_location(location, interface_index)
    else {
        return Ok(None);
    };
    if !source_matches_location(source, *device_address.ip()) {
        return Ok(None);
    }
    let description = http_request(
        device_address,
        &device_path,
        "GET",
        &[],
        None,
        MAX_DESCRIPTION_BYTES,
    )?;
    if description.status != 200 {
        return Ok(None);
    }
    let root = Element::parse(description.body.as_slice())
        .map_err(|error| GatewayError::new(format!("invalid IPv6 IGD description: {error}")))?;
    let Some(control_path) = find_control_url(&root) else {
        return Ok(None);
    };
    let Some((control_address, control_path)) = resolve_control_target(
        &root,
        device_address,
        &device_path,
        interface_index,
        &control_path,
    ) else {
        return Ok(None);
    };
    let identity = format!("{control_address}|{control_path}|{internal_address}");
    Ok(Some(IgdIpv6Firewall {
        control_address,
        control_path,
        internal_addresses: internal_addresses.to_vec(),
        identity,
    }))
}

fn resolve_control_target(
    root: &Element,
    device_address: SocketAddrV6,
    device_path: &str,
    interface_index: u32,
    control_url: &str,
) -> Option<(SocketAddrV6, String)> {
    if control_url.starts_with("http://") {
        let (address, path) = parse_ipv6_http_location(control_url, interface_index)?;
        if address.ip() != device_address.ip() {
            return None;
        }
        return Some((address, path));
    }
    let (control_address, base_path) = match child_text(root, "URLBase") {
        Some(url_base) => {
            let (url_base_address, url_base_path) =
                parse_ipv6_http_location(&url_base, interface_index)?;
            if url_base_address.ip() != device_address.ip() || url_base_path.contains(['?', '#']) {
                return None;
            }
            (url_base_address, url_base_path)
        }
        None => (device_address, device_path.to_owned()),
    };
    let control_path = resolve_control_path(&base_path, control_url)?;
    Some((control_address, control_path))
}

fn parse_ssdp_advertisement(response: &[u8]) -> Option<(&str, &str)> {
    let text = std::str::from_utf8(response).ok()?;
    let (status_line, headers) = text.split_once("\r\n")?;
    if !status_line.contains(" 200 ") {
        return None;
    }
    let mut target = None;
    let mut location = None;
    for line in headers.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("st") {
            target = Some(value.trim());
        } else if name.eq_ignore_ascii_case("location") {
            location = Some(value.trim());
        }
    }
    Some((target?, location?))
}

fn source_matches_location(source: SocketAddr, location: Ipv6Addr) -> bool {
    matches!(source, SocketAddr::V6(source) if *source.ip() == location)
}

fn parse_ipv6_http_location(
    location: &str,
    interface_index: u32,
) -> Option<(SocketAddrV6, String)> {
    let location = location.strip_prefix("http://")?;
    let authority_end = location.find(['/', '?', '#']).unwrap_or(location.len());
    let authority = &location[..authority_end];
    let path = &location[authority_end..];
    if authority.contains('@') || authority.is_empty() {
        return None;
    }
    let (host, port) = authority.strip_prefix('[')?.split_once(']')?;
    let address_part = host
        .split_once('%')
        .map_or(host, |(address, _scope)| address);
    let address = address_part.parse::<Ipv6Addr>().ok()?;
    let port = match port.strip_prefix(':') {
        Some(port) => port.parse::<u16>().ok()?,
        None if port.is_empty() => 80,
        None => return None,
    };
    if port == 0 {
        return None;
    }
    let path = if path.is_empty() { "/" } else { path };
    if !path.starts_with('/') || path.contains(['\r', '\n']) || path.starts_with("//") {
        return None;
    }
    Some((
        SocketAddrV6::new(address, port, 0, interface_index),
        path.to_owned(),
    ))
}

fn find_control_url(root: &Element) -> Option<String> {
    if root.name == "service"
        && child_text(root, "serviceType").as_deref() == Some(IPV6_FIREWALL_SERVICE)
    {
        return child_text(root, "controlURL");
    }
    root.children
        .iter()
        .filter_map(XMLNode::as_element)
        .find_map(find_control_url)
}

fn child_text(parent: &Element, name: &str) -> Option<String> {
    parent
        .get_child(name)?
        .get_text()
        .map(|text| text.trim().to_owned())
        .filter(|text| !text.is_empty())
}

fn resolve_control_path(root_path: &str, control_url: &str) -> Option<String> {
    if control_url.starts_with("http://") {
        return None;
    }
    if control_url.starts_with('/') {
        return valid_http_path(control_url).then(|| control_url.to_owned());
    }
    let base = root_path
        .rsplit_once('/')
        .map(|(prefix, _)| {
            if prefix.is_empty() {
                "/".to_owned()
            } else {
                format!("{prefix}/")
            }
        })
        .unwrap_or_else(|| "/".to_owned());
    let resolved = format!("{base}{control_url}");
    valid_http_path(&resolved).then_some(resolved)
}

fn valid_http_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.starts_with("//")
        && !path.contains(['\r', '\n', ' '])
        && !path.contains('#')
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

fn http_request(
    address: SocketAddrV6,
    path: &str,
    method: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    max_body_bytes: usize,
) -> Result<HttpResponse, GatewayError> {
    if !valid_http_path(path) {
        return Err(GatewayError::new("invalid IPv6 IGD HTTP path"));
    }
    let stream = TcpStream::connect_timeout(&SocketAddr::V6(address), HTTP_TIMEOUT)
        .map_err(|error| GatewayError::new(format!("IPv6 IGD HTTP connection failed: {error}")))?;
    stream
        .set_read_timeout(Some(HTTP_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(HTTP_TIMEOUT)))
        .map_err(|error| GatewayError::new(format!("IPv6 IGD HTTP setup failed: {error}")))?;

    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: [{}]:{}\r\nConnection: close\r\n",
        address.ip(),
        address.port()
    );
    for (name, value) in headers {
        if name.contains(['\r', '\n', ':']) || value.contains(['\r', '\n']) {
            return Err(GatewayError::new("invalid IPv6 IGD HTTP header"));
        }
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    if let Some(body) = body {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
        request.push_str("\r\n");
        let mut stream = stream;
        stream
            .write_all(request.as_bytes())
            .and_then(|()| stream.write_all(body))
            .map_err(|error| GatewayError::new(format!("IPv6 IGD HTTP write failed: {error}")))?;
        read_http_response(stream, max_body_bytes)
    } else {
        request.push_str("\r\n");
        let mut stream = stream;
        stream
            .write_all(request.as_bytes())
            .map_err(|error| GatewayError::new(format!("IPv6 IGD HTTP write failed: {error}")))?;
        read_http_response(stream, max_body_bytes)
    }
}

fn read_http_response(
    mut stream: TcpStream,
    max_body_bytes: usize,
) -> Result<HttpResponse, GatewayError> {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut header_end = None;
    let mut expected_body_length = None;
    loop {
        let read = stream
            .read(&mut chunk)
            .map_err(|error| GatewayError::new(format!("IPv6 IGD HTTP read failed: {error}")))?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..read]);
        if bytes.len() > max_body_bytes + MAX_HTTP_HEADER_BYTES {
            return Err(GatewayError::new(
                "IPv6 IGD HTTP response exceeded its size bound",
            ));
        }
        if header_end.is_none()
            && let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n")
        {
            let end = position + 4;
            header_end = Some(end);
            expected_body_length = parse_content_length(&bytes[..end]);
            if expected_body_length.is_some_and(|length| length > max_body_bytes) {
                return Err(GatewayError::new(
                    "IPv6 IGD HTTP response exceeded its size bound",
                ));
            }
        }
        if let (Some(header_end), Some(body_length)) = (header_end, expected_body_length)
            && bytes.len() >= header_end + body_length
        {
            bytes.truncate(header_end + body_length);
            break;
        }
    }
    let header_end =
        header_end.ok_or_else(|| GatewayError::new("invalid IPv6 IGD HTTP response"))?;
    let headers = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| GatewayError::new("invalid IPv6 IGD HTTP headers"))?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .ok_or_else(|| GatewayError::new("invalid IPv6 IGD HTTP status"))?;
    let body = bytes[header_end..].to_vec();
    Ok(HttpResponse { status, body })
}

fn parse_content_length(headers: &[u8]) -> Option<usize> {
    std::str::from_utf8(headers)
        .ok()?
        .lines()
        .skip(1)
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
}

impl Ipv6FirewallControl for IgdIpv6Firewall {
    fn firewall_status(&mut self) -> Result<crate::FirewallStatus, GatewayError> {
        let response = self.soap_action("GetFirewallStatus", &[])?;
        let firewall_enabled = xml_boolean(&response, "NewFirewallEnabled")?;
        let pinhole_allowed = xml_boolean(&response, "NewInboundPinholeAllowed")?;
        Ok(crate::FirewallStatus {
            firewall_enabled,
            pinhole_allowed,
        })
    }

    fn add_pinhole(
        &mut self,
        endpoint: PinholeEndpoint,
        lease_duration_seconds: u32,
    ) -> Result<u16, GatewayError> {
        if !valid_pinhole_endpoint(endpoint) {
            return Err(GatewayError::new("invalid IPv6 pinhole endpoint"));
        }
        let parameters = [
            ("RemoteHost", "".to_owned()),
            ("RemotePort", "0".to_owned()),
            ("InternalClient", endpoint.internal_client.to_string()),
            ("InternalPort", endpoint.internal_port.to_string()),
            ("Protocol", protocol_number(endpoint.protocol).to_owned()),
            ("LeaseTime", lease_duration_seconds.to_string()),
        ];
        let response = self.soap_action("AddPinhole", &parameters)?;
        xml_value(&response, "NewUniqueID")?
            .parse::<u16>()
            .map_err(|_| GatewayError::new("IPv6 gateway returned an invalid pinhole ID"))
    }

    fn refresh_pinhole(
        &mut self,
        unique_id: u16,
        lease_duration_seconds: u32,
    ) -> Result<PinholeRefreshOutcome, GatewayError> {
        match self.soap_action(
            "UpdatePinhole",
            &[
                ("UniqueID", unique_id.to_string()),
                ("LeaseTime", lease_duration_seconds.to_string()),
            ],
        ) {
            Ok(_) => Ok(PinholeRefreshOutcome::Refreshed),
            Err(error) if soap_error_code(&error) == Some(704) => {
                Ok(PinholeRefreshOutcome::Missing)
            }
            Err(error) => Err(error),
        }
    }

    fn delete_pinhole(&mut self, unique_id: u16) -> Result<PinholeDeleteOutcome, GatewayError> {
        match self.soap_action("DeletePinhole", &[("UniqueID", unique_id.to_string())]) {
            Ok(_) => Ok(PinholeDeleteOutcome::Deleted),
            Err(error) if soap_error_code(&error) == Some(704) => Ok(PinholeDeleteOutcome::Missing),
            Err(error) => Err(error),
        }
    }
}

impl IgdIpv6Firewall {
    fn soap_action(
        &self,
        action: &str,
        parameters: &[(&str, String)],
    ) -> Result<Element, GatewayError> {
        let body = soap_envelope(action, parameters);
        let action_header = format!("\"{IPV6_FIREWALL_SERVICE}#{action}\"");
        let response = http_request(
            self.control_address,
            &self.control_path,
            "POST",
            &[
                ("Content-Type", "text/xml; charset=\"utf-8\""),
                ("SOAPAction", &action_header),
            ],
            Some(body.as_bytes()),
            MAX_SOAP_RESPONSE_BYTES,
        )?;
        let root = Element::parse(response.body.as_slice())
            .map_err(|error| GatewayError::new(format!("invalid IPv6 SOAP response: {error}")))?;
        if response.status != 200 {
            let (code, description) = soap_fault(&root);
            return Err(GatewayError::new(format!(
                "IPv6 gateway rejected {action} with fault {code}: {description}"
            )));
        }
        Ok(root)
    }
}

fn soap_envelope(action: &str, parameters: &[(&str, String)]) -> String {
    let mut body = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:{action} xmlns:u=\"{IPV6_FIREWALL_SERVICE}\">"
    );
    for (name, value) in parameters {
        body.push_str(&format!("<New{name}>{}</New{name}>", xml_escape(value)));
    }
    body.push_str(&format!("</u:{action}></s:Body></s:Envelope>"));
    body
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn xml_value(root: &Element, name: &str) -> Result<String, GatewayError> {
    find_child_recursive(root, name)
        .and_then(Element::get_text)
        .map(|text| text.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| GatewayError::new(format!("IPv6 gateway response omitted {name}")))
}

fn xml_boolean(root: &Element, name: &str) -> Result<bool, GatewayError> {
    match xml_value(root, name)?.as_str() {
        "1" | "true" | "yes" => Ok(true),
        "0" | "false" | "no" => Ok(false),
        _ => Err(GatewayError::new(format!(
            "IPv6 gateway returned an invalid {name} value"
        ))),
    }
}

fn soap_fault(root: &Element) -> (String, String) {
    let code = find_child_recursive(root, "errorCode")
        .and_then(Element::get_text)
        .map(|value| value.trim().to_owned())
        .unwrap_or_else(|| "unknown".into());
    let description = find_child_recursive(root, "errorDescription")
        .and_then(Element::get_text)
        .map(|value| value.trim().to_owned())
        .unwrap_or_else(|| "no description".into());
    (code, description)
}

fn soap_error_code(error: &GatewayError) -> Option<u16> {
    let message = error.to_string();
    let rest = message.split_once("fault ")?.1;
    rest.split(':').next()?.parse().ok()
}

fn find_child_recursive<'a>(element: &'a Element, name: &str) -> Option<&'a Element> {
    if element.name == name {
        return Some(element);
    }
    element
        .children
        .iter()
        .filter_map(XMLNode::as_element)
        .find_map(|child| find_child_recursive(child, name))
}

fn protocol_number(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "6",
        Protocol::Udp => "17",
    }
}

fn valid_pinhole_endpoint(endpoint: PinholeEndpoint) -> bool {
    endpoint.internal_port != 0
        && !endpoint.internal_client.is_unspecified()
        && !endpoint.internal_client.is_loopback()
        && !endpoint.internal_client.is_multicast()
        && !endpoint.internal_client.is_unicast_link_local()
}

#[cfg(unix)]
mod platform {
    use super::{GatewayError, Ipv6Addr, Ipv6InterfaceAddress};
    use std::{io, ptr};

    pub(super) fn ipv6_interface_addresses() -> Result<Vec<Ipv6InterfaceAddress>, GatewayError> {
        let mut first_address = ptr::null_mut();
        // SAFETY: `getifaddrs` initializes the out pointer on success. The linked list is
        // traversed while alive and released exactly once by `freeifaddrs` below.
        if unsafe { libc::getifaddrs(&mut first_address) } != 0 {
            return Err(GatewayError::new(format!(
                "IPv6 interface enumeration failed: {}",
                io::Error::last_os_error()
            )));
        }

        let mut addresses = Vec::new();
        let mut current = first_address;
        while !current.is_null() {
            // SAFETY: `current` points into the valid list returned by getifaddrs.
            let interface = unsafe { &*current };
            if !interface.ifa_addr.is_null()
                // SAFETY: the first field of sockaddr is its address family.
                && unsafe { (*interface.ifa_addr).sa_family as i32 } == libc::AF_INET6
                && !interface.ifa_name.is_null()
            {
                // SAFETY: AF_INET6 above guarantees the pointed structure is sockaddr_in6.
                let address = unsafe {
                    let socket_address = &*interface.ifa_addr.cast::<libc::sockaddr_in6>();
                    Ipv6Addr::from(socket_address.sin6_addr.s6_addr)
                };
                // SAFETY: ifa_name is a NUL-terminated interface name owned by this list.
                let interface_index = unsafe { libc::if_nametoindex(interface.ifa_name) };
                if interface_index != 0
                    && !address.is_unspecified()
                    && !address.is_loopback()
                    && !address.is_multicast()
                {
                    addresses.push(Ipv6InterfaceAddress {
                        address,
                        interface_index,
                    });
                }
            }
            // SAFETY: current is a valid ifaddrs node; ifa_next links within the same list.
            current = unsafe { (*current).ifa_next };
        }
        // SAFETY: this is the original successful getifaddrs allocation.
        unsafe { libc::freeifaddrs(first_address) };
        addresses.sort();
        addresses.dedup();
        Ok(addresses)
    }
}

#[cfg(windows)]
mod platform {
    use super::{GatewayError, Ipv6Addr, Ipv6InterfaceAddress};
    use std::{io, ptr};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
        GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET6;

    const ERROR_BUFFER_OVERFLOW: u32 = 111;
    const SOCKADDR_IN6_LENGTH: usize = 28;

    pub(super) fn ipv6_interface_addresses() -> Result<Vec<Ipv6InterfaceAddress>, GatewayError> {
        let mut buffer = vec![0u64; 2048];
        let mut buffer_bytes = (buffer.len() * std::mem::size_of::<u64>()) as u32;
        let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
        // SAFETY: the `u64`-aligned buffer is passed with its exact byte capacity. Windows
        // initializes an adapter-address linked list in that storage when the return code is 0.
        let mut result = unsafe {
            GetAdaptersAddresses(
                AF_INET6 as u32,
                flags,
                ptr::null_mut(),
                buffer.as_mut_ptr().cast(),
                &mut buffer_bytes,
            )
        };
        if result == ERROR_BUFFER_OVERFLOW {
            let required_words = (buffer_bytes as usize).div_ceil(std::mem::size_of::<u64>());
            buffer.resize(required_words, 0);
            // SAFETY: the resized, aligned buffer advertises the exact capacity to the API.
            result = unsafe {
                GetAdaptersAddresses(
                    AF_INET6 as u32,
                    flags,
                    ptr::null_mut(),
                    buffer.as_mut_ptr().cast(),
                    &mut buffer_bytes,
                )
            };
        }
        if result != 0 {
            return Err(GatewayError::new(format!(
                "IPv6 interface enumeration failed: {}",
                io::Error::from_raw_os_error(result as i32)
            )));
        }

        let mut addresses = Vec::new();
        // SAFETY: the successful GetAdaptersAddresses call populated a list in buffer.
        let mut adapter = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        while !adapter.is_null() {
            // SAFETY: adapter points to an initialized node in the API-owned buffer.
            let adapter_record = unsafe { &*adapter };
            let interface_index = adapter_record.Ipv6IfIndex;
            // SAFETY: FirstUnicastAddress links initialized nodes owned by the same buffer.
            let mut unicast = adapter_record.FirstUnicastAddress;
            while !unicast.is_null() {
                // SAFETY: unicast points to an initialized node in the API-owned buffer.
                let unicast_record = unsafe { &*unicast };
                let socket_address = unicast_record.Address;
                if interface_index != 0
                    && !socket_address.lpSockaddr.is_null()
                    && socket_address.iSockaddrLength as usize >= SOCKADDR_IN6_LENGTH
                {
                    // SAFETY: the API-reported length is at least sockaddr_in6, so its family
                    // and address fields are readable from the returned adapter buffer.
                    let sockaddr = unsafe {
                        std::slice::from_raw_parts(
                            socket_address.lpSockaddr.cast::<u8>(),
                            socket_address.iSockaddrLength as usize,
                        )
                    };
                    if u16::from_ne_bytes([sockaddr[0], sockaddr[1]]) == AF_INET6 as u16 {
                        let octets: [u8; 16] = sockaddr[8..24]
                            .try_into()
                            .expect("the IPv6 socket address field is exactly 16 bytes");
                        let address = Ipv6Addr::from(octets);
                        if !address.is_unspecified()
                            && !address.is_loopback()
                            && !address.is_multicast()
                        {
                            addresses.push(Ipv6InterfaceAddress {
                                address,
                                interface_index,
                            });
                        }
                    }
                }
                unicast = unicast_record.Next;
            }
            adapter = adapter_record.Next;
        }
        addresses.sort();
        addresses.dedup();
        Ok(addresses)
    }
}

#[cfg(not(any(unix, windows)))]
mod platform {
    use super::{GatewayError, Ipv6InterfaceAddress};

    pub(super) fn ipv6_interface_addresses() -> Result<Vec<Ipv6InterfaceAddress>, GatewayError> {
        Err(GatewayError::new(
            "IPv6 UPnP interface discovery is unsupported on this platform",
        ))
    }
}

#[cfg(test)]
mod tests;
