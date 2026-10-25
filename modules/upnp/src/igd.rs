use std::net::UdpSocket;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use igd_next::{
    Gateway as IgdGatewayClient, GetGenericPortMappingEntryError, PortMappingEntry,
    PortMappingProtocol, SearchOptions,
};

use crate::{Gateway, GatewayError, Mapping, MappingKey, Protocol, RefreshOutcome, RemovalOutcome};

/// Upper bound for each IGD discovery search iteration.
pub const SEARCH_TIMEOUT: Duration = Duration::from_secs(2);

const MAX_MAPPING_SCAN: u32 = 4096;

/// A real Internet Gateway Device adapter backed by `igd-next`.
pub struct IgdGateway {
    gateway: IgdGatewayClient,
    internal_address: Ipv4Addr,
}

/// Discovers an IPv4 IGD and returns discovery errors to the caller.
pub fn discover_gateway() -> Result<IgdGateway, GatewayError> {
    let options = SearchOptions {
        timeout: Some(SEARCH_TIMEOUT),
        single_search_timeout: Some(SEARCH_TIMEOUT),
        ..SearchOptions::default()
    };
    let gateway = igd_next::search_gateway(options)
        .map_err(|error| GatewayError::new(format!("IGD discovery failed: {error}")))?;
    let internal_address = local_ipv4_route(gateway.addr)?;
    Ok(IgdGateway {
        gateway,
        internal_address,
    })
}

impl IgdGateway {
    /// IPv4 interface selected by the host route to this gateway.
    pub fn internal_address(&self) -> Ipv4Addr {
        self.internal_address
    }

    /// Stable identity used to keep mapping ownership attached to the same IGD.
    pub fn identity(&self) -> String {
        format!(
            "{}|{}|{}",
            self.gateway.addr, self.gateway.root_url, self.internal_address
        )
    }
}

fn local_ipv4_route(gateway: SocketAddr) -> Result<Ipv4Addr, GatewayError> {
    let socket = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0)))
        .map_err(|error| GatewayError::new(format!("failed to select an IGD route: {error}")))?;
    // UDP connect selects a route and local address without sending a packet.
    socket
        .connect(gateway)
        .map_err(|error| GatewayError::new(format!("failed to select an IGD route: {error}")))?;
    let address = socket
        .local_addr()
        .map_err(|error| GatewayError::new(format!("failed to inspect the IGD route: {error}")))?
        .ip();
    let IpAddr::V4(address) = address else {
        return Err(GatewayError::new(
            "IGD discovery selected a non-IPv4 local route",
        ));
    };
    if address.is_loopback() || address.is_unspecified() {
        return Err(GatewayError::new(
            "IGD discovery selected a non-routable local IPv4 address",
        ));
    }
    Ok(address)
}

impl Gateway for IgdGateway {
    fn find_mappings(&mut self, key: MappingKey) -> Result<Vec<Mapping>, GatewayError> {
        let mut mappings = Vec::new();

        for index in 0..MAX_MAPPING_SCAN {
            let entry = match self.gateway.get_generic_port_mapping_entry(index) {
                Ok(entry) => entry,
                Err(GetGenericPortMappingEntryError::SpecifiedArrayIndexInvalid) => {
                    return Ok(mappings);
                }
                Err(error) => {
                    return Err(GatewayError::new(format!(
                        "failed to inspect IGD mapping entry {index}: {error}"
                    )));
                }
            };

            if entry.external_port == key.external_port
                && protocol_from_igd(entry.protocol) == key.protocol
            {
                mappings.push(mapping_from_entry(entry)?);
            }
        }

        Err(GatewayError::new(format!(
            "IGD mapping table exceeded the {MAX_MAPPING_SCAN}-entry inspection bound"
        )))
    }

    fn create_if_absent(&mut self, mapping: &Mapping) -> Result<(), GatewayError> {
        if !self.find_mappings(mapping.key())?.is_empty() {
            return Err(GatewayError::new(format!(
                "IGD mapping {} {:?} appeared before creation; it was preserved",
                mapping.external_port, mapping.protocol
            )));
        }

        self.gateway
            .add_port(
                protocol_to_igd(mapping.protocol),
                mapping.external_port,
                SocketAddr::new(IpAddr::V4(mapping.internal_address), mapping.internal_port),
                mapping.lease_duration_seconds,
                &mapping.description,
            )
            .map_err(|error| GatewayError::new(format!("failed to add IGD mapping: {error}")))
    }

    fn remove_if_matches(&mut self, mapping: &Mapping) -> Result<RemovalOutcome, GatewayError> {
        let current_mappings = self.find_mappings(mapping.key())?;
        if current_mappings.is_empty() {
            return Ok(RemovalOutcome::Missing);
        }
        if !current_mappings
            .iter()
            .any(|current| current.has_same_owned_attributes(mapping))
        {
            return Ok(RemovalOutcome::Changed);
        }

        self.gateway
            .remove_port(protocol_to_igd(mapping.protocol), mapping.external_port)
            .map_err(|error| GatewayError::new(format!("failed to remove IGD mapping: {error}")))?;

        Ok(RemovalOutcome::Removed)
    }

    fn refresh_if_matches(&mut self, mapping: &Mapping) -> Result<RefreshOutcome, GatewayError> {
        let current_mappings = self.find_mappings(mapping.key())?;
        if current_mappings.is_empty() {
            return Ok(RefreshOutcome::Missing);
        }
        if !current_mappings
            .iter()
            .any(|current| current.has_same_owned_attributes(mapping))
        {
            return Ok(RefreshOutcome::Changed);
        }

        // IGD has no atomic compare-and-refresh operation; another writer can race
        // between this complete-value check and AddPortMapping.
        self.gateway
            .add_port(
                protocol_to_igd(mapping.protocol),
                mapping.external_port,
                SocketAddr::new(IpAddr::V4(mapping.internal_address), mapping.internal_port),
                mapping.lease_duration_seconds,
                &mapping.description,
            )
            .map_err(|error| {
                GatewayError::new(format!("failed to refresh IGD mapping: {error}"))
            })?;

        Ok(RefreshOutcome::Refreshed)
    }
}

fn mapping_from_entry(entry: PortMappingEntry) -> Result<Mapping, GatewayError> {
    let internal_address = entry.internal_client.parse::<Ipv4Addr>().map_err(|error| {
        GatewayError::new(format!("IGD returned a non-IPv4 mapping client: {error}"))
    })?;

    Ok(Mapping {
        external_port: entry.external_port,
        protocol: protocol_from_igd(entry.protocol),
        internal_address,
        internal_port: entry.internal_port,
        remote_host: entry.remote_host,
        enabled: entry.enabled,
        description: entry.port_mapping_description,
        lease_duration_seconds: entry.lease_duration,
    })
}

fn protocol_from_igd(protocol: PortMappingProtocol) -> Protocol {
    match protocol {
        PortMappingProtocol::TCP => Protocol::Tcp,
        PortMappingProtocol::UDP => Protocol::Udp,
    }
}

fn protocol_to_igd(protocol: Protocol) -> PortMappingProtocol {
    match protocol {
        Protocol::Tcp => PortMappingProtocol::TCP,
        Protocol::Udp => PortMappingProtocol::UDP,
    }
}
