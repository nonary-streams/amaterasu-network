use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::Ipv6Addr;

use crate::{GatewayError, MAPPING_LEASE_SECONDS, Protocol};

/// Lease requested for each IPv6 firewall pinhole.
pub const PINHOLE_LEASE_SECONDS: u32 = MAPPING_LEASE_SECONDS;

/// One exact IPv6 listener exposed through the gateway firewall control service.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PinholeEndpoint {
    pub internal_client: Ipv6Addr,
    pub internal_port: u16,
    pub protocol: Protocol,
}

impl PinholeEndpoint {
    pub fn new(internal_client: Ipv6Addr, internal_port: u16, protocol: Protocol) -> Self {
        Self {
            internal_client,
            internal_port,
            protocol,
        }
    }
}

/// Values returned by `GetFirewallStatus`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirewallStatus {
    pub firewall_enabled: bool,
    pub pinhole_allowed: bool,
}

/// Result of refreshing a pinhole recorded as owned by this process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PinholeRefreshOutcome {
    Refreshed,
    Missing,
}

/// Result of deleting a pinhole recorded as owned by this process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PinholeDeleteOutcome {
    Deleted,
    Missing,
}

/// UPnP WANIPv6FirewallControl operations required by the lifecycle manager.
pub trait Ipv6FirewallControl {
    fn firewall_status(&mut self) -> Result<FirewallStatus, GatewayError>;

    fn add_pinhole(
        &mut self,
        endpoint: PinholeEndpoint,
        lease_duration_seconds: u32,
    ) -> Result<u16, GatewayError>;

    fn refresh_pinhole(
        &mut self,
        unique_id: u16,
        lease_duration_seconds: u32,
    ) -> Result<PinholeRefreshOutcome, GatewayError>;

    fn delete_pinhole(&mut self, unique_id: u16) -> Result<PinholeDeleteOutcome, GatewayError>;
}

/// Summary of one IPv6 pinhole reconciliation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PinholeReport {
    pub allowed: bool,
    pub created: usize,
    pub refreshed: usize,
    pub removed: usize,
    pub already_missing: usize,
}

/// Errors produced while reconciling or removing owned pinholes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PinholeError {
    Status(GatewayError),
    Add {
        endpoint: PinholeEndpoint,
        source: GatewayError,
    },
    Refresh {
        endpoint: PinholeEndpoint,
        source: GatewayError,
    },
    Cleanup {
        failures: Vec<(PinholeEndpoint, GatewayError)>,
    },
    Shutdown {
        failures: Vec<(PinholeEndpoint, GatewayError)>,
    },
}

impl fmt::Display for PinholeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Status(source) => write!(formatter, "IPv6 firewall status failed: {source}"),
            Self::Add { endpoint, source } => write!(
                formatter,
                "IPv6 pinhole add failed for {}:{} {:?}: {source}",
                endpoint.internal_client, endpoint.internal_port, endpoint.protocol
            ),
            Self::Refresh { endpoint, source } => write!(
                formatter,
                "IPv6 pinhole refresh failed for {}:{} {:?}: {source}",
                endpoint.internal_client, endpoint.internal_port, endpoint.protocol
            ),
            Self::Cleanup { failures } => write!(
                formatter,
                "IPv6 pinhole reconcile left {} owned cleanup failure(s)",
                failures.len()
            ),
            Self::Shutdown { failures } => write!(
                formatter,
                "IPv6 pinhole shutdown left {} owned cleanup failure(s)",
                failures.len()
            ),
        }
    }
}

impl std::error::Error for PinholeError {}

/// Owns only the pinholes created by this manager and their gateway-assigned IDs.
pub struct PinholeManager<C> {
    control: C,
    owned: BTreeMap<PinholeEndpoint, u16>,
}

impl<C: Ipv6FirewallControl> PinholeManager<C> {
    pub fn new(control: C) -> Self {
        Self {
            control,
            owned: BTreeMap::new(),
        }
    }

    /// Replaces the control adapter while retaining pinhole IDs for the same gateway.
    ///
    /// The caller must compare stable gateway identities before replacing the adapter.
    pub fn replace_control_adapter(&mut self, control: C) {
        self.control = control;
    }

    /// Adds, refreshes, and removes only the pinholes owned by this manager.
    ///
    /// As in the reference behavior, additions are gated by `pinhole_allowed`; the
    /// separate `firewall_enabled` report bit is informational and does not gate the
    /// operation. Existing owned pinholes are removed when the gateway disallows new
    /// pinholes, and cleanup failures remain recorded for a later retry.
    pub fn reconcile(
        &mut self,
        endpoints: &[PinholeEndpoint],
    ) -> Result<PinholeReport, PinholeError> {
        let status = self
            .control
            .firewall_status()
            .map_err(PinholeError::Status)?;
        let desired: BTreeSet<_> = endpoints
            .iter()
            .copied()
            .filter(|endpoint| valid_endpoint(*endpoint))
            .collect();
        let mut report = PinholeReport {
            allowed: status.pinhole_allowed,
            ..PinholeReport::default()
        };

        if !status.pinhole_allowed {
            self.remove_stale_pinholes(&BTreeSet::new(), &mut report)?;
            return Ok(report);
        }

        for endpoint in &desired {
            let Some(unique_id) = self.owned.get(endpoint).copied() else {
                let unique_id = self
                    .control
                    .add_pinhole(*endpoint, PINHOLE_LEASE_SECONDS)
                    .map_err(|source| PinholeError::Add {
                        endpoint: *endpoint,
                        source,
                    })?;
                self.owned.insert(*endpoint, unique_id);
                report.created += 1;
                continue;
            };

            match self
                .control
                .refresh_pinhole(unique_id, PINHOLE_LEASE_SECONDS)
                .map_err(|source| PinholeError::Refresh {
                    endpoint: *endpoint,
                    source,
                })? {
                PinholeRefreshOutcome::Refreshed => report.refreshed += 1,
                PinholeRefreshOutcome::Missing => {
                    self.owned.remove(endpoint);
                    let replacement_id = self
                        .control
                        .add_pinhole(*endpoint, PINHOLE_LEASE_SECONDS)
                        .map_err(|source| PinholeError::Add {
                            endpoint: *endpoint,
                            source,
                        })?;
                    self.owned.insert(*endpoint, replacement_id);
                    report.created += 1;
                }
            }
        }

        self.remove_stale_pinholes(&desired, &mut report)?;
        Ok(report)
    }

    /// Deletes owned pinholes. Failed IDs remain recorded for retry.
    pub fn shutdown(&mut self) -> Result<PinholeReport, PinholeError> {
        let mut report = PinholeReport {
            allowed: false,
            ..PinholeReport::default()
        };
        self.remove_stale_pinholes(&BTreeSet::new(), &mut report)
            .map_err(|error| match error {
                PinholeError::Cleanup { failures } => PinholeError::Shutdown { failures },
                other => other,
            })?;
        Ok(report)
    }

    pub fn owned_pinholes(&self) -> impl Iterator<Item = (PinholeEndpoint, u16)> + '_ {
        self.owned
            .iter()
            .map(|(endpoint, unique_id)| (*endpoint, *unique_id))
    }

    fn remove_stale_pinholes(
        &mut self,
        desired: &BTreeSet<PinholeEndpoint>,
        report: &mut PinholeReport,
    ) -> Result<(), PinholeError> {
        let stale: Vec<_> = self
            .owned
            .iter()
            .filter(|(endpoint, _)| !desired.contains(endpoint))
            .map(|(endpoint, unique_id)| (*endpoint, *unique_id))
            .collect();
        let mut failures = Vec::new();
        for (endpoint, unique_id) in stale {
            match self.control.delete_pinhole(unique_id) {
                Ok(PinholeDeleteOutcome::Deleted) => {
                    self.owned.remove(&endpoint);
                    report.removed += 1;
                }
                Ok(PinholeDeleteOutcome::Missing) => {
                    self.owned.remove(&endpoint);
                    report.already_missing += 1;
                }
                Err(source) => failures.push((endpoint, source)),
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(PinholeError::Cleanup { failures })
        }
    }
}

fn valid_endpoint(endpoint: PinholeEndpoint) -> bool {
    endpoint.internal_port != 0
        && !endpoint.internal_client.is_unspecified()
        && !endpoint.internal_client.is_loopback()
        && !endpoint.internal_client.is_multicast()
        && !endpoint.internal_client.is_unicast_link_local()
}

#[cfg(test)]
mod tests;
