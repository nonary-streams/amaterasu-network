use std::cell::RefCell;
use std::collections::BTreeMap;
use std::net::Ipv6Addr;
use std::rc::Rc;

use super::*;

#[derive(Clone)]
struct FakeControl(Rc<RefCell<FakeControlState>>);

struct FakeControlState {
    status: FirewallStatus,
    next_id: u16,
    pinholes: BTreeMap<u16, PinholeEndpoint>,
    fail_delete_count: usize,
    missing_refresh_count: usize,
    added_leases: Vec<u32>,
    refreshed_leases: Vec<u32>,
}

impl Default for FakeControl {
    fn default() -> Self {
        Self(Rc::new(RefCell::new(FakeControlState {
            status: FirewallStatus {
                firewall_enabled: true,
                pinhole_allowed: true,
            },
            next_id: 1,
            pinholes: BTreeMap::new(),
            fail_delete_count: 0,
            missing_refresh_count: 0,
            added_leases: Vec::new(),
            refreshed_leases: Vec::new(),
        })))
    }
}

impl FakeControl {
    fn set_status(&self, status: FirewallStatus) {
        self.0.borrow_mut().status = status;
    }

    fn fail_deletes(&self, count: usize) {
        self.0.borrow_mut().fail_delete_count = count;
    }

    fn expire_next_refresh(&self) {
        self.0.borrow_mut().missing_refresh_count += 1;
    }

    fn pinholes(&self) -> BTreeMap<u16, PinholeEndpoint> {
        self.0.borrow().pinholes.clone()
    }
}

impl Ipv6FirewallControl for FakeControl {
    fn firewall_status(&mut self) -> Result<FirewallStatus, GatewayError> {
        Ok(self.0.borrow().status)
    }

    fn add_pinhole(
        &mut self,
        endpoint: PinholeEndpoint,
        lease_duration_seconds: u32,
    ) -> Result<u16, GatewayError> {
        let mut state = self.0.borrow_mut();
        let unique_id = state.next_id;
        state.next_id += 1;
        state.pinholes.insert(unique_id, endpoint);
        state.added_leases.push(lease_duration_seconds);
        Ok(unique_id)
    }

    fn refresh_pinhole(
        &mut self,
        unique_id: u16,
        lease_duration_seconds: u32,
    ) -> Result<PinholeRefreshOutcome, GatewayError> {
        let mut state = self.0.borrow_mut();
        state.refreshed_leases.push(lease_duration_seconds);
        if state.missing_refresh_count > 0 {
            state.missing_refresh_count -= 1;
            state.pinholes.remove(&unique_id);
            return Ok(PinholeRefreshOutcome::Missing);
        }
        Ok(if state.pinholes.contains_key(&unique_id) {
            PinholeRefreshOutcome::Refreshed
        } else {
            PinholeRefreshOutcome::Missing
        })
    }

    fn delete_pinhole(&mut self, unique_id: u16) -> Result<PinholeDeleteOutcome, GatewayError> {
        let mut state = self.0.borrow_mut();
        if state.fail_delete_count > 0 {
            state.fail_delete_count -= 1;
            return Err(GatewayError::new("injected delete failure"));
        }
        Ok(if state.pinholes.remove(&unique_id).is_some() {
            PinholeDeleteOutcome::Deleted
        } else {
            PinholeDeleteOutcome::Missing
        })
    }
}

fn endpoint(address: &str, port: u16, protocol: Protocol) -> PinholeEndpoint {
    PinholeEndpoint::new(address.parse::<Ipv6Addr>().unwrap(), port, protocol)
}

#[test]
fn reconcile_adds_and_refreshes_only_active_valid_endpoints_with_reference_lease() {
    let control = FakeControl::default();
    let mut manager = PinholeManager::new(control.clone());
    let desired = [
        endpoint("2001:db8::10", 47989, Protocol::Tcp),
        endpoint("2001:db8::10", 47998, Protocol::Udp),
        endpoint("::", 47999, Protocol::Udp),
        endpoint("::1", 48000, Protocol::Tcp),
        endpoint("ff02::1", 48001, Protocol::Udp),
        endpoint("fe80::1", 48002, Protocol::Tcp),
    ];

    let first = manager.reconcile(&desired).unwrap();
    assert_eq!(first.created, 2);
    assert_eq!(control.pinholes().len(), 2);
    assert_eq!(
        control.0.borrow().added_leases,
        vec![PINHOLE_LEASE_SECONDS; 2]
    );

    let second = manager.reconcile(&desired).unwrap();
    assert_eq!(second.refreshed, 2);
    assert_eq!(
        control.0.borrow().refreshed_leases,
        vec![PINHOLE_LEASE_SECONDS; 2]
    );
}

#[test]
fn pinhole_allowed_gates_additions_but_firewall_enabled_is_informational() {
    let control = FakeControl::default();
    let mut manager = PinholeManager::new(control.clone());
    control.set_status(FirewallStatus {
        firewall_enabled: false,
        pinhole_allowed: true,
    });
    let endpoint = endpoint("2001:db8::10", 47989, Protocol::Tcp);

    assert_eq!(manager.reconcile(&[endpoint]).unwrap().created, 1);
    assert_eq!(control.pinholes().len(), 1);

    control.set_status(FirewallStatus {
        firewall_enabled: true,
        pinhole_allowed: false,
    });
    let report = manager.reconcile(&[endpoint]).unwrap();
    assert!(!report.allowed);
    assert_eq!(report.removed, 1);
    assert!(control.pinholes().is_empty());
}

#[test]
fn expired_owned_pinhole_is_recreated_and_cleanup_failure_is_retried() {
    let control = FakeControl::default();
    let mut manager = PinholeManager::new(control.clone());
    let endpoint = endpoint("2001:db8::10", 47989, Protocol::Tcp);
    assert_eq!(manager.reconcile(&[endpoint]).unwrap().created, 1);

    control.expire_next_refresh();
    assert_eq!(manager.reconcile(&[endpoint]).unwrap().created, 1);
    assert_eq!(control.pinholes().len(), 1);

    control.fail_deletes(1);
    assert!(matches!(
        manager.shutdown(),
        Err(PinholeError::Shutdown { .. })
    ));
    assert_eq!(manager.owned_pinholes().count(), 1);
    assert_eq!(manager.shutdown().unwrap().removed, 1);
    assert_eq!(manager.owned_pinholes().count(), 0);
}

#[test]
fn disallowed_policy_preserves_pending_ownership_when_delete_fails() {
    let control = FakeControl::default();
    let mut manager = PinholeManager::new(control.clone());
    let endpoint = endpoint("2001:db8::10", 47989, Protocol::Tcp);
    manager.reconcile(&[endpoint]).unwrap();
    control.set_status(FirewallStatus {
        firewall_enabled: true,
        pinhole_allowed: false,
    });
    control.fail_deletes(1);

    assert!(matches!(
        manager.reconcile(&[endpoint]),
        Err(PinholeError::Cleanup { .. })
    ));
    assert_eq!(manager.owned_pinholes().count(), 1);
    assert_eq!(manager.reconcile(&[endpoint]).unwrap().removed, 1);
}
