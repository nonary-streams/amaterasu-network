use std::cell::RefCell;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::rc::Rc;

use super::{
    Gateway, GatewayError, ListenerEndpoint, MAPPING_LEASE_SECONDS, Mapping, MappingEndpoint,
    MappingKey, MappingManager, Protocol, ReconcileReport, RefreshOutcome, RefreshReport,
    RemovalOutcome, ShutdownReport, UpnpError,
};

#[derive(Clone, Default)]
struct FakeGateway(Rc<RefCell<FakeGatewayState>>);

#[derive(Default)]
struct FakeGatewayState {
    mappings: BTreeMap<MappingKey, Mapping>,
    fail_add_for: Option<MappingKey>,
    fail_add_on_attempt: Option<usize>,
    fail_remove_for: Option<MappingKey>,
    fail_refresh_for: Option<MappingKey>,
    mapping_after_next_removal: Option<Mapping>,
    add_attempts: usize,
    refresh_attempts: usize,
    refresh_requests: Vec<Mapping>,
}

impl FakeGateway {
    fn seed(&self, mapping: Mapping) {
        self.0.borrow_mut().mappings.insert(mapping.key(), mapping);
    }

    fn set_add_failure(&self, key: MappingKey) {
        self.0.borrow_mut().fail_add_for = Some(key);
    }

    fn set_add_failure_on_attempt(&self, attempt: usize) {
        self.0.borrow_mut().fail_add_on_attempt = Some(attempt);
    }

    fn set_remove_failure(&self, key: Option<MappingKey>) {
        self.0.borrow_mut().fail_remove_for = key;
    }

    fn set_refresh_failure(&self, key: Option<MappingKey>) {
        self.0.borrow_mut().fail_refresh_for = key;
    }

    fn mappings(&self) -> BTreeMap<MappingKey, Mapping> {
        self.0.borrow().mappings.clone()
    }

    fn add_attempts(&self) -> usize {
        self.0.borrow().add_attempts
    }

    fn refresh_attempts(&self) -> usize {
        self.0.borrow().refresh_attempts
    }

    fn refresh_requests(&self) -> Vec<Mapping> {
        self.0.borrow().refresh_requests.clone()
    }

    fn change_mapping(&self, mapping: Mapping) {
        self.0.borrow_mut().mappings.insert(mapping.key(), mapping);
    }

    fn change_mapping_after_next_removal(&self, mapping: Mapping) {
        self.0.borrow_mut().mapping_after_next_removal = Some(mapping);
    }

    fn remove_mapping(&self, key: MappingKey) {
        self.0.borrow_mut().mappings.remove(&key);
    }

    fn set_remaining_lease_seconds(&self, key: MappingKey, seconds: u32) {
        self.0
            .borrow_mut()
            .mappings
            .get_mut(&key)
            .expect("test mapping should exist")
            .lease_duration_seconds = seconds;
    }
}

impl Gateway for FakeGateway {
    fn find_mappings(&mut self, key: MappingKey) -> Result<Vec<Mapping>, GatewayError> {
        Ok(self
            .0
            .borrow()
            .mappings
            .get(&key)
            .cloned()
            .into_iter()
            .collect())
    }

    fn create_if_absent(&mut self, mapping: &Mapping) -> Result<(), GatewayError> {
        let mut state = self.0.borrow_mut();
        state.add_attempts += 1;

        if state.fail_add_for == Some(mapping.key())
            || state.fail_add_on_attempt == Some(state.add_attempts)
        {
            return Err(GatewayError::new("injected add failure"));
        }
        if state.mappings.contains_key(&mapping.key()) {
            return Err(GatewayError::new("mapping already exists"));
        }

        state.mappings.insert(mapping.key(), mapping.clone());
        Ok(())
    }

    fn remove_if_matches(&mut self, mapping: &Mapping) -> Result<RemovalOutcome, GatewayError> {
        let mut state = self.0.borrow_mut();
        let key = mapping.key();

        if state.fail_remove_for == Some(key) {
            return Err(GatewayError::new("injected remove failure"));
        }

        match state.mappings.get(&key) {
            None => Ok(RemovalOutcome::Missing),
            Some(current) if current.has_same_owned_attributes(mapping) => {
                state.mappings.remove(&key);
                if let Some(replacement) = state.mapping_after_next_removal.take() {
                    state.mappings.insert(replacement.key(), replacement);
                }
                Ok(RemovalOutcome::Removed)
            }
            Some(_) => Ok(RemovalOutcome::Changed),
        }
    }

    fn refresh_if_matches(&mut self, mapping: &Mapping) -> Result<RefreshOutcome, GatewayError> {
        let mut state = self.0.borrow_mut();
        let key = mapping.key();
        state.refresh_attempts += 1;
        state.refresh_requests.push(mapping.clone());

        if state.fail_refresh_for == Some(key) {
            return Err(GatewayError::new("injected refresh failure"));
        }

        match state.mappings.get(&key) {
            None => Ok(RefreshOutcome::Missing),
            Some(current) if current.has_same_owned_attributes(mapping) => {
                Ok(RefreshOutcome::Refreshed)
            }
            Some(_) => Ok(RefreshOutcome::Changed),
        }
    }
}

fn endpoint(address: [u8; 4], port: u16, active: bool) -> ListenerEndpoint {
    ListenerEndpoint::new(IpAddr::V4(Ipv4Addr::from(address)), port, active)
}

fn key(port: u16, protocol: Protocol) -> MappingKey {
    MappingKey {
        external_port: port,
        protocol,
    }
}

fn manager(gateway: FakeGateway) -> MappingManager<FakeGateway> {
    MappingManager::with_owner_id(gateway, "deterministic-test")
}

#[test]
fn reconcile_is_idempotent_for_owned_tcp_and_udp_mappings() {
    let fake_gateway = FakeGateway::default();
    let mut manager = manager(fake_gateway.clone());
    let configured = [endpoint([192, 168, 1, 10], 47989, true)];

    assert_eq!(
        manager.reconcile(&configured).unwrap(),
        ReconcileReport {
            created: 2,
            removed: 0,
            already_active: 0,
            changed_mappings_preserved: 0,
        }
    );
    assert_eq!(manager.reconcile(&configured).unwrap().created, 0);
    assert_eq!(manager.owned_mappings().count(), 2);
    assert_eq!(fake_gateway.add_attempts(), 2);
    assert_eq!(fake_gateway.mappings().len(), 2);
    assert!(
        fake_gateway
            .mappings()
            .values()
            .all(|mapping| mapping.lease_duration_seconds == MAPPING_LEASE_SECONDS)
    );
}

#[test]
fn reconcile_protocols_maps_only_live_listener_protocols() {
    let fake_gateway = FakeGateway::default();
    let mut manager = manager(fake_gateway.clone());
    let endpoints = [
        MappingEndpoint::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            47989,
            Protocol::Tcp,
            true,
        ),
        MappingEndpoint::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            47998,
            Protocol::Udp,
            true,
        ),
        MappingEndpoint::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            47997,
            Protocol::Udp,
            false,
        ),
    ];

    let report = manager.reconcile_protocols(&endpoints).unwrap();

    assert_eq!(report.created, 2);
    assert!(
        fake_gateway
            .mappings()
            .contains_key(&key(47989, Protocol::Tcp))
    );
    assert!(
        fake_gateway
            .mappings()
            .contains_key(&key(47998, Protocol::Udp))
    );
    assert!(
        !fake_gateway
            .mappings()
            .contains_key(&key(47989, Protocol::Udp))
    );
    assert!(
        !fake_gateway
            .mappings()
            .contains_key(&key(47998, Protocol::Tcp))
    );
    assert!(
        !fake_gateway
            .mappings()
            .contains_key(&key(47997, Protocol::Udp))
    );
}

#[test]
fn reconcile_updates_to_a_distinct_endpoint_and_port() {
    let fake_gateway = FakeGateway::default();
    let mut manager = manager(fake_gateway.clone());

    manager
        .reconcile(&[endpoint([192, 168, 1, 10], 47989, true)])
        .unwrap();
    let report = manager
        .reconcile(&[endpoint([192, 168, 1, 20], 48000, true)])
        .unwrap();

    assert_eq!(report.created, 2);
    assert_eq!(report.removed, 2);
    assert_eq!(manager.owned_mappings().count(), 2);
    let mappings = fake_gateway.mappings();
    assert_eq!(mappings.len(), 2);
    assert!(mappings.contains_key(&key(48000, Protocol::Tcp)));
    assert!(mappings.contains_key(&key(48000, Protocol::Udp)));
    assert!(!mappings.contains_key(&key(47989, Protocol::Tcp)));
}

#[test]
fn reconcile_retries_failed_stale_mapping_cleanup() {
    let fake_gateway = FakeGateway::default();
    let mut manager = manager(fake_gateway.clone());
    manager
        .reconcile(&[endpoint([192, 168, 1, 10], 47989, true)])
        .unwrap();
    let stale_mapping_key = key(47989, Protocol::Tcp);
    let desired_endpoints = [endpoint([192, 168, 1, 20], 48000, true)];
    fake_gateway.set_remove_failure(Some(stale_mapping_key));

    let error = manager.reconcile(&desired_endpoints).unwrap_err();

    assert!(matches!(error, UpnpError::CleanupFailed { .. }));
    assert_eq!(manager.owned_mappings().count(), 3);
    assert!(
        manager
            .owned_mappings()
            .any(|mapping| mapping.key() == stale_mapping_key)
    );
    assert!(fake_gateway.mappings().contains_key(&stale_mapping_key));
    assert!(
        fake_gateway
            .mappings()
            .contains_key(&key(48000, Protocol::Tcp))
    );
    assert!(
        fake_gateway
            .mappings()
            .contains_key(&key(48000, Protocol::Udp))
    );

    fake_gateway.set_remove_failure(None);
    let report = manager.reconcile(&desired_endpoints).unwrap();

    assert_eq!(report.created, 0);
    assert_eq!(report.removed, 1);
    assert_eq!(report.already_active, 2);
    assert_eq!(manager.owned_mappings().count(), 2);
    assert_eq!(fake_gateway.mappings().len(), 2);
    assert!(!fake_gateway.mappings().contains_key(&stale_mapping_key));
    assert!(
        fake_gateway
            .mappings()
            .contains_key(&key(48000, Protocol::Tcp))
    );
    assert!(
        fake_gateway
            .mappings()
            .contains_key(&key(48000, Protocol::Udp))
    );
}

#[test]
fn address_change_on_the_same_external_port_retargets_owned_mappings() {
    let fake_gateway = FakeGateway::default();
    let mut manager = manager(fake_gateway.clone());
    manager
        .reconcile(&[endpoint([192, 168, 1, 10], 47989, true)])
        .unwrap();

    let report = manager
        .reconcile(&[endpoint([192, 168, 1, 20], 47989, true)])
        .unwrap();

    assert_eq!(
        report,
        ReconcileReport {
            created: 2,
            removed: 2,
            already_active: 0,
            changed_mappings_preserved: 0,
        }
    );
    assert_eq!(manager.owned_mappings().count(), 2);
    assert_eq!(fake_gateway.mappings().len(), 2);
    assert!(
        fake_gateway
            .mappings()
            .values()
            .all(|mapping| { mapping.internal_address == Ipv4Addr::new(192, 168, 1, 20) })
    );
}

#[test]
fn same_port_retarget_preflight_preserves_an_externally_changed_entry() {
    let fake_gateway = FakeGateway::default();
    let mut manager = manager(fake_gateway.clone());
    manager
        .reconcile(&[endpoint([192, 168, 1, 10], 47989, true)])
        .unwrap();
    let changed_key = key(47989, Protocol::Tcp);
    let mut externally_changed_mapping = fake_gateway.mappings()[&changed_key].clone();
    externally_changed_mapping.internal_address = Ipv4Addr::new(192, 168, 1, 55);
    externally_changed_mapping.description = "changed by another owner".into();
    fake_gateway.change_mapping(externally_changed_mapping.clone());
    let mappings_before = fake_gateway.mappings();

    let error = manager
        .reconcile(&[endpoint([192, 168, 1, 20], 47989, true)])
        .unwrap_err();

    assert!(matches!(error, UpnpError::ExistingMapping { .. }));
    assert_eq!(fake_gateway.mappings(), mappings_before);
    assert_eq!(
        fake_gateway.mappings().get(&changed_key),
        Some(&externally_changed_mapping)
    );
    assert_eq!(fake_gateway.add_attempts(), 2);
    assert_eq!(manager.owned_mappings().count(), 1);
}

#[test]
fn same_port_retarget_preserves_a_foreign_mapping_that_appears_during_replacement() {
    let fake_gateway = FakeGateway::default();
    let mut manager = manager(fake_gateway.clone());
    manager
        .reconcile(&[endpoint([192, 168, 1, 10], 47989, true)])
        .unwrap();
    let raced_key = key(47989, Protocol::Tcp);
    let foreign_mapping = Mapping {
        external_port: raced_key.external_port,
        protocol: raced_key.protocol,
        internal_address: Ipv4Addr::new(192, 168, 1, 88),
        internal_port: 47989,
        remote_host: String::new(),
        enabled: true,
        description: "created by another writer".into(),
        lease_duration_seconds: 0,
    };
    fake_gateway.change_mapping_after_next_removal(foreign_mapping.clone());

    let error = manager
        .reconcile(&[endpoint([192, 168, 1, 20], 47989, true)])
        .unwrap_err();

    assert!(matches!(
        error,
        UpnpError::AddFailed {
            failure,
            rollback_failures
        } if failure.mapping == raced_key
            && rollback_failures.len() == 1
            && rollback_failures[0].operation == super::MappingOperation::Add
    ));
    assert_eq!(
        fake_gateway.mappings().get(&raced_key),
        Some(&foreign_mapping)
    );
    assert_eq!(fake_gateway.mappings().len(), 2);
    assert_eq!(manager.owned_mappings().count(), 1);
}

#[test]
fn same_port_retarget_does_not_add_after_a_failed_old_mapping_removal() {
    let fake_gateway = FakeGateway::default();
    let mut manager = manager(fake_gateway.clone());
    manager
        .reconcile(&[endpoint([192, 168, 1, 10], 47989, true)])
        .unwrap();
    let mappings_before = fake_gateway.mappings();
    fake_gateway.set_remove_failure(Some(key(47989, Protocol::Tcp)));

    let error = manager
        .reconcile(&[endpoint([192, 168, 1, 20], 47989, true)])
        .unwrap_err();

    assert!(matches!(
        error,
        UpnpError::ReconcileFailed {
            failure,
            rollback_failures
        } if failure.operation == super::MappingOperation::Remove
            && rollback_failures.is_empty()
    ));
    assert_eq!(fake_gateway.mappings(), mappings_before);
    assert_eq!(fake_gateway.add_attempts(), 2);
    assert_eq!(manager.owned_mappings().count(), 2);
}

#[test]
fn failed_same_port_retarget_add_restores_the_previous_mapping() {
    let fake_gateway = FakeGateway::default();
    let mut manager = manager(fake_gateway.clone());
    manager
        .reconcile(&[endpoint([192, 168, 1, 10], 47989, true)])
        .unwrap();
    let previous_mappings = fake_gateway.mappings();
    fake_gateway.set_add_failure_on_attempt(3);

    let error = manager
        .reconcile(&[endpoint([192, 168, 1, 20], 47989, true)])
        .unwrap_err();

    assert!(matches!(
        error,
        UpnpError::AddFailed {
            failure,
            rollback_failures
        } if failure.operation == super::MappingOperation::Add
            && rollback_failures.is_empty()
    ));
    assert_eq!(fake_gateway.mappings(), previous_mappings);
    assert_eq!(manager.owned_mappings().count(), 2);
    assert_eq!(fake_gateway.add_attempts(), 4);
}

#[test]
fn later_protocol_retarget_failure_rolls_back_the_earlier_protocol() {
    let fake_gateway = FakeGateway::default();
    let mut manager = manager(fake_gateway.clone());
    manager
        .reconcile(&[endpoint([192, 168, 1, 10], 47989, true)])
        .unwrap();
    let previous_mappings = fake_gateway.mappings();
    fake_gateway.set_add_failure_on_attempt(4);

    let error = manager
        .reconcile(&[endpoint([192, 168, 1, 20], 47989, true)])
        .unwrap_err();

    assert!(matches!(
        error,
        UpnpError::AddFailed {
            failure,
            rollback_failures
        } if failure.mapping == key(47989, Protocol::Udp)
            && rollback_failures.is_empty()
    ));
    assert_eq!(fake_gateway.mappings(), previous_mappings);
    assert_eq!(manager.owned_mappings().count(), 2);
    assert_eq!(fake_gateway.add_attempts(), 6);
}

#[test]
fn inactive_zero_port_and_non_ipv4_endpoints_are_ignored() {
    let fake_gateway = FakeGateway::default();
    let mut manager = manager(fake_gateway.clone());
    let endpoints = [
        endpoint([192, 168, 1, 10], 47989, false),
        endpoint([192, 168, 1, 10], 0, true),
        ListenerEndpoint::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 47990, true),
    ];

    assert_eq!(
        manager.reconcile(&endpoints).unwrap(),
        ReconcileReport::default()
    );
    assert!(fake_gateway.mappings().is_empty());
    assert_eq!(fake_gateway.add_attempts(), 0);
}

#[test]
fn preexisting_mapping_is_preserved_and_never_adopted() {
    let fake_gateway = FakeGateway::default();
    let preexisting_mapping = Mapping {
        external_port: 47989,
        protocol: Protocol::Tcp,
        internal_address: Ipv4Addr::new(192, 168, 1, 99),
        internal_port: 47989,
        remote_host: String::new(),
        enabled: true,
        description: "another service".into(),
        lease_duration_seconds: 0,
    };
    fake_gateway.seed(preexisting_mapping.clone());
    let mut manager = manager(fake_gateway.clone());

    let error = manager
        .reconcile(&[endpoint([192, 168, 1, 10], 47989, true)])
        .unwrap_err();

    assert!(matches!(error, UpnpError::ExistingMapping { .. }));
    assert_eq!(
        fake_gateway.mappings().get(&key(47989, Protocol::Tcp)),
        Some(&preexisting_mapping)
    );
    assert_eq!(fake_gateway.add_attempts(), 0);
    assert_eq!(manager.shutdown().unwrap(), ShutdownReport::default());
    assert_eq!(fake_gateway.mappings().len(), 1);
}

#[test]
fn failed_replacement_rolls_back_new_mappings_and_retains_old_mappings() {
    let fake_gateway = FakeGateway::default();
    let mut manager = manager(fake_gateway.clone());
    manager
        .reconcile(&[endpoint([192, 168, 1, 10], 47989, true)])
        .unwrap();
    let old_mappings = fake_gateway.mappings();
    fake_gateway.set_add_failure(key(48000, Protocol::Udp));

    let error = manager
        .reconcile(&[endpoint([192, 168, 1, 20], 48000, true)])
        .unwrap_err();

    assert!(matches!(error, UpnpError::AddFailed { .. }));
    assert_eq!(fake_gateway.mappings(), old_mappings);
    assert_eq!(manager.owned_mappings().count(), 2);
    assert_eq!(fake_gateway.add_attempts(), 4);
}

#[test]
fn shutdown_removes_only_unchanged_mappings_owned_by_this_manager() {
    let fake_gateway = FakeGateway::default();
    let mut manager = manager(fake_gateway.clone());
    manager
        .reconcile(&[endpoint([192, 168, 1, 10], 47989, true)])
        .unwrap();
    let mut changed_udp_mapping = fake_gateway
        .mappings()
        .get(&key(47989, Protocol::Udp))
        .unwrap()
        .clone();
    changed_udp_mapping.internal_address = Ipv4Addr::new(192, 168, 1, 55);
    changed_udp_mapping.description = "replaced by another owner".into();
    fake_gateway.change_mapping(changed_udp_mapping.clone());

    let report = manager.shutdown().unwrap();

    assert_eq!(
        report,
        ShutdownReport {
            removed: 1,
            already_missing: 0,
            changed_mappings_preserved: 1,
        }
    );
    assert_eq!(manager.owned_mappings().count(), 0);
    assert_eq!(fake_gateway.mappings().len(), 1);
    assert_eq!(
        fake_gateway.mappings().get(&key(47989, Protocol::Udp)),
        Some(&changed_udp_mapping)
    );
}

#[test]
fn shutdown_retries_failed_mapping_cleanup() {
    let fake_gateway = FakeGateway::default();
    let mut manager = manager(fake_gateway.clone());
    manager
        .reconcile(&[endpoint([192, 168, 1, 10], 47989, true)])
        .unwrap();
    let failed_mapping_key = key(47989, Protocol::Tcp);
    fake_gateway.set_remove_failure(Some(failed_mapping_key));

    let error = manager.shutdown().unwrap_err();

    assert!(matches!(error, UpnpError::ShutdownFailed { .. }));
    assert_eq!(manager.owned_mappings().count(), 1);
    assert!(
        manager
            .owned_mappings()
            .any(|mapping| mapping.key() == failed_mapping_key)
    );
    assert_eq!(fake_gateway.mappings().len(), 1);
    assert!(fake_gateway.mappings().contains_key(&failed_mapping_key));

    fake_gateway.set_remove_failure(None);
    assert_eq!(
        manager.shutdown().unwrap(),
        ShutdownReport {
            removed: 1,
            already_missing: 0,
            changed_mappings_preserved: 0,
        }
    );
    assert_eq!(manager.owned_mappings().count(), 0);
    assert!(fake_gateway.mappings().is_empty());
}

#[test]
fn refresh_owned_refreshes_exact_owned_mappings_with_the_recorded_tuple() {
    let fake_gateway = FakeGateway::default();
    let mut manager = manager(fake_gateway.clone());
    manager
        .reconcile(&[endpoint([192, 168, 1, 10], 47989, true)])
        .unwrap();
    let owned_mappings: Vec<Mapping> = manager.owned_mappings().cloned().collect();

    let report = manager.refresh_owned().unwrap();

    assert_eq!(
        report,
        RefreshReport {
            refreshed: 2,
            missing: 0,
            changed_mappings_preserved: 0,
        }
    );
    assert_eq!(fake_gateway.refresh_requests(), owned_mappings);
    assert_eq!(manager.owned_mappings().count(), 2);
}

#[test]
fn refresh_owned_relinquishes_missing_and_changed_mappings() {
    let fake_gateway = FakeGateway::default();
    let mut manager = manager(fake_gateway.clone());
    manager
        .reconcile(&[endpoint([192, 168, 1, 10], 47989, true)])
        .unwrap();
    let missing_key = key(47989, Protocol::Tcp);
    let changed_key = key(47989, Protocol::Udp);
    fake_gateway.remove_mapping(missing_key);
    let mut changed_mapping = fake_gateway.mappings()[&changed_key].clone();
    changed_mapping.description = "replaced by another owner".into();
    fake_gateway.change_mapping(changed_mapping.clone());

    let report = manager.refresh_owned().unwrap();

    assert_eq!(
        report,
        RefreshReport {
            refreshed: 0,
            missing: 1,
            changed_mappings_preserved: 1,
        }
    );
    assert_eq!(manager.owned_mappings().count(), 0);
    assert!(!fake_gateway.mappings().contains_key(&missing_key));
    assert_eq!(
        fake_gateway.mappings().get(&changed_key),
        Some(&changed_mapping)
    );
}

#[test]
fn refresh_owned_retains_failed_mappings_and_retries_them() {
    let fake_gateway = FakeGateway::default();
    let mut manager = manager(fake_gateway.clone());
    manager
        .reconcile(&[endpoint([192, 168, 1, 10], 47989, true)])
        .unwrap();
    let failed_key = key(47989, Protocol::Tcp);
    fake_gateway.set_refresh_failure(Some(failed_key));

    let error = manager.refresh_owned().unwrap_err();

    assert!(matches!(
        error,
        UpnpError::RefreshFailed { failures }
            if failures.len() == 1
                && failures[0].operation == super::MappingOperation::Refresh
                && failures[0].mapping == failed_key
    ));
    assert_eq!(manager.owned_mappings().count(), 2);
    assert_eq!(fake_gateway.refresh_attempts(), 2);

    fake_gateway.set_refresh_failure(None);
    let report = manager.refresh_owned().unwrap();

    assert_eq!(report.refreshed, 2);
    assert_eq!(manager.owned_mappings().count(), 2);
    assert_eq!(fake_gateway.refresh_attempts(), 4);
}

#[test]
fn remaining_lease_countdown_does_not_change_owned_mapping_identity() {
    let fake_gateway = FakeGateway::default();
    let mut manager = manager(fake_gateway.clone());
    let configured = [endpoint([192, 168, 1, 10], 47989, true)];
    manager.reconcile(&configured).unwrap();
    let tcp_key = key(47989, Protocol::Tcp);
    let udp_key = key(47989, Protocol::Udp);

    fake_gateway.set_remaining_lease_seconds(tcp_key, MAPPING_LEASE_SECONDS);
    fake_gateway.set_remaining_lease_seconds(udp_key, MAPPING_LEASE_SECONDS);
    let reconcile_report = manager.reconcile(&configured).unwrap();

    assert_eq!(reconcile_report.created, 0);
    assert_eq!(reconcile_report.already_active, 2);
    assert_eq!(manager.owned_mappings().count(), 2);

    fake_gateway.set_remaining_lease_seconds(tcp_key, MAPPING_LEASE_SECONDS - 1);
    fake_gateway.set_remaining_lease_seconds(udp_key, MAPPING_LEASE_SECONDS - 2);
    let refresh_report = manager.refresh_owned().unwrap();

    assert_eq!(refresh_report.refreshed, 2);
    assert_eq!(manager.owned_mappings().count(), 2);

    fake_gateway.set_remaining_lease_seconds(tcp_key, MAPPING_LEASE_SECONDS - 2);
    fake_gateway.set_remaining_lease_seconds(udp_key, MAPPING_LEASE_SECONDS - 3);
    assert_eq!(
        manager.shutdown().unwrap(),
        ShutdownReport {
            removed: 2,
            already_missing: 0,
            changed_mappings_preserved: 0,
        }
    );
    assert_eq!(manager.owned_mappings().count(), 0);
    assert!(fake_gateway.mappings().is_empty());
}
