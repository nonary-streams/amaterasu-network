# UPnP listener mapping lifecycle

This crate provides owned UPnP lifecycles for IPv4 port mappings and IPv6 firewall
pinholes. The caller supplies live listener endpoints to
`MappingManager::reconcile` or protocol-specific endpoints to
`MappingManager::reconcile_protocols`; the IPv4 adapter skips inactive,
zero-port, and IPv6 endpoints. External and internal IPv4 ports are the same.

Reconcile creates every replacement before removing stale mappings. If an add
fails, mappings created during that attempt are rolled back and the old owned
mappings remain. Existing mappings are never adopted or intentionally replaced.
Changing an endpoint's IPv4 address while keeping the same external port and
protocol cannot be staged on IGD, so reconcile reports the existing mapping and
leaves it intact.

Call `MappingManager::shutdown` during orderly shutdown. It removes only
mappings the manager successfully created whose full recorded mapping still
matches. Modified mappings are preserved. IGD exposes inspection and deletion as
separate operations, so the real adapter checks immediately before deletion;
the protocol does not provide an atomic compare-and-delete operation.
Likewise, creation preflights the mapping table before `AddPortMapping`, but
IGD does not provide an atomic create-if-absent operation; an external writer
could race between those requests. Refresh also checks the complete mapping
immediately before `AddPortMapping`; IGD provides no atomic compare-and-refresh
operation, so an external writer could race between the check and refresh.

Call `MappingManager::refresh_owned` periodically to reassert owned mappings.
It refreshes only mappings whose complete recorded value still matches, drops
ownership for missing or changed mappings, and preserves changed gateway entries.
Refresh errors are returned and their mappings remain owned for a later retry.
The requested lease is one hour, and
`RECOMMENDED_REFRESH_INTERVAL` is 120 seconds. IGDv2 reports the remaining lease
and counts it down, so that dynamic value is excluded from stable ownership
comparisons. The crate exposes the interval but does not run a timer; its caller
must schedule refreshes.

`discover_gateway` applies the crate's two-second search timeout and returns
discovery errors. Mapping, cleanup, and refresh errors are returned to the
caller.

`discover_ipv6_firewalls` separately searches `ff02::c` from each selected local
IPv6 interface, retaining that interface scope for the gateway's link-local
control endpoint. `PinholeManager` uses `WANIPv6FirewallControl`, asks for a
3600-second lease, refreshes owned pinhole IDs on the caller's schedule, and
deletes only IDs created by that manager. As in the reference behavior,
`GetFirewallStatus` gates additions on `NewInboundPinholeAllowed`; the reported
firewall-enabled bit is informational. The NVHTTP caller runs discovery and
refresh every 120 seconds and removes owned pinholes during orderly shutdown.
This exact-ID tracking and cleanup is a stricter lifecycle than the pinned
implementation, which relies on lease expiry after `AddPinhole`.

Tests use deterministic fake IPv4/IPv6 gateway controls and local protocol
fixtures; they do not contact a router or change host firewall state. No physical
router interoperability test has been run.

Mapping ownership is deliberately stricter than the pinned implementation:
pre-existing or externally changed conflicts are preserved instead of deleted.
The IGD protocol still has check-then-act races around create, refresh, and
delete; the adapter documents those limits at each operation.
