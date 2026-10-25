use super::*;
use crate::launch::Controller as LaunchController;
use crate::wire::{Request, RequestContext, RouterConfig};
use amaterasu_module_sdk::{Command, ModuleResult, Response};
use std::collections::VecDeque;

fn entry(id: u64, name: &str) -> Value {
    json!({"id":format!("app-{id:016x}"),"name":name})
}

fn page(revision: u64, entries: Vec<Value>, after: Option<u64>) -> Value {
    json!({"ok":true,"revision":revision,"entries":entries,"next_cursor":after.map(|after| json!({"revision":revision,"after":format!("app-{after:016x}"),"query":""}))})
}

fn router() -> Router {
    Router::new(
        RouterConfig {
            hostname: "test".into(),
            http_port: 1,
            https_port: 2,
        },
        LaunchController::new(None).unwrap(),
    )
}

fn request_context(secure: bool, trusted: bool, certificate: bool) -> RequestContext {
    RequestContext {
        secure,
        peer_trusted: trusted,
        remote: "127.0.0.1".parse().unwrap(),
        peer_certificate: certificate.then(|| vec![1, 2, 3]),
    }
}

fn dispatch(router: &mut Router, context: RequestContext, now: Instant) -> Option<Reply> {
    router.dispatch_with(
        1,
        Request {
            method: "GET".into(),
            target: "/applist?uniqueid=untrusted-metadata".into(),
            body: Vec::new(),
        },
        context,
        now,
        &mut |_| panic!("dispatch must only queue catalog work"),
    )
}

#[derive(Default)]
struct Catalog {
    pages: VecDeque<Value>,
    requests: Vec<Value>,
    next: u64,
    hold: bool,
    cancelled: Vec<u64>,
}

impl Catalog {
    fn send(&mut self, command: Command) -> ModuleResult<Response> {
        Ok(match command {
            Command::Request {
                service,
                payload,
                timeout_ms,
                ..
            } => {
                assert_eq!(service, CATALOG_SERVICE);
                assert_eq!(payload["action"], "export_list");
                assert_eq!(payload["limit"], PAGE_SIZE);
                assert!(timeout_ms <= 5000);
                self.requests.push(payload);
                self.next += 1;
                Response::Accepted { id: self.next }
            }
            Command::TakeResult { request } if self.cancelled.contains(&request) => {
                Response::Error {
                    code: "cancelled".into(),
                    message: String::new(),
                }
            }
            Command::TakeResult { .. } if self.hold => Response::Pending,
            Command::TakeResult { .. } => Response::Result {
                payload: self.pages.pop_front().expect("expected catalog page"),
            },
            Command::Cancel { request } => {
                self.cancelled.push(request);
                Response::Ok
            }
            other => panic!("unexpected catalog request {other:?}"),
        })
    }
}

fn poll(router: &mut Router, catalog: &mut Catalog, now: Instant) -> Vec<(u64, Reply)> {
    router.poll_with(now, &mut |command| catalog.send(command))
}

#[test]
fn catalog_is_never_called_without_paired_tls_possession() {
    let now = Instant::now();
    for context in [
        request_context(false, true, true),
        request_context(true, false, true),
        request_context(true, true, false),
    ] {
        let mut router = router();
        assert_eq!(dispatch(&mut router, context, now).unwrap().status, 401);
        assert!(router.jobs.is_empty());
        assert!(
            router
                .poll_with(now, &mut |_| panic!("untrusted catalog call"))
                .is_empty()
        );
    }
}

#[test]
fn forty_entries_require_two_pages_before_one_complete_xml_reply() {
    let now = Instant::now();
    let mut router = router();
    let mut catalog = Catalog {
        pages: VecDeque::from([
            page(
                7,
                (1..=32)
                    .map(|id| entry(id, "A<&\"'\u{fffe}\u{ffff}"))
                    .collect(),
                Some(32),
            ),
            page(
                7,
                (33..=40).map(|id| entry(id, "second page")).collect(),
                None,
            ),
        ]),
        ..Default::default()
    };
    assert!(dispatch(&mut router, request_context(true, true, true), now).is_none());
    for _ in 0..3 {
        assert!(poll(&mut router, &mut catalog, now).is_empty());
    }
    let mut replies = poll(&mut router, &mut catalog, now);
    assert_eq!(replies.len(), 1);
    let reply = replies.pop().unwrap().1;
    assert!(reply.requires_paired_tls);
    let body = String::from_utf8(reply.body).unwrap();
    assert_eq!(body.matches("<App>").count(), 40);
    assert!(body.contains("<AppTitle>A&lt;&amp;&quot;&apos;  </AppTitle>"));
    assert!(body.contains("<ID>1</ID>"));
    assert!(body.contains("<ID>40</ID>"));
    assert_eq!(
        body.matches("<IsHdrSupported>0</IsHdrSupported>").count(),
        40
    );
    // No client may be told a title is HDR-capable until a real 10-bit path exists.
    assert!(!body.contains("<IsHdrSupported>1</IsHdrSupported>"));
    assert_eq!(
        catalog.requests[1]["cursor"]["after"],
        "app-0000000000000020"
    );
    assert_eq!(catalog.requests[1]["cursor"]["revision"], 7);
}

#[test]
fn snapshot_changes_and_provider_errors_never_return_the_partial_list() {
    for final_page in [
        page(8, vec![entry(2, "later")], None),
        json!({"ok":false,"error":{"code":"revision_conflict"}}),
    ] {
        let now = Instant::now();
        let mut router = router();
        let mut catalog = Catalog {
            pages: VecDeque::from([
                page(7, vec![entry(1, "secret partial title")], Some(1)),
                final_page,
            ]),
            ..Default::default()
        };
        dispatch(&mut router, request_context(true, true, true), now);
        for _ in 0..3 {
            assert!(poll(&mut router, &mut catalog, now).is_empty());
        }
        let reply = poll(&mut router, &mut catalog, now).pop().unwrap().1;
        assert_eq!(reply.status, 409);
        assert!(
            !String::from_utf8(reply.body)
                .unwrap()
                .contains("secret partial title")
        );
    }
    assert_eq!(
        Applications::new(false)
            .accept(json!({"ok":false,"error":{"code":"permission_denied"}}))
            .err()
            .unwrap()
            .status,
        503
    );
}

#[test]
fn moonlight_ids_are_checked_without_hashing_or_truncation() {
    assert_eq!(numeric_id("app-0000000000000001"), Ok(1));
    assert_eq!(numeric_id("app-000000007fffffff"), Ok(i32::MAX as u32));
    for invalid in [
        "app-0000000000000000",
        "app-0000000080000000",
        "app-ffffffffffffffff",
        "app-000000000000000A",
        "app-1",
        "other-0000000000000001",
    ] {
        assert!(numeric_id(invalid).is_err(), "{invalid}");
        assert_eq!(
            Applications::new(false)
                .accept(page(1, vec![json!({"id":invalid,"name":"invalid"})], None))
                .err()
                .unwrap()
                .status,
            502
        );
    }
}

#[test]
fn malformed_pages_duplicate_ids_and_nonadvancing_cursors_fail_closed() {
    for invalid in [
        json!({"ok":true,"revision":1,"entries":[]}),
        json!({"ok":true,"revision":"1","entries":[],"next_cursor":null}),
        page(1, vec![entry(1, "a"), entry(1, "b")], None),
        page(1, vec![entry(2, "a"), entry(1, "b")], None),
        page(1, vec![], Some(1)),
        page(1, vec![entry(1, "a")], Some(2)),
        page(1, vec![entry(1, "\n")], None),
    ] {
        assert_eq!(
            Applications::new(false)
                .accept(invalid)
                .err()
                .unwrap()
                .status,
            502
        );
    }
    let mut accumulator = Applications::new(false);
    accumulator
        .accept(page(1, vec![entry(1, "a")], Some(1)))
        .unwrap();
    assert_eq!(
        accumulator
            .accept(page(1, vec![entry(1, "a")], Some(1)))
            .err()
            .unwrap()
            .status,
        502
    );
}

#[test]
fn byte_entry_page_and_concurrency_bounds_are_visible() {
    let mut accumulator = Applications::new(false);
    let long_name = "&".repeat(160);
    let mut overflow = None;
    for page_index in 0..100 {
        let start = page_index * PAGE_SIZE as u64 + 1;
        let end = start + PAGE_SIZE as u64 - 1;
        let result = accumulator.accept(page(
            1,
            (start..=end).map(|id| entry(id, &long_name)).collect(),
            Some(end),
        ));
        if let Err(reply) = result {
            overflow = Some(reply);
            break;
        }
    }
    assert_eq!(overflow.unwrap().status, 413);
    assert!(accumulator.body.len() < MAX_XML_BYTES);
    let mut accumulator = Applications::new(false);
    accumulator.entries = MAX_ENTRIES;
    assert_eq!(
        accumulator
            .accept(page(1, vec![entry(1, "x")], None))
            .err()
            .unwrap()
            .status,
        413
    );
    let mut accumulator = Applications::new(false);
    accumulator.pages = MAX_PAGES;
    assert_eq!(
        accumulator
            .accept(page(1, vec![], None))
            .err()
            .unwrap()
            .status,
        413
    );
    let mut router = router();
    let now = Instant::now();
    for _ in 0..MAX_ACTIVE_LISTS {
        assert!(dispatch(&mut router, request_context(true, true, true), now).is_none());
    }
    assert_eq!(
        dispatch(&mut router, request_context(true, true, true), now)
            .unwrap()
            .status,
        503
    );
}

#[test]
fn cancellation_and_total_deadline_cancel_outstanding_catalog_work() {
    for expired in [false, true] {
        let now = Instant::now();
        let mut router = router();
        let mut catalog = Catalog {
            hold: true,
            ..Default::default()
        };
        dispatch(&mut router, request_context(true, true, true), now);
        poll(&mut router, &mut catalog, now);
        if expired {
            let reply = poll(&mut router, &mut catalog, now + LIST_TIMEOUT)
                .pop()
                .unwrap()
                .1;
            assert_eq!(reply.status, 504);
        } else {
            router.cancel_with(1, now, &mut |command| catalog.send(command));
        }
        assert!(router.jobs.is_empty());
        assert_eq!(catalog.cancelled, vec![1]);
        assert_eq!(catalog.requests.len(), 1);
    }
}

#[test]
fn revocation_before_response_discards_complete_catalog_xml() {
    let mut applications = Applications::new(false);
    applications
        .accept(page(1, vec![entry(1, "private app")], None))
        .unwrap();
    let reply = applications.finish().authorize(false);
    assert_eq!(reply.status, 401);
    assert!(
        !String::from_utf8(reply.body)
            .unwrap()
            .contains("private app")
    );
    assert_eq!(xml::paired().authorize(false).status, 200);
}

#[test]
fn failed_cleanup_retains_request_and_admission_slot_until_release() {
    for expired in [false, true] {
        let now = Instant::now();
        let mut router = router();
        let mut catalog = Catalog {
            hold: true,
            ..Default::default()
        };
        dispatch(&mut router, request_context(true, true, true), now);
        poll(&mut router, &mut catalog, now);
        let cleanup_time = if expired { now + LIST_TIMEOUT } else { now };
        let mut failures = |_| -> ModuleResult<Response> { Err("transport unavailable".into()) };
        if expired {
            assert_eq!(
                router.poll_with(cleanup_time, &mut failures)[0].1.status,
                504
            );
        } else {
            router.cancel_with(1, cleanup_time, &mut failures);
        }
        assert!(router.jobs.is_empty());
        assert!(router.cancellations.contains_key(&1));
        for _ in 1..crate::wire::MAX_JOBS {
            router
                .queue(
                    None,
                    crate::wire::Purpose::Cleanup,
                    json!({}),
                    now + Duration::from_secs(300),
                    now + Duration::from_secs(300),
                )
                .unwrap();
        }
        assert!(
            router
                .queue(None, crate::wire::Purpose::Cleanup, json!({}), now, now)
                .is_err()
        );
        // No immediate busy-loop retry and no dropped ID when cancellation succeeds
        // but consuming/releasing the terminal result still fails.
        router.poll_with(cleanup_time, &mut |_| panic!("cleanup retried too early"));
        let retry_time = cleanup_time + Duration::from_millis(100);
        router.poll_with(retry_time, &mut |command| match command {
            Command::Cancel { request: 1 } => Ok(Response::Ok),
            Command::TakeResult { request: 1 } => Err("release acknowledgement lost".into()),
            other => panic!("unexpected {other:?}"),
        });
        assert!(router.cancellations.contains_key(&1));
        router.poll_with(
            retry_time + Duration::from_millis(100),
            &mut |command| match command {
                Command::Cancel { request: 1 } | Command::TakeResult { request: 1 } => {
                    Ok(Response::Error {
                        code: "not_found".into(),
                        message: String::new(),
                    })
                }
                other => panic!("unexpected {other:?}"),
            },
        );
        assert!(router.cancellations.is_empty());
        assert_eq!(catalog.requests.len(), 1);
    }
}

#[test]
fn failed_result_release_enters_cleanup_without_replaying_catalog_page() {
    let now = Instant::now();
    let mut router = router();
    let mut catalog = Catalog {
        hold: true,
        ..Default::default()
    };
    dispatch(&mut router, request_context(true, true, true), now);
    poll(&mut router, &mut catalog, now);
    let replies = router.poll_with(now, &mut |_| Err("result release failed".into()));
    assert_eq!(replies.len(), 1);
    assert!(router.jobs.is_empty());
    assert!(router.cancellations.contains_key(&1));
    router.poll_with(now + Duration::from_millis(100), &mut |command| {
        catalog.send(command)
    });
    assert!(router.cancellations.is_empty());
    assert_eq!(catalog.requests.len(), 1);
}

#[test]
fn desktop_entry_is_opt_in_and_catalog_collision_fails_closed() {
    let desktop_only = Applications::new(true).finish();
    let body = String::from_utf8(desktop_only.body).unwrap();
    assert!(body.contains("<AppTitle>Desktop</AppTitle>"));
    assert!(body.contains("<ID>2147483647</ID>"));
    assert!(
        !String::from_utf8(Applications::new(false).finish().body)
            .unwrap()
            .contains("Desktop")
    );

    let collision = Applications::new(true)
        .accept(page(1, vec![entry(i32::MAX as u64, "collision")], None))
        .err()
        .unwrap();
    assert_eq!(collision.status, 502);
}

#[test]
fn desktop_list_survives_missing_or_unavailable_catalog_provider() {
    let now = Instant::now();
    for failure in [
        Err("catalog provider is not registered".to_owned()),
        Ok(json!({"ok":false,"error":{"code":"permission_denied"}})),
    ] {
        let mut router = router();
        let job = Job {
            connection: Some(7),
            purpose: Purpose::Applications {
                desktop_enabled: true,
            },
            call: Call::Ready {
                payload: json!({}),
                not_before: now,
            },
            deadline: now + LIST_TIMEOUT,
            applications: Some(Applications::new(true)),
        };
        let mut replies = Vec::new();
        assert!(
            router
                .resolve_applications(job, failure, now, &mut replies)
                .is_none()
        );
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].1.status, 200);
        assert!(
            String::from_utf8(replies.pop().unwrap().1.body)
                .unwrap()
                .contains("<AppTitle>Desktop</AppTitle>")
        );
    }
}
