#[test]
fn application_preparation_can_exceed_startup_deadline_before_rtsp_admission() {
    let started = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut broker = Broker {
        application_state: "starting",
        ..Broker::default()
    };

    assert!(
        controller
            .launch(10, request(1), peer(1), started)
            .is_none()
    );
    for _ in 0..128 {
        assert!(
            controller
                .poll(started, &mut |command| broker.send(command))
                .is_empty()
        );
        if controller.records.values().next().unwrap().stage == Stage::AwaitApplicationReady {
            break;
        }
    }
    assert_eq!(
        controller.records.values().next().unwrap().stage,
        Stage::AwaitApplicationReady
    );

    let launch_export = broker
        .commands
        .iter()
        .find_map(|command| match command {
            Command::Request {
                service, payload, ..
            } if service == "amaterasu.launch/1" && payload["action"] == "launch_export" => {
                Some(payload)
            }
            _ => None,
        })
        .expect("launch export request");
    assert!(
        launch_export["return_on_admission"]
            .as_bool()
            .unwrap_or(false)
    );

    for elapsed_seconds in 1..=50 {
        let now = started + Duration::from_secs(elapsed_seconds);
        for _ in 0..3 {
            assert!(
                controller
                    .poll(now, &mut |command| broker.send(command))
                    .is_empty()
            );
        }
    }

    let record = controller.records.values().next().unwrap();
    assert_eq!(record.stage, Stage::AwaitApplicationReady);
    assert_eq!(record.state, super::record::State::Starting);
    assert!(controller.busy());
    assert!(!broker.actions().contains(&("amaterasu.rtsp/1", "open")));
    let status_timeouts: Vec<_> = broker
        .commands
        .iter()
        .filter_map(|command| match command {
            Command::Request {
                service,
                payload,
                timeout_ms,
                ..
            } if service == "amaterasu.launch/1" && payload["action"] == "status" => {
                Some(*timeout_ms)
            }
            _ => None,
        })
        .collect();
    assert!(status_timeouts.len() >= 20);
    assert!(status_timeouts.iter().all(|timeout| *timeout == 5_000));

    broker.application_state = "active";
    let ready_at = started + Duration::from_secs(51);
    let (connection, reply) = poll_until_reply(&mut controller, &mut broker, ready_at);
    assert_eq!(connection, 10);
    assert_eq!(reply.status, 200);
    assert!(broker.actions().contains(&("amaterasu.rtsp/1", "open")));
    assert_eq!(
        controller.records.values().next().unwrap().deadline,
        ready_at + INITIAL_DEADLINE
    );
}

#[test]
fn explicit_cancel_stops_application_while_preparation_is_still_running() {
    let started = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut broker = Broker {
        application_state: "starting",
        ..Broker::default()
    };

    assert!(
        controller
            .launch(10, request(1), peer(1), started)
            .is_none()
    );
    for _ in 0..128 {
        assert!(
            controller
                .poll(started, &mut |command| broker.send(command))
                .is_empty()
        );
        if controller.records.values().next().unwrap().stage == Stage::AwaitApplicationReady {
            break;
        }
    }
    assert_eq!(
        controller.records.values().next().unwrap().stage,
        Stage::AwaitApplicationReady
    );

    assert!(
        controller
            .cancel(20, &peer(1), started + Duration::from_secs(1))
            .is_none()
    );
    let (connection, reply) = poll_until_reply(
        &mut controller,
        &mut broker,
        started + Duration::from_secs(1),
    );
    assert_eq!(connection, 20);
    assert_eq!(reply.status, 200);
    assert!(broker.actions().contains(&("amaterasu.launch/1", "stop")));
    assert!(!broker.actions().contains(&("amaterasu.rtsp/1", "open")));
    assert_eq!(controller.current_game(&peer(1)), 0);
}

#[test]
fn application_readiness_reuses_an_existing_rtsp_ticket() {
    let started = Instant::now();
    let mut controller = Controller::new(Some(config())).unwrap();
    let mut broker = Broker {
        application_state: "starting",
        ..Broker::default()
    };

    assert!(
        controller
            .launch(10, request(1), peer(1), started)
            .is_none()
    );
    for _ in 0..128 {
        assert!(
            controller
                .poll(started, &mut |command| broker.send(command))
                .is_empty()
        );
        if controller.records.values().next().unwrap().stage == Stage::AwaitApplicationReady {
            break;
        }
    }
    assert_eq!(
        controller.records.values().next().unwrap().stage,
        Stage::AwaitApplicationReady
    );

    let record = controller.records.values_mut().next().unwrap();
    record.rtsp_ticket = Some(77);
    record.rtsp_url = Some("rtspenc://127.0.0.1:48010/existing".into());
    record.rtsp_requested = true;
    broker.application_state = "active";

    let (connection, reply) = poll_until_reply(
        &mut controller,
        &mut broker,
        started + Duration::from_secs(1),
    );

    assert_eq!(connection, 10);
    assert_eq!(reply.status, 200);
    assert!(!broker.actions().contains(&("amaterasu.rtsp/1", "open")));
}
