use super::*;
use crate::controller::tests::{configured, request};
use crate::model::Operation;

fn query() -> NativeInterfaceQuery {
    NativeInterfaceQuery {
        header: AbiHeader::of::<NativeInterfaceQuery>(),
        interface_major: INTERFACE_MAJOR,
        min_minor: INTERFACE_MINOR,
        min_size: size_of::<ControlTransportApi>() as u32,
    }
}

unsafe fn binding(factory: &Factory, owner: &str) -> *const ControlTransportApi {
    let mut output = std::ptr::null();
    // SAFETY: all arguments remain live throughout bind; caller releases the result.
    assert_eq!(
        unsafe {
            bind(
                factory.api.context,
                BorrowedBytes::new(owner.as_bytes()),
                &query(),
                &mut output,
            )
        },
        STATUS_OK
    );
    output.cast()
}

#[test]
fn invalid_bind_clears_output_and_rejects_versions() {
    let factory = Factory::new(Arc::new(Mutex::new(configured())));
    let mut output = std::ptr::dangling::<NativeInterface>();
    // SAFETY: writable output is valid; null context must be rejected before access.
    assert_eq!(
        unsafe {
            bind(
                std::ptr::null_mut(),
                BorrowedBytes::new(b"alice"),
                &query(),
                &mut output,
            )
        },
        STATUS_INVALID_ARGUMENT
    );
    assert!(output.is_null());
    let mut unsupported = query();
    unsupported.interface_major += 1;
    assert_eq!(
        unsafe {
            bind(
                factory.api.context,
                BorrowedBytes::new(b"alice"),
                &unsupported,
                &mut output,
            )
        },
        MEDIA_UNSUPPORTED
    );
    assert!(output.is_null());
}

#[test]
fn native_handles_copy_owner_observe_shutdown_and_release_exactly_once() {
    let controller = Arc::new(Mutex::new(configured()));
    let id = controller
        .lock()
        .unwrap()
        .handle("alice", Operation::Open(request()))
        .unwrap()
        .created
        .unwrap();
    let factory = Factory::new(controller.clone());
    let owner = String::from("alice");
    // SAFETY: factory lives through bind; each resulting handle is released below.
    let alice = unsafe { binding(&factory, &owner) };
    let bob = unsafe { binding(&factory, "bob") };
    drop(owner);
    drop(factory);
    assert_eq!(Arc::strong_count(&controller), 3);
    let sink = ControlMessageSink {
        context: std::ptr::null_mut(),
        write: None,
    };
    // SAFETY: both bindings remain live and sink has no callback allocation.
    unsafe {
        assert_eq!(
            ((*bob).receive)((*bob).base.context, id, sink),
            MEDIA_CLOSED
        );
        assert_eq!(
            ((*alice).receive)((*alice).base.context, id, sink),
            STATUS_INVALID_ARGUMENT
        );
        let lock = controller.lock().unwrap();
        assert_eq!(
            ((*alice).receive)((*alice).base.context, id, sink),
            MEDIA_BUSY
        );
        drop(lock);
        controller.lock().unwrap().shutdown();
        assert_eq!(
            ((*alice).receive)((*alice).base.context, id, sink),
            MEDIA_CLOSED
        );
        ((*alice).base.release.unwrap())((*alice).base.context);
        ((*bob).base.release.unwrap())((*bob).base.context);
    }
    assert_eq!(Arc::strong_count(&controller), 1);
}
