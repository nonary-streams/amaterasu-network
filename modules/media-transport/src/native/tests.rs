use super::*;
use crate::{
    model::{Operation, Settings},
    stream::tests::{receivers, request, video_packet},
};
use amaterasu_media::MEDIA_CLOSED;

#[test]
fn bound_native_tables_isolate_owners_and_remain_closed_after_shutdown() {
    let (video, audio) = receivers();
    let shared = Arc::new(Mutex::new(Controller::new(Settings {
        enabled: true,
        allow_remote: false,
        allowed_principals: vec!["owner".into()],
    })));
    let id = shared
        .lock()
        .unwrap()
        .handle("owner", Operation::Open(request(&video, &audio, false)))
        .unwrap()
        .created
        .unwrap();
    let factory = Factory::new(shared.clone());
    let query = NativeInterfaceQuery {
        header: AbiHeader::of::<NativeInterfaceQuery>(),
        interface_major: INTERFACE_MAJOR,
        min_minor: INTERFACE_MINOR,
        min_size: size_of::<MediaTransportApi>() as u32,
    };
    let bytes = [0, 0, 0, 1, 0x65, 1];
    for owner in ["other", "owner"] {
        let mut output = std::ptr::null();
        // SAFETY: test factory/query/output and packet pointers remain live. Each
        // returned binding is released once after its synchronous callbacks end.
        unsafe {
            assert_eq!(
                factory.api.bind.unwrap()(
                    factory.api.context,
                    BorrowedBytes::new(owner.as_bytes()),
                    &query,
                    &mut output
                ),
                STATUS_OK
            );
            let api = &*output.cast::<MediaTransportApi>();
            assert_eq!(
                (api.submit_video)(api.base.context, id, &video_packet(&bytes, 0)),
                if owner == "owner" {
                    STATUS_OK
                } else {
                    MEDIA_CLOSED
                }
            );
            assert_eq!(
                (api.submit_video)(api.base.context, id, std::ptr::null()),
                STATUS_INVALID_ARGUMENT
            );
            if owner == "owner" {
                let guard = shared.lock().unwrap();
                assert_eq!((api.drain)(api.base.context, id), MEDIA_BUSY);
                drop(guard);
                shared.lock().unwrap().shutdown();
                assert_eq!((api.drain)(api.base.context, id), MEDIA_CLOSED);
            }
            api.base.release.unwrap()(api.base.context);
        }
    }
}
