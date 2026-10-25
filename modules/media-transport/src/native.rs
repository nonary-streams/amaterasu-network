use crate::controller::Controller;
use amaterasu_media::{
    EncodedAudioPacket, EncodedPacket, INTERFACE_MAJOR, INTERFACE_MINOR, MEDIA_BACKEND_ERROR,
    MEDIA_BUSY, MEDIA_UNSUPPORTED, MediaTransportApi,
};
use amaterasu_module_sdk::abi::*;
use std::{
    ffi::c_void,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, Mutex, TryLockError},
};

pub type Shared = Arc<Mutex<Controller>>;

pub struct Factory {
    pub api: NativeServiceFactory,
    shared: Shared,
}

impl Factory {
    pub fn new(shared: Shared) -> Box<Self> {
        let mut factory = Box::new(Self {
            api: NativeServiceFactory {
                header: AbiHeader::of::<NativeServiceFactory>(),
                context: std::ptr::null_mut(),
                bind: Some(bind),
            },
            shared,
        });
        factory.api.context = (&mut *factory as *mut Self).cast();
        factory
    }
}

struct Binding {
    api: MediaTransportApi,
    shared: Shared,
    owner: String,
}

unsafe extern "C" fn bind(
    context: *mut c_void,
    principal: BorrowedBytes,
    query: *const NativeInterfaceQuery,
    output: *mut *const NativeInterface,
) -> Status {
    guarded(|| {
        if context.is_null() || query.is_null() || output.is_null() {
            return STATUS_INVALID_ARGUMENT;
        }
        // SAFETY: the runtime supplies a live boxed factory, query, output and
        // callback-lifetime principal. Only the copied owner and Arc are retained.
        unsafe {
            *output = std::ptr::null();
            let query = &*query;
            if !query.header.supports::<NativeInterfaceQuery>()
                || query.interface_major != INTERFACE_MAJOR
                || query.min_minor > INTERFACE_MINOR
                || query.min_size as usize > size_of::<MediaTransportApi>()
            {
                return MEDIA_UNSUPPORTED;
            }
            let owner = match principal
                .read()
                .ok()
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
            {
                Some(owner) if !owner.is_empty() && owner.len() <= 128 => owner.to_owned(),
                _ => return STATUS_INVALID_ARGUMENT,
            };
            let mut binding = Box::new(Binding {
                api: MediaTransportApi {
                    base: NativeInterface {
                        header: AbiHeader {
                            size: size_of::<MediaTransportApi>() as u32,
                            major: INTERFACE_MAJOR,
                            minor: INTERFACE_MINOR,
                        },
                        context: std::ptr::null_mut(),
                        release: Some(release),
                    },
                    submit_video,
                    submit_audio,
                    drain,
                },
                shared: (&*context.cast::<Factory>()).shared.clone(),
                owner,
            });
            binding.api.base.context = (&mut *binding as *mut Binding).cast();
            let pointer = Box::into_raw(binding);
            *output = &(*pointer).api.base;
        }
        STATUS_OK
    })
}

unsafe extern "C" fn release(context: *mut c_void) {
    let _ = guarded(|| {
        if !context.is_null() {
            // SAFETY: this unique binding is released once, after all calls end.
            drop(unsafe { Box::from_raw(context.cast::<Binding>()) });
        }
        STATUS_OK
    });
}

unsafe extern "C" fn submit_video(
    context: *mut c_void,
    id: u64,
    packet: *const EncodedPacket,
) -> Status {
    guarded(|| {
        if packet.is_null() {
            return STATUS_INVALID_ARGUMENT;
        }
        // SAFETY: native caller supplies a live table context, readable packet
        // header and initialized immutable bytes until this callback returns.
        unsafe {
            with_controller(context, |controller, owner| {
                controller.submit_video(owner, id, &*packet)
            })
        }
    })
}

unsafe extern "C" fn submit_audio(
    context: *mut c_void,
    id: u64,
    packet: *const EncodedAudioPacket,
) -> Status {
    guarded(|| {
        if packet.is_null() {
            return STATUS_INVALID_ARGUMENT;
        }
        // SAFETY: caller keeps the complete packet allocation and binding alive.
        unsafe {
            with_controller(context, |controller, owner| {
                controller.submit_audio(owner, id, &*packet)
            })
        }
    })
}

unsafe extern "C" fn drain(context: *mut c_void, id: u64) -> Status {
    guarded(|| {
        // SAFETY: binding remains live throughout the call.
        unsafe { with_controller(context, |controller, owner| controller.drain(owner, id)) }
    })
}

unsafe fn with_controller(
    context: *mut c_void,
    operation: impl FnOnce(&mut Controller, &str) -> Status,
) -> Status {
    if context.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }
    // SAFETY: the callback caller guarantees this live binding allocation.
    let binding = unsafe { &*context.cast::<Binding>() };
    let mut controller = match binding.shared.try_lock() {
        Ok(controller) => controller,
        Err(TryLockError::WouldBlock) => return MEDIA_BUSY,
        Err(TryLockError::Poisoned(_)) => return MEDIA_BACKEND_ERROR,
    };
    operation(&mut controller, &binding.owner)
}

fn guarded(operation: impl FnOnce() -> Status) -> Status {
    catch_unwind(AssertUnwindSafe(operation)).unwrap_or(STATUS_INTERNAL_ERROR)
}

#[cfg(test)]
mod tests;
