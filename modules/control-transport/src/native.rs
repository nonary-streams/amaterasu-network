//! Native handles retain only the synchronized controller and a copied principal.
use crate::controller::Controller;
use amaterasu_media::*;
use amaterasu_module_sdk::abi::*;
use std::{
    ffi::c_void,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, Mutex, TryLockError},
};

pub type Shared = Arc<Mutex<Controller>>;

pub struct Factory {
    pub api: NativeServiceFactory,
    controller: Shared,
}

impl Factory {
    pub fn new(controller: Shared) -> Box<Self> {
        let mut factory = Box::new(Self {
            api: NativeServiceFactory {
                header: AbiHeader::of::<NativeServiceFactory>(),
                context: std::ptr::null_mut(),
                bind: Some(bind),
            },
            controller,
        });
        factory.api.context = (&mut *factory as *mut Self).cast();
        factory
    }
}

struct Binding {
    api: ControlTransportApi,
    controller: Shared,
    owner: String,
}

unsafe extern "C" fn bind(
    context: *mut c_void,
    principal: BorrowedBytes,
    query: *const NativeInterfaceQuery,
    output: *mut *const NativeInterface,
) -> Status {
    guard(|| {
        if output.is_null() {
            return STATUS_INVALID_ARGUMENT;
        }
        // SAFETY: a non-null output is writable under the factory ABI contract.
        unsafe {
            *output = std::ptr::null();
        }
        if context.is_null() || query.is_null() {
            return STATUS_INVALID_ARGUMENT;
        }
        // SAFETY: runtime supplies a live factory and initialized query/output.
        // The principal is borrowed only for this callback and copied below.
        unsafe {
            let query = &*query;
            if !query.header.supports::<NativeInterfaceQuery>()
                || query.interface_major != INTERFACE_MAJOR
                || query.min_minor > INTERFACE_MINOR
                || query.min_size as usize > size_of::<ControlTransportApi>()
            {
                return MEDIA_UNSUPPORTED;
            }
            let Some(owner) = principal
                .read()
                .ok()
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .filter(|owner| crate::model::valid_name(owner))
            else {
                return STATUS_INVALID_ARGUMENT;
            };
            let mut binding = Box::new(Binding {
                api: ControlTransportApi {
                    base: NativeInterface {
                        header: AbiHeader {
                            size: size_of::<ControlTransportApi>() as u32,
                            major: INTERFACE_MAJOR,
                            minor: INTERFACE_MINOR,
                        },
                        context: std::ptr::null_mut(),
                        release: Some(release),
                    },
                    send,
                    receive,
                },
                controller: (&*context.cast::<Factory>()).controller.clone(),
                owner: owner.into(),
            });
            binding.api.base.context = (&mut *binding as *mut Binding).cast();
            *output = &(*Box::into_raw(binding)).api.base;
        }
        STATUS_OK
    })
}

unsafe extern "C" fn release(context: *mut c_void) {
    let _ = guard(|| {
        if !context.is_null() {
            // SAFETY: runtime releases this unique binding once after all calls end.
            drop(unsafe { Box::from_raw(context.cast::<Binding>()) });
        }
        STATUS_OK
    });
}

unsafe extern "C" fn send(
    context: *mut c_void,
    stream: u64,
    message: *const ControlMessage,
) -> Status {
    guard(|| {
        if message.is_null() {
            return STATUS_INVALID_ARGUMENT;
        }
        // SAFETY: consumer keeps context, message and initialized payload alive.
        unsafe {
            with_controller(context, |controller, owner| {
                controller.send(owner, stream, &*message)
            })
        }
    })
}

unsafe extern "C" fn receive(
    context: *mut c_void,
    stream: u64,
    sink: ControlMessageSink,
) -> Status {
    guard(|| {
        // SAFETY: consumer keeps its binding and callback context live through return.
        unsafe {
            with_controller(context, |controller, owner| {
                controller.receive(owner, stream, sink)
            })
        }
    })
}

unsafe fn with_controller(
    context: *mut c_void,
    operation: impl FnOnce(&mut Controller, &str) -> Status,
) -> Status {
    if context.is_null() {
        return STATUS_INVALID_ARGUMENT;
    }
    // SAFETY: caller holds a live binding; the immutable handle may be shared.
    let binding = unsafe { &*context.cast::<Binding>() };
    match binding.controller.try_lock() {
        Ok(mut controller) => operation(&mut controller, &binding.owner),
        Err(TryLockError::WouldBlock) => MEDIA_BUSY,
        Err(TryLockError::Poisoned(_)) => MEDIA_BACKEND_ERROR,
    }
}

fn guard(operation: impl FnOnce() -> Status) -> Status {
    catch_unwind(AssertUnwindSafe(operation)).unwrap_or(MEDIA_BACKEND_ERROR)
}

#[cfg(test)]
mod tests;
