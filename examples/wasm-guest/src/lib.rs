//! A Rust guest for the Poring WIT world (`wit/poring-plugin.wit`).
//!
//! `no_std` + `alloc` with a bump allocator: every request runs in a fresh instance whose
//! memory is discarded afterwards, so freeing is unnecessary. No WASI is imported; the guest
//! has no filesystem, network, clock or environment access.
#![cfg_attr(target_arch = "wasm32", no_std)]

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec;

wit_bindgen::generate!({
    path: "../../crates/poring/wit",
    world: "guest",
});

use exports::poring::plugin::handler::{Guest, GuestError, GuestInfo, Header, Request, Response};

struct EchoGuest;

impl Guest for EchoGuest {
    fn info() -> GuestInfo {
        GuestInfo {
            name: String::from("rust-echo"),
            version: String::from(env!("CARGO_PKG_VERSION")),
            abi: 1,
            capabilities: vec![],
        }
    }

    fn handle(req: Request) -> Result<Response, GuestError> {
        if req.path.ends_with("/teapot") {
            return Err(GuestError { status: 418, message: String::from("I'm a teapot") });
        }
        let who = req.principal.unwrap_or_else(|| String::from("anonymous"));
        let body = format!("hello {who} from rust-echo {}: {} {}", env!("CARGO_PKG_VERSION"), req.method, req.path);
        Ok(Response {
            status: 200,
            headers: vec![Header { name: String::from("content-type"), value: String::from("text/plain") }],
            body: body.into_bytes(),
        })
    }
}

export!(EchoGuest);

#[cfg(target_arch = "wasm32")]
mod rt {
    use core::alloc::{GlobalAlloc, Layout};
    use core::cell::UnsafeCell;

    /// Bump allocator over linear memory (grows via `memory.grow`, never frees).
    struct Bump(UnsafeCell<usize>);
    // SAFETY: Wasm guests are single-threaded (one instance per request, no threads).
    unsafe impl Sync for Bump {}

    #[global_allocator]
    static ALLOC: Bump = Bump(UnsafeCell::new(0));

    unsafe impl GlobalAlloc for Bump {
        unsafe fn alloc(&self, l: Layout) -> *mut u8 {
            // SAFETY: single-threaded; the cell is only accessed here.
            let next = unsafe { &mut *self.0.get() };
            if *next == 0 {
                *next = core::arch::wasm32::memory_size(0) * 65536;
            }
            let start = (*next + l.align() - 1) & !(l.align() - 1);
            let end = start + l.size();
            let have = core::arch::wasm32::memory_size(0) * 65536;
            if end > have && core::arch::wasm32::memory_grow(0, (end - have).div_ceil(65536)) == usize::MAX {
                return core::ptr::null_mut();
            }
            *next = end;
            start as *mut u8
        }
        unsafe fn dealloc(&self, _: *mut u8, _: Layout) {}
    }

    #[panic_handler]
    fn panic(_: &core::panic::PanicInfo) -> ! {
        core::arch::wasm32::unreachable()
    }
}
