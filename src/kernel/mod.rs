//! Bridges flowspecs to OS kernel.
//!
//! Currently only Linux is supported, which uses nftables. Future support may
//! include *BSD using `pf` as backend.

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
mod rtnl;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

// TODO: Kernel trait
// TODO: noop adapter
// TODO: universal kernel::Error

pub type Result<T, E = Error> = std::result::Result<T, E>;
