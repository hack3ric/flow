//! Bridges flowspecs to OS kernel.
//!
//! Currently only Linux is supported, which uses nftables. Future support may
//! include *BSD using `pf` as backend.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

pub type Result<T, E = Error> = std::result::Result<T, E>;
