//! Bridges flowspecs to OS kernel.
//!
//! Currently only Linux is supported. Future support may include *BSD using
//! `pf` as backend.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
mod rtnl;

use crate::bgp::flow::Flowspec;
use crate::bgp::route::RouteInfo;
use serde::{Deserialize, Serialize};
use std::future::{pending, ready, Future};
use strum::Display;
use thiserror::Error;

/// Interface between BGP flowspec and the OS.
pub trait Kernel: Sized {
  /// Type representing a flowspec's counterpart in kernel.
  type Handle;

  /// Apply a flowspec to kernel.
  fn apply(&mut self, spec: &Flowspec, info: &RouteInfo<'_>) -> impl Future<Output = Result<Self::Handle>>;

  /// Remove a flowspec from kernel using previously returned handle.
  fn remove(&mut self, handle: Self::Handle) -> impl Future<Output = Result<()>>;

  /// Process notifications from kernel, timers, etc.
  fn process(&mut self) -> impl Future<Output = Result<()>> {
    pending()
  }

  /// Drops the kernel interface and do asynchronous cleanups.
  fn terminate(self) -> impl Future<Output = ()> {
    ready(())
  }
}

/// Adapter of different `Kernel` implementations.
#[derive(Debug, Serialize, Deserialize)]
pub enum KernelAdapter {
  /// Do nothing.
  Noop,

  /// Linux implementation, using nftables and rtnetlink.
  #[cfg(target_os = "linux")]
  Linux(Linux),
}

impl KernelAdapter {
  #[cfg(target_os = "linux")]
  pub async fn linux(args: KernelArgs) -> Result<Self> {
    Ok(Self::Linux(Linux::new(args).await?))
  }
}

impl Kernel for KernelAdapter {
  type Handle = KernelHandle;

  async fn apply(&mut self, _spec: &Flowspec, _info: &RouteInfo<'_>) -> Result<Self::Handle> {
    match self {
      Self::Noop => Ok(KernelHandle::Noop),
      #[cfg(target_os = "linux")]
      Self::Linux(linux) => Ok(KernelHandle::Linux(linux.apply(_spec, _info).await?)),
    }
  }

  async fn remove(&mut self, handle: Self::Handle) -> Result<()> {
    match (self, handle) {
      (Self::Noop, KernelHandle::Noop) => Ok(()),
      #[cfg(target_os = "linux")]
      (Self::Linux(linux), KernelHandle::Linux(handle)) => linux.remove(handle).await,
      #[cfg(target_os = "linux")]
      _ => Err(Error::HandleMismatch),
    }
  }

  async fn process(&mut self) -> Result<()> {
    match self {
      Self::Noop => pending().await,
      #[cfg(target_os = "linux")]
      Self::Linux(linux) => linux.process().await,
    }
  }

  async fn terminate(self) {
    match self {
      Self::Noop => {}
      #[cfg(target_os = "linux")]
      Self::Linux(linux) => linux.terminate().await,
    }
  }
}

#[derive(Debug, Display, Clone, Serialize, Deserialize)]
pub enum KernelHandle {
  #[strum(to_string = "()")]
  Noop,

  #[cfg(target_os = "linux")]
  #[strum(to_string = "{0}")]
  Linux(<Linux as Kernel>::Handle),
}

#[derive(Debug, Error)]
pub enum Error {
  #[cfg(target_os = "linux")]
  #[error(transparent)]
  Nftables(#[from] nftables::helper::NftablesError),

  #[cfg(any(target_os = "linux", target_os = "freebsd"))]
  #[error(transparent)]
  RtNetlink(#[from] rtnetlink::Error),

  #[error("flowspec matches nothing")]
  MatchNothing,

  #[error("kernel handle mismatch")]
  HandleMismatch,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
