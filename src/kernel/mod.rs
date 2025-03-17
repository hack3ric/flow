//! Bridges flowspecs to OS kernel.
//!
//! Currently only Linux is supported. Future support may include *BSD using
//! `pf` as backend.

#[cfg(linux)]
mod linux;
#[cfg(linux)]
pub use linux::*;

#[cfg(rtnetlink_supported)]
mod rtnl;

use crate::bgp::flow::Flowspec;
use crate::bgp::route::RouteInfo;
use serde::{Deserialize, Serialize};
use std::future::{Future, pending, ready};
use strum::Display;
use thiserror::Error;

/// Interface between BGP flowspec and the OS.
pub trait Kernel: Sized {
  /// Type representing a flowspec's counterpart in kernel.
  type Handle: Eq + Ord;

  /// Apply a flowspec to kernel.
  fn apply(
    &mut self,
    spec: &Flowspec,
    before: Option<&Self::Handle>,
    info: &RouteInfo<'_>,
  ) -> impl Future<Output = Result<Self::Handle>>;

  /// Remove a flowspec from kernel using previously returned handle.
  fn remove(&mut self, handle: &Self::Handle) -> impl Future<Output = ()>;

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
  #[cfg(linux)]
  Linux(Linux),
}

impl KernelAdapter {
  #[cfg(linux)]
  pub async fn linux(args: KernelArgs) -> Result<Self> {
    Ok(Self::Linux(Linux::new(args).await?))
  }
}

impl Kernel for KernelAdapter {
  type Handle = KernelHandle;

  async fn apply(
    &mut self,
    _spec: &Flowspec,
    _before: Option<&Self::Handle>,
    _info: &RouteInfo<'_>,
  ) -> Result<Self::Handle> {
    match self {
      Self::Noop => Ok(KernelHandle::Noop),
      #[cfg(linux)]
      Self::Linux(linux) => Ok(KernelHandle::Linux(
        linux.apply(_spec, _before.map(|l| l.as_linux().unwrap()), _info).await?,
      )),
    }
  }

  async fn remove(&mut self, handle: &Self::Handle) {
    match (self, handle) {
      (Self::Noop, KernelHandle::Noop) => {}
      #[cfg(linux)]
      (Self::Linux(linux), KernelHandle::Linux(handle)) => linux.remove(handle).await,
      #[cfg(linux)]
      _ => panic!("handle mismatch"),
    }
  }

  async fn process(&mut self) -> Result<()> {
    match self {
      Self::Noop => pending().await,
      #[cfg(linux)]
      Self::Linux(linux) => linux.process().await,
    }
  }

  async fn terminate(self) {
    match self {
      Self::Noop => {}
      #[cfg(linux)]
      Self::Linux(linux) => linux.terminate().await,
    }
  }
}

#[derive(Debug, Display, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum KernelHandle {
  #[strum(to_string = "()")]
  Noop,

  #[cfg(linux)]
  #[strum(to_string = "{0:?}")]
  Linux(<Linux as Kernel>::Handle),
}

impl KernelHandle {
  #[cfg(linux)]
  pub fn as_linux(&self) -> Option<&<Linux as Kernel>::Handle> {
    match self {
      KernelHandle::Linux(linux) => Some(linux),
      _ => None,
    }
  }
}

#[derive(Debug, Error)]
pub enum Error {
  #[cfg(linux)]
  #[error(transparent)]
  Nftables(#[from] nftables::helper::NftablesError),

  #[cfg(rtnetlink_supported)]
  #[error(transparent)]
  RtNetlink(#[from] rtnetlink::Error),

  #[error("flowspec matches nothing")]
  MatchNothing,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
