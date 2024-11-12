//! Bridges flowspecs to OS kernel.
//!
//! Currently only Linux is supported, which uses nftables. Future support may
//! include *BSD using `pf` as backend.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
mod rtnl;

use crate::bgp::flow::Flowspec;
use crate::bgp::route::RouteInfo;
use futures::future::pending;
use serde::{Deserialize, Serialize};
use std::future::Future;
use strum::Display;
use thiserror::Error;

pub trait KernelAdapter {
  type Handle;
  fn apply(&mut self, spec: &Flowspec, info: &RouteInfo<'_>) -> impl Future<Output = Result<Self::Handle>>;
  fn remove(&mut self, handle: Self::Handle) -> impl Future<Output = Result<()>>;
  fn process(&mut self) -> impl Future<Output = Result<()>> {
    pending()
  }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Kernel {
  Noop,
  #[cfg(target_os = "linux")]
  Linux(Linux),
}

impl Kernel {
  #[cfg(target_os = "linux")]
  pub fn linux(args: KernelArgs) -> Result<Self> {
    Ok(Self::Linux(Linux::new(args)?))
  }
}

impl KernelAdapter for Kernel {
  type Handle = KernelHandle;

  async fn apply(&mut self, spec: &Flowspec, info: &RouteInfo<'_>) -> Result<Self::Handle> {
    match self {
      Self::Noop => Ok(KernelHandle::Noop),
      Self::Linux(linux) => Ok(KernelHandle::Linux(linux.apply(spec, info).await?)),
    }
  }

  async fn remove(&mut self, handle: Self::Handle) -> Result<()> {
    match (self, handle) {
      (Self::Noop, KernelHandle::Noop) => Ok(()),
      (Self::Linux(linux), KernelHandle::Linux(handle)) => linux.remove(handle).await,
      _ => Err(Error::HandleMismatch),
    }
  }

  async fn process(&mut self) -> Result<()> {
    match self {
      Self::Noop => pending().await,
      Self::Linux(linux) => linux.process().await,
    }
  }
}

#[derive(Debug, Display, Clone, Serialize, Deserialize)]
pub enum KernelHandle {
  #[strum(to_string = "()")]
  Noop,

  #[cfg(target_os = "linux")]
  #[strum(to_string = "{0}")]
  Linux(<Linux as KernelAdapter>::Handle),
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
