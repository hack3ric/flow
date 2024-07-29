use super::msg::Notification;
use crate::net::{IpPrefixError, IpPrefixErrorKind};
use std::io;
use std::net::IpAddr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BgpError {
  #[error(transparent)]
  Io(#[from] io::Error),
  #[error(transparent)]
  Notification(#[from] Notification<'static>),
  #[error(transparent)]
  IpPrefix(IpPrefixError),

  #[error("address {0} not acceptable")]
  UnacceptableAddr(IpAddr),
  #[error("session is already running")]
  AlreadyRunning,
}

impl From<IpPrefixError> for BgpError {
  fn from(value: IpPrefixError) -> Self {
    match value.kind {
      IpPrefixErrorKind::Io(e) => Self::Io(e),
      _ => Self::IpPrefix(value),
    }
  }
}
