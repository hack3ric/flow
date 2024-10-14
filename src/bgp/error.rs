use super::flow::FlowError;
use super::msg::Notification;
use super::nlri::NlriError;
use crate::net::{IpPrefixError, IpPrefixErrorKind};
use std::io;
use std::net::IpAddr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BgpError {
  #[error("address {0} not acceptable")]
  UnacceptableAddr(IpAddr),
  #[error("session is already running")]
  AlreadyRunning,

  #[error(transparent)]
  Notification(#[from] Notification<'static>),
  #[error("remote said: {0}")]
  Remote(Notification<'static>),

  #[error(transparent)]
  Io(#[from] io::Error),
  #[error(transparent)]
  IpPrefix(IpPrefixError),
  #[error(transparent)]
  Flow(#[from] FlowError),
  #[error(transparent)]
  Nlri(#[from] NlriError),

  #[error(transparent)]
  Anyhow(#[from] anyhow::Error),
}

impl From<IpPrefixError> for BgpError {
  fn from(e: IpPrefixError) -> Self {
    match e.kind {
      IpPrefixErrorKind::Io(e) => Self::Io(e),
      _ => Self::IpPrefix(e),
    }
  }
}
