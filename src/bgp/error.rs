use super::msg::Notification;
use std::io;
use std::net::IpAddr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BGPError {
  #[error(transparent)]
  IO(#[from] io::Error),
  #[error(transparent)]
  Notification(#[from] Notification<'static>),

  #[error("address {0} not acceptable")]
  UnacceptableAddr(IpAddr),
  #[error("session is already running")]
  AlreadyRunning,
}
