mod error;
mod flow;
mod msg;

use crate::net::IpPrefix;
use error::BgpError;
use futures::future::pending;
use log::info;
use msg::HeaderError::*;
use msg::OpenError::*;
use msg::{Message, MessageSend, Notification, OpenMessage, SendAndReturn};
use replace_with::replace_with_or_abort;
use std::net::IpAddr;
use tokio::io::BufReader;
use tokio::net::TcpStream;
use State::*;

pub struct Config {
  pub router_id: u32,
  pub local_as: u32,
  pub remote_as: Option<u32>,
  pub remote_ip: IpPrefix,
}

/// A passive BGP session.
///
/// Implemented RFCs:
/// - RFC 4271: A Border Gateway Protocol 4 (BGP-4) \[partial\]
///   - RFC 6793: BGP Support for Four-Octet Autonomous System (AS) Number Space
///   - RFC 4760: Multiprotocol Extensions for BGP
///     - RFC 2545: Use of BGP-4 Multiprotocol Extensions for IPv6 Inter-Domain
///       Routing
///
/// To be implemented:
/// - RFC 8955: Dissemination of Flow Specification Rules
///   - RFC 8956: Dissemination of Flow Specification Rules for IPv6
pub struct Session {
  config: Config,
  state: State,
}

impl Session {
  pub const fn new(config: Config) -> Self {
    Self { config, state: Active }
  }

  #[allow(dead_code)]
  pub fn start(&mut self) {
    self.state = Active;
  }

  #[allow(dead_code)]
  pub async fn stop(&mut self) -> Result<(), BgpError> {
    match &mut self.state {
      Idle | Connect | Active => {}
      OpenSent { stream } | OpenConfirm { stream, .. } | Established { stream, .. } => {
        Notification::Cease.send(stream).await?;
      }
    }
    self.state = Idle;
    Ok(())
  }

  pub async fn accept(&mut self, mut stream: TcpStream, addr: IpAddr) -> Result<(), BgpError> {
    if !self.config.remote_ip.contains(addr) {
      return Err(BgpError::UnacceptableAddr(addr));
    } else if !matches!(self.state, Active) {
      return Err(BgpError::AlreadyRunning);
    }
    let open = OpenMessage {
      my_as: self.config.local_as,
      hold_time: 180,
      bgp_id: self.config.router_id,
      ..Default::default()
    };
    open.send(&mut stream).await?;
    self.state = OpenSent {
      stream: BufReader::new(stream),
    };
    Ok(())
  }

  pub async fn process(&mut self) -> Result<(), BgpError> {
    let result = self.process_inner().await;
    if result.is_err() {
      self.state = Active;
    }
    result
  }

  async fn process_inner(&mut self) -> Result<(), BgpError> {
    match &mut self.state {
      Idle | Connect | Active => pending().await,
      OpenSent { stream } => match Message::recv(stream).await? {
        Message::Open(msg) => {
          if self.config.remote_as.map_or(false, |x| msg.my_as != x) {
            BadPeerAS.send_and_return(stream).await
          } else if msg.hold_time == 1 || msg.hold_time == 2 {
            UnacceptableHoldTime.send_and_return(stream).await
          } else {
            Message::Keepalive.send(stream).await?;
            replace_with_or_abort(&mut self.state, |this| {
              let OpenSent { stream } = this else { unreachable!() };
              OpenConfirm {
                stream,
                remote_open: msg,
              }
            });
            Ok(())
          }
        }
        other => BadType(other.kind() as u8).send_and_return(stream).await,
      },
      OpenConfirm { stream, .. } => match Message::recv(stream).await? {
        Message::Keepalive => {
          replace_with_or_abort(&mut self.state, |this| {
            let OpenConfirm { stream, remote_open } = this else {
              unreachable!()
            };
            Established { stream, remote_open }
          });
          info!("established");
          Ok(())
        }
        other => BadType(other.kind() as u8).send_and_return(stream).await,
      },
      Established { .. } => pending().await,
    }
  }
}

#[derive(Debug)]
pub enum State {
  Idle,
  #[allow(dead_code)]
  Connect, // never used in passive mode
  Active,
  OpenSent {
    stream: BufReader<TcpStream>,
  },
  OpenConfirm {
    stream: BufReader<TcpStream>,
    remote_open: OpenMessage<'static>,
  },
  Established {
    stream: BufReader<TcpStream>,
    remote_open: OpenMessage<'static>,
  },
}
