pub mod error;
pub mod flow;
pub mod msg;

pub mod nlri;

use crate::net::IpPrefix;
use error::BgpError;
use futures::future::pending;
use log::info;
use msg::HeaderError::*;
use msg::OpenError::*;
use msg::{Message, MessageSend, Notification, OpenMessage, SendAndReturn};
use num::integer::gcd;
use replace_with::replace_with_or_abort;
use std::cmp::min;
use std::future::Future;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncWrite, BufReader};
use tokio::net::TcpStream;
use tokio::select;
use tokio::time::{interval, Interval};
use State::*;

pub struct Config {
  pub router_id: u32,
  pub local_as: u32,
  pub remote_as: Option<u32>,
  pub remote_ip: Vec<IpPrefix>,
  pub hold_timer: u16,
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
    // TODO: timer here
  },
  Established {
    stream: BufReader<TcpStream>,
    #[allow(unused)]
    remote_open: OpenMessage<'static>,
    clock: Interval,
    hold_timer: Option<(Duration, Instant)>,
    keepalive_timer: Option<(Duration, Instant)>,
  },
}

/// A (currently passive only) BGP session.
///
/// Implemented RFCs:
/// - RFC 4271: A Border Gateway Protocol 4 (BGP-4) \[partial\]
/// - RFC 6793: BGP Support for Four-Octet Autonomous System (AS) Number Space
/// - RFC 4760: Multiprotocol Extensions for BGP
/// - RFC 2545: Use of BGP-4 Multiprotocol Extensions for IPv6 Inter-Domain
///   Routing (?)
/// - RFC 1997: BGP Communities Attribute
/// - RFC 4360: BGP Extended Communities Attribute \[partial\]
/// - RFC 8092: BGP Large Communities Attribute
/// - RFC 8955: Dissemination of Flow Specification Rules
/// - RFC 8956: Dissemination of Flow Specification Rules for IPv6
///
/// To implement:
/// - RFC 7606: Revised Error Handling for BGP UPDATE Messages
pub struct Session {
  config: Config,
  pub(crate) state: State,
}

impl Session {
  pub const fn new(config: Config) -> Self {
    Self { config, state: Active }
  }

  pub fn start(&mut self) {
    self.state = Active;
  }

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

  pub async fn accept(&mut self, mut stream: TcpStream, addr: SocketAddr) -> Result<(), BgpError> {
    let ip = addr.ip();
    if !self.config.remote_ip.iter().any(|x| x.contains(ip)) {
      return Err(BgpError::UnacceptableAddr(ip));
    } else if !matches!(self.state, Active) {
      return Err(BgpError::AlreadyRunning);
    }
    let open = OpenMessage {
      my_as: self.config.local_as,
      hold_time: self.config.hold_timer,
      bgp_id: self.config.router_id,
      ..Default::default()
    };
    open.send(&mut stream).await?;
    self.state = OpenSent { stream: BufReader::new(stream) };
    info!("accepting BGP connection from {addr}");
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
    fn bad_type<'a>(
      msg: Message,
      stream: &'a mut (impl AsyncWrite + Unpin),
    ) -> impl Future<Output = Result<(), BgpError>> + 'a {
      BadType(msg.kind() as u8).send_and_return(stream)
    }

    match &mut self.state {
      Idle | Connect | Active => pending().await,
      OpenSent { stream } => match Message::recv(stream).await? {
        Message::Open(msg) => {
          if self.config.remote_as.map_or(false, |x| msg.my_as != x) {
            BadPeerAs.send_and_return(stream).await?;
          } else if msg.hold_time == 1 || msg.hold_time == 2 {
            UnacceptableHoldTime.send_and_return(stream).await?;
          } else {
            Message::Keepalive.send(stream).await?;
            replace_with_or_abort(&mut self.state, |this| {
              let OpenSent { stream } = this else { unreachable!() };
              OpenConfirm { stream, remote_open: msg }
            });
          }
        }
        other => bad_type(other, stream).await?,
      },
      OpenConfirm { stream, .. } => match Message::recv(stream).await? {
        Message::Keepalive => {
          replace_with_or_abort(&mut self.state, |this| {
            let OpenConfirm { stream, remote_open } = this else {
              unreachable!()
            };
            let hold_time = min(self.config.hold_timer, remote_open.hold_time);
            let keepalive_time = hold_time / 3;
            let hold_timer = (hold_time != 0)
              .then(|| Duration::from_secs(hold_time.into()))
              .map(|x| (x, Instant::now() + x));
            let keepalive_timer = (keepalive_time != 0)
              .then(|| Duration::from_secs(keepalive_time.into()))
              .map(|x| (x, Instant::now() + x));
            Established {
              stream,
              remote_open,
              clock: interval(Duration::from_secs(gcd(hold_time, keepalive_time).into())),
              hold_timer,
              keepalive_timer,
            }
          });
          info!("established");
        }
        other => bad_type(other, stream).await?,
      },
      Established { stream, clock, hold_timer, keepalive_timer, .. } => select! {
        msg = Message::recv(stream) => {
          match msg? {
            Message::Update(msg) => {
              if let Some((afi, safi)) = msg.is_end_of_rib() {
                info!("received End-of-RIB of ({afi}, {safi:?})");
              } else {
                info!("received update: {msg:?}");
              }
              // TODO: process
            }
            Message::Keepalive => if let Some((dur, next)) = hold_timer {
              *next = Instant::now() + *dur;
            },
            other => bad_type(other, stream).await?,
          };
        }
        _ = clock.tick() => {
          if let &mut Some((_, next)) = hold_timer {
            if next <= Instant::now() {
              Notification::HoldTimerExpired.send_and_return(stream).await?;
            }
          }
          if let &mut Some((_, next)) = keepalive_timer {
            if next <= Instant::now() {
              Message::Keepalive.send(stream).await?;
            }
          }
        }
      },
    }
    Ok(())
  }
}

// Utilities

#[inline]
fn extend_with_u8_len<F: FnOnce(&mut Vec<u8>)>(buf: &mut Vec<u8>, extend: F) {
  let len_pos = buf.len();
  buf.push(0);
  extend(buf);
  let len = buf.len() - len_pos - 1;
  buf[len_pos] = len.try_into().expect("length should fit in u8");
}

#[inline]
fn extend_with_u16_len<F: FnOnce(&mut Vec<u8>)>(buf: &mut Vec<u8>, extend: F) {
  let len_pos = buf.len();
  buf.extend([0; 2]);
  extend(buf);
  let len = u16::try_from(buf.len() - len_pos - 2).expect("");
  buf[len_pos..len_pos + 2].copy_from_slice(&len.to_be_bytes())
}
