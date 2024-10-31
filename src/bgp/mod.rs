pub mod flow;
pub mod msg;
pub mod nlri;
pub mod route;

use crate::args::RunArgs;
use crate::net::{IpPrefixError, IpPrefixErrorKind};
use crate::sync::RwLock;
use flow::FlowError;
use futures::future::pending;
use log::{debug, info};
use msg::HeaderError::*;
use msg::OpenError::*;
use msg::{Message, MessageSend, Notification, OpenMessage, SendAndReturn};
use nlri::NlriError;
use num::integer::gcd;
use replace_with::replace_with_or_abort;
use route::Routes;
use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::cmp::min;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::time::{Duration, Instant};
use strum::EnumDiscriminants;
use thiserror::Error;
use tokio::io::{AsyncWrite, BufReader};
use tokio::net::TcpStream;
use tokio::select;
use tokio::time::{interval, Interval};
use State::*;

#[derive(Debug, EnumDiscriminants)]
#[strum_discriminants(name(StateKind), derive(Serialize, Deserialize))]
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
/// - RFC 4360: BGP Extended Communities Attribute
/// - RFC 5668: 4-Octet AS Specific BGP Extended Community
/// - RFC 5701: IPv6 Address Specific BGP Extended Community Attribute
/// - RFC 8092: BGP Large Communities Attribute
/// - RFC 8955: Dissemination of Flow Specification Rules
/// - RFC 8956: Dissemination of Flow Specification Rules for IPv6
///
/// To implement:
/// - RFC 7606: Revised Error Handling for BGP UPDATE Messages
#[derive(Debug)]
pub struct Session {
  config: Rc<RunArgs>,
  state: State,
  state_kind: Rc<Cell<StateKind>>,
  routes: Rc<RwLock<Routes>>,
}

impl Session {
  pub fn new(routes: Rc<RwLock<Routes>>, config: Rc<RunArgs>) -> Self {
    Self { routes, config, state: Active, state_kind: Rc::new(Cell::new(StateKind::Active)) }
  }

  pub fn start(&mut self) {
    self.change_state(|_| Active);
  }

  pub async fn stop(&mut self) -> Result<()> {
    match &mut self.state {
      Idle | Connect | Active => {}
      OpenSent { stream } | OpenConfirm { stream, .. } | Established { stream, .. } => {
        Notification::Cease.send(stream).await?;
      }
    }
    self.change_state(|_| Idle);
    Ok(())
  }

  pub fn state(&self) -> &State {
    &self.state
  }

  pub fn state_kind(&self) -> Rc<Cell<StateKind>> {
    self.state_kind.clone()
  }

  fn change_state(&mut self, f: impl FnOnce(State) -> State) {
    Self::change_state2(&mut self.state, &self.state_kind, f);
  }

  fn change_state2(state: &mut State, kind: &Cell<StateKind>, f: impl FnOnce(State) -> State) {
    replace_with_or_abort(state, f);
    kind.set((&*state).into());
  }

  pub async fn accept(&mut self, mut stream: TcpStream, addr: SocketAddr) -> Result<()> {
    let ip = addr.ip();
    if !self.config.allowed_ips.iter().any(|x| x.contains(ip)) {
      return Err(Error::UnacceptableAddr(ip));
    } else if !matches!(self.state, Active) {
      return Err(Error::AlreadyRunning);
    }
    let open = OpenMessage {
      my_as: self.config.local_as,
      hold_time: self.config.hold_time,
      bgp_id: self.config.router_id.to_bits(),
      ..Default::default()
    };
    open.send(&mut stream).await?;
    self.change_state(|_| OpenSent { stream: BufReader::new(stream) });
    info!("accepting BGP connection from {addr}");
    Ok(())
  }

  pub async fn process(&mut self) -> Result<()> {
    let result = self.process_inner().await;
    if result.is_err() {
      self.change_state(|_| Active);
      self.routes.write().await.withdraw_all().unwrap();
    }
    result
  }

  async fn process_inner(&mut self) -> Result<()> {
    fn bad_type<'a>(msg: Message, stream: &'a mut (impl AsyncWrite + Unpin)) -> impl Future<Output = Result<()>> + 'a {
      BadType(msg.kind() as u8).send_and_return(stream)
    }

    match &mut self.state {
      Idle | Connect | Active => pending().await,
      OpenSent { stream } => match Message::read(stream).await? {
        Message::Open(msg) => {
          if self.config.remote_as.map_or(false, |x| msg.my_as != x) {
            BadPeerAs.send_and_return(stream).await?;
          } else if msg.hold_time == 1 || msg.hold_time == 2 {
            UnacceptableHoldTime.send_and_return(stream).await?;
          } else {
            Message::Keepalive.send(stream).await?;
            self.change_state(|this| {
              let OpenSent { stream } = this else { unreachable!() };
              OpenConfirm { stream, remote_open: msg }
            });
          }
        }
        other => bad_type(other, stream).await?,
      },
      OpenConfirm { stream, .. } => match Message::read(stream).await? {
        Message::Keepalive => {
          Self::change_state2(&mut self.state, &self.state_kind, |this| {
            let OpenConfirm { stream, remote_open } = this else {
              unreachable!()
            };
            let hold_time = min(self.config.hold_time, remote_open.hold_time);
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
        msg = Message::read(stream) => {
          match msg? {
            Message::Update(msg) => if let Some((afi, safi)) = msg.is_end_of_rib() {
              debug!("received End-of-RIB of ({afi}, {safi:?})");
            } else {
              debug!("received update: {msg:?}");
              let mut routes = self.routes.write().await;
              if msg.nlri.is_some() || msg.old_nlri.is_some() {
                let route_info = Rc::new(msg.route_info);
                (msg.nlri)
                  .into_iter()
                  .chain(msg.old_nlri)
                  .for_each(|n| routes.commit(n, route_info.clone()).unwrap());
              }
              if msg.withdrawn.is_some() || msg.old_withdrawn.is_some() {
                (msg.withdrawn)
                  .into_iter()
                  .chain(msg.old_withdrawn)
                  .for_each(|n| routes.withdraw(n).unwrap());
              }
            },
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

#[derive(Debug, Error)]
pub enum Error {
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
}

impl From<IpPrefixError> for Error {
  fn from(e: IpPrefixError) -> Self {
    match e.kind {
      IpPrefixErrorKind::Io(e) => Self::Io(e),
      _ => Self::IpPrefix(e),
    }
  }
}

pub type Result<T> = std::result::Result<T, Error>;
