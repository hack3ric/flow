pub mod flow;
pub mod msg;
pub mod nlri;
pub mod route;

use crate::args::RunArgs;
use crate::net::{Afi, IpPrefixError, IpPrefixErrorKind};
use crate::nft::Nft;
use flow::FlowError;
use futures::future::pending;
use log::{debug, error, info, warn};
use msg::HeaderError::*;
use msg::OpenError::*;
use msg::{Message, MessageSend, Notification, OpenMessage, SendAndReturn, UpdateError};
use nftables::helper::NftablesError;
use nlri::{Nlri, NlriError, NlriKind};
use num::integer::gcd;
use replace_with::replace_with_or_abort;
use route::Routes;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::borrow::Cow;
use std::cmp::min;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use strum::EnumDiscriminants;
use thiserror::Error;
use tokio::io::{AsyncWrite, BufReader};
use tokio::net::TcpStream;
use tokio::select;
use tokio::time::{interval, Duration, Instant, Interval};
use State::*;

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
/// - RFC 7606: Revised Error Handling for BGP UPDATE Messages
/// - RFC 8092: BGP Large Communities Attribute
/// - RFC 8955: Dissemination of Flow Specification Rules
/// - RFC 8956: Dissemination of Flow Specification Rules for IPv6
#[derive(Debug)]
pub struct Session {
  config: RunArgs,
  state: State,
  routes: Routes,
}

impl Session {
  pub fn new(c: RunArgs) -> Result<Self> {
    let nft = (!c.dry_run)
      .then(|| Nft::new(c.table.clone(), c.chain.clone(), c.hooked, c.priority))
      .transpose()?;
    Ok(Self { config: c, state: Active, routes: Routes::new(nft) })
  }

  pub fn start(&mut self) {
    self.state = Active;
  }

  pub async fn stop(&mut self) -> Result<()> {
    match &mut self.state {
      Idle | Connect | Active => {}
      OpenSent { stream } | OpenConfirm { stream, .. } | Established { stream, .. } => {
        Notification::Cease.send(stream).await?;
      }
    }
    self.state = Idle;
    Ok(())
  }

  pub fn config(&self) -> &RunArgs {
    &self.config
  }
  pub fn state(&self) -> &State {
    &self.state
  }
  pub fn routes(&self) -> &Routes {
    &self.routes
  }

  pub async fn accept(&mut self, mut stream: TcpStream, addr: SocketAddr) -> Result<()> {
    let ip = addr.ip();
    if !self.config.allowed_ips.iter().any(|x| x.contains(ip)) {
      return Err(Error::UnacceptableAddr(ip));
    } else if !matches!(self.state, Active) {
      return Err(Error::AlreadyRunning);
    }
    let open = OpenMessage::with_caps(
      self.config.local_as,
      self.config.hold_time,
      self.config.router_id.to_bits(),
    );
    open.send(&mut stream).await?;
    replace_with_or_abort(&mut self.state, |_| OpenSent { stream: BufReader::new(stream) });
    info!("accepting BGP connection from {addr}");
    Ok(())
  }

  pub async fn process(&mut self) -> Result<()> {
    let result = self.process_inner().await;
    if result.is_err() {
      self.state = Active;
      self.routes.withdraw_all()?; // TODO: print this error only
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
        Message::Open(remote_open) => {
          if !remote_open.bgp_mp.contains(&(Afi::Ipv4 as _, NlriKind::Flow as _))
            && !remote_open.bgp_mp.contains(&(Afi::Ipv6 as _, NlriKind::Flow as _))
          {
            warn!("remote does not seem to support flowspec, is it enabled?");
          }
          if !remote_open.supports_4b_asn {
            error!("remote does not support 4-octet AS number");
            Unspecific.send_and_return(stream).await?;
          } else if self.config.remote_as.map_or(false, |x| remote_open.my_as != x) {
            BadPeerAs.send_and_return(stream).await?;
          } else if remote_open.hold_time == 1 || remote_open.hold_time == 2 {
            UnacceptableHoldTime.send_and_return(stream).await?;
          } else {
            Message::Keepalive.send(stream).await?;
            replace_with_or_abort(&mut self.state, |this| {
              let OpenSent { stream } = this else { unreachable!() };
              let hold_time = min(self.config.hold_time, remote_open.hold_time);
              let timers = Timers::new(hold_time);
              OpenConfirm { stream, remote_open, timers }
            });
          }
        }
        other => bad_type(other, stream).await?,
      },
      OpenConfirm { stream, timers, .. } => select! {
        msg = Message::read(stream) => match msg? {
          Message::Keepalive => {
            replace_with_or_abort(&mut self.state, |this| {
              let OpenConfirm { stream, remote_open, mut timers } = this else {
                unreachable!()
              };
              timers.as_mut().map(Timers::update_hold);
              Established { stream, remote_open, timers }
            });
            info!("established");
          }
          other => bad_type(other, stream).await?,
        },
        inst = timers.as_mut().unwrap().tick(), if timers.is_some() => {
          timers.as_mut().unwrap().process_tick(inst, stream).await?;
        }
      },
      Established { stream, timers, .. } => select! {
        msg = Message::read(stream) => {
          match msg {
            Ok(Message::Update(msg)) => if let Some((afi, safi)) = msg.is_end_of_rib() {
              debug!("received End-of-RIB of ({afi}, {safi:?})");
            } else {
              debug!("received update: {msg:?}");
              if msg.nlri.is_some() || msg.old_nlri.is_some() {
                let route_info = Rc::new(msg.route_info);
                (msg.nlri)
                  .into_iter()
                  .chain(msg.old_nlri)
                  .map(|n| self.routes.commit(n, route_info.clone()))
                  .collect::<Result<(), _>>()?;
              }
              if msg.withdrawn.is_some() || msg.old_withdrawn.is_some() {
                (msg.withdrawn)
                  .into_iter()
                  .chain(msg.old_withdrawn)
                  .map(|n| self.routes.withdraw(n))
                  .collect::<Result<(), _>>()?;
              }
            },
            Err(Error::Withdraw(error, nlris)) => {
              error!("{error}");
              nlris
                .into_iter()
                .map(|n| self.routes.withdraw(n))
                .collect::<Result<(), _>>()?;
            },
            Ok(Message::Keepalive) => timers.as_mut().map(Timers::update_hold).unwrap_or(()),
            other => bad_type(other?, stream).await?,
          };
        }
        inst = timers.as_mut().unwrap().tick(), if timers.is_some() => {
          timers.as_mut().unwrap().process_tick(inst, stream).await?;
        }
      },
    }
    Ok(())
  }
}

#[derive(Debug)]
pub enum State {
  Idle,
  Connect, // never used in passive mode
  Active,
  OpenSent {
    stream: BufReader<TcpStream>,
  },
  OpenConfirm {
    stream: BufReader<TcpStream>,
    remote_open: OpenMessage<'static>,
    timers: Option<Timers>,
  },
  Established {
    stream: BufReader<TcpStream>,
    remote_open: OpenMessage<'static>,
    timers: Option<Timers>,
  },
}

impl State {
  pub fn kind(&self) -> StateKind {
    self.view().into()
  }

  pub fn view(&self) -> StateView {
    match self {
      Idle => StateView::Idle,
      Connect => StateView::Connect,
      Active => StateView::Active,
      OpenSent { .. } => StateView::OpenSent,
      OpenConfirm { stream, remote_open, .. } => StateView::OpenConfirm {
        remote_open: Cow::Borrowed(remote_open),
        local_addr: stream.get_ref().local_addr().ok(),
        remote_addr: stream.get_ref().peer_addr().ok(),
      },
      Established { stream, remote_open, .. } => StateView::Established {
        remote_open: Cow::Borrowed(remote_open),
        local_addr: stream.get_ref().local_addr().ok(),
        remote_addr: stream.get_ref().peer_addr().ok(),
      },
    }
  }
}

#[derive(Debug)]
pub struct Timers {
  clock: Interval,
  hold_timer: (Duration, Instant),
  keepalive_timer: (Duration, Instant),
}

impl Timers {
  pub fn new(hold_time: u16) -> Option<Self> {
    (hold_time != 0).then(|| {
      let now = Instant::now();
      let keepalive_time = hold_time / 3;
      let hold = Duration::from_secs(hold_time.into());
      let keepalive = Duration::from_secs(keepalive_time.into());
      Self {
        clock: interval(Duration::from_secs(u64::from(gcd(hold_time, keepalive_time) / 2))),
        hold_timer: (hold, now + hold),
        keepalive_timer: (keepalive, now + keepalive),
      }
    })
  }

  pub fn update_hold(&mut self) {
    let (dur, next) = &mut self.hold_timer;
    *next = Instant::now() + *dur;
  }

  pub async fn tick(&mut self) -> Instant {
    self.clock.tick().await
  }

  pub async fn process_tick(&mut self, inst: Instant, stream: &mut (impl AsyncWrite + Unpin)) -> Result<()> {
    if self.hold_timer.1 <= inst {
      Notification::HoldTimerExpired.send_and_return(stream).await?;
    }
    if self.keepalive_timer.1 <= inst {
      Message::Keepalive.send(stream).await?;
    }
    Ok(())
  }
}

#[derive(Debug, Clone, EnumDiscriminants, Serialize, Deserialize)]
#[strum_discriminants(name(StateKind))]
pub enum StateView<'a> {
  Idle,
  Connect,
  Active,
  OpenSent,
  OpenConfirm {
    remote_open: Cow<'a, OpenMessage<'a>>,
    local_addr: Option<SocketAddr>,
    remote_addr: Option<SocketAddr>,
  },
  Established {
    remote_open: Cow<'a, OpenMessage<'a>>,
    local_addr: Option<SocketAddr>,
    remote_addr: Option<SocketAddr>,
  },
}

impl StateView<'_> {
  pub fn kind(&self) -> StateKind {
    self.into()
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
  #[error("withdraw")] // TODO: print all routes to withdraw
  Withdraw(UpdateError<'static>, SmallVec<[Nlri; 1]>),

  #[error(transparent)]
  Io(#[from] io::Error),
  #[error(transparent)]
  IpPrefix(IpPrefixError),
  #[error(transparent)]
  Flow(#[from] FlowError),
  #[error(transparent)]
  Nlri(#[from] NlriError),

  #[error(transparent)]
  Nftables(#[from] NftablesError),
}

impl From<IpPrefixError> for Error {
  fn from(e: IpPrefixError) -> Self {
    match e.kind {
      IpPrefixErrorKind::Io(e) => Self::Io(e),
      _ => Self::IpPrefix(e),
    }
  }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
