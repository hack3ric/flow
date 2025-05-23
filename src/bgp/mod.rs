pub mod flow;
pub mod msg;
pub mod nlri;
pub mod route;

use crate::args::RunArgs;
use crate::kernel::{self, KernelAdapter};
use crate::net::{Afi, IpPrefixError, IpPrefixErrorKind};
use State::*;
use either::Either;
use flow::FlowError;
use itertools::Itertools;
use log::{debug, error, info, warn};
use msg::HeaderError::*;
use msg::OpenError::*;
use msg::{Message, MessageSend, Notification, OpenMessage, SendAndReturn, UpdateError};
use nlri::{Nlri, NlriContent, NlriError, NlriKind};
use num_integer::gcd;
use replace_with::replace_with_or_abort;
use route::Routes;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::borrow::Cow;
use std::cmp::min;
use std::fmt::Display;
use std::future::{Future, pending};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use strum::EnumDiscriminants;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, BufReader};
use tokio::net::TcpStream;
use tokio::select;
use tokio::time::{Duration, Instant, Interval, interval};

#[cfg(test)]
use {crate::integration_tests::TestEvent, tokio::sync::mpsc};

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
/// - RFC 5065: Autonomous System Confederations for BGP
/// - RFC 5668: 4-Octet AS Specific BGP Extended Community
/// - RFC 5701: IPv6 Address Specific BGP Extended Community Attribute
/// - RFC 7606: Revised Error Handling for BGP UPDATE Messages
/// - RFC 8092: BGP Large Communities Attribute
/// - RFC 8955: Dissemination of Flow Specification Rules
/// - RFC 8956: Dissemination of Flow Specification Rules for IPv6
#[derive(Debug)]
pub struct Session<S: AsyncRead + AsyncWrite + Unpin> {
  config: RunArgs,
  state: State<S>,
  routes: Routes,
  #[cfg(test)]
  event_tx: mpsc::Sender<TestEvent>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Session<S> {
  pub async fn new(config: RunArgs, #[cfg(test)] event_tx: mpsc::Sender<TestEvent>) -> Result<Self> {
    let kernel = if config.dry_run {
      KernelAdapter::Noop
    } else {
      #[cfg(linux)]
      let result = KernelAdapter::linux(config.kernel.clone()).await?;
      #[cfg(not(kernel_supported))]
      let result = KernelAdapter::Noop;
      result
    };
    Ok(Self {
      config,
      state: Active,
      routes: Routes::new(kernel),
      #[cfg(test)]
      event_tx,
    })
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
  pub fn state(&self) -> &State<S> {
    &self.state
  }
  pub fn routes(&self) -> &Routes {
    &self.routes
  }

  pub async fn accept(&mut self, mut stream: S, addr: SocketAddr) -> Result<()> {
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
    replace_with_or_abort(&mut self.state, |_| OpenSent { stream });
    info!("accepting BGP connection from {addr}");
    Ok(())
  }

  pub async fn process(&mut self) -> Result<()> {
    let result = self.process_inner().await;
    if result.is_err() {
      self.state = Active;
      self.routes.withdraw_all().await;
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
          } else if self.config.remote_as.is_some_and(|x| remote_open.my_as != x) {
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
              #[cfg(test)]
              let _ = self.event_tx.send(TestEvent::EndOfRib(afi, safi)).await;

            } else {
              debug!("received update: {msg:?}");
              #[cfg(test)]
              let _ = self.event_tx.send(TestEvent::Update(msg.clone())).await;

              // here `msg` is partially moved
              if msg.nlri.is_some() || msg.old_nlri.is_some() {
                let route_info = Rc::new(msg.route_info);
                for n in msg.nlri.into_iter().chain(msg.old_nlri) {
                  self.routes.commit(n, route_info.clone()).await;
                }
              }
              if msg.withdrawn.is_some() || msg.old_withdrawn.is_some() {
                for n in msg.withdrawn.into_iter().chain(msg.old_withdrawn) {
                  self.routes.withdraw(n).await;
                }
              }
            },
            Err(Error::Withdraw(error, nlris)) => {
              error!("{error}");
              for n in nlris {
                self.routes.withdraw(n).await;
              }
            },
            Ok(Message::Keepalive) => timers.as_mut().map(Timers::update_hold).unwrap_or(()),
            other => bad_type(other?, stream).await?,
          };
        }
        inst = timers.as_mut().unwrap().tick(), if timers.is_some() => {
          timers.as_mut().unwrap().process_tick(inst, stream).await?;
        }
        result = self.routes.process() => result?,
      },
    }
    Ok(())
  }

  pub async fn terminate(&mut self) {
    self.routes.terminate().await;
  }
}

#[derive(Debug)]
pub enum State<S: AsyncRead + AsyncWrite + Unpin> {
  Idle,
  Connect, // never used in passive mode
  Active,
  OpenSent { stream: S },
  OpenConfirm { stream: S, remote_open: OpenMessage<'static>, timers: Option<Timers> },
  Established { stream: S, remote_open: OpenMessage<'static>, timers: Option<Timers> },
}

impl<S: AsyncRead + AsyncWrite + Unpin> State<S> {
  pub fn kind(&self) -> StateKind {
    match self {
      Idle => StateKind::Idle,
      Connect => StateKind::Connect,
      Active => StateKind::Active,
      OpenSent { .. } => StateKind::OpenSent,
      OpenConfirm { .. } => StateKind::OpenConfirm,
      Established { .. } => StateKind::Established,
    }
  }
}

impl State<BufReader<TcpStream>> {
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
  #[error("withdraw {}: {}", print_withdraw(.1.iter()), .0)]
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
  Kernel(#[from] kernel::Error),
}

impl From<IpPrefixError> for Error {
  fn from(e: IpPrefixError) -> Self {
    match e.kind {
      IpPrefixErrorKind::Io(e) => Self::Io(e),
      _ => Self::IpPrefix(e),
    }
  }
}

fn print_withdraw<'a>(nlris: impl Iterator<Item = &'a Nlri> + 'a) -> impl Display + 'a {
  use Either::*;
  use NlriContent::*;
  nlris
    .flat_map(|x| match &x.content {
      Unicast { prefixes, .. } => Left(prefixes.iter().map(|y| Box::new(y) as Box<dyn Display>)),
      Flow { specs } => Right(specs.iter().map(|y| Box::new(y) as Box<dyn Display>)),
    })
    .format(", ")
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
