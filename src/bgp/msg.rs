use super::error::BgpError;
use crate::net::IpPrefix;
use std::collections::HashSet;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::{borrow::Cow, net::IpAddr};
use strum::EnumDiscriminants;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use HeaderError::*;
use OpenError::*;
use UpdateError::*;

pub const MSG_OPEN: u8 = 1;
pub const MSG_UPDATE: u8 = 2;
pub const MSG_NOTIFICATION: u8 = 3;
pub const MSG_KEEPALIVE: u8 = 4;

pub const OPT_PARAM_CAP: u8 = 2;

pub const CAP_4B_ASN: u8 = 65;
pub const CAP_BGP_MP: u8 = 1;

// https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
pub const AFI_IPV4: u16 = 1;
pub const AFI_IPV6: u16 = 2;

pub const SAFI_UNICAST: u8 = 1;
#[allow(dead_code)]
pub const SAFI_MULTICAST: u8 = 2;
#[allow(dead_code)]
pub const SAFI_FLOW: u8 = 133;

pub const ORIGIN: u8 = 1;
pub const AS_PATH: u8 = 2;
pub const NEXT_HOP: u8 = 3;
pub const MP_REACH_NLRI: u8 = 14;
pub const MP_UNREACH_NLRI: u8 = 15;

pub const AS_TRANS: u16 = 23456;

pub trait MessageSend {
  fn serialize_data(&self, buf: &mut Vec<u8>);

  fn serialize_message(&self, buf: &mut Vec<u8>) {
    let start_pos = buf.len();
    buf.extend([u8::MAX; 16]); // marker
    buf.extend([0; 2]); // reserved for length
    self.serialize_data(buf);
    let total_len = u16::try_from(buf.len() - start_pos).expect("total_len should fit in u16");
    buf[start_pos + 16..start_pos + 18].copy_from_slice(&total_len.to_be_bytes());
  }

  async fn send<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> io::Result<()> {
    let mut buf = Vec::new();
    self.serialize_message(&mut buf);
    writer.write_all(&buf).await?;
    writer.flush().await?;
    Ok(())
  }
}

#[derive(Debug, Clone, EnumDiscriminants)]
#[repr(u8)]
pub enum Message<'a> {
  Open(OpenMessage<'a>) = 1,
  // TODO: UPDATE
  Update(UpdateMessage) = 2,
  Notification(Notification<'a>) = 3,
  Keepalive = 4,
}

impl Message<'_> {
  pub fn kind(&self) -> MessageDiscriminants {
    self.into()
  }
}

impl Message<'static> {
  pub async fn recv_raw<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self, BgpError> {
    let mut header = [0; 19];
    reader.read_exact(&mut header).await?;
    if header[0..16] != [u8::MAX; 16] {
      return Err(Notification::Header(HeaderError::ConnNotSynced).into());
    }
    let len = u16::from_be_bytes(header[16..18].try_into().unwrap()) - 19;
    let msg_type = header[18];

    if len == 0 {
      return if msg_type == MSG_KEEPALIVE {
        Ok(Self::Keepalive)
      } else {
        Err(Notification::Header(BadLen(len)).into())
      };
    }

    let mut buf = vec![0; len.into()];
    reader.read_exact(&mut buf).await?;
    let mut ptr = &*buf;

    match msg_type {
      MSG_OPEN => {
        if ptr.read_u8().await? != 4 {
          return Err(Notification::Open(UnsupportedVersion(4)).into());
        }
        let mut msg = OpenMessage::default();
        msg.my_as = ptr.read_u16().await?.into();
        msg.hold_time = ptr.read_u16().await?;
        msg.bgp_id = ptr.read_u32().await?;

        let params_len = ptr.read_u8().await?;
        if u16::from(params_len) + 10 != len {
          return Err(Notification::Open(Unspecific).into());
        }

        while let Ok(x) = ptr.read_u16().await {
          let [param_type, param_len] = x.to_be_bytes();
          if ptr.len() < param_len.into() {
            return Err(Notification::Open(Unspecific).into());
          }
          match param_type {
            OPT_PARAM_CAP => {
              let (mut ptr_cap, ptr1) = ptr.split_at(param_len.into());
              ptr = ptr1;
              while let Ok(x) = ptr_cap.read_u16().await {
                let [cap_type, cap_len] = x.to_be_bytes();
                if param_len < cap_len {
                  return Err(Notification::Open(Unspecific).into());
                }
                match cap_type {
                  CAP_4B_ASN => {
                    if cap_len != 4 {
                      return Err(Notification::Open(Unspecific).into());
                    }
                    msg.my_as = ptr_cap.read_u32().await?;
                    // TODO: require peer to support 4b ASN
                  }
                  _ => {
                    let mut cap_buf = vec![0; cap_len.into()];
                    ptr_cap.read_exact(&mut cap_buf).await?;
                    msg.other_caps.push((cap_type, cap_buf.into()));
                  }
                }
              }
            }
            _ => {
              let mut param_buf = vec![0; param_len.into()];
              ptr.read_exact(&mut param_buf).await?;
              msg.other_opt_params.push((param_type, param_buf.into()));
            }
          }
        }
        Ok(Message::Open(msg))
      }

      MSG_UPDATE => todo!(),

      MSG_NOTIFICATION => {
        let code = ptr.read_u8().await?;
        let subcode = ptr.read_u8().await?;
        let notification = match code {
          N_HEADER => {
            let subcode_p = match subcode {
              NH_CONN_NOT_SYNCED => Some(ConnNotSynced),
              NH_BAD_LEN => Some(BadLen(ptr.read_u16().await?)),
              NH_BAD_TYPE => Some(BadType(ptr.read_u8().await?)),
              _ => None,
            };
            subcode_p
              .map(|x| Notification::Header(x))
              .unwrap_or_else(|| Notification::Unknown(code, subcode, ptr.to_vec().into()))
          }
          N_OPEN => {
            let subcode_p = match subcode {
              NO_UNSPECIFIC => Some(OpenError::Unspecific),
              NO_UNSUPPORTED_VERSION => Some(UnsupportedVersion(ptr.read_u16().await?)),
              NO_BAD_PEER_AS => Some(BadPeerAS),
              NO_BAD_BGP_ID => Some(BadBGPID),
              NO_UNSUPPORTED_OPT_PARAM => Some(UnsupportedOptParam),
              NO_UNACCEPTABLE_HOLD_TIME => Some(UnacceptableHoldTime),
              _ => None,
            };
            subcode_p
              .map(|x| Notification::Open(x))
              .unwrap_or_else(|| Notification::Unknown(code, subcode, ptr.to_vec().into()))
          }
          N_UPDATE => {
            let subcode_p = match subcode {
              NU_MALFORMED_ATTR_LIST => Some(MalformedAttrList),
              NU_MISSING_WELL_KNOWN_ATTR => Some(MissingWellKnownAttr(ptr.read_u8().await?)),
              NU_INVALID_NETWORK => Some(InvalidNetwork),
              NU_MALFORMED_AS_PATH => Some(MalformedASPath),
              NU_UNRECOGNIZED_WELL_KNOWN_ATTR
              | NU_ATTR_FLAGS
              | NU_ATTR_LEN
              | NU_INVALID_ORIGIN
              | NU_INVALID_NEXT_HOP
              | NU_OPT_ATTR => {
                let discrim_fn = match subcode {
                  NU_UNRECOGNIZED_WELL_KNOWN_ATTR => UpdateError::UnrecognizedWellKnownAttr,
                  NU_ATTR_FLAGS => UpdateError::AttrFlags,
                  NU_ATTR_LEN => UpdateError::AttrLen,
                  NU_INVALID_ORIGIN => UpdateError::InvalidOrigin,
                  NU_INVALID_NEXT_HOP => UpdateError::InvalidNextHop,
                  NU_OPT_ATTR => UpdateError::OptAttr,
                  _ => unreachable!(),
                };
                Some(discrim_fn(
                  ptr.read_u8().await?,
                  ptr.read_u8().await?,
                  ptr.to_vec().into(),
                ))
              }
              _ => None,
            };
            subcode_p
              .map(|x| Notification::Update(x))
              .unwrap_or_else(|| Notification::Unknown(code, subcode, ptr.to_vec().into()))
          }
          N_HOLD_TIMER_EXPIRED => Notification::HoldTimerExpired,
          N_FSM => Notification::Fsm,
          N_CEASE => Notification::Cease,
          _ => Notification::Unknown(code, subcode, ptr.to_vec().into()),
        };
        Ok(Message::Notification(notification))
      }

      MSG_KEEPALIVE => Err(Notification::Header(BadLen(len)).into()),
      _ => Err(Notification::Header(BadType(msg_type)).into()),
    }
  }

  pub async fn recv<S: AsyncWrite + AsyncRead + Unpin>(socket: &mut S) -> Result<Self, BgpError> {
    match Message::recv_raw(socket).await {
      Ok(Message::Notification(n)) => Err(n.into()),
      Err(BgpError::Notification(n)) => return n.send_and_return(socket).await.map(|_| unreachable!()),
      other => other,
    }
  }
}

impl MessageSend for Message<'_> {
  fn serialize_data(&self, buf: &mut Vec<u8>) {
    match self {
      Self::Open(x) => x.serialize_data(buf),
      Self::Update(x) => x.serialize_data(buf),
      Self::Notification(x) => x.serialize_data(buf),
      Self::Keepalive => buf.push(MSG_KEEPALIVE),
    }
  }
}

/// Track buffer extension length
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

// TODO: Only support 4b ASN
#[derive(Debug, Clone, Default)]
pub struct OpenMessage<'a> {
  pub my_as: u32,
  pub hold_time: u16,
  pub bgp_id: u32,

  pub other_caps: Vec<(u8, Cow<'a, [u8]>)>,
  pub other_opt_params: Vec<(u8, Cow<'a, [u8]>)>,
}

impl MessageSend for OpenMessage<'_> {
  fn serialize_data(&self, buf: &mut Vec<u8>) {
    assert!(self.my_as != AS_TRANS.into());

    buf.extend([MSG_OPEN, 4]); // message type, BGP version
    buf.extend(u16::to_be_bytes(self.my_as.try_into().unwrap_or(AS_TRANS))); // my AS (2b)
    buf.extend(u16::to_be_bytes(self.hold_time));
    buf.extend(u32::to_be_bytes(self.bgp_id));

    // Optional Parameters
    extend_with_u8_len(buf, |buf| {
      // Capabilities
      buf.push(OPT_PARAM_CAP);
      extend_with_u8_len(buf, |buf| {
        [(AFI_IPV4, SAFI_UNICAST), (AFI_IPV6, SAFI_UNICAST)]
          .into_iter()
          .for_each(|(afi, safi)| {
            buf.extend([CAP_BGP_MP, 4]);
            buf.extend(u16::to_be_bytes(afi));
            buf.extend([0, safi]);
          });
        buf.extend([CAP_4B_ASN, 4]);
        buf.extend(u32::to_be_bytes(self.my_as));
        self.other_caps.iter().for_each(|(kind, value)| {
          let len = u8::try_from(value.len()).expect("opt_param_len should fit in u8");
          buf.extend([*kind, len]);
          buf.extend(&value[..]);
        });
      });

      self.other_opt_params.iter().for_each(|(kind, value)| {
        let len = u8::try_from(value.len()).expect("opt_param_len should fit in u8");
        buf.extend([*kind, len]);
        buf.extend(&value[..]);
      });
    });
  }
}

// TODO: communities...
#[derive(Debug, Clone)]
pub struct UpdateMessage {
  withdrawn: HashSet<IpPrefix>,
  nlri: Option<Nlri>,
  origin: Origin,
  as_path: Vec<u32>, // Stored in reverse
}

impl MessageSend for UpdateMessage {
  fn serialize_data(&self, buf: &mut Vec<u8>) {
    buf.push(MSG_UPDATE);

    // IPv4 withdrawn routes
    extend_with_u16_len(buf, |buf| {
      self.withdrawn.iter().filter(|x| x.is_ipv4()).for_each(|p| p.serialize(buf));
    });

    // MP_UNREACH_NLRI
    // optional, non-transitive, non-partial, use 2b length
    buf.extend([0b10010000, MP_UNREACH_NLRI]);
    self.withdrawn.iter().filter(|x| x.is_ipv6()).for_each(|p| p.serialize(buf));

    // Path attributes
    buf.extend([0b01000000, ORIGIN, 1, self.origin as u8]);
    buf.extend([
      0b01000000,
      AS_PATH,
      u8::try_from(self.as_path.len() * 4).expect("AS path length should fit in u8"),
    ]);
    buf.extend(self.as_path.iter().rev().map(|x| x.to_be_bytes()).flatten());

    // MP_REACH_NLRI
    if let Some(nlri) = &self.nlri {
      nlri.serialize(buf);
    }

    match &self.nlri {
      Some(Nlri::Route {
        prefixes,
        next_hop: NextHop::V4(next_hop),
      }) => {
        // well-known, transitive, non-partial, use 1b length
        buf.extend([0b01000000, NEXT_HOP, 4]);
        buf.extend(next_hop.octets());
        // IPv4 NLRI
        prefixes.iter().for_each(|p| {
          assert!(p.is_ipv4(), "IPv6 with IPv4 next hop not supported");
          p.serialize(buf);
        })
      }
      Some(nlri) => nlri.serialize(buf),
      _ => {}
    }
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Nlri {
  Route {
    prefixes: HashSet<IpPrefix>,
    next_hop: NextHop,
  },
  // TODO: flowspec
}

impl Nlri {
  /// Serialize to MP_REACH_NLRI.
  fn serialize(&self, buf: &mut Vec<u8>) {
    match self {
      Self::Route { prefixes, next_hop } => {
        let mut iter = prefixes.iter().peekable();
        let is_ipv4 = iter.peek().expect("NLRI contains no prefix").is_ipv4();
        let afi = if is_ipv4 { AFI_IPV4 } else { AFI_IPV6 };

        // optional, non-transitive, non-partial, use 2b length
        buf.extend([0b10010000, MP_REACH_NLRI]);
        extend_with_u16_len(buf, |buf| {
          buf.extend(afi.to_be_bytes());
          buf.push(SAFI_UNICAST);
          next_hop.serialize(buf);
          buf.push(0); // reserved
          iter.for_each(|p| {
            assert_eq!(p.is_ipv4(), is_ipv4, "NLRI contains multiple kinds of prefix");
            p.serialize(buf)
          });
        });
      }
    }
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NextHop {
  V4(Ipv4Addr),
  V6(Ipv6Addr, Option<Ipv6Addr>),
}

impl NextHop {
  fn serialize(&self, buf: &mut Vec<u8>) {
    match self {
      Self::V4(x) => {
        buf.push(4);
        buf.extend(x.octets());
      }
      Self::V6(x, Some(y)) => {
        buf.push(32);
        buf.extend(x.octets());
        buf.extend(y.octets());
      }
      Self::V6(x, None) => {
        buf.push(16);
        buf.extend(x.octets());
      }
    }
  }
}

impl From<IpAddr> for NextHop {
  fn from(ip: IpAddr) -> Self {
    match ip {
      IpAddr::V4(ip) => ip.into(),
      IpAddr::V6(ip) => ip.into(),
    }
  }
}

impl From<Ipv4Addr> for NextHop {
  fn from(ip: Ipv4Addr) -> Self {
    Self::V4(ip)
  }
}

impl From<Ipv6Addr> for NextHop {
  fn from(ip: Ipv6Addr) -> Self {
    if let [0xfe80, ..] = ip.segments() {
      Self::V6([0; 8].into(), Some(ip))
    } else {
      Self::V6(ip, None)
    }
  }
}

impl From<[Ipv6Addr; 2]> for NextHop {
  fn from(ips: [Ipv6Addr; 2]) -> Self {
    Self::V6(ips[0], Some(ips[1]))
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Origin {
  Igp = 0,
  Egp = 1,
  Incomplete = 2,
}

pub const N_HEADER: u8 = 1;
pub const N_OPEN: u8 = 2;
pub const N_UPDATE: u8 = 3;
pub const N_HOLD_TIMER_EXPIRED: u8 = 4;
pub const N_FSM: u8 = 5;
pub const N_CEASE: u8 = 6;

#[derive(Debug, Clone, EnumDiscriminants, Error)]
#[repr(u8)]
pub enum Notification<'a> {
  #[error("message header error: {0}")]
  Header(#[from] HeaderError) = N_HEADER,

  #[error("OPEN message error: {0}")]
  Open(#[from] OpenError) = N_OPEN,

  #[error("UPDATE message error: {0}")]
  Update(UpdateError<'a>) = N_UPDATE,

  #[error("hold timer expired")]
  HoldTimerExpired = N_HOLD_TIMER_EXPIRED,

  #[error("finite state machine error")]
  Fsm = N_FSM,

  #[error("ceasing operation")]
  Cease = N_CEASE,

  #[error("unknown BGP error: ({0}, {1}, {2:02x?})")]
  Unknown(u8, u8, Cow<'a, [u8]>),
}

impl Notification<'_> {
  pub fn code(&self) -> u8 {
    match self {
      Self::Unknown(code, ..) => *code,
      _ => NotificationDiscriminants::from(self) as u8,
    }
  }

  pub fn subcode(&self) -> u8 {
    match self {
      Self::Header(x) => HeaderErrorDiscriminants::from(x) as u8,
      Self::Open(x) => OpenErrorDiscriminants::from(x) as u8,
      Self::Update(x) => UpdateErrorDiscriminants::from(x) as u8,
      Self::HoldTimerExpired | Self::Fsm | Self::Cease => 0,
      Self::Unknown(_, subcode, _) => *subcode,
    }
  }

  pub fn serialize_data(&self, buf: &mut Vec<u8>) {
    match self {
      Self::Header(BadLen(x)) | Self::Open(UnsupportedVersion(x)) => buf.extend(u16::to_be_bytes(*x)),
      Self::Header(BadType(x)) | Self::Update(MissingWellKnownAttr(x)) => buf.push(*x),
      Self::Update(UnrecognizedWellKnownAttr(t, l, v))
      | Self::Update(AttrFlags(t, l, v))
      | Self::Update(AttrLen(t, l, v))
      | Self::Update(InvalidOrigin(t, l, v))
      | Self::Update(InvalidNextHop(t, l, v))
      | Self::Update(OptAttr(t, l, v)) => {
        buf.extend([t, l]);
        buf.extend(&v[..]);
      }
      Self::Unknown(_, _, data) => buf.extend(&data[..]),
      _ => {}
    }
  }
}

impl MessageSend for Notification<'_> {
  fn serialize_data(&self, buf: &mut Vec<u8>) {
    buf.extend([MSG_NOTIFICATION, self.code(), self.subcode()]);
    self.serialize_data(buf);
  }
}

impl<'a> From<UpdateError<'a>> for Notification<'a> {
  fn from(value: UpdateError<'a>) -> Self {
    Self::Update(value)
  }
}

pub trait SendAndReturn {
  async fn send_and_return<W: AsyncWrite + Unpin>(self, writer: &mut W) -> Result<(), BgpError>;
}

impl<T: Into<Notification<'static>>> SendAndReturn for T {
  async fn send_and_return<W: AsyncWrite + Unpin>(self, writer: &mut W) -> Result<(), BgpError> {
    let n = self.into();
    n.send(writer).await?;
    Err(n.into())
  }
}

pub const NH_CONN_NOT_SYNCED: u8 = 1;
pub const NH_BAD_LEN: u8 = 2;
pub const NH_BAD_TYPE: u8 = 3;

#[derive(Debug, Clone, EnumDiscriminants, Error)]
#[repr(u8)]
pub enum HeaderError {
  #[error("connection not synchronised")]
  ConnNotSynced = NH_CONN_NOT_SYNCED,

  #[error("bad message length: {0}")]
  BadLen(u16) = NH_BAD_LEN,

  #[error("bad message type: {0}")]
  BadType(u8) = NH_BAD_TYPE,
}

pub const NO_UNSPECIFIC: u8 = 0;
pub const NO_UNSUPPORTED_VERSION: u8 = 1;
pub const NO_BAD_PEER_AS: u8 = 2;
pub const NO_BAD_BGP_ID: u8 = 3;
pub const NO_UNSUPPORTED_OPT_PARAM: u8 = 4;
// value 5 is deprecated
pub const NO_UNACCEPTABLE_HOLD_TIME: u8 = 6;

#[derive(Debug, Clone, EnumDiscriminants, Error)]
#[repr(u8)]
pub enum OpenError {
  #[error("malformed optional parameter")]
  Unspecific = NO_UNSPECIFIC,

  #[error("unsupported version number; we support at least/at most version {0}")]
  UnsupportedVersion(u16) = NO_UNSUPPORTED_VERSION,

  #[error("bad peer AS")]
  BadPeerAS = NO_BAD_PEER_AS,

  #[error("bad BGP ID")]
  BadBGPID = NO_BAD_BGP_ID,

  #[error("unsupported optional parameters")]
  UnsupportedOptParam = NO_UNSUPPORTED_OPT_PARAM,

  #[error("unacceptable hold time")]
  UnacceptableHoldTime = NO_UNACCEPTABLE_HOLD_TIME,
}

pub const NU_MALFORMED_ATTR_LIST: u8 = 1;
pub const NU_UNRECOGNIZED_WELL_KNOWN_ATTR: u8 = 2;
pub const NU_MISSING_WELL_KNOWN_ATTR: u8 = 3;
pub const NU_ATTR_FLAGS: u8 = 4;
pub const NU_ATTR_LEN: u8 = 5;
pub const NU_INVALID_ORIGIN: u8 = 6;
// value 7 is deprecated
pub const NU_INVALID_NEXT_HOP: u8 = 8;
pub const NU_OPT_ATTR: u8 = 9;
pub const NU_INVALID_NETWORK: u8 = 10;
pub const NU_MALFORMED_AS_PATH: u8 = 11;

#[derive(Debug, Clone, EnumDiscriminants, Error)]
#[repr(u8)]
pub enum UpdateError<'a> {
  #[error("malformed attribute list")]
  MalformedAttrList = NU_MALFORMED_ATTR_LIST,

  #[error("unrecognized well-known attribute ({0}, {1}, {2:02x?})")]
  UnrecognizedWellKnownAttr(u8, u8, Cow<'a, [u8]>) = NU_UNRECOGNIZED_WELL_KNOWN_ATTR,

  #[error("missing well-known attribute type {0}")]
  MissingWellKnownAttr(u8) = NU_MISSING_WELL_KNOWN_ATTR,

  #[error("attribute flags error: ({0}, {1}, {2:02x?})")]
  AttrFlags(u8, u8, Cow<'a, [u8]>) = NU_ATTR_FLAGS,

  #[error("attribute length error: ({0}, {1}, {2:02x?})")]
  AttrLen(u8, u8, Cow<'a, [u8]>) = NU_ATTR_LEN,

  #[error("invalid ORIGIN attribute: ({0}, {1}, {2:02x?})")]
  InvalidOrigin(u8, u8, Cow<'a, [u8]>) = NU_INVALID_ORIGIN,

  #[error("invalid NEXT_HOP attribute: ({0}, {1}, {2:02x?})")]
  InvalidNextHop(u8, u8, Cow<'a, [u8]>) = NU_INVALID_NEXT_HOP,

  #[error("optional attribute error: ({0}, {1}, {2:02x?})")]
  OptAttr(u8, u8, Cow<'a, [u8]>) = NU_OPT_ATTR,

  #[error("invalid network field")]
  InvalidNetwork = NU_INVALID_NETWORK,

  #[error("malformed AS_PATH")]
  MalformedASPath = NU_MALFORMED_AS_PATH,
}
