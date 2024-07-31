use super::error::BgpError;
use crate::net::{IpPrefix, IpPrefixError};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use strum::EnumDiscriminants;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use HeaderError::*;
use OpenError::*;
use UpdateError::*;

pub const AS_TRANS: u16 = 23456;

pub const MSG_OPEN: u8 = 1;
pub const MSG_UPDATE: u8 = 2;
pub const MSG_NOTIFICATION: u8 = 3;
pub const MSG_KEEPALIVE: u8 = 4;

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
  Open(OpenMessage<'a>) = MSG_OPEN,
  Update(UpdateMessage<'a>) = MSG_UPDATE,
  Notification(Notification<'a>) = MSG_NOTIFICATION,
  Keepalive = MSG_KEEPALIVE,
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

    let mut msg_reader = reader.take(len.into());
    match msg_type {
      MSG_OPEN => OpenMessage::recv(&mut msg_reader).await.map(Message::Open),
      MSG_UPDATE => UpdateMessage::recv(&mut msg_reader).await.map(Message::Update),
      MSG_NOTIFICATION => Notification::recv(&mut msg_reader).await.map(Message::Notification),
      MSG_KEEPALIVE => Err(Notification::Header(BadLen(len)).into()),
      _ => Err(Notification::Header(BadType(msg_type)).into()),
    }
  }

  pub async fn recv<S: AsyncWrite + AsyncRead + Unpin>(socket: &mut S) -> Result<Self, BgpError> {
    // TODO: separate our error and their error
    match Message::recv_raw(socket).await {
      Ok(Message::Notification(n)) => Err(n.into()),
      Err(BgpError::Notification(n)) => n.send_and_return(socket).await.map(|_| unreachable!()),
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

async fn get_pattr_buf(
  reader: &mut (impl AsyncRead + Unpin),
  flags: u8,
  kind: u8,
  len: u16,
  read_data: impl IntoIterator<Item = u8>,
) -> Result<Cow<'static, [u8]>, BgpError> {
  let mut pattr_buf = vec![flags, kind];
  if flags & PF_EXT_LEN == 0 {
    pattr_buf.push(len as u8);
  } else {
    pattr_buf.extend(len.to_be_bytes());
  }
  pattr_buf.extend(read_data);
  reader.take(len.into()).read_to_end(&mut pattr_buf).await?;
  Ok(pattr_buf.into())
}

pub const OPT_PARAM_CAP: u8 = 2;

pub const CAP_4B_ASN: u8 = 65;
pub const CAP_BGP_MP: u8 = 1;

#[derive(Debug, Clone, Default)]
pub struct OpenMessage<'a> {
  pub my_as: u32,
  pub hold_time: u16,
  pub bgp_id: u32,

  pub other_caps: Vec<(u8, Cow<'a, [u8]>)>,
  pub other_opt_params: Vec<(u8, Cow<'a, [u8]>)>,
}

impl OpenMessage<'static> {
  async fn recv<R: AsyncRead + Unpin>(ptr: &mut R) -> Result<Self, BgpError> {
    match Self::recv_inner(ptr).await {
      Err(BgpError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => Err(Notification::Open(Unspecific).into()),
      other => other,
    }
  }

  async fn recv_inner<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self, BgpError> {
    if reader.read_u8().await? != 4 {
      return Err(Notification::Open(UnsupportedVersion(4)).into());
    }
    let mut msg = OpenMessage::default();
    msg.my_as = reader.read_u16().await?.into();
    msg.hold_time = reader.read_u16().await?;
    msg.bgp_id = reader.read_u32().await?;

    let params_len = reader.read_u8().await?;
    let mut reader = reader.take(params_len.into());
    while let Ok(x) = reader.read_u16().await {
      let [param_type, param_len] = x.to_be_bytes();
      match param_type {
        OPT_PARAM_CAP => {
          let mut cap_reader = (&mut reader).take(param_len.into());
          while let Ok(x) = cap_reader.read_u16().await {
            let [cap_type, cap_len] = x.to_be_bytes();
            if param_len < cap_len {
              return Err(Notification::Open(Unspecific).into());
            }
            match cap_type {
              CAP_4B_ASN => {
                if cap_len != 4 {
                  return Err(Notification::Open(Unspecific).into());
                }
                msg.my_as = cap_reader.read_u32().await?;
                // TODO: require peer to support 4b ASN
              }
              _ => {
                let mut cap_buf = vec![0; cap_len.into()];
                cap_reader.read_exact(&mut cap_buf).await?;
                msg.other_caps.push((cap_type, cap_buf.into()));
              }
            }
          }
        }
        _ => {
          let mut param_buf = vec![0; param_len.into()];
          reader.read_exact(&mut param_buf).await?;
          msg.other_opt_params.push((param_type, param_buf.into()));
        }
      }
    }
    Ok(msg)
  }
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

// https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
pub const AFI_IPV4: u16 = 1;
pub const AFI_IPV6: u16 = 2;

pub const SAFI_UNICAST: u8 = 1;
#[allow(dead_code)]
pub const SAFI_MULTICAST: u8 = 2;
#[allow(dead_code)]
pub const SAFI_FLOW: u8 = 133;

// Path attribute flags
pub const PF_OPTIONAL: u8 = 0b1000_0000;
pub const PF_TRANSITIVE: u8 = 0b0100_0000;
pub const PF_PARTIAL: u8 = 0b0010_0000;
pub const PF_EXT_LEN: u8 = 0b0001_0000;
pub const PF_WELL_KNOWN: u8 = 0b0100_0000;

// Path attribute types
pub const P_ORIGIN: u8 = 1;
pub const P_AS_PATH: u8 = 2;
pub const P_NEXT_HOP: u8 = 3;
pub const P_MP_REACH_NLRI: u8 = 14;
pub const P_MP_UNREACH_NLRI: u8 = 15;

// Strictly, according to RFC 7606 Section 5.1, one UPDATE message MUST NOT
// contain more than one kind of (un)reachability information. However we allow
// it here for compatibility reasons stated in the same section.
//
// TODO: communities...
#[derive(Debug, Clone)]
pub struct UpdateMessage<'a> {
  withdrawn: HashSet<IpPrefix>,
  nlri: Option<Nlri>,
  old_nlri: Option<Nlri>,
  origin: Origin,
  /// AS path, stored in reverse.
  as_path: Cow<'a, [u32]>,
  /// Transitive but unrecognized path attributes.
  other_attrs: HashMap<u8, Cow<'a, [u8]>>,
}

impl UpdateMessage<'static> {
  async fn recv<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self, BgpError> {
    match Self::recv_inner(reader).await {
      Err(BgpError::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
        Err(Notification::Update(MalformedAttrList).into())
      }
      other => other,
    }
  }

  async fn recv_inner<R: AsyncRead + Unpin>(mut reader: &mut R) -> Result<Self, BgpError> {
    let mut result = Self {
      withdrawn: HashSet::new(),
      nlri: None,
      old_nlri: None,
      origin: Origin::Incomplete,
      as_path: Cow::Borrowed(&[]),
      other_attrs: HashMap::new(),
    };

    let withdrawn_len = reader.read_u16().await?;
    let mut withdrawn_reader = (&mut reader).take(withdrawn_len.into());
    while let Some(prefix) = IpPrefix::recv_v4(&mut withdrawn_reader).await? {
      result.withdrawn.insert(prefix);
    }

    let mut visited = HashSet::new();
    let mut old_next_hop = None::<NextHop>;
    let pattrs_len = reader.read_u16().await?;
    let mut pattrs_reader = (&mut reader).take(pattrs_len.into());

    while let Ok(x) = pattrs_reader.read_u16().await {
      let [flags, kind] = x.to_be_bytes();
      let len: u16 = if flags & PF_EXT_LEN == 0 {
        pattrs_reader.read_u8().await?.into()
      } else {
        pattrs_reader.read_u16().await?
      };

      async fn gen_attr_flags_error(
        reader: &mut (impl AsyncRead + Unpin),
        flags: u8,
        kind: u8,
        len: u16,
      ) -> Result<UpdateMessage<'static>, BgpError> {
        let pattr_buf = get_pattr_buf(reader, flags, kind, len, []).await?;
        Err(Notification::Update(AttrFlags(pattr_buf)).into())
      }

      if visited.contains(&kind) {
        let pattr_buf = get_pattr_buf(&mut pattrs_reader, flags, kind, len, []).await?;
        return Err(Notification::Update(AttrFlags(pattr_buf)).into());
      }

      match kind {
        // Well-known attributes
        P_ORIGIN | P_AS_PATH | P_NEXT_HOP if flags & (PF_OPTIONAL | PF_PARTIAL) != 0 || flags & PF_TRANSITIVE == 0 => {
          return gen_attr_flags_error(&mut pattrs_reader, flags, kind, len).await;
        }
        P_ORIGIN => {
          if len != 1 {
            let pattr_buf = get_pattr_buf(&mut pattrs_reader, flags, kind, len, []).await?;
            return Err(Notification::Update(AttrLen(pattr_buf)).into());
          }
          result.origin = match pattrs_reader.read_u8().await? {
            O_IGP => Origin::Igp,
            O_EGP => Origin::Egp,
            O_INCOMPLETE => Origin::Incomplete,
            other => {
              let pattr_buf = get_pattr_buf(&mut pattrs_reader, flags, kind, len, [other]).await?;
              return Err(Notification::Update(InvalidOrigin(pattr_buf)).into());
            }
          }
        }
        P_AS_PATH => {
          if len % 4 != 0 {
            return Err(Notification::Update(MalformedASPath).into());
          }
          let mut as_path = Vec::new();
          let mut as_path_reader = (&mut pattrs_reader).take(len.into());
          while let Ok(asn) = as_path_reader.read_u32().await {
            as_path.push(asn);
          }
          if result.as_path.len() != usize::from(len % 4) {
            return Err(Notification::Update(MalformedASPath).into());
          }
          as_path.reverse();
          result.as_path = as_path.into();
        }
        P_NEXT_HOP => {
          if len != 4 {
            let pattr_buf = get_pattr_buf(&mut pattrs_reader, flags, kind, len, []).await?;
            return Err(Notification::Update(InvalidNextHop(pattr_buf)).into());
          }
          old_next_hop = Some(NextHop::V4(pattrs_reader.read_u32().await?.into()));
        }

        // Known optional attributes
        P_MP_REACH_NLRI | P_MP_UNREACH_NLRI
          if flags & PF_OPTIONAL == 0 || flags & (PF_TRANSITIVE | PF_PARTIAL) != 0 =>
        {
          return gen_attr_flags_error(&mut pattrs_reader, flags, kind, len).await;
        }
        P_MP_REACH_NLRI => {
          let mut opt_buf = vec![0; len.into()];
          pattrs_reader.read_exact(&mut opt_buf).await?;
          match Nlri::recv_mp(&mut &opt_buf[..]).await {
            Ok(nlri) => result.nlri = Some(nlri),
            Err(_) => {
              let pattr_buf = get_pattr_buf(&mut &[][..], flags, kind, len, opt_buf).await?;
              return Err(Notification::Update(OptAttr(pattr_buf)).into());
            }
          }
        }
        P_MP_UNREACH_NLRI => {
          let mut opt_buf = vec![0; len.into()];
          pattrs_reader.read_exact(&mut opt_buf).await?;
          let mut unreach_reader = &*opt_buf;
          let exec = async {
            while let Some(prefix) = IpPrefix::recv_v6(&mut unreach_reader).await? {
              result.withdrawn.insert(prefix);
            }
            Ok::<_, IpPrefixError>(())
          };
          if exec.await.is_err() {
            let pattr_buf = get_pattr_buf(&mut &[][..], flags, kind, len, opt_buf).await?;
            return Err(Notification::Update(OptAttr(pattr_buf)).into());
          }
        }

        // Others
        _ => {
          // reject unknown well-known attribute
          if flags & PF_OPTIONAL == 0 {
            return gen_attr_flags_error(&mut pattrs_reader, flags, kind, len).await;
          }
          // reject non-transitive but partial set
          if flags & PF_TRANSITIVE == 0 && flags & PF_PARTIAL != 0 {
            return gen_attr_flags_error(&mut pattrs_reader, flags, kind, len).await;
          }
          // store transitive unknown attributes
          if flags & PF_TRANSITIVE != 0 {
            let pattr_buf = get_pattr_buf(&mut pattrs_reader, flags, kind, len, []).await?;
            result.other_attrs.insert(kind, pattr_buf);
          }
          // silently ignore optional non-transitive unrecognized attributes
        }
      }

      visited.insert(kind);
    }

    let mut old_prefixes = HashSet::new();
    let exec = async {
      while let Some(prefix) = IpPrefix::recv_v4(reader).await? {
        old_prefixes.insert(prefix);
      }
      Ok::<_, IpPrefixError>(())
    };
    if exec.await.is_err() {
      return Err(Notification::Update(InvalidNetwork).into());
    }
    if let Some(next_hop) = old_next_hop {
      result.old_nlri = Some(Nlri::Route {
        prefixes: old_prefixes,
        next_hop,
      });
    } else if !old_prefixes.is_empty() {
      return Err(Notification::Update(MissingWellKnownAttr(P_NEXT_HOP)).into());
    }

    if result.nlri.is_some() || result.old_nlri.is_some() {
      for attr in [P_ORIGIN, P_AS_PATH] {
        if !visited.contains(&attr) {
          return Err(Notification::Update(MissingWellKnownAttr(attr)).into());
        }
      }
    }

    Ok(result)
  }
}

impl MessageSend for UpdateMessage<'_> {
  fn serialize_data(&self, buf: &mut Vec<u8>) {
    let old_nlri = match &self.old_nlri {
      Some(Nlri::Route {
        prefixes,
        next_hop: NextHop::V4(next_hop),
      }) => Some((prefixes, next_hop)),
      Some(_) => panic!("BGP-4 NLRI supports IPv4 only"),
      None => None,
    };

    buf.push(MSG_UPDATE);

    // IPv4 withdrawn routes
    extend_with_u16_len(buf, |buf| {
      self.withdrawn.iter().filter(|x| x.is_ipv4()).for_each(|p| p.serialize(buf));
    });

    extend_with_u16_len(buf, |buf| {
      // MP_REACH_NLRI
      if let Some(nlri) = &self.nlri {
        nlri.serialize_mp(buf);
      }
      // MP_UNREACH_NLRI
      if !self.withdrawn.is_empty() {
        buf.extend([PF_OPTIONAL | PF_EXT_LEN, P_MP_UNREACH_NLRI]);
        self.withdrawn.iter().filter(|x| x.is_ipv6()).for_each(|p| p.serialize(buf));
      }

      // Path attributes
      buf.extend([PF_WELL_KNOWN, P_ORIGIN, 1, self.origin as u8]);
      let as_path_len = u8::try_from(self.as_path.len() * 4).expect("AS path length should fit in u8");
      buf.extend([PF_WELL_KNOWN, P_AS_PATH, as_path_len]);
      buf.extend(self.as_path.iter().rev().map(|x| x.to_be_bytes()).flatten());

      if let Some((_, next_hop)) = &old_nlri {
        buf.extend([PF_WELL_KNOWN, P_NEXT_HOP, 4]);
        buf.extend(next_hop.octets());
      }
    });

    // IPv4 NLRI
    if let Some((prefixes, _)) = &old_nlri {
      prefixes.iter().for_each(|p| {
        assert!(p.is_ipv4(), "BGP-4 NLRI supports IPv4 only");
        p.serialize(buf);
      })
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
  fn serialize_mp(&self, buf: &mut Vec<u8>) {
    match self {
      Self::Route { prefixes, next_hop } => {
        let mut iter = prefixes.iter().peekable();
        let is_ipv4 = iter.peek().expect("NLRI contains no prefix").is_ipv4();
        let afi = if is_ipv4 { AFI_IPV4 } else { AFI_IPV6 };

        buf.extend([PF_OPTIONAL | PF_EXT_LEN, P_MP_REACH_NLRI]);
        extend_with_u16_len(buf, |buf| {
          buf.extend(afi.to_be_bytes());
          buf.push(SAFI_UNICAST);
          next_hop.serialize_mp(buf);
          buf.push(0); // reserved
          iter.for_each(|p| {
            assert_eq!(p.is_ipv4(), is_ipv4, "NLRI contains multiple kinds of prefix");
            p.serialize(buf)
          });
        });
      }
    }
  }

  async fn recv_mp<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self, IpPrefixError> {
    let afi = reader.read_u16().await?;
    let safi = reader.read_u8().await?;
    let next_hop = NextHop::recv_mp(reader).await?;
    let mut prefixes = HashSet::new();
    match (afi, safi, next_hop) {
      (AFI_IPV4, SAFI_UNICAST, _) => {
        while let Some(prefix) = IpPrefix::recv_v4(reader).await? {
          prefixes.insert(prefix);
        }
      }
      (AFI_IPV6, SAFI_UNICAST, NextHop::V6(..)) => {
        while let Some(prefix) = IpPrefix::recv_v6(reader).await? {
          prefixes.insert(prefix);
        }
      }
      // TODO: flow
      _ => return Err(io::Error::other("dummy").into()),
    }
    todo!();
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NextHop {
  V4(Ipv4Addr),
  V6(Ipv6Addr, Option<Ipv6Addr>),
}

impl NextHop {
  fn serialize_mp(&self, buf: &mut Vec<u8>) {
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

  async fn recv_mp<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Self> {
    let len = reader.read_u8().await?;
    match len {
      4 => Ok(Self::V4(reader.read_u32().await?.into())),
      16 => Ok(Self::V6(reader.read_u128().await?.into(), None)),
      32 => Ok(Self::V6(
        reader.read_u128().await?.into(),
        Some(reader.read_u128().await?.into()),
      )),
      _ => Err(io::Error::other("dummy")),
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

pub const O_IGP: u8 = 0;
pub const O_EGP: u8 = 1;
pub const O_INCOMPLETE: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Origin {
  Igp = O_IGP,
  Egp = O_EGP,
  Incomplete = O_INCOMPLETE,
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
}

impl Notification<'static> {
  async fn recv<R: AsyncRead + Unpin>(ptr: &mut R) -> Result<Self, BgpError> {
    async fn to_vec<R: AsyncRead + Unpin>(ptr: &mut R) -> io::Result<Vec<u8>> {
      let mut buf = Vec::new();
      ptr.read_to_end(&mut buf).await?;
      Ok(buf)
    }

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
        match subcode_p {
          Some(x) => Notification::Header(x),
          None => Notification::Unknown(code, subcode, to_vec(ptr).await?.into()),
        }
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
        match subcode_p {
          Some(x) => Notification::Open(x),
          None => Notification::Unknown(code, subcode, to_vec(ptr).await?.into()),
        }
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
            Some(discrim_fn(to_vec(ptr).await?.into()))
          }
          _ => None,
        };
        match subcode_p {
          Some(x) => Notification::Update(x),
          None => Notification::Unknown(code, subcode, to_vec(ptr).await?.into()),
        }
      }
      N_HOLD_TIMER_EXPIRED => Notification::HoldTimerExpired,
      N_FSM => Notification::Fsm,
      N_CEASE => Notification::Cease,
      _ => Notification::Unknown(code, subcode, to_vec(ptr).await?.into()),
    };
    Ok(notification)
  }
}

impl MessageSend for Notification<'_> {
  fn serialize_data(&self, buf: &mut Vec<u8>) {
    buf.extend([MSG_NOTIFICATION, self.code(), self.subcode()]);
    match self {
      Self::Header(BadLen(x)) | Self::Open(UnsupportedVersion(x)) => buf.extend(u16::to_be_bytes(*x)),
      Self::Header(BadType(x)) | Self::Update(MissingWellKnownAttr(x)) => buf.push(*x),
      Self::Update(UnrecognizedWellKnownAttr(v))
      | Self::Update(AttrFlags(v))
      | Self::Update(AttrLen(v))
      | Self::Update(InvalidOrigin(v))
      | Self::Update(InvalidNextHop(v))
      | Self::Update(OptAttr(v)) => {
        buf.extend(&v[..]);
      }
      Self::Unknown(_, _, data) => buf.extend(&data[..]),
      _ => {}
    }
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

  #[error("unrecognized well-known attribute: {0:02x?}")]
  UnrecognizedWellKnownAttr(Cow<'a, [u8]>) = NU_UNRECOGNIZED_WELL_KNOWN_ATTR,

  #[error("missing well-known attribute type {0}")]
  MissingWellKnownAttr(u8) = NU_MISSING_WELL_KNOWN_ATTR,

  #[error("attribute flags error: {0:02x?}")]
  AttrFlags(Cow<'a, [u8]>) = NU_ATTR_FLAGS,

  #[error("attribute length error: {0:02x?}")]
  AttrLen(Cow<'a, [u8]>) = NU_ATTR_LEN,

  #[error("invalid ORIGIN attribute: {0:02x?}")]
  InvalidOrigin(Cow<'a, [u8]>) = NU_INVALID_ORIGIN,

  #[error("invalid NEXT_HOP attribute: {0:02x?}")]
  InvalidNextHop(Cow<'a, [u8]>) = NU_INVALID_NEXT_HOP,

  #[error("optional attribute error: {0:02x?}")]
  OptAttr(Cow<'a, [u8]>) = NU_OPT_ATTR,

  #[error("invalid network field")]
  InvalidNetwork = NU_INVALID_NETWORK,

  #[error("malformed AS_PATH")]
  MalformedASPath = NU_MALFORMED_AS_PATH,
}
