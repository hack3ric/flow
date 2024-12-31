use super::nlri::{NextHop, Nlri, NlriContent, NlriKind};
use super::route::{AsSegment, AsSegmentKind, Origin, RouteInfo};
use super::{extend_with_u16_len, Result};
use crate::bgp::extend_with_u8_len;
use crate::bgp::route::{Community, ExtCommunity, Ipv6ExtCommunity, LargeCommunity};
use crate::net::{Afi, IpPrefix, IpPrefixError};
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, Take};
use log::{error, warn};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::borrow::Cow;
use std::collections::BTreeSet;
use std::future::Future;
use std::io;
use strum::{Display, EnumDiscriminants, FromRepr};
use thiserror::Error;
use HeaderError::*;
use OpenError::*;
use UpdateError::*;
use crate::util::AsyncReadBytes;

pub const AS_TRANS: u16 = 23456;

pub trait MessageSend {
  fn write_data(&self, buf: &mut Vec<u8>);

  fn write_msg(&self, buf: &mut Vec<u8>) {
    let start_pos = buf.len();
    buf.extend([u8::MAX; 16]); // marker
    buf.extend([0; 2]); // reserved for length
    self.write_data(buf);
    let total_len = u16::try_from(buf.len() - start_pos).expect("total_len should fit in u16");
    buf[start_pos + 16..start_pos + 18].copy_from_slice(&total_len.to_be_bytes());
  }

  fn send<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> impl Future<Output = io::Result<()>> {
    async {
      let mut buf = Vec::new();
      self.write_msg(&mut buf);
      writer.write_all(&buf).await?;
      writer.flush().await?;
      Ok(())
    }
  }
}

#[derive(Debug, Clone, EnumDiscriminants)]
#[strum_discriminants(name(MessageKind), derive(FromRepr))]
#[repr(u8)]
pub enum Message<'a> {
  Open(OpenMessage<'a>) = 1,
  Update(UpdateMessage<'a>) = 2,
  Notification(Notification<'a>) = 3,
  Keepalive = 4,
}

impl Message<'_> {
  pub fn kind(&self) -> MessageKind {
    self.into()
  }
}

impl Message<'static> {
  pub async fn read_raw<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
    use MessageKind as MK;

    let mut header = [0; 19];
    reader.read_exact(&mut header).await?;
    if header[0..16] != [u8::MAX; 16] {
      return Err(Notification::Header(ConnNotSynced).into());
    }
    let len = u16::from_be_bytes(header[16..18].try_into().unwrap());
    let msg_len = len.checked_sub(19).ok_or(Notification::Header(BadLen(len)))?;
    let msg_type = header[18];

    if msg_len == 0 {
      return if msg_type == MessageKind::Keepalive as u8 {
        Ok(Self::Keepalive)
      } else {
        Err(Notification::Header(BadLen(len)).into())
      };
    }

    let mut msg_reader = reader.take(msg_len.into());
    match MessageKind::from_repr(msg_type) {
      Some(MK::Open) => OpenMessage::read(&mut msg_reader).await.map(Self::Open),
      Some(MK::Update) => UpdateMessage::read(&mut msg_reader).await.map(Self::Update),
      Some(MK::Notification) => Notification::read(&mut msg_reader).await.map(Self::Notification),
      Some(MK::Keepalive) => Err(Notification::Header(BadLen(len)).into()),
      _ => Err(Notification::Header(BadType(msg_type)).into()),
    }
  }

  pub async fn read<S: AsyncWrite + AsyncRead + Unpin>(socket: &mut S) -> Result<Self> {
    match Message::read_raw(socket).await {
      Ok(Message::Notification(n)) => Err(super::Error::Remote(n)),
      Err(super::Error::Notification(n)) => n.send_and_return(socket).await.map(|_| unreachable!()),
      other => other,
    }
  }
}

impl MessageSend for Message<'_> {
  fn write_data(&self, buf: &mut Vec<u8>) {
    match self {
      Self::Open(x) => x.write_data(buf),
      Self::Update(x) => x.write_data(buf),
      Self::Notification(x) => x.write_data(buf),
      Self::Keepalive => buf.push(MessageKind::Keepalive as u8),
    }
  }
}

fn take<R: AsyncRead + Unpin>(reader: &mut R, limit: u64) -> Take<&mut R> {
  reader.take(limit)
}

async fn get_pattr_buf(
  reader: impl AsyncRead + Unpin,
  flags: u8,
  kind: u8,
  len: u16,
  read_data: impl IntoIterator<Item = u8>,
) -> Result<Cow<'static, [u8]>> {
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

async fn discard(mut reader: impl AsyncRead + Unpin) -> io::Result<()> {
  futures::io::copy(&mut reader, &mut futures::io::sink()).await?;
  Ok(())
}

pub const OPT_PARAM_CAP: u8 = 2;

pub const CAP_4B_ASN: u8 = 65;
pub const CAP_BGP_MP: u8 = 1;
pub const CAP_EXT_NEXT_HOP: u8 = 5;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OpenMessage<'a> {
  pub my_as: u32,
  pub hold_time: u16,
  pub bgp_id: u32,

  pub supports_4b_asn: bool,
  pub bgp_mp: BTreeSet<(u16, u16)>,
  pub ext_next_hop: BTreeSet<(u16, u16, u16)>,

  pub other_caps: Vec<(u8, Cow<'a, [u8]>)>,
  pub other_opt_params: Vec<(u8, Cow<'a, [u8]>)>,
}

impl OpenMessage<'static> {
  pub fn empty() -> Self {
    Self::default()
  }

  pub fn with_caps(my_as: u32, hold_time: u16, bgp_id: u32) -> Self {
    let mp = [
      (Afi::Ipv4, NlriKind::Unicast),
      (Afi::Ipv6, NlriKind::Unicast),
      (Afi::Ipv4, NlriKind::Flow),
      (Afi::Ipv6, NlriKind::Flow),
    ];
    let enh = [(Afi::Ipv4, NlriKind::Unicast, Afi::Ipv6)];
    Self {
      my_as,
      hold_time,
      bgp_id,
      supports_4b_asn: true,
      bgp_mp: mp.into_iter().map(|(a, b)| (a as _, b as _)).collect(),
      ext_next_hop: enh.into_iter().map(|(a, b, c)| (a as _, b as _, c as _)).collect(),
      ..Default::default()
    }
  }

  async fn read<R: AsyncRead + Unpin>(ptr: &mut R) -> Result<Self> {
    match Self::read_inner(ptr).await {
      Err(super::Error::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
        Err(Notification::Open(Unspecific).into())
      }
      other => other,
    }
  }

  async fn read_inner<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
    if reader.read_u8().await? != 4 {
      return Err(Notification::Open(UnsupportedVersion(4)).into());
    }
    let mut msg = OpenMessage::empty();
    msg.my_as = reader.read_u16().await?.into();
    msg.hold_time = reader.read_u16().await?;
    msg.bgp_id = reader.read_u32().await?;

    let params_len = reader.read_u8().await?;
    let mut reader = reader.take(params_len.into());
    while let Ok(x) = reader.read_u16().await {
      let [param_type, param_len] = x.to_be_bytes();
      match param_type {
        OPT_PARAM_CAP => {
          let mut cap_reader = take(&mut reader, param_len.into());
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
                msg.supports_4b_asn = true;
                msg.my_as = cap_reader.read_u32().await?;
              }
              CAP_BGP_MP => {
                if cap_len != 4 {
                  return Err(Notification::Open(Unspecific).into());
                }
                let afi = cap_reader.read_u16().await?;
                let safi = cap_reader.read_u16().await?;
                msg.bgp_mp.insert((afi, safi));
              }
              CAP_EXT_NEXT_HOP => {
                if cap_len % 6 != 0 {
                  return Err(Notification::Open(Unspecific).into());
                }
                let afi = cap_reader.read_u16().await?;
                let safi = cap_reader.read_u16().await?;
                let next_hop_afi = cap_reader.read_u16().await?;
                msg.ext_next_hop.insert((afi, safi, next_hop_afi));
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
  fn write_data(&self, buf: &mut Vec<u8>) {
    assert!(self.my_as != AS_TRANS as u32);

    buf.extend([MessageKind::Open as u8, 4]); // message type, BGP version
    buf.extend(u16::to_be_bytes(self.my_as.try_into().unwrap_or(AS_TRANS))); // my AS (2b)
    buf.extend(u16::to_be_bytes(self.hold_time));
    buf.extend(u32::to_be_bytes(self.bgp_id));

    // Optional Parameters
    extend_with_u8_len(buf, |buf| {
      // Capabilities
      buf.push(OPT_PARAM_CAP);
      extend_with_u8_len(buf, |buf| {
        self.bgp_mp.iter().for_each(|(afi, safi)| {
          buf.extend([CAP_BGP_MP, 4]);
          buf.extend(u16::to_be_bytes(*afi as _));
          buf.extend([0, *safi as u8]);
        });
        if self.supports_4b_asn {
          buf.extend([CAP_4B_ASN, 4]);
          buf.extend(u32::to_be_bytes(self.my_as));
        }
        if !self.ext_next_hop.is_empty() {
          buf.extend([
            CAP_EXT_NEXT_HOP,
            u8::try_from(self.ext_next_hop.len() * 6).expect("extended next hop capability length should fit in u8"),
          ]);
          self.ext_next_hop.iter().for_each(|&(a, b, c)| {
            buf.extend(u16::to_be_bytes(a as _));
            buf.extend([0, b as _]);
            buf.extend(u16::to_be_bytes(c as _));
          });
        }
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

// Path attribute flags
pub const PF_OPTIONAL: u8 = 0b1000_0000;
pub const PF_TRANSITIVE: u8 = 0b0100_0000;
pub const PF_PARTIAL: u8 = 0b0010_0000;
pub const PF_EXT_LEN: u8 = 0b0001_0000;
pub const PF_WELL_KNOWN: u8 = 0b0100_0000;

#[derive(Debug, Display, Clone, Copy, PartialEq, Eq, FromRepr)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
#[repr(u8)]
pub enum PathAttr {
  Origin = 1,
  AsPath = 2,
  NextHop = 3,
  MultiExitDesc = 4,
  LocalPref = 5,
  AtomicAggregate = 6,
  Aggregator = 7,
  Communities = 8,
  MpReachNlri = 14,
  MpUnreachNlri = 15,
  ExtCommunities = 16,
  Ipv6ExtCommunities = 25,
  LargeCommunities = 32,
}

// Strictly, according to RFC 7606 Section 5.1, one UPDATE message MUST NOT
// contain more than one kind of (un)reachability information. However we allow
// it here for compatibility reasons stated in the same section.
#[derive(Debug, Clone, Default)]
pub struct UpdateMessage<'a> {
  pub withdrawn: Option<Nlri>,
  pub old_withdrawn: Option<Nlri>,
  pub nlri: Option<Nlri>,
  pub old_nlri: Option<Nlri>,
  pub route_info: RouteInfo<'a>,
}

impl UpdateMessage<'_> {
  pub fn is_end_of_rib(&self) -> Option<(Afi, NlriKind)> {
    use NlriContent::*;
    if self.old_withdrawn.is_some() || self.nlri.is_some() || self.old_nlri.is_some() || !self.route_info.is_empty() {
      return None;
    }
    match &self.withdrawn {
      Some(Nlri { afi, content: c @ Unicast { prefixes, .. } }) if prefixes.is_empty() => Some((*afi, c.into())),
      Some(Nlri { afi, content: c @ Flow { specs } }) if specs.is_empty() => Some((*afi, c.into())),
      Some(_) => None,
      None => Some((Afi::Ipv4, NlriKind::Unicast)),
    }
  }

  pub fn contains_nlri(&self) -> bool {
    self.nlri.is_some() || self.old_nlri.is_some()
  }

  pub fn contains_withdrawn(&self) -> bool {
    self.withdrawn.is_some() || self.old_withdrawn.is_some()
  }
}

impl UpdateMessage<'static> {
  async fn read<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
    match Self::read_inner(reader).await {
      Err(super::Error::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
        Err(Notification::Update(MalformedAttrList).into())
      }
      other => other,
    }
  }

  async fn read_inner<R: AsyncRead + Unpin>(mut reader: &mut R) -> Result<Self> {
    let mut result = Self::default();

    let withdrawn_len = reader.read_u16().await?;
    let mut withdrawn_reader = take(&mut reader, withdrawn_len.into());
    let mut withdrawn_prefixes = BTreeSet::new();
    let mut withdrawn_read_bytes = 0u16;
    while let Some((prefix, bytes)) = IpPrefix::read_v4(&mut withdrawn_reader).await? {
      withdrawn_prefixes.insert(prefix);
      withdrawn_read_bytes += u16::from(bytes);
    }
    if withdrawn_read_bytes != withdrawn_len {
      return Err(Notification::Update(MalformedAttrList).into());
    }
    if !withdrawn_prefixes.is_empty() {
      result.old_withdrawn = Some(Nlri::new_route(Afi::Ipv4, withdrawn_prefixes, None)?);
    }

    let mut visited = BTreeSet::new();
    let mut old_next_hop = None::<NextHop>;
    let pattrs_len = reader.read_u16().await?;
    let mut pattrs_reader = take(&mut reader, pattrs_len.into());

    let mut withdraw = None;

    let read = async {
      while let Ok(flags) = pattrs_reader.read_u8().await {
        let kind = pattrs_reader.read_u8().await?;
        let len: u16 = if flags & PF_EXT_LEN == 0 {
          pattrs_reader.read_u8().await?.into()
        } else {
          pattrs_reader.read_u16().await?
        };

        if visited.contains(&kind) {
          if kind == PathAttr::MpReachNlri as u8 || kind == PathAttr::MpUnreachNlri as u8 {
            let pattr_buf = get_pattr_buf(&mut pattrs_reader, flags, kind, len, []).await?;
            return Err(Notification::Update(AttrFlags(pattr_buf)).into());
          } else {
            warn!("duplicate path attribute {kind}, ignoring");
            discard(take(&mut pattrs_reader, len.into())).await?;
            continue;
          }
        }

        match PathAttr::from_repr(kind) {
          // Well-known attributes
          Some(
            PathAttr::Origin
            | PathAttr::AsPath
            | PathAttr::NextHop
            | PathAttr::MultiExitDesc
            | PathAttr::LocalPref
            | PathAttr::AtomicAggregate
            | PathAttr::Aggregator,
          ) if flags & (PF_OPTIONAL | PF_PARTIAL) != 0 || flags & PF_TRANSITIVE == 0 => {
            let pattr_buf = get_pattr_buf(&mut pattrs_reader, flags, kind, len, []).await?;
            withdraw.get_or_insert(AttrFlags(pattr_buf));
          }

          Some(PathAttr::Origin) => {
            if len == 1 {
              let origin = pattrs_reader.read_u8().await?;
              match Origin::from_repr(origin) {
                Some(x) => result.route_info.origin = x,
                None => {
                  let pattr_buf = get_pattr_buf(&mut pattrs_reader, flags, kind, len, [origin]).await?;
                  withdraw.get_or_insert(InvalidOrigin(pattr_buf));
                }
              }
            } else {
              let pattr_buf = get_pattr_buf(&mut pattrs_reader, flags, kind, len, []).await?;
              withdraw.get_or_insert(AttrLen(pattr_buf));
            }
          }

          Some(PathAttr::AsPath) => {
            if len != 0 {
              let mut seg_reader = take(&mut pattrs_reader, len.into());
              while let Ok(seg_type) = seg_reader.read_u8().await {
                let Some(seg_type) = AsSegmentKind::from_repr(seg_type) else {
                  error!("unknown AS_PATH segment type: {seg_type}");
                  discard(seg_reader).await?;
                  withdraw.get_or_insert(MalformedAsPath);
                  break;
                };
                let as_len = seg_reader.read_u8().await?;
                if u16::from(as_len) != len / 4 {
                  discard(seg_reader).await?;
                  withdraw.get_or_insert(MalformedAsPath);
                  break;
                }
                let mut seq = SmallVec::with_capacity(as_len.into());
                let mut as_path_reader = take(&mut seg_reader, (as_len * 4).into());
                let mut count = 0;
                while let Ok(asn) = as_path_reader.read_u32().await {
                  seq.push(asn);
                  count += 1;
                }
                if count != as_len {
                  discard(seg_reader).await?;
                  withdraw.get_or_insert(MalformedAsPath);
                  break;
                }
                let seg = match seg_type {
                  AsSegmentKind::Set => AsSegment::Set(seq.into_iter().collect()),
                  AsSegmentKind::Sequence => AsSegment::Sequence(seq),
                  AsSegmentKind::ConfedSequence => AsSegment::ConfedSequence(seq),
                  AsSegmentKind::ConfedSet => AsSegment::ConfedSet(seq.into_iter().collect()),
                };
                result.route_info.as_path.push(seg);
              }
            }
          }

          Some(PathAttr::NextHop) => {
            if len == 4 {
              old_next_hop = Some(NextHop::V4(pattrs_reader.read_u32().await?.into()));
            } else {
              let pattr_buf = get_pattr_buf(&mut pattrs_reader, flags, kind, len, []).await?;
              withdraw.get_or_insert(InvalidNextHop(pattr_buf));
            }
          }

          Some(PathAttr::MultiExitDesc) => {
            if len == 4 {
              result.route_info.med = Some(pattrs_reader.read_u32().await?);
            } else {
              let pattr_buf = get_pattr_buf(&mut pattrs_reader, flags, kind, len, []).await?;
              withdraw.get_or_insert(AttrLen(pattr_buf));
            }
          }

          Some(PathAttr::LocalPref) => {
            if len == 4 {
              result.route_info.local_pref = Some(pattrs_reader.read_u32().await?);
            } else {
              let pattr_buf = get_pattr_buf(&mut pattrs_reader, flags, kind, len, []).await?;
              withdraw.get_or_insert(AttrLen(pattr_buf));
            }
          }

          Some(PathAttr::AtomicAggregate) => {
            if len == 0 {
              result.route_info.atomic_aggregate = true;
            } else {
              warn!("ATOMIC_AGGREGATE length is not zero, ignoring");
            }
          }

          Some(PathAttr::Aggregator) => {
            if len == 6 {
              result.route_info.aggregator = Some((pattrs_reader.read_u16().await?, pattrs_reader.read_u32().await?));
            } else {
              warn!("AGGREGATOR length is not 6, ignoring");
            }
          }

          // Known, optional, transitive attributes
          Some(
            PathAttr::Communities
            | PathAttr::ExtCommunities
            | PathAttr::Ipv6ExtCommunities
            | PathAttr::LargeCommunities,
          ) if flags & (PF_OPTIONAL | PF_TRANSITIVE) == 0 => {
            let pattr_buf = get_pattr_buf(&mut pattrs_reader, flags, kind, len, []).await?;
            withdraw.get_or_insert(AttrFlags(pattr_buf));
          }

          Some(PathAttr::Communities) => {
            if len % 4 == 0 {
              let mut opt_buf = vec![0; len.into()];
              pattrs_reader.read_exact(&mut opt_buf).await?;
              result.route_info.comm = opt_buf
                .chunks_exact(4)
                .map(|x| Community::from_bytes(x.try_into().unwrap()))
                .collect();
            } else {
              let pattr_buf = get_pattr_buf(&mut pattrs_reader, flags, kind, len, []).await?;
              withdraw.get_or_insert(AttrLen(pattr_buf));
            }
          }

          Some(PathAttr::ExtCommunities) => {
            if len % 8 == 0 {
              let mut opt_buf = vec![0; len.into()];
              pattrs_reader.read_exact(&mut opt_buf).await?;
              result.route_info.ext_comm = opt_buf
                .chunks_exact(8)
                .map(|x| ExtCommunity::from_bytes(x.try_into().unwrap()))
                .collect();
            } else {
              let pattr_buf = get_pattr_buf(&mut pattrs_reader, flags, kind, len, []).await?;
              withdraw.get_or_insert(AttrLen(pattr_buf));
            }
          }

          Some(PathAttr::Ipv6ExtCommunities) => {
            if len % 20 == 0 {
              let mut opt_buf = vec![0; len.into()];
              pattrs_reader.read_exact(&mut opt_buf).await?;
              if let Some(comm) = opt_buf
                .chunks_exact(20)
                .map(|x| Ipv6ExtCommunity::from_bytes(x.try_into().unwrap()))
                .collect()
              {
                result.route_info.ipv6_ext_comm = comm;
              } else {
                let pattr_buf = get_pattr_buf(&[][..], flags, kind, len, opt_buf).await?;
                withdraw.get_or_insert(OptAttr(pattr_buf));
              }
            } else {
              let pattr_buf = get_pattr_buf(&mut pattrs_reader, flags, kind, len, []).await?;
              withdraw.get_or_insert(AttrLen(pattr_buf));
            }
          }

          Some(PathAttr::LargeCommunities) => {
            if len % 12 == 0 {
              let mut opt_buf = vec![0; len.into()];
              pattrs_reader.read_exact(&mut opt_buf).await?;
              result.route_info.large_comm = opt_buf
                .chunks_exact(12)
                .map(|x| LargeCommunity::from_bytes(x.try_into().unwrap()))
                .collect();
            } else {
              let pattr_buf = get_pattr_buf(&mut pattrs_reader, flags, kind, len, []).await?;
              withdraw.get_or_insert(AttrLen(pattr_buf));
            }
          }

          // Known, optional, non-transitive attributes
          Some(PathAttr::MpReachNlri | PathAttr::MpUnreachNlri)
            if flags & PF_OPTIONAL == 0 || flags & (PF_TRANSITIVE | PF_PARTIAL) != 0 =>
          {
            let pattr_buf = get_pattr_buf(&mut pattrs_reader, flags, kind, len, []).await?;
            withdraw.get_or_insert(AttrFlags(pattr_buf));
          }

          Some(PathAttr::MpReachNlri) => {
            let mut opt_buf = vec![0; len.into()];
            pattrs_reader.read_exact(&mut opt_buf).await?;
            match Nlri::read_mp_reach(&mut &opt_buf[..]).await {
              Ok(nlri) => result.nlri = Some(nlri),
              Err(_) => {
                let pattr_buf = get_pattr_buf(&[][..], flags, kind, len, opt_buf).await?;
                return Err(Notification::Update(OptAttr(pattr_buf)).into());
              }
            }
          }

          Some(PathAttr::MpUnreachNlri) => {
            let mut opt_buf = vec![0; len.into()];
            pattrs_reader.read_exact(&mut opt_buf).await?;
            match Nlri::read_mp_unreach(&mut &opt_buf[..]).await {
              Ok(nlri) => result.withdrawn = Some(nlri),
              Err(_) => {
                let pattr_buf = get_pattr_buf(&[][..], flags, kind, len, opt_buf).await?;
                return Err(Notification::Update(OptAttr(pattr_buf)).into());
              }
            }
          }

          // Others
          None => {
            if flags & PF_OPTIONAL == 0 {
              // reject unknown well-known attribute
              let pattr_buf = get_pattr_buf(&mut pattrs_reader, flags, kind, len, []).await?;
              withdraw.get_or_insert(AttrFlags(pattr_buf));
            } else if flags & PF_TRANSITIVE == 0 && flags & PF_PARTIAL != 0 {
              // reject non-transitive but partial set
              let pattr_buf = get_pattr_buf(&mut pattrs_reader, flags, kind, len, []).await?;
              withdraw.get_or_insert(AttrFlags(pattr_buf));
            } else if flags & PF_TRANSITIVE != 0 {
              // store transitive unknown attributes
              let pattr_buf = get_pattr_buf(&mut pattrs_reader, flags, kind, len, []).await?;
              result.route_info.other_attrs.insert(kind, pattr_buf);
            }
            // silently ignore optional non-transitive unrecognized attributes
          }
        }

        visited.insert(kind);
      }
      Ok(())
    };
    match read.await {
      Err(super::Error::Io(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
        discard(pattrs_reader).await?;
        withdraw.get_or_insert(MalformedAttrList);
      }
      other => other?,
    }

    let mut old_prefixes = BTreeSet::new();
    let exec = async {
      while let Some((prefix, _)) = IpPrefix::read_v4(reader).await? {
        old_prefixes.insert(prefix);
      }
      Ok::<_, IpPrefixError>(())
    };
    if exec.await.is_err() {
      return Err(Notification::Update(InvalidNetwork).into());
    }

    if let Some(next_hop) = old_next_hop {
      result.old_nlri = Some(Nlri::new_route(Afi::Ipv4, old_prefixes, Some(next_hop))?);
    } else if !old_prefixes.is_empty() {
      warn!("missing NEXT_HOP while containing BGP-4 NLRI");
      withdraw.get_or_insert(MissingWellKnownAttr(PathAttr::NextHop as u8));
    }

    if result.nlri.is_some() || result.old_nlri.is_some() {
      for attr in [PathAttr::Origin, PathAttr::AsPath] {
        let attr_num = attr as u8;
        if !visited.contains(&attr_num) {
          warn!("missing well-known mandatory attribute {attr}");
          withdraw.get_or_insert(MissingWellKnownAttr(attr_num));
        }
      }
    }

    if let Some(error) = withdraw {
      let nlris: SmallVec<_> = [result.nlri, result.old_nlri, result.withdrawn, result.old_withdrawn]
        .into_iter()
        .flatten()
        .collect();
      if nlris.is_empty() {
        Err(Notification::Update(error).into())
      } else {
        Err(super::Error::Withdraw(error, nlris))
      }
    } else {
      // XXX: we don't have a way to check semantics of next hop
      Ok(result)
    }
  }
}

impl MessageSend for UpdateMessage<'_> {
  /// Flow does not actually send UPDATE messages, but the serialization
  /// implementation is still done for the sake of completeness. It also helps
  /// test the correctness of the deserialization logic. With that said, it is
  /// important to make this function correct as well.
  fn write_data(&self, buf: &mut Vec<u8>) {
    let old_nlri = match &self.old_nlri.as_ref().map(|x| &x.content) {
      Some(NlriContent::Unicast { prefixes, next_hop: NextHop::V4(next_hop), .. }) => Some((prefixes, next_hop)),
      Some(_) => panic!("BGP-4 NLRI supports IPv4 only"),
      None => None,
    };

    buf.push(MessageKind::Update as u8);

    // BGP-4 withdrawn routes
    extend_with_u16_len(buf, |buf| {
      let Some(NlriContent::Unicast { prefixes, .. }) = &self.old_withdrawn.as_ref().map(|x| &x.content) else {
        panic!("BGP-4 withdrawn routes support IPv4 only");
      };
      prefixes.iter().for_each(|p| {
        assert!(p.is_ipv4(), "BGP-4 withdrawn routes support IPv4 only");
        p.write(buf)
      });
    });

    extend_with_u16_len(buf, |buf| {
      if let Some(n) = self.nlri.as_ref() {
        n.write_mp_reach(buf)
      }
      if let Some(w) = self.withdrawn.as_ref() {
        w.write_mp_unreach(buf)
      }

      // Path attributes
      buf.extend([PF_WELL_KNOWN, PathAttr::Origin as u8, 1, self.route_info.origin as u8]);

      let segs_len: u16 = (self.route_info.as_path.iter())
        .fold(0u32, |a, x| a + u32::from(x.bytes_len()))
        .try_into()
        .expect("AS_PATH segment length should fit in u16");
      if let Ok(len) = u8::try_from(segs_len) {
        buf.extend([PF_WELL_KNOWN, PathAttr::AsPath as u8, len]);
      } else {
        buf.extend([PF_WELL_KNOWN | PF_EXT_LEN, PathAttr::AsPath as u8]);
        buf.extend(u16::to_be_bytes(segs_len));
      }
      self.route_info.as_path.iter().for_each(|x| x.write(buf));

      // BGP-4 next hop
      if let Some((_, next_hop)) = &old_nlri {
        buf.extend([PF_WELL_KNOWN, PathAttr::NextHop as u8, 4]);
        buf.extend(next_hop.octets());
      }

      if !self.route_info.comm.is_empty() {
        buf.extend([PF_OPTIONAL | PF_TRANSITIVE | PF_EXT_LEN, PathAttr::Communities as u8]);
        buf.extend(
          u16::try_from(self.route_info.comm.len() * 4)
            .expect("communities length should fit in u16")
            .to_be_bytes(),
        );
        buf.extend((self.route_info.comm.iter()).flat_map(|x| x.0).flat_map(u16::to_be_bytes));
      }

      if !self.route_info.ext_comm.is_empty() {
        buf.extend([PF_OPTIONAL | PF_TRANSITIVE | PF_EXT_LEN, PathAttr::ExtCommunities as u8]);
        buf.extend(
          u16::try_from(self.route_info.ext_comm.len() * 8)
            .expect("extended communities length should fit in u16")
            .to_be_bytes(),
        );
        buf.extend(self.route_info.ext_comm.iter().filter(|x| x.is_transitive()).flat_map(|x| x.0));
      }

      if !self.route_info.ipv6_ext_comm.is_empty() {
        buf.extend([
          PF_OPTIONAL | PF_TRANSITIVE | PF_EXT_LEN,
          PathAttr::Ipv6ExtCommunities as u8,
        ]);
        buf.extend(
          u16::try_from(self.route_info.ipv6_ext_comm.len() * 20)
            .expect("IPv6 extended communities length should fit in u16")
            .to_be_bytes(),
        );
        buf.extend(
          (self.route_info.ipv6_ext_comm.iter())
            .filter(|x| x.is_transitive())
            .flat_map(|x| {
              [x.kind, x.sub_kind]
                .into_iter()
                .chain(x.global_admin.octets())
                .chain(x.local_admin.to_be_bytes())
            }),
        );
      }

      if !self.route_info.large_comm.is_empty() {
        buf.extend([
          PF_OPTIONAL | PF_TRANSITIVE | PF_EXT_LEN,
          PathAttr::LargeCommunities as u8,
        ]);
        buf.extend(
          u16::try_from(self.route_info.large_comm.len() * 12)
            .expect("large communities length should fit in u16")
            .to_be_bytes(),
        );
        buf.extend(self.route_info.large_comm.iter().flat_map(|x| x.0).flat_map(u32::to_be_bytes));
      }

      self.route_info.other_attrs.values().for_each(|x| buf.extend(&x[..]));
    });

    // BGP-4 NLRI
    if let Some((prefixes, _)) = &old_nlri {
      prefixes.iter().for_each(|p| {
        assert!(p.is_ipv4(), "BGP-4 NLRI supports IPv4 only");
        p.write(buf);
      })
    }
  }
}

#[derive(Debug, Clone, EnumDiscriminants, Error)]
#[strum_discriminants(name(NotificationKind), derive(FromRepr))]
#[repr(u8)]
pub enum Notification<'a> {
  #[error("message header error: {0}")]
  Header(#[from] HeaderError) = 1,

  #[error("OPEN message error: {0}")]
  Open(#[from] OpenError) = 2,

  #[error("UPDATE message error: {0}")]
  Update(UpdateError<'a>) = 3,

  #[error("hold timer expired")]
  HoldTimerExpired = 4,

  #[error("finite state machine error")]
  Fsm = 5,

  #[error("ceasing operation")]
  Cease = 6,

  #[error("unknown BGP error: ({0}, {1}, {2:02x?})")]
  Unknown(u8, u8, Cow<'a, [u8]>),
}

impl Notification<'_> {
  pub fn code(&self) -> u8 {
    match self {
      Self::Unknown(code, ..) => *code,
      _ => NotificationKind::from(self) as u8,
    }
  }

  pub fn subcode(&self) -> u8 {
    match self {
      Self::Header(x) => HeaderErrorKind::from(x) as u8,
      Self::Open(x) => OpenErrorKind::from(x) as u8,
      Self::Update(x) => UpdateErrorKind::from(x) as u8,
      Self::HoldTimerExpired | Self::Fsm | Self::Cease => 0,
      Self::Unknown(_, subcode, _) => *subcode,
    }
  }
}

impl Notification<'static> {
  async fn read<R: AsyncRead + Unpin>(ptr: &mut R) -> Result<Self> {
    use Notification::*;
    use {HeaderErrorKind as HEK, NotificationKind as NK, OpenErrorKind as OEK, UpdateErrorKind as UEK};

    async fn to_vec<R: AsyncRead + Unpin>(ptr: &mut R) -> io::Result<Vec<u8>> {
      let mut buf = Vec::new();
      ptr.read_to_end(&mut buf).await?;
      Ok(buf)
    }

    let [code, subcode] = ptr.read_u16().await?.to_be_bytes();
    let notification = match NK::from_repr(code) {
      Some(NK::Header) => match HEK::from_repr(subcode) {
        Some(HEK::ConnNotSynced) => Header(ConnNotSynced),
        Some(HEK::BadLen) => Header(BadLen(ptr.read_u16().await?)),
        Some(HEK::BadType) => Header(BadType(ptr.read_u8().await?)),
        _ => Unknown(code, subcode, to_vec(ptr).await?.into()),
      },
      Some(NK::Open) => match OEK::from_repr(subcode) {
        Some(OEK::Unspecific) => Open(Unspecific),
        Some(OEK::UnsupportedVersion) => Open(UnsupportedVersion(ptr.read_u16().await?)),
        Some(OEK::BadPeerAs) => Open(BadPeerAs),
        Some(OEK::BadBgpId) => Open(BadBgpId),
        Some(OEK::UnsupportedOptParam) => Open(UnsupportedOptParam),
        Some(OEK::UnacceptableHoldTime) => Open(UnacceptableHoldTime),
        _ => Unknown(code, subcode, to_vec(ptr).await?.into()),
      },
      Some(NK::Update) => match UEK::from_repr(subcode) {
        Some(UEK::MalformedAttrList) => Update(MalformedAttrList),
        Some(UEK::MissingWellKnownAttr) => Update(MissingWellKnownAttr(ptr.read_u8().await?)),
        Some(UEK::InvalidNetwork) => Update(InvalidNetwork),
        Some(UEK::MalformedAsPath) => Update(MalformedAsPath),
        Some(UEK::UnrecognizedWellKnownAttr) => Update(UnrecognizedWellKnownAttr(to_vec(ptr).await?.into())),
        Some(UEK::AttrFlags) => Update(AttrFlags(to_vec(ptr).await?.into())),
        Some(UEK::AttrLen) => Update(AttrLen(to_vec(ptr).await?.into())),
        Some(UEK::InvalidOrigin) => Update(InvalidOrigin(to_vec(ptr).await?.into())),
        Some(UEK::InvalidNextHop) => Update(InvalidNextHop(to_vec(ptr).await?.into())),
        Some(UEK::OptAttr) => Update(OptAttr(to_vec(ptr).await?.into())),
        _ => Unknown(code, subcode, to_vec(ptr).await?.into()),
      },
      Some(NK::HoldTimerExpired) => HoldTimerExpired,
      Some(NK::Fsm) => Fsm,
      Some(NK::Cease) => Cease,
      _ => Unknown(code, subcode, to_vec(ptr).await?.into()),
    };
    Ok(notification)
  }
}

impl MessageSend for Notification<'_> {
  fn write_data(&self, buf: &mut Vec<u8>) {
    buf.extend([MessageKind::Notification as u8, self.code(), self.subcode()]);
    match self {
      Self::Header(BadLen(x)) | Self::Open(UnsupportedVersion(x)) => buf.extend(u16::to_be_bytes(*x)),
      Self::Header(BadType(x)) | Self::Update(MissingWellKnownAttr(x)) => buf.push(*x),
      Self::Update(UnrecognizedWellKnownAttr(v))
      | Self::Update(AttrFlags(v))
      | Self::Update(AttrLen(v))
      | Self::Update(InvalidOrigin(v))
      | Self::Update(InvalidNextHop(v))
      | Self::Update(OptAttr(v)) => buf.extend(&v[..]),
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
  fn send_and_return<W: AsyncWrite + Unpin>(self, writer: &mut W) -> impl Future<Output = Result<()>>;
}

impl<T: Into<Notification<'static>>> SendAndReturn for T {
  async fn send_and_return<W: AsyncWrite + Unpin>(self, writer: &mut W) -> Result<()> {
    let n = self.into();
    n.send(writer).await?;
    Err(n.into())
  }
}

#[derive(Debug, Clone, EnumDiscriminants, Error)]
#[strum_discriminants(name(HeaderErrorKind), derive(FromRepr))]
#[repr(u8)]
pub enum HeaderError {
  #[error("connection not synchronised")]
  ConnNotSynced = 1,

  #[error("bad message length: {0}")]
  BadLen(u16) = 2,

  #[error("bad message type: {0}")]
  BadType(u8) = 3,
}

#[derive(Debug, Clone, EnumDiscriminants, Error)]
#[strum_discriminants(name(OpenErrorKind), derive(FromRepr))]
#[repr(u8)]
pub enum OpenError {
  #[error("malformed optional parameter")]
  Unspecific = 0,

  #[error("unsupported version number; we support at least/at most version {0}")]
  UnsupportedVersion(u16) = 1,

  #[error("bad peer AS")]
  BadPeerAs = 2,

  #[error("bad BGP ID")]
  BadBgpId = 3,

  #[error("unsupported optional parameters")]
  UnsupportedOptParam = 4,

  // value 5 is deprecated
  #[error("unacceptable hold time")]
  UnacceptableHoldTime = 6,
}

#[derive(Debug, Clone, EnumDiscriminants, Error)]
#[strum_discriminants(name(UpdateErrorKind), derive(FromRepr))]
#[repr(u8)]
pub enum UpdateError<'a> {
  #[error("malformed attribute list")]
  MalformedAttrList = 1,

  #[error("unrecognized well-known attribute: {0:02x?}")]
  UnrecognizedWellKnownAttr(Cow<'a, [u8]>) = 2,

  #[error("missing well-known attribute type {0}")]
  MissingWellKnownAttr(u8) = 3,

  #[error("attribute flags error: {0:02x?}")]
  AttrFlags(Cow<'a, [u8]>) = 4,

  #[error("attribute length error: {0:02x?}")]
  AttrLen(Cow<'a, [u8]>) = 5,

  #[error("invalid ORIGIN attribute: {0:02x?}")]
  InvalidOrigin(Cow<'a, [u8]>) = 6,

  // value 7 is deprecated
  #[error("invalid NEXT_HOP attribute: {0:02x?}")]
  InvalidNextHop(Cow<'a, [u8]>) = 8,

  #[error("optional attribute error: {0:02x?}")]
  OptAttr(Cow<'a, [u8]>) = 9,

  #[error("invalid network field")]
  InvalidNetwork = 10,

  #[error("malformed AS_PATH")]
  MalformedAsPath = 11,
}
