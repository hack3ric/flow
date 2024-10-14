//! Network Layer Reachability Information (NLRI).

use super::error::BgpError;
use super::extend_with_u16_len;
use super::flow::FlowSpec;
use super::msg::{PathAttr, AFI_IPV4, AFI_IPV6, PF_EXT_LEN, PF_OPTIONAL};
use crate::net::IpPrefix;
use smallvec::SmallVec;
use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use strum::{EnumDiscriminants, FromRepr};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};

/// Network Layer Reachability Information (NLRI).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nlri {
  pub(super) ipv6: bool,
  pub(super) content: NlriContent,
}

/// NLRI contents, defined by (AFI, SAFI) tuple.
#[derive(Debug, Clone, PartialEq, Eq, EnumDiscriminants)]
#[strum_discriminants(name(NlriKind), derive(FromRepr))]
#[repr(u8)]
pub enum NlriContent {
  Unicast { prefixes: HashSet<IpPrefix>, next_hop: NextHop } = 1, // TODO: probably use LSM trie
  Flow { specs: SmallVec<[FlowSpec; 4]> } = 133,
}

impl Nlri {
  pub fn new_route(ipv6: bool, prefixes: HashSet<IpPrefix>, next_hop: Option<NextHop>) -> Result<Self, NlriError> {
    for prefix in &prefixes {
      if prefix.is_ipv6() != ipv6 {
        return Err(NlriError::MultipleAddrFamilies(ipv6));
      }
    }
    let next_hop = match next_hop {
      Some(next_hop) => next_hop,
      _ if ipv6 => NextHop::V6(Ipv6Addr::UNSPECIFIED, None),
      _ => NextHop::V4(Ipv4Addr::UNSPECIFIED),
    };
    Ok(Self { ipv6, content: NlriContent::Unicast { prefixes, next_hop } })
  }

  pub fn new_flow(ipv6: bool, specs: SmallVec<[FlowSpec; 4]>) -> Result<Self, NlriError> {
    for spec in &specs {
      if spec.is_ipv6() != ipv6 {
        return Err(NlriError::MultipleAddrFamilies(ipv6));
      }
    }
    Ok(Self { ipv6, content: NlriContent::Flow { specs } })
  }

  pub fn kind(&self) -> &NlriContent {
    &self.content
  }

  pub fn serialize_mp_reach(&self, buf: &mut Vec<u8>) {
    self.serialize_mp(buf, true);
  }
  pub fn serialize_mp_unreach(&self, buf: &mut Vec<u8>) {
    self.serialize_mp(buf, false);
  }
  pub fn serialize_mp(&self, buf: &mut Vec<u8>, reach: bool) {
    buf.extend([
      PF_OPTIONAL | PF_EXT_LEN,
      if reach {
        PathAttr::MpReachNlri
      } else {
        PathAttr::MpUnreachNlri
      } as u8,
    ]);
    if self.ipv6 {
      buf.extend(AFI_IPV6.to_be_bytes());
    } else {
      buf.extend(AFI_IPV4.to_be_bytes());
    }
    match self.kind() {
      NlriContent::Unicast { prefixes, next_hop } => {
        extend_with_u16_len(buf, |buf| {
          buf.push(NlriKind::Unicast as u8);
          if reach {
            next_hop.serialize_mp(buf);
            buf.push(0); // reserved
          }
          prefixes.iter().for_each(|p| {
            assert_eq!(p.is_ipv6(), self.ipv6, "NLRI contains multiple kinds of prefix");
            p.serialize(buf)
          });
        });
      }
      NlriContent::Flow { specs } => {
        extend_with_u16_len(buf, |buf| {
          buf.push(NlriKind::Flow as u8);
          if reach {
            buf.extend([0; 2]); // null next hop, reserved
          }
          specs.iter().for_each(|s| {
            assert_eq!(s.is_ipv6(), self.ipv6, "NLRI contains flowspecs of multiple protocols");
            s.serialize(buf);
          });
        });
      }
    }
  }

  pub async fn recv_mp_reach<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self, BgpError> {
    Self::recv_mp(reader, true).await
  }
  pub async fn recv_mp_unreach<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self, BgpError> {
    Self::recv_mp(reader, false).await
  }
  pub async fn recv_mp<R: AsyncRead + Unpin>(reader: &mut R, reach: bool) -> Result<Self, BgpError> {
    let afi = reader.read_u16().await?;
    let safi = reader.read_u8().await?;
    let next_hop;
    if reach {
      next_hop = NextHop::recv_mp(reader).await?;
      let _reserved = reader.read_u8().await?;
    } else {
      next_hop = (safi != NlriKind::Flow as u8).then_some(NextHop::V6(Ipv6Addr::UNSPECIFIED, None));
    };
    match (afi, NlriKind::from_repr(safi), next_hop) {
      (AFI_IPV4, Some(NlriKind::Unicast), Some(next_hop))
      | (AFI_IPV6, Some(NlriKind::Unicast), Some(next_hop @ NextHop::V6(..))) => {
        let mut prefixes = HashSet::new();
        while let Some(prefix) = IpPrefix::recv(reader, afi == AFI_IPV6).await? {
          prefixes.insert(prefix);
        }
        Ok(Self::new_route(afi == AFI_IPV6, prefixes, Some(next_hop))?)
      }
      (_, Some(NlriKind::Flow), None) => {
        let mut specs = SmallVec::new_const();
        while let Some(spec) = FlowSpec::recv(reader, afi == AFI_IPV6).await? {
          specs.push(spec);
        }
        Ok(Self::new_flow(afi == AFI_IPV6, specs)?)
      }
      (_, Some(kind @ NlriKind::Unicast), None) | (_, Some(kind @ NlriKind::Flow), Some(_)) => {
        return Err(NlriError::InvalidNextHop { ipv6: afi == AFI_IPV6, kind, next_hop }.into())
      }
      _ => return Err(NlriError::UnknownTuple(afi, safi).into()),
    }
  }
}

/// Next hop address.
///
/// IPv6 next hop address may include a link-local IPv6 address.
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

  async fn recv_mp<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Option<Self>> {
    let len = reader.read_u8().await?;
    match len {
      0 => Ok(None),
      4 => Ok(Some(Self::V4(reader.read_u32().await?.into()))),
      16 => Ok(Some(Self::V6(reader.read_u128().await?.into(), None))),
      32 => Ok(Some(Self::V6(
        reader.read_u128().await?.into(),
        Some(reader.read_u128().await?.into()),
      ))),
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

#[derive(Debug, Clone, Error)]
pub enum NlriError {
  #[error("{} NLRI contains {} information", if *.0 { "IPv6" } else { "IPv4" }, if *.0 { "IPv4" } else { "IPv6" })]
  MultipleAddrFamilies(bool),
  #[error("NLRI ({}, {kind:?}) contains invalid next hop: {next_hop:?}", if *.ipv6 { "IPv6" } else { "IPv4" })]
  InvalidNextHop { ipv6: bool, kind: NlriKind, next_hop: Option<NextHop> },
  #[error("unknown (AFI, SAFI) tuple: ({0}, {1})")]
  UnknownTuple(u16, u8),
}
