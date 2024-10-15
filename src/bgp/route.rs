use super::flow::FlowSpec;
use super::nlri::NextHop;
use crate::net::IpPrefix;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fmt::{self, Debug, Display, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr};
use strum::FromRepr;

#[derive(Debug)]
pub struct Routes {
  unicast: HashMap<IpPrefix, (NextHop, RouteInfo<'static>)>,
  flow: HashMap<FlowSpec, RouteInfo<'static>>,
}

#[derive(Debug, Clone)]
pub struct RouteInfo<'a> {
  pub(super) origin: Origin,

  /// AS path, stored in reverse.
  pub(super) as_path: Cow<'a, [u32]>,

  /// RFC 1997 communities.
  pub(super) comm: HashSet<[u16; 2]>,
  /// RFC 4360/5668 extended communities.
  pub(super) ext_comm: HashSet<ExtCommunity>,
  /// RFC 5701 IPv6 address-specific extended communities.
  pub(super) ipv6_ext_comm: HashSet<Ipv6ExtCommunity>,
  /// RFC 8092 large communities.
  pub(super) large_comm: HashSet<[u32; 3]>,

  /// Transitive but unrecognized path attributes.
  pub(super) other_attrs: HashMap<u8, Cow<'a, [u8]>>,
}

impl RouteInfo<'_> {
  pub fn is_empty(&self) -> bool {
    self.as_path.is_empty()
      && self.comm.is_empty()
      && self.ext_comm.is_empty()
      && self.ipv6_ext_comm.is_empty()
      && self.large_comm.is_empty()
      && self.other_attrs.is_empty()
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, FromRepr)]
#[repr(u8)]
pub enum Origin {
  Igp = 0,
  Egp = 1,
  Incomplete = 2,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExtCommunity([u8; 8]);

impl ExtCommunity {
  pub fn from_bytes(bytes: [u8; 8]) -> Self {
    Self(bytes)
  }

  pub fn new_as_specific(transitive: bool, sub_kind: u8, asn: u32, local_admin: u32) -> Self {
    let mut bytes = [0; 8];
    bytes[1] = sub_kind;
    if asn > u16::MAX.into() {
      bytes[0] = 2;
      let local_admin = local_admin
        .try_into()
        .expect("4b ASN extended community can only contain 16-bit local admin value");
      bytes[2..6].copy_from_slice(&u32::to_be_bytes(asn));
      bytes[6..8].copy_from_slice(&u16::to_be_bytes(local_admin));
    } else {
      bytes[0] = 0;
      bytes[2..4].copy_from_slice(&u16::to_be_bytes(asn as _));
      bytes[4..8].copy_from_slice(&u32::to_be_bytes(local_admin));
    }
    if !transitive {
      bytes[0] |= 1 << 6;
    }
    Self(bytes)
  }

  pub fn new_ipv4_specific(transitive: bool, sub_kind: u8, ipv4: Ipv4Addr, local_admin: u16) -> Self {
    let mut bytes = [0; 8];
    bytes[0] = 1;
    bytes[1] = sub_kind;
    bytes[2..6].copy_from_slice(&ipv4.octets());
    bytes[6..8].copy_from_slice(&u16::to_be_bytes(local_admin));
    if !transitive {
      bytes[0] |= 1 << 6;
    }
    Self(bytes)
  }

  pub fn iana_authority(self) -> bool {
    self.0[0] & (1 << 7) != 0
  }
  pub fn is_transitive(self) -> bool {
    self.0[0] & (1 << 6) == 0
  }
  pub fn kind(self) -> u8 {
    self.0[0]
  }
  pub fn kind_struct(self) -> u8 {
    self.0[0] & 0b111111
  }
  pub fn sub_kind(self) -> u8 {
    self.0[1]
  }

  pub fn admins(self) -> Option<(GlobalAdmin, u32)> {
    use GlobalAdmin::*;
    match self.kind_struct() {
      0 => Some((
        As(u16::from_be_bytes(self.0[2..4].try_into().unwrap()).into()),
        u32::from_be_bytes(self.0[4..8].try_into().unwrap()),
      )),
      1 => Some((
        Ipv4(u32::from_be_bytes(self.0[2..6].try_into().unwrap()).into()),
        u16::from_be_bytes(self.0[6..8].try_into().unwrap()).into(),
      )),
      2 => Some((
        As(u32::from_be_bytes(self.0[2..6].try_into().unwrap())),
        u16::from_be_bytes(self.0[6..8].try_into().unwrap()).into(),
      )),
      _ => None,
    }
  }
  pub fn global_admin(self) -> Option<GlobalAdmin> {
    self.admins().map(|(g, _)| g)
  }
  pub fn local_admin(self) -> Option<u32> {
    self.admins().map(|(_, l)| l)
  }

  pub fn opaque_value(self) -> Option<u64> {
    (self.kind_struct() == 3).then(|| {
      let mut bytes = self.0;
      bytes[0..2].copy_from_slice(&[0; 2]);
      u64::from_be_bytes(bytes)
    })
  }
}

impl Debug for ExtCommunity {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    write!(f, "ExtCommunity{self}")
  }
}

impl Display for ExtCommunity {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    match (self.admins(), self.opaque_value()) {
      (Some(_), Some(_)) => unreachable!(),
      (Some((g, l)), None) => {
        match [self.kind(), self.sub_kind()] {
          [0x00 | 0x01 | 0x02, 0x02] => f.write_str("(route-target, ")?,
          [0x00 | 0x01 | 0x02, 0x03] => f.write_str("(route-origin, ")?,
          bytes => write!(f, "({:#06x}, ", u16::from_be_bytes(bytes))?,
        }
        if l > u16::MAX.into() {
          write!(f, "{g}, {l:#010x})")
        } else {
          write!(f, "{g}, {l:#06x})")
        }
      }
      (None, Some(val)) => {
        let kind = u16::from_be_bytes([self.kind(), self.sub_kind()]);
        write!(f, "({kind:#06x}, {val:#014x})")
      }
      (None, None) => write!(f, "({:#018x})", u64::from_be_bytes(self.0)),
    }
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlobalAdmin {
  As(u32),
  Ipv4(Ipv4Addr),
}

impl Display for GlobalAdmin {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    match self {
      Self::As(n) => Display::fmt(n, f),
      Self::Ipv4(ip) => Display::fmt(ip, f),
    }
  }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TrafficAction {
  TrafficRateBytes { desc: u16, rate: f32 },
  TrafficRatePackets { desc: u16, rate: f32 },
  TrafficAction { terminal: bool, sample: bool },
  RtRedirect { rt: GlobalAdmin, value: u32 },
  RtRedirectIpv6 { rt: Ipv6Addr, value: u16 },
  TrafficMarking { dscp: u8 },
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv6ExtCommunity {
  pub kind: u8,
  pub sub_kind: u8,
  pub global_admin: Ipv6Addr,
  pub local_admin: u16,
}

impl Ipv6ExtCommunity {
  pub fn new(transitive: bool, sub_kind: u8, global_admin: Ipv6Addr, local_admin: u16) -> Self {
    Self { kind: if transitive { 0 } else { 1 << 6 }, sub_kind, global_admin, local_admin }
  }

  pub fn from_bytes(bytes: [u8; 20]) -> Option<Self> {
    if bytes[0] == 0x00 || bytes[0] == 0x40 {
      Some(Self {
        kind: bytes[0],
        sub_kind: bytes[1],
        global_admin: Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[2..18]).unwrap()),
        local_admin: u16::from_be_bytes(bytes[18..20].try_into().unwrap()),
      })
    } else {
      None
    }
  }

  pub fn iana_authority(self) -> bool {
    self.kind & (1 << 7) != 0
  }
  pub fn is_transitive(self) -> bool {
    self.kind & (1 << 6) == 0
  }
  pub fn kind_struct(self) -> u8 {
    self.kind & 0b111111
  }
}

impl Debug for Ipv6ExtCommunity {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    write!(f, "Ipv6ExtCommunity{self}")
  }
}

impl Display for Ipv6ExtCommunity {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    match [self.kind, self.sub_kind] {
      [0x00, 0x02] => f.write_str("(route-target, ")?,
      [0x00, 0x03] => f.write_str("(route-origin, ")?,
      [0x00, 0x0d] => f.write_str("(rt-redirect-ipv6, ")?,
      bytes => write!(f, "({:#06x}, ", u16::from_be_bytes(bytes))?,
    }
    write!(f, "{}, {:#06x})", self.global_admin, self.local_admin)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_ext_comm() {
    println!("{:?}", ExtCommunity::new_as_specific(true, 3, 207268, 12345));
    println!("{:?}", ExtCommunity::from_bytes((1145141919810000000u64).to_be_bytes()));
    println!(
      "{:?}",
      Ipv6ExtCommunity::new(true, 0x0d, "2a09::".parse().unwrap(), 11451)
    );
  }
}
