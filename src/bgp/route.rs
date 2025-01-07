use super::flow::Flowspec;
use super::nlri::{NextHop, Nlri, NlriContent};
use crate::kernel::{self, Kernel, KernelAdapter, KernelHandle};
use crate::net::IpPrefix;
use crate::util::{MaybeRc, BOLD, FG_BLUE_BOLD, FG_GREEN_BOLD, RESET};
use either::Either;
use itertools::Itertools;
use log::{warn, Level, LevelFilter};
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::borrow::Cow;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Debug, Display, Formatter};
use std::mem::swap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::rc::Rc;
use strum::{EnumDiscriminants, FromRepr};

/// Route storage for a session.
#[derive(Debug, Serialize, Deserialize)]
pub struct Routes {
  unicast: BTreeMap<IpPrefix, (NextHop, MaybeRc<RouteInfo<'static>>)>,
  flow: BTreeMap<Flowspec, (KernelHandle, MaybeRc<RouteInfo<'static>>)>,
  kernel: KernelAdapter,
}

impl Routes {
  pub fn new(kernel: KernelAdapter) -> Self {
    Self { unicast: BTreeMap::new(), flow: BTreeMap::new(), kernel }
  }

  pub async fn commit(&mut self, nlri: Nlri, info: Rc<RouteInfo<'static>>) {
    match nlri.content {
      NlriContent::Unicast { prefixes, next_hop } => self
        .unicast
        .extend(prefixes.into_iter().map(|p| (p, (next_hop, MaybeRc::Rc(info.clone()))))),
      NlriContent::Flow { specs } => {
        for spec in specs {
          let before = self.flow.range(&spec..).next().map(|(_, (handle, _))| handle);
          let id = match self.kernel.apply(&spec, before, &info).await {
            Ok(id) => id,
            Err(error) => {
              warn!("flowspec {spec} rejected: {error}");
              self.withdraw_spec(spec).await;
              continue;
            }
          };
          match self.flow.entry(spec) {
            Entry::Vacant(e) => {
              e.insert((id, MaybeRc::Rc(info.clone())));
            }
            Entry::Occupied(mut e) => {
              let (id, _) = e.insert((id, MaybeRc::Rc(info.clone())));
              self.kernel.remove(&id).await;
            }
          }
        }
      }
    }
  }

  pub async fn withdraw(&mut self, nlri: Nlri) {
    match nlri.content {
      NlriContent::Unicast { prefixes, .. } => prefixes
        .into_iter()
        .for_each(|p| self.unicast.remove(&p).map(|_| ()).unwrap_or(())),
      NlriContent::Flow { specs } => {
        for s in specs {
          self.withdraw_spec(s).await;
        }
      }
    }
  }

  pub async fn withdraw_all(&mut self) {
    self.unicast.clear();
    let mut flow = BTreeMap::new();
    swap(&mut flow, &mut self.flow);
    for (_, (handle, _)) in flow {
      self.kernel.remove(&handle).await;
    }
  }

  async fn withdraw_spec(&mut self, spec: Flowspec) {
    let Some((handle, _)) = self.flow.remove(&spec) else {
      return;
    };
    self.kernel.remove(&handle).await;
  }

  pub async fn process(&mut self) -> kernel::Result<()> {
    self.kernel.process().await
  }

  pub fn print(&self, verbosity: LevelFilter) {
    fn print_info(info: &RouteInfo) {
      println!("  {BOLD}Origin:{RESET} {}", info.origin);
      if !info.as_path.is_empty() {
        println!("  {BOLD}AS Path:{RESET} {}", info.as_path.iter().format(", "));
      }
      if !info.comm.is_empty() {
        println!("  {BOLD}Communities:{RESET} {}", info.comm.iter().format(", "));
      }
      if !info.ext_comm.is_empty() {
        println!(
          "  {BOLD}Extended Communities:{RESET} {}",
          info.ext_comm.iter().format(", "),
        );
      }
      if !info.ipv6_ext_comm.is_empty() {
        println!(
          "  {BOLD}IPv6 Specific Extended Communities:{RESET} {}",
          info.ipv6_ext_comm.iter().format(", "),
        );
      }
      if !info.large_comm.is_empty() {
        println!(
          "  {BOLD}Large Communities:{RESET} {}",
          info.large_comm.iter().format(", "),
        );
      }
    }

    if verbosity >= Level::Debug {
      for (prefix, (next_hop, info)) in &self.unicast {
        println!("{FG_BLUE_BOLD}Unicast{RESET} {prefix}");
        println!("  {BOLD}Next Hop:{RESET} {next_hop}");
        print_info(info);
        println!();
      }
    }

    for (spec, (index, info)) in &self.flow {
      println!("{FG_GREEN_BOLD}Flowspec{RESET} {spec}");
      if verbosity >= Level::Debug {
        println!("  {BOLD}Kernel Rule ID:{RESET} {index}");
        print!("  {BOLD}Hex Representation:{RESET} ");
        let mut buf = Vec::new();
        spec.write(&mut buf);
        println!("{:02x}", buf.iter().format(""));
      }
      print_info(info);
      println!();
    }
  }

  pub async fn terminate(&mut self) {
    let mut kernel = KernelAdapter::Noop;
    std::mem::swap(&mut kernel, &mut self.kernel);
    kernel.terminate().await;
  }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteInfo<'a> {
  pub origin: Origin,

  /// AS path, stored in reverse for easy prepending.
  pub as_path: SmallVec<[AsSegment; 1]>,

  pub comm: BTreeSet<Community>,
  pub ext_comm: BTreeSet<ExtCommunity>,
  pub ipv6_ext_comm: BTreeSet<Ipv6ExtCommunity>,
  pub large_comm: BTreeSet<LargeCommunity>,

  pub med: Option<u32>,
  pub local_pref: Option<u32>,
  pub atomic_aggregate: bool,
  pub aggregator: Option<(u16, u32)>,

  /// Transitive but unrecognized path attributes.
  pub other_attrs: BTreeMap<u8, Cow<'a, [u8]>>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, FromRepr, Serialize, Deserialize)]
#[repr(u8)]
pub enum Origin {
  Igp = 0,
  Egp = 1,
  Incomplete = 2,
}

impl Display for Origin {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    match self {
      Self::Igp => f.write_str("IGP"),
      Self::Egp => f.write_str("EGP"),
      Self::Incomplete => f.write_str("incomplete"),
    }
  }
}

impl Default for Origin {
  fn default() -> Self {
    Self::Incomplete
  }
}

#[derive(Debug, Clone, EnumDiscriminants, PartialEq, Eq, Serialize, Deserialize)]
#[strum_discriminants(name(AsSegmentKind), derive(FromRepr))]
#[repr(u8)]
pub enum AsSegment {
  Set(BTreeSet<u32>) = 1,
  Sequence(SmallVec<[u32; 4]>) = 2,
  ConfedSequence(SmallVec<[u32; 4]>) = 3,
  ConfedSet(BTreeSet<u32>) = 4,
}

impl AsSegment {
  pub fn kind(&self) -> AsSegmentKind {
    self.into()
  }

  pub fn write(&self, buf: &mut Vec<u8>) {
    buf.extend([self.kind() as u8, self.as_count()]);
    buf.extend(self.iter().flat_map(u32::to_be_bytes));
  }

  pub fn as_count(&self) -> u8 {
    match self {
      Self::Set(set) | Self::ConfedSet(set) => set.len().try_into().unwrap(),
      Self::Sequence(seq) | Self::ConfedSequence(seq) => seq.len().try_into().unwrap(),
    }
  }

  pub fn iter(&self) -> impl Iterator<Item = u32> + '_ {
    match self {
      Self::Set(set) | Self::ConfedSet(set) => Either::Left(set.iter().copied()),
      Self::Sequence(seq) | Self::ConfedSequence(seq) => Either::Right(seq.iter().copied()),
    }
  }

  pub fn bytes_len(&self) -> u16 {
    (self.as_count() * 4 + 2).into()
  }
}

impl Display for AsSegment {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    match self {
      Self::Set(set) => Debug::fmt(set, f),
      Self::Sequence(seq) => Display::fmt(&seq.iter().format(", "), f),
      Self::ConfedSequence(seq) => write!(f, "Confed {seq:?}"),
      Self::ConfedSet(set) => write!(f, "Confed {set:?}"),
    }
  }
}

/// RFC 1997 communities.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Community(pub [u16; 2]);

impl Community {
  pub fn from_bytes(bytes: [u8; 4]) -> Self {
    Self([
      u16::from_be_bytes([bytes[0], bytes[1]]),
      u16::from_be_bytes([bytes[2], bytes[3]]),
    ])
  }
}

impl Debug for Community {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    Display::fmt(self, f)
  }
}

impl Display for Community {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    write!(f, "({}, {})", self.0[0], self.0[1])
  }
}

/// RFC 4360/5668 extended communities.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ExtCommunity(pub [u8; 8]);

impl ExtCommunity {
  pub fn from_bytes(bytes: [u8; 8]) -> Self {
    Self(bytes)
  }

  pub fn new_as(transitive: bool, sub_kind: u8, asn: u32, local_admin: u32) -> Self {
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
    bytes[0] |= 1 << 7;
    if !transitive {
      bytes[0] |= 1 << 6;
    }
    Self(bytes)
  }

  pub fn new_ipv4(transitive: bool, sub_kind: u8, ipv4: Ipv4Addr, local_admin: u16) -> Self {
    let mut bytes = [0; 8];
    bytes[0] = 1 | (1 << 7);
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

  pub fn action(self) -> Option<TrafficFilterAction> {
    use GlobalAdmin::*;
    use TrafficFilterAction::*;
    if !self.iana_authority() || !self.is_transitive() {
      return None;
    }
    let (g, l) = self.admins()?;
    let result = match (g, self.sub_kind()) {
      (As(desc), 0x06) => TrafficRateBytes { desc: desc as u16, rate: f32::from_bits(l) },
      (As(desc), 0x0c) => TrafficRatePackets { desc: desc as u16, rate: f32::from_bits(l) },
      (As(_), 0x07) => TrafficAction { terminal: l & 1 == 0, sample: l & (1 << 1) != 0 },
      (_, 0x08) => RtRedirect { rt: g, value: l },
      (As(_), 0x09) => TrafficMarking { dscp: (l as u8) & 0b111111 },
      (Ipv4(ip), 0x0c) => RedirectToIp { ip: ip.into(), copy: l & 1 != 0 },
      _ => return None,
    };
    Some(result)
  }
}

impl Debug for ExtCommunity {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    Display::fmt(self, f)
  }
}

impl Display for ExtCommunity {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    if let Some(act) = self.action() {
      Display::fmt(&act, f)
    } else if let Some((g, l)) = self.admins() {
      match [self.kind(), self.sub_kind()] {
        [0x00..=0x02, 0x02] => f.write_str("(rt, ")?,
        [0x00..=0x02, 0x03] => f.write_str("(ro, ")?,
        bytes => write!(f, "({:#06x}, ", u16::from_be_bytes(bytes))?,
      }
      if l > u16::MAX.into() {
        write!(f, "{g}, {l:#010x})")
      } else {
        write!(f, "{g}, {l:#06x})")
      }
    } else if let Some(val) = self.opaque_value() {
      let kind = u16::from_be_bytes([self.kind(), self.sub_kind()]);
      write!(f, "({kind:#06x}, {val:#014x})")
    } else {
      write!(f, "({:#018x})", u64::from_be_bytes(self.0))
    }
  }
}

/// RFC 5701 IPv6 address-specific extended communities.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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

  pub fn action(self) -> Option<TrafficFilterAction> {
    use TrafficFilterAction::*;
    let action = match [self.kind, self.sub_kind] {
      [0x00, 0x0c] => RedirectToIp { ip: self.global_admin.into(), copy: self.local_admin & 1 != 0 },
      [0x00, 0x0d] => RtRedirectIpv6 { rt: self.global_admin, value: self.local_admin },
      _ => return None,
    };
    Some(action)
  }
}

impl Debug for Ipv6ExtCommunity {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    write!(f, "Ipv6ExtCommunity{self}")
  }
}

impl Display for Ipv6ExtCommunity {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    if let Some(action) = self.action() {
      Display::fmt(&action, f)
    } else {
      match [self.kind, self.sub_kind] {
        [0x00, 0x02] => f.write_str("(rt, ")?,
        [0x00, 0x03] => f.write_str("(ro, ")?,
        bytes => write!(f, "({:#06x}, ", u16::from_be_bytes(bytes))?,
      }
      write!(f, "{}, {:#06x})", self.global_admin, self.local_admin)
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

#[derive(Debug, Clone, Copy, PartialEq, EnumDiscriminants)]
#[strum_discriminants(name(TrafficFilterActionKind), derive(PartialOrd, Ord))]
pub enum TrafficFilterAction {
  TrafficRateBytes { desc: u16, rate: f32 },
  TrafficRatePackets { desc: u16, rate: f32 },
  TrafficAction { terminal: bool, sample: bool },
  RtRedirect { rt: GlobalAdmin, value: u32 },
  RtRedirectIpv6 { rt: Ipv6Addr, value: u16 },
  TrafficMarking { dscp: u8 },
  RedirectToIp { ip: IpAddr, copy: bool },
}

impl TrafficFilterAction {
  pub fn kind(self) -> TrafficFilterActionKind {
    self.into()
  }

  pub fn into_ext_comm(self) -> Either<ExtCommunity, Ipv6ExtCommunity> {
    use Either::*;
    use TrafficFilterAction::*;
    match self {
      TrafficRateBytes { desc, rate } => Left(ExtCommunity::new_as(true, 0x06, desc.into(), rate.to_bits())),
      TrafficRatePackets { desc, rate } => Left(ExtCommunity::new_as(true, 0x0c, desc.into(), rate.to_bits())),
      TrafficAction { terminal: t, sample: s } => {
        Left(ExtCommunity::new_as(true, 0x07, 0, (!t as u32) | ((s as u32) << 1)))
      }
      RtRedirect { rt: GlobalAdmin::As(rt), value } => Left(ExtCommunity::new_as(true, 0x08, rt, value)),
      RtRedirect { rt: GlobalAdmin::Ipv4(rt), value } => {
        let value = value.try_into().expect("it should fit in u16");
        Left(ExtCommunity::new_ipv4(true, 0x08, rt, value))
      }
      RtRedirectIpv6 { rt, value } => Right(Ipv6ExtCommunity::new(true, 0x0d, rt, value)),
      TrafficMarking { dscp } => Left(ExtCommunity::new_as(true, 0x09, 0, (dscp & 0b111111).into())),
      RedirectToIp { ip: IpAddr::V4(ip), copy } => Left(ExtCommunity::new_ipv4(true, 0x0c, ip, copy.into())),
      RedirectToIp { ip: IpAddr::V6(ip), copy } => Right(Ipv6ExtCommunity::new(true, 0x0c, ip, copy.into())),
    }
  }
}

impl Display for TrafficFilterAction {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    use TrafficFilterAction::*;
    match self {
      TrafficRateBytes { desc, rate } => write!(f, "(traffic-rate-bytes, {desc}, {rate})"),
      TrafficRatePackets { desc, rate } => write!(f, "(traffic-rate-packets, {desc}, {rate})"),
      TrafficAction { terminal, sample } => write!(
        f,
        "(traffic-action{}{})",
        terminal.then_some(", terminal").unwrap_or(""),
        sample.then_some(", sample").unwrap_or(""),
      ),
      RtRedirect { rt, value } => {
        write!(f, "(rt-redirect, {rt}, ")?;
        if *value > u16::MAX.into() {
          write!(f, "{value:#010x})")
        } else {
          write!(f, "{value:#06x})")
        }
      }
      RtRedirectIpv6 { rt, value } => write!(f, "(rt-redirect-ipv6, {rt}, {value:#06x})"),
      TrafficMarking { dscp } => write!(f, "(traffic-marking, {dscp})"),
      RedirectToIp { ip, copy } => write!(f, "(redirect-to-ip, {ip}{})", copy.then_some(", copy").unwrap_or("")),
    }
  }
}

/// RFC 8092 large communities.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LargeCommunity(pub [u32; 3]);

impl LargeCommunity {
  pub fn from_bytes(bytes: [u8; 12]) -> Self {
    Self([
      u32::from_be_bytes(bytes[0..4].try_into().unwrap()),
      u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
      u32::from_be_bytes(bytes[8..12].try_into().unwrap()),
    ])
  }
}

impl Debug for LargeCommunity {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    Display::fmt(self, f)
  }
}

impl Display for LargeCommunity {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    write!(f, "({}, {}, {})", self.0[0], self.0[1], self.0[2])
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_ext_comm() {
    println!("{:?}", ExtCommunity::new_as(true, 3, 207268, 12345));
    println!("{:?}", ExtCommunity::from_bytes((1145141919810000000u64).to_be_bytes()));
    println!(
      "{:?}",
      Ipv6ExtCommunity::new(true, 0x0d, "2a09::".parse().unwrap(), 11451)
    );
  }
}
