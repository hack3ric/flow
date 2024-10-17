use super::flow::FlowSpec;
use super::nlri::{NextHop, Nlri, NlriContent};
use crate::net::IpPrefix;
use crate::util::MaybeRc;
use anstyle::{AnsiColor, Color, Reset, Style};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::{self, Debug, Display, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::rc::Rc;
use strum::FromRepr;

/// Route storage for a session.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Routes {
  pub unicast: BTreeMap<IpPrefix, (NextHop, MaybeRc<RouteInfo<'static>>)>,
  pub flow: BTreeMap<FlowSpec, MaybeRc<RouteInfo<'static>>>,
}

impl Routes {
  pub fn new() -> Self {
    Default::default()
  }

  pub fn commit(&mut self, nlri: Nlri, info: Rc<RouteInfo<'static>>) {
    match nlri.content {
      NlriContent::Unicast { prefixes, next_hop } => self
        .unicast
        .extend(prefixes.into_iter().map(|p| (p, (next_hop, MaybeRc::Rc(info.clone()))))),
      NlriContent::Flow { specs } => {
        self.flow.extend(specs.into_iter().map(|s| (s, MaybeRc::Rc(info.clone()))));
      }
    }
  }

  pub fn withdraw(&mut self, nlri: Nlri) {
    match nlri.content {
      NlriContent::Unicast { prefixes, .. } => {
        for prefix in prefixes {
          self.unicast.remove(&prefix);
        }
      }
      NlriContent::Flow { specs } => {
        for spec in specs {
          self.flow.remove(&spec);
        }
      }
    }
  }

  pub fn withdraw_all(&mut self) {
    self.unicast.retain(|_, _| false);
    self.flow.retain(|_, _| false);
  }

  pub fn print(&self) {
    const FG_GREEN_BOLD: Style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::Green))).bold();
    const BOLD: Style = Style::new().bold();
    const RESET: Reset = Reset;

    fn print_series<'a, I: Iterator<Item = &'a D>, D: Display + 'a>(mut iter: I) {
      let Some(first) = iter.next() else {
        print!("<empty>");
        return;
      };
      print!("{first}");
      iter.for_each(|x| print!(", {x}"));
    }

    fn print_info(info: &RouteInfo) {
      println!("    {BOLD}Origin:{RESET} {}", info.origin);
      if !info.as_path.is_empty() {
        print!("    {BOLD}AS Path:{RESET} ");
        print_series(info.as_path.iter().rev());
        println!();
      }
      if !info.comm.is_empty() {
        print!("    {BOLD}Communities:{RESET} ");
        print_series(info.comm.iter());
        println!();
      }
      if !info.ext_comm.is_empty() {
        print!("    {BOLD}Extended Communities:{RESET} ");
        print_series(info.ext_comm.iter());
        println!();
      }
      if !info.ipv6_ext_comm.is_empty() {
        print!("    {BOLD}IPv6 Specific Extended Communities:{RESET} ");
        print_series(info.ipv6_ext_comm.iter());
        println!();
      }
      if !info.large_comm.is_empty() {
        print!("    {BOLD}Large Communities:{RESET} ");
        print_series(info.large_comm.iter());
        println!();
      }
    }

    for (prefix, (next_hop, info)) in &self.unicast {
      println!("{FG_GREEN_BOLD}Unicast{RESET} {prefix}");
      println!("    {BOLD}Next Hop:{RESET} {next_hop}");
      print_info(info);
      println!();
    }
    for (spec, info) in &self.flow {
      println!("{FG_GREEN_BOLD}Flowspec{RESET} {spec}");
      print_info(info);
      println!();
    }
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteInfo<'a> {
  pub(super) origin: Origin,

  /// AS path, stored in reverse for easy prepending.
  pub(super) as_path: Cow<'a, [u32]>,

  pub(super) comm: HashSet<Community>,
  pub(super) ext_comm: HashSet<ExtCommunity>,
  pub(super) ipv6_ext_comm: HashSet<Ipv6ExtCommunity>,
  pub(super) large_comm: HashSet<LargeCommunity>,

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

/// RFC 1997 communities.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Community([u16; 2]);

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
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

  pub fn traffic_filter_action(self) -> Option<TrafficFilterAction> {
    use GlobalAdmin::*;
    use TrafficFilterAction::*;
    if !self.iana_authority() || !self.is_transitive() {
      return None;
    }
    let Some((g, l)) = self.admins() else {
      return None;
    };
    let result = match (g, self.sub_kind()) {
      (As(desc), 0x06) => TrafficRateBytes { desc: desc as u16, rate: f32::from_bits(l) },
      (As(desc), 0x0c) => TrafficRatePackets { desc: desc as u16, rate: f32::from_bits(l) },
      (As(_), 0x07) => TrafficAction { terminal: l & 1 != 0, sample: l & (1 << 1) != 0 },
      (_, 0x08) => RtRedirect { rt: g, value: l },
      (As(_), 0x09) => TrafficMarking { dscp: (l as u8) & 0b111111 },
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
    if let Some(act) = self.traffic_filter_action() {
      Display::fmt(&act, f)
    } else if let Some((g, l)) = self.admins() {
      match [self.kind(), self.sub_kind()] {
        [0x00 | 0x01 | 0x02, 0x02] => f.write_str("(rt, ")?,
        [0x00 | 0x01 | 0x02, 0x03] => f.write_str("(ro, ")?,
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
pub enum TrafficFilterAction {
  TrafficRateBytes { desc: u16, rate: f32 },
  TrafficRatePackets { desc: u16, rate: f32 },
  TrafficAction { terminal: bool, sample: bool },
  RtRedirect { rt: GlobalAdmin, value: u32 },
  RtRedirectIpv6 { rt: Ipv6Addr, value: u16 },
  TrafficMarking { dscp: u8 },
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
        if *terminal { ", terminal" } else { "" },
        if *sample { ", sample" } else { "" }
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
    }
  }
}

/// RFC 5701 IPv6 address-specific extended communities.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
      [0x00, 0x02] => f.write_str("(rt, ")?,
      [0x00, 0x03] => f.write_str("(ro, ")?,
      [0x00, 0x0d] => f.write_str("(rt-redirect-ipv6, ")?,
      bytes => write!(f, "({:#06x}, ", u16::from_be_bytes(bytes))?,
    }
    write!(f, "{}, {:#06x})", self.global_admin, self.local_admin)
  }
}

/// RFC 8092 large communities.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LargeCommunity([u32; 3]);

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
    println!("{:?}", ExtCommunity::new_as_specific(true, 3, 207268, 12345));
    println!("{:?}", ExtCommunity::from_bytes((1145141919810000000u64).to_be_bytes()));
    println!(
      "{:?}",
      Ipv6ExtCommunity::new(true, 0x0d, "2a09::".parse().unwrap(), 11451)
    );
  }
}
