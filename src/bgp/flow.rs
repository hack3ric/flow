use super::Result;
use crate::net::{Afi, IpPrefix, IpPrefixError, IpWithPrefix, IpWithPrefixErrorKind};
use serde::{Deserialize, Serialize};
use smallvec::{smallvec, SmallVec};
use std::borrow::Borrow;
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt::{self, Debug, Display, Formatter, Write};
use std::hash::{Hash, Hasher};
use std::io;
use std::io::ErrorKind::UnexpectedEof;
use std::marker::PhantomData;
use std::net::IpAddr;
use strum::{EnumDiscriminants, FromRepr};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Clone, Serialize, Deserialize)]
pub struct Flowspec {
  afi: Afi,
  inner: BTreeSet<ComponentStore>,
}

impl Flowspec {
  pub fn new(afi: Afi) -> Self {
    Self { afi, inner: Default::default() }
  }
  pub fn new_v4() -> Self {
    Self::new(Afi::Ipv4)
  }
  pub fn new_v6() -> Self {
    Self::new(Afi::Ipv6)
  }

  pub fn insert(&mut self, c: Component) -> Result<(), FlowError> {
    if !c.is_valid(self.afi) {
      return Err(FlowError::Invalid);
    }
    let kind = c.kind();
    if !self.inner.insert(ComponentStore(c)) {
      return Err(FlowError::Duplicate(kind));
    }
    Ok(())
  }

  pub fn with(mut self, c: Component) -> Result<Self, FlowError> {
    self.insert(c)?;
    Ok(self)
  }

  pub fn afi(&self) -> Afi {
    self.afi
  }
  pub fn is_ipv4(&self) -> bool {
    self.afi == Afi::Ipv4
  }
  pub fn is_ipv6(&self) -> bool {
    self.afi == Afi::Ipv6
  }

  pub fn write(&self, buf: &mut Vec<u8>) {
    let mut buf2 = Vec::new();
    self.inner.iter().for_each(|c| c.0.write(&mut buf2));
    let len: u16 = buf2.len().try_into().expect("flowspec length should fit in u16");
    assert!(len < 0xf000);
    if len < 240 {
      buf.push(len.try_into().unwrap());
    } else if len < 4096 {
      buf.extend((len | 0xf000).to_be_bytes());
    } else {
      panic!("flowspec length exceeds 0xfff");
    }
    buf.extend(buf2);
  }

  pub async fn read<R: AsyncRead + Unpin>(reader: &mut R, afi: Afi) -> Result<Option<Self>> {
    let mut len_bytes = [0; 2];
    match reader.read_u8().await {
      Ok(n) => len_bytes[0] = n,
      Err(error) if error.kind() == UnexpectedEof => return Ok(None),
      Err(error) => return Err(error.into()),
    }
    let len = if len_bytes[0] & 0xf0 == 0xf0 {
      len_bytes[0] &= 0x0f;
      len_bytes[1] = reader.read_u8().await?;
      u16::from_be_bytes(len_bytes)
    } else {
      len_bytes[0].into()
    };
    let mut flow_reader = reader.take(len.into());
    let mut inner = BTreeSet::<ComponentStore>::new();
    while let Some(comp) = Component::read(&mut flow_reader, afi).await? {
      if inner.last().map(|x| x.0.kind() >= comp.kind()).unwrap_or(false) {
        return Err(FlowError::Unsorted.into()); // also probably duplicate
      }
      if !comp.is_valid(afi) {
        return Err(FlowError::Invalid.into());
      }
      let kind = comp.kind();
      if !inner.insert(ComponentStore(comp)) {
        return Err(FlowError::Duplicate(kind).into());
      }
    }
    Ok(Some(Self { afi, inner }))
  }
  pub async fn read_v4<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Self>> {
    Self::read(reader, Afi::Ipv4).await
  }
  pub async fn read_v6<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Self>> {
    Self::read(reader, Afi::Ipv6).await
  }

  pub fn components(&self) -> impl Iterator<Item = &Component> {
    self.inner.iter().map(|c| &c.0)
  }

  pub fn component_set(&self) -> &BTreeSet<ComponentStore> {
    &self.inner
  }
}

impl Debug for Flowspec {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    Display::fmt(self, f)
  }
}

impl Display for Flowspec {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    match self.afi {
      Afi::Ipv4 => f.write_str("flow4 { ")?,
      Afi::Ipv6 => f.write_str("flow6 { ")?,
    }
    if let Some(ComponentStore(first)) = self.inner.first() {
      write!(f, "{first}")?;
    } else {
      f.write_str("<empty>")?;
    }
    for ComponentStore(c) in self.inner.iter().skip(1) {
      write!(f, "; {c}")?;
    }
    f.write_str(" }")
  }
}

impl PartialEq for Flowspec {
  fn eq(&self, other: &Self) -> bool {
    // ComponentStore's PartialEq only compares kind, so manually implement instead
    self.afi == other.afi
      && self.inner.len() == other.inner.len()
      && self.inner.iter().zip(other.inner.iter()).all(|(a, b)| a.0 == b.0)
  }
}

impl Eq for Flowspec {}

impl PartialOrd for Flowspec {
  fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
    Some(self.cmp(other))
  }
}

impl Ord for Flowspec {
  fn cmp(&self, other: &Self) -> Ordering {
    match self.afi.cmp(&other.afi) {
      Ordering::Equal => {}
      ord => return ord,
    }
    self.inner.iter().map(|x| &x.0).cmp(other.inner.iter().map(|x| &x.0))
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentStore(pub Component);

impl PartialEq for ComponentStore {
  fn eq(&self, other: &Self) -> bool {
    self.0.kind() == other.0.kind()
  }
}

impl Eq for ComponentStore {}

impl PartialOrd for ComponentStore {
  fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
    Some(self.cmp(other))
  }
}

impl Ord for ComponentStore {
  fn cmp(&self, other: &Self) -> Ordering {
    self.0.kind().cmp(&other.0.kind())
  }
}

impl Borrow<ComponentKind> for ComponentStore {
  fn borrow(&self) -> &ComponentKind {
    use Component::*;
    use ComponentKind as CK;
    match self.0 {
      DstPrefix(..) => &CK::DstPrefix,
      SrcPrefix(..) => &CK::SrcPrefix,
      Protocol(..) => &CK::Protocol,
      Port(..) => &CK::Port,
      DstPort(..) => &CK::DstPort,
      SrcPort(..) => &CK::SrcPort,
      IcmpType(..) => &CK::IcmpType,
      IcmpCode(..) => &CK::IcmpCode,
      TcpFlags(..) => &CK::TcpFlags,
      PacketLen(..) => &CK::PacketLen,
      Dscp(..) => &CK::Dscp,
      Fragment(..) => &CK::Fragment,
      FlowLabel(..) => &CK::FlowLabel,
    }
  }
}

#[derive(Clone, PartialEq, Eq, Hash, EnumDiscriminants, Serialize, Deserialize)]
#[strum_discriminants(name(ComponentKind), derive(FromRepr, PartialOrd, Ord))]
#[repr(u8)]
pub enum Component {
  DstPrefix(IpPrefix, u8) = 1,
  SrcPrefix(IpPrefix, u8) = 2,
  Protocol(Ops<Numeric>) = 3,
  Port(Ops<Numeric>) = 4,
  DstPort(Ops<Numeric>) = 5,
  SrcPort(Ops<Numeric>) = 6,
  IcmpType(Ops<Numeric>) = 7,
  IcmpCode(Ops<Numeric>) = 8,
  TcpFlags(Ops<Bitmask>) = 9,
  PacketLen(Ops<Numeric>) = 10,
  Dscp(Ops<Numeric>) = 11,
  Fragment(Ops<Bitmask>) = 12,
  FlowLabel(Ops<Numeric>) = 13,
}

impl Component {
  #[allow(non_snake_case)]
  pub fn DstPrefixV4(p: IpPrefix) -> Self {
    assert!(p.is_ipv4());
    Self::DstPrefix(p, 0)
  }

  #[allow(non_snake_case)]
  pub fn SrcPrefixV4(p: IpPrefix) -> Self {
    assert!(p.is_ipv4());
    Self::SrcPrefix(p, 0)
  }

  pub fn kind(&self) -> ComponentKind {
    self.into()
  }

  pub fn write(&self, buf: &mut Vec<u8>) {
    buf.push(self.kind() as u8);
    match self {
      Self::DstPrefix(prefix, offset) | Self::SrcPrefix(prefix, offset) => {
        if let IpAddr::V6(v6) = prefix.prefix() {
          let pattern_bytes = (prefix.len() - offset).div_ceil(8);
          buf.extend([prefix.len(), *offset]);
          buf.extend((v6.to_bits() << offset).to_be_bytes().into_iter().take(pattern_bytes.into()));
        } else {
          prefix.write(buf);
        }
      }
      Self::Protocol(ops)
      | Self::Port(ops)
      | Self::DstPort(ops)
      | Self::SrcPort(ops)
      | Self::IcmpType(ops)
      | Self::IcmpCode(ops)
      | Self::PacketLen(ops)
      | Self::Dscp(ops)
      | Self::FlowLabel(ops) => ops.write(buf),
      Self::TcpFlags(ops) | Self::Fragment(ops) => ops.write(buf),
    }
  }

  pub async fn read<R: AsyncRead + Unpin>(reader: &mut R, afi: Afi) -> Result<Option<Self>> {
    use ComponentKind as CK;

    let kind = match reader.read_u8().await {
      Ok(kind) => kind,
      Err(error) if error.kind() == UnexpectedEof => return Ok(None),
      Err(error) => return Err(error.into()),
    };
    let result = match ComponentKind::from_repr(kind) {
      Some(CK::DstPrefix) if afi == Afi::Ipv4 => Self::parse_v4_prefix(Self::DstPrefix, reader).await?,
      Some(CK::SrcPrefix) if afi == Afi::Ipv4 => Self::parse_v4_prefix(Self::SrcPrefix, reader).await?,
      Some(CK::DstPrefix) if afi == Afi::Ipv6 => Self::parse_v6_prefix_pattern(Self::DstPrefix, reader).await?,
      Some(CK::SrcPrefix) if afi == Afi::Ipv6 => Self::parse_v6_prefix_pattern(Self::SrcPrefix, reader).await?,
      Some(CK::Protocol) => Self::Protocol(Ops::read(reader).await?),
      Some(CK::Port) => Self::Port(Ops::read(reader).await?),
      Some(CK::DstPort) => Self::DstPort(Ops::read(reader).await?),
      Some(CK::SrcPort) => Self::SrcPort(Ops::read(reader).await?),
      Some(CK::IcmpType) => Self::IcmpType(Ops::read(reader).await?),
      Some(CK::IcmpCode) => Self::IcmpCode(Ops::read(reader).await?),
      Some(CK::TcpFlags) => Self::TcpFlags(Ops::read(reader).await?),
      Some(CK::PacketLen) => Self::PacketLen(Ops::read(reader).await?),
      Some(CK::Dscp) => Self::Dscp(Ops::read(reader).await?),
      Some(CK::Fragment) => Self::Fragment(Ops::read(reader).await?),
      Some(CK::FlowLabel) => Self::FlowLabel(Ops::read(reader).await?),
      _ => return Err(FlowError::UnsupportedKind(kind).into()),
    };
    Ok(Some(result))
  }

  pub fn is_valid(&self, afi: Afi) -> bool {
    match afi {
      Afi::Ipv4 => self.is_valid_v4(),
      Afi::Ipv6 => self.is_valid_v6(),
    }
  }

  pub fn is_valid_v4(&self) -> bool {
    use Component::*;
    match self {
      DstPrefix(prefix, offset) | SrcPrefix(prefix, offset) => prefix.is_ipv4() && *offset == 0,
      Fragment(ops) => ops.0.iter().all(|x| x.value & !0b1111 == 0),
      FlowLabel(_) => false,
      _ => true,
    }
  }

  pub fn is_valid_v6(&self) -> bool {
    use Component::*;
    match self {
      DstPrefix(prefix, offset) | SrcPrefix(prefix, offset) => prefix.is_ipv6() && *offset < prefix.len(),
      Fragment(ops) => ops.0.iter().all(|x| x.value & !0b1110 == 0),
      _ => true,
    }
  }

  async fn parse_v4_prefix(f: fn(IpPrefix, u8) -> Self, reader: &mut (impl AsyncRead + Unpin)) -> Result<Self> {
    let (prefix, _) = IpPrefix::read_v4(reader).await?.ok_or_else(|| io::Error::from(UnexpectedEof))?;
    Ok(f(prefix, 0))
  }

  async fn parse_v6_prefix_pattern(f: fn(IpPrefix, u8) -> Self, reader: &mut (impl AsyncRead + Unpin)) -> Result<Self> {
    let len = reader.read_u8().await?;
    if len > 128 {
      return Err(IpPrefixError { kind: IpWithPrefixErrorKind::PrefixLenTooLong(len, 128).into(), value: None }.into());
    }
    let offset = reader.read_u8().await?;
    if offset >= len {
      return Err(FlowError::PrefixOffsetTooBig(offset, len).into());
    }
    let mut buf = [0; 16];
    let pattern_bytes = (len - offset).div_ceil(8);
    reader.read_exact(&mut buf[0..pattern_bytes.into()]).await?;
    let pattern = u128::from_be_bytes(buf) >> offset;
    let prefix = IpWithPrefix::new(IpAddr::V6(pattern.into()), len).prefix();
    Ok(f(prefix, offset))
  }

  fn prefix_offset(&self) -> Option<(IpPrefix, u8)> {
    use Component::*;
    match self {
      DstPrefix(p, o) | SrcPrefix(p, o) => Some((*p, *o)),
      _ => None,
    }
  }

  fn numeric_ops(&self) -> Option<&Ops<Numeric>> {
    use Component::*;
    match self {
      Protocol(ops) | Port(ops) | DstPort(ops) | SrcPort(ops) | IcmpType(ops) | IcmpCode(ops) | PacketLen(ops)
      | Dscp(ops) | FlowLabel(ops) => Some(ops),
      _ => None,
    }
  }

  fn bitmask_ops(&self) -> Option<&Ops<Bitmask>> {
    use Component::*;
    match self {
      TcpFlags(ops) | Fragment(ops) => Some(ops),
      _ => None,
    }
  }
}

impl Debug for Component {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    write!(f, "Component({self})")
  }
}

impl Display for Component {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    match self {
      Self::DstPrefix(pat, off) if pat.is_ipv6() && *off != 0 => {
        write!(f, "dst_ip in {}/{}-{}", pat.prefix(), off, pat.len())
      }
      Self::DstPrefix(pat, _) => write!(f, "dst_ip in {pat}"),
      Self::SrcPrefix(pat, off) if pat.is_ipv6() && *off != 0 => {
        write!(f, "src_ip in {}/{}-{}", pat.prefix(), off, pat.len())
      }
      Self::SrcPrefix(pat, _) => write!(f, "src_ip in {pat}"),
      Self::Protocol(ops) => write!(f, "protocol {ops}"),
      Self::Port(ops) => write!(f, "port {ops}"),
      Self::DstPort(ops) => write!(f, "dst_port {ops}"),
      Self::SrcPort(ops) => write!(f, "src_port {ops}"),
      Self::IcmpType(ops) => write!(f, "icmp.type {ops}"),
      Self::IcmpCode(ops) => write!(f, "icmp.code {ops}"),
      Self::TcpFlags(ops) => write!(f, "tcp.flags {ops}"),
      Self::PacketLen(ops) => write!(f, "len {ops}"),
      Self::Dscp(ops) => write!(f, "dscp {ops}"),
      Self::Fragment(ops) => write!(f, "frag {ops}"),
      Self::FlowLabel(ops) => write!(f, "flow_label {ops}"),
    }
  }
}

impl PartialOrd for Component {
  fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
    Some(self.cmp(other))
  }
}

impl Ord for Component {
  fn cmp(&self, other: &Self) -> Ordering {
    match self.kind().cmp(&other.kind()) {
      Ordering::Equal => {}
      ord => return ord,
    }
    if let (Some((ip1, off1)), Some((ip2, off2))) = (self.prefix_offset(), other.prefix_offset()) {
      match off1.cmp(&off2) {
        Ordering::Equal => ip1.cmp(&ip2),
        ord => ord,
      }
    } else if let (Some(ops1), Some(ops2)) = (self.numeric_ops(), other.numeric_ops()) {
      ops1.cmp(ops2)
    } else if let (Some(ops1), Some(ops2)) = (self.bitmask_ops(), other.bitmask_ops()) {
      ops1.cmp(ops2)
    } else {
      unreachable!()
    }
  }
}

/// Operator sequence with values.
#[derive(Serialize, Deserialize)]
pub struct Ops<K: OpKind>(pub SmallVec<[Op<K>; 4]>);

impl<K: OpKind> Ops<K> {
  pub fn new(op: Op<K>) -> Self {
    Self(smallvec![op.make_or()])
  }

  pub fn with(mut self, op: Op<K>) -> Self {
    self.0.push(op);
    self
  }
  pub fn and(self, op: Op<K>) -> Self {
    self.with(op.make_and())
  }
  pub fn or(self, op: Op<K>) -> Self {
    self.with(op.make_or())
  }

  pub fn write(&self, buf: &mut Vec<u8>) {
    self.0[..self.0.len() - 1].iter().for_each(|x| x.write(buf, false));
    self.0.last().unwrap().write(buf, true);
  }

  pub async fn read<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Self> {
    let mut inner = Vec::new();
    let mut first = true;
    loop {
      let (mut op, eol) = Op::read(reader).await?;
      if first {
        op = op.make_or();
      }
      inner.push(op);
      if eol {
        break;
      }
      first = false;
    }
    assert!(!inner.is_empty());
    inner[0].flags &= 0b1011_1111; // make sure first is always OR
    Ok(Self(inner.into()))
  }

  pub fn op(&self, data: u64) -> bool {
    let mut result = false;
    for op in &self.0 {
      if op.is_and() {
        result &= op.op(data);
      } else if result {
        return true;
      } else {
        result |= op.op(data);
      }
    }
    result
  }
}

impl<K: OpKind> From<Op<K>> for Ops<K> {
  fn from(op: Op<K>) -> Self {
    Self::new(op)
  }
}

impl<K: OpKind> Debug for Ops<K> {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    write!(f, "Ops({self})")
  }
}

impl<K: OpKind> Display for Ops<K> {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    if self.0.len() > 1 {
      f.write_char('(')?;
    }
    K::fmt(f, self.0[0].flags, self.0[0].value)?;
    if self.0.len() > 1 {
      for op in &self.0[1..] {
        if op.is_and() {
          f.write_str(" && ")?;
        } else {
          f.write_str(" || ")?;
        }
        K::fmt(f, op.flags, op.value)?;
      }
    }
    if self.0.len() > 1 {
      f.write_char(')')?;
    }
    Ok(())
  }
}

impl<K: OpKind> Clone for Ops<K> {
  fn clone(&self) -> Self {
    Self(self.0.clone())
  }
}

impl<K: OpKind> PartialEq for Ops<K> {
  fn eq(&self, other: &Self) -> bool {
    self.0 == other.0
  }
}

impl<K: OpKind> Eq for Ops<K> {}

impl<K: OpKind> PartialOrd for Ops<K> {
  fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
    Some(self.cmp(other))
  }
}

impl<K: OpKind> Ord for Ops<K> {
  fn cmp(&self, other: &Self) -> Ordering {
    let mut self_buf = Vec::new();
    let mut other_buf = Vec::new();
    self.write(&mut self_buf);
    other.write(&mut other_buf);
    self_buf.cmp(&other_buf)
  }
}

impl<K: OpKind> Hash for Ops<K> {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.0.hash(state);
  }
}

#[derive(Serialize, Deserialize)]
pub struct Op<K: OpKind> {
  pub flags: u8,
  pub value: u64,
  pub _k: PhantomData<K>,
}

impl<K: OpKind> Op<K> {
  pub const AND: u8 = 0b0100_0000;

  pub fn op(self, data: u64) -> bool {
    K::op(self.flags, data, self.value)
  }

  pub fn is_and(self) -> bool {
    self.flags & Self::AND != 0
  }
  pub fn is_or(self) -> bool {
    !self.is_and()
  }
  pub fn make_and(mut self) -> Self {
    self.flags |= Self::AND;
    self
  }
  pub fn make_or(mut self) -> Self {
    self.flags &= !Self::AND;
    self
  }
  pub fn and(self, op: Self) -> Ops<K> {
    Ops::new(self).and(op)
  }
  pub fn or(self, op: Self) -> Ops<K> {
    Ops::new(self).or(op)
  }

  fn write(self, buf: &mut Vec<u8>, eol: bool) {
    let op_pos = buf.len();
    buf.push(0);
    let len = match self.value {
      0x0..=0xff => 0,
      0x100..=0xffff => 1,
      0x10000..=0xffffffff => 2,
      0x100000000..=0xffffffffffffffff => 3,
    };
    match len {
      0 => buf.push(self.value as _),
      1 => buf.extend(u16::to_be_bytes(self.value as _)),
      2 => buf.extend(u32::to_be_bytes(self.value as _)),
      3 => buf.extend(u64::to_be_bytes(self.value)),
      _ => unreachable!(),
    };
    buf[op_pos] = (self.flags & K::FLAGS_MASK) | (len << 4) | (u8::from(eol) << 7);
  }

  async fn read<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<(Self, bool)> {
    let flags = reader.read_u8().await?;
    let len = (flags & 0b0011_0000) >> 4;
    let value = match len {
      0 => reader.read_u8().await?.into(),
      1 => reader.read_u16().await?.into(),
      2 => reader.read_u32().await?.into(),
      3 => reader.read_u64().await?,
      _ => unreachable!(),
    };
    let eol = flags & 0b1000_0000 != 0;
    let flags = flags & K::FLAGS_MASK;
    let _k = PhantomData;
    Ok((Self { flags, value, _k }, eol))
  }
}

impl Op<Numeric> {
  pub fn num(flags: NumericFlags, value: u64) -> Self {
    Self { flags: flags as u8, value, _k: PhantomData }
  }
  pub fn lt(value: u64) -> Self {
    Self::num(NumericFlags::Lt, value)
  }
  pub fn gt(value: u64) -> Self {
    Self::num(NumericFlags::Gt, value)
  }
  pub fn eq(value: u64) -> Self {
    Self::num(NumericFlags::Eq, value)
  }
  pub fn le(value: u64) -> Self {
    Self::num(NumericFlags::Le, value)
  }
  pub fn ge(value: u64) -> Self {
    Self::num(NumericFlags::Ge, value)
  }
  pub fn ne(value: u64) -> Self {
    Self::num(NumericFlags::Ne, value)
  }
}

impl Op<Bitmask> {
  pub const DONT_FRAG: u64 = 1;
  pub const IS_FRAG: u64 = 1 << 1;
  pub const FIRST_FRAG: u64 = 1 << 2;
  pub const LAST_FRAG: u64 = 1 << 3;

  pub const FIN: u64 = 1;
  pub const SYN: u64 = 1 << 1;
  pub const RST: u64 = 1 << 2;
  pub const PSH: u64 = 1 << 3;
  pub const ACK: u64 = 1 << 4;
  pub const URG: u64 = 1 << 5;
  pub const ECE: u64 = 1 << 6;
  pub const CWR: u64 = 1 << 7;

  pub fn bit(flags: BitmaskFlags, value: u64) -> Self {
    Self { flags: flags as u8, value, _k: PhantomData }
  }
  pub fn any(value: u64) -> Self {
    Self::bit(BitmaskFlags::Any, value)
  }
  pub fn not_any(value: u64) -> Self {
    Self::bit(BitmaskFlags::NotAny, value)
  }
  pub fn all(value: u64) -> Self {
    Self::bit(BitmaskFlags::Any, value)
  }
  pub fn not_all(value: u64) -> Self {
    Self::bit(BitmaskFlags::NotAll, value)
  }
}

impl<K: OpKind> Debug for Op<K> {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    write!(f, "Op({self})")
  }
}

impl<K: OpKind> Display for Op<K> {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    if self.is_and() {
      f.write_str("&& ")?;
    } else {
      f.write_str("|| ")?;
    }
    K::fmt(f, self.flags, self.value)
  }
}

impl<K: OpKind> Clone for Op<K> {
  fn clone(&self) -> Self {
    *self
  }
}

impl<K: OpKind> Copy for Op<K> {}

impl<K: OpKind> PartialEq for Op<K> {
  fn eq(&self, other: &Self) -> bool {
    self.flags == other.flags && self.value == other.value
  }
}

impl<K: OpKind> Eq for Op<K> {}

impl<K: OpKind> Hash for Op<K> {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.flags.hash(state);
    self.value.hash(state);
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromRepr)]
#[repr(u8)]
pub enum NumericFlags {
  False = 0b000,
  Lt = 0b100,
  Gt = 0b010,
  Eq = 0b001,
  Le = 0b101,
  Ge = 0b011,
  Ne = 0b110,
  True = 0b111,
}

#[derive(Serialize, Deserialize)]
pub enum Numeric {}

impl OpKind for Numeric {
  const FLAGS_MASK: u8 = 0b0100_0111;

  fn op(flags: u8, data: u64, value: u64) -> bool {
    let mut result = false;
    result |= flags & 0b100 != 0 && data < value;
    result |= flags & 0b010 != 0 && data > value;
    result |= flags & 0b001 != 0 && data == value;
    result
  }

  fn fmt(f: &mut Formatter, flags: u8, value: u64) -> fmt::Result {
    use NumericFlags::*;
    match NumericFlags::from_repr(flags & NumericFlags::True as u8).unwrap() {
      False => f.write_str("false"),
      Lt => write!(f, "<{value}"),
      Gt => write!(f, ">{value}"),
      Eq => write!(f, "={value}"),
      Le => write!(f, "<={value}"),
      Ge => write!(f, ">={value}"),
      Ne => write!(f, "!={value}"),
      True => f.write_str("true"),
    }
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromRepr)]
#[repr(u8)]
pub enum BitmaskFlags {
  Any = 0b00,
  NotAny = 0b10,
  All = 0b01,
  NotAll = 0b11,
}

#[derive(Serialize, Deserialize)]
pub enum Bitmask {}

impl Bitmask {
  const NOT: u8 = 0b10;
  const MATCH: u8 = 0b01;
}

impl OpKind for Bitmask {
  const FLAGS_MASK: u8 = 0b0100_0011;

  fn op(flags: u8, d: u64, v: u64) -> bool {
    let result = if flags & Self::MATCH == 0 {
      d & v != 0
    } else {
      d & v == v
    };
    if flags & Self::NOT == 0 {
      result
    } else {
      !result
    }
  }

  fn fmt(f: &mut Formatter, flags: u8, value: u64) -> fmt::Result {
    use BitmaskFlags::*;
    match BitmaskFlags::from_repr(flags & (Self::NOT | Self::MATCH)).unwrap() {
      Any => write!(f, "<0b{value:b}"),
      NotAny => write!(f, ">0b{value:b}"),
      All => write!(f, "=0b{value:b}"),
      NotAll => write!(f, "!=0b{value:b}"),
    }
  }
}

pub trait OpKind {
  const FLAGS_MASK: u8;
  fn op(flags: u8, data: u64, value: u64) -> bool;
  fn fmt(f: &mut Formatter, flags: u8, value: u64) -> fmt::Result;
}

#[derive(Debug, Error)]
pub enum FlowError {
  #[error("invalid component")]
  Invalid,
  #[error("duplicate component {0:?}")]
  Duplicate(ComponentKind),
  #[error("components are not sorted")]
  Unsorted,
  #[error("unsupported component kind {0}")]
  UnsupportedKind(u8),
  #[error("IPv6 prefix component offset too big: {0} >= {1}")]
  PrefixOffsetTooBig(u8, u8),
}

#[cfg(test)]
mod tests {
  use super::*;
  use test_case::test_case;

  #[tokio::test]
  async fn test_flowspec() -> anyhow::Result<()> {
    use Component::*;
    use ComponentKind as CK;

    let mut f = Flowspec::new_v6()
      .with(DstPrefix("::1:1234:5678:9800:0/104".parse()?, 63))?
      .with(DstPort(Op::ge(80).and(Op::le(443))))?
      .with(TcpFlags(Op::all(Op::SYN | Op::ACK).into()))?;

    f.insert(Component::SrcPrefixV4("10.0.0.0/8".parse()?))
      .expect_err("IPv4 flowspec component should not be inserted to IPv6 flowspec");

    let mut buf = Vec::new();
    f.write(&mut buf);

    #[rustfmt::skip]
    let buf_expected = [
      18,
      CK::DstPrefix as u8, 0x68, 0x3f, 0x89, 0x1a, 0x2b, 0x3c, 0x4c, 0x00,
      CK::DstPort as u8, 0x03, 0x50, 0xd5, 0x01, 0xbb,
      CK::TcpFlags as u8, 0x80, (Op::SYN | Op::ACK).try_into().unwrap(),
    ];

    println!("{f}");
    println!("{buf:02x?}");
    assert_eq!(buf, buf_expected);
    assert_eq!(f, Flowspec::read_v6(&mut &buf[..]).await?.unwrap());

    Ok(())
  }

  const OP_NUM: PhantomData<Numeric> = PhantomData;
  const OP_BIT: PhantomData<Bitmask> = PhantomData;

  #[test_case(OP_NUM, &[0b00000011, 114, 0b01010100, 2, 2, 0b10000001, 1], &[1, 114, 200], &[0, 2, 514]; "n ge 114 AND n lt 514 OR n eq 1")]
  #[test_case(OP_BIT, &[0b10000001, 0b101], &[85, 1365, 65525, 65535], &[0, 1, 2, 114, 514]; "n bitand 0b101 eq 0b101")]
  #[tokio::test]
  async fn test_ops<K: OpKind>(_op: PhantomData<K>, mut seq: &[u8], aye: &[u64], nay: &[u64]) -> anyhow::Result<()> {
    let ops = Ops::<K>::read(&mut seq).await?;
    aye.iter().for_each(|&n| assert!(ops.op(n), "!ops.op({n})"));
    nay.iter().for_each(|&n| assert!(!ops.op(n), "ops.op({n})"));
    Ok(())
  }
}
