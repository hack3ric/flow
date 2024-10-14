use super::error::BgpError;
use crate::net::{IpPrefix, IpPrefixError, IpWithPrefix, IpWithPrefixErrorKind};
use anyhow::anyhow;
use smallvec::{smallvec, SmallVec};
use std::borrow::Borrow;
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt::{self, Debug, Display, Formatter};
use std::io;
use std::marker::PhantomData;
use std::net::IpAddr;
use strum::{EnumDiscriminants, FromRepr};
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Clone, PartialEq, Eq)]
pub struct FlowSpec {
  ipv6: bool,
  inner: BTreeSet<ComponentStore>,
}

impl FlowSpec {
  pub fn new(ipv6: bool) -> Self {
    Self { ipv6, inner: Default::default() }
  }
  pub fn new_v4() -> Self {
    Self::new(false)
  }
  pub fn new_v6() -> Self {
    Self::new(true)
  }

  pub fn insert(&mut self, c: Component) -> Result<(), BgpError> {
    if !c.is_valid(self.ipv6) {
      return Err(anyhow!("invalid component").into());
    }
    if !self.inner.insert(ComponentStore(c)) {
      return Err(anyhow!("duplicate component").into());
    }
    Ok(())
  }

  pub fn with(mut self, c: Component) -> Result<Self, BgpError> {
    self.insert(c)?;
    Ok(self)
  }
  pub fn is_ipv4(&self) -> bool {
    !self.ipv6
  }
  pub fn is_ipv6(&self) -> bool {
    self.ipv6
  }

  pub fn serialize(&self, buf: &mut Vec<u8>) {
    let mut buf2 = Vec::new();
    self.inner.iter().for_each(|ComponentStore(c)| {
      assert!(c.is_valid(self.ipv6)); // TODO: relax this if we have flowspec builder
      c.serialize(&mut buf2);
    });
    let len: u16 = buf2.len().try_into().expect("flowspec length should fit in u16");
    assert!(len < 0xf000);
    if len < 240 {
      buf.push(len.try_into().unwrap());
    } else {
      buf.extend((len | 0xf000).to_be_bytes());
    }
    buf.extend(buf2);
  }

  pub async fn recv<R: AsyncRead + Unpin>(reader: &mut R, ipv6: bool) -> Result<Option<Self>, BgpError> {
    let mut len_bytes = [0; 2];
    if let Ok(n) = reader.read_u8().await {
      len_bytes[0] = n;
    } else {
      return Ok(None);
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
    while let Some(comp) = Component::recv(&mut flow_reader, ipv6).await? {
      if inner.last().map(|x| x.0.kind() >= comp.kind()).unwrap_or(false) {
        return Err(anyhow!("flowspec components must be unique and sorted by type").into());
      }
      if !inner.insert(ComponentStore(comp)) {
        return Err(anyhow!("duplicate component").into());
      }
    }
    Ok(Some(Self { ipv6, inner }))
  }
  pub async fn recv_v4<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Self>, BgpError> {
    Self::recv(reader, false).await
  }
  pub async fn recv_v6<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Self>, BgpError> {
    Self::recv(reader, true).await
  }
}

impl Debug for FlowSpec {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    f.debug_set().entries(self.inner.iter().map(|ComponentStore(c)| c)).finish()
  }
}

impl Display for FlowSpec {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    if let Some(ComponentStore(first)) = self.inner.first() {
      write!(f, "({first})")?;
    } else {
      f.write_str("empty")?;
    }
    for ComponentStore(c) in self.inner.iter().skip(1) {
      write!(f, " && ({c})")?;
    }
    Ok(())
  }
}

#[derive(Debug, Clone)]
struct ComponentStore(Component);

impl PartialEq for ComponentStore {
  fn eq(&self, other: &Self) -> bool {
    self.0.kind() == other.0.kind()
  }
}

impl Eq for ComponentStore {}

impl PartialOrd for ComponentStore {
  fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
    self.0.kind().partial_cmp(&other.0.kind())
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

#[derive(Clone, EnumDiscriminants)]
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

  pub fn serialize(&self, buf: &mut Vec<u8>) {
    buf.push(self.kind() as u8);
    match self {
      Self::DstPrefix(prefix, offset) | Self::SrcPrefix(prefix, offset) => {
        if let IpAddr::V6(v6) = prefix.prefix() {
          let pattern_bytes = (prefix.len() - offset).div_ceil(8);
          buf.extend([prefix.len(), *offset]);
          buf.extend((v6.to_bits() << offset).to_be_bytes().into_iter().take(pattern_bytes.into()));
        } else {
          prefix.serialize(buf);
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
      | Self::FlowLabel(ops) => ops.serialize(buf),
      Self::TcpFlags(ops) | Self::Fragment(ops) => ops.serialize(buf),
    }
  }

  pub async fn recv<R: AsyncRead + Unpin>(reader: &mut R, v6: bool) -> Result<Option<Self>, BgpError> {
    use ComponentKind as CK;

    let Ok(kind) = reader.read_u8().await else {
      return Ok(None);
    };
    let result = match ComponentKind::from_repr(kind) {
      Some(CK::DstPrefix) if !v6 => Self::parse_v4_prefix(Self::DstPrefix, reader).await?,
      Some(CK::SrcPrefix) if !v6 => Self::parse_v4_prefix(Self::SrcPrefix, reader).await?,
      Some(CK::DstPrefix) if v6 => Self::parse_v6_prefix_pattern(Self::DstPrefix, reader).await?,
      Some(CK::SrcPrefix) if v6 => Self::parse_v6_prefix_pattern(Self::SrcPrefix, reader).await?,
      Some(CK::Protocol) => Self::Protocol(Ops::recv(reader).await?),
      Some(CK::Port) => Self::Port(Ops::recv(reader).await?),
      Some(CK::DstPort) => Self::DstPort(Ops::recv(reader).await?),
      Some(CK::SrcPort) => Self::SrcPort(Ops::recv(reader).await?),
      Some(CK::IcmpType) => Self::IcmpType(Ops::recv(reader).await?),
      Some(CK::IcmpCode) => Self::IcmpCode(Ops::recv(reader).await?),
      Some(CK::TcpFlags) => Self::TcpFlags(Ops::recv(reader).await?),
      Some(CK::PacketLen) => Self::PacketLen(Ops::recv(reader).await?),
      Some(CK::Dscp) => Self::Dscp(Ops::recv(reader).await?),
      Some(CK::Fragment) => Self::Fragment(Ops::recv(reader).await?),
      Some(CK::FlowLabel) => Self::FlowLabel(Ops::recv(reader).await?),
      _ => return Err(anyhow!("unsupported flow component kind: {kind}").into()),
    };
    Ok(Some(result))
  }

  fn is_valid(&self, v6: bool) -> bool {
    if v6 {
      self.is_valid_v6()
    } else {
      self.is_valid_v4()
    }
  }

  fn is_valid_v4(&self) -> bool {
    use Component::*;
    match self {
      DstPrefix(prefix, offset) | SrcPrefix(prefix, offset) => prefix.is_ipv4() && *offset == 0,
      Fragment(ops) => ops.0.iter().all(|x| x.value & !0b1111 == 0),
      FlowLabel(_) => false,
      _ => true,
    }
  }

  fn is_valid_v6(&self) -> bool {
    use Component::*;
    match self {
      DstPrefix(prefix, offset) | SrcPrefix(prefix, offset) => prefix.is_ipv6() && *offset < prefix.len(),
      Fragment(ops) => ops.0.iter().all(|x| x.value & !0b1110 == 0),
      _ => true,
    }
  }

  async fn parse_v4_prefix(
    f: fn(IpPrefix, u8) -> Self,
    reader: &mut (impl AsyncRead + Unpin),
  ) -> Result<Self, BgpError> {
    let prefix = IpPrefix::recv_v4(reader)
      .await?
      .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
    Ok(f(prefix, 0))
  }

  async fn parse_v6_prefix_pattern(
    f: fn(IpPrefix, u8) -> Self,
    reader: &mut (impl AsyncRead + Unpin),
  ) -> Result<Self, BgpError> {
    let len = reader.read_u8().await?;
    if len > 128 {
      return Err(IpPrefixError { kind: IpWithPrefixErrorKind::PrefixLenTooLong(len, 128).into(), value: None }.into());
    }
    let offset = reader.read_u8().await?;
    if offset >= len {
      return Err(anyhow!("IPv6 prefix component offset too big").into());
    }
    let mut buf = [0; 16];
    let pattern_bytes = (len - offset).div_ceil(8);
    reader.read_exact(&mut buf[0..pattern_bytes.into()]).await?;
    let pattern = u128::from_be_bytes(buf) >> offset;
    let prefix = IpWithPrefix::new(IpAddr::V6(pattern.into()), len).prefix();
    Ok(f(prefix, offset))
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
      Self::Protocol(ops) => ops.fmt(f, &"protocol"),
      Self::Port(ops) => ops.fmt(f, &"port"),
      Self::DstPort(ops) => ops.fmt(f, &"dst_port"),
      Self::SrcPort(ops) => ops.fmt(f, &"src_port"),
      Self::IcmpType(ops) => ops.fmt(f, &"icmp.type"),
      Self::IcmpCode(ops) => ops.fmt(f, &"icmp.code"),
      Self::TcpFlags(ops) => ops.fmt(f, &"tcp.flags"),
      Self::PacketLen(ops) => ops.fmt(f, &"len"),
      Self::Dscp(ops) => ops.fmt(f, &"dscp"),
      Self::Fragment(ops) => ops.fmt(f, &"frag"),
      Self::FlowLabel(ops) => ops.fmt(f, &"flow_label"),
    }
  }
}

/// Operator sequence with values.
pub struct Ops<K: OpKind>(SmallVec<[Op<K>; 4]>);

impl<K: OpKind> Ops<K> {
  pub fn new(op: Op<K>) -> Self {
    Self(smallvec![op])
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

  pub fn serialize(&self, buf: &mut Vec<u8>) {
    self.0[..self.0.len() - 1].iter().for_each(|x| x.serialize(buf, false));
    self.0.last().unwrap().serialize(buf, true);
  }

  pub async fn recv<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Self> {
    let mut inner = Vec::new();
    loop {
      let (op, eol) = Op::recv(reader).await?;
      inner.push(op);
      if eol {
        break;
      }
    }
    assert!(inner.len() > 0);
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

  fn fmt(&self, f: &mut Formatter, data: &impl Display) -> fmt::Result {
    K::fmt(f, self.0[0].flags, data, self.0[0].value)?;
    if self.0.len() > 1 {
      for op in &self.0[1..] {
        if op.is_and() {
          f.write_str(" && ")?;
        } else {
          f.write_str(" || ")?;
        }
        K::fmt(f, op.flags, data, op.value)?;
      }
    }
    Ok(())
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
    self.fmt(f, &"data")
  }
}

impl<K: OpKind> Clone for Ops<K> {
  fn clone(&self) -> Self {
    Self(self.0.clone())
  }
}

pub struct Op<K: OpKind> {
  flags: u8,
  value: u64,
  _k: PhantomData<K>,
}

impl<K: OpKind> Op<K> {
  const AND: u8 = 0b0100_0000;

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

  fn serialize(self, buf: &mut Vec<u8>, eol: bool) {
    let op_pos = buf.len();
    buf.push(0);
    let len = match self.value {
      0x0..=0xff => 0,
      0x100..=0xffff => 1,
      0x10000..=0xffffffff => 2,
      0x100000000..=0xffffffffffffffff => 3,
    };
    match len {
      0 => buf.push(self.value as u8),
      1 => buf.extend((self.value as u16).to_be_bytes()),
      2 => buf.extend((self.value as u32).to_be_bytes()),
      3 => buf.extend(self.value.to_be_bytes()),
      _ => unreachable!(),
    };
    buf[op_pos] = (self.flags & K::FLAGS_MASK) | (len << 4) | (u8::from(eol) << 7);
  }

  async fn recv<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<(Self, bool)> {
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
    K::fmt(f, self.flags, &"data", self.value)
  }
}

impl<K: OpKind> Clone for Op<K> {
  fn clone(&self) -> Self {
    Self { flags: self.flags.clone(), value: self.value.clone(), _k: PhantomData }
  }
}

impl<K: OpKind> Copy for Op<K> {}

impl<K: OpKind> PartialEq for Op<K> {
  fn eq(&self, other: &Self) -> bool {
    self.flags == other.flags && self.value == other.value
  }
}

impl<K: OpKind> Eq for Op<K> {}

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

  fn fmt(f: &mut Formatter, flags: u8, data: &impl Display, value: u64) -> fmt::Result {
    use NumericFlags::*;
    match NumericFlags::from_repr(flags & NumericFlags::True as u8).unwrap() {
      False => f.write_str("false"),
      Lt => write!(f, "{data} < {value}"),
      Gt => write!(f, "{data} > {value}"),
      Eq => write!(f, "{data} == {value}"),
      Le => write!(f, "{data} <= {value}"),
      Ge => write!(f, "{data} >= {value}"),
      Ne => write!(f, "{data} != {value}"),
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

  fn fmt(f: &mut Formatter, flags: u8, data: &impl Display, value: u64) -> fmt::Result {
    use BitmaskFlags::*;
    match BitmaskFlags::from_repr(flags & (Self::NOT | Self::MATCH)).unwrap() {
      Any => write!(f, "{data} & 0b{value:b} != 0"),
      NotAny => write!(f, "{data} & 0b{value:b} == 0"),
      All => write!(f, "{data} & 0b{value:b} == 0b{value:b}"),
      NotAll => write!(f, "{data} & 0b{value:b} != 0b{value:b}"),
    }
  }
}

pub trait OpKind {
  const FLAGS_MASK: u8;
  fn op(flags: u8, data: u64, value: u64) -> bool;
  fn fmt(f: &mut Formatter, flags: u8, data: &impl Display, value: u64) -> fmt::Result;
}

#[cfg(test)]
mod tests {
  use super::*;
  use test_case::test_case;

  #[tokio::test]
  async fn test_flowspec() -> anyhow::Result<()> {
    use Component::*;
    use ComponentKind as CK;

    let mut f = FlowSpec::new_v6()
      .with(DstPrefix("::1:1234:5678:9800:0/104".parse()?, 63))?
      .with(DstPort(Op::ge(80).and(Op::le(443))))?
      .with(TcpFlags(Op::all(Op::SYN | Op::ACK).into()))?;

    f.insert(Component::SrcPrefixV4("10.0.0.0/8".parse()?))
      .expect_err("IPv4 flowspec component should not be inserted to IPv6 flowspec");

    let mut buf = Vec::new();
    f.serialize(&mut buf);

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
    assert_eq!(f, FlowSpec::recv_v6(&mut &buf[..]).await?.unwrap());

    Ok(())
  }

  const OP_NUM: PhantomData<Numeric> = PhantomData;
  const OP_BIT: PhantomData<Bitmask> = PhantomData;

  #[test_case(OP_NUM, &[0b00000011, 114, 0b01010100, 2, 2, 0b10000001, 1], &[1, 114, 200], &[0, 2, 514]; "n ge 114 AND n lt 514 OR n eq 1")]
  #[test_case(OP_BIT, &[0b10000001, 0b101], &[85, 1365, 65525, 65535], &[0, 1, 2, 114, 514]; "n bitand 0b101 eq 0b101")]
  #[tokio::test]
  async fn test_ops<K: OpKind>(_op: PhantomData<K>, mut seq: &[u8], aye: &[u64], nay: &[u64]) -> anyhow::Result<()> {
    let ops = Ops::<K>::recv(&mut seq).await?;
    aye.iter().for_each(|&n| assert!(ops.op(n), "!ops.op({n})"));
    nay.iter().for_each(|&n| assert!(!ops.op(n), "ops.op({n})"));
    Ok(())
  }
}
