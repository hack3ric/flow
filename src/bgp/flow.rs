use super::error::BgpError;
use crate::net::{IpPrefix, IpPrefixError, IpWithPrefix, IpWithPrefixErrorKind};
use anyhow::anyhow;
use smallvec::SmallVec;
use std::borrow::Borrow;
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt::{self, Debug, Display, Formatter};
use std::io;
use std::marker::PhantomData;
use std::net::IpAddr;
use strum::{EnumDiscriminants, FromRepr};
use tokio::io::{AsyncRead, AsyncReadExt};

/// Operator sequence with values.
pub struct Ops<K: OpKind>(SmallVec<[Op<K>; 4]>);

pub type NumericOps = Ops<NumericOp>;
pub type BitmaskOps = Ops<BitmaskOp>;

impl<K: OpKind> Ops<K> {
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
      if op.and() {
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
        if op.and() {
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

  fn op(self, data: u64) -> bool {
    K::op(self.flags, data, self.value)
  }

  fn and(self) -> bool {
    self.flags & 0b0100_0000 != 0
  }
}

impl<K: OpKind> Debug for Op<K> {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    write!(f, "Op({self})")
  }
}

impl<K: OpKind> Display for Op<K> {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    if self.and() {
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

pub enum NumericOp {}

impl NumericOp {
  const FALSE: u8 = 0b000;
  const LT: u8 = 0b100;
  const GT: u8 = 0b010;
  const EQ: u8 = 0b001;
  const LE: u8 = Self::LT | Self::EQ;
  const GE: u8 = Self::GT | Self::EQ;
  const NE: u8 = Self::LT | Self::GT;
  const TRUE: u8 = Self::LT | Self::GT | Self::EQ;
}

impl OpKind for NumericOp {
  const FLAGS_MASK: u8 = 0b0100_0111;

  fn op(flags: u8, data: u64, value: u64) -> bool {
    let mut result = false;
    result |= flags & 0b100 != 0 && data < value;
    result |= flags & 0b010 != 0 && data > value;
    result |= flags & 0b001 != 0 && data == value;
    result
  }

  fn fmt(f: &mut Formatter, flags: u8, data: &impl Display, value: u64) -> fmt::Result {
    match flags & Self::TRUE {
      Self::FALSE => f.write_str("false"),
      Self::LT => write!(f, "{data} < {value}"),
      Self::GT => write!(f, "{data} > {value}"),
      Self::EQ => write!(f, "{data} == {value}"),
      Self::LE => write!(f, "{data} <= {value}"),
      Self::GE => write!(f, "{data} >= {value}"),
      Self::NE => write!(f, "{data} != {value}"),
      Self::TRUE => f.write_str("true"),
      _ => unreachable!(),
    }
  }
}

pub enum BitmaskOp {}

impl BitmaskOp {
  const NOT: u8 = 0b10;
  const MATCH: u8 = 0b01;
  const NOT_MATCH: u8 = Self::NOT | Self::MATCH;
}

impl OpKind for BitmaskOp {
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
    match flags & Self::NOT_MATCH {
      0 => write!(f, "{data} & 0b{value:b} != 0"),
      Self::NOT => write!(f, "{data} & 0b{value:b} == 0"),
      Self::MATCH => write!(f, "{data} & 0b{value:b} == 0b{value:b}"),
      Self::NOT_MATCH => write!(f, "{data} & 0b{value:b} != 0b{value:b}"),
      _ => unreachable!(),
    }
  }
}

pub trait OpKind {
  const FLAGS_MASK: u8;
  fn op(flags: u8, data: u64, value: u64) -> bool;
  fn fmt(f: &mut Formatter, flags: u8, data: &impl Display, value: u64) -> fmt::Result;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowSpec(BTreeSet<ComponentStore>);

impl FlowSpec {
  pub fn is_ipv4(&self) -> bool {
    if let Component::DstPrefix(p, _) | Component::SrcPrefix(p, _) = &(self.0)
      .get(&ComponentKind::DstPrefix)
      .or_else(|| self.0.get(&ComponentKind::SrcPrefix))
      .unwrap()
      .0
    {
      p.is_ipv4()
    } else {
      panic!("does not know whether the flowspec is IPv4 or v6")
    }
  }

  pub fn is_ipv6(&self) -> bool {
    !self.is_ipv4()
  }

  pub fn serialize(&self, buf: &mut Vec<u8>) {
    let mut buf2 = Vec::new();
    let ipv6 = self.is_ipv6();
    self.0.iter().for_each(|ComponentStore(c)| {
      assert!(!c.is_valid(ipv6)); // TODO: relax this if we have flowspec builder
      if let Component::DstPrefix(prefix, 0) | Component::SrcPrefix(prefix, 0) = c {
        if *prefix == IpPrefix::V4_ALL || *prefix == IpPrefix::V6_ALL {
          return;
        }
      }
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

  pub async fn recv<R: AsyncRead + Unpin>(reader: &mut R, v6: bool) -> Result<Option<Self>, BgpError> {
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
    let mut set = BTreeSet::<ComponentStore>::new();
    while let Some(comp) = Component::recv(&mut flow_reader, v6).await? {
      if set.last().map(|x| x.0.kind() >= comp.kind()).unwrap_or(false) {
        return Err(anyhow!("flowspec components must be unique and sorted by type").into());
      }
      set.insert(ComponentStore(comp));
    }
    if !set.contains(&ComponentKind::DstPrefix) && !set.contains(&ComponentKind::SrcPrefix) {
      let a = if v6 { IpPrefix::V6_ALL } else { IpPrefix::V4_ALL };
      set.insert(ComponentStore(Component::DstPrefix(a, 0)));
    }
    Ok(Some(Self(set)))
  }
}

#[derive(Clone)]
struct ComponentStore(Component);

impl Debug for ComponentStore {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    Debug::fmt(&self.0, f)
  }
}

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
  Protocol(NumericOps) = 3,
  Port(NumericOps) = 4,
  DstPort(NumericOps) = 5,
  SrcPort(NumericOps) = 6,
  IcmpType(NumericOps) = 7,
  IcmpCode(NumericOps) = 8,
  TcpFlags(BitmaskOps) = 9,
  PacketLen(NumericOps) = 10,
  Dscp(NumericOps) = 11,
  Fragment(BitmaskOps) = 12,
  FlowLabel(NumericOps) = 13,
}

impl Component {
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
      DstPrefix(prefix, _) | SrcPrefix(prefix, _) => prefix.is_ipv4(),
      Fragment(ops) => ops.0.iter().all(|x| x.value & !0b1111 == 0),
      FlowLabel(_) => false,
      _ => true,
    }
  }

  fn is_valid_v6(&self) -> bool {
    use Component::*;
    match self {
      DstPrefix(prefix, _) | SrcPrefix(prefix, _) => prefix.is_ipv6(),
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

#[cfg(test)]
mod tests {
  use super::*;
  use test_case::test_case;

  const OP_NUM: PhantomData<NumericOp> = PhantomData;
  const OP_BIT: PhantomData<BitmaskOp> = PhantomData;

  #[test_case(OP_NUM, &[0b00000011, 114, 0b01010100, 2, 2, 0b10000001, 1], &[1, 114, 200], &[0, 2, 514]; "n ge 114 AND n lt 514 OR n eq 1")]
  #[test_case(OP_BIT, &[0b10000001, 0b101], &[85, 1365, 65525, 65535], &[0, 1, 2, 114, 514]; "n bitand 0b101 eq 0b101")]
  #[tokio::test]
  async fn test_ops<K: OpKind>(_op: PhantomData<K>, mut seq: &[u8], aye: &[u64], nay: &[u64]) -> anyhow::Result<()> {
    let ops = Ops::<K>::recv(&mut seq).await?;
    dbg!(&ops);
    aye.iter().for_each(|&n| assert!(ops.op(n), "!ops.op({n})"));
    nay.iter().for_each(|&n| assert!(!ops.op(n), "ops.op({n})"));
    Ok(())
  }
}
