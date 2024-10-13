//! Flowspec Operators, as specified in [RFC 8955 Section 4.2.1](https://www.rfc-editor.org/rfc/rfc8955#section-4.2.1).

use smallvec::SmallVec;
use std::fmt::{self, Debug, Display, Formatter};
use std::io;
use std::marker::PhantomData;
use tokio::io::{AsyncRead, AsyncReadExt};

/// Operator sequence with values.
pub struct Ops<K: OpKind>(SmallVec<[Op<K>; 4]>);

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
