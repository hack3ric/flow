use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt::{self, Debug, Display, Formatter};
use std::io;
use std::io::ErrorKind::UnexpectedEof;
use std::net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::ParseIntError;
use std::str::FromStr;
use strum::FromRepr;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt};

/// <https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml>
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, FromRepr, Serialize, Deserialize)]
#[repr(u16)]
pub enum Afi {
  Ipv4 = 1,
  Ipv6 = 2,
}

impl Display for Afi {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    match self {
      Self::Ipv4 => f.write_str("IPv4"),
      Self::Ipv6 => f.write_str("IPv6"),
    }
  }
}

/// Max prefix length of a certain IP type.
pub const fn prefix_max_len(prefix: IpAddr) -> u8 {
  match prefix {
    IpAddr::V4(_) => 32,
    IpAddr::V6(_) => 128,
  }
}

/// IP address with its prefix length attached.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct IpWithPrefix {
  addr: IpAddr,
  prefix_len: u8,
}

impl IpWithPrefix {
  pub const fn new(addr: IpAddr, prefix_len: u8) -> Self {
    assert!(
      prefix_len <= prefix_max_len(addr),
      "prefix length should not exceed its range"
    );
    Self { addr, prefix_len }
  }

  pub const fn addr(self) -> IpAddr {
    self.addr
  }

  pub const fn prefix_len(self) -> u8 {
    self.prefix_len
  }

  const fn mask_raw(self) -> u128 {
    if self.prefix_len == 0 {
      0
    } else {
      u128::MAX.wrapping_shl((prefix_max_len(self.addr) - self.prefix_len) as u32)
    }
  }

  pub fn mask(self) -> IpAddr {
    match self.addr {
      IpAddr::V4(_) => Ipv4Addr::from(self.mask_raw() as u32).into(),
      IpAddr::V6(_) => Ipv6Addr::from(self.mask_raw()).into(),
    }
  }

  pub fn prefix(self) -> IpPrefix {
    let mut inner = self;
    match (&mut inner.addr, self.mask()) {
      (IpAddr::V4(v4), IpAddr::V4(mask)) => *v4 &= mask,
      (IpAddr::V6(v6), IpAddr::V6(mask)) => *v6 &= mask,
      _ => unreachable!(),
    };
    IpPrefix { inner }
  }

  pub const fn afi(&self) -> Afi {
    if self.is_ipv4() { Afi::Ipv4 } else { Afi::Ipv6 }
  }

  pub const fn is_ipv4(&self) -> bool {
    self.addr.is_ipv4()
  }

  pub const fn is_ipv6(&self) -> bool {
    self.addr.is_ipv6()
  }
}

impl Debug for IpWithPrefix {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    Display::fmt(self, f)
  }
}

impl Display for IpWithPrefix {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    write!(f, "{}/{}", self.addr, self.prefix_len)
  }
}

impl FromStr for IpWithPrefix {
  type Err = IpWithPrefixError;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    use IpWithPrefixErrorKind::*;

    let Some((addr, prefix_len)) = s.split_once('/') else {
      return Err(IpWithPrefixError::new(PrefixLenNotFound, s));
    };
    let addr = addr.parse::<IpAddr>().map_err(|e| IpWithPrefixError::new(e, s))?;
    let prefix_len = prefix_len.parse::<u8>().map_err(|e| IpWithPrefixError::new(e, s))?;
    let max_len = prefix_max_len(addr);
    if prefix_len > max_len {
      Err(IpWithPrefixError::new(PrefixLenTooLong(prefix_len, max_len), s))
    } else {
      Ok(Self { addr, prefix_len })
    }
  }
}

impl From<IpAddr> for IpWithPrefix {
  fn from(addr: IpAddr) -> Self {
    Self { addr, prefix_len: prefix_max_len(addr) }
  }
}

#[derive(Debug, Clone, Error)]
#[error("error parsing IP with prefix '{value}': {kind}")]
pub struct IpWithPrefixError {
  kind: IpWithPrefixErrorKind,
  value: String,
}

impl IpWithPrefixError {
  fn new(kind: impl Into<IpWithPrefixErrorKind>, value: impl Into<String>) -> Self {
    Self { kind: kind.into(), value: value.into() }
  }
}

#[derive(Debug, Clone, Error)]
pub enum IpWithPrefixErrorKind {
  #[error(transparent)]
  AddrParse(#[from] AddrParseError),
  #[error("prefix length not found")]
  PrefixLenNotFound,
  #[error("parsing prefix length failed: {0}")]
  PrefixLenParse(#[from] ParseIntError),
  #[error("prefix length too long ({0} > {1})")]
  PrefixLenTooLong(u8, u8),
}

/// IP prefix.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IpPrefix {
  inner: IpWithPrefix,
}

impl IpPrefix {
  pub const V4_ALL: Self = Self { inner: IpWithPrefix { addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED), prefix_len: 0 } };
  pub const V6_ALL: Self = Self { inner: IpWithPrefix { addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED), prefix_len: 0 } };

  pub fn new(prefix: IpAddr, len: u8) -> Self {
    let inner = IpWithPrefix::new(prefix, len);
    let result = inner.prefix();
    assert_eq!(result.inner, inner, "bits out of range must be zeroes");
    result
  }

  pub const fn prefix(self) -> IpAddr {
    self.inner.addr
  }

  #[allow(clippy::len_without_is_empty)]
  pub const fn len(self) -> u8 {
    self.inner.prefix_len
  }

  pub fn mask(self) -> IpAddr {
    self.inner.mask()
  }

  pub fn contains<T: Into<Self>>(self, other: T) -> bool {
    use IpAddr::*;
    use std::cmp::Ordering::*;

    let other = other.into();
    match self.len().cmp(&other.len()) {
      Less => match (self.prefix(), self.inner.mask(), other.prefix()) {
        (V4(p1), V4(mask), V4(p2)) => p2 & mask == p1,
        (V6(p1), V6(mask), V6(p2)) => p2 & mask == p1,
        _ => false,
      },
      Equal => self == other,
      Greater => false,
    }
  }

  pub fn overlaps<T: Into<Self>>(self, other: T) -> bool {
    use IpAddr::*;
    use std::cmp::Ordering::*;

    let other = other.into();
    match self.len().cmp(&other.len()) {
      Less => match (self.prefix(), self.inner.mask(), other.prefix()) {
        (V4(p1), V4(mask), V4(p2)) => (p1.to_bits() ^ p2.to_bits()) & mask.to_bits() == 0,
        (V6(p1), V6(mask), V6(p2)) => (p1.to_bits() ^ p2.to_bits()) & mask.to_bits() == 0,
        _ => false,
      },
      Equal => self == other,
      Greater => other.overlaps(self),
    }
  }

  pub const fn is_single(self) -> bool {
    prefix_max_len(self.prefix()) == self.len()
  }

  pub const fn afi(self) -> Afi {
    self.inner.afi()
  }

  pub const fn is_ipv4(self) -> bool {
    self.inner.is_ipv4()
  }

  pub const fn is_ipv6(self) -> bool {
    self.inner.is_ipv6()
  }

  pub fn write(self, buf: &mut Vec<u8>) {
    let prefix_bytes = self.len().div_ceil(8);
    buf.push(self.len());
    match self.prefix() {
      IpAddr::V4(v4) => {
        assert!(prefix_bytes <= 4);
        buf.extend(v4.octets().into_iter().take(prefix_bytes.into()))
      }
      IpAddr::V6(v6) => {
        assert!(prefix_bytes <= 16);
        buf.extend(v6.octets().into_iter().take(prefix_bytes.into()))
      }
    }
  }

  pub async fn read<R: AsyncRead + Unpin>(reader: &mut R, afi: Afi) -> Result<Option<(Self, u8)>, IpPrefixError> {
    match afi {
      Afi::Ipv4 => Self::read_v4(reader).await,
      Afi::Ipv6 => Self::read_v6(reader).await,
    }
  }

  pub async fn read_v4<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<(Self, u8)>, IpPrefixError> {
    Self::read_generic::<32, 4, _, _>(reader, IpAddr::V4).await
  }

  pub async fn read_v6<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<(Self, u8)>, IpPrefixError> {
    Self::read_generic::<128, 16, _, _>(reader, IpAddr::V6).await
  }

  async fn read_generic<const L: u8, const M: usize, T, R>(
    reader: &mut R,
    ctor: fn(T) -> IpAddr,
  ) -> Result<Option<(Self, u8)>, IpPrefixError>
  where
    T: From<[u8; M]>,
    R: AsyncRead + Unpin,
  {
    let len = match reader.read_u8().await {
      Ok(len) => len,
      Err(error) if error.kind() == UnexpectedEof => return Ok(None),
      Err(error) => return Err(error.into()),
    };
    if len > L {
      return Err(IpPrefixError { kind: IpWithPrefixErrorKind::PrefixLenTooLong(len, L).into(), value: None });
    }
    let mut buf = [0; M];
    let prefix_bytes = len.div_ceil(8);
    reader.read_exact(&mut buf[0..prefix_bytes.into()]).await?;
    let inner = IpWithPrefix { addr: ctor(buf.into()), prefix_len: len };
    let result = inner.prefix();
    if result.inner == inner {
      Ok(Some((result, prefix_bytes + 1)))
    } else {
      Err(IpPrefixError { kind: IpPrefixErrorKind::TrailingBitsNonZero, value: None })
    }
  }
}

impl Debug for IpPrefix {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    Display::fmt(&self.inner, f)
  }
}

impl Display for IpPrefix {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    Display::fmt(&self.inner, f)
  }
}

impl FromStr for IpPrefix {
  type Err = IpPrefixError;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    let inner = s
      .parse::<IpWithPrefix>()
      .map_err(|e| IpPrefixError { kind: e.kind.into(), value: Some(e.value) })?;
    let result = inner.prefix();
    if result.inner == inner {
      Ok(result)
    } else {
      Err(IpPrefixError { kind: IpPrefixErrorKind::TrailingBitsNonZero, value: Some(s.into()) })
    }
  }
}

impl From<IpAddr> for IpPrefix {
  fn from(addr: IpAddr) -> Self {
    Self::new(addr, prefix_max_len(addr))
  }
}

impl PartialOrd for IpPrefix {
  fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
    Some(self.cmp(other))
  }
}

impl Ord for IpPrefix {
  fn cmp(&self, other: &Self) -> Ordering {
    match self.inner.prefix_len.cmp(&other.inner.prefix_len) {
      Ordering::Equal => self.inner.addr.cmp(&other.inner.addr),
      Ordering::Greater => Ordering::Less,
      Ordering::Less => Ordering::Greater,
    }
  }
}

#[derive(Debug, Error)]
pub struct IpPrefixError {
  pub kind: IpPrefixErrorKind,
  pub value: Option<String>,
}

impl Display for IpPrefixError {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    if let Some(value) = &self.value {
      write!(f, "error parsing IP prefix '{}': {}", value, self.kind)
    } else {
      write!(f, "error parsing IP prefix: {}", self.kind)
    }
  }
}

impl From<io::Error> for IpPrefixError {
  fn from(e: io::Error) -> Self {
    Self { kind: IpPrefixErrorKind::Io(e), value: None }
  }
}

#[derive(Debug, Error)]
pub enum IpPrefixErrorKind {
  #[error(transparent)]
  Io(#[from] io::Error),
  #[error(transparent)]
  IpWithPrefixParse(#[from] IpWithPrefixErrorKind),
  #[error("trailing bits of a prefix are non-zero")]
  TrailingBitsNonZero,
}

#[cfg(test)]
mod tests {
  use super::*;
  use IpPrefixErrorKind::*;
  use IpWithPrefixErrorKind::*;
  use test_case::test_case;

  #[test_case("192.0.2.66/27")]
  #[test_case("2001:db8::dead:cafe/32")]
  fn test_ip_with_prefix_valid(prefix: &str) {
    assert_eq!(prefix.parse::<IpWithPrefix>().unwrap().to_string(), prefix);
  }

  #[test_case("2a0c:32d7:da9:1ba0/64", |e| matches!(e.kind, AddrParse(_)))]
  #[test_case("128.42.65.125", |e| matches!(e.kind, PrefixLenNotFound))]
  #[test_case("83.34.123.31/-1", |e| matches!(e.kind, PrefixLenParse(_)))]
  #[test_case("83.34.123.31/56", |e| matches!(e.kind, PrefixLenTooLong(_, 32)))]
  #[test_case("::64:ff9b:1.2.3.4/897123", |e| matches!(e.kind, PrefixLenParse(_)))]
  fn test_ip_with_prefix_invalid(prefix: &str, matcher: impl Fn(IpWithPrefixError) -> bool) {
    let error = prefix.parse::<IpWithPrefix>().unwrap_err();
    assert!(matcher(error));
  }

  #[test_case("192.0.2.64/27")]
  #[test_case("2001:db8::/32")]
  #[test_case("2001:db8:dead:beef::/64")]
  fn test_ip_prefix_valid(prefix: &str) {
    assert_eq!(prefix.parse::<IpPrefix>().unwrap().to_string(), prefix);
  }

  #[test_case("192.0.2.65/27", |e| matches!(e.kind, TrailingBitsNonZero))]
  #[test_case("fe80::1/64", |e| matches!(e.kind, TrailingBitsNonZero))]
  fn test_ip_prefix_invalid(prefix: &str, matcher: impl Fn(IpPrefixError) -> bool) {
    let error = prefix.parse::<IpPrefix>().unwrap_err();
    assert!(matcher(error));
  }

  #[test_case("192.168.0.0/16", "192.168.233.0/24", true)]
  #[test_case("192.168.0.0/32", "192.168.233.0/24", false)]
  #[test_case("fdfd:abcc:deff::/48", "fdfd:abcc:deff:1233::/64", true)]
  #[test_case("fdfd:abcc:deff::/64", "fdfd:abcc:deff:1233::/64", false)]
  fn test_ip_prefix_contains(a: &str, b: &str, result: bool) {
    let (a, b) = (a.parse::<IpPrefix>().unwrap(), b.parse::<IpPrefix>().unwrap());
    assert_eq!(a.contains(b), result);
  }
}
