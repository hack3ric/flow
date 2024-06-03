use std::fmt::{self, Debug, Display, Formatter};
use std::net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::ParseIntError;
use std::str::FromStr;
use thiserror::Error;

/// Max prefix length of a certain IP type.
#[inline]
pub const fn prefix_max_len(prefix: IpAddr) -> u8 {
  match prefix {
    IpAddr::V4(_) => 32,
    IpAddr::V6(_) => 128,
  }
}

/// IP address with its prefix length attached.
#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub struct IpWithPrefix {
  addr: IpAddr,
  prefix_len: u8,
}

impl IpWithPrefix {
  #[inline]
  pub const fn new(addr: IpAddr, prefix_len: u8) -> Self {
    assert!(
      prefix_len <= prefix_max_len(addr),
      "prefix length should not exceed its range"
    );
    Self { addr, prefix_len }
  }

  #[inline]
  #[allow(dead_code)]
  pub const fn addr(self) -> IpAddr {
    self.addr
  }

  #[inline]
  #[allow(dead_code)]
  pub const fn prefix_len(self) -> u8 {
    self.prefix_len
  }

  #[inline]
  const fn mask_raw(self) -> u128 {
    u128::MAX << (prefix_max_len(self.addr) - self.prefix_len)
  }

  #[inline]
  pub fn mask(self) -> IpAddr {
    match self.addr {
      IpAddr::V4(_) => Ipv4Addr::from(self.mask_raw() as u32).into(),
      IpAddr::V6(_) => Ipv6Addr::from(self.mask_raw()).into(),
    }
  }

  #[inline]
  pub fn prefix(self) -> IpPrefix {
    let mut inner = self;
    match (&mut inner.addr, self.mask()) {
      (IpAddr::V4(v4), IpAddr::V4(mask)) => *v4 &= mask,
      (IpAddr::V6(v6), IpAddr::V6(mask)) => *v6 &= mask,
      _ => unreachable!(),
    };
    IpPrefix { inner }
  }
}

impl Debug for IpWithPrefix {
  #[inline]
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    Display::fmt(self, f)
  }
}

impl Display for IpWithPrefix {
  #[inline]
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
  #[inline]
  fn from(addr: IpAddr) -> Self {
    Self {
      addr,
      prefix_len: prefix_max_len(addr),
    }
  }
}

#[derive(Debug, Clone, Error)]
#[error("error parsing IP with prefix '{value}': {kind}")]
pub struct IpWithPrefixError {
  kind: IpWithPrefixErrorKind,
  value: String,
}

impl IpWithPrefixError {
  #[inline]
  fn new(kind: impl Into<IpWithPrefixErrorKind>, value: impl Into<String>) -> Self {
    Self {
      kind: kind.into(),
      value: value.into(),
    }
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
#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub struct IpPrefix {
  inner: IpWithPrefix,
}

impl IpPrefix {
  #[inline]
  pub fn new(prefix: IpAddr, len: u8) -> Self {
    let inner = IpWithPrefix::new(prefix, len);
    let result = inner.prefix();
    assert_eq!(result.inner, inner, "bits out of range must be zeroes");
    result
  }

  #[inline]
  pub const fn prefix(self) -> IpAddr {
    self.inner.addr
  }

  #[inline]
  pub const fn len(self) -> u8 {
    self.inner.prefix_len
  }

  #[inline]
  #[allow(dead_code)]
  pub fn mask(self) -> IpAddr {
    self.inner.mask()
  }

  #[inline]
  pub fn contains<T: Into<Self>>(self, other: T) -> bool {
    use std::cmp::Ordering::*;
    use IpAddr::*;

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

  #[inline]
  #[allow(dead_code)]
  pub const fn is_single(self) -> bool {
    prefix_max_len(self.prefix()) == self.len()
  }
}

impl Debug for IpPrefix {
  #[inline]
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    Display::fmt(&self.inner, f)
  }
}

impl Display for IpPrefix {
  #[inline]
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    Display::fmt(&self.inner, f)
  }
}

impl FromStr for IpPrefix {
  type Err = IpPrefixError;

  #[inline]
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    let inner = s.parse::<IpWithPrefix>().map_err(|e| IpPrefixError {
      kind: e.kind.into(),
      value: e.value,
    })?;
    let result = inner.prefix();
    if result.inner == inner {
      Ok(result)
    } else {
      Err(IpPrefixError {
        kind: IpPrefixErrorKind::TrailingBitsNonZero,
        value: s.into(),
      })
    }
  }
}

impl From<IpAddr> for IpPrefix {
  #[inline]
  fn from(addr: IpAddr) -> Self {
    Self::new(addr, prefix_max_len(addr))
  }
}

#[derive(Debug, Clone, Error)]
#[error("error parsing IP prefix '{value}': {kind}")]
pub struct IpPrefixError {
  kind: IpPrefixErrorKind,
  value: String,
}

#[derive(Debug, Clone, Error)]
pub enum IpPrefixErrorKind {
  #[error(transparent)]
  IpWithPrefixParse(#[from] IpWithPrefixErrorKind),
  #[error("trailing bits of a prefix are non-zero")]
  TrailingBitsNonZero,
}

#[cfg(test)]
mod tests {
  use super::*;
  use test_case::test_case;
  use IpPrefixErrorKind::*;
  use IpWithPrefixErrorKind::*;

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
