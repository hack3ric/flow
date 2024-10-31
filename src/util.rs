use anstyle::{AnsiColor, Color, Reset, Style};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::cmp::min;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::ops::{Deref, RangeInclusive};
use std::rc::Rc;

pub const FG_GREEN_BOLD: Style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::Green))).bold();
pub const FG_BLUE_BOLD: Style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::Blue))).bold();
pub const BOLD: Style = Style::new().bold();
pub const RESET: Reset = Reset;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MaybeRc<T> {
  Rc(Rc<T>),
  Owned(T),
}

impl<T: Display> Display for MaybeRc<T> {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    <T as Display>::fmt(self, f)
  }
}

impl<T: Default> Default for MaybeRc<T> {
  fn default() -> Self {
    Self::Owned(T::default())
  }
}

impl<T> Deref for MaybeRc<T> {
  type Target = T;

  fn deref(&self) -> &Self::Target {
    match self {
      Self::Rc(t) => &*t,
      Self::Owned(t) => t,
    }
  }
}

impl<T: Serialize> Serialize for MaybeRc<T> {
  fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
    T::serialize(self, ser)
  }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for MaybeRc<T> {
  fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
    Ok(Self::Owned(T::deserialize(de)?))
  }
}

pub trait Intersect<T = Self>: Sized {
  fn intersect(self, other: T) -> Option<Self>;
}

impl<T: Ord> Intersect for RangeInclusive<T> {
  fn intersect(self, other: Self) -> Option<Self> {
    if self.start() > other.start() {
      Self::intersect(other, self)
    } else if self.end() < other.start() {
      None
    } else {
      let (_, self_end) = self.into_inner();
      let (other_start, other_end) = other.into_inner();
      Some(other_start..=min(self_end, other_end))
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use test_case::test_case;

  #[test_case(0..=5, 5..=10, Some(5..=5))]
  #[test_case(0..=114, 5..=10, Some(5..=10))]
  #[test_case(0..=5, 114..=514, None)]
  fn test_intersect(a: RangeInclusive<u64>, b: RangeInclusive<u64>, result: Option<RangeInclusive<u64>>) {
    assert_eq!(a.intersect(b), result);
  }
}
