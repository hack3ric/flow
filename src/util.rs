use anstyle::{AnsiColor, Color, Reset, Style};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use smallvec::SmallVec;
use std::borrow::Cow;
use std::cmp::min;
use std::collections::BTreeSet;
use std::fmt::{self, Display, Formatter, Write};
use std::ops::{Add, Deref, RangeInclusive};
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
      Self::Rc(t) => t,
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

#[derive(Debug, Clone)]
pub struct TruthTable {
  pub mask: u64,
  pub inv: bool,
  pub truth: BTreeSet<u64>,
}

impl TruthTable {
  pub fn new(mask: u64, inv: bool, truth: impl IntoIterator<Item = u64>) -> Self {
    let truth = truth.into_iter().map(|x| x & mask).collect();
    let mut result = Self { mask, inv, truth };
    result.optimize();
    result
  }

  fn optimize(&mut self) {
    if self.truth.len() > (1 << (self.mask.count_ones() - 1)) {
      if self.inv {
        self.truth = self.possible_values_masked().into_owned();
        self.inv = false;
      } else {
        self.inv = true;
        self.truth = self.possible_values_masked().into_owned();
      }
    }
  }

  pub const fn always_true() -> Self {
    Self { mask: 0, inv: true, truth: BTreeSet::new() }
  }

  pub const fn always_false() -> Self {
    Self { mask: 0, inv: false, truth: BTreeSet::new() }
  }

  pub fn is_always_true(&self) -> bool {
    self.inv && self.truth.is_empty() || !self.inv && self.truth.len() == 1 << self.mask.count_ones()
  }

  pub fn is_always_false(&self) -> bool {
    !self.inv && self.truth.is_empty() || self.inv && self.truth.len() == 1 << self.mask.count_ones()
  }

  pub fn and(self, other: Self) -> Self {
    if self.is_always_false() || other.is_always_false() {
      Self::always_false()
    } else if self.is_always_true() {
      other
    } else if other.is_always_true() {
      self
    } else {
      match (self.inv, other.inv) {
        (false, false) => self.truth_intersection(&other, false),
        (true, true) => self.truth_union(&other, true),
        (false, true) => self.truth_difference(&other, false),
        (true, false) => other.and(self),
      }
    }
  }

  pub fn or(self, other: Self) -> Self {
    if self.is_always_true() || other.is_always_true() {
      Self::always_true()
    } else if self.is_always_false() {
      other
    } else if other.is_always_false() {
      self
    } else {
      match (self.inv, other.inv) {
        (false, false) => self.truth_union(&other, false),
        (true, true) => self.truth_intersection(&other, true),
        (false, true) => other.truth_difference(&self, true),
        (true, false) => other.or(self),
      }
    }
  }

  pub fn invert(mut self) -> Self {
    self.inv = !self.inv;
    self
  }

  pub fn possible_values_masked(&self) -> Cow<BTreeSet<u64>> {
    if self.inv {
      Cow::Owned(
        iter_masked(self.mask)
          .collect::<BTreeSet<_>>()
          .difference(&self.truth)
          .copied()
          .collect(),
      )
    } else {
      Cow::Borrowed(&self.truth)
    }
  }

  pub fn shrink(&self, other_mask: u64) -> Cow<Self> {
    let mask = self.mask & other_mask;
    if mask == self.mask {
      Cow::Borrowed(self)
    } else {
      Cow::Owned(Self { mask, inv: self.inv, truth: self.truth.iter().map(|v| v & mask).collect() })
    }
  }

  pub fn expand(&self, other_mask: u64) -> Cow<Self> {
    let mask = self.mask | other_mask;
    if mask == self.mask {
      Cow::Borrowed(self)
    } else {
      Cow::Owned(Self {
        mask,
        inv: self.inv,
        truth: iter_masked(other_mask & !self.mask)
          .flat_map(|a| self.truth.iter().map(move |b| a | b))
          .collect(),
      })
    }
  }

  fn expand_set(&self, other_mask: u64) -> Cow<BTreeSet<u64>> {
    match self.expand(other_mask) {
      Cow::Borrowed(x) => Cow::Borrowed(&x.truth),
      Cow::Owned(x) => Cow::Owned(x.truth),
    }
  }

  fn truth_intersection(&self, other: &Self, inv: bool) -> Self {
    self.truth_op(other, inv, |a, b| a.intersection(b).copied().collect())
  }
  fn truth_union(&self, other: &Self, inv: bool) -> Self {
    self.truth_op(other, inv, |a, b| a.union(b).copied().collect())
  }
  fn truth_difference(&self, other: &Self, inv: bool) -> Self {
    self.truth_op(other, inv, |a, b| a.difference(b).copied().collect())
  }
  fn truth_op<F>(&self, other: &Self, inv: bool, f: F) -> Self
  where
    F: for<'a> FnOnce(&'a BTreeSet<u64>, &'a BTreeSet<u64>) -> BTreeSet<u64>,
  {
    Self {
      mask: self.mask | other.mask,
      inv,
      truth: f(&self.expand_set(other.mask), &other.expand_set(self.mask)),
    }
  }
}

impl PartialEq for TruthTable {
  fn eq(&self, other: &Self) -> bool {
    self.mask == other.mask && self.possible_values_masked() == other.possible_values_masked()
  }
}

impl Eq for TruthTable {}

fn pos_of_set_bits(mut mask: u64) -> SmallVec<[u8; 6]> {
  let mut pos = SmallVec::with_capacity(mask.count_ones().try_into().unwrap());
  while mask.trailing_zeros() < 64 {
    pos.push(mask.trailing_zeros().try_into().unwrap());
    mask ^= 1 << mask.trailing_zeros();
  }
  pos
}

/// Iterator over every possible value under the mask.
fn iter_masked(mask: u64) -> impl Iterator<Item = u64> + Clone + 'static {
  let pos = pos_of_set_bits(mask);
  let empty_zero = pos.is_empty().then_some(0);
  (0u64..1 << mask.count_ones())
    .map(move |x| pos.iter().enumerate().map(|(i, p)| ((x >> i) & 1) << p).fold(0, Add::add))
    .chain(empty_zero)
}

impl Display for TruthTable {
  fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
    write!(f, "({}{:b}) {{", if f.alternate() { "0b" } else { "" }, self.mask)?;
    let possible_values = self.possible_values_masked();
    let mut iter = possible_values.iter();
    if let Some(first) = iter.next() {
      if f.alternate() {
        f.write_str("0b")?;
      }
      for _ in 0..first.leading_zeros() - self.mask.leading_zeros() {
        f.write_char('0')?;
      }
      if *first > 0 {
        write!(f, "{:b}", first)?;
      }
      for val in iter {
        f.write_str(", ")?;
        if f.alternate() {
          f.write_str("0b")?;
        }
        for _ in 0..val.leading_zeros() - self.mask.leading_zeros() {
          f.write_char('0')?;
        }
        if *val > 0 {
          write!(f, "{:b}", val)?;
        }
      }
    }
    f.write_char('}')
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::bgp::flow::Op;
  use test_case::test_case;

  #[test_case(0..=5, 5..=10, Some(5..=5))]
  #[test_case(0..=114, 5..=10, Some(5..=10))]
  #[test_case(0..=5, 114..=514, None)]
  fn test_intersect(a: RangeInclusive<u64>, b: RangeInclusive<u64>, result: Option<RangeInclusive<u64>>) {
    assert_eq!(a.intersect(b), result);
  }

  #[test]
  fn test_truth_table() {
    assert!(TruthTable::always_true().is_always_true());
    assert!(TruthTable::always_false().is_always_false());
    assert!(Op::not_any(0b0000).to_truth_table().is_always_true());

    let op1 = Op::all(0b0100);
    let op2 = Op::not_all(0b1010);
    let tt = op1.to_truth_table().or(op2.to_truth_table());
    assert_eq!(tt, TruthTable::new(0b1110, true, [0b1010]));

    assert_eq!(
      tt,
      TruthTable::new(0b1110, false, [0b0000, 0b0010, 0b0100, 0b0110, 0b1000, 0b1100, 0b1110]),
    );
  }
}
