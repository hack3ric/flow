use std::cmp::min;
use std::ops::RangeInclusive;

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
