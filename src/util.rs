use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::fmt::{Display, Formatter};
use std::ops::Deref;
use std::rc::Rc;

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
