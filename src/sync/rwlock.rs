use futures::future::poll_fn;
use futures::Future;
use smallvec::SmallVec;
use std::cell::{Ref, RefCell, RefMut};
use std::ops::{Deref, DerefMut};
use std::task::{Context, Poll, Waker};

// TODO: prevent too many readers from blocking writers?

#[derive(Debug)]
pub struct RwLock<T> {
  raw: RawRwLock,
  value: RefCell<T>, // TODO: use UnsafeCell
}

impl<T> RwLock<T> {
  pub fn new(value: T) -> Self {
    Self { raw: RawRwLock::new(), value: RefCell::new(value) }
  }

  pub async fn read(&self) -> RwLockReadGuard<T> {
    let _raw = self.raw.read().await;
    let value = self.value.borrow();
    RwLockReadGuard { _raw, value }
  }

  pub async fn write(&self) -> RwLockWriteGuard<T> {
    let _raw = self.raw.write().await;
    let value = self.value.borrow_mut();
    RwLockWriteGuard { _raw, value }
  }
}

#[derive(Debug)]
pub struct RwLockReadGuard<'a, T> {
  _raw: RawRwLockGuard<'a>,
  value: Ref<'a, T>,
}

impl<T> Deref for RwLockReadGuard<'_, T> {
  type Target = T;
  fn deref(&self) -> &Self::Target {
    &self.value
  }
}

pub struct RwLockWriteGuard<'a, T> {
  _raw: RawRwLockGuard<'a>,
  value: RefMut<'a, T>,
}

impl<T> Deref for RwLockWriteGuard<'_, T> {
  type Target = T;
  fn deref(&self) -> &Self::Target {
    &self.value
  }
}

impl<T> DerefMut for RwLockWriteGuard<'_, T> {
  fn deref_mut(&mut self) -> &mut Self::Target {
    &mut self.value
  }
}

/// Single-threaded raw read-write lock
#[derive(Debug)]
pub struct RawRwLock(RefCell<Inner>);

#[derive(Debug)]
struct Inner {
  state: State,
  read_wakers: SmallVec<[Waker; 4]>,
  write_wakers: SmallVec<[Waker; 4]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
  Read(u32),
  Write,
  Vacant,
}

impl RawRwLock {
  pub fn new() -> Self {
    Self(RefCell::new(Inner {
      state: State::Vacant,
      read_wakers: SmallVec::new(),
      write_wakers: SmallVec::new(),
    }))
  }
}

impl RawRwLock {
  pub fn poll_read<'a>(&'a self, cx: &mut Context) -> Poll<RawRwLockGuard<'a>> {
    let mut inner = self.0.borrow_mut();
    match inner.state {
      State::Vacant => {
        inner.state = State::Read(1);
        drop(inner);
        Poll::Ready(RawRwLockGuard(&self.0))
      }
      State::Read(count) => {
        inner.state = State::Read(count + 1);
        drop(inner);
        Poll::Ready(RawRwLockGuard(&self.0))
      }
      State::Write => {
        inner.read_wakers.push(cx.waker().clone());
        Poll::Pending
      }
    }
  }

  pub fn poll_write<'a>(&'a self, cx: &mut Context) -> Poll<RawRwLockGuard<'a>> {
    let mut inner = self.0.borrow_mut();
    match inner.state {
      State::Vacant => {
        inner.state = State::Write;
        drop(inner);
        Poll::Ready(RawRwLockGuard(&self.0))
      }
      State::Read(_) | State::Write => {
        inner.write_wakers.push(cx.waker().clone());
        Poll::Pending
      }
    }
  }

  pub fn read(&self) -> impl Future<Output = RawRwLockGuard> + '_ {
    poll_fn(|cx| self.poll_read(cx))
  }

  pub fn write(&self) -> impl Future<Output = RawRwLockGuard> + '_ {
    poll_fn(|cx| self.poll_write(cx))
  }
}

#[derive(Debug)]
pub struct RawRwLockGuard<'a>(&'a RefCell<Inner>);

impl Drop for RawRwLockGuard<'_> {
  fn drop(&mut self) {
    let mut inner = self.0.borrow_mut();
    let read_count = if let State::Read(count) = inner.state {
      count - 1
    } else {
      0
    };
    inner.state = if read_count == 0 {
      State::Vacant
    } else {
      State::Read(read_count)
    };
    if !inner.write_wakers.is_empty() {
      for waker in inner.write_wakers.drain(..) {
        waker.wake();
      }
    } else if !inner.read_wakers.is_empty() {
      for waker in inner.read_wakers.drain(..) {
        waker.wake();
      }
    }
  }
}
