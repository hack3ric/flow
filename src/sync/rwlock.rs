use futures::future::poll_fn;
use futures::Future;
use smallvec::SmallVec;
use std::cell::{Ref, RefCell, RefMut};
use std::ops::{Deref, DerefMut};
use std::task::{Context, Poll, Waker};

pub struct RwLock<T, const R: usize = 4, const W: usize = 4> {
  raw: RawRwLock<R, W>,
  value: RefCell<T>, // TODO: use UnsafeCell
}

impl<T, const R: usize, const W: usize> RwLock<T, R, W> {
  pub fn new(value: T) -> Self {
    Self { raw: RawRwLock::new(), value: RefCell::new(value) }
  }

  pub async fn read(&self) -> RwLockReadGuard<T, R, W> {
    let _raw = self.raw.read().await;
    let value = self.value.borrow();
    RwLockReadGuard { _raw, value }
  }

  pub async fn write(&self) -> RwLockWriteGuard<T, R, W> {
    let _raw = self.raw.write().await;
    let value = self.value.borrow_mut();
    RwLockWriteGuard { _raw, value }
  }
}

pub struct RwLockReadGuard<'a, T, const R: usize, const W: usize> {
  _raw: RawRwLockGuard<'a, R, W>,
  value: Ref<'a, T>,
}

impl<T, const R: usize, const W: usize> Deref for RwLockReadGuard<'_, T, R, W> {
  type Target = T;
  fn deref(&self) -> &Self::Target {
    &self.value
  }
}

pub struct RwLockWriteGuard<'a, T, const R: usize, const W: usize> {
  _raw: RawRwLockGuard<'a, R, W>,
  value: RefMut<'a, T>,
}

impl<T, const R: usize, const W: usize> Deref for RwLockWriteGuard<'_, T, R, W> {
  type Target = T;
  fn deref(&self) -> &Self::Target {
    &self.value
  }
}

impl<T, const R: usize, const W: usize> DerefMut for RwLockWriteGuard<'_, T, R, W> {
  fn deref_mut(&mut self) -> &mut Self::Target {
    &mut self.value
  }
}

/// Single-threaded raw read-write lock
#[derive(Debug)]
pub struct RawRwLock<const R: usize, const W: usize>(RefCell<Inner<R, W>>);

#[derive(Debug)]
struct Inner<const R: usize, const W: usize> {
  state: State,
  read_wakers: SmallVec<[Waker; R]>,
  write_wakers: SmallVec<[Waker; W]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
  Read(u32),
  Write,
  Vacant,
}

impl<const R: usize, const W: usize> RawRwLock<R, W> {
  pub fn new() -> Self {
    Self(RefCell::new(Inner {
      state: State::Vacant,
      read_wakers: SmallVec::new(),
      write_wakers: SmallVec::new(),
    }))
  }
}

impl<const R: usize, const W: usize> RawRwLock<R, W> {
  pub fn poll_read<'a>(&'a self, cx: &mut Context) -> Poll<RawRwLockGuard<'a, R, W>> {
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

  pub fn poll_write<'a>(&'a self, cx: &mut Context) -> Poll<RawRwLockGuard<'a, R, W>> {
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

  pub fn read(&self) -> impl Future<Output = RawRwLockGuard<R, W>> + '_ {
    poll_fn(|cx| self.poll_read(cx))
  }

  pub fn write(&self) -> impl Future<Output = RawRwLockGuard<R, W>> + '_ {
    poll_fn(|cx| self.poll_write(cx))
  }
}

pub struct RawRwLockGuard<'a, const R: usize, const W: usize>(&'a RefCell<Inner<R, W>>);

impl<const R: usize, const W: usize> Drop for RawRwLockGuard<'_, R, W> {
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
