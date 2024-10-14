use futures::future::poll_fn;
use futures::Future;
use smallvec::SmallVec;
use std::cell::RefCell;
use std::task::{Context, Poll, Waker};

/// Single-threaded read-write lock
#[derive(Debug)]
pub struct LocalRwLock<const R: usize = 4, const W: usize = 4>(RefCell<Inner<R, W>>);

impl<const R: usize, const W: usize> LocalRwLock<R, W> {
  pub fn new() -> Self {
    Self(RefCell::new(Inner {
      state: LocalRwLockState::Vacant,
      read_wakers: SmallVec::new(),
      write_wakers: SmallVec::new(),
    }))
  }
}

#[derive(Debug)]
struct Inner<const R: usize, const W: usize> {
  state: LocalRwLockState,
  read_wakers: SmallVec<[Waker; R]>,
  write_wakers: SmallVec<[Waker; W]>,
}

impl<const R: usize, const W: usize> LocalRwLock<R, W> {
  pub fn poll_read<'a>(&'a self, cx: &mut Context) -> Poll<LocalRwLockGuard<'a, R, W>> {
    let mut inner = self.0.borrow_mut();
    match inner.state {
      LocalRwLockState::Vacant => {
        inner.state = LocalRwLockState::Read(1);
        drop(inner);
        Poll::Ready(LocalRwLockGuard(&self.0))
      }
      LocalRwLockState::Read(count) => {
        inner.state = LocalRwLockState::Read(count + 1);
        drop(inner);
        Poll::Ready(LocalRwLockGuard(&self.0))
      }
      LocalRwLockState::Write => {
        inner.read_wakers.push(cx.waker().clone());
        Poll::Pending
      }
    }
  }

  pub fn poll_write<'a>(&'a self, cx: &mut Context) -> Poll<LocalRwLockGuard<'a, R, W>> {
    let mut inner = self.0.borrow_mut();
    match inner.state {
      LocalRwLockState::Vacant => {
        inner.state = LocalRwLockState::Write;
        drop(inner);
        Poll::Ready(LocalRwLockGuard(&self.0))
      }
      LocalRwLockState::Read(_) | LocalRwLockState::Write => {
        inner.write_wakers.push(cx.waker().clone());
        Poll::Pending
      }
    }
  }

  pub fn read(&self) -> impl Future<Output = LocalRwLockGuard<R, W>> + '_ {
    poll_fn(|cx| self.poll_read(cx))
  }

  pub fn write(&self) -> impl Future<Output = LocalRwLockGuard<R, W>> + '_ {
    poll_fn(|cx| self.poll_write(cx))
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalRwLockState {
  Read(u32),
  Write,
  Vacant,
}

pub struct LocalRwLockGuard<'a, const R: usize, const W: usize>(&'a RefCell<Inner<R, W>>);

impl<const R: usize, const W: usize> Drop for LocalRwLockGuard<'_, R, W> {
  fn drop(&mut self) {
    let mut inner = self.0.borrow_mut();
    let read_count = if let LocalRwLockState::Read(count) = inner.state {
      count - 1
    } else {
      0
    };
    inner.state = if read_count == 0 {
      LocalRwLockState::Vacant
    } else {
      LocalRwLockState::Read(read_count)
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
