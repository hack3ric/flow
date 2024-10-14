use futures::channel::oneshot::Canceled;
use futures::future::FusedFuture;
use futures::Future;
use std::cell::RefCell;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

pub fn local_channel<T>() -> (Sender<T>, Receiver<T>) {
  let inner = Rc::new(RefCell::new(Inner::new()));
  (Sender(inner.clone()), Receiver(inner))
}

pub struct Receiver<T>(Rc<RefCell<Inner<T>>>);

impl<T> Future for Receiver<T> {
  type Output = Result<T, Canceled>;

  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    self.0.borrow_mut().recv(cx)
  }
}

impl<T> FusedFuture for Receiver<T> {
  fn is_terminated(&self) -> bool {
    let this = self.0.borrow_mut();
    this.complete && this.data.is_none()
  }
}

impl<T> Drop for Receiver<T> {
  fn drop(&mut self) {
    self.0.borrow_mut().complete = true;
  }
}

pub struct Sender<T>(Rc<RefCell<Inner<T>>>);

impl<T> Sender<T> {
  pub fn send(self, t: T) -> Result<(), T> {
    self.0.borrow_mut().send(t)
  }
}

impl<T> Drop for Sender<T> {
  fn drop(&mut self) {
    self.0.borrow_mut().complete = true;
  }
}

struct Inner<T> {
  complete: bool,
  data: Option<T>,
  rx_waker: Option<Waker>,
}

impl<T> Inner<T> {
  fn new() -> Self {
    Self { complete: false, data: None, rx_waker: None }
  }

  fn send(&mut self, t: T) -> Result<(), T> {
    if self.complete {
      Err(t)
    } else {
      assert!(self.data.is_none());
      self.data = Some(t);
      if let Some(waker) = self.rx_waker.take() {
        waker.wake();
      }
      Ok(())
    }
  }

  fn try_recv(&mut self) -> Result<Option<T>, Canceled> {
    if self.complete {
      if let Some(t) = self.data.take() {
        Ok(Some(t))
      } else {
        Err(Canceled)
      }
    } else {
      Ok(None)
    }
  }

  fn recv(&mut self, cx: &mut Context) -> Poll<Result<T, Canceled>> {
    match self.try_recv() {
      Ok(Some(t)) => Poll::Ready(Ok(t)),
      Ok(None) => {
        self.rx_waker = Some(cx.waker().clone());
        Poll::Pending
      }
      Err(_) => Poll::Ready(Err(Canceled)),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::time::Duration;
  use tokio::task::{spawn_local, LocalSet};

  #[tokio::test]
  async fn test() {
    LocalSet::new()
      .run_until(async {
        let (tx, rx) = local_channel::<i32>();
        spawn_local(async {
          tokio::time::sleep(Duration::from_secs(2)).await;
          tx.send(114514).unwrap();
        });
        dbg!(rx.await.unwrap());
      })
      .await;
  }
}
