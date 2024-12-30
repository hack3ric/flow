//! These are "integration" tests for the `flow` binary, in the form of unit
//! tests.

mod helpers;

use crate::bgp::msg::UpdateMessage;
use crate::bgp::nlri::NlriKind;
use crate::net::Afi;

#[derive(Debug, Clone)]
pub enum TestEvent {
  EndOfRib(Afi, NlriKind),
  Update(UpdateMessage<'static>),
}

macro_rules! test_local {
  (
    $(#[$post_attr:meta])*
    async fn $name:ident ($($pname:ident : $pty:ty),* $(,)?)
    $(-> $ret:ty)? $bl:block
  ) => {
    $(#[$post_attr])*
    #[tokio::test]
    async fn $name($($pname: $pty),*) $(-> $ret)? {
      tokio::task::LocalSet::new().run_until(async move $bl).await
    }
  };
}

pub(crate) use test_local;

// Test files
mod basic;
