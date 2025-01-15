//! These are "integration" tests for the `flow` binary, in the form of unit
//! tests.

mod helpers;

use crate::bgp::msg::UpdateMessage;
use crate::bgp::nlri::NlriKind;
use crate::bgp::Session;
use crate::net::Afi;
use tokio::io::BufReader;
use tokio::net::TcpStream;

#[derive(Debug)]
pub enum TestEvent {
  EndOfRib(Afi, NlriKind),
  Update(UpdateMessage<'static>),
  Exit(Session<BufReader<TcpStream>>),
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
mod flowspec;
#[cfg(linux)]
mod kernel_linux;

const BIRD_CONFIG_1: &str = "\
router id 10.234.56.78;

flow4 table myflow4;
flow6 table myflow6;

protocol static f4 {
  flow4 { table myflow4; };
  @@FLOW4@@
}

protocol static f6 {
  flow6 { table myflow6; };
  @@FLOW6@@
}

protocol bgp flow_test {
  debug all;
  connect delay time 1;

  local ::1 port @@BIRD_PORT@@ as 65000;
  neighbor ::1 port @@FLOW_PORT@@ as 65000;
  multihop;

  flow4 { table myflow4; import none; export all; };
  flow6 { table myflow6; import none; export all; };
}";

const EXABGP_CONFIG_1: &str = "\
neighbor ::1 {
  router-id 10.234.56.78;
  local-address ::1;
  local-as 65000;
  peer-as 65000;

  flow {
    @@FLOWS@@
  }
}";
