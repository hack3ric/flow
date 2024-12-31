//! These are "integration" tests for the `flow` binary, in the form of unit
//! tests.

// mod helpers;

use crate::bgp::msg::UpdateMessage;
use crate::bgp::nlri::NlriKind;
use crate::bgp::Session;
use crate::net::Afi;
use futures::io::BufReader;
use smol::net::TcpStream;

#[derive(Debug)]
pub enum TestEvent {
  EndOfRib(Afi, NlriKind),
  Update(UpdateMessage<'static>),
  Exit(Session<BufReader<TcpStream>>),
}

// Test files
// mod flowspec;
