mod msg;

use crate::net::IpPrefix;
use futures::future::pending;
use msg::Message;
use std::io;
use tokio::net::TcpStream;
use State::*;

pub struct Config {
  router_id: u32,
  local_as: u32,
  remote_as: Option<u32>,
  remote_ip: IpPrefix,
}

/// A passive BGP session.
pub struct Session {
  config: Config,
  state: State,
  conn: Option<TcpStream>,
}

impl Session {
  pub async fn process(&mut self) -> io::Result<()> {
    match &mut self.state {
      Idle | Connect | Active => pending().await,
      OpenSent => {
        let mut stream = self.conn.take().expect("session should have connection socket in OpenSent");
        let msg_result = Message::recv(&mut stream).await;
        if let Ok(Message::Open(msg)) = msg_result {
          if self.config.remote_as.map_or(false, |x| msg.my_as != x) {
            return Err(io::Error::other("remote AS mismatch"));
          }
          self.state = OpenConfirm;
        } else {
          // TODO: send notification
          match msg_result {
            Ok(_msg) => {}
            Err(_error) => {}
          }
          self.conn = None;
          self.state = Active;
        }
      }
      OpenConfirm => todo!(),
      Established => todo!(),
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum State {
  Idle,
  Connect, // never used in passive mode
  Active,
  OpenSent,
  OpenConfirm,
  Established,
}
