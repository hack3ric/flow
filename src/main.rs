mod bgp;
mod net;

use tokio::net::TcpListener;
use tokio::select;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
  pretty_env_logger::init();

  let listener = TcpListener::bind("0.0.0.0:179").await?;
  let mut bgp = bgp::Session::new(bgp::Config {
    router_id: 123456,
    local_as: 65001,
    remote_as: None,
    remote_ip: "0.0.0.0/0".parse()?,
  });
  loop {
    select! {
      result = listener.accept() => {
        let (stream, addr) = result?;
        bgp.accept(stream, addr.ip()).await?;
      }
      result = bgp.process() => result?,
    }
  }
}
