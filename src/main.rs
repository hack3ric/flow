mod bgp;
mod net;

use clap::Parser;
use std::net::{IpAddr, SocketAddr};
use tokio::net::TcpListener;
use tokio::select;

#[derive(Parser)]
struct Args {
  /// Address to bind
  #[arg(short, long, value_parser = parse_bgp_bind, default_value = "::")]
  bind: SocketAddr,

  #[arg(short, long, default_value = "65000")]
  local_as: u32,
  #[arg(short, long)]
  remote_as: Option<u32>,
}

fn parse_bgp_bind(bind: &str) -> anyhow::Result<SocketAddr> {
  let result = bind.parse().or_else(|_| bind.parse::<IpAddr>().map(|ip| (ip, 179).into()))?;
  Ok(result)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
  let args = Args::parse();
  pretty_env_logger::init();

  let listener = TcpListener::bind(args.bind).await?;
  let mut bgp = bgp::Session::new(bgp::Config {
    router_id: 123456,
    local_as: args.local_as,
    remote_as: args.remote_as,
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
