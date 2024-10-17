use crate::net::IpPrefix;
use clap::{Args, Parser, Subcommand};
use clap_verbosity::{InfoLevel, Verbosity};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

#[derive(Debug, Parser)]
pub struct Cli {
  #[command(subcommand)]
  pub command: Command,
  #[command(flatten)]
  pub verbosity: Verbosity<InfoLevel>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
  Run(RunArgs),
  Show,
}

#[derive(Debug, Args)]
pub struct RunArgs {
  /// Address to bind.
  #[arg(
    short, long,
    value_parser = parse_bgp_bind,
    default_value_t = (Ipv6Addr::UNSPECIFIED, 179).into(),
  )]
  pub bind: SocketAddr,

  #[arg(short, long, default_value_t = 65000)]
  pub local_as: u32,

  #[arg(short, long)]
  pub remote_as: Option<u32>,

  #[arg(short = 'i', long)]
  pub router_id: Option<Ipv4Addr>,

  #[arg(
    short, long,
    value_parser = IpPrefix::from_str,
    default_values_t = [
      IpPrefix::new(Ipv4Addr::UNSPECIFIED.into(), 0),
      IpPrefix::new(Ipv6Addr::UNSPECIFIED.into(), 0),
    ],
  )]
  pub allowed_ips: Vec<IpPrefix>,
}

fn parse_bgp_bind(bind: &str) -> anyhow::Result<SocketAddr> {
  let result = bind.parse().or_else(|_| bind.parse::<IpAddr>().map(|ip| (ip, 179).into()))?;
  Ok(result)
}
