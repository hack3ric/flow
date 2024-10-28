use crate::net::IpPrefix;
use clap::{Parser, Subcommand};
use clap_verbosity::{InfoLevel, Verbosity};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
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

#[derive(Debug, Parser)]
pub struct RunArgs {
  /// Address to bind.
  #[arg(
    short, long, value_name = "ADDR:PORT",
    value_parser = parse_bgp_bind,
    default_value_t = (Ipv6Addr::UNSPECIFIED, 179).into(),
  )]
  pub bind: SocketAddr,

  /// Local AS.
  #[arg(short, long, value_name = "ASN", default_value_t = 65000)]
  pub local_as: u32,

  /// Remote AS.
  #[arg(short, long, value_name = "ASN")]
  pub remote_as: Option<u32>,

  /// Router ID.
  #[arg(short = 'i', long, value_name = "ID", default_value_t = [127, 0, 0, 1].into())]
  pub router_id: Ipv4Addr,

  /// Allowed incoming IP prefix.
  ///
  /// May be specified more than once.
  #[arg(
    short, long,
    value_name = "PREFIX",
    value_parser = IpPrefix::from_str,
    default_values_t = [IpPrefix::V4_ALL, IpPrefix::V6_ALL],
  )]
  pub allowed_ips: Vec<IpPrefix>,

  /// File to read arguments from.
  ///
  /// All CLI arguments except -v are ignored if set.
  #[arg(short, long)]
  pub file: Option<PathBuf>,
}

fn parse_bgp_bind(bind: &str) -> anyhow::Result<SocketAddr> {
  let result = bind.parse().or_else(|_| bind.parse::<IpAddr>().map(|ip| (ip, 179).into()))?;
  Ok(result)
}
