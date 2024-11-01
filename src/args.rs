use crate::net::IpPrefix;
use clap::{Args, Parser, Subcommand};
use clap_verbosity::{InfoLevel, Verbosity};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

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
  Show(ShowArgs),
}

#[derive(Debug, Clone, Parser, Serialize, Deserialize)]
pub struct RunArgs {
  /// Address to bind.
  ///
  /// May be specified more than once.
  #[arg(
    short, long,
    value_name = "ADDR:PORT",
    value_parser = parse_bgp_bind,
    default_values_t = [SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 179)],
  )]
  pub bind: Vec<SocketAddr>,

  /// Local AS.
  #[arg(short, long, value_name = "ASN", default_value_t = 65000)]
  pub local_as: u32,

  /// Allowed remote AS (optional).
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
    value_parser = parse_prefix,
    default_values_t = [IpPrefix::V4_ALL, IpPrefix::V6_ALL],
  )]
  pub allowed_ips: Vec<IpPrefix>,

  /// Time in seconds before shutdown since the last received keepalive.
  #[arg(short = 'H', long, default_value_t = 240)]
  pub hold_time: u16,

  /// File to read arguments from.
  ///
  /// All CLI arguments except -v are ignored if `--file` is present.
  #[arg(short, long)]
  pub file: Option<PathBuf>,
}

fn parse_bgp_bind(bind: &str) -> anyhow::Result<SocketAddr> {
  let result = bind.parse().or_else(|_| bind.parse::<IpAddr>().map(|ip| (ip, 179).into()))?;
  Ok(result)
}

fn parse_prefix(p: &str) -> anyhow::Result<IpPrefix> {
  let result = p.parse().or_else(|_| {
    p.parse::<IpAddr>()
      .map(|x| IpPrefix::new(x, x.is_ipv4().then_some(32).unwrap_or(128)))
  })?;
  Ok(result)
}

#[derive(Debug, Args)]
pub struct ShowArgs {}
