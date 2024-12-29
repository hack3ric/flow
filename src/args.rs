use crate::net::IpPrefix;
use clap::{Args, Parser, Subcommand};
use clap_verbosity_flag::{InfoLevel, Verbosity};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

#[cfg(kernel_supported)]
use crate::kernel::KernelArgs;

#[derive(Debug, Parser)]
pub struct Cli {
  #[command(subcommand)]
  pub command: Command,
  #[command(flatten)]
  pub verbosity: Verbosity<InfoLevel>,

  /// Path of runtime directory.
  #[arg(long, global = true, default_value = "/run/flow")]
  pub run_dir: PathBuf,
}

#[derive(Debug, Subcommand)]
pub enum Command {
  Run(RunArgs),
  Show(ShowArgs),
}

#[derive(Debug, Clone, Parser, Serialize, Deserialize)]
pub struct RunArgs {
  /// Address to bind.
  #[arg(
    short, long,
    value_name = "ADDR:PORT",
    value_parser = parse_bgp_bind,
    default_value_t = SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 179),
  )]
  pub bind: SocketAddr,

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
  ///
  /// Keepalive time is set to 1/3 of hold time. Set 0 to disable keepalive
  /// mechanism. Hold time of 1 or 2 are invalid and will be rejected.
  #[arg(short = 'H', long, default_value_t = 240)]
  pub hold_time: u16,

  /// Do not apply flowspecs to kernel settings.
  ///
  /// On unsupported platforms, this is no-op and no changes will be applied to
  /// kernel.
  #[arg(short, long)]
  pub dry_run: bool,

  /// Platform-specific kernel settings.
  #[cfg(kernel_supported)]
  #[command(flatten)]
  pub kernel: KernelArgs,

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
      .map(|x| IpPrefix::new(x, if x.is_ipv4() { 32 } else { 128 }))
  })?;
  Ok(result)
}

#[derive(Debug, Args)]
pub struct ShowArgs {}
