//! These are "integration" tests for the `flow` binary, in the form of unit
//! tests.

mod helpers;

use crate::args::Cli;
use clap::Parser;
use helpers::bird::ensure_bird_ver_ge;
use helpers::cli::run_cli_with_bird;
use helpers::kernel::{ensure_loopback_up, pick_port};
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn test_basic() -> anyhow::Result<()> {
  ensure_bird_ver_ge!("2");
  ensure_loopback_up().await?;

  let port = pick_port().await?.to_string();
  let cli = Cli::try_parse_from(["flow", "run", "-v", "--dry-run", &format!("--bind=[::1]:{port}")])?;
  let bird = include_str!("config/basic.bird.conf.in").replace("@@FLOW_PORT@@", &port);

  let fut = run_cli_with_bird(cli, &bird, |_cli, _bird, _ls| async {
    sleep(Duration::from_secs(7)).await;
    Ok(())
  });

  fut.await
}
