//! These are "integration" tests for the `flow` binary, in the form of unit
//! tests.

mod helpers;

use crate::args::Cli;
use clap::Parser;
use helpers::bird::{ensure_bird_ver_ge, run_bird};
use helpers::cli::run_cli;
use helpers::kernel::ensure_loopback_up;
use std::ffi::OsString;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn test_basic() -> anyhow::Result<()> {
  ensure_bird_ver_ge!("2");
  ensure_loopback_up().await?;

  let (mut bird, (_f, temp_dir)) = run_bird(include_str!("config/basic.bird.conf")).await?;
  let temp_dir_path = temp_dir.as_os_str().into();
  let cli_opt = Cli::try_parse_from(
    ["flow", "run", "-v", "--dry-run", "--bind=[::1]:1179", "--run-dir"]
      .into_iter()
      .map(OsString::from)
      .chain(Some(temp_dir_path)),
  )?;

  // TODO: implement events when cfg(test) in CLI
  let fut = run_cli(cli_opt, |_cli, _ls| async {
    sleep(Duration::from_secs(7)).await;
    bird.kill().await?;
    Ok(())
  });

  fut.await
}
