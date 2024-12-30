use super::helpers::bird::ensure_bird_2;
use super::helpers::cli::run_cli_with_bird;
use super::helpers::kernel::{ensure_loopback_up, pick_port};
use super::helpers::str_to_file;
use super::test_local;
use crate::args::Cli;
use clap::Parser;
use macro_rules_attribute::apply;
use std::time::Duration;
use tokio::time::sleep;

#[apply(test_local!)]
async fn test_basic() -> anyhow::Result<()> {
  ensure_bird_2()?;
  ensure_loopback_up().await?;

  let flow_port = pick_port().await?.to_string();
  let cli = Cli::try_parse_from(["flow", "run", "-v", "--dry-run", &format!("--bind=[::1]:{flow_port}")])?;
  let bird = include_str!("config/basic.bird.conf.in")
    .replace("@@BIRD_PORT@@", &pick_port().await?.to_string())
    .replace("@@FLOW_PORT@@", &flow_port);
  let bird = str_to_file(bird.as_bytes()).await?;

  let (_cli, _bird, _event, _temp_dir) = run_cli_with_bird(cli, bird.file_path()).await?;
  sleep(Duration::from_secs(7)).await;
  Ok(())
}
