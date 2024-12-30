use super::helpers::bird::ensure_bird_2;
use super::helpers::cli::run_cli_with_bird;
use super::helpers::kernel::{ensure_loopback_up, pick_port};
use super::helpers::str_to_file;
use super::test_local;
use crate::args::Cli;
use anyhow::bail;
use clap::Parser;
use macro_rules_attribute::apply;
use std::time::Duration;
use tokio::select;
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
  let (mut cli, mut bird, mut events, _temp_dir) = run_cli_with_bird(cli, bird.file_path()).await?;

  let mut end_of_rib_count = 0;
  loop {
    select! {
      Some(()) = events.recv(), if !events.is_closed() => {
        end_of_rib_count += 1;
        if end_of_rib_count >= 2 {
          break;
        }
      }
      _ = sleep(Duration::from_secs(10)) => bail!("timed out"),
      code = &mut cli => bail!("CLI exited early with code {}", code??),
      status = bird.wait() => bail!("BIRD exited early with {}", status?),
    }
  }

  Ok(())
}
