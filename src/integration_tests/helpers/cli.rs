use super::bird::run_bird;
use crate::args::Cli;
use crate::cli_entry;
use async_tempfile::TempDir;
use std::path::Path;
use tokio::process::Child;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

pub type CliChild = JoinHandle<anyhow::Result<u8>>;

fn run_cli(options: Cli, event_tx: mpsc::Sender<()>) -> CliChild {
  tokio::task::spawn_local(async {
    let exit_code = cli_entry(options, event_tx).await;
    anyhow::Ok(exit_code)
  })
}

pub async fn run_cli_with_bird(
  mut cli_opt: Cli,
  bird_conf_path: impl AsRef<Path>,
) -> anyhow::Result<(CliChild, Child, mpsc::Receiver<()>, TempDir)> {
  let sock_dir = TempDir::new().await?;
  cli_opt.run_dir = sock_dir.as_ref().into();
  let bird = run_bird(bird_conf_path.as_ref(), sock_dir.join("bird.sock")).await?;

  let (event_tx, event_rx) = mpsc::channel(127);
  let cli = run_cli(cli_opt, event_tx);
  Ok((cli, bird, event_rx, sock_dir))
}
