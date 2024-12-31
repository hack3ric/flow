use super::bird::run_bird;
use super::str_to_file;
use crate::args::Cli;
use crate::cli_entry;
use crate::integration_tests::TestEvent;
use async_tempfile::{TempDir, TempFile};
use futures_channel::{mpsc, oneshot};
use tokio::process::Child;
use tokio::task::JoinHandle;

pub type CliChild = JoinHandle<anyhow::Result<u8>>;

fn run_cli(options: Cli, event_tx: mpsc::Sender<TestEvent>, close_rx: oneshot::Receiver<()>) -> CliChild {
  tokio::task::spawn_local(async {
    let exit_code = cli_entry(options, event_tx, close_rx).await;
    anyhow::Ok(exit_code)
  })
}

pub async fn run_cli_with_bird(
  mut cli_opt: Cli,
  bird_conf: &str,
) -> anyhow::Result<(
  CliChild,
  Child,
  mpsc::Receiver<TestEvent>,
  oneshot::Sender<()>,
  (TempFile, TempDir),
)> {
  let bird_conf_file = str_to_file(bird_conf.as_bytes()).await?;

  let sock_dir = TempDir::new().await?;
  cli_opt.run_dir = sock_dir.as_ref().into();
  let bird = run_bird(bird_conf_file.file_path(), sock_dir.join("bird.sock")).await?;

  let (event_tx, event_rx) = mpsc::channel(127);
  let (close_tx, close_rx) = oneshot::channel();
  let cli = run_cli(cli_opt, event_tx, close_rx);
  Ok((cli, bird, event_rx, close_tx, (bird_conf_file, sock_dir)))
}
