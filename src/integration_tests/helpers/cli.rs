use super::bird::run_bird;
use super::exabgp::run_exabgp;
use super::str_to_file;
use crate::args::Cli;
use crate::cli_entry;
use crate::integration_tests::TestEvent;
use async_tempfile::{TempDir, TempFile};
use tokio::process::Child;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

pub type CliChild = JoinHandle<anyhow::Result<u8>>;
pub type CliGuard = (
  CliChild,
  Child,
  (mpsc::Receiver<TestEvent>, oneshot::Sender<()>),
  (TempFile, TempDir),
);

pub async fn run_cli_with_bird(mut cli_opt: Cli, bird_conf: &str) -> anyhow::Result<CliGuard> {
  let conf_file = str_to_file(bird_conf.as_bytes()).await?;

  let sock_dir = TempDir::new().await?;
  cli_opt.run_dir = sock_dir.as_ref().into();
  let bird = run_bird(conf_file.file_path(), sock_dir.join("bird.sock")).await?;

  let (cli, event, close) = run_cli(cli_opt);
  Ok((cli, bird, (event, close), (conf_file, sock_dir)))
}

pub async fn run_cli_with_exabgp(mut cli_opt: Cli, exabgp_conf: &str, port: u16) -> anyhow::Result<CliGuard> {
  let conf_file = str_to_file(exabgp_conf.as_bytes()).await?;
  let sock_dir = TempDir::new().await?;
  cli_opt.run_dir = sock_dir.as_ref().into();
  let daemon = run_exabgp(conf_file.file_path(), port).await?;
  let (cli, event, close) = run_cli(cli_opt);
  Ok((cli, daemon, (event, close), (conf_file, sock_dir)))
}

fn run_cli(cli_opt: Cli) -> (CliChild, mpsc::Receiver<TestEvent>, oneshot::Sender<()>) {
  let (event_tx, event_rx) = mpsc::channel(127);
  let (close_tx, close_rx) = oneshot::channel();
  let cli = tokio::task::spawn_local(async {
    let exit_code = cli_entry(cli_opt, event_tx, close_rx).await;
    anyhow::Ok(exit_code)
  });
  (cli, event_rx, close_tx)
}

pub async fn close_cli(chans: (mpsc::Receiver<TestEvent>, oneshot::Sender<()>)) {
  let (mut events, close) = chans;
  let _ = close.send(());
  while let Some(event) = events.recv().await {
    if let TestEvent::Exit(_) = event {
      break;
    }
  }
}
