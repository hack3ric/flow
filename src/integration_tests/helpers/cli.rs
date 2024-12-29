use super::bird::run_bird;
use crate::args::Cli;
use crate::cli_entry;
use async_tempfile::{TempDir, TempFile};
use std::future::Future;
use std::process::ExitCode;
use tokio::io::AsyncWriteExt;
use tokio::process::Child;
use tokio::task::{JoinHandle, LocalSet};

pub type CliChild = JoinHandle<anyhow::Result<ExitCode>>;

fn spawn_cli(ls: &LocalSet, options: Cli) -> CliChild {
  ls.enter();
  ls.spawn_local(async {
    let exit_code = cli_entry(options).await;
    anyhow::Ok(exit_code)
  })
}

pub async fn run_cli_with_bird<F, Fut, R>(mut cli_opt: Cli, bird_conf: &str, f: F) -> anyhow::Result<R>
where
  F: FnOnce(CliChild, &mut Child, &LocalSet) -> Fut,
  Fut: Future<Output = anyhow::Result<R>>,
{
  let mut bird_conf_file = TempFile::new().await?;
  bird_conf_file.write_all(bird_conf.as_bytes()).await?;
  bird_conf_file.flush().await?;

  let sock_dir = TempDir::new().await?;
  cli_opt.run_dir = sock_dir.as_ref().into();
  let mut bird = run_bird(bird_conf_file.file_path(), sock_dir.join("bird.sock")).await?;

  let ls = LocalSet::new();
  let cli = spawn_cli(&ls, cli_opt);
  let result = ls.run_until(f(cli, &mut bird, &ls)).await;
  bird.kill().await?;
  result
}
