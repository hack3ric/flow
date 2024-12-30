use super::bird::run_bird;
use crate::args::Cli;
use crate::cli_entry;
use anyhow::bail;
use async_tempfile::TempDir;
use std::future::Future;
use std::path::Path;
use std::process::ExitCode;
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

pub async fn run_cli_with_bird<F, Fut, R>(mut cli_opt: Cli, bird_conf_path: impl AsRef<Path>, f: F) -> anyhow::Result<R>
where
  F: FnOnce(&CliChild, &mut Child, &LocalSet) -> Fut,
  Fut: Future<Output = anyhow::Result<R>>,
{
  let sock_dir = TempDir::new().await?;
  cli_opt.run_dir = sock_dir.as_ref().into();
  let mut bird = run_bird(bird_conf_path.as_ref(), sock_dir.join("bird.sock")).await?;

  let ls = LocalSet::new();
  let cli = spawn_cli(&ls, cli_opt);
  let result = ls
    .run_until(async {
      let result = f(&cli, &mut bird, &ls).await?;
      if cli.is_finished() {
        let _exit_code = cli.await??;
        bail!("CLI exits early");
      }
      if let Some(status) = bird.try_wait()? {
        bail!("BIRD exits early with {status}");
      }
      Ok(result)
    })
    .await?;
  bird.kill().await?;
  Ok(result)
}
