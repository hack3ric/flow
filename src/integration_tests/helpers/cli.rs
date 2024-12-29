use crate::args::Cli;
use crate::cli_entry;
use std::future::Future;
use std::process::ExitCode;
use tokio::task::{JoinHandle, LocalSet};

pub type CliChild = JoinHandle<anyhow::Result<ExitCode>>;

pub async fn run_cli<F, Fut, R>(options: Cli, f: F) -> anyhow::Result<R>
where
  F: FnOnce(CliChild, &LocalSet) -> Fut,
  Fut: Future<Output = anyhow::Result<R>>,
{
  let ls = LocalSet::new();
  let cli = ls.spawn_local(async {
    let exit_code = cli_entry(options).await;
    anyhow::Ok(exit_code)
  });
  ls.run_until(f(cli, &ls)).await
}
