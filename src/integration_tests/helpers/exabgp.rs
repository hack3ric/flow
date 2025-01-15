use nix::unistd::{Uid, User};
use std::path::Path;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

pub async fn run_exabgp(config_path: impl AsRef<Path>, port: u16) -> anyhow::Result<Child> {
  let mut exabgp = Command::new("exabgp")
    .arg(config_path.as_ref())
    .env("exabgp.tcp.port", port.to_string())
    .env("exabgp.daemon.user", User::from_uid(Uid::effective())?.unwrap().name)
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .kill_on_drop(true)
    .spawn()?;

  let mut exabgp_stderr = BufReader::new(exabgp.stdout.take().unwrap());
  tokio::spawn(async move {
    let mut buf = String::new();
    while exabgp_stderr.read_line(&mut buf).await? != 0 {
      eprint!("{buf}");
      buf.clear();
    }
    anyhow::Ok(())
  });

  Ok(exabgp)
}
