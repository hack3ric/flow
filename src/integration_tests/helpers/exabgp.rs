use nix::unistd::{Uid, User};
use std::borrow::Cow;
use std::env;
use std::ffi::OsStr;
use std::path::Path;
use std::process::Stdio;
use std::sync::LazyLock;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

static EXABGP_PATH: LazyLock<Cow<'static, OsStr>> = LazyLock::new(|| {
  env::var_os("FLOW_EXABGP_PATH")
    .map(Cow::Owned)
    .unwrap_or(Cow::Borrowed("exabgp".as_ref()))
});

pub async fn run_exabgp(config_path: impl AsRef<Path>, port: u16) -> anyhow::Result<Child> {
  let mut exabgp = Command::new(&*EXABGP_PATH)
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
