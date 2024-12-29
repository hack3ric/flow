use anyhow::bail;
use nix::unistd::{Gid, Uid};
use std::env::{self, VarError};
use std::io::BufRead;
use unshare::{GidMap, Namespace, UidMap};

pub(crate) fn run_unshare_internal(test_name: &str, f: impl FnOnce() -> anyhow::Result<()>) -> anyhow::Result<bool> {
  const ENV_UNSHARE: &str = "FLOW_UNSHARE__INTERNAL";
  match env::var(ENV_UNSHARE) {
    Ok(s) if s == "1" => return f().map(|()| true),
    Ok(_) | Err(VarError::NotPresent) => {}
    Err(e) => return Err(e.into()),
  }

  let mut command = unshare::Command::new(env::current_exe()?);
  command
    .args(&["--test", "--exact", "--show-output", "--test-threads=1", test_name])
    .stdin(unshare::Stdio::null())
    .stdout(unshare::Stdio::piped())
    .stderr(unshare::Stdio::null()) // libtest does 2>&1, so no stderr normally
    .env(ENV_UNSHARE, "1")
    .unshare([Namespace::Net].iter())
    .allow_setgroups(false)
    .set_id_maps(
      vec![UidMap { inside_uid: 0, outside_uid: Uid::effective().as_raw(), count: 1 }],
      vec![GidMap { inside_gid: 0, outside_gid: Gid::effective().as_raw(), count: 1 }],
    );

  let mut child = match command.spawn() {
    Ok(child) => child,
    Err(unshare::Error::Fork(_)) => return Ok(false),
    Err(e) => return Err(e.into()),
  };

  println!("+++++++++++++++++++++++++ ENTER UNSHARE +++++++++++++++++++++++++");
  for ele in std::io::BufReader::new(child.stdout.as_mut().unwrap()).lines() {
    let ele = ele?;
    println!("  {ele}");
  }
  println!("+++++++++++++++++++++++++ EXIT UNSHARE ++++++++++++++++++++++++++");

  let e = child.wait()?;
  if !e.success() {
    bail!("subprocess does not exit successfully")
  }
  Ok(true)
}
