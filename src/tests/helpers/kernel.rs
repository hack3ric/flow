use anyhow::bail;
use function_name::named;
use nix::unistd::{Gid, Uid};
use std::env::VarError;
use std::io::BufRead;
use std::{env, future::Future};
use unshare::{GidMap, Namespace, UidMap};

#[doc(hidden)]
pub(crate) fn run_unshare_internal(test_name: &str, f: impl FnOnce() -> anyhow::Result<()>) -> anyhow::Result<()> {
  const ENV_UNSHARE: &str = "FLOW_UNSHARE__INTERNAL";
  match env::var(ENV_UNSHARE) {
    Ok(s) if s == "1" => return f(),
    Ok(_) | Err(VarError::NotPresent) => {}
    Err(e) => return Err(e.into()),
  }

  let mut child = unshare::Command::new(env::current_exe()?)
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
    )
    .spawn()?;

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
  Ok(())
}

#[expect(unused)]
#[doc(hidden)]
pub(crate) fn run_unshare_async_internal<F, Fut>(test_name: &str, f: F) -> anyhow::Result<()>
where
  F: FnOnce() -> Fut,
  Fut: Future<Output = anyhow::Result<()>>,
{
  run_unshare_internal(test_name, || {
    tokio::runtime::Builder::new_current_thread()
      .enable_all()
      .build()?
      .block_on(f())
  })
}

macro_rules! test_path {
  () => {{
    let t = concat!(module_path!(), "::", function_name!());
    t.split_once("::").map(|x| x.1).unwrap_or(t)
  }};
}

#[doc(hidden)]
pub(crate) use test_path;

macro_rules! run_unshare {
  ($f:expr) => {
    $crate::tests::helpers::kernel::run_unshare_internal($crate::tests::helpers::kernel::test_path!(), $f)
  };
}

#[expect(unused)]
macro_rules! run_unshare_async {
  ($f:expr) => {
    $crate::tests::helpers::kernel::run_unshare_async_internal($crate::tests::helpers::kernel::test_path!(), $f)
  };
}

pub(crate) use run_unshare;
#[expect(unused)]
pub(crate) use run_unshare_async;

#[test]
#[named]
fn test_unshare_subprocess() -> anyhow::Result<()> {
  run_unshare!(|| {
    eprintln!("Current effective UID: {}", Uid::effective().is_root());
    Ok(())
  })
}

#[test]
#[ignore = "no tests requiring root; for now we use unshare only"]
fn check_root() -> anyhow::Result<()> {
  if !Uid::effective().is_root() {
    bail!(
      "effective user not root\n\
        \n  \
        Some tests need root to access kernel interface (netns, rtnetlink, nftables,\n  \
        etc.), and are skipped when run with normal users.\n\
        \n  \
        Please run the tests (again) with root to test them:\n  \
        `CARGO_TARGET_<triple>_RUNNER='sudo -E' cargo test`, or suppress this message by\n  \
        skipping this particular test.",
    )
  }
  Ok(())
}
