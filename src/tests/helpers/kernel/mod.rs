#[cfg(linux)]
mod linux;

#[cfg(linux)]
use linux as platform_specific;

#[doc(hidden)]
pub(crate) use platform_specific::run_unshare_internal;

use anyhow::bail;
use function_name::named;
use nix::unistd::Uid;
use std::future::Future;

#[doc(hidden)]
pub(crate) fn run_unshare_f(test_name: &str, f: impl FnOnce() -> anyhow::Result<()>) -> anyhow::Result<()> {
  match run_unshare_internal(test_name, f) {
    Ok(false) => {
      eprintln!("seems environment does not support unshare, skipping this test");
      Ok(())
    }
    Ok(true) => Ok(()),
    Err(e) => Err(e),
  }
}

#[expect(unused)]
#[doc(hidden)]
pub(crate) fn run_unshare_async_f<F, Fut>(test_name: &str, f: F) -> anyhow::Result<()>
where
  F: FnOnce() -> Fut,
  Fut: Future<Output = anyhow::Result<()>>,
{
  run_unshare_f(test_name, || {
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

#[expect(unused)]
macro_rules! run_unshare {
  ($f:expr) => {
    $crate::tests::helpers::kernel::run_unshare_f($crate::tests::helpers::kernel::test_path!(), $f)
  };
}

#[expect(unused)]
macro_rules! run_unshare_async {
  ($f:expr) => {
    $crate::tests::helpers::kernel::run_unshare_async_f($crate::tests::helpers::kernel::test_path!(), $f)
  };
}

#[expect(unused)]
pub(crate) use run_unshare;
#[expect(unused)]
pub(crate) use run_unshare_async;

#[test]
#[cfg_attr(unshare_supported, ignore = "no tests requiring root; for now we use unshare only")]
#[cfg_attr(not(unshare_supported), ignore = "no tests requiring root")]
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

#[cfg(unshare_supported)]
#[test]
#[named]
fn check_unshare() -> anyhow::Result<()> {
  if !run_unshare_internal(test_path!(), || {
    assert!(Uid::effective().is_root(), "effective UID not root inside unshare");
    Ok(())
  })? {
    bail!(
      "unshare not supported\n\
        \n  \
        This may be because the test is running in a qemu-user environment, the kernel\n  \
        does not have/enable support for namespaces, or is unimplemented. In such cases,\n  \
        please skip this particular test to suppress this warning.",
    )
  }
  Ok(())
}
