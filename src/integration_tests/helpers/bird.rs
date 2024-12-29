use anyhow::bail;
use std::borrow::Cow;
use std::ffi::OsStr;
use std::process::{Command, Stdio};
use std::sync::LazyLock;
use std::{env, io};
use version_compare::compare_to;

static BIRD_PATH: LazyLock<Cow<'static, OsStr>> = LazyLock::new(|| {
  env::var_os("FLOW_BIRD_PATH")
    .map(Cow::Owned)
    .unwrap_or(Cow::Borrowed("bird".as_ref()))
});

static BIRD_VERSION: LazyLock<Result<Option<String>, String>> = LazyLock::new(|| {
  let output = Command::new(&*BIRD_PATH).arg("--version").stdin(Stdio::null()).output();
  let mut stderr = match output {
    Ok(output) => output.stderr,
    Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
    Err(e) => return Err(e.to_string()),
  };
  const PREFIX: &[u8] = b"BIRD version ";
  if !stderr.starts_with(PREFIX) {
    return Err("invalid `bird --version` output".into());
  }
  let prefix_len = PREFIX.len() + if stderr[PREFIX.len()] == b'v' { 1 } else { 0 };
  let mut ver = stderr.split_off(prefix_len);
  ver.pop();
  String::from_utf8(ver).map(Some).map_err(|e| e.to_string())
});

fn bird_ver_ge(min_ver: &str) -> anyhow::Result<Option<bool>> {
  let Some(ver) = BIRD_VERSION.as_ref().map_err(anyhow::Error::msg)? else {
    return Ok(None);
  };
  compare_to(ver, min_ver, version_compare::Cmp::Ge)
    .map(Some)
    .map_err(|()| anyhow::Error::msg("invalid version number"))
}

#[doc(hidden)]
pub(crate) fn ensure_bird_ver_ge_internal(min_ver: &str) -> anyhow::Result<bool> {
  match bird_ver_ge(min_ver) {
    Ok(None) => {
      eprintln!(
        "executable '{}' missing, skipping this test",
        BIRD_PATH.to_string_lossy(),
      );
      Ok(false)
    }
    Ok(Some(false)) => {
      eprintln!("BIRD version less than {min_ver}, skipping this test");
      Ok(false)
    }
    Ok(Some(true)) => Ok(true),
    Err(e) => Err(e),
  }
}

macro_rules! ensure_bird_ver_ge {
  ($min_ver:expr) => {
    $crate::integration_tests::helpers::bird::ensure_bird_ver_ge!($min_ver, ())
  };
  ($min_ver:expr,$ret:expr) => {
    if !$crate::integration_tests::helpers::bird::ensure_bird_ver_ge_internal($min_ver)? {
      return Ok($ret);
    }
  };
}

pub(crate) use ensure_bird_ver_ge;

fn check_bird_ver(ver: &str, msg: &'static str) -> anyhow::Result<()> {
  match bird_ver_ge(ver) {
    Ok(None) => bail!(
      "BIRD not found, some tests will not run\n
        \n  \
        Do one of the following to suppress this warning:\n    \
          - Install BIRD under PATH\n    \
          - Specify FLOW_BIRD_PATH to point to BIRD executable\n    \
          - Skip this particular test (only when absolutely necessary)",
    ),
    Ok(Some(false)) => Err(anyhow::Error::msg(msg)),
    Ok(Some(true)) => Ok(()),
    Err(e) => Err(e.context("failed to get BIRD version")),
  }
}

#[test]
fn check_bird_2() -> anyhow::Result<()> {
  check_bird_ver(
    "2",
    "the BIRD in your system is the outdated 1.x version\n\
      \n  \
      Please update to BIRD 2.x to run the tests.",
  )
}

#[test]
#[ignore = "no BIRD 2.16 tests for now"]
fn check_bird_2_16() -> anyhow::Result<()> {
  check_bird_ver(
    "2.16",
    "the BIRD in your system is below the version of 2.16\n\
      \n  \
      BIRD version below 2.16 incorrectly implements Flowspec's IPv6 offset. Upgrade\n  \
      to BIRD 2.16, 3.x, or above to allow respective tests to run, or skip this\n  \
      particular test if such versions are not available.\n\
      \n  \
      See https://gitlab.nic.cz/labs/bird/-/commit/072821e55e2a3bd0fb3ffee309937592\n  \
      for more information.",
  )
}
