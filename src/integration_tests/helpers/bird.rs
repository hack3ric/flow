use anyhow::bail;
use std::borrow::Cow;
use std::ffi::OsStr;
use std::path::Path;
use std::process::Stdio;
use std::sync::LazyLock;
use std::{env, io};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use version_compare::compare_to;

static BIRD_PATH: LazyLock<Cow<'static, OsStr>> = LazyLock::new(|| {
  env::var_os("FLOW_BIRD_PATH")
    .map(Cow::Owned)
    .unwrap_or(Cow::Borrowed("bird".as_ref()))
});

static BIRD_VERSION: LazyLock<Result<Option<String>, String>> = LazyLock::new(|| {
  let output = std::process::Command::new(&*BIRD_PATH)
    .arg("--version")
    .stdin(Stdio::null())
    .output();
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

fn ensure_bird_ver(ver: &str, msg: &'static str) -> anyhow::Result<()> {
  match bird_ver_ge(ver) {
    Ok(None) => bail!(
      "BIRD not found\n\
        Please install BIRD under PATH, or specify FLOW_BIRD_PATH to point to \
        BIRD executable.",
    ),
    Ok(Some(false)) => Err(anyhow::Error::msg(msg)),
    Ok(Some(true)) => Ok(()),
    Err(e) => Err(e.context("failed to get BIRD version")),
  }
}

pub fn ensure_bird_2() -> anyhow::Result<()> {
  ensure_bird_ver(
    "2",
    "outdated BIRD version\n\
      The BIRD in your system is the outdated 1.x version. Please update to BIRD 2.x \
      to run the tests.",
  )
}

#[expect(unused)]
pub fn ensure_bird_2_16() -> anyhow::Result<()> {
  if env::var_os("FLOW_SKIP_BIRD_2_16_TESTS").is_some() {
    Ok(())
  } else {
    ensure_bird_ver(
      "2.16",
      "BIRD version below 2.16\n\
      BIRD version below 2.16 incorrectly implements Flowspec's IPv6 offset. Upgrade \
      to BIRD 2.16, 3.x, or above to allow respective tests to run.\n\
      See https://gitlab.nic.cz/labs/bird/-/commit/072821e55e2a3bd0fb3ffee309937592 \
      for more information.",
    )
  }
}

pub async fn run_bird(config_path: impl AsRef<Path>, sock_path: impl AsRef<Path>) -> anyhow::Result<Child> {
  let mut bird = Command::new(&*BIRD_PATH)
    .arg("-d")
    .args(["-c".as_ref(), config_path.as_ref().as_os_str()])
    .args(["-s".as_ref(), sock_path.as_ref().as_os_str()])
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .kill_on_drop(true)
    .spawn()?;

  let mut bird_stderr = BufReader::new(bird.stderr.take().unwrap());
  tokio::spawn(async move {
    let mut buf = String::new();
    while bird_stderr.read_line(&mut buf).await? != 0 {
      eprint!("{buf}");
      buf.clear();
    }
    anyhow::Ok(())
  });

  Ok(bird)
}
