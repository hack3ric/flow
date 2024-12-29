use anyhow::bail;
use nix::unistd::Uid;

#[test]
fn check_root() -> anyhow::Result<()> {
  if !Uid::effective().is_root() {
    bail!(
      "effective user not root\n\
        \n  \
        Some tests need root to access kernel interface (rtnetlink, nftables, etc.), and\n  \
        are skipped when run with normal users.\n\
        \n  \
        Please run the tests (again) with root or unshare to test them:\n  \
        `CARGO_TARGET_<triple>_RUNNER='unshare -rn' cargo test`, or suppress this\n  \
        message by skipping this particular test.",
    )
  }
  Ok(())
}
