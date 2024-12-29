use anyhow::bail;
use nix::unistd::Uid;
use tokio::net::TcpListener;

#[cfg(rtnetlink_supported)]
pub async fn ensure_loopback_up() -> anyhow::Result<()> {
  use rtnetlink::{LinkMessageBuilder, LinkUnspec};

  if !Uid::effective().is_root() {
    return Ok(());
  }
  let (conn, handle, _) = rtnetlink::new_connection()?;
  tokio::spawn(conn);
  handle
    .link()
    .set(LinkMessageBuilder::<LinkUnspec>::new().index(1).up().build())
    .execute()
    .await?;
  Ok(())
}

#[cfg(not(rtnetlink_supported))]
pub async fn ensure_loopback_up() -> anyhow::Result<()> {}

pub async fn pick_port() -> anyhow::Result<u16> {
  let sock = TcpListener::bind("127.0.0.1:0").await?;
  Ok(sock.local_addr()?.port())
}

#[test]
fn check_root() -> anyhow::Result<()> {
  if !Uid::effective().is_root() {
    bail!(
      "effective user not root\n\
        \n  \
        Some tests need root to access kernel interface (rtnetlink, nftables, etc.), and\n  \
        are skipped when run with normal users.\n\
        \n  \
        Please run the tests (again) with root or unshare to test them, or suppress this\n  \
        message by skipping this particular test.",
    )
  }
  Ok(())
}
