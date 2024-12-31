use nix::unistd::Uid;
use tokio::net::TcpListener;

#[expect(unused)]
pub fn ensure_root() {
  assert!(
    Uid::effective().is_root(),
    "This test needs root (or an isolated namespace acting like root) to access \
      kernel network interface (rtnetlink, nftables, etc.). Please run the tests with \
      root, unshare(1) or jail(8) to test them.",
  );
}

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
