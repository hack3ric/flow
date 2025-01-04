use nftables::helper::DEFAULT_NFT;
use nftables::schema::{NfListObject, NfObject};
use nftables::stmt::Statement;
use nftables::types::NfFamily;
use nix::unistd::Uid;
use tokio::net::TcpListener;

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

pub async fn get_nft_stmts(table: &str, chain: &str) -> anyhow::Result<Vec<Vec<Statement<'static>>>> {
  let args = ["-ns", "list", "chain", "inet", table, chain];
  let chain_obj = nftables::helper::get_current_ruleset_with_args_async(DEFAULT_NFT, args)
    .await?
    .objects
    .into_owned();

  let rules = chain_obj.into_iter().filter_map(|x| {
    if let NfObject::ListObject(NfListObject::Rule(mut rule)) = x {
      rule.handle = None;
      Some(rule)
    } else {
      None
    }
  });
  assert!(rules
    .clone()
    .all(|r| r.family == NfFamily::INet && r.table == table && r.chain == chain));

  Ok(rules.map(|r| r.expr.into_owned()).collect())
}

pub async fn print_nft_chain(table: &str, chain: &str) -> anyhow::Result<()> {
  let output = tokio::process::Command::new("nft")
    .args(["-an", "list", "chain", "inet", table, chain])
    .output()
    .await?;
  println!("{}", String::from_utf8(output.stdout)?);
  Ok(())
}

pub async fn print_ip_rule() -> anyhow::Result<()> {
  let output = tokio::process::Command::new("ip").arg("rule").output().await?;
  println!("{}", String::from_utf8(output.stdout)?);
  Ok(())
}

pub async fn print_ip_route(table: u32) -> anyhow::Result<()> {
  let output = tokio::process::Command::new("ip")
    .args(["route", "show", "table", &table.to_string()])
    .output()
    .await?;
  println!("{}", String::from_utf8(output.stdout)?);
  Ok(())
}
