use nftables::helper::DEFAULT_NFT;
use nftables::schema::{NfListObject, NfObject};
use nftables::stmt::Statement;
use nftables::types::NfFamily;

pub async fn print_nft_chain(table: &str, chain: &str) -> anyhow::Result<()> {
  let output = tokio::process::Command::new("nft")
    .args(["-an", "list", "chain", "inet", table, chain])
    .output()
    .await?;
  println!("{}", String::from_utf8(output.stdout)?);
  Ok(())
}

pub async fn print_ip_rule(v6: bool) -> anyhow::Result<()> {
  let output = tokio::process::Command::new("ip")
    .arg(if v6 { "-6" } else { "-4" })
    .arg("rule")
    .output()
    .await?;
  println!("{}", String::from_utf8(output.stdout)?);
  Ok(())
}

pub async fn print_ip_route(v6: bool, table: u32) -> anyhow::Result<()> {
  let output = tokio::process::Command::new("ip")
    .arg(if v6 { "-6" } else { "-4" })
    .args(["route", "show", "table", &table.to_string()])
    .output()
    .await?;
  println!("{}", String::from_utf8(output.stdout)?);
  Ok(())
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
