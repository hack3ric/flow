use super::helpers::bird::ensure_bird_2;
use super::helpers::cli::{run_cli_with_bird, CliChild};
use super::helpers::kernel::{ensure_loopback_up, ensure_root, pick_port};
use super::{TestEvent, BIRD_CONFIG_1};
use crate::args::Cli;
use crate::bgp::flow::Op;
use crate::kernel::nft::{make_limit, make_meta, make_payload_field, prefix_stmt, range_stmt};
use async_tempfile::{TempDir, TempFile};
use clap::Parser;
use macro_rules_attribute::apply;
use nftables::expr::MetaKey;
use nftables::helper::DEFAULT_NFT;
use nftables::schema::{NfListObject, NfObject};
use nftables::stmt::Statement;
use nftables::types::NfFamily;
use rand::distributions::Alphanumeric;
use rand::Rng;
use std::time::Duration;
use tokio::process::Child;
use tokio::select;
use tokio::sync::oneshot;
use tokio::time::sleep;

#[apply(test_local!)]
async fn test_nftables() -> anyhow::Result<()> {
  let (name, _g) = run_kernel_test([
    "flow4 { dst 10.0.0.0/9; length > 1024; } { bgp_ext_community.add((unknown 0x8006, 0, 0x4c97a25c)); }",
    "flow6 { src fdfd::/128; next header 17; } { bgp_ext_community.add((unknown 0x800c, 0, 0)); }",
  ])
  .await?;

  let args = ["-ns", "list", "chain", "inet", &name, &name];
  let chain = nftables::helper::get_current_ruleset_with_args_async(DEFAULT_NFT, args)
    .await?
    .objects
    .into_owned();

  let rules = chain.into_iter().filter_map(|x| {
    if let NfObject::ListObject(NfListObject::Rule(mut rule)) = x {
      rule.handle = None;
      Some(rule)
    } else {
      None
    }
  });
  assert!(rules
    .clone()
    .all(|r| r.family == NfFamily::INet && r.table == name && r.chain == name));

  let stmts: Vec<_> = rules.map(|r| r.expr).collect();
  let stmts: Vec<_> = stmts.iter().map(|x| &x[..]).collect();
  assert_eq!(stmts, [
    &[
      prefix_stmt("daddr", "10.0.0.0/9".parse()?).unwrap(),
      range_stmt(make_payload_field("ip", "length"), &Op::gt(1024).into(), 0xffff)?.unwrap(),
      make_limit(true, 79500000., "bytes", "second"),
      Statement::Drop(None),
    ][..],
    &[
      prefix_stmt("daddr", "10.0.0.0/9".parse()?).unwrap(),
      range_stmt(make_payload_field("ip", "length"), &Op::gt(1024).into(), 0xffff)?.unwrap(),
      Statement::Accept(None),
    ][..],
    &[
      prefix_stmt("saddr", "fdfd::/128".parse()?).unwrap(),
      range_stmt(make_meta(MetaKey::L4proto), &Op::eq(17).into(), 0xff)?.unwrap(),
      Statement::Drop(None),
    ][..],
  ],);
  Ok(())
}

type Guard = (CliChild, Child, oneshot::Sender<()>, (TempFile, TempDir));

async fn run_kernel_test(flows: impl IntoIterator<Item = &str>) -> anyhow::Result<(String, Guard)> {
  ensure_bird_2();
  ensure_root();
  ensure_loopback_up().await?;

  let (flow4, flow6) = flows.into_iter().fold((String::new(), String::new()), |(v4, v6), str| {
    if str.starts_with("flow4") {
      (v4 + "route " + str + ";", v6)
    } else {
      (v4, v6 + "route " + str + ";")
    }
  });

  let table_name: String = "flow_test_"
    .chars()
    .chain(rand::thread_rng().sample_iter(&Alphanumeric).take(8).map(char::from))
    .collect();
  let flow_port = pick_port().await?.to_string();
  let cli = Cli::try_parse_from([
    "flow",
    "run",
    "-v",
    &format!("--bind=[::1]:{flow_port}"),
    "--local-as=65000",
    "--remote-as=65000",
    "--table",
    &table_name,
    "--chain",
    &table_name,
  ])?;
  let bird = BIRD_CONFIG_1
    .replace("@@BIRD_PORT@@", &pick_port().await?.to_string())
    .replace("@@FLOW_PORT@@", &flow_port)
    .replace("@@FLOW4@@", &flow4)
    .replace("@@FLOW6@@", &flow6);

  let (mut cli, mut bird, mut events, close, g) = run_cli_with_bird(cli, &bird).await?;
  let mut end_of_rib_count = 0;
  loop {
    select! {
      Some(event) = events.recv(), if !events.is_closed() => match event {
        TestEvent::EndOfRib(..) => {
          end_of_rib_count += 1;
          if end_of_rib_count >= 2 {
            break;
          }
        }
        TestEvent::Update(_) => {},
        TestEvent::Exit(_) => panic!("unexpected CLI exit event"),
      },
      _ = sleep(Duration::from_secs(10)) => panic!("timed out"),
      code = &mut cli => panic!("CLI exited early with code {}", code??),
      status = bird.wait() => panic!("BIRD exited early with {}", status?),
    }
  }

  let guard = (cli, bird, close, g);
  Ok((table_name, guard))
}
