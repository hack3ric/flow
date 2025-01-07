use super::helpers::bird::ensure_bird_2;
use super::helpers::cli::{close_cli, run_cli_with_bird, CliGuard};
use super::helpers::kernel::rtnl::{create_dummy_link, get_ip_route, get_ip_rule, remove_link, route_msg_normalize};
use super::helpers::kernel::{ensure_loopback_up, ensure_root, pick_port};
use super::{TestEvent, BIRD_CONFIG_1};
use crate::args::Cli;
use crate::bgp::flow::Op;
use crate::integration_tests::helpers::kernel::linux::{get_nft_stmts, print_ip_route, print_ip_rule, print_nft_chain};
use crate::integration_tests::helpers::kernel::rtnl::make_ip_rule_mark;
use crate::kernel::nft::{make_limit, make_meta, make_payload_field, prefix_stmt, range_stmt, ACCEPT, DROP};
use clap::Parser;
use macro_rules_attribute::apply;
use nftables::expr::Expression::Number;
use nftables::expr::{self, MetaKey};
use nftables::stmt;
use rand::distributions::Alphanumeric;
use rand::Rng;
use rtnetlink::{IpVersion, RouteMessageBuilder};
use std::net::IpAddr;
use std::time::Duration;
use tokio::select;
use tokio::time::sleep;

#[apply(test_local!)]
async fn test_order() -> anyhow::Result<()> {
  let (name, (_g1, _g2, chans, _g3)) = run_kernel_test([
    "flow4 { dst 10.0.0.0/9; length > 1024; } { bgp_ext_community.add((unknown 0x8006, 0, 0)); }",
    "flow4 { dst 10.0.0.0/10; length > 1024; } { bgp_ext_community.add((unknown 0x8006, 0, 0x4c97a25c)); }",
    "flow6 { src fdfd::/128; next header 17; } { bgp_ext_community.add((unknown 0x800c, 0, 0)); }",
    "flow6 { dst fdfd::/16; } { bgp_ext_community.add((unknown 0x800c, 0, 0)); }",
  ])
  .await?;

  print_nft_chain(&name, &name).await?;

  let result = get_nft_stmts(&name, &name).await?;
  close_cli(chans).await;

  assert_eq!(result, [
    vec![
      prefix_stmt("daddr", "10.0.0.0/10".parse()?).unwrap(),
      range_stmt(make_payload_field("ip", "length"), &Op::gt(1024).into(), 0xffff)?.unwrap(),
      make_limit(true, 79500000., "bytes", "second"),
      DROP,
    ],
    vec![
      prefix_stmt("daddr", "10.0.0.0/10".parse()?).unwrap(),
      range_stmt(make_payload_field("ip", "length"), &Op::gt(1024).into(), 0xffff)?.unwrap(),
      ACCEPT,
    ],
    vec![
      prefix_stmt("daddr", "10.0.0.0/9".parse()?).unwrap(),
      range_stmt(make_payload_field("ip", "length"), &Op::gt(1024).into(), 0xffff)?.unwrap(),
      DROP,
    ],
    vec![prefix_stmt("daddr", "fdfd::/16".parse()?).unwrap(), DROP],
    vec![
      prefix_stmt("saddr", "fdfd::/128".parse()?).unwrap(),
      range_stmt(make_meta(MetaKey::L4proto), &Op::eq(17).into(), 0xff)?.unwrap(),
      DROP,
    ],
  ]);
  Ok(())
}

#[apply(test_local!)]
async fn test_redirect_to_ip() -> anyhow::Result<()> {
  let (conn, handle, _) = rtnetlink::new_connection()?;
  tokio::spawn(conn);

  let table = 0xffff0000;
  let fwmarks = [0xffff0000, 0xffff0001];
  let dummy_index = create_dummy_link(&handle, "10.128.128.254/24".parse()?).await?;
  let (name, (_g1, mut bird, chans, _g2)) = run_kernel_test([
    "flow4 { dst 172.20.0.0/16; } { bgp_ext_community.add((unknown 0x800c, 10.128.128.1, 0)); }",
    "flow4 { dst 172.21.0.0/16; } { bgp_ext_community.add((unknown 0x800c, 10.128.128.1, 0)); }",
  ])
  .await?;

  print_nft_chain(&name, &name).await?;
  print_ip_rule().await?;
  print_ip_route(table).await?;

  let nft_stmts = get_nft_stmts(&name, &name).await?;
  let ip_rules = get_ip_rule(&handle, IpVersion::V4).await?;
  let ip_routes = get_ip_route(&handle, IpVersion::V4, 10000).await?;
  close_cli(chans).await;
  bird.kill().await?;
  remove_link(&handle, dummy_index).await?;

  assert_eq!(nft_stmts, [vec![
    prefix_stmt("daddr", "172.20.0.0/16".parse()?).unwrap(),
    stmt::Statement::Mangle(stmt::Mangle { key: make_meta(expr::MetaKey::Mark), value: Number(fwmarks[0]) }),
    ACCEPT,
  ]]);

  let ip_rule_exp = make_ip_rule_mark(IpVersion::V4, 100, fwmarks[0], table);
  println!("> ip rule = {ip_rules:?}");
  println!("> exp = {ip_rule_exp:?}");
  assert!(ip_rules.contains(&ip_rule_exp));

  let mut ip_route_exp = RouteMessageBuilder::<IpAddr>::new()
    .table_id(table)
    .destination_prefix("172.20.0.0".parse()?, 16)?
    .output_interface(dummy_index)
    .gateway("10.128.128.1".parse()?)?
    .build();
  route_msg_normalize(&mut ip_route_exp);
  assert_eq!(ip_routes, [ip_route_exp]);

  Ok(())
}

async fn run_kernel_test(flows: impl IntoIterator<Item = &str>) -> anyhow::Result<(String, CliGuard)> {
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

  let (mut cli, mut bird, (mut events, close), g) = run_cli_with_bird(cli, &bird).await?;
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

  let guard = (cli, bird, (events, close), g);
  Ok((table_name, guard))
}
