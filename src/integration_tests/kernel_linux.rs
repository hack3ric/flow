use super::helpers::bird::ensure_bird_2;
use super::helpers::cli::{close_cli, run_cli_with_bird, run_cli_with_exabgp, CliGuard};
use super::helpers::kernel::rtnl::{create_dummy_link, get_ip_route, get_ip_rule, remove_link, route_msg_normalize};
use super::helpers::kernel::{ensure_loopback_up, ensure_root, pick_port};
use super::{TestEvent, BIRD_CONFIG_1, EXABGP_CONFIG_1};
use crate::args::Cli;
use crate::bgp::flow::Op;
use crate::integration_tests::helpers::kernel::linux::{get_nft_stmts, print_ip_route, print_ip_rule, print_nft_chain};
use crate::integration_tests::helpers::kernel::rtnl::make_ip_rule_mark;
use crate::kernel::nft::{make_limit, make_meta, make_payload_field, prefix_stmt, range_stmt, ACCEPT, DROP};
use clap::Parser;
use itertools::Itertools;
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

  let table_index = 10000;
  let dummy_index = create_dummy_link(&handle, "10.128.128.254/24".parse()?).await?;
  let (name, (_g1, bird, chans, _g2)) = run_kernel_test([
    "flow4 { dst 172.20.0.0/16; } { bgp_ext_community.add((unknown 0x800c, 10.128.128.1, 0)); }",
    "flow4 { dst 172.21.0.0/16; } { bgp_ext_community.add((unknown 0x800c, 10.128.128.1, 0)); }",
  ])
  .await?;

  print_nft_chain(&name, &name).await?;
  print_ip_rule(false).await?;
  print_ip_route(false, table_index).await?;

  let ip_rules = get_ip_rule(&handle, IpVersion::V4).await?;
  let ip_routes = get_ip_route(&handle, IpVersion::V4, table_index).await?;
  let nft_stmts = get_nft_stmts(&name, &name).await?;
  close_cli(chans).await;
  drop(bird);
  remove_link(&handle, dummy_index).await?;

  assert_eq!(nft_stmts, [
    vec![
      prefix_stmt("daddr", "172.20.0.0/16".parse()?).unwrap(),
      stmt::Statement::Mangle(stmt::Mangle { key: make_meta(expr::MetaKey::Mark), value: Number(table_index) }),
      ACCEPT,
    ],
    vec![
      prefix_stmt("daddr", "172.21.0.0/16".parse()?).unwrap(),
      stmt::Statement::Mangle(stmt::Mangle { key: make_meta(expr::MetaKey::Mark), value: Number(table_index) }),
      ACCEPT,
    ]
  ]);

  let ip_rule_exp = make_ip_rule_mark(IpVersion::V4, 100, table_index, table_index);
  println!("> ip rule = {ip_rules:?}");
  println!("> exp = {ip_rule_exp:?}");
  assert!(ip_rules.contains(&ip_rule_exp));

  let mut ip_routes_exp = [
    RouteMessageBuilder::<IpAddr>::new()
      .table_id(table_index)
      .destination_prefix("172.20.0.0".parse()?, 16)?
      .output_interface(dummy_index)
      .gateway("10.128.128.1".parse()?)?
      .build(),
    RouteMessageBuilder::<IpAddr>::new()
      .table_id(table_index)
      .destination_prefix("172.21.0.0".parse()?, 16)?
      .output_interface(dummy_index)
      .gateway("10.128.128.1".parse()?)?
      .build(),
  ];
  ip_routes_exp.iter_mut().for_each(route_msg_normalize);
  assert_eq!(ip_routes, ip_routes_exp);

  Ok(())
}

#[apply(test_local!)]
async fn test_redirect_to_ipv6() -> anyhow::Result<()> {
  let (conn, handle, _) = rtnetlink::new_connection()?;
  tokio::spawn(conn);

  let table_index = 10000;
  let dummy_index = create_dummy_link(&handle, "fc64::1/64".parse()?).await?;
  let (name, (_g1, exabgp, chans, _g2)) = run_kernel_test_exabgp([
    "match { destination fc00::/16; } then { redirect-to-nexthop-ietf fc64::ffff; }",
    "match { destination fc65:6565::/32; } then { redirect-to-nexthop-ietf fc64::2333; }",
  ])
  .await?;

  print_nft_chain(&name, &name).await?;
  print_ip_rule(true).await?;
  print_ip_route(true, table_index).await?;

  let ip_rules = get_ip_rule(&handle, IpVersion::V6).await?;
  let ip_routes = get_ip_route(&handle, IpVersion::V6, table_index).await?;
  let nft_stmts = get_nft_stmts(&name, &name).await?;
  close_cli(chans).await;
  drop(exabgp);
  remove_link(&handle, dummy_index).await?;

  assert_eq!(nft_stmts, [
    vec![
      prefix_stmt("daddr", "fc65:6565::/32".parse()?).unwrap(),
      stmt::Statement::Mangle(stmt::Mangle { key: make_meta(expr::MetaKey::Mark), value: Number(table_index) }),
      ACCEPT,
    ],
    vec![
      prefix_stmt("daddr", "fc00::/16".parse()?).unwrap(),
      stmt::Statement::Mangle(stmt::Mangle { key: make_meta(expr::MetaKey::Mark), value: Number(table_index) }),
      ACCEPT,
    ],
  ]);

  let ip_rule_exp = make_ip_rule_mark(IpVersion::V6, 100, table_index, table_index);
  println!("> ip rule = {ip_rules:?}");
  println!("> exp = {ip_rule_exp:?}");
  assert!(ip_rules.contains(&ip_rule_exp));

  let mut ip_routes_exp = [
    RouteMessageBuilder::<IpAddr>::new()
      .table_id(table_index)
      .destination_prefix("fc00::".parse()?, 16)?
      .output_interface(dummy_index)
      .gateway("fc64::ffff".parse()?)?
      .build(),
    RouteMessageBuilder::<IpAddr>::new()
      .table_id(table_index)
      .destination_prefix("fc65:6565::".parse()?, 32)?
      .output_interface(dummy_index)
      .gateway("fc64::2333".parse()?)?
      .build(),
  ];
  ip_routes_exp.iter_mut().for_each(route_msg_normalize);
  assert_eq!(ip_routes, ip_routes_exp);

  Ok(())
}

// TODO: test IPv4 with IPv6 nexthop

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

  let (table_name, flow_port, cli) = prepare_kernel_test().await?;
  let bird = BIRD_CONFIG_1
    .replace("@@BIRD_PORT@@", &pick_port().await?.to_string())
    .replace("@@FLOW_PORT@@", &flow_port.to_string())
    .replace("@@FLOW4@@", &flow4)
    .replace("@@FLOW6@@", &flow6);

  let guard = run_kernel_test_common(run_cli_with_bird(cli, &bird).await?).await?;
  Ok((table_name, guard))
}

async fn run_kernel_test_exabgp(flows: impl IntoIterator<Item = &str>) -> anyhow::Result<(String, CliGuard)> {
  // ensure_exabgp();
  ensure_root();
  ensure_loopback_up().await?;

  let flows = flows.into_iter().map(|x| format!("route {{ {x} }}")).join("\n");

  let (table_name, port, cli) = prepare_kernel_test().await?;
  let daemon = EXABGP_CONFIG_1.replace("@@FLOWS@@", &flows);

  let guard = run_kernel_test_common(run_cli_with_exabgp(cli, &daemon, port).await?).await?;
  Ok((table_name, guard))
}

async fn prepare_kernel_test() -> anyhow::Result<(String, u16, Cli)> {
  let table_name: String = "flow_test_"
    .chars()
    .chain(rand::thread_rng().sample_iter(&Alphanumeric).take(8).map(char::from))
    .collect();
  let port = pick_port().await?;
  let cli = Cli::try_parse_from([
    "flow",
    "run",
    "-v",
    &format!("--bind=[::1]:{port}"),
    "--local-as=65000",
    "--remote-as=65000",
    "--table",
    &table_name,
    "--chain",
    &table_name,
  ])?;
  Ok((table_name, port, cli))
}

async fn run_kernel_test_common(g: CliGuard) -> anyhow::Result<CliGuard> {
  let (mut cli, mut daemon, (mut events, close), g) = g;
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
      status = daemon.wait() => panic!("BIRD exited early with {}", status?),
    }
  }
  Ok((cli, daemon, (events, close), g))
}
