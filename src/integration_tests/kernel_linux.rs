use super::helpers::bird::ensure_bird_2;
use super::helpers::cli::{CliGuard, close_cli, run_cli_with_bird, run_cli_with_exabgp};
use super::helpers::kernel::rtnl::{create_dummy_link, get_ip_route, get_ip_rule, remove_link, route_msg_normalize};
use super::helpers::kernel::{ensure_loopback_up, ensure_root, pick_port};
use super::{BIRD_CONFIG_1, EXABGP_CONFIG_1, TestEvent};
use crate::args::Cli;
use crate::bgp::flow::Op;
use crate::integration_tests::helpers::kernel::linux::{get_nft_stmts, print_ip_route, print_ip_rule, print_nft_chain};
use crate::integration_tests::helpers::kernel::rtnl::make_ip_rule_mark;
use crate::kernel::nft::{
  ACCEPT, DROP, make_limit, make_meta, make_payload_field, mangle_stmt, prefix_stmt, range_stmt,
};
use crate::net::IpPrefix;
use clap::Parser;
use itertools::Itertools;
use macro_rules_attribute::apply;
use nftables::expr::Expression::Number;
use nftables::expr::{self, MetaKey};
use rand::Rng;
use rand::distr::Alphanumeric;
use rtnetlink::packet_route::route::{RouteAttribute, RouteType};
use rtnetlink::{IpVersion, RouteMessageBuilder};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tokio::select;
use tokio::time::sleep;

#[apply(test_local!)]
async fn test_order() -> anyhow::Result<()> {
  let (name, (_g1, _g2, chans, _g3)) = run_kernel_test_bird(0xffff0000, [
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

  let table_id = 0xffff0001;
  let dummy_id = create_dummy_link(&handle, "10.128.128.254/24".parse()?).await?;
  let (name, (_g1, bird, chans, _g2)) = run_kernel_test_bird(table_id, [
    "flow4 { dst 172.20.0.0/16; } { bgp_ext_community.add((unknown 0x000c, 10.128.128.1, 0)); }",
    "flow4 { dst 172.21.0.0/16; } { bgp_ext_community.add((unknown 0x000c, 10.128.128.1, 0)); }",
  ])
  .await?;

  print_nft_chain(&name, &name).await?;
  print_ip_rule(false).await?;
  print_ip_route(false, table_id).await?;

  let nft_stmts = get_nft_stmts(&name, &name).await?;
  let ip_rules = get_ip_rule(&handle, IpVersion::V4).await?;
  let ip_routes = get_ip_route(&handle, IpVersion::V4, table_id).await?;
  close_cli(chans).await;
  drop(bird);
  remove_link(&handle, dummy_id).await?;

  assert_eq!(nft_stmts, [
    vec![
      prefix_stmt("daddr", "172.20.0.0/16".parse()?).unwrap(),
      mangle_stmt(make_meta(expr::MetaKey::Mark), Number(table_id)),
      ACCEPT,
    ],
    vec![
      prefix_stmt("daddr", "172.21.0.0/16".parse()?).unwrap(),
      mangle_stmt(make_meta(expr::MetaKey::Mark), Number(table_id)),
      ACCEPT,
    ]
  ]);

  let ip_rule_exp = make_ip_rule_mark(IpVersion::V4, 100, table_id, table_id);
  println!("> ip rule = {ip_rules:?}");
  println!("> exp = {ip_rule_exp:?}");
  assert!(ip_rules.contains(&ip_rule_exp));

  let mut ip_routes_exp = [
    RouteMessageBuilder::<Ipv4Addr>::new()
      .table_id(table_id)
      .destination_prefix("172.20.0.0".parse()?, 16)
      .output_interface(dummy_id)
      .gateway("10.128.128.1".parse()?)
      .build(),
    RouteMessageBuilder::<Ipv4Addr>::new()
      .table_id(table_id)
      .destination_prefix("172.21.0.0".parse()?, 16)
      .output_interface(dummy_id)
      .gateway("10.128.128.1".parse()?)
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

  let table_id = 0xffff0002;
  let dummy_id = create_dummy_link(&handle, "fc64::1/64".parse()?).await?;
  let (name, (_g1, exabgp, chans, _g2)) = run_kernel_test_exabgp(table_id, [
    "match { destination fc00::/16; } then { redirect-to-nexthop-ietf fc64::ffff; }",
    "match { destination fc65:6565::/32; } then { redirect-to-nexthop-ietf fc64::2333; }",
  ])
  .await?;

  print_nft_chain(&name, &name).await?;
  print_ip_rule(true).await?;
  print_ip_route(true, table_id).await?;

  let nft_stmts = get_nft_stmts(&name, &name).await?;
  let ip_rules = get_ip_rule(&handle, IpVersion::V6).await?;
  let ip_routes = get_ip_route(&handle, IpVersion::V6, table_id).await?;
  close_cli(chans).await;
  drop(exabgp);
  remove_link(&handle, dummy_id).await?;

  assert_eq!(nft_stmts, [
    vec![
      prefix_stmt("daddr", "fc65:6565::/32".parse()?).unwrap(),
      mangle_stmt(make_meta(expr::MetaKey::Mark), Number(table_id)),
      ACCEPT,
    ],
    vec![
      prefix_stmt("daddr", "fc00::/16".parse()?).unwrap(),
      mangle_stmt(make_meta(expr::MetaKey::Mark), Number(table_id)),
      ACCEPT,
    ],
  ]);

  let ip_rule_exp = make_ip_rule_mark(IpVersion::V6, 100, table_id, table_id);
  println!("> ip rule = {ip_rules:?}");
  println!("> exp = {ip_rule_exp:?}");
  assert!(ip_rules.contains(&ip_rule_exp));

  let mut ip_routes_exp = [
    RouteMessageBuilder::<Ipv6Addr>::new()
      .table_id(table_id)
      .destination_prefix("fc00::".parse()?, 16)
      .output_interface(dummy_id)
      .gateway("fc64::ffff".parse()?)
      .build(),
    RouteMessageBuilder::<Ipv6Addr>::new()
      .table_id(table_id)
      .destination_prefix("fc65:6565::".parse()?, 32)
      .output_interface(dummy_id)
      .gateway("fc64::2333".parse()?)
      .build(),
  ];
  ip_routes_exp.iter_mut().for_each(route_msg_normalize);
  assert_eq!(ip_routes, ip_routes_exp);

  Ok(())
}

#[apply(test_local!)]
async fn test_ipv4_redirect_to_ipv6() -> anyhow::Result<()> {
  let (conn, handle, _) = rtnetlink::new_connection()?;
  tokio::spawn(conn);

  let table_id = 0xffff0003;
  let dummy_id = create_dummy_link(&handle, "fc65::1/64".parse()?).await?;
  let (name, (_g1, exabgp, chans, _g2)) = run_kernel_test_exabgp(table_id, [
    "match { destination 172.17.254.192/26; } then { redirect-to-nexthop-ietf fc65::ffff; }",
    "match { destination 192.0.2.0/27; } then { redirect-to-nexthop-ietf fc65::2333; }",
  ])
  .await?;

  print_nft_chain(&name, &name).await?;
  print_ip_rule(false).await?;
  print_ip_route(false, table_id).await?;

  let nft_stmts = get_nft_stmts(&name, &name).await?;
  let ip_rules = get_ip_rule(&handle, IpVersion::V4).await?;
  let ip_routes = get_ip_route(&handle, IpVersion::V4, table_id).await?;
  close_cli(chans).await;
  drop(exabgp);
  remove_link(&handle, dummy_id).await?;

  assert_eq!(nft_stmts, [
    vec![
      prefix_stmt("daddr", "192.0.2.0/27".parse()?).unwrap(),
      mangle_stmt(make_meta(expr::MetaKey::Mark), Number(table_id)),
      ACCEPT,
    ],
    vec![
      prefix_stmt("daddr", "172.17.254.192/26".parse()?).unwrap(),
      mangle_stmt(make_meta(expr::MetaKey::Mark), Number(table_id)),
      ACCEPT,
    ],
  ]);

  let ip_rule_exp = make_ip_rule_mark(IpVersion::V4, 100, table_id, table_id);
  println!("> ip rule = {ip_rules:?}");
  println!("> exp = {ip_rule_exp:?}");
  assert!(ip_rules.contains(&ip_rule_exp));

  let mut ip_routes_exp = [
    RouteMessageBuilder::<Ipv4Addr>::new()
      .table_id(table_id)
      .destination_prefix("172.17.254.192".parse()?, 26)
      .output_interface(dummy_id)
      .gateway("fc65::ffff".parse()?)
      .build(),
    RouteMessageBuilder::<Ipv4Addr>::new()
      .table_id(table_id)
      .destination_prefix("192.0.2.0".parse()?, 27)
      .output_interface(dummy_id)
      .gateway("fc65::2333".parse()?)
      .build(),
  ];
  ip_routes_exp.iter_mut().for_each(route_msg_normalize);
  assert_eq!(ip_routes, ip_routes_exp);

  Ok(())
}

#[apply(test_local!)]
async fn test_unreachable_routes() -> anyhow::Result<()> {
  let (conn, handle, _) = rtnetlink::new_connection()?;
  tokio::spawn(conn);

  let table_id = 0xffff0004;
  let unreach_prefixes = ["192.0.2.0/24", "fc99::/64"];
  let unreach_msgs: Vec<_> = unreach_prefixes
    .into_iter()
    .map(|p| {
      let p = p.parse::<IpPrefix>().unwrap();
      RouteMessageBuilder::<IpAddr>::new()
        .destination_prefix(p.prefix(), p.len())
        .unwrap()
        .kind(RouteType::Unreachable)
        .build()
    })
    .collect();
  for msg in unreach_msgs.iter().cloned() {
    handle.route().add(msg).execute().await?;
  }

  let (name, (_g1, exabgp, chans, _g2)) = run_kernel_test_exabgp(table_id, [
    "match { destination 172.17.254.192/26; } then { redirect-to-nexthop-ietf 192.0.2.128; }",
    "match { destination 192.0.2.0/27; } then { redirect-to-nexthop-ietf fc99::2333; }",
    "match { destination fc42::/32; } then { redirect-to-nexthop-ietf fc99::6666; }",
  ])
  .await?;

  print_nft_chain(&name, &name).await?;
  print_ip_rule(false).await?;
  print_ip_rule(true).await?;
  print_ip_route(false, 254).await?;
  print_ip_route(true, 254).await?;
  print_ip_route(false, table_id).await?;
  print_ip_route(true, table_id).await?;

  let nft_stmts = get_nft_stmts(&name, &name).await?;
  let ip_rules = [
    get_ip_rule(&handle, IpVersion::V4).await?,
    get_ip_rule(&handle, IpVersion::V6).await?,
  ];
  let ip_routes = [
    get_ip_route(&handle, IpVersion::V4, table_id).await?,
    get_ip_route(&handle, IpVersion::V6, table_id).await?,
  ];
  let ip_rules: Vec<_> = ip_rules.into_iter().flatten().collect();
  let ip_routes: Vec<_> = ip_routes.into_iter().flatten().collect();
  close_cli(chans).await;
  drop(exabgp);
  for msg in unreach_msgs {
    handle.route().del(msg).execute().await?;
  }

  assert_eq!(nft_stmts, [
    vec![
      prefix_stmt("daddr", "192.0.2.0/27".parse()?).unwrap(),
      mangle_stmt(make_meta(expr::MetaKey::Mark), Number(table_id)),
      ACCEPT,
    ],
    vec![
      prefix_stmt("daddr", "172.17.254.192/26".parse()?).unwrap(),
      mangle_stmt(make_meta(expr::MetaKey::Mark), Number(table_id)),
      ACCEPT,
    ],
    vec![
      prefix_stmt("daddr", "fc42::/32".parse()?).unwrap(),
      mangle_stmt(make_meta(expr::MetaKey::Mark), Number(table_id)),
      ACCEPT,
    ],
  ]);

  let ip_rules_exp: Vec<_> = [IpVersion::V4, IpVersion::V6]
    .into_iter()
    .map(|x| make_ip_rule_mark(x, 100, table_id, table_id))
    .collect();
  println!("> ip rule = {ip_rules:?}");
  println!("> exp = {ip_rules_exp:?}");
  assert!(ip_rules_exp.iter().all(|x| ip_rules.contains(x)));

  let ip_routes_exp = ["172.17.254.192/26", "192.0.2.0/27", "fc42::/32"];
  let mut ip_routes_exp: Vec<_> = ip_routes_exp
    .into_iter()
    .map(|prefix| {
      let prefix = prefix.parse::<IpPrefix>().unwrap();
      let mut msg = RouteMessageBuilder::<IpAddr>::new()
        .kind(RouteType::Unreachable)
        .table_id(table_id)
        .destination_prefix(prefix.prefix(), prefix.len())
        .unwrap()
        .build();
      if prefix.is_ipv6() {
        msg.attributes.push(RouteAttribute::Oif(1));
      }
      msg
    })
    .collect();
  ip_routes_exp.iter_mut().for_each(route_msg_normalize);
  assert_eq!(ip_routes, ip_routes_exp);

  Ok(())
}

// TODO: test IPv6 offset
// TODO: test prefix overlap
// TODO: test rtnetlink listen to network changes

async fn run_kernel_test_bird(
  init_table_id: u32,
  flows: impl IntoIterator<Item = &str>,
) -> anyhow::Result<(String, CliGuard)> {
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

  let (table_name, flow_port, cli) = prepare_kernel_test(init_table_id).await?;
  let bird = BIRD_CONFIG_1
    .replace("@@BIRD_PORT@@", &pick_port().await?.to_string())
    .replace("@@FLOW_PORT@@", &flow_port.to_string())
    .replace("@@FLOW4@@", &flow4)
    .replace("@@FLOW6@@", &flow6);

  let guard = run_kernel_test_common(run_cli_with_bird(cli, &bird).await?).await?;
  Ok((table_name, guard))
}

async fn run_kernel_test_exabgp(
  init_table_id: u32,
  flows: impl IntoIterator<Item = &str>,
) -> anyhow::Result<(String, CliGuard)> {
  // ensure_exabgp();
  ensure_root();
  ensure_loopback_up().await?;

  let flows = flows.into_iter().map(|x| format!("route {{ {x} }}")).join("\n");

  let (table_name, port, cli) = prepare_kernel_test(init_table_id).await?;
  let daemon = EXABGP_CONFIG_1.replace("@@FLOWS@@", &flows);

  let guard = run_kernel_test_common(run_cli_with_exabgp(cli, &daemon, port).await?).await?;
  Ok((table_name, guard))
}

async fn prepare_kernel_test(init_table_id: u32) -> anyhow::Result<(String, u16, Cli)> {
  let table_name: String = "flow_test_"
    .chars()
    .chain(rand::rng().sample_iter(&Alphanumeric).take(8).map(char::from))
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
    "--init-table-id",
    &init_table_id.to_string(),
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
