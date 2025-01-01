use super::helpers::bird::{ensure_bird_2, ensure_bird_2_16};
use super::helpers::cli::run_cli_with_bird;
use super::helpers::kernel::{ensure_loopback_up, pick_port};
use super::{test_local, TestEvent};
use crate::args::Cli;
use crate::bgp::flow::Component::*;
use crate::bgp::flow::{Flowspec, Op};
use crate::bgp::route::{AsSegment, ExtCommunity, GlobalAdmin, Origin, RouteInfo, TrafficFilterAction};
use anyhow::Context;
use clap::Parser;
use macro_rules_attribute::apply;
use smallvec::{smallvec, smallvec_inline};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use tokio::select;
use tokio::time::sleep;

#[apply(test_local!)]
async fn test_flow() -> anyhow::Result<()> {
  run_flowspec_route_test([
    (
      "flow4 { dst 10.0.0.0/8; length > 1024; }",
      Flowspec::new_v4()
        .with(DstPrefix("10.0.0.0/8".parse()?, 0))?
        .with(PacketLen(Op::gt(1024).into()))?,
    ),
    (
      "flow4 { src 123.45.67.192/26; icmp type 3; icmp code >= 2 && < 13; }",
      Flowspec::new_v4()
        .with(SrcPrefix("123.45.67.192/26".parse()?, 0))?
        .with(IcmpType(Op::eq(3).into()))?
        .with(IcmpCode(Op::ge(2).and(Op::lt(13))))?,
    ),
    ("flow4 {}", Flowspec::new_v4()),
    (
      "flow6 { dst fec0:1122:3344:5566:7788:99aa:bbcc:ddee/128;
               tcp flags 0x03/0x0f && !0/0xff || 0x33/0x33;
               dport = 6000;
               fragment !is_fragment || !first_fragment; }",
      Flowspec::new_v6()
        .with(DstPrefix("fec0:1122:3344:5566:7788:99aa:bbcc:ddee/128".parse()?, 0))?
        .with(TcpFlags(
          Op::all(0x3).and(Op::not_any(0xc)).and(Op::any(0xff)).or(Op::all(0x33)),
        ))?
        .with(DstPort(Op::eq(6000).into()))?
        .with(Fragment(Op::not_any(0b10).or(Op::not_any(0b100))))?,
    ),
    (
      "flow6 { dst fd00::/8; label 0x8e5 || 0x8e6; }",
      Flowspec::new_v6()
        .with(DstPrefix("fd00::/8".parse()?, 0))?
        .with(FlowLabel(Op::eq(0x8e5).or(Op::eq(0x8e6))))?,
    ),
    ("flow6 {}", Flowspec::new_v6()),
  ])
  .await
}

#[apply(test_local!)]
async fn test_flow_attr() -> anyhow::Result<()> {
  use TrafficFilterAction::*;

  fn tfa_to_ext_comm(iter: impl IntoIterator<Item = TrafficFilterAction>) -> BTreeSet<ExtCommunity> {
    iter.into_iter().map(|x| x.into_ext_comm().left().unwrap()).collect()
  }

  let route_info_default = RouteInfo { origin: Origin::Igp, local_pref: Some(100), ..Default::default() };
  run_flowspec_test([
    (
      "flow4 { dst 10.0.0.0/8; length > 1024; } {
        bgp_path.prepend(114514);
        bgp_path.prepend(1919810);
        bgp_ext_community.add((unknown 0x8108, 1.1.1.1, 1234));
        bgp_ext_community.add((unknown 0x8006, 0, 0x453b8000));
        bgp_ext_community.add((unknown 0x800c, 172.20.0.1, 0));
      }",
      Flowspec::new_v4()
        .with(DstPrefix("10.0.0.0/8".parse()?, 0))?
        .with(PacketLen(Op::gt(1024).into()))?,
      RouteInfo {
        as_path: smallvec_inline![AsSegment::Sequence(smallvec![1919810, 114514])],
        ext_comm: tfa_to_ext_comm([
          RtRedirect { rt: GlobalAdmin::Ipv4("1.1.1.1".parse()?), value: 1234 },
          TrafficRateBytes { desc: 0, rate: 3e3 },
          RedirectToIp { ip: "172.20.0.1".parse()?, copy: false },
        ]),
        ..route_info_default.clone()
      },
    ),
    (
      "flow6 { dst ::1.1.1.1/128 offset 96; next header 17; } {
        bgp_ext_community.add((unknown 0x8007, 0, 3));
      }",
      Flowspec::new_v6()
        .with(DstPrefix("::1.1.1.1/128".parse()?, 96))?
        .with(Protocol(Op::eq(17).into()))?,
      RouteInfo {
        ext_comm: tfa_to_ext_comm([TrafficAction { terminal: false, sample: true }]),
        ..route_info_default
      },
    ),
  ])
  .await
}

#[apply(test_local!)]
async fn test_flow6_offset_bird_2_16() -> anyhow::Result<()> {
  ensure_bird_2_16();
  run_flowspec_route_test([
    (
      "flow6 { dst ::1:1234:5678:9800:0/104 offset 60; }",
      Flowspec::new_v6().with(DstPrefix("::1:1234:5678:9800:0/104".parse()?, 60))?,
    ),
    (
      "flow6 { src ::1:1234:5678:9800:0/104 offset 63; }",
      Flowspec::new_v6().with(SrcPrefix("::1:1234:5678:9800:0/104".parse()?, 63))?,
    ),
  ])
  .await
}

async fn run_flowspec_route_test(flows: impl IntoIterator<Item = (&str, Flowspec)>) -> anyhow::Result<()> {
  let route_info_default = RouteInfo { origin: Origin::Igp, local_pref: Some(100), ..Default::default() };
  let flows = flows.into_iter().map(|(v, k)| (k, (v, route_info_default.clone()))).collect();
  run_flowspec_test_inner(flows).await
}

async fn run_flowspec_test(flows: impl IntoIterator<Item = (&str, Flowspec, RouteInfo<'_>)>) -> anyhow::Result<()> {
  let flows = flows.into_iter().map(|(u, k, v)| (k, (u, v))).collect();
  run_flowspec_test_inner(flows).await
}

async fn run_flowspec_test_inner(mut flows: BTreeMap<Flowspec, (&str, RouteInfo<'_>)>) -> anyhow::Result<()> {
  const BIRD_FILE: &str = "\
router id 10.234.56.78;

flow4 table myflow4;
flow6 table myflow6;

protocol static f4 {
  flow4 { table myflow4; };
  @@FLOW4@@;
}

protocol static f6 {
  flow6 { table myflow6; };
  @@FLOW6@@;
}

protocol bgp flow_test {
  debug all;
  connect delay time 1;

  local ::1 port @@BIRD_PORT@@ as 65000;
  neighbor ::1 port @@FLOW_PORT@@ as 65000;
  multihop;

  flow4 { table myflow4; import none; export all; };
  flow6 { table myflow6; import none; export all; };
}";

  ensure_bird_2();
  ensure_loopback_up().await?;

  let (flow4, flow6) = flows.iter().fold((String::new(), String::new()), |(v4, v6), (k, v)| {
    if k.is_ipv4() {
      (v4 + "route " + v.0 + ";", v6)
    } else {
      (v4, v6 + "route " + v.0 + ";")
    }
  });

  let flow_port = pick_port().await?.to_string();
  let cli = Cli::try_parse_from([
    "flow",
    "run",
    "-v",
    "--dry-run",
    &format!("--bind=[::1]:{flow_port}"),
    "--local-as=65000",
    "--remote-as=65000",
  ])?;
  let bird = BIRD_FILE
    .replace("@@BIRD_PORT@@", &pick_port().await?.to_string())
    .replace("@@FLOW_PORT@@", &flow_port)
    .replace("@@FLOW4@@", &flow4)
    .replace("@@FLOW6@@", &flow6);

  let (mut cli, mut bird, mut events, close, _g) = run_cli_with_bird(cli, &bird).await?;

  let mut end_of_rib_count = 0;
  let mut visited = BTreeSet::new();
  let _state = 'outer: loop {
    select! {
      Some(event) = events.recv(), if !events.is_closed() => match event {
        TestEvent::EndOfRib(_afi, _safi) => {
          end_of_rib_count += 1;
          if end_of_rib_count >= 2 {
            let _ = close.send(());
            while let Some(event) = events.recv().await {
              if let TestEvent::Exit(state) = event {
                break 'outer state;
              }
            }
            panic!("no state received");
          }
        }
        TestEvent::Update(msg) => {
          for nlri in msg.nlri.into_iter().chain(msg.old_nlri) {
            let specs = nlri.into_flow().context("received NLRI other than flowspec")?;
            for spec in specs {
              if let Some((spec1, (_, info))) = flows.remove_entry(&spec) {
                visited.insert(spec1);
                assert_eq!(info, msg.route_info, "route info does not match for {spec}" );
              } else {
                assert!(visited.contains(&spec), "received duplicate flowspec: {spec}");
                panic!("received unknown flowspec: {spec}");
              }
            }
          }
        }
        TestEvent::Exit(_) => panic!("unexpected CLI exit event"),
      },
      _ = sleep(Duration::from_secs(10)) => panic!("timed out"),
      code = &mut cli => panic!("CLI exited early with code {}", code??),
      status = bird.wait() => panic!("BIRD exited early with {}", status?),
    }
  };

  assert!(flows.is_empty(), "some flowspecs not received: {flows:?}");
  Ok(())
}
