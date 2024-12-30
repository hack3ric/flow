use super::helpers::bird::ensure_bird_2;
use super::helpers::cli::run_cli_with_bird;
use super::helpers::kernel::{ensure_loopback_up, pick_port};
use super::{test_local, TestEvent};
use crate::args::Cli;
use crate::bgp::flow::Component::*;
use crate::bgp::flow::{Flowspec, Op};
use anyhow::{bail, Context};
use clap::Parser;
use macro_rules_attribute::apply;
use map_macro::btree_map;
use std::collections::BTreeSet;
use std::time::Duration;
use tokio::select;
use tokio::time::sleep;

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

#[apply(test_local!)]
async fn test_routes() -> anyhow::Result<()> {
  ensure_bird_2()?;
  ensure_loopback_up().await?;

  let mut flows = btree_map! {
    Flowspec::new_v4()
      .with(DstPrefix("10.0.0.0/8".parse()?, 0))?
      .with(PacketLen(Op::gt(1024).into()))?
    => "flow4 { dst 10.0.0.0/8; length > 1024; }",

    Flowspec::new_v4()
      .with(SrcPrefix("123.45.67.192/26".parse()?, 0))?
      .with(IcmpType(Op::eq(3).into()))?
      .with(IcmpCode(Op::ge(2).and(Op::lt(13))))?
    => "flow4 { src 123.45.67.192/26; icmp type 3; icmp code >= 2 && < 13; }",

    Flowspec::new_v6()
      .with(DstPrefix("fec0:1122:3344:5566:7788:99aa:bbcc:ddee/128".parse()?, 0))?
      .with(TcpFlags(Op::all(0x3).and(Op::not_any(0xc)).and(Op::any(0xff)).or(Op::all(0x33))))?
      .with(DstPort(Op::eq(6000).into()))?
      .with(Fragment(Op::not_any(0b10).or(Op::not_any(0b100))))?
    => "flow6 { dst fec0:1122:3344:5566:7788:99aa:bbcc:ddee/128; \
                tcp flags 0x03/0x0f && !0/0xff || 0x33/0x33; \
                dport = 6000; \
                fragment !is_fragment || !first_fragment; }"
  };

  let (flow4, flow6) = flows.iter().fold((String::new(), String::new()), |(v4, v6), (k, v)| {
    if k.is_ipv4() {
      (v4 + "route " + v + ";", v6)
    } else {
      (v4, v6 + "route " + v + ";")
    }
  });

  let flow_port = pick_port().await?.to_string();
  let cli = Cli::try_parse_from(["flow", "run", "-v", "--dry-run", &format!("--bind=[::1]:{flow_port}")])?;
  let bird = BIRD_FILE
    .replace("@@BIRD_PORT@@", &pick_port().await?.to_string())
    .replace("@@FLOW_PORT@@", &flow_port)
    .replace("@@FLOW4@@", &flow4)
    .replace("@@FLOW6@@", &flow6);

  let (mut cli, mut bird, mut events, _g) = run_cli_with_bird(cli, &bird).await?;

  let mut end_of_rib_count = 0;
  let mut visited = BTreeSet::new();
  loop {
    select! {
      Some(event) = events.recv(), if !events.is_closed() => match event {
        TestEvent::EndOfRib(_afi, _safi) => {
          end_of_rib_count += 1;
          if end_of_rib_count >= 2 {
            break;
          }
        }
        TestEvent::Update(msg) => {
          for nlri in msg.nlri.into_iter().chain(msg.old_nlri) {
            let specs = nlri.into_flow().context("received NLRI other than flowspec")?;
            for spec in specs {
              if let Some((spec1, _)) = flows.remove_entry(&spec) {
                visited.insert(spec1);
              } else if visited.contains(&spec) {
                bail!("received duplicate flowspec: {spec}");
              } else {
                bail!("received unknown flowspec: {spec}");
              }
            }
          }
        }
      },
      _ = sleep(Duration::from_secs(10)) => bail!("timed out"),
      code = &mut cli => bail!("CLI exited early with code {}", code??),
      status = bird.wait() => bail!("BIRD exited early with {}", status?),
    }
  }

  if flows.len() != 0 {
    bail!("some flowspecs not received: {flows:?}");
  }
  Ok(())
}
