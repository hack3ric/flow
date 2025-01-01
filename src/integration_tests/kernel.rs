use super::helpers::cli::CliChild;
use crate::args::Cli;
use crate::integration_tests::helpers::bird::ensure_bird_2;
use crate::integration_tests::helpers::cli::run_cli_with_bird;
use crate::integration_tests::helpers::kernel::{ensure_loopback_up, ensure_root, pick_port};
use crate::integration_tests::{TestEvent, BIRD_CONFIG_1};
use async_tempfile::{TempDir, TempFile};
use clap::Parser;
use macro_rules_attribute::apply;
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
  ])
  .await?;

  let chain =
    nftables::helper::get_current_ruleset_async(None, Some(&["-ns", "list", "chain", "inet", &name, &name])).await?;
  println!("{chain:?}");
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
