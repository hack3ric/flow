pub mod bgp;
pub mod ipc;
pub mod kernel;
pub mod net;
pub mod util;

mod args;

#[cfg(test)]
mod integration_tests;

use anstyle::{Reset, Style};
use anyhow::Context;
use args::{Cli, Command, RunArgs, ShowArgs};
use bgp::{Session, StateView};
use clap::Parser;
use env_logger::fmt::Formatter;
use ipc::{get_sock_path, IpcServer};
use itertools::Itertools;
use log::{error, info, warn, Level, LevelFilter, Record};
use std::fs::{create_dir_all, File};
use std::io::ErrorKind::UnexpectedEof;
use std::io::{self, BufRead, Write};
use std::net::Ipv4Addr;
use std::path::Path;
use tokio::io::BufReader;
use tokio::net::TcpListener;
use tokio::select;
use util::{BOLD, FG_GREEN_BOLD, RESET};

#[cfg(test)]
use {std::future::pending, tokio::sync::mpsc};

#[cfg(not(test))]
use {
  futures::future::{select, FutureExt},
  std::process::ExitCode,
  tokio::pin,
  tokio::signal::unix::{signal, SignalKind},
};

async fn run(mut args: RunArgs, sock_path: &Path, #[cfg(test)] event_tx: mpsc::Sender<()>) -> anyhow::Result<u8> {
  if let Some(file) = args.file {
    let cmd = std::env::args().next().unwrap();
    args = RunArgs::parse_from(
      Some(Ok(format!("{cmd} run")))
        .into_iter()
        .chain(std::io::BufReader::new(File::open(file)?).lines())
        .filter(|x| !x.as_ref().is_ok_and(|x| x.is_empty() || x.starts_with('#')))
        .map_ok(|x| "--".to_string() + &x)
        .collect::<Result<Vec<_>, _>>()?,
    );
    if args.file.is_some() {
      warn!("`file` option in configuration file ignored");
    }
  }

  let bind = args.bind;
  let listener = TcpListener::bind(&bind)
    .await
    .with_context(|| format!("failed to bind to {bind:?}"))?;

  let local_as = args.local_as;
  let router_id = args.router_id;

  #[cfg(not(test))]
  let mut bgp = Session::new(args).await?;
  #[cfg(test)]
  let mut bgp = Session::new(args, event_tx).await?;

  create_dir_all(Path::new(sock_path).parent().unwrap_or(Path::new("/")))?;
  let mut ipc =
    IpcServer::new(sock_path).with_context(|| format!("failed to create socket at {}", sock_path.display()))?;

  info!("Flow listening to {bind:?} as AS{local_as}, router ID {router_id}");

  #[cfg(not(test))]
  let (mut sigint, mut sigterm) = (
    signal(SignalKind::interrupt()).context("failed to register signal handler")?,
    signal(SignalKind::terminate()).context("failed to register signal handler")?,
  );

  loop {
    let select = async {
      #[cfg(not(test))]
      pin! {
        let sigint = sigint.recv().map(|_| "SIGINT");
        let sigterm = sigterm.recv().map(|_| "SIGTERM");
        let signal_select = select(sigint, sigterm);
      }
      #[cfg(test)]
      let signal_select = pending();

      select! {
        result = listener.accept(), if matches!(bgp.state(), bgp::State::Active) => {
          let (stream, mut addr) = result.context("failed to accept TCP connection")?;
          addr.set_ip(addr.ip().to_canonical());
          bgp.accept(BufReader::new(stream), addr).await.context("failed to accept BGP connection")?;
        }
        result = bgp.process() => match result {
          Ok(()) => {}
          Err(bgp::Error::Io(error)) if error.kind() == UnexpectedEof => warn!("remote closed"),
          Err(e @ (bgp::Error::Notification(_) | bgp::Error::Remote(_))) => error!("BGP error: {e}"),
          Err(_) => result.context("failed to process BGP")?,
        },
        result = ipc.accept() => {
          let mut stream = result.context("failed to accept IPC connection")?;
          bgp.write_states(&mut stream).await.context("failed to write to IPC channel")?;
        },

        _signal = signal_select => {
          #[cfg(not(test))]
          {
            let (signal, _) = _signal.factor_first();
            warn!("{signal} received, exiting");
            return Ok(Some(0))
          }
        }
      }
      anyhow::Ok(None)
    };
    match select.await {
      Ok(Some(x)) => {
        // TODO: return read-only state
        bgp.terminate().await;
        return Ok(x);
      }
      Ok(None) => {}
      Err(error) => error!("{error:?}"),
    }
  }
}

async fn show(_args: ShowArgs, verbosity: LevelFilter, sock_path: &Path) -> anyhow::Result<()> {
  use StateView::*;
  let mut buf = Vec::new();
  let (config, state, routes) = ipc::get_states(sock_path, &mut buf)
    .await
    .with_context(|| format!("failed to connect to {}", sock_path.display()))?;

  println!("{FG_GREEN_BOLD}Flow{RESET} listening to {:?}", config.bind);
  println!("  {BOLD}State:{RESET} {:?}", state.kind());
  println!("  {BOLD}Local AS:{RESET} {}", config.local_as);
  println!("  {BOLD}Local Router ID:{RESET} {}", config.router_id);
  match state {
    Idle | Connect | Active | OpenSent => {
      if let Some(remote_as) = config.remote_as {
        println!("  {BOLD}Remote AS:{RESET} {remote_as}");
      }
      println!("  {BOLD}Allowed IPs:{RESET} {}", config.allowed_ips.iter().format(", "));
    }
    OpenConfirm { remote_open, local_addr, remote_addr } | Established { remote_open, local_addr, remote_addr } => {
      if let Some(local_addr) = local_addr {
        println!("  {BOLD}Local Address:{RESET} {local_addr}");
      }
      println!("  {BOLD}Remote AS:{RESET} {}", remote_open.my_as);
      println!(
        "  {BOLD}Remote Router ID:{RESET} {}",
        Ipv4Addr::from_bits(remote_open.bgp_id),
      );
      if let Some(remote_addr) = remote_addr {
        println!("  {BOLD}Remote Address:{RESET} {remote_addr}");
      }
      if verbosity >= Level::Debug {
        println!(
          "  {BOLD}Hold Time:{RESET} {}",
          config.hold_time.min(remote_open.hold_time),
        )
      }
    }
  }
  println!();

  routes.print(verbosity);
  Ok(())
}

fn format_log(f: &mut Formatter, record: &Record<'_>) -> io::Result<()> {
  use anstyle::AnsiColor::*;
  use log::Level::*;

  let (level_color, text_color, str) = match record.level() {
    Error => (Red, None, "Error"),
    Warn => (Yellow, None, " Warn"),
    Info => (Green, None, " Info"),
    Debug => (Blue, None, "Debug"),
    Trace => (BrightBlack, Some(BrightBlack), "Trace"),
  };

  let level_style = Style::new().bold().fg_color(Some(level_color.into()));
  write!(f, "{}{}{} ", level_style, str, Reset)?;

  if let Some(text_color) = text_color {
    let text_style = Style::new().fg_color(Some(text_color.into()));
    writeln!(f, "{}{}{}", text_style, record.args(), Reset)
  } else {
    writeln!(f, "{}", record.args())
  }
}

pub async fn cli_entry(cli: Cli, #[cfg(test)] event_tx: mpsc::Sender<()>) -> u8 {
  let mut builder = env_logger::builder();
  builder
    .filter_level(cli.verbosity.log_level_filter())
    .format(format_log)
    .filter_module("netlink", LevelFilter::Off);
  #[cfg(test)]
  builder.is_test(true);
  builder.init();

  let sock_path = get_sock_path(&cli.run_dir).unwrap();

  match cli.command {
    Command::Run(args) => {
      #[cfg(test)]
      let result = run(args, &sock_path, event_tx).await;
      #[cfg(not(test))]
      let result = run(args, &sock_path).await;
      match result {
        Ok(x) => x,
        Err(error) => {
          error!("fatal error: {error:?}");
          1
        }
      }
    }
    Command::Show(args) => match show(args, cli.verbosity.log_level_filter(), &sock_path).await {
      Ok(()) => 0,
      Err(error) => {
        error!("{error:?}");
        1
      }
    },
  }
}

#[cfg(not(any(test, feature = "__gen")))]
#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
  let cli = Cli::parse();
  cli_entry(cli).await.into()
}

/// Manpage and autocompletion generator.
///
/// The `args` module links to all parts of the program and not possible to
/// include it only, so we can only generate manpage right inside `main.rs`,
/// gated by `__gen` feature.
#[cfg(feature = "__gen")]
fn main() {
  use clap::{CommandFactory, ValueEnum};

  let target_dir = "target/assets";
  std::fs::create_dir_all(target_dir).unwrap();
  let mut cli = Cli::command();

  // We generate manpages first since clap_complete will call `cli.build()`, and
  // the manpages generated after that will contain thing like "flow-help-help".
  clap_mangen::generate_to(cli.clone(), target_dir).unwrap();

  for &shell in clap_complete::Shell::value_variants() {
    clap_complete::generate_to(shell, &mut cli, env!("CARGO_PKG_NAME"), target_dir).unwrap();
  }

  eprintln!("Manpages and autocompletions successfully generated to {target_dir}.");
}
