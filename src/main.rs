pub mod bgp;
pub mod ipc;
pub mod kernel;
pub mod net;
pub mod util;

mod args;

use anstyle::{Reset, Style};
use anyhow::Context;
use args::{Cli, Command, RunArgs, ShowArgs};
use bgp::{Session, StateView};
use clap::Parser;
use env_logger::fmt::Formatter;
use futures::future::select;
use futures::FutureExt;
use ipc::{get_sock_path, IpcServer};
use itertools::Itertools;
use log::{error, info, warn, Level, LevelFilter, Record};
use std::fs::{create_dir_all, File};
use std::io::ErrorKind::UnexpectedEof;
use std::io::{self, BufRead, Write};
use std::net::Ipv4Addr;
use std::path::Path;
use std::process::ExitCode;
use tokio::io::BufReader;
use tokio::net::TcpListener;
use tokio::signal::unix::{signal, SignalKind};
use tokio::{pin, select};
use util::{BOLD, FG_GREEN_BOLD, RESET};

async fn run(mut args: RunArgs, sock_path: &str) -> anyhow::Result<ExitCode> {
  if let Some(file) = args.file {
    let cmd = std::env::args().next().unwrap();
    args = RunArgs::parse_from(
      Some(Ok(format!("{cmd} run")))
        .into_iter()
        .chain(std::io::BufReader::new(File::open(file)?).lines())
        .filter(|x| !x.as_ref().is_ok_and(|x| x.is_empty() || x.chars().next().unwrap() == '#'))
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

  let mut bgp = Session::new(args).await?;

  create_dir_all(Path::new(sock_path).parent().unwrap_or(Path::new("/")))?;
  let mut ipc = IpcServer::new(sock_path).with_context(|| format!("failed to create socket at {sock_path}"))?;

  info!("Flow listening to {bind:?} as AS{local_as}, router ID {router_id}");

  let mut sigint = signal(SignalKind::interrupt()).context("failed to register signal handler")?;
  let mut sigterm = signal(SignalKind::terminate()).context("failed to register signal handler")?;

  loop {
    let select = async {
      pin! {
        let sigint = sigint.recv().map(|_| "SIGINT");
        let sigterm = sigterm.recv().map(|_| "SIGTERM");
      }
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
        signal = select(sigint, sigterm) => {
          let (signal, _) = signal.factor_first();
          warn!("{signal} received, exiting");
          return Ok(Some(ExitCode::SUCCESS))
        }
      }
      anyhow::Ok(None)
    };
    match select.await {
      Ok(Some(x)) => return Ok(x),
      Ok(None) => {}
      Err(error) => error!("{error:?}"),
    }
  }
}

async fn show(_args: ShowArgs, verbosity: LevelFilter, sock_path: &str) -> anyhow::Result<()> {
  use StateView::*;
  let mut buf = Vec::new();
  let (config, state, routes) = ipc::get_states(sock_path, &mut buf)
    .await
    .with_context(|| format!("failed to connect to {sock_path}"))?;

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

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
  let cli = Cli::parse();
  let sock_path = get_sock_path(&cli.run_dir).unwrap();
  env_logger::builder()
    .filter_level(cli.verbosity.log_level_filter())
    .format(format_log)
    .filter_module("netlink", LevelFilter::Off)
    .init();
  match cli.command {
    Command::Run(args) => match run(args, &sock_path).await {
      Ok(x) => x,
      Err(error) => {
        error!("fatal error: {error:?}");
        ExitCode::FAILURE
      }
    },
    Command::Show(args) => match show(args, cli.verbosity.log_level_filter(), &sock_path).await {
      Ok(()) => ExitCode::SUCCESS,
      Err(error) => {
        error!("{error:?}");
        ExitCode::FAILURE
      }
    },
  }
}
