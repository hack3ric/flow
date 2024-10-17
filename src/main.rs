pub mod bgp;
pub mod ipc;
pub mod net;
pub mod sync;
pub mod util;

mod args;

use anstyle::{Reset, Style};
use args::{Cli, Command, RunArgs};
use bgp::route::Routes;
use bgp::{Config, Session};
use clap::Parser;
use env_logger::fmt::Formatter;
use futures::future::select;
use futures::FutureExt;
use ipc::IpcServer;
use log::{error, info, warn, Record};
use std::io::ErrorKind::UnexpectedEof;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::rc::Rc;
use sync::RwLock;
use tokio::net::TcpListener;
use tokio::signal::unix::{signal, SignalKind};
use tokio::{pin, select};

async fn run(args: RunArgs) -> anyhow::Result<ExitCode> {
  let routes = Rc::new(RwLock::new(Routes::new()));

  let listener = TcpListener::bind(args.bind).await?;
  let mut bgp = Session::new(routes.clone(), Config {
    router_id: args.router_id.map(Ipv4Addr::to_bits).unwrap_or(23456),
    local_as: args.local_as,
    remote_as: args.remote_as,
    remote_ip: args.allowed_ips,
    hold_timer: 240,
  });

  let mut ipc = IpcServer::new("/run/flow/flow.sock", routes)?;

  let mut sigint = signal(SignalKind::interrupt())?;
  let mut sigterm = signal(SignalKind::terminate())?;

  info!("Flow listening to {} as AS{}", args.bind, args.local_as);
  loop {
    let select = async {
      pin! {
        let sigint = sigint.recv().map(|_| "SIGINT");
        let sigterm = sigterm.recv().map(|_| "SIGTERM");
      }
      select! {
        r = listener.accept(), if matches!(bgp.state, bgp::State::Active) => {
          let (stream, mut addr) = r?;
          addr.set_ip(addr.ip().to_canonical());
          bgp.accept(stream, addr).await?;
        }
        r = bgp.process() => match r {
          Ok(()) => {}
          Err(bgp::Error::Io(error)) if error.kind() == UnexpectedEof => warn!("remote closed"),
          Err(error) => return Err(error.into()),
        },
        r = ipc.process() => r?,
        x = select(sigint, sigterm) => {
          let (x, _) = x.factor_first();
          info!("{x} received, exiting");
          return Ok(Some(ExitCode::SUCCESS))
        }
      }
      anyhow::Ok(None)
    };
    match select.await {
      Ok(Some(x)) => return Ok(x),
      Ok(None) => {}
      Err(error) => error!("{error}"),
    }
  }
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
  env_logger::builder()
    .filter_level(cli.verbosity.log_level_filter())
    .format(format_log)
    .init();
  match cli.command {
    Command::Run(args) => match run(args).await {
      Ok(x) => x,
      Err(error) => {
        error!("fatal error: {error}");
        ExitCode::FAILURE
      }
    },
    Command::Show => {
      let result = async {
        let routes = ipc::get_routes("/run/flow/flow.sock").await?;
        routes.print();
        anyhow::Ok(())
      };
      match result.await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
          error!("{error}");
          ExitCode::FAILURE
        }
      }
    }
  }
}
