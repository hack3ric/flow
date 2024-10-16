pub mod bgp;
pub mod ipc;
pub mod net;
pub mod sync;
pub mod util;

use anstyle::{Reset, Style};
use bgp::route::Routes;
use bgp::{Config, Session};
use clap::Parser;
use clap_verbosity::{InfoLevel, Verbosity};
use env_logger::fmt::Formatter;
use log::{error, info, Record};
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr};
use std::process::exit;
use std::rc::Rc;
use sync::RwLock;
use tokio::net::TcpListener;
use tokio::select;

#[derive(Debug, Parser)]
struct Args {
  /// Address to bind.
  #[arg(short, long, value_parser = parse_bgp_bind, default_value = "::")]
  bind: SocketAddr,

  #[arg(short, long, default_value = "65000")]
  local_as: u32,
  #[arg(short, long)]
  remote_as: Option<u32>,

  #[command(flatten)]
  verbosity: Verbosity<InfoLevel>,
}

fn parse_bgp_bind(bind: &str) -> anyhow::Result<SocketAddr> {
  let result = bind.parse().or_else(|_| bind.parse::<IpAddr>().map(|ip| (ip, 179).into()))?;
  Ok(result)
}

async fn run(args: Args) -> anyhow::Result<()> {
  let routes = Rc::new(RwLock::new(Routes::new()));

  let listener = TcpListener::bind(args.bind).await?;
  let mut bgp = Session::new(routes.clone(), Config {
    router_id: 123456,
    local_as: args.local_as,
    remote_as: args.remote_as,
    remote_ip: vec!["0.0.0.0/0".parse()?, "::/0".parse()?],
    hold_timer: 240,
  });

  info!("Flow listening to {} as AS{}", args.bind, args.local_as);
  loop {
    let select = async {
      select! {
        result = listener.accept(), if matches!(bgp.state, bgp::State::Active) => {
          let (stream, mut addr) = result?;
          addr.set_ip(addr.ip().to_canonical());
          bgp.accept(stream, addr).await?;
        }
        result = bgp.process() => result?,
      }
      anyhow::Ok(())
    };
    if let Err(error) = select.await {
      error!("{error}");
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
async fn main() {
  let args = Args::parse();
  env_logger::builder()
    .filter_level(args.verbosity.log_level_filter())
    .format(format_log)
    .init();
  if let Err(error) = run(args).await {
    error!("fatal error: {error}");
    exit(1);
  }
}
