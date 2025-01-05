use clap::Parser;
use std::process::{Command, ExitCode};

#[derive(Debug, Parser)]
enum Cli {
  /// Generate manpages and shell autocompletions into target/assets.
  Gen,
  /// Run command with `unshare -rn`
  Unshare {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    _args: Vec<String>,
  },
  /// Run command with `sudo -E`
  Sudo {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    _args: Vec<String>,
  },
}

fn main() -> ExitCode {
  let status = match Cli::parse() {
    Cli::Gen => Command::new(env!("CARGO")).args(["run", "--features=__gen"]).status().unwrap(),

    #[cfg(target_os = "linux")]
    Cli::Unshare { _args } => Command::new(env!("CARGO"))
      .args(["--config", "target.'cfg(target_os = \"linux\")'.runner = 'unshare -rn'"])
      .args(std::env::args().skip(2))
      .status()
      .unwrap(),

    #[cfg(not(target_os = "linux"))]
    Cli::Unshare { _args } => {
      eprintln!("Unshare not supported, running tests as current user");
      Command::new(env!("CARGO")).args(std::env::args().skip(2)).status().unwrap()
    }

    Cli::Sudo { _args } => Command::new(env!("CARGO"))
      .args([
        "--config",
        &format!(
          "target.'cfg(target_os = \"{}\")'.runner = 'sudo -E'",
          std::env::consts::OS
        ),
      ])
      .args(std::env::args().skip(2))
      .status()
      .unwrap(),
  };

  match status.code() {
    Some(code) => ExitCode::from(code as u8),
    None => ExitCode::from(255),
  }
}
