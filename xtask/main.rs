use clap::Parser;
use std::process::{Command, ExitCode};

#[derive(Debug, Parser)]
enum Cli {
  /// Generate manpages and shell autocompletions into target/assets.
  Gen,
  /// Run command with `unshare -rn`.
  Unshare {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
  },
  /// Run command with `sudo -E`.
  Sudo {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
  },
  /// Run command with `ip netns exec <netns>`.
  Netns {
    netns: String,
    /// Prepend `sudo -E` to runner.
    #[arg(long)]
    sudo: bool,
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
  },
}

fn cargo_with_runner(runner: &str) -> Command {
  let mut cmd = Command::new(env!("CARGO"));
  let os = std::env::consts::OS;
  cmd.args([
    "--config",
    &format!("target.'cfg(target_os = \"{os}\")'.runner = '{runner}'"),
  ]);
  cmd
}

fn main() -> ExitCode {
  let status = match Cli::parse() {
    Cli::Gen => Command::new(env!("CARGO")).args(["run", "--features=__gen"]).status().unwrap(),

    #[cfg(target_os = "linux")]
    Cli::Unshare { args } => cargo_with_runner("unshare -rn").args(args).status().unwrap(),

    #[cfg(not(target_os = "linux"))]
    Cli::Unshare { args } => {
      eprintln!("Unshare not supported, running tests as current user");
      Command::new(env!("CARGO")).args(args).status().unwrap()
    }

    Cli::Sudo { args } => cargo_with_runner("sudo -E").args(args).status().unwrap(),

    Cli::Netns { netns, sudo, args } => {
      let runner = if sudo {
        format!("sudo -E ip netns exec {netns}")
      } else {
        format!("ip netns exec {netns}")
      };
      cargo_with_runner(&runner).args(args).status().unwrap()
    }
  };

  match status.code() {
    Some(code) => ExitCode::from(code as u8),
    None => ExitCode::from(255),
  }
}
