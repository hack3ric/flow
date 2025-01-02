use clap::Parser;
use std::process::Command;

#[derive(Debug, Parser)]
enum Cli {
  /// Generate manpages and shell autocompletions into target/assets.
  Gen,
  /// Run tests with `unshare -rn`
  UnshareTest {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    _args: Vec<String>,
  },
  /// Run tests with `sudo -E`
  SudoTest {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    _args: Vec<String>,
  },
}

fn main() {
  let args = Cli::parse();
  match args {
    Cli::Gen => {
      Command::new(env!("CARGO")).args(["run", "--features=__gen"]).status().unwrap();
    }

    Cli::UnshareTest { _args } => {
      #[cfg(not(target_os = "linux"))]
      eprintln!("Unshare not supported, running tests as current user");

      Command::new(env!("CARGO"))
        .args([
          "--config",
          "target.'cfg(target_os = \"linux\")'.runner = 'unshare -rn'",
          "test",
        ])
        .args(std::env::args().skip(2))
        .status()
        .unwrap();
    }

    Cli::SudoTest { _args } => {
      Command::new(env!("CARGO"))
        .args([
          "--config",
          &format!(
            "target.'cfg(target_os = \"{}\")'.runner = 'sudo -E'",
            std::env::consts::OS
          ),
          "test",
        ])
        .args(std::env::args().skip(2))
        .status()
        .unwrap();
    }
  }
}
