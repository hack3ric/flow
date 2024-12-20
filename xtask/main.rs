use clap::Parser;
use std::process::Command;

#[derive(Debug, Parser)]
enum Cli {
  Gen,
}

fn main() {
  let args = Cli::parse();
  match args {
    Cli::Gen => {
      Command::new(env!("CARGO"))
        .args(["run", "--bin", "DONTSHIPIT-flow-gen"])
        .status()
        .unwrap();
    }
  }
}
