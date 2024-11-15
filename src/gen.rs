//! Manpage and autocompletion generator.
//!
//! The `args` module links to all parts of the program and not possible to
//! include it only, so we can only generate manpage for it if we include all of
//! the modules that Flow main program includes.

// `pub` essentially acts as better-looking `#[allow(unused)]` here.
pub mod bgp;
pub mod kernel;
pub mod net;
pub mod util;

mod args;

use clap::CommandFactory;
use clap::ValueEnum;
use clap_complete::Shell;

fn main() {
  let target_dir = "target/assets";
  std::fs::create_dir_all(target_dir).unwrap();

  let mut cli = args::Cli::command();
  for &shell in Shell::value_variants() {
    clap_complete::generate_to(shell, &mut cli, env!("CARGO_PKG_NAME"), target_dir).unwrap();
  }
  clap_mangen::generate_to(cli, target_dir).unwrap();

  eprintln!("Manpages and autocompletions successfully generated to {target_dir}.");
}
