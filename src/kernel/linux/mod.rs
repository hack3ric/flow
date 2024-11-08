mod nft;

pub use nft::flow_to_nft_stmts as flow_to_rules;

use super::Result;
use clap::Args;
use nft::Nft;
use nftables::batch::Batch;
use nftables::helper::NftablesError;
use nftables::schema::{NfCmd, NfObject, Nftables};
use nftables::stmt::Statement;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use thiserror::Error;

pub type Rule = Vec<Statement>;

#[derive(Debug, Serialize, Deserialize)]
pub struct Kernel {
  nft: Nft,
  counter: u64,
}

impl Kernel {
  pub fn new(args: KernelArgs) -> Result<Self> {
    let KernelArgs { table, chain, hooked, priority } = args;
    Ok(Self { nft: Nft::new(table, chain, hooked, priority)?, counter: 0 })
  }

  pub fn apply(&mut self, rules: impl IntoIterator<Item = Rule>) -> Result<u64> {
    let id = self.counter;
    self.counter += 1;
    let nftables = Nftables {
      objects: rules
        .into_iter()
        .map(|x| NfObject::CmdObject(NfCmd::Add(self.nft.make_new_rule(x, Some(id)))))
        .collect(),
    };
    self.nft.apply_ruleset(&nftables)?;
    Ok(id)
  }

  pub fn remove(&self, id: u64) -> Result<()> {
    #[derive(Debug, Deserialize)]
    struct MyNftables {
      nftables: Vec<MyNftObject>,
    }
    #[derive(Debug, Deserialize)]
    struct MyNftObject {
      rule: Option<MyNftRule>,
    }
    #[derive(Debug, Deserialize)]
    struct MyNftRule {
      comment: Option<String>,
      handle: u32,
    }
    let mut batch = Batch::new();
    let s = self.nft.get_current_ruleset_raw()?;
    let MyNftables { nftables } = serde_json::from_str(&s).map_err(NftablesError::NftInvalidJson)?;
    nftables
      .into_iter()
      .filter_map(|x| x.rule)
      .filter(|x| x.comment.as_ref().is_some_and(|y| y == &id.to_string()))
      .for_each(|x| batch.delete(self.nft.make_rule_handle(x.handle)));
    self.nft.apply_ruleset(&batch.to_nftables())?;
    Ok(())
  }
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct KernelArgs {
  /// nftables table name.
  ///
  /// The table WILL NOT be automatically deleted when the program exits.
  #[arg(long, default_value_t = Cow::Borrowed("flowspecs"))]
  pub table: Cow<'static, str>,

  /// nftables chain name.
  ///
  /// The chain WILL be automatically deleted when the program exits.
  #[arg(long, default_value_t = Cow::Borrowed("flowspecs"))]
  pub chain: Cow<'static, str>,

  /// Attach flowspec rules to nftables input hook.
  ///
  /// If not set, the nftables rule must be `jump`ed or `goto`ed from a base
  /// (hooked) chain in the same table to take effect.
  #[arg(long)]
  pub hooked: bool,

  /// Hook priority.
  #[arg(long, default_value_t = 0)]
  pub priority: i32,
}

#[derive(Debug, Error)]
pub enum Error {
  #[error(transparent)]
  Nftables(#[from] NftablesError),

  // TODO: move this out
  #[error("flowspec matches nothing")]
  ToNftStmt,
}
