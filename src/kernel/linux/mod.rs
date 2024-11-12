mod nft;

use super::rtnl::RtNetlink;
use super::{KernelAdapter, Result};
use crate::bgp::flow::Flowspec;
use crate::bgp::route::RouteInfo;
use clap::Args;
use futures::future::pending;
use itertools::Itertools;
use nft::Nftables;
use nftables::batch::Batch;
use nftables::helper::NftablesError;
use nftables::schema::{NfCmd, NfObject, Nftables as NftablesReq};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

#[derive(Debug, Serialize, Deserialize)]
pub struct Linux {
  nft: Nftables,
  #[serde(skip)]
  rtnl: Option<RtNetlink>,
  counter: u64,
}

impl Linux {
  pub fn new(args: KernelArgs) -> Result<Self> {
    let KernelArgs { table, chain, hooked, priority } = args;
    Ok(Self { nft: Nftables::new(table, chain, hooked, priority)?, rtnl: None, counter: 0 })
  }
}

impl KernelAdapter for Linux {
  type Handle = u64;

  async fn apply(&mut self, spec: &Flowspec, info: &RouteInfo<'_>) -> Result<Self::Handle> {
    let mut total = 1usize;
    let (info_stmts, rt_info) = info
      .to_nft_stmts(spec.afi(), &mut self.rtnl)
      .map(|(a, b)| (Some(a), b))
      .unwrap_or_default();
    let base = spec
      .to_nft_stmts()?
      .chain(info_stmts.map(Ok))
      .map_ok(|branch| {
        let count = total;
        total *= branch.len();
        (branch, count)
      })
      .collect::<Result<Vec<_>, _>>()?;
    let rules = (0..total).map(move |i| {
      (base.iter())
        .flat_map(|(x, v)| x[(x.len() == 1).then_some(0).unwrap_or_else(|| i / v % x.len())].iter())
        .cloned()
        .collect::<Vec<_>>()
    });

    let handle = self.counter;
    self.counter += 1;
    let nftables = NftablesReq {
      objects: rules
        .into_iter()
        .map(|x| NfObject::CmdObject(NfCmd::Add(self.nft.make_new_rule(x, Some(handle)))))
        .collect(),
    };

    self.nft.apply_ruleset(&nftables)?;
    if let Some((next_hop, table_id)) = rt_info {
      let rtnl = self.rtnl.as_mut().expect("RtNetlink should be initialized");
      let real_table_id = rtnl.add(handle, spec, next_hop).await?;
      assert_eq!(table_id, real_table_id, "table ID mismatch");
    }

    Ok(handle)
  }

  async fn remove(&mut self, handle: Self::Handle) -> Result<()> {
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
      .filter(|x| x.comment.as_ref().is_some_and(|y| y == &handle.to_string()))
      .for_each(|x| batch.delete(self.nft.make_rule_handle(x.handle)));
    self.nft.apply_ruleset(&batch.to_nftables())?;

    if let Some(rtnl) = &mut self.rtnl {
      rtnl.del(handle).await;
      // TODO: if rtnl is empty, reset it to None
    }

    Ok(())
  }

  async fn process(&mut self) -> Result<()> {
    if let Some(rtnl) = &mut self.rtnl {
      rtnl.process().await
    } else {
      pending().await
    }
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
