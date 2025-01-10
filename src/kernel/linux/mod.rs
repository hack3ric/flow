pub(crate) mod nft;

use super::rtnl::{RtNetlink, RtNetlinkArgs};
use super::{Kernel, Result};
use crate::bgp::flow::Flowspec;
use crate::bgp::route::RouteInfo;
use clap::Args;
use futures::future::OptionFuture;
use futures::join;
use itertools::Itertools;
use nft::Nftables;
use nftables::batch::Batch;
use nftables::schema::{NfCmd, NfListObject, NfObject, Nftables as NftablesReq};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::BTreeSet;
use std::future::pending;

#[derive(Debug, Serialize, Deserialize)]
pub struct Linux {
  nft: Nftables,
  #[serde(skip)]
  rtnl: Option<RtNetlink<Self>>,
  rtnl_args: RtNetlinkArgs,
}

impl Linux {
  pub async fn new(args: KernelArgs) -> Result<Self> {
    let KernelArgs { table, chain, hooked, hook_priority, rtnl } = args;
    Ok(Self {
      nft: Nftables::new(table, chain, hooked, hook_priority).await?,
      rtnl: None,
      rtnl_args: rtnl,
    })
  }
}

impl Kernel for Linux {
  type Handle = BTreeSet<u32>;

  async fn apply(
    &mut self,
    spec: &Flowspec,
    before: Option<&Self::Handle>,
    info: &RouteInfo<'_>,
  ) -> Result<Self::Handle> {
    let mut total = 1usize;
    let (info_stmts, rt_info) = info
      .to_nft_stmts(spec.afi(), &mut self.rtnl, &self.rtnl_args)
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

    let nftables = NftablesReq {
      objects: rules
        .into_iter()
        .map(|x| {
          let cmd = if let Some(before) = before {
            NfCmd::Insert(self.nft.make_new_rule_with_index(x.into(), *before.first().unwrap()))
          } else {
            NfCmd::Add(self.nft.make_new_rule(x.into()))
          };
          NfObject::CmdObject(cmd)
        })
        .collect(),
    };
    let result = self.nft.apply_and_return_ruleset(&nftables).await?;

    let handle: Self::Handle = (result.objects.iter())
      .filter_map(|x| {
        if let NfObject::CmdObject(NfCmd::Add(NfListObject::Rule(rule)))
        | NfObject::CmdObject(NfCmd::Insert(NfListObject::Rule(rule))) = x
        {
          Some(rule.handle.unwrap())
        } else {
          None
        }
      })
      .collect();

    debug_assert_eq!(nftables.objects.len(), handle.len());

    if let Some((next_hop, table_id)) = rt_info {
      let rtnl = self.rtnl.as_mut().expect("RtNetlink should be initialized");
      let real_table_id = rtnl.add(handle.clone(), spec, next_hop).await?;
      assert_eq!(table_id, real_table_id, "table ID mismatch");
    }

    Ok(handle)
  }

  async fn remove(&mut self, handle: &Self::Handle) -> Result<()> {
    let mut batch = Batch::new();
    for h in handle.iter().copied() {
      batch.delete(self.nft.make_rule_handle(h));
    }
    self.nft.apply_ruleset(&batch.to_nftables()).await?;
    if let Some(rtnl) = &mut self.rtnl {
      rtnl.del(handle).await?;
      if rtnl.is_empty() {
        self.rtnl = None;
      }
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

  async fn terminate(self) {
    join!(
      self.nft.terminate(),
      OptionFuture::from(self.rtnl.map(RtNetlink::terminate)),
    );
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
  #[arg(long, value_name = "PRIO", default_value_t = 0)]
  pub hook_priority: i32,

  #[command(flatten)]
  pub rtnl: RtNetlinkArgs,
}
