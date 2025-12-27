use super::{Kernel, Result};
use crate::bgp::flow::Flowspec;
use crate::net::{Afi, IpPrefix};
use crate::util::grace;
use clap::Args;
use futures::channel::mpsc::UnboundedReceiver;
use futures::{StreamExt, try_join};
use libc::{EHOSTUNREACH, ENETUNREACH};
use log::{debug, trace};
use rtnetlink::Error::NetlinkError;
use rtnetlink::packet_core::{NetlinkMessage, NetlinkPayload};
use rtnetlink::packet_route::route::{RouteAddress, RouteAttribute, RouteMessage, RouteType, RouteVia};
use rtnetlink::packet_route::rule::{RuleAction, RuleAttribute, RuleMessage};
use rtnetlink::packet_route::{AddressFamily, RouteNetlinkMessage};
use rtnetlink::{Handle, MulticastGroup, RouteMessageBuilder};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::IpAddr;
use std::time::Duration;
use tokio::select;
use tokio::time::{Interval, interval};

// We allow redirecting to any address by resolving its next hop using `ip route
// get`. This aligns with the RFC draft v4.
//
// Not handling ECMP for now.

#[derive(Debug)]
pub struct RtNetlink<K: Kernel> {
  args: RtNetlinkArgs,
  handle: Handle,
  msgs: UnboundedReceiver<(NetlinkMessage<RouteNetlinkMessage>, rtnetlink::sys::SocketAddr)>,
  routes: BTreeMap<K::Handle, RouteEntry>,
  rules: BTreeMap<u32, BTreeSet<IpPrefix>>,
  timer: Interval,
}

impl<K: Kernel> RtNetlink<K> {
  pub fn new(args: RtNetlinkArgs) -> io::Result<Self> {
    use MulticastGroup::*;
    let (conn, handle, msgs) = rtnetlink::new_multicast_connection(&[Ipv4Route, Ipv6Route, Ipv4Rule, Ipv6Rule])?;
    let scan_time = args.route_scan_time;
    tokio::spawn(conn);
    trace!("rtnetlink: spawned");
    Ok(Self {
      args,
      handle,
      msgs,
      routes: BTreeMap::new(),
      rules: BTreeMap::new(),
      timer: interval(Duration::from_secs(scan_time)),
    })
  }

  pub async fn add(&mut self, id: K::Handle, spec: &Flowspec, next_hop: IpAddr) -> Result<u32> {
    let prefix = spec.dst_prefix();
    let attrs = self.get_route(prefix.afi(), next_hop).await?;

    // Create table first...
    let (table_id, table_created) = if let Some((table_id, prefixes)) =
      (self.rules).iter_mut().find(|(_, v)| v.iter().all(|p| !p.overlaps(prefix)))
    {
      // there's a table whose content doesn't overlap with our prefix, we reuse it
      prefixes.insert(prefix);
      (*table_id, false)
    } else {
      let table_id = self.next_table();
      self.rules.insert(table_id, Some(prefix).into_iter().collect());

      let rule_add = (self.handle.rule().add())
        .fw_mark(table_id)
        .action(RuleAction::ToTable)
        .table_id(table_id)
        .priority(self.args.rt_rule_priority);

      // TODO: separate v4 and v6 tables
      try_join!(rule_add.clone().v4().execute(), rule_add.v6().execute())?;
      (table_id, true)
    };

    // ...and then add route to the table...
    let mut msg = RouteMessageBuilder::<IpAddr>::new()
      .destination_prefix(prefix.prefix(), prefix.len())
      .expect("destination prefix should be valid")
      .table_id(table_id)
      .build();
    if let Some(attrs) = &attrs {
      msg.attributes.extend(attrs.iter().cloned());
    } else {
      msg.header.kind = RouteType::Throw;
    };
    if let Err(error) = self.handle.route().add(msg).replace().execute().await {
      if table_created {
        self.rules.remove(&table_id);
        self.del_rule(table_id).await;
      }
      return Err(error.into());
    }

    // ...and finally insert to our own database
    self.routes.insert(id, RouteEntry { prefix, next_hop, table_id, attrs });

    Ok(table_id)
  }

  pub fn next_table(&self) -> u32 {
    (self.rules)
      .last_key_value()
      .map(|(k, _)| *k + 1)
      .unwrap_or(self.args.init_table_id)
  }

  pub fn next_table_for(&self, prefix: IpPrefix) -> u32 {
    // TODO: room for optimization
    (self.rules.iter())
      .find(|(_, v)| v.iter().all(|p| !p.overlaps(prefix)))
      .map(|(k, _)| *k)
      .unwrap_or_else(|| self.next_table())
  }

  pub async fn del(&mut self, id: &K::Handle) {
    let Some(RouteEntry { prefix, table_id, .. }) = self.routes.remove(id) else {
      return;
    };
    self.del_route(table_id, prefix).await;

    let prefixes = self.rules.get_mut(&table_id).expect("route contains non-existent table??");
    prefixes.remove(&prefix);
    if prefixes.is_empty() {
      self.rules.remove(&table_id);
      self.del_rule(table_id).await;
    }
  }

  async fn del_route(&self, table_id: u32, prefix: IpPrefix) {
    let mut msg = RouteMessageBuilder::<IpAddr>::new()
      .destination_prefix(prefix.prefix(), prefix.len())
      .expect("destination prefix should be valid")
      .table_id(table_id)
      .build();
    if self.handle.route().del(msg.clone()).execute().await.is_err() {
      msg.header.kind = RouteType::Throw;
      grace(self.handle.route().del(msg).execute().await, "failed to delete route");
    }
  }

  /// Deletes kernel `ip rule`. `self.rules` remains unchanged.
  async fn del_rule(&self, table_id: u32) {
    // TODO: add RuleMessageBuilder to rtnetlink crate
    let mut msg = RuleMessage::default();
    msg.header.family = AddressFamily::Inet;
    msg.attributes.push(RuleAttribute::FwMark(table_id));
    msg.header.action = RuleAction::ToTable;
    if table_id > 255 {
      msg.attributes.push(RuleAttribute::Table(table_id));
    } else {
      msg.header.table = table_id as u8;
    }
    grace(
      self.handle.rule().del(msg.clone()).execute().await,
      "failed to delete IPv4 rule",
    );
    msg.header.family = AddressFamily::Inet6;
    grace(
      self.handle.rule().del(msg).execute().await,
      "failed to delete IPv6 rule",
    );
  }

  pub fn is_empty(&self) -> bool {
    self.routes.is_empty()
  }

  // route & addr change: check if next hop in changed prefix
  // rule change: full update for AF
  // link change: full update
  // scan timer triggered: full update
  pub async fn process(&mut self) -> Result<()> {
    use NetlinkPayload::*;
    use RouteNetlinkMessage::*;
    use RouteType::*;

    fn af_to_wildcard(f: AddressFamily) -> IpPrefix {
      if f == AddressFamily::Inet {
        IpPrefix::V4_ALL
      } else {
        IpPrefix::V6_ALL
      }
    }

    fn route_msg_dst_prefix(msg: RouteMessage) -> IpPrefix {
      use RouteAddress::{Inet, Inet6};
      use RouteAttribute::Destination;
      let dst_len = msg.header.destination_prefix_length;
      (dst_len != 0)
        .then(|| {
          (msg.attributes.into_iter())
            .filter_map(|x| match x {
              Destination(Inet(ip)) => Some(IpPrefix::new(IpAddr::V4(ip), dst_len)),
              Destination(Inet6(ip)) => Some(IpPrefix::new(IpAddr::V6(ip), dst_len)),
              _ => None,
            })
            .next()
        })
        .flatten()
        .unwrap_or_else(|| af_to_wildcard(msg.header.address_family))
    }

    select! {
      _ = self.timer.tick() => {
        trace!("rtnetlink: timer tick");
        self.process_all().await
      }
      Some((msg, _)) = self.msgs.next() => {
        match msg.payload {
          InnerMessage(msg) => {
            match msg {
              NewRoute(msg) | DelRoute(msg) if !matches!(msg.header.kind, Local | Broadcast | Anycast | Multicast) => {
                let prefix = route_msg_dst_prefix(msg);
                trace!("rtnetlink: route to {prefix:?} changed");
                self.process_prefix(prefix).await
              }
              NewRule(msg) | DelRule(msg) => {
                trace!("rtnetlink: rule changed: {msg:?}");
                self.process_prefix(af_to_wildcard(msg.header.family)).await
              }
              _ => Ok(()),
            }
          }
          _ => Ok(()),
        }
      }
    }
  }

  async fn process_prefix(&mut self, prefix: IpPrefix) -> Result<()> {
    Self::process_iter(
      &self.handle,
      self.routes.values_mut().filter(|x| prefix.contains(x.next_hop)),
    )
    .await
  }

  async fn process_all(&mut self) -> Result<()> {
    Self::process_iter(&self.handle, self.routes.values_mut()).await
  }

  async fn process_iter(handle: &Handle, iter: impl Iterator<Item = &mut RouteEntry>) -> Result<()> {
    // TODO: remove route if next hop becomes unreachable
    for RouteEntry { prefix, next_hop, table_id, attrs } in iter {
      let new_attrs = Self::get_route_from_handle(handle, prefix.afi(), *next_hop).await?;
      if *attrs != new_attrs {
        debug!("route attrs: {attrs:?} -> {new_attrs:?}");
        *attrs = new_attrs.clone();
        let mut msg = RouteMessageBuilder::<IpAddr>::new()
          .destination_prefix(prefix.prefix(), prefix.len())
          .expect("destination prefix should be valid")
          .table_id(*table_id)
          .build();
        if let Some(attrs) = &attrs {
          msg.attributes.extend(attrs.iter().cloned());
        } else {
          msg.header.kind = RouteType::Throw;
        };
        handle.route().add(msg).replace().execute().await?;
      }
    }
    Ok(())
  }

  async fn get_route(&self, afi: Afi, ip: IpAddr) -> Result<Option<Vec<RouteAttribute>>> {
    Self::get_route_from_handle(&self.handle, afi, ip).await
  }

  async fn get_route_from_handle(handle: &Handle, prefix_afi: Afi, ip: IpAddr) -> Result<Option<Vec<RouteAttribute>>> {
    let msg = RouteMessageBuilder::<IpAddr>::new()
      .destination_prefix(ip, if ip.is_ipv4() { 32 } else { 128 })
      .expect("destination prefix should be valid")
      .build();
    let rt = match handle.route().get(msg).execute().next().await.unwrap() {
      Ok(rt) => rt,
      Err(NetlinkError(e)) if [ENETUNREACH, EHOSTUNREACH].contains(&-e.raw_code()) => return Ok(None),
      Err(error) => return Err(error.into()),
    };

    let mut has_gateway = false;
    let mut attrs = rt
      .attributes
      .into_iter()
      .filter(|x| {
        if matches!(x, RouteAttribute::Gateway(_) | RouteAttribute::Via(_)) {
          has_gateway = true;
          true
        } else {
          matches!(x, RouteAttribute::Oif(_))
        }
      })
      .collect::<Vec<_>>();
    if !has_gateway {
      if let (Afi::Ipv4, IpAddr::V6(v6)) = (prefix_afi, ip) {
        attrs.push(RouteAttribute::Via(RouteVia::Inet6(v6)));
      } else {
        attrs.push(RouteAttribute::Gateway(ip.into()));
      }
    }
    Ok(Some(attrs))
  }

  pub async fn terminate(self) {
    for (table_id, prefixes) in &self.rules {
      self.del_rule(*table_id).await;
      for prefix in prefixes {
        self.del_route(*table_id, *prefix).await;
      }
    }
  }
}

#[derive(Debug, Clone)]
pub struct RouteEntry {
  prefix: IpPrefix,
  next_hop: IpAddr,
  table_id: u32,
  attrs: Option<Vec<RouteAttribute>>,
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
pub struct RtNetlinkArgs {
  /// Time between each routing table scan.
  ///
  /// Netlink allows route change notifications and does not need to scan the
  /// entire routing table every time, so this value could be set higher.
  #[arg(long, value_name = "TIME", default_value_t = 60)]
  pub route_scan_time: u64,

  /// Initial routing table ID.
  ///
  /// Table IDs are also used as fwmarks.
  #[arg(long, value_name = "ID", default_value_t = 0xffff0000)]
  pub init_table_id: u32, // TODO: specify table range

  /// Route rule priority as shown in `ip rule`.
  #[arg(long, value_name = "PRIO", default_value_t = 100)]
  pub rt_rule_priority: u32,
}
