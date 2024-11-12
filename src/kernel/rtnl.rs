use super::Result;
use crate::bgp::flow::{Component, ComponentKind, Flowspec};
use crate::net::{Afi, IpPrefix};
use clap::Args;
use futures::channel::mpsc::UnboundedReceiver;
use futures::{StreamExt, TryStreamExt};
use libc::{RTA_GATEWAY, RTA_OIF};
use log::warn;
use rtnetlink::packet_core::{NetlinkMessage, NetlinkPayload};
use rtnetlink::packet_route::address::{AddressAttribute, AddressMessage};
use rtnetlink::packet_route::route::{RouteAddress, RouteAttribute, RouteMessage};
use rtnetlink::packet_route::rule::{RuleAction, RuleAttribute, RuleMessage};
use rtnetlink::packet_route::{AddressFamily, RouteNetlinkMessage};
use rtnetlink::packet_utils::nla::Nla;
use rtnetlink::{Handle, RouteMessageBuilder};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::IpAddr;
use std::time::Duration;
use tokio::select;
use tokio::time::{interval, Interval};

#[derive(Debug)]
pub struct RtNetlink {
  handle: Handle,
  msgs: UnboundedReceiver<(NetlinkMessage<RouteNetlinkMessage>, rtnetlink::sys::SocketAddr)>,
  routes: BTreeMap<u64, (IpPrefix, IpAddr, u32, Vec<RouteAttribute>)>,
  rules: BTreeMap<u32, BTreeSet<IpPrefix>>,
  timer: Interval,
}

impl RtNetlink {
  pub fn new(args: RtNetlinkArgs) -> io::Result<Self> {
    let (conn, handle, msgs) = rtnetlink::new_connection()?;
    tokio::spawn(conn);
    Ok(Self {
      handle,
      msgs,
      routes: BTreeMap::new(),
      rules: BTreeMap::new(),
      timer: interval(Duration::from_secs(60)), // TODO: customize scan time
    })
  }

  pub async fn add(&mut self, id: u64, spec: &Flowspec, next_hop: IpAddr) -> Result<u32> {
    let prefix = spec
      .component_set()
      .get(&ComponentKind::DstPrefix)
      .and_then(|x| {
        let Component::DstPrefix(pat, offset) = x.0 else {
          unreachable!();
        };
        (offset == 0).then_some(pat)
      })
      .unwrap_or_else(|| match spec.afi() {
        Afi::Ipv4 => IpPrefix::V4_ALL,
        Afi::Ipv6 => IpPrefix::V6_ALL,
      });

    let table_id = if let Some((table_id, prefixes)) = (self.rules.iter_mut())
      .filter(|(_, v)| v.iter().all(|p| !p.overlaps(prefix)))
      .next()
    {
      prefixes.insert(prefix);
      *table_id
    } else {
      // TODO: customize starting table ID/fwmark
      let table_id = self.next_table_id();
      self.rules.insert(table_id, Some(prefix).into_iter().collect());
      (self.handle.rule().add().v4())
        .fw_mark(table_id)
        .action(RuleAction::ToTable)
        .table_id(table_id)
        .priority(100)
        .execute()
        .await?;
      (self.handle.rule().add().v6())
        .fw_mark(table_id)
        .action(RuleAction::ToTable)
        .table_id(table_id)
        .priority(100)
        .execute()
        .await?;
      self.handle.rule().get(rtnetlink::IpVersion::V4);
      table_id
    };

    let attrs = self.get_route(next_hop).await?.collect::<Vec<_>>();
    self.routes.insert(id, (prefix, next_hop, table_id, attrs.clone()));
    let mut msg = RouteMessageBuilder::<IpAddr>::new()
      .destination_prefix(prefix.prefix(), prefix.len())
      .expect("destination prefix should be valid")
      .table_id(table_id)
      .build();
    msg.attributes.extend(attrs);
    self.handle.route().add(msg).execute().await?;

    Ok(table_id)
  }

  pub fn next_table_id(&self) -> u32 {
    self.rules.last_key_value().map(|(k, _)| *k + 1).unwrap_or(10000)
  }

  pub async fn del(&mut self, id: u64) -> Result<()> {
    let Some((prefix, _, table_id, _)) = self.routes.remove(&id) else {
      return Ok(());
    };
    let msg = RouteMessageBuilder::<IpAddr>::new()
      .destination_prefix(prefix.prefix(), prefix.len())
      .expect("destination prefix should be valid")
      .table_id(table_id)
      .build();
    self.handle.route().del(msg).execute().await?;

    let prefixes = self.rules.get_mut(&table_id).expect("route contains non-existant table??");
    prefixes.remove(&prefix);
    if prefixes.is_empty() {
      self.rules.remove(&table_id);

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
      self.handle.rule().del(msg.clone()).execute().await?;
      msg.header.family = AddressFamily::Inet6;
      self.handle.rule().del(msg).execute().await?;
    }
    Ok(())
  }

  // route & addr change: check if next hop in changed prefix
  // rule change: full update for AF
  // link change: full update
  // scan timer triggered: full update
  pub async fn process(&mut self) -> Result<()> {
    use NetlinkPayload::*;
    use RouteNetlinkMessage::*;

    fn af_to_wildcard(f: AddressFamily) -> IpPrefix {
      (f == AddressFamily::Inet)
        .then_some(IpPrefix::V4_ALL)
        .unwrap_or(IpPrefix::V6_ALL)
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

    fn addr_msg_dst_prefix(msg: AddressMessage) -> IpPrefix {
      use AddressAttribute::Address;
      let dst_len = msg.header.prefix_len;
      (dst_len != 0)
        .then(|| {
          (msg.attributes.into_iter())
            .filter_map(|x| if let Address(ip) = x { Some(ip) } else { None })
            .map(|x| IpPrefix::new(x, dst_len))
            .next()
        })
        .flatten()
        .unwrap_or_else(|| af_to_wildcard(msg.header.family))
    }

    select! {
      _ = self.timer.tick() => self.process_all().await,
      Some((msg, _)) = self.msgs.next() => match msg.payload {
        InnerMessage(msg) => match msg {
          NewRoute(msg) | DelRoute(msg) => self.process_prefix(route_msg_dst_prefix(msg)).await,
          NewAddress(msg) | DelAddress(msg) => self.process_prefix(addr_msg_dst_prefix(msg)).await,
          NewRule(msg) | DelRule(msg) => self.process_prefix(af_to_wildcard(msg.header.family)).await,
          NewLink(_) | DelLink(_) => self.process_all().await,
          _ => Ok(()),
        },
        _ => Ok(()),
      },
    }
  }

  pub fn is_empty(&self) -> bool {
    self.routes.is_empty()
  }

  async fn process_prefix(&mut self, prefix: IpPrefix) -> Result<()> {
    Self::process_iter(&self.handle, self.routes.values_mut().filter(|x| prefix.contains(x.1))).await
  }
  async fn process_all(&mut self) -> Result<()> {
    Self::process_iter(&self.handle, self.routes.values_mut()).await
  }
  async fn process_iter(
    handle: &Handle,
    iter: impl Iterator<Item = &mut (IpPrefix, IpAddr, u32, Vec<RouteAttribute>)>,
  ) -> Result<()> {
    for (prefix, next_hop, table_id, attrs) in iter {
      warn!("process {prefix}");
      let new_attrs = Self::get_route2(handle, *next_hop).await?.collect::<Vec<_>>();
      if *attrs != new_attrs {
        *attrs = new_attrs.clone();
        let mut msg = RouteMessageBuilder::<IpAddr>::new()
          .destination_prefix(prefix.prefix(), prefix.len())
          .expect("destination prefix should be valid")
          .table_id(*table_id)
          .build();
        msg.attributes.extend(new_attrs);
        handle.route().add(msg).replace().execute().await?;
      }
    }
    Ok(())
  }

  async fn get_route(&self, ip: IpAddr) -> Result<impl Iterator<Item = RouteAttribute>> {
    Self::get_route2(&self.handle, ip).await
  }
  async fn get_route2(handle: &Handle, ip: IpAddr) -> Result<impl Iterator<Item = RouteAttribute>> {
    let msg = RouteMessageBuilder::<IpAddr>::new()
      .destination_prefix(ip, ip.is_ipv4().then_some(32).unwrap_or(128))
      .expect("destination prefix should be valid")
      .build();
    let mut msg = (handle.route()).get(msg).dump(false).execute();
    let Some(rt) = msg.try_next().await? else {
      unreachable!();
    };
    let attrs = rt.attributes.into_iter().filter(|x| [RTA_GATEWAY, RTA_OIF].contains(&x.kind()));
    Ok(attrs)
  }
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
  #[arg(long, value_name = "ID", default_value_t = 10000)]
  pub init_table_id: u32,

  /// Route rule priority as shown in `ip rule`.
  #[arg(long, value_name = "PRIO", default_value_t = 100)]
  pub rt_rule_priority: u32,
}
