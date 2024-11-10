use super::Result;
use crate::bgp::flow::{Component, ComponentKind, Flowspec};
use crate::net::{Afi, IpPrefix};
use futures::channel::mpsc::UnboundedReceiver;
use futures::{StreamExt, TryStreamExt};
use libc::{RTA_GATEWAY, RTA_OIF};
use rtnetlink::packet_core::NetlinkMessage;
use rtnetlink::packet_route::route::RouteAttribute;
use rtnetlink::packet_route::rule::{RuleAction, RuleAttribute, RuleMessage};
use rtnetlink::packet_route::{AddressFamily, RouteNetlinkMessage};
use rtnetlink::packet_utils::nla::Nla;
use rtnetlink::{Handle, RouteMessageBuilder};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::IpAddr;
use std::time::Duration;
use tokio::select;
use tokio::time::{interval, Interval};

pub struct RtNetlink {
  handle: Handle,
  msgs: UnboundedReceiver<(NetlinkMessage<RouteNetlinkMessage>, rtnetlink::sys::SocketAddr)>,
  routes: BTreeMap<u64, (IpPrefix, IpAddr, u32)>,
  rules: BTreeMap<u32, BTreeSet<IpPrefix>>,
  timer: Interval,
}

impl RtNetlink {
  pub fn new() -> io::Result<Self> {
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
      let table_id = self.rules.last_key_value().map(|(k, _)| *k + 1).unwrap_or(10000);
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

    self.routes.insert(id, (prefix, next_hop, table_id));
    let attrs = self.get_route(next_hop).await?;
    let mut msg = RouteMessageBuilder::<IpAddr>::new()
      .destination_prefix(prefix.prefix(), prefix.len())
      .expect("destination prefix should be valid")
      .table_id(table_id)
      .build();
    msg.attributes.extend(attrs);
    self.handle.route().add(msg).execute().await?;

    Ok(table_id)
  }

  pub async fn del(&mut self, id: u64) {
    let Some((prefix, _next_hop, table_id)) = self.routes.remove(&id) else {
      return;
    };
    let msg = RouteMessageBuilder::<IpAddr>::new()
      .destination_prefix(prefix.prefix(), prefix.len())
      .expect("destination prefix should be valid")
      .table_id(table_id)
      .build();
    _ = self.handle.route().del(msg).execute().await;

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
      _ = self.handle.rule().del(msg.clone()).execute().await;
      msg.header.family = AddressFamily::Inet6;
      _ = self.handle.rule().del(msg).execute().await;
    }
  }

  // TODO: timer and periodic refresh
  // route change: check if next hop in changed prefix
  // rule&link change: full update
  // scan timer triggered: full update
  pub async fn process(&mut self) -> Result<()> {
    select! {
      _ = self.timer.tick() => {}
      _x = self.msgs.next() => {}
    }
    Ok(())
  }

  pub async fn get_route(&self, ip: IpAddr) -> Result<impl Iterator<Item = RouteAttribute>> {
    let msg = RouteMessageBuilder::<IpAddr>::new()
      .destination_prefix(ip, ip.is_ipv4().then_some(32).unwrap_or(128))
      .expect("destination prefix should be valid")
      .build();
    let mut msg = (self.handle.route()).get(msg).dump(false).execute();
    let Some(rt) = msg.try_next().await? else {
      unreachable!();
    };
    // TODO: error on multiple routes received
    let attrs = rt.attributes.into_iter().filter(|x| [RTA_GATEWAY, RTA_OIF].contains(&x.kind()));
    Ok(attrs)
  }
}

#[tokio::test]
async fn test_rt() {
  let (conn, handle, _) = rtnetlink::new_connection().unwrap();
  tokio::spawn(conn);
  (handle.rule().add().v4())
    .fw_mark(1000)
    .action(RuleAction::ToTable)
    .table_id(1000)
    .priority(100)
    .execute()
    .await
    .unwrap();
  (handle.rule().add().v6())
    .fw_mark(1000)
    .action(RuleAction::ToTable)
    .table_id(1000)
    .priority(100)
    .execute()
    .await
    .unwrap()
}
