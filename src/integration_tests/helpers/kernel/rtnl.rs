use crate::net::IpWithPrefix;
use futures::TryStreamExt;
use nix::net::if_::if_nametoindex;
use rand::distr::Alphanumeric;
use rand::Rng;
use rtnetlink::packet_route::link::InfoKind;
use rtnetlink::packet_route::route::{RouteAttribute, RouteMessage, RoutePreference, RouteProtocol};
use rtnetlink::packet_route::rule::{RuleAction, RuleAttribute, RuleHeader, RuleMessage};
use rtnetlink::packet_route::AddressFamily;
use rtnetlink::packet_utils::nla::Nla;
use rtnetlink::packet_utils::Emitable;
use rtnetlink::{Handle, IpVersion, LinkMessageBuilder, LinkUnspec, RouteMessageBuilder};
use std::cmp::Ordering;
use std::net::IpAddr;

pub async fn create_dummy_link(handle: &Handle, addr: IpWithPrefix) -> anyhow::Result<u32> {
  let name: String = "dummy_"
    .chars()
    .chain(rand::rng().sample_iter(&Alphanumeric).take(8).map(char::from))
    .collect();
  let link_msg = LinkMessageBuilder::<LinkUnspec>::new_with_info_kind(InfoKind::Dummy)
    .name(name.clone())
    .up()
    .build();
  handle.link().add(link_msg).execute().await?;
  let index = if_nametoindex(&*name)?;
  handle.address().add(index, addr.addr(), addr.prefix_len()).execute().await?;
  Ok(index)
}

pub async fn remove_link(handle: &Handle, index: u32) -> anyhow::Result<()> {
  handle.link().del(index).execute().await?;
  Ok(())
}

pub async fn get_ip_rule(handle: &Handle, ip_version: IpVersion) -> anyhow::Result<Vec<RuleMessage>> {
  use RuleAttribute::*;

  let mut buf = Vec::new();
  let mut stream = handle.rule().get(ip_version).execute();
  while let Some(mut msg) = stream.try_next().await? {
    // normalize first
    msg.attributes.retain(|attr| {
      if let RuleAttribute::Table(_) = attr {
        msg.header.table = 0;
        return true;
      }
      // The following attributes have no meaning (?) but are still present in
      // get_ip_rule's output. Probably subject to kernel's internal change.
      !matches!(
        attr,
        SuppressPrefixLen(u32::MAX) | FwMask(u32::MAX) | Protocol(RouteProtocol::Unspec)
      )
    });
    msg.attributes.sort_by(rule_attr_sort);
    buf.push(msg);
  }
  Ok(buf)
}

pub fn make_ip_rule_mark(ip_version: IpVersion, prio: u32, mark: u32, table: u32) -> RuleMessage {
  use RuleAttribute::*;

  let mut msg = RuleMessage::default();
  msg.header = RuleHeader {
    family: match ip_version {
      IpVersion::V4 => AddressFamily::Inet,
      IpVersion::V6 => AddressFamily::Inet6,
    },
    table: if table > 0xff { 0 } else { table as u8 },
    action: RuleAction::ToTable,
    ..Default::default()
  };
  msg.attributes.extend([Priority(prio), FwMark(mark)]);
  msg.attributes.extend((table > 0xff).then_some(Table(table)));
  msg.attributes.sort_by(rule_attr_sort);
  msg
}

fn rule_attr_sort(a: &RuleAttribute, b: &RuleAttribute) -> Ordering {
  match a.kind().cmp(&b.kind()) {
    Ordering::Equal => {}
    ord => return ord,
  }
  let (al, bl) = (a.value_len(), b.value_len());
  match al.cmp(&bl) {
    Ordering::Equal => {}
    ord => return ord,
  }
  let (mut abuf, mut bbuf) = (vec![0; al], vec![0; bl]);
  a.emit(&mut abuf);
  b.emit(&mut bbuf);
  abuf.cmp(&bbuf)
}

pub async fn get_ip_route(handle: &Handle, ip_version: IpVersion, table: u32) -> anyhow::Result<Vec<RouteMessage>> {
  let mut msg = RouteMessageBuilder::<IpAddr>::new().table_id(table).build();
  msg.header.address_family = match ip_version {
    IpVersion::V4 => AddressFamily::Inet,
    IpVersion::V6 => AddressFamily::Inet6,
  };
  let mut buf = Vec::new();
  let mut stream = handle.route().get(msg).execute();
  while let Some(mut msg) = stream.try_next().await? {
    if msg.header.table as u32 == table || msg.attributes.contains(&RouteAttribute::Table(table)) {
      route_msg_normalize(&mut msg);
      buf.push(msg);
    }
  }
  Ok(buf)
}

pub fn route_msg_normalize(msg: &mut RouteMessage) {
  use RouteAttribute::*;
  msg.attributes.retain(|attr| match attr {
    Table(table) => {
      if *table > 0xff {
        msg.header.table = 0;
      }
      true
    }
    CacheInfo(_) => false, // TODO: match all zero on non-exhaustive struct
    Priority(1024) | Preference(RoutePreference::Medium) => false,
    _ => true,
  });
  msg.attributes.sort_by(route_attr_sort);
}

fn route_attr_sort(a: &RouteAttribute, b: &RouteAttribute) -> Ordering {
  match a.kind().cmp(&b.kind()) {
    Ordering::Equal => {}
    ord => return ord,
  }
  let (al, bl) = (a.value_len(), b.value_len());
  match al.cmp(&bl) {
    Ordering::Equal => {}
    ord => return ord,
  }
  let (mut abuf, mut bbuf) = (vec![0; al], vec![0; bl]);
  a.emit(&mut abuf);
  b.emit(&mut bbuf);
  abuf.cmp(&bbuf)
}
